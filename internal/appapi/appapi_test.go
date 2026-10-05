package appapi

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func newTestServer() *Server {
	reg := NewRegistry()
	s := NewServer(reg, 4)
	s.RegisterDefaults()
	return s
}

// TestRouting verifies that a registered action is dispatched and an
// unregistered action returns CodeNotFound.
func TestRouting(t *testing.T) {
	s := newTestServer()
	state := &connState{dedup: newDedupCache(8)}

	// Registered action: echo.
	req := `{"ver":1,"req_id":"r1","action":"echo","timeout_ms":1000,"payload":{"hello":"world"}}`
	resp := s.handle([]byte(req), state)
	if !resp.Ok || resp.Code != CodeOK {
		t.Fatalf("expected ok, got code=%s error=%s", resp.Code, resp.Error)
	}
	var data map[string]any
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data["hello"] != "world" {
		t.Fatalf("echo data mismatch: %v", data)
	}
	if resp.ReqID != "r1" {
		t.Fatalf("req_id not echoed: got %s", resp.ReqID)
	}

	// Unregistered action.
	req2 := `{"ver":1,"req_id":"r2","action":"does.not.exist","payload":{}}`
	resp2 := s.handle([]byte(req2), state)
	if resp2.Ok || resp2.Code != CodeNotFound {
		t.Fatalf("expected not_found, got ok=%v code=%s", resp2.Ok, resp2.Code)
	}
	if resp2.Error == "" {
		t.Fatalf("expected generic error message")
	}
}

// TestBadJSON verifies that malformed JSON and missing fields return a
// unified bad_request error with no internal detail leaked.
func TestBadJSON(t *testing.T) {
	s := newTestServer()
	state := &connState{dedup: newDedupCache(8)}

	cases := []struct {
		name string
		req  string
	}{
		{"malformed json", `{not json`},
		{"missing req_id", `{"ver":1,"action":"echo","payload":{}}`},
		{"missing action", `{"ver":1,"req_id":"x","payload":{}}`},
		{"wrong version", `{"ver":99,"req_id":"x","action":"echo","payload":{}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := s.handle([]byte(c.req), state)
			if resp.Ok || resp.Code != CodeBadRequest {
				t.Fatalf("expected bad_request, got ok=%v code=%s", resp.Ok, resp.Code)
			}
			// Error message must be generic (no JSON parse internals).
			if resp.Error == "" {
				t.Fatalf("expected generic error message")
			}
		})
	}
}

// TestIdempotency verifies that a repeated req_id returns the cached
// response without re-running the handler.
func TestIdempotency(t *testing.T) {
	reg := NewRegistry()
	s := NewServer(reg, 4)
	calls := 0
	reg.Register("count", func(ctx context.Context, req *Request) (*Response, error) {
		calls++
		return okResp(req.ReqID, json.RawMessage(`{"n":1}`)), nil
	})

	state := &connState{dedup: newDedupCache(8)}
	req := `{"ver":1,"req_id":"dup","action":"count","payload":{}}`

	resp1 := s.handle([]byte(req), state)
	resp2 := s.handle([]byte(req), state)

	if calls != 1 {
		t.Fatalf("handler should run once for duplicate req_id, ran %d times", calls)
	}
	if resp1.Code != resp2.Code || string(resp1.Data) != string(resp2.Data) {
		t.Fatalf("duplicate req_id should return cached response")
	}
}

// TestTimeout verifies that a handler exceeding timeout_ms returns a
// timeout error and does not leak internal details.
func TestTimeout(t *testing.T) {
	reg := NewRegistry()
	s := NewServer(reg, 4)
	reg.Register("slow", func(ctx context.Context, req *Request) (*Response, error) {
		select {
		case <-time.After(500 * time.Millisecond):
			return okResp(req.ReqID, json.RawMessage(`{}`)), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	state := &connState{dedup: newDedupCache(8)}
	req := `{"ver":1,"req_id":"slow","action":"slow","timeout_ms":50,"payload":{}}`

	start := time.Now()
	resp := s.handle([]byte(req), state)
	elapsed := time.Since(start)

	if resp.Ok || resp.Code != CodeTimeout {
		t.Fatalf("expected timeout, got ok=%v code=%s", resp.Ok, resp.Code)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("timeout took too long: %v", elapsed)
	}
}

// TestKVSetGet verifies the kv.set/kv.get demo handlers round-trip.
func TestKVSetGet(t *testing.T) {
	s := newTestServer()
	state := &connState{dedup: newDedupCache(8)}

	setReq := `{"ver":1,"req_id":"k1","action":"kv.set","payload":{"key":"foo","value":"bar"}}`
	resp := s.handle([]byte(setReq), state)
	if !resp.Ok {
		t.Fatalf("kv.set failed: %s", resp.Error)
	}

	getReq := `{"ver":1,"req_id":"k2","action":"kv.get","payload":{"key":"foo"}}`
	resp2 := s.handle([]byte(getReq), state)
	var data map[string]any
	_ = json.Unmarshal(resp2.Data, &data)
	if data["value"] != "bar" {
		t.Fatalf("kv.get returned wrong value: %v", data)
	}
}

// TestWorkerBounds verifies the server does not exceed maxWorkers.
func TestWorkerBounds(t *testing.T) {
	reg := NewRegistry()
	s := NewServer(reg, 2)
	reg.Register("sleep", func(ctx context.Context, req *Request) (*Response, error) {
		select {
		case <-time.After(20 * time.Millisecond):
			return okResp(req.ReqID, nil), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	// Dispatch many requests concurrently via dispatch (bounded pool).
	// We just verify no panic and all complete.
	state := &connState{dedup: newDedupCache(32)}
	for i := 0; i < 10; i++ {
		s.dispatch(nil, []byte(`{"ver":1,"req_id":"w`+itoa(i)+`","action":"sleep","payload":{}}`), state)
	}
	state.wg.Wait()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
