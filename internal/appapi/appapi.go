// Package appapi implements the application-layer request/response protocol
// that runs on top of the encrypted transport.Conn.
//
// All messages are JSON carried inside MsgType=Data frames (AEAD-encrypted).
// Handlers never see keys, sequence numbers, or ciphertext — only the
// decrypted JSON payload. This keeps the application layer decoupled from
// the cryptographic transport.
//
// Security properties inherited from the transport:
//   - Confidentiality & integrity via AEAD.
//   - Replay protection via seq window + timestamp window.
//   - Ambiguous external errors (PublicError) and constant failure delay.
//
// The application layer adds:
//   - Action routing via a Registry.
//   - Per-request timeout (timeout_ms).
//   - Bounded worker pool so slow handlers cannot stall the read loop.
//   - req_id deduplication (idempotency) for recently seen requests.
package appapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/transport"
)

// Protocol version of the application-layer JSON envelope.
const EnvelopeVersion = 1

// Business response codes. These are stable strings exposed to clients;
// they are intentionally coarse and do not leak internal implementation
// details.
const (
	CodeOK           = "ok"
	CodeBadRequest   = "bad_request"    // malformed JSON / missing fields
	CodeNotFound     = "not_found"      // unregistered action
	CodeTimeout      = "timeout"        // handler exceeded timeout_ms
	CodeTooManyReqs  = "too_many_requests" // worker pool saturated
	CodeInternal     = "internal_error" // handler returned an error
	CodeDuplicate    = "duplicate"      // req_id was already processed
)

// Request is the application-layer request envelope.
//
//	{"ver":1,"req_id":"...","action":"<string>","timeout_ms":<int>,"payload":{...}}
type Request struct {
	Ver       int             `json:"ver"`
	ReqID     string          `json:"req_id"`
	Action    string          `json:"action"`
	TimeoutMs int             `json:"timeout_ms"`
	Payload   json.RawMessage `json:"payload"`
}

// Response is the application-layer response envelope.
//
//	{"ver":1,"req_id":"<echo>","ok":true|false,"code":"<code>","data":{...},"error":"<generic>"}
//
// The `error` field is always a generic string; internal details are never
// exposed to the client.
type Response struct {
	Ver   int             `json:"ver"`
	ReqID string          `json:"req_id"`
	Ok    bool            `json:"ok"`
	Code  string          `json:"code"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

// Handler processes a request and returns a response. The context carries
// the per-request timeout. Handlers MUST respect ctx.Done().
//
// A returned error is mapped to CodeInternal with a generic message; the
// error text itself is never sent to the client.
type Handler func(ctx context.Context, req *Request) (*Response, error)

// Registry maps action names to handlers. It is safe for concurrent use.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{handlers: make(map[string]Handler)}
}

// Register registers a handler for the given action. Overwrites any existing
// handler for that action.
func (r *Registry) Register(action string, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[action] = h
}

// Get returns the handler for the action, or (nil, false) if not registered.
func (r *Registry) Get(action string) (Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[action]
	return h, ok
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// Default bounds for the application server.
const (
	DefaultMaxWorkers   = 64
	DefaultMaxTimeoutMs = 30_000 // 30s cap on any single request
	DefaultDedupSize    = 1024
)

// Server serves application requests over a transport.Conn.
type Server struct {
	registry   *Registry
	maxWorkers int
	maxTimeout time.Duration

	// workers is a counting semaphore (buffered channel) bounding concurrent
	// handler goroutines across all connections sharing this server.
	workers chan struct{}

	// kv is the shared key/value store for the kv.set/kv.get demo handlers.
	kv sync.Map

	// dedupSize is the per-connection dedup cache capacity.
	dedupSize int
}

// NewServer creates an application server. If maxWorkers <= 0,
// DefaultMaxWorkers is used.
func NewServer(registry *Registry, maxWorkers int) *Server {
	if maxWorkers <= 0 {
		maxWorkers = DefaultMaxWorkers
	}
	return &Server{
		registry:   registry,
		maxWorkers: maxWorkers,
		maxTimeout: time.Duration(DefaultMaxTimeoutMs) * time.Millisecond,
		workers:    make(chan struct{}, maxWorkers),
		dedupSize:  DefaultDedupSize,
	}
}

// connState holds per-connection state for the application server.
type connState struct {
	dedup *dedupCache
	wg    sync.WaitGroup
}

// ServeConn attaches to a transport connection and serves application
// requests until the connection closes. It blocks. In-flight requests are
// drained (given their timeout) before returning.
//
// This is intended to be used as the server's OnConn callback:
//
//	srv.OnConn = appSrv.ServeConn
func (s *Server) ServeConn(conn *transport.Conn) error {
	state := &connState{dedup: newDedupCache(s.dedupSize)}
	conn.SetOnData(func(data []byte) {
		s.dispatch(conn, data, state)
	})
	err := conn.ReadLoop()
	// Drain in-flight requests (each respects its own timeout, so this is
	// bounded by maxTimeout).
	state.wg.Wait()
	return err
}

// dispatch offloads a request to the bounded worker pool. It returns
// immediately so the read loop is never blocked by a slow handler.
func (s *Server) dispatch(conn *transport.Conn, data []byte, state *connState) {
	state.wg.Add(1)
	go func() {
		defer state.wg.Done()
		// Acquire a worker slot (blocks here, not in the read loop).
		s.workers <- struct{}{}
		defer func() { <-s.workers }()
		s.process(conn, data, state)
	}()
}

// process parses, routes, and executes a single request.
func (s *Server) process(conn *transport.Conn, data []byte, state *connState) {
	// Backward-compatibility: payloads that are not JSON appapi envelopes
	// are echoed verbatim. This keeps pre-appapi clients (raw bytes)
	// working while routing JSON envelopes to the action registry.
	if len(data) == 0 || data[0] != '{' {
		if conn != nil {
			_ = conn.SendData(data)
		}
		return
	}

	resp := s.handle(data, state)
	// Re-serialize and send. Errors here (e.g. conn closed) are ignored:
	// the read loop will surface them.
	if conn == nil {
		return
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_ = conn.SendData(b)
}

// handle is the pure request-handling logic (no I/O), making it testable.
func (s *Server) handle(data []byte, state *connState) *Response {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return errResp("", CodeBadRequest, "malformed request")
	}
	if req.Ver != EnvelopeVersion {
		return errResp(req.ReqID, CodeBadRequest, "unsupported version")
	}
	if req.ReqID == "" || req.Action == "" {
		return errResp(req.ReqID, CodeBadRequest, "missing required fields")
	}

	// Idempotency: if this req_id was recently processed on this connection,
	// return the cached response instead of re-running the handler.
	if cached, ok := state.dedup.Get(req.ReqID); ok {
		cached.ReqID = req.ReqID
		return cached
	}

	h, ok := s.registry.Get(req.Action)
	if !ok {
		resp := errResp(req.ReqID, CodeNotFound, "action not found")
		state.dedup.Put(req.ReqID, resp)
		return resp
	}

	// Per-request timeout, bounded by maxTimeout.
	timeout := s.maxTimeout
	if req.TimeoutMs > 0 {
		t := time.Duration(req.TimeoutMs) * time.Millisecond
		if t < timeout {
			timeout = t
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan *Response, 1)
	go func() {
		resp, err := h(ctx, &req)
		if err != nil {
			// Never leak the internal error text.
			done <- errResp(req.ReqID, CodeInternal, "handler error")
			return
		}
		if resp == nil {
			resp = okResp(req.ReqID, nil)
		}
		resp.ReqID = req.ReqID
		resp.Ver = EnvelopeVersion
		done <- resp
	}()

	select {
	case resp := <-done:
		state.dedup.Put(req.ReqID, resp)
		return resp
	case <-ctx.Done():
		resp := errResp(req.ReqID, CodeTimeout, "request timed out")
		state.dedup.Put(req.ReqID, resp)
		return resp
	}
}

// errResp builds a non-OK response with a generic error message.
func errResp(reqID, code, msg string) *Response {
	return &Response{
		Ver:   EnvelopeVersion,
		ReqID: reqID,
		Ok:    false,
		Code:  code,
		Error: msg,
	}
}

// okResp builds an OK response with optional data.
func okResp(reqID string, data json.RawMessage) *Response {
	return &Response{
		Ver:   EnvelopeVersion,
		ReqID: reqID,
		Ok:    true,
		Code:  CodeOK,
		Data:  data,
	}
}

// ---------------------------------------------------------------------------
// dedupCache: a small bounded cache for req_id -> Response.
// ---------------------------------------------------------------------------

type dedupCache struct {
	mu    sync.Mutex
	cap   int
	items map[string]*Response
	order []string // insertion order for eviction
}

func newDedupCache(cap int) *dedupCache {
	if cap <= 0 {
		cap = DefaultDedupSize
	}
	return &dedupCache{
		cap:   cap,
		items: make(map[string]*Response),
	}
}

func (d *dedupCache) Get(reqID string) (*Response, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.items[reqID]
	return r, ok
}

func (d *dedupCache) Put(reqID string, resp *Response) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.items[reqID]; exists {
		return
	}
	if len(d.items) >= d.cap {
		// Evict oldest.
		oldest := d.order[0]
		d.order = d.order[1:]
		delete(d.items, oldest)
	}
	// Store a shallow copy so callers can't mutate the cached response.
	cp := *resp
	d.items[reqID] = &cp
	d.order = append(d.order, reqID)
}

// ---------------------------------------------------------------------------
// Built-in handlers
// ---------------------------------------------------------------------------

// EchoHandler returns the request payload verbatim in the response data.
func EchoHandler(ctx context.Context, req *Request) (*Response, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return okResp(req.ReqID, req.Payload), nil
}

// StatsHandler returns a snapshot of the protocol metrics.
func StatsHandler(ctx context.Context, req *Request) (*Response, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	m := protocol.Snapshot()
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return okResp(req.ReqID, b), nil
}

// kvRequestPayload is the payload for kv.set / kv.get.
type kvRequestPayload struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

// KVSetHandler stores a key/value pair.
func (s *Server) KVSetHandler(ctx context.Context, req *Request) (*Response, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	var p kvRequestPayload
	if err := json.Unmarshal(req.Payload, &p); err != nil {
		return errResp(req.ReqID, CodeBadRequest, "invalid payload"), nil
	}
	if p.Key == "" {
		return errResp(req.ReqID, CodeBadRequest, "missing key"), nil
	}
	s.kv.Store(p.Key, p.Value)
	return okResp(req.ReqID, json.RawMessage(`{"stored":true}`)), nil
}

// KVGetHandler retrieves a value by key.
func (s *Server) KVGetHandler(ctx context.Context, req *Request) (*Response, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	var p kvRequestPayload
	if err := json.Unmarshal(req.Payload, &p); err != nil {
		return errResp(req.ReqID, CodeBadRequest, "invalid payload"), nil
	}
	v, ok := s.kv.Load(p.Key)
	if !ok {
		return okResp(req.ReqID, json.RawMessage(`{"found":false}`)), nil
	}
	b, _ := json.Marshal(map[string]any{"found": true, "value": fmt.Sprint(v)})
	return okResp(req.ReqID, b), nil
}

// RegisterDefaults registers the built-in demo handlers on the registry.
func (s *Server) RegisterDefaults() {
	s.registry.Register("echo", EchoHandler)
	s.registry.Register("server.stats", StatsHandler)
	s.registry.Register("kv.set", s.KVSetHandler)
	s.registry.Register("kv.get", s.KVGetHandler)
}

// errRequestTooLarge is returned when a request payload exceeds the limit.
// (Currently the transport enforces MaxFramePayload; this is a placeholder
// for future application-level limits.)
var errRequestTooLarge = errors.New("request too large")
