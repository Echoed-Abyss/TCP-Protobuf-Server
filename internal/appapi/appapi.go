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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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

	// HardHandlerTimeoutMs is the absolute wall-clock ceiling for any
	// handler execution, independent of (and always <=) the request's
	// timeout_ms. A handler that ignores ctx.Done() and runs forever is
	// still killed at this limit.
	HardHandlerTimeoutMs = 5_000 // 5s

	// MaxKVEntries caps the number of key/value pairs the demo kv store
	// holds. Beyond this, oldest entries are evicted (LRU).
	MaxKVEntries = 1024
)

// Server serves application requests over a transport.Conn.
type Server struct {
	registry   *Registry
	maxWorkers int
	maxTimeout time.Duration

	// workers is a counting semaphore (buffered channel) bounding concurrent
	// handler goroutines across all connections sharing this server.
	workers chan struct{}

	// kv is a bounded key/value store for the kv.set/kv.get demo handlers.
	// It is shared across connections and capped at MaxKVEntries (LRU
	// eviction) so a flood of kv.set cannot exhaust memory.
	kv *boundedKV

	// dedupSize is the per-connection dedup cache capacity.
	dedupSize int

	// failureDelay is a constant artificial delay applied to every error
	// response so that clients cannot distinguish failure modes by timing.
	failureDelay time.Duration
}

// DefaultFailureDelayMs is the constant delay applied to appapi error
// responses to mitigate timing side-channels.
const DefaultFailureDelayMs = 2

// NewServer creates an application server. If maxWorkers <= 0,
// DefaultMaxWorkers is used.
func NewServer(registry *Registry, maxWorkers int) *Server {
	if maxWorkers <= 0 {
		maxWorkers = DefaultMaxWorkers
	}
	return &Server{
		registry:     registry,
		maxWorkers:   maxWorkers,
		maxTimeout:   time.Duration(DefaultMaxTimeoutMs) * time.Millisecond,
		workers:      make(chan struct{}, maxWorkers),
		kv:           newBoundedKV(MaxKVEntries),
		dedupSize:    DefaultDedupSize,
		failureDelay: time.Duration(DefaultFailureDelayMs) * time.Millisecond,
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

// dispatch offloads a request to the bounded worker pool. If the pool is
// saturated, it returns a too_many_requests response immediately (no
// unbounded queueing) so the read loop is never blocked.
func (s *Server) dispatch(conn *transport.Conn, data []byte, state *connState) {
	state.wg.Add(1)
	go func() {
		defer state.wg.Done()
		// Non-blocking worker acquisition: if the pool is full, reject
		// fast rather than queueing unbounded requests.
		select {
		case s.workers <- struct{}{}:
		default:
			protocol.GlobalMetrics.AppWorkerReject.Add(1)
			s.sendResp(conn, errResp("", CodeTooManyReqs, "server busy"))
			return
		}
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

	// Hard limit on decrypted application payload size BEFORE parsing.
	if len(data) > protocol.MaxAppPayload {
		protocol.GlobalMetrics.AppPayloadReject.Add(1)
		s.sendResp(conn, errResp("", CodeBadRequest, "payload too large"))
		return
	}

	resp := s.handle(data, state)
	s.sendResp(conn, resp)
}

// sendResp marshals and sends a response, ignoring send errors (the read
// loop surfaces connection failures). For non-OK responses a constant
// artificial delay is applied so clients cannot distinguish failure modes
// by response timing.
func (s *Server) sendResp(conn *transport.Conn, resp *Response) {
	if conn == nil {
		return
	}
	if !resp.Ok && s.failureDelay > 0 {
		time.Sleep(s.failureDelay)
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_ = conn.SendData(b)
}

// handle is the pure request-handling logic (no I/O), making it testable.
func (s *Server) handle(data []byte, state *connState) *Response {
	// Enforce JSON nesting depth before full unmarshal to prevent
	// stack/CPU exhaustion from deeply nested payloads.
	if err := checkJSONDepth(data, protocol.MaxJSONDepth); err != nil {
		protocol.GlobalMetrics.AppPayloadReject.Add(1)
		return errResp("", CodeBadRequest, "malformed request")
	}

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
	// req_id must be short and use a safe charset to prevent cache-key
	// abuse and log injection.
	if !validReqID(req.ReqID) {
		protocol.GlobalMetrics.AppReqIDReject.Add(1)
		return errResp("", CodeBadRequest, "invalid req_id")
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

	// Per-request timeout, bounded by both maxTimeout and the hard
	// handler ceiling. A handler that ignores ctx cannot run forever.
	timeout := s.maxTimeout
	if req.TimeoutMs > 0 {
		t := time.Duration(req.TimeoutMs) * time.Millisecond
		if t < timeout {
			timeout = t
		}
	}
	if hardLimit := time.Duration(HardHandlerTimeoutMs) * time.Millisecond; timeout > hardLimit {
		timeout = hardLimit
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan *Response, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Handler panicked: never leak the panic value/stack to
				// the client. Return a generic internal error.
				protocol.GlobalMetrics.AppPanicRecovered.Add(1)
				done <- errResp(req.ReqID, CodeInternal, "handler error")
			}
		}()
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

// validReqID reports whether id is a safe req_id: length <= MaxReqIDLen and
// only [A-Za-z0-9._-]. This prevents cache-key collisions, log injection,
// and oversized-key memory pressure.
func validReqID(id string) bool {
	if len(id) == 0 || len(id) > protocol.MaxReqIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z') &&
			!(c >= 'A' && c <= 'Z') &&
			!(c >= '0' && c <= '9') &&
			c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// checkJSONDepth walks the JSON tokens in data and returns an error if the
// nesting depth exceeds maxDepth. It rejects malformed JSON too (the caller
// then reports a generic bad_request). Using json.Decoder.Token is
// streaming and does not materialise the full object tree.
func checkJSONDepth(data []byte, maxDepth int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch tok.(type) {
		case json.Delim:
			d := tok.(json.Delim)
			if d == '{' || d == '[' {
				depth++
				if depth > maxDepth {
					return errDepthExceeded
				}
			} else if d == '}' || d == ']' {
				depth--
			}
		}
	}
}

var errDepthExceeded = errors.New("json nesting depth exceeded")

// errResp builds a non-OK response with a generic error message. The
// message is intentionally coarse and does not reveal which validation
// check failed (e.g. "payload too large" vs "invalid req_id" both map to
// "request rejected"). The stable `code` field is the only signal clients
// may rely on.
func errResp(reqID, code, _ string) *Response {
	var msg string
	switch code {
	case CodeBadRequest:
		msg = "request rejected"
	case CodeNotFound:
		msg = "not found"
	case CodeTimeout:
		msg = "timeout"
	case CodeTooManyReqs:
		msg = "busy"
	case CodeInternal:
		msg = "internal error"
	case CodeDuplicate:
		msg = "duplicate"
	default:
		msg = "error"
	}
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

// Bounds for kv demo store keys/values to prevent memory abuse.
const (
	maxKVKeyLen   = 256
	maxKVValueLen = 4096
)

// KVSetHandler stores a key/value pair. Keys and values are length-bounded.
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
	if p.Key == "" || len(p.Key) > maxKVKeyLen {
		return errResp(req.ReqID, CodeBadRequest, "invalid key"), nil
	}
	if len(p.Value) > maxKVValueLen {
		return errResp(req.ReqID, CodeBadRequest, "value too large"), nil
	}
	s.kv.set(p.Key, p.Value)
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
	v, ok := s.kv.get(p.Key)
	if !ok {
		return okResp(req.ReqID, json.RawMessage(`{"found":false}`)), nil
	}
	b, _ := json.Marshal(map[string]any{"found": true, "value": v})
	return okResp(req.ReqID, b), nil
}

// RegisterDefaults registers the built-in demo handlers on the registry.
func (s *Server) RegisterDefaults() {
	s.registry.Register("echo", EchoHandler)
	s.registry.Register("server.stats", StatsHandler)
	s.registry.Register("kv.set", s.KVSetHandler)
	s.registry.Register("kv.get", s.KVGetHandler)
}

// ---------------------------------------------------------------------------
// boundedKV: a small LRU key/value store with a hard capacity cap.
// Used by the kv.set/kv.get demo handlers so a flood of sets cannot
// exhaust memory.
// ---------------------------------------------------------------------------

type boundedKV struct {
	mu     sync.Mutex
	cap    int
	items  map[string]string
	order  []string // insertion order for LRU eviction
}

func newBoundedKV(cap int) *boundedKV {
	if cap <= 0 {
		cap = MaxKVEntries
	}
	return &boundedKV{
		cap:   cap,
		items: make(map[string]string),
	}
}

func (k *boundedKV) set(key, value string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, exists := k.items[key]; exists {
		k.items[key] = value
		return
	}
	if len(k.items) >= k.cap {
		// Evict oldest (LRU).
		oldest := k.order[0]
		k.order = k.order[1:]
		delete(k.items, oldest)
	}
	k.items[key] = value
	k.order = append(k.order, key)
}

func (k *boundedKV) get(key string) (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.items[key]
	return v, ok
}

// errRequestTooLarge is returned when a request payload exceeds the limit.
var errRequestTooLarge = errors.New("request too large")
