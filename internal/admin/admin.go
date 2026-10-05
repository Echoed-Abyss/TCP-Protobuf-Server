// Package admin implements a localhost-only management HTTP server.
//
// Security constraints (enforced here, not just documented):
//   - Listens ONLY on 127.0.0.1 (or an explicitly configured loopback
//     address). It refuses to bind to 0.0.0.0 or any non-loopback IP.
//   - Every mutating and stats endpoint requires a bearer token loaded
//     from the environment / config file. The token is never logged.
//   - Stats read from the single source of truth (protocol.GlobalMetrics);
//     no parallel counters are maintained.
//   - Connection snapshots are redacted (fingerprint, not raw pubkey).
//   - Logs never include tokens, keys, or payloads.
package admin

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
)

// Auth rate-limit thresholds. After MaxAuthFailures failures from the same
// source IP, that IP is locked out for LockoutDuration. This slows brute-
// force token guessing.
const (
	MaxAuthFailures = 5
	LockoutDuration = 30 * time.Second
)

// authRecord tracks failed authentication attempts from a single source IP.
type authRecord struct {
	failures  int
	lockedAt  time.Time
}

// Server is the admin HTTP server.
type Server struct {
	token    string
	bind     string
	cm       ConnManager
	static   StaticConfig
	healthFn func() error // optional additional health check

	// authMu protects authFailures.
	authMu       sync.Mutex
	authFailures map[string]*authRecord // source IP -> failure record
}

// ConnManager is the interface the admin server uses to inspect and close
// active connections. It is satisfied by *server.Server. Defining it here
// avoids an import cycle.
type ConnManager interface {
	Connections() []protocol.ConnInfo
	CloseConn(id uint64) bool
}

// StaticConfig describes configuration that requires a restart to change.
// It is exposed read-only through /admin/config.
type StaticConfig struct {
	ListenAddr   string `json:"listen_addr"`
	KeyFile      string `json:"key_file"`
	TrustStore   string `json:"trust_store"`
	SessionTTLNs int64  `json:"session_ttl_ns"`
	MaxKeyID     uint8  `json:"max_key_id"`
	ProtocolVer  uint8  `json:"protocol_version"`
}

// New creates an admin server. The token is loaded from the SECPROTO_ADMIN_TOKEN
// environment variable if token is empty. It returns an error if no token is
// available (fail-closed: an admin endpoint without auth is not allowed).
func New(bind, token string, cm ConnManager, static StaticConfig) (*Server, error) {
	if token == "" {
		token = os.Getenv("SECPROTO_ADMIN_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("admin token not set: provide -admin-token or SECPROTO_ADMIN_TOKEN")
	}
	if bind == "" {
		bind = "127.0.0.1:9090"
	}
	if err := ensureLoopback(bind); err != nil {
		return nil, err
	}
	return &Server{
		token:        token,
		bind:         bind,
		cm:           cm,
		static:       static,
		authFailures: make(map[string]*authRecord),
	}, nil
}

// ensureLoopback returns an error if addr does not resolve to a loopback IP.
func ensureLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid admin bind address %q: %w", addr, err)
	}
	// Allow literal localhost and loopback IPs.
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("admin bind host %q is not a loopback address", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("admin must bind to loopback only; got %q", host)
	}
	return nil
}

// SetHealthCheck registers an additional health-check function (e.g. key
// file permissions). The default always returns nil.
func (s *Server) SetHealthCheck(fn func() error) {
	s.healthFn = fn
}

// ListenAndServe starts the admin HTTP server. It blocks.
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/stats", s.requireAuth(s.handleStats))
	mux.HandleFunc("/metrics", s.requireAuth(s.handleMetrics))
	mux.HandleFunc("/admin/config", s.requireAuth(s.handleConfig))
	mux.HandleFunc("/admin/connections", s.requireAuth(s.handleConnections))
	mux.HandleFunc("/admin/connections/", s.requireAuth(s.handleConnectionOp))
	mux.HandleFunc("/admin/healthz", s.handleHealthz) // no auth needed: liveness only
	mux.HandleFunc("/admin/", s.requireAuth(s.handleUI))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := &http.Server{
		Addr:              s.bind,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return srv.ListenAndServe()
}

// requireAuth enforces bearer-token authentication with per-IP rate
// limiting (lockout after repeated failures) plus a custom-header CSRF
// check for state-changing requests. The token is compared in constant
// time. The token value is never logged.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := sourceIP(r)

		// 1. Lockout check: if this IP is in a lockout window, reject
		//    immediately without comparing the token.
		if s.isLockedOut(ip) {
			protocol.GlobalMetrics.AdminRateLimited.Add(1)
			http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
			return
		}

		// 2. Token check (constant-time comparison).
		got := extractToken(r)
		authed := subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
		if !authed {
			protocol.GlobalMetrics.AdminAuthFail.Add(1)
			s.recordAuthResult(ip, false)
			// Constant artificial delay on auth failure to reduce timing
			// side-channels that could distinguish wrong-token from
			// lockout. 5ms is small enough not to enable DoS amplification
			// but large enough to dominate comparison timing.
			time.Sleep(5 * time.Millisecond)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.recordAuthResult(ip, true)

		// 3. CSRF defence for state-changing methods: require a custom
		//    header that browsers will not send on cross-origin requests
		//    without CORS preflight (which the admin server does not
		//    allow). Simple <form> submissions cannot set custom headers.
		if r.Method == http.MethodPut || r.Method == http.MethodPost || r.Method == http.MethodDelete {
			if r.Header.Get("X-Admin-Action") == "" {
				protocol.GlobalMetrics.AdminAuthFail.Add(1)
				http.Error(w, "missing X-Admin-Action header", http.StatusForbidden)
				return
			}
		}

		next(w, r)
	}
}

// sourceIP extracts the client IP from a request's RemoteAddr.
func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isLockedOut reports whether the source IP is currently locked out due to
// too many failed auth attempts.
func (s *Server) isLockedOut(ip string) bool {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	rec, ok := s.authFailures[ip]
	if !ok {
		return false
	}
	if rec.failures >= MaxAuthFailures {
		if time.Since(rec.lockedAt) < LockoutDuration {
			return true
		}
		rec.failures = 0 // lockout expired
	}
	return false
}

// recordAuthResult updates the failure counter for an IP.
func (s *Server) recordAuthResult(ip string, ok bool) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	rec, exists := s.authFailures[ip]
	if !exists {
		rec = &authRecord{}
		s.authFailures[ip] = rec
	}
	if ok {
		rec.failures = 0
	} else {
		rec.failures++
		rec.lockedAt = time.Now()
	}
}

// audit writes an audit log entry for admin state-changing operations.
// The message must never contain tokens, keys, or sensitive payloads.
func (s *Server) audit(action, detail string) {
	fmt.Fprintf(os.Stderr, "[admin-audit] time=%s action=%s detail=%s\n",
		time.Now().UTC().Format(time.RFC3339), action, detail)
}

// extractToken reads the token from the Authorization header
// (Bearer <token>) or the X-Admin-Token header.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return r.Header.Get("X-Admin-Token")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleStats returns protocol metrics + active connection count.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m := protocol.Snapshot()
	stats := map[string]any{
		"metrics":      m,
		"active_conns": 0,
		"goroutines":   runtime.NumGoroutine(),
	}
	if s.cm != nil {
		stats["active_conns"] = len(s.cm.Connections())
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleMetrics exposes metrics in Prometheus text format.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m := protocol.Snapshot()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for k, v := range m {
		fmt.Fprintf(w, "secproto_%s %d\n", k, v)
	}
	if s.cm != nil {
		fmt.Fprintf(w, "secproto_active_connections %d\n", len(s.cm.Connections()))
	}
}

// configResponse is the shape of GET /admin/config.
type configResponse struct {
	Hot     protocol.ConfigSnapshot `json:"hot"`
	Static  StaticConfig            `json:"static"`
	HotKeys []string                `json:"hot_keys"`
}

// handleConfig returns the current config (hot-changeable + restart-only).
// PUT applies a partial hot-update.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, configResponse{
			Hot:     protocol.GlobalConfig.Snapshot(),
			Static:  s.static,
			HotKeys: []string{
				"heartbeat_interval_ns",
				"dummy_frame_interval_ns",
				"dummy_frame_jitter_ns",
				"dummy_frames_enabled",
				"padding_block_size",
				"data_time_window_ns",
			},
		})
	case http.MethodPut:
		var u protocol.HotConfigUpdate
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			protocol.GlobalMetrics.AdminConfigReject.Add(1)
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"ok": "false", "code": "bad_request", "error": "invalid json",
			})
			return
		}
		if err := protocol.GlobalConfig.Apply(u); err != nil {
			protocol.GlobalMetrics.AdminConfigReject.Add(1)
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"ok": "false", "code": "bad_request", "error": err.Error(),
			})
			return
		}
		// Audit: log which fields were changed, never their values.
		var changed []string
		if u.HeartbeatIntervalNs != nil {
			changed = append(changed, "heartbeat_interval_ns")
		}
		if u.DummyFrameIntervalNs != nil {
			changed = append(changed, "dummy_frame_interval_ns")
		}
		if u.DummyFrameJitterNs != nil {
			changed = append(changed, "dummy_frame_jitter_ns")
		}
		if u.DummyFramesEnabled != nil {
			changed = append(changed, "dummy_frames_enabled")
		}
		if u.PaddingBlockSize != nil {
			changed = append(changed, "padding_block_size")
		}
		if u.DataTimeWindowNs != nil {
			changed = append(changed, "data_time_window_ns")
		}
		s.audit("config.update", "fields="+strings.Join(changed, ","))
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "code": "ok", "hot": protocol.GlobalConfig.Snapshot(),
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleConnections lists active connections (redacted).
func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cm == nil {
		writeJSON(w, http.StatusOK, []protocol.ConnInfo{})
		return
	}
	conns := s.cm.Connections()
	writeJSON(w, http.StatusOK, conns)
}

// handleConnectionOp handles POST /admin/connections/{id}/close.
func (s *Server) handleConnectionOp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Path: /admin/connections/{id}/close
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/connections/"), "/")
	if len(parts) != 2 || parts[1] != "close" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "invalid connection id", http.StatusBadRequest)
		return
	}
	if s.cm == nil {
		http.Error(w, "no connection manager", http.StatusServiceUnavailable)
		return
	}
	if !s.cm.CloseConn(id) {
		http.Error(w, "connection not found", http.StatusNotFound)
		return
	}
	// Audit log (no secrets: only the conn id, which is a local counter).
	s.audit("connection.close", fmt.Sprintf("conn_id=%d", id))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// handleHealthz returns process liveness + optional self-check.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	}
	if s.healthFn != nil {
		if err := s.healthFn(); err != nil {
			status["status"] = "degraded"
			status["error"] = err.Error()
			writeJSON(w, http.StatusServiceUnavailable, status)
			return
		}
	}
	writeJSON(w, http.StatusOK, status)
}
