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
	"time"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
)

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

// Server is the admin HTTP server.
type Server struct {
	token    string
	bind     string
	cm       ConnManager
	static   StaticConfig
	healthFn func() error // optional additional health check
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
		token:  token,
		bind:   bind,
		cm:     cm,
		static: static,
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

// requireAuth is a middleware that enforces bearer-token authentication.
// The token is compared in constant time. The token value is never logged.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := extractToken(r)
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
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
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"ok": "false", "code": "bad_request", "error": "invalid json",
			})
			return
		}
		if err := protocol.GlobalConfig.Apply(u); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"ok": "false", "code": "bad_request", "error": err.Error(),
			})
			return
		}
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
	// Audit log (no secrets).
	fmt.Printf("[admin] connection %d closed by admin\n", id)
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
