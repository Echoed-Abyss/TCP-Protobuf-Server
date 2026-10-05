package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
)

// newTestAdmin creates an admin server with a fixed token and no
// connection manager for testing auth/CSRF middleware.
func newTestAdmin() *Server {
	return &Server{
		token:        "secret-token",
		authFailures: make(map[string]*authRecord),
	}
}

// TestAuthRejectsMissingToken verifies requests without a token get 401.
func TestAuthRejectsMissingToken(t *testing.T) {
	s := newTestAdmin()
	handler := s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin/stats", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// TestAuthRejectsWrongToken verifies wrong tokens get 401.
func TestAuthRejectsWrongToken(t *testing.T) {
	s := newTestAdmin()
	handler := s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin/stats", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// TestAuthAcceptsCorrectToken verifies the correct token is accepted.
func TestAuthAcceptsCorrectToken(t *testing.T) {
	s := newTestAdmin()
	handler := s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin/stats", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// TestAuthLockout verifies that repeated failures trigger a lockout.
func TestAuthLockout(t *testing.T) {
	s := newTestAdmin()
	handler := s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Send MaxAuthFailures wrong tokens.
	for i := 0; i < MaxAuthFailures; i++ {
		req := httptest.NewRequest("GET", "/admin/stats", nil)
		req.RemoteAddr = "127.0.0.1:5555"
		req.Header.Set("Authorization", "Bearer wrong")
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i, rec.Code)
		}
	}

	// Even with the correct token, the IP should now be locked out.
	req := httptest.NewRequest("GET", "/admin/stats", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 (locked out), got %d", rec.Code)
	}
	if protocol.GlobalMetrics.AdminRateLimited.Load() == 0 {
		t.Fatal("expected AdminRateLimited counter to be incremented")
	}
}

// TestCSRFHeaderRequired verifies that write requests without the
// X-Admin-Action header are rejected even with a valid token.
func TestCSRFHeaderRequired(t *testing.T) {
	s := newTestAdmin()
	handler := s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// PUT without X-Admin-Action header -> 403.
	req := httptest.NewRequest("PUT", "/admin/config", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for PUT without X-Admin-Action, got %d", rec.Code)
	}

	// PUT with the header -> 200.
	req2 := httptest.NewRequest("PUT", "/admin/config", nil)
	req2.RemoteAddr = "127.0.0.1:1234"
	req2.Header.Set("Authorization", "Bearer secret-token")
	req2.Header.Set("X-Admin-Action", "1")
	rec2 := httptest.NewRecorder()
	handler(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 for PUT with X-Admin-Action, got %d", rec2.Code)
	}
}

// TestFailClosedNoToken verifies that New refuses to create a server
// without a token.
func TestFailClosedNoToken(t *testing.T) {
	_, err := New("127.0.0.1:0", "", nil, StaticConfig{})
	if err == nil {
		t.Fatal("expected error when no token is provided")
	}
}

// TestLoopbackEnforcement verifies that New refuses non-loopback addresses.
func TestLoopbackEnforcement(t *testing.T) {
	_, err := New("0.0.0.0:9090", "token", nil, StaticConfig{})
	if err == nil {
		t.Fatal("expected error when binding to 0.0.0.0")
	}
}
