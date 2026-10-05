package server

import (
	"net"
	"testing"
)

// TestConnGateMaxConns verifies that a single IP cannot exceed the
// configured simultaneous connection limit.
func TestConnGateMaxConns(t *testing.T) {
	g := newConnGate(2, 100) // 2 conns per IP, high rate

	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}

	// First two should be admitted.
	rel1, ok := g.Admit(addr)
	if !ok {
		t.Fatal("first conn should be admitted")
	}
	rel2, ok := g.Admit(addr)
	if !ok {
		t.Fatal("second conn should be admitted")
	}
	defer rel1()
	defer rel2()

	// Third should be rejected (over limit).
	_, ok = g.Admit(addr)
	if ok {
		t.Fatal("third conn should be rejected (over limit)")
	}

	// Release one and try again: should be admitted.
	rel1()
	_, ok = g.Admit(addr)
	if !ok {
		t.Fatal("conn should be admitted after release")
	}
}

// TestConnGateRateLimit verifies that new connections per IP are rate-limited.
func TestConnGateRateLimit(t *testing.T) {
	g := newConnGate(100, 1) // 1 conn/sec rate, high conn count

	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 12345}

	// First conn uses the single token.
	rel, ok := g.Admit(addr)
	if !ok {
		t.Fatal("first conn should be admitted")
	}
	defer rel()

	// Second should be rate-limited (no tokens left).
	_, ok = g.Admit(addr)
	if ok {
		t.Fatal("second conn should be rate-limited")
	}
}

// TestConnGateUnknownIP verifies that connections without a parseable IP
// are rejected (fail-closed).
func TestConnGateUnknownIP(t *testing.T) {
	g := newConnGate(10, 10)
	_, ok := g.Admit(nil)
	if ok {
		t.Fatal("nil address should be rejected (fail-closed)")
	}
}
