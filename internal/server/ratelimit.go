package server

import (
	"net"
	"sync"
	"time"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
)

// Default limits for the connection gate. These can be overridden via
// Server.SetConnLimits.
const (
	DefaultMaxConnsPerIP = 32
	DefaultConnRatePerSec = 16 // new connections per second per IP
)

// connGate enforces per-IP connection count and rate limits before the
// handshake runs. It prevents unauthenticated resource exhaustion (SYN
// flood / fd exhaustion / goroutine explosion).
//
// The gate is fail-closed: if it cannot determine the client IP or the
// rate limiter state is corrupt, the connection is rejected.
type connGate struct {
	mu          sync.Mutex
	conns       map[string]int       // ip -> active count
	tokens      map[string]*tokenBucket // ip -> rate limiter
	maxPerIP    int
	ratePerSec  int
}

// tokenBucket is a simple token-bucket rate limiter.
type tokenBucket struct {
	tokens   float64
	rate     float64 // tokens per second
	capacity float64
	last     time.Time
}

func newTokenBucket(ratePerSec, capacity int) *tokenBucket {
	return &tokenBucket{
		tokens:   float64(capacity),
		rate:     float64(ratePerSec),
		capacity: float64(capacity),
		last:     time.Now(),
	}
}

// allow returns true if a token is available (and consumes it).
func (b *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}

func newConnGate(maxPerIP, ratePerSec int) *connGate {
	if maxPerIP <= 0 {
		maxPerIP = DefaultMaxConnsPerIP
	}
	if ratePerSec <= 0 {
		ratePerSec = DefaultConnRatePerSec
	}
	return &connGate{
		conns:      make(map[string]int),
		tokens:     make(map[string]*tokenBucket),
		maxPerIP:   maxPerIP,
		ratePerSec: ratePerSec,
	}
}

// clientIP extracts the IP portion of a remote address.
func clientIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		// Fall back to the raw string if it isn't host:port.
		return addr.String()
	}
	return host
}

// Admit decides whether a new connection from addr should be accepted.
// If accepted, the per-IP count is incremented and the caller MUST call
// Release when the connection closes.
func (g *connGate) Admit(addr net.Addr) (release func(), ok bool) {
	ip := clientIP(addr)
	if ip == "" {
		// Cannot identify the client; fail-closed.
		protocol.GlobalMetrics.ConnRateLimited.Add(1)
		return func() {}, false
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Rate limit check (token bucket).
	tb, ok := g.tokens[ip]
	if !ok {
		tb = newTokenBucket(g.ratePerSec, g.ratePerSec)
		g.tokens[ip] = tb
	}
	if !tb.allow() {
		protocol.GlobalMetrics.ConnRateLimited.Add(1)
		return func() {}, false
	}

	// Per-IP connection count check.
	if g.conns[ip] >= g.maxPerIP {
		protocol.GlobalMetrics.ConnRateLimited.Add(1)
		return func() {}, false
	}
	g.conns[ip]++

	return func() {
		g.mu.Lock()
		g.conns[ip]--
		if g.conns[ip] <= 0 {
			delete(g.conns, ip)
		}
		g.mu.Unlock()
	}, true
}
