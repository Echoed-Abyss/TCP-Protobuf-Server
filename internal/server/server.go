package server

import (
	"net"
	"sync"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/crypto"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/transport"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/trust"
)

// Server accepts TCP connections and runs the secure protocol handshake.
type Server struct {
	listener   net.Listener
	identity   *crypto.IdentityKey
	logger     *protocol.SensitiveLogger
	trustStore *trust.Store

	// OnConn is called for each successfully handshaken connection.
	OnConn func(c *transport.Conn)

	// active tracks handshaken connections keyed by connID.
	active   map[uint64]*transport.Conn
	activeMu sync.Mutex

	// gate enforces per-IP connection count and rate limits before the
	// handshake runs, preventing unauthenticated resource exhaustion.
	gate *connGate
}

// NewServer creates a server that will listen on addr.
func NewServer(identity *crypto.IdentityKey) *Server {
	return &Server{
		identity: identity,
		logger:   protocol.NewSensitiveLogger("[server] "),
		active:   make(map[uint64]*transport.Conn),
		gate:     newConnGate(DefaultMaxConnsPerIP, DefaultConnRatePerSec),
	}
}

// SetConnLimits configures the per-IP connection gate. maxConns is the
// maximum simultaneous connections per IP; ratePerSec is the maximum new
// connections per second per IP. Values <= 0 use defaults.
func (s *Server) SetConnLimits(maxConns, ratePerSec int) {
	s.gate = newConnGate(maxConns, ratePerSec)
}

// SetTrustStore enables TOFU / pinned-key verification for incoming clients.
// The client's remote address is used as the trust-store identifier.
func (s *Server) SetTrustStore(store *trust.Store) {
	s.trustStore = store
}

// Listen starts listening on the given address.
func (s *Server) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.logger.Printf("listening on %s", addr)
	return nil
}

// Serve accepts connections in a loop. Blocks until the listener is closed.
func (s *Server) Serve() error {
	if s.listener == nil {
		return protocol.ErrClosed
	}
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(raw)
	}
}

func (s *Server) handleConn(raw net.Conn) {
	// Per-IP connection + rate gate. Fail-closed: rejected connections are
	// closed immediately before any handshake work is done.
	release, ok := s.gate.Admit(raw.RemoteAddr())
	if !ok {
		_ = raw.Close()
		return
	}
	defer release()

	c := transport.NewConn(raw, s.identity, false)
	defer func() {
		s.activeMu.Lock()
		delete(s.active, c.ConnID())
		s.activeMu.Unlock()
		c.Close()
	}()

	if s.trustStore != nil {
		c.SetTrustStore(s.trustStore, raw.RemoteAddr().String())
	}

	if err := c.Handshake(); err != nil {
		protocol.GlobalMetrics.HandshakeFailed.Add(1)
		s.logger.Printf("handshake failed from %s: %v", raw.RemoteAddr(), err)
		return
	}
	protocol.GlobalMetrics.ConnectionsTotal.Add(1)
	s.activeMu.Lock()
	s.active[c.ConnID()] = c
	s.activeMu.Unlock()
	s.logger.Printf("client connected: %s", raw.RemoteAddr())

	if s.OnConn != nil {
		// OnConn owns the read loop (e.g. appapi.ServeConn calls
		// c.ReadLoop internally and blocks until the connection closes).
		// When it returns, the defer below closes the connection.
		s.OnConn(c)
	} else {
		// No OnConn: run the read loop directly so data is delivered
		// via the OnData callback (or dropped if unset).
		if err := c.ReadLoop(); err != nil {
			s.logger.Printf("connection closed: %v", err)
		}
	}
}

// Connections returns a redacted snapshot of all currently active
// (handshaken) connections.
func (s *Server) Connections() []protocol.ConnInfo {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	out := make([]protocol.ConnInfo, 0, len(s.active))
	for _, c := range s.active {
		out = append(out, protocol.ConnInfo{
			ID:        c.ConnID(),
			Peer:      c.PeerFingerprint(),
			Addr:      c.RemoteAddr().String(),
			Connected: c.ConnectedAt(),
			KeyID:     c.CurrentKeyID(),
			BytesSent: c.BytesSent(),
			BytesRecv: c.BytesRecv(),
		})
	}
	return out
}

// CloseConn closes the connection with the given ID. Returns true if a
// connection with that ID was found and closed.
func (s *Server) CloseConn(id uint64) bool {
	s.activeMu.Lock()
	c, ok := s.active[id]
	s.activeMu.Unlock()
	if !ok {
		return false
	}
	_ = c.Close()
	return true
}

// Close stops the server.
func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Addr returns the server's listen address.
func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}
