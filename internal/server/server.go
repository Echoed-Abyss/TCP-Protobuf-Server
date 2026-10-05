package server

import (
	"net"

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
}

// NewServer creates a server that will listen on addr.
func NewServer(identity *crypto.IdentityKey) *Server {
	return &Server{
		identity: identity,
		logger:   protocol.NewSensitiveLogger("[server] "),
	}
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
	c := transport.NewConn(raw, s.identity, false)
	defer c.Close()

	if s.trustStore != nil {
		c.SetTrustStore(s.trustStore, raw.RemoteAddr().String())
	}

	if err := c.Handshake(); err != nil {
		protocol.GlobalMetrics.HandshakeFailed.Add(1)
		s.logger.Printf("handshake failed from %s: %v", raw.RemoteAddr(), err)
		return
	}
	s.logger.Printf("client connected: %s", raw.RemoteAddr())

	if s.OnConn != nil {
		s.OnConn(c)
	}

	// Run the read loop until the connection closes.
	if err := c.ReadLoop(); err != nil {
		s.logger.Printf("connection closed: %v", err)
	}
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
