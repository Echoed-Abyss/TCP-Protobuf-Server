package client

import (
	"net"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/crypto"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/transport"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/trust"
)

// Client dials a server and runs the secure handshake.
type Client struct {
	identity   *crypto.IdentityKey
	peerID     []byte
	trustStore *trust.Store
	logger     *protocol.SensitiveLogger
}

// NewClient creates a client with the given identity key.
func NewClient(identity *crypto.IdentityKey) *Client {
	return &Client{
		identity: identity,
		logger:   protocol.NewSensitiveLogger("[client] "),
	}
}

// SetPeerID pins the expected server identity public key.
func (c *Client) SetPeerID(pub []byte) {
	c.peerID = pub
}

// SetTrustStore enables TOFU verification of the server's identity key.
// The dial address is used as the trust-store identifier.
func (c *Client) SetTrustStore(store *trust.Store) {
	c.trustStore = store
}

// Dial connects to addr and completes the handshake.
func (c *Client) Dial(addr string) (*transport.Conn, error) {
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := transport.NewConn(raw, c.identity, true)
	if c.peerID != nil {
		conn.SetPeerID(c.peerID)
	}
	if c.trustStore != nil {
		conn.SetTrustStore(c.trustStore, addr)
	}
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	c.logger.Printf("connected to %s", addr)
	return conn, nil
}
