package client

import (
	"net"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/crypto"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/transport"
)

// Client dials a server and runs the secure handshake.
type Client struct {
	identity *crypto.IdentityKey
	peerID   []byte
	logger   *protocol.SensitiveLogger
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
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	c.logger.Printf("connected to %s", addr)
	return conn, nil
}
