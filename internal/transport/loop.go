package transport

import (
	"time"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/crypto"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/proto/secpb"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/session"

	"google.golang.org/protobuf/proto"
)

// ReadLoop continuously reads frames from the connection and dispatches them.
// It returns when the connection is closed or an unrecoverable error occurs.
//
// Application data is delivered via the OnData callback.
// Heartbeat and Rekey frames are handled internally.
func (c *Conn) ReadLoop() error {
	for {
		if c.isClosed() {
			return protocol.ErrClosed
		}
		sess := c.getSession()
		if sess == nil {
			return protocol.ErrNotReady
		}

		f, err := c.readFrame()
		if err != nil {
			return err
		}

		if err := c.dispatchFrame(f, sess); err != nil {
			return err
		}
	}
}

// dispatchFrame handles a single received frame.
func (c *Conn) dispatchFrame(f *protocol.Frame, sess *session.Session) error {
	// Replay + time-window checks before decryption.
	if !sess.CheckReplay(f.Seq) {
		return protocol.ErrReplay
	}
	if !checkTimeWindow(f, time.Duration(protocol.DataTimeWindow)) {
		return protocol.ErrExpired
	}

	aad := aadFor(f, sess.SessionID())
	plaintext, err := sess.Decrypt(f.Seq, f.Payload, aad)
	if err != nil {
		return protocol.ErrDecryptFailed
	}
	sess.AcceptReplay(f.Seq)

	switch f.MsgType {
	case protocol.MsgTypeData:
		if c.onData != nil {
			c.onData(plaintext)
		}
	case protocol.MsgTypeHeartbeat:
		// Heartbeat received; nothing to do. The peer is alive.
	case protocol.MsgTypeRekey:
		if err := c.handleRekey(plaintext); err != nil {
			return err
		}
	case protocol.MsgTypeAlert:
		// Peer sent an alert; close the connection.
		return protocol.ErrClosed
	default:
		// Unknown message type; drop.
	}
	return nil
}

// startHeartbeat starts the heartbeat goroutine. It sends a heartbeat frame
// every HeartbeatInterval and checks session key expiry.
func (c *Conn) startHeartbeat() {
	c.heartbeatWg.Add(1)
	go c.heartbeatLoop()
}

func (c *Conn) heartbeatLoop() {
	defer c.heartbeatWg.Done()
	ticker := time.NewTicker(time.Duration(protocol.HeartbeatInterval))
	defer ticker.Stop()

	for {
		select {
		case <-c.heartbeatStop:
			return
		case <-ticker.C:
			// Check session key TTL; rekey if expired.
			sess := c.getSession()
			if sess != nil && sess.IsExpired(time.Duration(protocol.SessionKeyTTL)) {
				if err := c.InitiateRekey(); err != nil {
					c.Close()
					return
				}
				continue
			}
			// Send heartbeat.
			if err := c.writeEncrypted(protocol.MsgTypeHeartbeat, nil); err != nil {
				c.Close()
				return
			}
		}
	}
}

// InitiateRekey starts a key rotation. It generates a new ephemeral key,
// derives new keys, and sends a Rekey frame. The peer must also rotate.
//
// Rekey protocol:
//   1. Initiator generates new ephemeral key + random, sends Rekey{new_pubkey, new_random}
//   2. Both sides compute new shared secret = X25519(new_priv, peer's old or new pub?) 
//
// For simplicity and security, rekey uses the existing session's traffic
// secret mixed with new randomness (no new ECDH round-trip needed). This
// provides forward-security-like key evolution without an extra handshake.
//
// Actually, to maintain forward secrecy properly, we do a fresh X25519.
// But that requires exchanging new ephemeral keys. Let's do the simpler
// HKDF-based rekey: new_traffic_secret = HKDF(old_traffic_secret || new_random).
// This is secure as long as old_traffic_secret is not compromised.
func (c *Conn) InitiateRekey() error {
	sess := c.getSession()
	if sess == nil {
		return protocol.ErrNotReady
	}

	newRandom := randomBytes(32)
	prevTS := sess.TrafficSecret()

	newKeys, err := crypto.DeriveRekeyKeys(prevTS, newRandom)
	if err != nil {
		return err
	}

	// Send Rekey frame with the new random (encrypted with current key).
	rk := &secpb.Rekey{
		NewKeyId: uint32(sess.KeyID() + 1),
		NewRandom: newRandom,
	}
	rkBytes, err := proto.Marshal(rk)
	if err != nil {
		return err
	}
	if err := c.writeEncrypted(protocol.MsgTypeRekey, rkBytes); err != nil {
		return err
	}

	// Rotate our keys immediately after sending.
	return sess.Rotate(newKeys, sess.CipherSuite(), c.isClient)
}

// handleRekey processes an incoming Rekey frame and rotates keys.
func (c *Conn) handleRekey(plaintext []byte) error {
	sess := c.getSession()
	if sess == nil {
		return protocol.ErrNotReady
	}

	rk := &secpb.Rekey{}
	if err := proto.Unmarshal(plaintext, rk); err != nil {
		return protocol.ErrHandshake
	}
	if len(rk.NewRandom) != 32 {
		return protocol.ErrHandshake
	}

	prevTS := sess.TrafficSecret()
	newKeys, err := crypto.DeriveRekeyKeys(prevTS, rk.NewRandom)
	if err != nil {
		return err
	}

	return sess.Rotate(newKeys, sess.CipherSuite(), c.isClient)
}
