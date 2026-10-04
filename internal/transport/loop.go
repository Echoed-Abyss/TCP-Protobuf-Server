package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
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
//
// All security failures are wrapped into a generic public error and subject
// to the constant failure delay, so callers cannot distinguish failure modes.
func (c *Conn) ReadLoop() error {
	for {
		if c.isClosed() {
			return protocol.ErrClosed
		}
		sess := c.getSession()
		if sess == nil {
			return c.fail(protocol.ErrNotReady)
		}

		f, err := c.readFrame()
		if err != nil {
			// Network errors / EOF: not security-sensitive, return as-is.
			return err
		}

		if err := c.dispatchFrame(f, sess); err != nil {
			if errors.Is(err, protocol.ErrClosed) {
				return err
			}
			return c.fail(err)
		}
	}
}

// dispatchFrame handles a single received frame.
func (c *Conn) dispatchFrame(f *protocol.Frame, sess *session.Session) error {
	protocol.GlobalMetrics.FramesReceived.Add(1)

	// Replay + time-window checks before decryption.
	if !sess.CheckReplay(f.Seq) {
		protocol.GlobalMetrics.ReplayRejected.Add(1)
		return protocol.ErrReplay
	}
	if !c.checkTimeWindow(f, time.Duration(protocol.DataTimeWindow)) {
		protocol.GlobalMetrics.ExpiredRejected.Add(1)
		return protocol.ErrExpired
	}

	aad := aadFor(f, sess.SessionID())
	padded, err := sess.Decrypt(f.Seq, f.Payload, aad)
	if err != nil {
		protocol.GlobalMetrics.DecryptFailed.Add(1)
		return protocol.ErrDecryptFailed
	}
	plaintext, err := protocol.UnpadWithPrefix(padded)
	if err != nil {
		protocol.GlobalMetrics.DecryptFailed.Add(1)
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
	case protocol.MsgTypeDummy:
		// Cover traffic; ignore the payload.
	case protocol.MsgTypeRekey:
		if err := c.handleRekey(plaintext); err != nil {
			return err
		}
	case protocol.MsgTypeRenegClientHello,
		protocol.MsgTypeRenegServerHello,
		protocol.MsgTypeRenegServerProof,
		protocol.MsgTypeRenegClientFinished,
		protocol.MsgTypeRenegServerFinished:
		if err := c.handleRenegotiationFrame(f.MsgType, plaintext); err != nil {
			return err
		}
	case protocol.MsgTypeAlert:
		// Peer sent an alert; close the connection.
		return protocol.ErrClosed
	default:
		// Unknown message type; drop silently.
	}
	return nil
}

// startHeartbeat starts the heartbeat goroutine. It sends a heartbeat frame
// every HeartbeatInterval, checks session key expiry (triggers PFS
// renegotiation), and periodically sends dummy/cover frames with jitter.
func (c *Conn) startHeartbeat() {
	c.heartbeatWg.Add(1)
	go c.heartbeatLoop()
}

func (c *Conn) heartbeatLoop() {
	defer c.heartbeatWg.Done()
	hbTicker := time.NewTicker(time.Duration(protocol.HeartbeatInterval))
	defer hbTicker.Stop()

	dummyTimer := time.NewTimer(c.nextDummyDelay())
	defer dummyTimer.Stop()

	for {
		select {
		case <-c.heartbeatStop:
			return
		case <-hbTicker.C:
			// Check session key TTL; trigger full renegotiation (PFS)
			// when expired. Full renegotiation uses fresh X25519 keys so
			// the new session is forward-secret.
			sess := c.getSession()
			if sess != nil && sess.IsExpired(time.Duration(protocol.SessionKeyTTL)) {
				if err := c.InitiateRenegotiate(); err != nil {
					// Renegotiation failed (e.g. key_id exhaustion or
					// peer non-cooperation). Close so the peer reconnects
					// with a completely fresh handshake.
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
		case <-dummyTimer.C:
			// Send a dummy/cover frame to obfuscate traffic timing.
			if err := c.sendDummyFrame(); err != nil {
				c.Close()
				return
			}
			dummyTimer.Reset(c.nextDummyDelay())
		}
	}
}

// nextDummyDelay returns a randomized delay for the next dummy frame.
// Base interval ± jitter, clamped to >= 1ms.
func (c *Conn) nextDummyDelay() time.Duration {
	base := protocol.DummyFrameInterval
	jitter := protocol.DummyFrameJitter
	if base == 0 {
		// Dummy frames disabled; return a very long duration.
		return time.Duration(1<<63 - 1)
	}
	// random in [-jitter, +jitter]
	r := randomInt63n(jitter*2) - jitter
	d := base + r
	if d < 1e6 { // at least 1ms
		d = 1e6
	}
	return time.Duration(d)
}

// sendDummyFrame sends a cover-traffic frame with random payload.
func (c *Conn) sendDummyFrame() error {
	payload := randomBytes(protocol.DefaultDummyPayloadSize)
	return c.writeEncrypted(protocol.MsgTypeDummy, payload)
}

// randomInt63n returns a pseudo-random int64 in [0, n) using crypto/rand.
func randomInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return 0
	}
	// Use the lower 63 bits.
	v := int64(binary.BigEndian.Uint64(b) & 0x7FFFFFFFFFFFFFFF)
	return v % n
}

// InitiateRekey starts a key rotation. It mixes fresh randomness into the
// traffic secret via HKDF to derive new session keys, then sends a Rekey
// frame. The peer rotates to the same new keys.
//
// Security note: rekey uses HKDF(old_traffic_secret || new_random) to derive
// the new traffic secret. This is NOT a fresh X25519 exchange, so it does not
// provide post-compromise forward secrecy (if old_traffic_secret is leaked,
// new keys can be derived). For full forward secrecy, perform a complete
// re-handshake instead. Rekey is used for key lifetime / nonce-space
// management, not forward secrecy.
//
// If key_id has reached MaxKeyID, this returns ErrRekeyOverflow and the
// caller must close the connection and re-establish via a fresh handshake.
func (c *Conn) InitiateRekey() error {
	sess := c.getSession()
	if sess == nil {
		return protocol.ErrNotReady
	}

	// Check before doing any work: if key_id is exhausted, refuse.
	if sess.KeyID() >= protocol.MaxKeyID {
		return protocol.ErrRekeyOverflow
	}

	newRandom := randomBytes(32)
	prevTS := sess.TrafficSecret()

	newKeys, err := crypto.DeriveRekeyKeys(prevTS, newRandom)
	if err != nil {
		return err
	}

	// Send Rekey frame with the new random (encrypted with current key).
	rk := &secpb.Rekey{
		NewKeyId:  uint32(sess.KeyID() + 1),
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
