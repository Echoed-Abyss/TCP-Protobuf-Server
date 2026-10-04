package transport

import (
	"bufio"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/crypto"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/session"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/trust"
)

// Conn is a secure, authenticated TCP connection.
//
// It wraps a net.Conn and provides:
//   - Mutual authentication via Ed25519-signed handshake
//   - X25519 key exchange + HKDF key derivation
//   - AEAD-encrypted frames (AES-256-GCM or ChaCha20-Poly1305)
//   - Per-direction sequence numbers and replay protection
//   - Heartbeat keepalive
//   - Key rotation (rekey)
type Conn struct {
	raw     net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex

	identity *crypto.IdentityKey
	peerID   []byte // peer's Ed25519 public key, set after handshake

	session   *session.Session
	sessionMu sync.RWMutex

	isClient bool

	handshakeDone bool
	handshakeMu   sync.Mutex

	closed   bool
	closedMu sync.Mutex

	// heartbeat
	heartbeatStop chan struct{}
	heartbeatWg   sync.WaitGroup

	// callbacks
	onData func(data []byte)

	// timeouts applied to every read/write.
	readTimeout  time.Duration
	writeTimeout time.Duration

	// failureDelay is a constant delay applied before returning any security
	// failure (replay, expired, decrypt failed, handshake failed). It makes
	// failure modes harder to distinguish by timing.
	failureDelay time.Duration

	// trust store for TOFU / pinned peer identity verification.
	trustStore     *trust.Store
	peerIdentifier string // label used in the trust store (e.g. dial address)
}

// NewConn wraps an existing net.Conn. The identity key is used for
// authentication. isClient determines the handshake role.
func NewConn(raw net.Conn, identity *crypto.IdentityKey, isClient bool) *Conn {
	return &Conn{
		raw:           raw,
		reader:        bufio.NewReaderSize(raw, 64*1024),
		identity:      identity,
		isClient:      isClient,
		heartbeatStop: make(chan struct{}),
		readTimeout:   30 * time.Second,
		writeTimeout:  10 * time.Second,
		failureDelay:  5 * time.Millisecond,
	}
}

// SetOnData registers a callback for received application data.
func (c *Conn) SetOnData(fn func(data []byte)) {
	c.onData = fn
}

// SetPeerID pins the expected peer identity public key. If set, the
// handshake will reject any peer presenting a different key.
func (c *Conn) SetPeerID(pub []byte) {
	c.peerID = make([]byte, len(pub))
	copy(c.peerID, pub)
}

// SetTrustStore configures TOFU / pinned-key verification for this
// connection. identifier is the label under which the peer's key is stored
// (e.g. the dial address for clients).
func (c *Conn) SetTrustStore(store *trust.Store, identifier string) {
	c.trustStore = store
	c.peerIdentifier = identifier
}

// verifyPeerTrust checks the peer's identity key against the trust store
// (if configured) and the pinned peerID. Returns ErrHandshake on mismatch.
func (c *Conn) verifyPeerTrust(peerPub []byte) error {
	if c.peerID != nil && !crypto.SecureEqual(peerPub, c.peerID) {
		return protocol.ErrHandshake
	}
	if c.trustStore != nil && c.peerIdentifier != "" {
		if err := c.trustStore.VerifyOrTrust(c.peerIdentifier, peerPub); err != nil {
			// Trust mismatch: possible MITM or rotation. Map to handshake error
			// so the external error stays generic.
			return protocol.ErrHandshake
		}
	}
	return nil
}

// RemoteAddr returns the remote address.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// LocalAddr returns the local address.
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }

// isClosed returns whether the connection is closed.
func (c *Conn) isClosed() bool {
	c.closedMu.Lock()
	defer c.closedMu.Unlock()
	return c.closed
}

// Close closes the underlying connection and stops the heartbeat.
func (c *Conn) Close() error {
	c.closedMu.Lock()
	if c.closed {
		c.closedMu.Unlock()
		return nil
	}
	c.closed = true
	c.closedMu.Unlock()

	close(c.heartbeatStop)
	c.heartbeatWg.Wait()
	c.sessionMu.Lock()
	if c.session != nil {
		c.session.Wipe()
	}
	c.sessionMu.Unlock()
	return c.raw.Close()
}

// writeFrame writes a frame to the wire, applying a write timeout.
func (c *Conn) writeFrame(f *protocol.Frame) error {
	if c.isClosed() {
		return protocol.ErrClosed
	}
	data := f.Marshal()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.raw.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	_, err := c.raw.Write(data)
	return err
}

// readFrame reads a complete frame from the wire, applying a read timeout.
func (c *Conn) readFrame() (*protocol.Frame, error) {
	if c.isClosed() {
		return nil, protocol.ErrClosed
	}
	_ = c.raw.SetReadDeadline(time.Now().Add(c.readTimeout))
	return protocol.ReadFrame(c.reader)
}

// getSession returns the current session (nil if handshake not done).
func (c *Conn) getSession() *session.Session {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.session
}

// aadFor builds the AAD for a frame: header bytes || session_id.
// The session_id binds the frame to this exact session, preventing
// cross-session replay.
func aadFor(f *protocol.Frame, sessionID []byte) []byte {
	hdr := f.HeaderBytes()
	aad := make([]byte, len(hdr)+len(sessionID))
	copy(aad, hdr)
	copy(aad[len(hdr):], sessionID)
	return aad
}

// writeEncrypted encrypts the given message type + payload and sends it.
func (c *Conn) writeEncrypted(msgType protocol.MsgType, payload []byte) error {
	sess := c.getSession()
	if sess == nil {
		return protocol.ErrNotReady
	}

	seq := sess.NextWriteSeq()
	// Build the frame first so the AAD binds to the exact header bytes
	// (including timestamp) that will be transmitted.
	f := protocol.NewFrame(msgType, sess.KeyID(), seq, nil, nil)
	aad := aadFor(f, sess.SessionID())

	ciphertext := sess.Encrypt(seq, payload, aad)
	f.Payload = ciphertext
	// Populate the nonce field with the deterministic nonce for explicitness.
	copy(f.Nonce[:], deriveNonceBytes(seq))

	return c.writeFrame(f)
}

// deriveNonceBytes returns the 12-byte nonce for the given seq.
// The actual AEAD nonce is computed internally by the cipher as
// prefix(4) || seq_be(8). Here we encode seq in the last 8 bytes for
// debugging aid; the transmitted value is informational since the
// receiver recomputes the nonce from seq.
func deriveNonceBytes(seq uint64) []byte {
	nonce := make([]byte, 12)
	nonce[4] = byte(seq >> 56)
	nonce[5] = byte(seq >> 48)
	nonce[6] = byte(seq >> 40)
	nonce[7] = byte(seq >> 32)
	nonce[8] = byte(seq >> 24)
	nonce[9] = byte(seq >> 16)
	nonce[10] = byte(seq >> 8)
	nonce[11] = byte(seq)
	return nonce
}

// SendData sends application data (encrypted).
func (c *Conn) SendData(data []byte) error {
	if err := c.writeEncrypted(protocol.MsgTypeData, data); err != nil {
		return c.fail(err)
	}
	return nil
}

// fail applies the constant failure delay and wraps the internal error into
// a generic public error so callers (and remote peers) cannot distinguish
// failure modes. Network/EOF errors are returned as-is since they carry no
// security-relevant detail.
func (c *Conn) fail(internalErr error) error {
	if internalErr == nil {
		return nil
	}
	if c.failureDelay > 0 {
		time.Sleep(c.failureDelay)
	}
	return protocol.NewPublicError(internalErr)
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err) // crypto/rand should never fail
	}
	return b
}

// checkTimeWindow verifies the frame timestamp is within the allowed skew.
func checkTimeWindow(f *protocol.Frame, maxSkew time.Duration) bool {
	now := time.Now().UnixNano()
	ts := int64(f.Timestamp)
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	return diff <= maxSkew.Nanoseconds()
}

// ErrNotReady is returned when the connection hasn't completed the handshake.
var ErrNotReady = errors.New("connection not ready")
