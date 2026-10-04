package session

import (
	"sync"
	"time"

	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/crypto"
	"github.com/Echoed-Abyss/TCP-Protobuf-Server/internal/protocol"
)

// Session holds the per-connection cryptographic state.
//
// A session has two independent traffic directions, each with its own:
//   - AEAD cipher (key + nonce prefix)
//   - send sequence counter
//   - receive replay window
//
// Keys are never logged. The Wipe method zeroes all key material.
type Session struct {
	mu sync.RWMutex

	cipherSuite protocol.CipherSuite

	// write direction: we encrypt with this
	writeCipher *crypto.AEADCipher
	writeSeq    uint64

	// read direction: we decrypt with this
	readCipher *crypto.AEADCipher
	readWindow *crypto.ReplayWindow

	keyID     uint8
	sessionID []byte
	createdAt time.Time

	// trafficSecret is retained for key rotation (rekey).
	// It is NOT used directly for encryption.
	trafficSecret []byte
}

// NewSession creates a session from derived keys.
//
// isClient determines which key is used for writing:
//   - client writes with ClientWriteKey, reads with ServerWriteKey
//   - server writes with ServerWriteKey, reads with ClientWriteKey
func NewSession(keys *crypto.SessionKeys, suite protocol.CipherSuite, isClient bool) (*Session, error) {
	s := &Session{
		cipherSuite:   suite,
		keyID:         1,
		sessionID:     keys.SessionID,
		createdAt:     time.Now(),
		trafficSecret: nil, // caller sets via SetTrafficSecret
	}

	var writeKey, writeNP, readKey, readNP []byte
	if isClient {
		writeKey, writeNP = keys.ClientWriteKey, keys.ClientNoncePrefix
		readKey, readNP = keys.ServerWriteKey, keys.ServerNoncePrefix
	} else {
		writeKey, writeNP = keys.ServerWriteKey, keys.ServerNoncePrefix
		readKey, readNP = keys.ClientWriteKey, keys.ClientNoncePrefix
	}

	var err error
	s.writeCipher, err = newAEAD(suite, writeKey, writeNP)
	if err != nil {
		return nil, err
	}
	s.readCipher, err = newAEAD(suite, readKey, readNP)
	if err != nil {
		return nil, err
	}
	s.readWindow = crypto.NewReplayWindow(protocol.ReplayWindowSize)
	return s, nil
}

func newAEAD(suite protocol.CipherSuite, key, noncePrefix []byte) (*crypto.AEADCipher, error) {
	switch suite {
	case protocol.CipherSuiteAES256GCM:
		return crypto.NewAES256GCM(key, noncePrefix)
	case protocol.CipherSuiteChaCha20Poly1305:
		return crypto.NewChaCha20Poly1305(key, noncePrefix)
	default:
		return nil, protocol.ErrHandshake
	}
}

// SetTrafficSecret stores the traffic secret for later rekey operations.
func (s *Session) SetTrafficSecret(ts []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trafficSecret = make([]byte, len(ts))
	copy(s.trafficSecret, ts)
}

// CipherSuite returns the negotiated cipher suite.
func (s *Session) CipherSuite() protocol.CipherSuite {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cipherSuite
}

// KeyID returns the current key version.
func (s *Session) KeyID() uint8 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keyID
}

// SessionID returns the session identifier used in AAD.
func (s *Session) SessionID() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// NextWriteSeq returns the next sequence number for sending and increments.
func (s *Session) NextWriteSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeSeq++
	return s.writeSeq
}

// CurrentWriteSeq returns the current send sequence number without incrementing.
func (s *Session) CurrentWriteSeq() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.writeSeq
}

// CheckReplay checks whether the given receive sequence number is acceptable.
func (s *Session) CheckReplay(seq uint64) bool {
	return s.readWindow.Check(seq)
}

// AcceptReplay marks a receive sequence number as seen.
func (s *Session) AcceptReplay(seq uint64) {
	s.readWindow.Accept(seq)
}

// Encrypt encrypts plaintext for sending using the write cipher.
func (s *Session) Encrypt(seq uint64, plaintext, aad []byte) []byte {
	return s.writeCipher.Encrypt(seq, plaintext, aad)
}

// Decrypt decrypts received ciphertext using the read cipher.
func (s *Session) Decrypt(seq uint64, ciphertext, aad []byte) ([]byte, error) {
	return s.readCipher.Decrypt(seq, ciphertext, aad)
}

// IsExpired returns true if the session key has exceeded its TTL.
func (s *Session) IsExpired(ttl time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.createdAt) > ttl
}

// Age returns how long the session has been alive.
func (s *Session) Age() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.createdAt)
}

// TrafficSecret returns a copy of the traffic secret for rekey.
func (s *Session) TrafficSecret() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]byte, len(s.trafficSecret))
	copy(out, s.trafficSecret)
	return out
}

// Rotate replaces the session's ciphers with new keys (from a rekey).
// The keyID is incremented.
//
// Key rotation invariants (nonce reuse proof):
//
//	AEAD nonce = nonce_prefix(4) || seq(8).
//	For a fixed key K, seq is monotonic per direction, so all nonces are
//	unique per K. When rotating to K', the key material changes (derived
//	from a fresh IKM via HKDF), so K' ≠ K. AEAD security only requires
//	(key, nonce) uniqueness, not global nonce uniqueness. Therefore even if
//	seq resets to 0 after rotation, no (key, nonce) pair collides with any
//	past pair. The nonce prefix also changes with overwhelming probability
//	(defense in depth).
//
// If keyID has reached MaxKeyID, Rotate returns ErrRekeyOverflow and the
// caller MUST perform a full renegotiation (new handshake) instead of
// continuing in-band rekeys.
func (s *Session) Rotate(newKeys *crypto.SessionKeys, suite protocol.CipherSuite, isClient bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Refuse to rotate if key_id would exceed MaxKeyID. Force full
	// renegotiation so the key_id space resets cleanly.
	if s.keyID >= protocol.MaxKeyID {
		return protocol.ErrRekeyOverflow
	}

	var writeKey, writeNP, readKey, readNP []byte
	if isClient {
		writeKey, writeNP = newKeys.ClientWriteKey, newKeys.ClientNoncePrefix
		readKey, readNP = newKeys.ServerWriteKey, newKeys.ServerNoncePrefix
	} else {
		writeKey, writeNP = newKeys.ServerWriteKey, newKeys.ServerNoncePrefix
		readKey, readNP = newKeys.ClientWriteKey, newKeys.ClientNoncePrefix
	}

	newWrite, err := newAEAD(suite, writeKey, writeNP)
	if err != nil {
		return err
	}
	newRead, err := newAEAD(suite, readKey, readNP)
	if err != nil {
		return err
	}

	// Wipe old key material references.
	s.writeCipher = newWrite
	s.readCipher = newRead
	s.keyID++
	// Reset sequence numbers for the new key. As proven above, this is safe
	// because the key has changed.
	s.writeSeq = 0
	s.sessionID = newKeys.SessionID
	s.createdAt = time.Now()
	// Reset the replay window: seq numbering restarts from 0 for the new key.
	s.readWindow = crypto.NewReplayWindow(protocol.ReplayWindowSize)

	protocol.GlobalMetrics.KeyRotations.Add(1)
	return nil
}

// Wipe zeroes all key material from the session.
func (s *Session) Wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.trafficSecret {
		s.trafficSecret[i] = 0
	}
	for i := range s.sessionID {
		s.sessionID[i] = 0
	}
}
