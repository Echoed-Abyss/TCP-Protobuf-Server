package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"io"

	"golang.org/x/crypto/curve25519"
)

// IdentityKey is a long-term Ed25519 key pair used for authentication
// (signing the handshake transcript). It is NEVER used for data encryption.
type IdentityKey struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateIdentity creates a new Ed25519 identity key pair using a
// cryptographically secure random source.
func GenerateIdentity() (*IdentityKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &IdentityKey{Public: pub, Private: priv}, nil
}

// Sign produces an Ed25519 signature over the given message.
func (k *IdentityKey) Sign(msg []byte) []byte {
	return ed25519.Sign(k.Private, msg)
}

// VerifySignature verifies an Ed25519 signature against the given public key.
// Returns true only if the signature is valid. Uses constant-time comparison
// internally (ed25519.Verify already does this).
func VerifySignature(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// EphemeralKey is a per-handshake X25519 key pair used for key exchange.
// It is generated fresh for every handshake and discarded afterwards.
type EphemeralKey struct {
	Public  [32]byte
	private [32]byte
}

// GenerateEphemeral creates a new X25519 ephemeral key pair.
func GenerateEphemeral() (*EphemeralKey, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	ek := &EphemeralKey{private: priv}
	copy(ek.Public[:], pub)
	// Zero the private scalar copy where possible.
	return ek, nil
}

// SharedSecret computes the X25519 shared secret between our private key and
// the peer's public key. The raw output is NOT suitable for direct use as a
// key and MUST be passed through HKDF.
func (k *EphemeralKey) SharedSecret(peerPub [32]byte) ([]byte, error) {
	secret, err := curve25519.X25519(k.private[:], peerPub[:])
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// Wipe zeroes the ephemeral private key from memory.
func (k *EphemeralKey) Wipe() {
	for i := range k.private {
		k.private[i] = 0
	}
}

// SecureEqual performs a constant-time comparison of two byte slices.
func SecureEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
