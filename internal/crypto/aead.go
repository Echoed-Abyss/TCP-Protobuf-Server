package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEADCipher wraps a Go crypto/cipher.AEAD with direction-specific nonce
// construction. The nonce is built as: noncePrefix(4) || seq(8, big-endian).
// This guarantees uniqueness per key as long as the sequence number does not
// wrap (impossible in practice with uint64).
type AEADCipher struct {
	aead        cipher.AEAD
	noncePrefix [4]byte
}

// NewAES256GCM creates an AES-256-GCM AEAD cipher with the given 32-byte key
// and 4-byte nonce prefix.
func NewAES256GCM(key []byte, noncePrefix []byte) (*AEADCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	c := &AEADCipher{aead: gcm}
	copy(c.noncePrefix[:], noncePrefix)
	return c, nil
}

// NewChaCha20Poly1305 creates a ChaCha20-Poly1305 AEAD cipher with the given
// 32-byte key and 4-byte nonce prefix.
func NewChaCha20Poly1305(key []byte, noncePrefix []byte) (*AEADCipher, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	c := &AEADCipher{aead: aead}
	copy(c.noncePrefix[:], noncePrefix)
	return c, nil
}

// NonceSize returns the AEAD nonce size.
func (c *AEADCipher) NonceSize() int { return c.aead.NonceSize() }

// Overhead returns the authentication tag size appended to ciphertext.
func (c *AEADCipher) Overhead() int { return c.aead.Overhead() }

// nonceForSeq builds a 12-byte nonce from the prefix and sequence number.
func (c *AEADCipher) nonceForSeq(seq uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[0:4], c.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:12], seq)
	return nonce
}

// Encrypt encrypts plaintext with the given seq and AAD.
// Returns ciphertext||tag.
func (c *AEADCipher) Encrypt(seq uint64, plaintext, aad []byte) []byte {
	nonce := c.nonceForSeq(seq)
	return c.aead.Seal(nil, nonce[:], plaintext, aad)
}

// Decrypt decrypts ciphertext (which includes the tag) with the given seq
// and AAD. Returns an error if authentication fails.
func (c *AEADCipher) Decrypt(seq uint64, ciphertext, aad []byte) ([]byte, error) {
	nonce := c.nonceForSeq(seq)
	return c.aead.Open(nil, nonce[:], ciphertext, aad)
}
