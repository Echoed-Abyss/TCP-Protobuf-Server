package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

// Key file format (passphrase-encrypted Ed25519 seed):
//
//	[16] salt          (scrypt salt)
//	[12] nonce         (AES-GCM nonce)
//	[..] ciphertext+tag (AES-256-GCM over the 32-byte seed)
//
// The 32-byte AES key is derived from the passphrase via scrypt with the
// salt. The seed is NEVER written to disk in plaintext.

const (
	keyFileSaltSize  = 16
	keyFileNonceSize = 12
	keyFileOverhead  = keyFileSaltSize + keyFileNonceSize // + AES-GCM tag (16)

	// scrypt parameters (interactive, OWASP-recommended).
	scryptN = 1 << 15 // 32768
	scryptR = 8
	scryptP = 1
)

var (
	// ErrEmptyPassphrase is returned when an empty passphrase is provided.
	// Empty passphrases are rejected because they provide no protection
	// beyond file-system permissions (which the file already has via 0600).
	ErrEmptyPassphrase = errors.New("passphrase must not be empty")

	// ErrBadKeyFile is returned when the encrypted key file is malformed
	// or decryption fails (wrong passphrase or tampering).
	ErrBadKeyFile = errors.New("invalid or corrupted key file (wrong passphrase?)")
)

// EncryptSeed encrypts an Ed25519 seed with a passphrase using
// scrypt-derived AES-256-GCM. Returns the file bytes.
func EncryptSeed(seed, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	salt := make([]byte, keyFileSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, seed, nil)

	out := make([]byte, 0, keyFileOverhead+len(ct))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// DecryptSeed decrypts a passphrase-encrypted seed file. Returns the 32-byte
// Ed25519 seed.
func DecryptSeed(data, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptyPassphrase
	}
	if len(data) < keyFileOverhead {
		return nil, ErrBadKeyFile
	}
	salt := data[:keyFileSaltSize]
	nonce := data[keyFileSaltSize : keyFileSaltSize+keyFileNonceSize]
	ct := data[keyFileSaltSize+keyFileNonceSize:]

	key, err := scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, ErrBadKeyFile
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrBadKeyFile
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrBadKeyFile
	}
	seed, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrBadKeyFile
	}
	return seed, nil
}

// SeedFingerprint returns a short, non-reversible fingerprint of a seed for
// logging/identification purposes. It uses SHA-256 truncated to 8 bytes so
// the actual seed material is never exposed.
func SeedFingerprint(seed []byte) string {
	h := sha256.Sum256(seed)
	return hex.EncodeToString(h[:8])
}
