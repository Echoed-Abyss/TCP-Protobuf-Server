// Package trust implements a Trust-On-First-Use (TOFU) store for peer
// Ed25519 identity public keys.
//
// The store maps a peer identifier (typically the dial address for clients,
// or any stable label) to a pinned Ed25519 public key. On first encounter
// the key is saved; on subsequent encounters it must match, otherwise the
// connection is rejected (potential MITM).
//
// The store is backed by a JSON file with mode 0600. It never stores private
// keys.
package trust

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// ErrPeerKeyMismatch is returned when a peer presents a public key that
// differs from the previously pinned key. This indicates a potential MITM
// attack or a legitimate key rotation.
var ErrPeerKeyMismatch = errors.New("peer identity key mismatch (possible MITM or key rotation)")

// Store is a TOFU trust store.
type Store struct {
	mu       sync.Mutex
	path     string
	entries  map[string]string // identifier -> hex(public key)
	pinned   map[string]string // identifier -> hex(public key), takes precedence (from config)
}

// NewStore loads a trust store from path. If the file does not exist, an
// empty store is created (and persisted on first write).
func NewStore(path string) (*Store, error) {
	s := &Store{
		path:    path,
		entries: make(map[string]string),
		pinned:  make(map[string]string),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// SetPinned registers a compile-time/configuration-pinned key for an
// identifier. Pinned keys take precedence over TOFU entries and are never
// overwritten.
func (s *Store) SetPinned(identifier string, pubKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pinned[identifier] = hex.EncodeToString(pubKey)
}

// VerifyOrTrust checks whether pubKey matches the stored key for identifier.
//
//   - If a pinned key is set, pubKey MUST match it (no automatic trust).
//   - If no entry exists, the key is trusted and saved (TOFU).
//   - If an entry exists, pubKey MUST match it.
//
// Returns nil on success, ErrPeerKeyMismatch on mismatch.
func (s *Store) VerifyOrTrust(identifier string, pubKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hexKey := hex.EncodeToString(pubKey)

	// Pinned key always wins.
	if pinned, ok := s.pinned[identifier]; ok {
		if pinned != hexKey {
			return fmt.Errorf("%w: identifier=%s expected=%s got=%s",
				ErrPeerKeyMismatch, identifier, pinned, hexKey)
		}
		return nil
	}

	existing, ok := s.entries[identifier]
	if !ok {
		// First time: trust and save.
		s.entries[identifier] = hexKey
		return s.saveLocked()
	}
	if existing != hexKey {
		return fmt.Errorf("%w: identifier=%s expected=%s got=%s",
			ErrPeerKeyMismatch, identifier, existing, hexKey)
	}
	return nil
}

// Forget removes a TOFU entry (e.g. after a legitimate key rotation).
// Pinned keys cannot be forgotten via this method.
func (s *Store) Forget(identifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[identifier]; !ok {
		return nil
	}
	delete(s.entries, identifier)
	return s.saveLocked()
}

// load reads the store from disk.
func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // empty store is fine
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &s.entries)
}

// saveLocked persists the store to disk. Caller must hold s.mu.
func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return err
	}
	// Write with 0600: the file contains public keys only, but restricting
	// access prevents tampering with the trust decisions.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
