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
	entries  map[string]string   // identifier -> hex(public key)
	pinned   map[string][]string // identifier -> []hex(public key) (pin list)
	revoked  map[string]bool     // hex(public key) -> revoked (CRL)
}

// NewStore loads a trust store from path. If the file does not exist, an
// empty store is created (and persisted on first write).
func NewStore(path string) (*Store, error) {
	s := &Store{
		path:    path,
		entries: make(map[string]string),
		pinned:  make(map[string][]string),
		revoked: make(map[string]bool),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// SetPinned registers a compile-time/configuration-pinned key for an
// identifier. Pinned keys take precedence over TOFU entries and are never
// overwritten. Replaces any existing pinned keys for this identifier.
func (s *Store) SetPinned(identifier string, pubKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pinned[identifier] = []string{hex.EncodeToString(pubKey)}
}

// SetPinnedList registers multiple pinned keys for an identifier (smooth
// key rotation: both old and new keys are accepted during transition).
func (s *Store) SetPinnedList(identifier string, pubKeys [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]string, 0, len(pubKeys))
	for _, k := range pubKeys {
		list = append(list, hex.EncodeToString(k))
	}
	s.pinned[identifier] = list
}

// Revoke adds a public key to the revocation list (CRL). Any connection
// presenting this key is rejected regardless of pinning or TOFU status.
func (s *Store) Revoke(pubKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[hex.EncodeToString(pubKey)] = true
}

// RevokeList adds multiple public keys to the revocation list.
func (s *Store) RevokeList(pubKeys [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range pubKeys {
		s.revoked[hex.EncodeToString(k)] = true
	}
}

// IsRevoked returns true if the public key is in the revocation list.
func (s *Store) IsRevoked(pubKey []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked[hex.EncodeToString(pubKey)]
}

// VerifyOrTrust checks whether pubKey matches the stored key for identifier.
//
//   - If pubKey is in the CRL, it is always rejected.
//   - If a pinned key list is set, pubKey MUST match one of them (no
//     automatic trust).
//   - If no entry exists, the key is trusted and saved (TOFU).
//   - If an entry exists, pubKey MUST match it.
//
// Returns nil on success, ErrPeerKeyMismatch on mismatch.
func (s *Store) VerifyOrTrust(identifier string, pubKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hexKey := hex.EncodeToString(pubKey)

	// CRL check first: revoked keys are never accepted.
	if s.revoked[hexKey] {
		return fmt.Errorf("%w: key %s is revoked", ErrPeerKeyMismatch, hexKey)
	}

	// Pinned key list always wins. Check the specific identifier first,
	// then the global "*" catch-all (used when the same pin set applies
	// to all peers, e.g. a server pinning a set of allowed client keys).
	pinned := s.pinned[identifier]
	if len(pinned) == 0 {
		pinned = s.pinned["*"]
	}
	if len(pinned) > 0 {
		for _, p := range pinned {
			if p == hexKey {
				return nil
			}
		}
		return fmt.Errorf("%w: identifier=%s not in pinned list",
			ErrPeerKeyMismatch, identifier)
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
