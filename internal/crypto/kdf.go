package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveSessionKeys derives all session traffic keys from the X25519 shared
// secret and the handshake random values.
//
// Key hierarchy (HKDF-SHA256):
//
//	salt   = client_random || server_random
//	ikm    = x25519_shared_secret
//	handshake_secret = HKDF(ikm, salt, "secproto/v1/handshake")
//	traffic_secret   = HKDF(handshake_secret, "", "secproto/v1/traffic")
//	client_key  = HKDF(traffic_secret, "", "client write key",  32)
//	server_key  = HKDF(traffic_secret, "", "server write key",  32)
//	client_np   = HKDF(traffic_secret, "", "client nonce",       4)
//	server_np   = HKDF(traffic_secret, "", "server nonce",       4)
//	session_id  = HKDF(traffic_secret, "", "session id",         8)
type SessionKeys struct {
	ClientWriteKey    []byte // 32 bytes
	ServerWriteKey    []byte // 32 bytes
	ClientNoncePrefix []byte // 4 bytes
	ServerNoncePrefix []byte // 4 bytes
	SessionID         []byte // 8 bytes, binds AAD to this session
}

const (
	hkdfInfoHandshake = "secproto/v1/handshake"
	hkdfInfoTraffic   = "secproto/v1/traffic"
)

// DeriveKeys runs the full key derivation. clientRandom/serverRandom are the
// 32-byte values exchanged in the handshake. shared is the raw X25519 output.
func DeriveKeys(shared, clientRandom, serverRandom []byte) (*SessionKeys, error) {
	salt := make([]byte, 0, len(clientRandom)+len(serverRandom))
	salt = append(salt, clientRandom...)
	salt = append(salt, serverRandom...)

	// handshake_secret
	hsReader := hkdf.New(sha256.New, shared, salt, []byte(hkdfInfoHandshake))
	handshakeSecret := make([]byte, 32)
	if _, err := io.ReadFull(hsReader, handshakeSecret); err != nil {
		return nil, err
	}

	// traffic_secret
	tsReader := hkdf.New(sha256.New, handshakeSecret, nil, []byte(hkdfInfoTraffic))
	trafficSecret := make([]byte, 32)
	if _, err := io.ReadFull(tsReader, trafficSecret); err != nil {
		return nil, err
	}

	keys := &SessionKeys{}

	// client write key
	keys.ClientWriteKey, _ = hkdfExpand(trafficSecret, "client write key", 32)
	// server write key
	keys.ServerWriteKey, _ = hkdfExpand(trafficSecret, "server write key", 32)
	// client nonce prefix
	keys.ClientNoncePrefix, _ = hkdfExpand(trafficSecret, "client nonce", 4)
	// server nonce prefix
	keys.ServerNoncePrefix, _ = hkdfExpand(trafficSecret, "server nonce", 4)
	// session id
	keys.SessionID, _ = hkdfExpand(trafficSecret, "session id", 8)

	return keys, nil
}

// hkdfExpand is a helper that expands a key with a label to the given length.
func hkdfExpand(prk []byte, label string, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, prk, nil, []byte(label))
	out := make([]byte, length)
	_, err := io.ReadFull(r, out)
	return out, err
}

// DeriveRekeyKeys derives fresh keys for a rekey operation. It mixes the
// previous traffic secret with a new random value to produce a new traffic
// secret, then derives the same set of sub-keys.
func DeriveRekeyKeys(prevTrafficSecret, newRandom []byte) (*SessionKeys, error) {
	// New IKM = prevTrafficSecret || newRandom
	ikm := make([]byte, 0, len(prevTrafficSecret)+len(newRandom))
	ikm = append(ikm, prevTrafficSecret...)
	ikm = append(ikm, newRandom...)

	tsReader := hkdf.New(sha256.New, ikm, nil, []byte(hkdfInfoTraffic))
	trafficSecret := make([]byte, 32)
	if _, err := io.ReadFull(tsReader, trafficSecret); err != nil {
		return nil, err
	}

	keys := &SessionKeys{}
	keys.ClientWriteKey, _ = hkdfExpand(trafficSecret, "client write key", 32)
	keys.ServerWriteKey, _ = hkdfExpand(trafficSecret, "server write key", 32)
	keys.ClientNoncePrefix, _ = hkdfExpand(trafficSecret, "client nonce", 4)
	keys.ServerNoncePrefix, _ = hkdfExpand(trafficSecret, "server nonce", 4)
	keys.SessionID, _ = hkdfExpand(trafficSecret, "session id", 8)
	return keys, nil
}

// DeriveTrafficSecretForRekey extracts the traffic secret (the intermediate
// value needed for rekey) from the shared secret. This is stored securely for
// later rekey derivation.
func DeriveTrafficSecretForRekey(shared, clientRandom, serverRandom []byte) ([]byte, error) {
	salt := make([]byte, 0, len(clientRandom)+len(serverRandom))
	salt = append(salt, clientRandom...)
	salt = append(salt, serverRandom...)

	hsReader := hkdf.New(sha256.New, shared, salt, []byte(hkdfInfoHandshake))
	handshakeSecret := make([]byte, 32)
	if _, err := io.ReadFull(hsReader, handshakeSecret); err != nil {
		return nil, err
	}
	tsReader := hkdf.New(sha256.New, handshakeSecret, nil, []byte(hkdfInfoTraffic))
	trafficSecret := make([]byte, 32)
	if _, err := io.ReadFull(tsReader, trafficSecret); err != nil {
		return nil, err
	}
	return trafficSecret, nil
}
