package protocol

import "errors"

// Sentinel errors used internally. These are intentionally generic so that
// callers cannot distinguish failure modes (which would leak information
// about the internal state to an attacker).
var (
	// ErrInvalidFrame is returned for any malformed frame (bad magic, wrong
	// version, oversized payload, etc.).
	ErrInvalidFrame = errors.New("invalid frame")

	// ErrDecryptFailed is returned when AEAD decryption or authentication
	// fails. The connection must be torn down.
	ErrDecryptFailed = errors.New("decrypt failed")

	// ErrReplay is returned when a frame is detected as a replay.
	ErrReplay = errors.New("replay detected")

	// ErrExpired is returned when a frame's timestamp is outside the allowed
	// time window.
	ErrExpired = errors.New("frame expired")

	// ErrHandshake is returned for any handshake failure (bad signature,
	// unsupported cipher suite, version mismatch, etc.).
	ErrHandshake = errors.New("handshake failed")

	// ErrNotReady is returned when data is sent before the handshake
	// completes.
	ErrNotReady = errors.New("connection not ready")

	// ErrClosed is returned when the connection has been closed.
	ErrClosed = errors.New("connection closed")

	// ErrKeyRotation is returned when a key rotation is required.
	ErrKeyRotation = errors.New("key rotation required")
)

// PublicError is the only error type returned to external callers. It
// intentionally carries no detail about the underlying cause.
type PublicError struct {
	msg string
}

func (e *PublicError) Error() string { return e.msg }

// NewPublicError wraps an internal error into a generic public error.
func NewPublicError(internalErr error) error {
	if internalErr == nil {
		return nil
	}
	return &PublicError{msg: "protocol error"}
}
