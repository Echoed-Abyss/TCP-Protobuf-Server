package protocol

import "sync/atomic"

// Metrics tracks security-relevant counters for internal observability.
// These counters are NEVER transmitted to the peer or included in any
// error message. They are for local logging/alerting only.
type Metrics struct {
	FramesReceived   atomic.Uint64
	FramesSent       atomic.Uint64
	ReplayRejected   atomic.Uint64 // seq window rejected
	ExpiredRejected  atomic.Uint64 // timestamp window rejected
	DecryptFailed    atomic.Uint64 // AEAD auth failed
	HandshakeFailed  atomic.Uint64 // handshake errors
	InvalidFrame     atomic.Uint64 // bad magic/version/length
	KeyRotations     atomic.Uint64 // successful rekeys
}

// GlobalMetrics is a process-wide counter set. In production you may want
// per-connection or per-server instances, but a global set is sufficient for
// demonstrating the counter categories.
var GlobalMetrics Metrics

// Snapshot returns a copy of the current metric values.
func Snapshot() map[string]uint64 {
	return map[string]uint64{
		"frames_received":  GlobalMetrics.FramesReceived.Load(),
		"frames_sent":      GlobalMetrics.FramesSent.Load(),
		"replay_rejected":  GlobalMetrics.ReplayRejected.Load(),
		"expired_rejected": GlobalMetrics.ExpiredRejected.Load(),
		"decrypt_failed":   GlobalMetrics.DecryptFailed.Load(),
		"handshake_failed": GlobalMetrics.HandshakeFailed.Load(),
		"invalid_frame":    GlobalMetrics.InvalidFrame.Load(),
		"key_rotations":    GlobalMetrics.KeyRotations.Load(),
	}
}
