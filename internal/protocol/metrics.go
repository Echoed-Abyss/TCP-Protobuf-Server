package protocol

import "sync/atomic"

// Metrics tracks security-relevant counters for internal observability.
// These counters are NEVER transmitted to the peer or included in any
// error message. They are for local logging/alerting only.
//
// The admin /stats and /metrics endpoints read from this single source of
// truth; the application must not maintain a parallel counter set.
type Metrics struct {
	FramesReceived   atomic.Uint64
	FramesSent       atomic.Uint64
	ReplayRejected   atomic.Uint64 // seq window rejected
	ExpiredRejected  atomic.Uint64 // timestamp window rejected
	DecryptFailed    atomic.Uint64 // AEAD auth failed
	HandshakeFailed  atomic.Uint64 // handshake errors
	HandshakeOK      atomic.Uint64 // successful handshakes
	InvalidFrame     atomic.Uint64 // bad magic/version/length
	KeyRotations     atomic.Uint64 // successful rekeys
	Renegotiations   atomic.Uint64 // successful full PFS renegotiations
	DummyFramesSent  atomic.Uint64 // dummy/cover frames sent
	ConnectionsTotal atomic.Uint64 // cumulative accepted connections
}

// GlobalMetrics is a process-wide counter set. In production you may want
// per-connection or per-server instances, but a global set is sufficient for
// demonstrating the counter categories.
var GlobalMetrics Metrics

// Snapshot returns a copy of the current metric values.
func Snapshot() map[string]uint64 {
	return map[string]uint64{
		"frames_received":    GlobalMetrics.FramesReceived.Load(),
		"frames_sent":        GlobalMetrics.FramesSent.Load(),
		"replay_rejected":    GlobalMetrics.ReplayRejected.Load(),
		"expired_rejected":   GlobalMetrics.ExpiredRejected.Load(),
		"decrypt_failed":     GlobalMetrics.DecryptFailed.Load(),
		"handshake_failed":   GlobalMetrics.HandshakeFailed.Load(),
		"handshake_ok":       GlobalMetrics.HandshakeOK.Load(),
		"invalid_frame":      GlobalMetrics.InvalidFrame.Load(),
		"key_rotations":      GlobalMetrics.KeyRotations.Load(),
		"renegotiations":     GlobalMetrics.Renegotiations.Load(),
		"dummy_frames_sent":  GlobalMetrics.DummyFramesSent.Load(),
		"connections_total":  GlobalMetrics.ConnectionsTotal.Load(),
	}
}
