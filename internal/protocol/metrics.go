package protocol

import "sync/atomic"

// Metrics tracks security-relevant counters for internal observability.
// These counters are NEVER transmitted to the peer or included in any
// error message. They are for local logging/alerting only.
//
// The admin /stats and /metrics endpoints read from this single source of
// truth; the application must not maintain a parallel counter set.
type Metrics struct {
	FramesReceived    atomic.Uint64
	FramesSent        atomic.Uint64
	ReplayRejected    atomic.Uint64 // seq window rejected
	ExpiredRejected   atomic.Uint64 // timestamp window rejected
	DecryptFailed     atomic.Uint64 // AEAD auth failed
	HandshakeFailed   atomic.Uint64 // handshake errors
	HandshakeOK       atomic.Uint64 // successful handshakes
	InvalidFrame      atomic.Uint64 // bad magic/version/length
	KeyRotations      atomic.Uint64 // successful rekeys
	Renegotiations    atomic.Uint64 // successful full PFS renegotiations
	DummyFramesSent   atomic.Uint64 // dummy/cover frames sent
	ConnectionsTotal  atomic.Uint64 // cumulative accepted connections
	OversizedFrame    atomic.Uint64 // frame length exceeded MaxFramePayload
	ConnRateLimited   atomic.Uint64 // connections rejected by per-IP rate limit
	HandshakeTimeout  atomic.Uint64 // handshakes that exceeded HandshakeTimeout
	AppPayloadReject  atomic.Uint64 // appapi payloads rejected (size/depth/...)
	AppReqIDReject    atomic.Uint64 // appapi requests with bad req_id
	AppWorkerReject   atomic.Uint64 // appapi requests rejected (worker pool full)
	AppPanicRecovered atomic.Uint64 // appapi handler panics that were recovered
	AdminAuthFail     atomic.Uint64 // admin auth failures (wrong/missing token)
	AdminRateLimited  atomic.Uint64 // admin requests rate-limited
	AdminConfigReject atomic.Uint64 // admin PUT config rejected (bounds/invalid)
}

// GlobalMetrics is a process-wide counter set. In production you may want
// per-connection or per-server instances, but a global set is sufficient for
// demonstrating the counter categories.
var GlobalMetrics Metrics

// Snapshot returns a copy of the current metric values.
func Snapshot() map[string]uint64 {
	return map[string]uint64{
		"frames_received":     GlobalMetrics.FramesReceived.Load(),
		"frames_sent":         GlobalMetrics.FramesSent.Load(),
		"replay_rejected":     GlobalMetrics.ReplayRejected.Load(),
		"expired_rejected":    GlobalMetrics.ExpiredRejected.Load(),
		"decrypt_failed":      GlobalMetrics.DecryptFailed.Load(),
		"handshake_failed":    GlobalMetrics.HandshakeFailed.Load(),
		"handshake_ok":        GlobalMetrics.HandshakeOK.Load(),
		"invalid_frame":       GlobalMetrics.InvalidFrame.Load(),
		"key_rotations":       GlobalMetrics.KeyRotations.Load(),
		"renegotiations":      GlobalMetrics.Renegotiations.Load(),
		"dummy_frames_sent":   GlobalMetrics.DummyFramesSent.Load(),
		"connections_total":   GlobalMetrics.ConnectionsTotal.Load(),
		"oversized_frame":     GlobalMetrics.OversizedFrame.Load(),
		"conn_rate_limited":   GlobalMetrics.ConnRateLimited.Load(),
		"handshake_timeout":   GlobalMetrics.HandshakeTimeout.Load(),
		"app_payload_reject":  GlobalMetrics.AppPayloadReject.Load(),
		"app_reqid_reject":    GlobalMetrics.AppReqIDReject.Load(),
		"app_worker_reject":   GlobalMetrics.AppWorkerReject.Load(),
		"app_panic_recovered": GlobalMetrics.AppPanicRecovered.Load(),
		"admin_auth_fail":     GlobalMetrics.AdminAuthFail.Load(),
		"admin_rate_limited":  GlobalMetrics.AdminRateLimited.Load(),
		"admin_config_reject": GlobalMetrics.AdminConfigReject.Load(),
	}
}
