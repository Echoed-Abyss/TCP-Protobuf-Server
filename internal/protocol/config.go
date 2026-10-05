package protocol

import (
	"errors"
	"sync/atomic"
)

// errConfig is the error type returned for invalid hot-config values.
func errConfig(msg string) error { return errors.New("config: " + msg) }

// RuntimeConfig holds protocol parameters that can be changed at runtime
// (hot-reload) without restarting the process. All fields are atomics so
// readers (transport loops) and writers (admin API) never race.
//
// Parameters that require a restart (listen address, identity key path,
// SessionKeyTTL, etc.) are NOT here; they are read from env/flags at
// startup and exposed read-only through the admin config endpoint.
//
// Defaults are loaded from the package constants in constants.go.
type RuntimeConfig struct {
	// HeartbeatInterval is the interval between heartbeat frames (ns).
	HeartbeatInterval atomic.Int64

	// DummyFrameInterval is the base interval for dummy/cover frames (ns).
	DummyFrameInterval atomic.Int64

	// DummyFrameJitter is the max random jitter added to DummyFrameInterval (ns).
	DummyFrameJitter atomic.Int64

	// DummyFramesEnabled toggles periodic dummy/cover traffic.
	DummyFramesEnabled atomic.Bool

	// PaddingBlockSize is the block size to which payloads are padded.
	// 0 disables padding.
	PaddingBlockSize atomic.Int32

	// DataTimeWindow is the max age for data frames (ns).
	DataTimeWindow atomic.Int64

	// HandshakeTimeWindow is the max clock skew for handshake frames (ns).
	HandshakeTimeWindow atomic.Int64
}

// GlobalConfig is the process-wide runtime configuration. The admin API
// updates these fields; transport readers pick up changes on the next
// iteration of their loops / on the next frame.
var GlobalConfig = &RuntimeConfig{}

func init() {
	GlobalConfig.HeartbeatInterval.Store(HeartbeatInterval)
	GlobalConfig.DummyFrameInterval.Store(DummyFrameInterval)
	GlobalConfig.DummyFrameJitter.Store(DummyFrameJitter)
	GlobalConfig.DummyFramesEnabled.Store(true)
	GlobalConfig.PaddingBlockSize.Store(PaddingBlockSize)
	GlobalConfig.DataTimeWindow.Store(DataTimeWindow)
	GlobalConfig.HandshakeTimeWindow.Store(HandshakeTimeWindow)
}

// PaddingBlock returns the current padding block size (runtime-configurable).
// Returns 0 when padding is disabled.
func PaddingBlock() int {
	v := GlobalConfig.PaddingBlockSize.Load()
	if v < 0 {
		return 0
	}
	return int(v)
}

// SnapshotConfig returns a plain snapshot of the current runtime config
// (for the admin endpoint / logging). It never includes secrets.
type ConfigSnapshot struct {
	HeartbeatIntervalNs  int64 `json:"heartbeat_interval_ns"`
	DummyFrameIntervalNs int64 `json:"dummy_frame_interval_ns"`
	DummyFrameJitterNs   int64 `json:"dummy_frame_jitter_ns"`
	DummyFramesEnabled   bool  `json:"dummy_frames_enabled"`
	PaddingBlockSize     int32 `json:"padding_block_size"`
	DataTimeWindowNs     int64 `json:"data_time_window_ns"`
	HandshakeTimeWindowNs int64 `json:"handshake_time_window_ns"`
}

// Snapshot returns a copy of the current runtime config.
func (c *RuntimeConfig) Snapshot() ConfigSnapshot {
	return ConfigSnapshot{
		HeartbeatIntervalNs:  c.HeartbeatInterval.Load(),
		DummyFrameIntervalNs: c.DummyFrameInterval.Load(),
		DummyFrameJitterNs:   c.DummyFrameJitter.Load(),
		DummyFramesEnabled:   c.DummyFramesEnabled.Load(),
		PaddingBlockSize:     c.PaddingBlockSize.Load(),
		DataTimeWindowNs:     c.DataTimeWindow.Load(),
		HandshakeTimeWindowNs: c.HandshakeTimeWindow.Load(),
	}
}

// SetHotConfig applies a partial hot-update. Field-level validation is the
// caller's responsibility; this only applies values within sane bounds.
// Returns an error if any value is out of range (no partial write: if one
// field fails, none are applied).
type HotConfigUpdate struct {
	HeartbeatIntervalNs  *int64 `json:"heartbeat_interval_ns,omitempty"`
	DummyFrameIntervalNs *int64 `json:"dummy_frame_interval_ns,omitempty"`
	DummyFrameJitterNs   *int64 `json:"dummy_frame_jitter_ns,omitempty"`
	DummyFramesEnabled   *bool  `json:"dummy_frames_enabled,omitempty"`
	PaddingBlockSize     *int32 `json:"padding_block_size,omitempty"`
	DataTimeWindowNs     *int64 `json:"data_time_window_ns,omitempty"`
}

// Apply validates and applies the hot-update. On any validation error it
// returns an error and applies nothing.
func (c *RuntimeConfig) Apply(u HotConfigUpdate) error {
	// Validate all fields first.
	if u.HeartbeatIntervalNs != nil {
		if *u.HeartbeatIntervalNs < 1e9 || *u.HeartbeatIntervalNs > 3600*1e9 {
			return errConfig("heartbeat_interval_ns must be in [1s, 1h]")
		}
	}
	if u.DummyFrameIntervalNs != nil {
		if *u.DummyFrameIntervalNs < 0 || *u.DummyFrameIntervalNs > 3600*1e9 {
			return errConfig("dummy_frame_interval_ns must be in [0, 1h] (0 disables)")
		}
	}
	if u.DummyFrameJitterNs != nil {
		if *u.DummyFrameJitterNs < 0 || *u.DummyFrameJitterNs > 60*1e9 {
			return errConfig("dummy_frame_jitter_ns must be in [0, 60s]")
		}
	}
	if u.PaddingBlockSize != nil {
		// Min 1: padding MUST be applied (0 would disable traffic-analysis
		// protection). Max 1024 keeps per-frame overhead bounded.
		if *u.PaddingBlockSize < 1 || *u.PaddingBlockSize > 1024 {
			return errConfig("padding_block_size must be in [1, 1024]")
		}
	}
	if u.DataTimeWindowNs != nil {
		// Min 1s: a window of 0 would disable timestamp replay protection.
		if *u.DataTimeWindowNs < 1e9 || *u.DataTimeWindowNs > 3600*1e9 {
			return errConfig("data_time_window_ns must be in [1s, 1h]")
		}
	}
	// Cross-field check: jitter must not exceed the dummy frame interval,
	// otherwise the dummy sender could compute a negative sleep duration.
	if u.DummyFrameJitterNs != nil && u.DummyFrameIntervalNs != nil {
		if *u.DummyFrameJitterNs > *u.DummyFrameIntervalNs {
			return errConfig("dummy_frame_jitter_ns must not exceed dummy_frame_interval_ns")
		}
	}

	// All valid; apply.
	if u.HeartbeatIntervalNs != nil {
		c.HeartbeatInterval.Store(*u.HeartbeatIntervalNs)
	}
	if u.DummyFrameIntervalNs != nil {
		c.DummyFrameInterval.Store(*u.DummyFrameIntervalNs)
	}
	if u.DummyFrameJitterNs != nil {
		c.DummyFrameJitter.Store(*u.DummyFrameJitterNs)
	}
	if u.DummyFramesEnabled != nil {
		c.DummyFramesEnabled.Store(*u.DummyFramesEnabled)
	}
	if u.PaddingBlockSize != nil {
		c.PaddingBlockSize.Store(*u.PaddingBlockSize)
	}
	if u.DataTimeWindowNs != nil {
		c.DataTimeWindow.Store(*u.DataTimeWindowNs)
	}
	return nil
}
