package protocol

import "errors"

// Protocol magic number. Frames that don't start with this are dropped.
const Magic uint16 = 0x5343 // "SC"

// ProtocolVersion is the current wire protocol version. Used to prevent
// downgrade attacks: any frame with an unsupported version is rejected.
const ProtocolVersion uint8 = 1

// MinSupportedVersion is the lowest version we are willing to speak.
const MinSupportedVersion uint8 = 1

// Message types carried in the frame header.
type MsgType uint8

const (
	MsgTypeUnknown          MsgType = 0
	MsgTypeClientHello      MsgType = 1
	MsgTypeServerHello      MsgType = 2
	MsgTypeServerProof      MsgType = 3
	MsgTypeClientFinished   MsgType = 4
	MsgTypeServerFinished   MsgType = 5
	MsgTypeData             MsgType = 6
	MsgTypeHeartbeat        MsgType = 7
	MsgTypeRekey            MsgType = 8 // in-band rekey (non-PFS, HKDF from old TS)
	MsgTypeAlert            MsgType = 9

	// Renegotiation message types (full re-handshake for PFS).
	// These are sent ENCRYPTED under the current session key. They carry
	// fresh X25519 ephemeral keys so the new session provides forward
	// secrecy: compromise of the old session key does not reveal the new
	// session key (which is derived from a fresh DH exchange).
	MsgTypeRenegClientHello    MsgType = 10
	MsgTypeRenegServerHello    MsgType = 11
	MsgTypeRenegServerProof    MsgType = 12
	MsgTypeRenegClientFinished MsgType = 13
	MsgTypeRenegServerFinished MsgType = 14

	// Dummy / cover traffic frame. Payload is random padding; ignored by
	// the receiver. Used to obfuscate traffic timing and message sizes.
	MsgTypeDummy MsgType = 15
)

// Cipher suites negotiated in the handshake.
type CipherSuite uint8

const (
	CipherSuiteUnspecified      CipherSuite = 0
	CipherSuiteAES256GCM        CipherSuite = 1
	CipherSuiteChaCha20Poly1305 CipherSuite = 2
)

// Header sizes in bytes.
// Frame layout:
//
//	Magic(2) Version(1) MsgType(1) KeyID(1) Seq(8) Nonce(12) Timestamp(8) Length(4) | Payload(var)
const (
	HeaderSize    = MagicSize + VersionSize + MsgTypeSize + KeyIDSize + SeqSize + NonceSize + TimestampSize + LengthSize
	MagicSize     = 2
	VersionSize   = 1
	MsgTypeSize   = 1
	KeyIDSize     = 1
	SeqSize       = 8
	NonceSize     = 12 // AES-GCM / ChaCha20-Poly1305 nonce
	TimestampSize = 8
	LengthSize    = 4
)

// MaxFramePayload is the maximum allowed payload length per frame.
// 16 MiB is a generous upper bound; anything larger is treated as an attack.
const MaxFramePayload = 16 * 1024 * 1024

// HandshakeTimeWindow is the maximum allowed clock skew for handshake
// messages (nanoseconds). Frames outside this window are rejected.
const HandshakeTimeWindow int64 = 30 * 1e9 // 30 seconds

// DataTimeWindow is the maximum allowed age for data frames (nanoseconds).
const DataTimeWindow int64 = 60 * 1e9 // 60 seconds

// ReplayWindowSize is the number of sequence numbers tracked for replay
// protection. 1024 means we accept any seq in [maxSeen-1023, maxSeen].
const ReplayWindowSize = 1024

// HeartbeatInterval is the default interval between heartbeat frames.
const HeartbeatInterval int64 = 15 * 1e9 // 15 seconds

// SessionKeyTTL is the lifetime of a session key before rekey is required.
const SessionKeyTTL int64 = 3600 * 1e9 // 1 hour

// MaxKeyID is the highest key_id value allowed for in-band rekey.
// key_id is a uint8, so it can hold 0..255. We reserve the top range
// (251..255) so that incrementing never wraps silently. When key_id reaches
// MaxKeyID, the next rotation MUST be a full renegotiation (new handshake),
// not an in-band rekey. This guarantees the (key, nonce) space never wraps.
const MaxKeyID uint8 = 250

// RekeyOverflow is the error returned when an in-band rekey is attempted
// but key_id has reached MaxKeyID. The caller must perform a full
// renegotiation (close and re-handshake) instead.
var ErrRekeyOverflow = errors.New("key id exhausted; full renegotiation required")

// PaddingBlockSize is the block size to which payloads are padded.
// Padding is applied BEFORE encryption so the ciphertext length does not
// reveal the plaintext length. Padding bytes are zero (the receiver strips
// them after decryption using the declared plaintext length embedded in the
// payload prefix). Default 16 bytes; set to 0 to disable.
const PaddingBlockSize = 16

// MaxPaddingSize caps the total padding overhead per frame.
const MaxPaddingSize = 1024

// DummyFrameInterval is the base interval between dummy/cover frames.
// A random jitter of ±DummyFrameJitter is applied so the timing does not
// form a detectable pattern. 0 disables dummy frames.
const DummyFrameInterval int64 = 10 * 1e9 // 10 seconds

// DummyFrameJitter is the maximum random jitter added to/subtracted from
// DummyFrameInterval.
const DummyFrameJitter int64 = 3 * 1e9 // ±3 seconds

// DefaultDummyPayloadSize is the payload size of dummy frames.
const DefaultDummyPayloadSize = 64

// MaxClockOffset is the maximum allowed estimated clock offset that the
// client will compensate for. Offsets beyond this are treated as errors.
const MaxClockOffset int64 = 5 * 60 * 1e9 // 5 minutes

// ForceRenegotiateInterval is the default interval after which a full
// re-handshake is triggered to restore forward secrecy.
const ForceRenegotiateInterval int64 = 3600 * 1e9 // 1 hour
