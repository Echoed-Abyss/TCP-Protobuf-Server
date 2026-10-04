package protocol

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
	MsgTypeRekey            MsgType = 8
	MsgTypeAlert            MsgType = 9
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
