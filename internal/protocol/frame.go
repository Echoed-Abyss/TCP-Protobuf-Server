package protocol

import (
	"encoding/binary"
	"io"
	"time"
)

// Frame is the on-wire frame structure.
//
// Wire layout (big-endian):
//
//	Offset  Size  Field
//	0       2     Magic      (0x5343)
//	2       1     Version
//	3       1     MsgType
//	4       1     KeyID
//	5       8     Seq        (uint64)
//	13      12    Nonce      (AEAD nonce)
//	25      8     Timestamp  (Unix nanoseconds)
//	33      4     Length     (payload length, uint32)
//	37      var   Payload    (ciphertext+tag for AEAD, or handshake bytes)
type Frame struct {
	Magic     uint16
	Version   uint8
	MsgType   MsgType
	KeyID     uint8
	Seq       uint64
	Nonce     [NonceSize]byte
	Timestamp uint64
	Payload   []byte
}

// NewFrame creates a frame with the current timestamp.
func NewFrame(msgType MsgType, keyID uint8, seq uint64, nonce []byte, payload []byte) *Frame {
	f := &Frame{
		Magic:     Magic,
		Version:   ProtocolVersion,
		MsgType:   msgType,
		KeyID:     keyID,
		Seq:       seq,
		Timestamp: uint64(time.Now().UnixNano()),
		Payload:   payload,
	}
	copy(f.Nonce[:], nonce)
	return f
}

// Marshal serializes the frame into its wire representation.
// The returned slice has capacity HeaderSize+len(Payload).
func (f *Frame) Marshal() []byte {
	buf := make([]byte, HeaderSize+len(f.Payload))
	binary.BigEndian.PutUint16(buf[0:2], f.Magic)
	buf[2] = f.Version
	buf[3] = uint8(f.MsgType)
	buf[4] = f.KeyID
	binary.BigEndian.PutUint64(buf[5:13], f.Seq)
	copy(buf[13:25], f.Nonce[:])
	binary.BigEndian.PutUint64(buf[25:33], f.Timestamp)
	binary.BigEndian.PutUint32(buf[33:37], uint32(len(f.Payload)))
	copy(buf[37:], f.Payload)
	return buf
}

// HeaderBytes returns the authenticated portion of the header (everything
// except the payload and the nonce/length fields). This is used as the AAD
// for AEAD.
//
// AAD = Magic(2) || Version(1) || MsgType(1) || KeyID(1) || Seq(8) || Timestamp(8)
// The session_id is appended by the caller (see transport.aadFor).
//
// Including Timestamp in the AAD means an attacker cannot tamper with the
// timestamp without breaking the AEAD tag, so time-window replay protection
// is cryptographically bound to the frame.
func (f *Frame) HeaderBytes() []byte {
	buf := make([]byte, MagicSize+VersionSize+MsgTypeSize+KeyIDSize+SeqSize+TimestampSize)
	off := 0
	binary.BigEndian.PutUint16(buf[off:off+MagicSize], f.Magic)
	off += MagicSize
	buf[off] = f.Version
	off += VersionSize
	buf[off] = uint8(f.MsgType)
	off += MsgTypeSize
	buf[off] = f.KeyID
	off += KeyIDSize
	binary.BigEndian.PutUint64(buf[off:off+SeqSize], f.Seq)
	off += SeqSize
	binary.BigEndian.PutUint64(buf[off:off+TimestampSize], f.Timestamp)
	return buf
}

// ParseHeader reads exactly HeaderSize bytes from r and returns a partial
// Frame (without Payload) plus the payload length.
func ParseHeader(r io.Reader) (*Frame, uint32, error) {
	hdr := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, 0, err
	}
	magic := binary.BigEndian.Uint16(hdr[0:2])
	if magic != Magic {
		GlobalMetrics.InvalidFrame.Add(1)
		return nil, 0, ErrInvalidFrame
	}
	version := hdr[2]
	if version < MinSupportedVersion || version > ProtocolVersion {
		GlobalMetrics.InvalidFrame.Add(1)
		return nil, 0, ErrInvalidFrame
	}
	seq := binary.BigEndian.Uint64(hdr[5:13])
	payloadLen := binary.BigEndian.Uint32(hdr[33:37])
	if payloadLen > MaxFramePayload {
		GlobalMetrics.OversizedFrame.Add(1)
		return nil, 0, ErrInvalidFrame
	}
	f := &Frame{
		Magic:     magic,
		Version:   version,
		MsgType:   MsgType(hdr[3]),
		KeyID:     hdr[4],
		Seq:       seq,
		Timestamp: binary.BigEndian.Uint64(hdr[25:33]),
	}
	copy(f.Nonce[:], hdr[13:25])
	return f, payloadLen, nil
}

// ReadFrame reads a complete frame from r (header + payload).
// It handles TCP stream framing (sticky packets / split packets) by reading
// exactly the declared length.
func ReadFrame(r io.Reader) (*Frame, error) {
	f, payloadLen, err := ParseHeader(r)
	if err != nil {
		return nil, err
	}
	if payloadLen > 0 {
		f.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
	} else {
		f.Payload = nil
	}
	return f, nil
}
