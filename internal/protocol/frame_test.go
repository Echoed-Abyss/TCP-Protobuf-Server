package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("hello secure world")
	f := NewFrame(MsgTypeData, 1, 42, make([]byte, NonceSize), payload)
	data := f.Marshal()

	r := bytes.NewReader(data)
	got, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Magic != Magic {
		t.Errorf("magic: got %x want %x", got.Magic, Magic)
	}
	if got.MsgType != MsgTypeData {
		t.Errorf("msgtype: got %d want %d", got.MsgType, MsgTypeData)
	}
	if got.KeyID != 1 {
		t.Errorf("keyid: got %d want 1", got.KeyID)
	}
	if got.Seq != 42 {
		t.Errorf("seq: got %d want 42", got.Seq)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestFrameBadMagic(t *testing.T) {
	buf := make([]byte, HeaderSize)
	// wrong magic
	buf[0] = 0x00
	buf[1] = 0x00
	r := bytes.NewReader(buf)
	if _, err := ReadFrame(r); err != ErrInvalidFrame {
		t.Errorf("expected ErrInvalidFrame, got %v", err)
	}
}

func TestFrameOversizedPayload(t *testing.T) {
	f := NewFrame(MsgTypeData, 1, 1, make([]byte, NonceSize), nil)
	data := f.Marshal()
	// tamper length to be huge
	data[33] = 0xFF
	data[34] = 0xFF
	data[35] = 0xFF
	data[36] = 0xFF
	r := bytes.NewReader(data)
	if _, err := ReadFrame(r); err != ErrInvalidFrame {
		t.Errorf("expected ErrInvalidFrame for oversized payload, got %v", err)
	}
}

func TestHeaderBytesDeterministic(t *testing.T) {
	f := NewFrame(MsgTypeData, 1, 100, make([]byte, NonceSize), []byte("x"))
	h1 := f.HeaderBytes()
	h2 := f.HeaderBytes()
	if !bytes.Equal(h1, h2) {
		t.Error("HeaderBytes not deterministic")
	}
	if len(h1) != 2+1+1+1+8+8 {
		t.Errorf("header bytes len: got %d want %d", len(h1), 2+1+1+1+8+8)
	}
}
