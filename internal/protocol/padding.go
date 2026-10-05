package protocol

import (
	"encoding/binary"
)

// Padding format (applied to encrypted plaintext only):
//
//	[uint32 plaintext_len BE][plaintext bytes][zero padding to block boundary]
//
// The length prefix lets the receiver strip padding exactly. Padding bytes
// are zero; the receiver MUST verify they are zero (defense in depth against
// padding oracle / tampering). Because padding is inside the AEAD plaintext,
// the AEAD tag already authenticates it, but the zero-check is cheap.
//
// Padding is applied to the PLAINTEXT before encryption, so the ciphertext
// length reveals only the padded length (rounded up to the block size), not
// the true plaintext length. The frame's Length field covers ciphertext+tag.
//
// If blockSize == 0, padding is disabled (plaintext is sent as-is with a
// 4-byte length prefix for forward compatibility).

// PadWithPrefix wraps plaintext with a 4-byte length prefix and zero-pads
// the result up to a multiple of blockSize. If blockSize < 1, returns
// length-prefixed plaintext without block padding.
func PadWithPrefix(plaintext []byte, blockSize int) []byte {
	n := len(plaintext)
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(n))

	body := make([]byte, 0, 4+n)
	body = append(body, prefix...)
	body = append(body, plaintext...)

	if blockSize > 1 {
		// Round up to next multiple of blockSize.
		rem := len(body) % blockSize
		if rem != 0 {
			pad := blockSize - rem
			body = append(body, make([]byte, pad)...)
		}
	}
	return body
}

// UnpadWithPrefix reverses PadWithPrefix. It reads the 4-byte length prefix,
// extracts the plaintext, and verifies the remaining bytes are zero.
func UnpadWithPrefix(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, ErrInvalidFrame
	}
	n := binary.BigEndian.Uint32(padded[0:4])
	if uint64(n)+4 > uint64(len(padded)) {
		return nil, ErrInvalidFrame
	}
	plaintext := padded[4 : 4+n]
	// Verify padding bytes are all zero.
	for _, b := range padded[4+n:] {
		if b != 0 {
			return nil, ErrInvalidFrame
		}
	}
	return plaintext, nil
}
