package crypto

import (
	"sync"
)

// ReplayWindow implements a sliding-window replay detector using a bitmap.
//
// It tracks the highest sequence number seen (maxSeq) and a bitmask covering
// the last `window` sequence numbers. A frame is acceptable iff:
//   - seq + window > maxSeq  (seq is not below the window bottom)
//   - the bit for seq is not already set
//
// After successful decryption the caller marks the seq as seen via Accept.
// This ensures failed decryptions do not consume a sequence slot.
//
// window MUST be a power of two so that seq & (window-1) gives the bit index.
type ReplayWindow struct {
	mu     sync.Mutex
	maxSeq uint64
	window uint64 // number of bits, power of two
	mask   uint64 // window - 1
	seen   []uint64
}

// NewReplayWindow creates a replay window. windowSize is rounded up to a
// power of two and clamped to >= 64.
func NewReplayWindow(windowSize uint64) *ReplayWindow {
	if windowSize < 64 {
		windowSize = 64
	}
	// Round up to next power of two.
	w := uint64(64)
	for w < windowSize {
		w <<= 1
	}
	rw := &ReplayWindow{
		window: w,
		mask:   w - 1,
		seen:   make([]uint64, w/64),
	}
	return rw
}

// Check returns true if seq is within the acceptance window and has not been
// seen. It does NOT mark seq as seen.
func (rw *ReplayWindow) Check(seq uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	// Reject if seq is below the window bottom.
	if seq+rw.window <= rw.maxSeq {
		return false
	}

	// If seq is beyond maxSeq, it's always fresh.
	if seq > rw.maxSeq {
		return true
	}

	// seq is within [maxSeq-window+1, maxSeq]. Check the bit.
	idx := seq & rw.mask
	return rw.seen[idx/64]&(1<<(idx%64)) == 0
}

// Accept marks seq as seen. Must be called only after the frame has been
// successfully authenticated.
func (rw *ReplayWindow) Accept(seq uint64) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if seq > rw.maxSeq {
		delta := seq - rw.maxSeq
		if delta >= rw.window {
			// All previously seen seqs are now out of window.
			for i := range rw.seen {
				rw.seen[i] = 0
			}
		} else {
			// Clear the `delta` bits that fell out of the window.
			// These correspond to seqs [maxSeq-window+1, seq-window],
			// whose indices are (maxSeq+1)&mask .. seq&mask (wrap-around).
			start := (rw.maxSeq + 1) & rw.mask
			rw.clearBits(start, delta)
		}
		rw.maxSeq = seq
	}

	idx := seq & rw.mask
	rw.seen[idx/64] |= 1 << (idx % 64)
}

// clearBits clears `count` consecutive bits starting at `start` (wrapping
// around the circular bitmap).
func (rw *ReplayWindow) clearBits(start, count uint64) {
	for i := uint64(0); i < count; i++ {
		idx := (start + i) & rw.mask
		rw.seen[idx/64] &^= 1 << (idx % 64)
	}
}

// MaxSeq returns the highest sequence number accepted so far.
func (rw *ReplayWindow) MaxSeq() uint64 {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.maxSeq
}
