//go:build linux

package xdp

import (
	"encoding/binary"
	"testing"
)

// FuzzDecodeEvent feeds arbitrary byte slices into decodeEvent. Like
// FuzzParse (internal/parser) and FuzzFingerprint (internal/detect/tlsfp),
// the only property under test is "never panics". decodeEvent parses
// bytes that originated in the kernel program rather than directly off
// the wire, but they still cross a trust boundary this process doesn't
// control end-to-end, so the same discipline applies.
func FuzzDecodeEvent(f *testing.F) {
	seeds := [][]byte{
		{},
		make([]byte, eventHeaderLen),
		validEventSeed(10),
		validEventSeed(snapLen),
		oversizedLenSeed(),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeEvent(data)
	})
}

func validEventSeed(n int) []byte {
	buf := make([]byte, eventHeaderLen+snapLen)
	binary.LittleEndian.PutUint32(buf[:eventHeaderLen], uint32(n))
	return buf
}

// oversizedLenSeed claims a length far larger than both the buffer
// actually present and snapLen — exactly the inconsistency decodeEvent's
// bounds check exists to reject.
func oversizedLenSeed() []byte {
	buf := make([]byte, eventHeaderLen+16)
	binary.LittleEndian.PutUint32(buf[:eventHeaderLen], 0xFFFFFFFF)
	return buf
}
