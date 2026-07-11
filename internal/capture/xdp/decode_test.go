//go:build linux

package xdp

import (
	"encoding/binary"
	"testing"
)

func TestDecodeEvent_ValidRecord(t *testing.T) {
	buf := make([]byte, eventHeaderLen+snapLen)
	binary.LittleEndian.PutUint32(buf[:eventHeaderLen], 5)
	copy(buf[eventHeaderLen:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE})

	frame, ok := decodeEvent(buf)
	if !ok {
		t.Fatalf("expected a valid record to decode successfully")
	}
	if len(frame) != 5 {
		t.Fatalf("expected a 5-byte frame, got %d bytes", len(frame))
	}
	want := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	for i := range want {
		if frame[i] != want[i] {
			t.Fatalf("frame content mismatch at byte %d: got %x, want %x", i, frame[i], want[i])
		}
	}
}

func TestDecodeEvent_TooShortForHeader(t *testing.T) {
	if _, ok := decodeEvent([]byte{1, 2, 3}); ok {
		t.Fatalf("expected a record shorter than the length header to be rejected")
	}
}

func TestDecodeEvent_LenExceedsActualBody(t *testing.T) {
	buf := make([]byte, eventHeaderLen+8) // only 8 bytes of body present
	binary.LittleEndian.PutUint32(buf[:eventHeaderLen], 100)
	if _, ok := decodeEvent(buf); ok {
		t.Fatalf("expected a claimed length exceeding the actual body to be rejected")
	}
}

func TestDecodeEvent_LenExceedsSnapLen(t *testing.T) {
	buf := make([]byte, eventHeaderLen+snapLen+100)
	binary.LittleEndian.PutUint32(buf[:eventHeaderLen], snapLen+50)
	if _, ok := decodeEvent(buf); ok {
		t.Fatalf("expected a claimed length exceeding snapLen to be rejected even if the buffer is large enough")
	}
}

func TestDecodeEvent_ZeroLengthIsValid(t *testing.T) {
	// A zero-length capture (e.g. the kernel program's unrolled copy loop
	// broke on the very first byte) is a legitimate, if useless, record —
	// it must decode successfully to an empty frame, not be rejected.
	buf := make([]byte, eventHeaderLen+snapLen)
	frame, ok := decodeEvent(buf)
	if !ok {
		t.Fatalf("expected a zero-length record to decode successfully")
	}
	if len(frame) != 0 {
		t.Fatalf("expected an empty frame, got %d bytes", len(frame))
	}
}
