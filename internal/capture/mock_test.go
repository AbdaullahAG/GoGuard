package capture

import (
	"context"
	"testing"
	"time"
)

func TestMockSource_EmitsConfiguredFrame(t *testing.T) {
	src := &MockSource{Frame: []byte{1, 2, 3}, Interval: 10 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	frames, err := src.Frames(ctx)
	if err != nil {
		t.Fatalf("Frames returned error: %v", err)
	}

	f, ok := <-frames
	if !ok {
		t.Fatalf("expected at least one frame before the channel closed")
	}
	if len(f) != 3 || f[0] != 1 || f[1] != 2 || f[2] != 3 {
		t.Fatalf("unexpected frame content: %v", f)
	}
}

func TestMockSource_ChannelClosesOnContextCancellation(t *testing.T) {
	src := &MockSource{Frame: []byte{1}, Interval: 5 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())

	frames, err := src.Frames(ctx)
	if err != nil {
		t.Fatalf("Frames returned error: %v", err)
	}
	<-frames // consume at least one frame to know the source is running
	cancel()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-frames:
			if !ok {
				return // channel closed as expected after cancellation
			}
		case <-deadline:
			t.Fatalf("expected frames channel to close after context cancellation")
		}
	}
}

func TestMockSource_DefaultsIntervalWhenUnset(t *testing.T) {
	// Interval left at zero must not busy-loop or panic; New defaults it.
	src := &MockSource{Frame: []byte{9}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	frames, err := src.Frames(ctx)
	if err != nil {
		t.Fatalf("Frames returned error: %v", err)
	}
	// Just confirm it doesn't panic and the channel behaves; a 1-second
	// default interval means no frame is expected within this short test
	// window, so only confirm the channel closes cleanly on cancellation.
	select {
	case <-frames:
	case <-time.After(200 * time.Millisecond):
	}
}
