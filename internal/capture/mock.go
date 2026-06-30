package capture

import (
	"context"
	"time"
)

// MockSource emits a fixed frame at a fixed interval. It exists so the
// pipeline can be built, tested, and demoed end-to-end without root
// privileges or a real NIC, and so Source has a concrete, safe-by-default
// implementation before a real capture backend is wired in.
type MockSource struct {
	Frame    []byte
	Interval time.Duration
}

func (m *MockSource) Frames(ctx context.Context) (<-chan []byte, error) {
	out := make(chan []byte, 16)
	go func() {
		defer close(out)
		interval := m.Interval
		if interval <= 0 {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case out <- m.Frame:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}
