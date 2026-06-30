// Package capture abstracts where raw frames come from.
package capture

import "context"

// Source produces raw frames for the parser to consume.
//
// Deliberately not implemented here with libpcap via cgo: cgo opts the
// process out of Go's memory-safety guarantees and its goroutine/runtime
// integration — exactly the safety margin this whole project is built to
// keep. A production backend should be pure Go: golang.org/x/sys/unix raw
// AF_PACKET sockets for a portable baseline, or github.com/cilium/ebpf for
// the in-kernel XDP capture-and-block path described in the architecture.
type Source interface {
	// Frames returns a channel of raw frames. The channel is closed when
	// the source is exhausted or ctx is cancelled. Implementations must
	// never block forever trying to push into a full downstream consumer —
	// that would turn ordinary back-pressure into an outage of the entire
	// pipeline, which is worse than dropping a frame.
	Frames(ctx context.Context) (<-chan []byte, error)
}
