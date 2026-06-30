// Package detect defines the contract every detection engine must satisfy.
package detect

import "ids-ips/pkg/types"

// Engine inspects a single parsed packet and optionally returns a Finding.
// ok=false means "no opinion", not "this is safe" — the absence of a
// finding from one engine must carry no weight on its own; only the
// correlator decides what a lack of evidence means.
type Engine interface {
	Name() string
	Inspect(pkt types.Packet) (finding types.Finding, ok bool)
}
