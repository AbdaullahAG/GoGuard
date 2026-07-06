//go:build linux

package main

import (
	"io"

	"ids-ips/internal/capture"
	"ids-ips/internal/capture/xdp"
)

// newRealCaptureSource wires the real, Linux-only XDP capture backend.
// Isolating this behind a build tag (and this tiny indirection file) means
// `go build` on Windows or macOS — this project's normal development
// platform per the docs — never even attempts to compile cilium/ebpf,
// which talks to Linux-specific syscalls that don't exist elsewhere.
func newRealCaptureSource(iface string) (capture.Source, io.Closer, error) {
	src, err := xdp.New(iface)
	if err != nil {
		return nil, nil, err
	}
	return src, src, nil
}
