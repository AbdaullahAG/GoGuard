//go:build !linux

package main

import (
	"fmt"
	"io"

	"ids-ips/internal/capture"
)

// newRealCaptureSource is a stub on non-Linux platforms. Real XDP capture
// depends on Linux-specific kernel facilities (the bpf() syscall, XDP
// hooks) that have no equivalent on Windows or macOS — the platform this
// project is normally developed on. -iface therefore fails with a clear
// message here rather than -rules-style flags silently doing nothing, or
// the whole binary failing to compile at all.
func newRealCaptureSource(_ string) (capture.Source, io.Closer, error) {
	return nil, nil, fmt.Errorf("real packet capture (-iface) requires Linux; build and run idsips on a Linux host or VM")
}
