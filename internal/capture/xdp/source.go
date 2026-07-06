//go:build linux

// Package xdp is the production capture.Source backend: a real XDP
// program (internal/capture/xdp/bpf/xdp_capture.c) loaded via cilium/ebpf,
// running at the earliest point in the receive path.
//
// This replaces the interface note left in internal/capture/capture.go
// ("a production backend should be pure Go... github.com/cilium/ebpf for
// the in-kernel XDP capture-and-block path") with a concrete
// implementation. The eBPF program itself was compiled with clang
// (-target bpf) and its acceptance was verified against a real Linux
// kernel BPF verifier before this Go code was written around it — see
// the object file's build notes in bpf/xdp_capture.c for what that
// program does and why each part is shaped the way it is.
package xdp

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed bpf/xdp_capture.o
var programObject []byte

// snapLen must match #define SNAPLEN in xdp_capture.c. Kept as an
// exported constant here rather than silently assumed, since a mismatch
// would only surface as truncated/garbage frames at runtime — the two
// definitions are logically one value that happens to live in two
// languages.
const snapLen = 256

// eventHeaderLen is sizeof(__u32) for the leading `len` field of the C
// `struct event` — see xdp_capture.c. The struct has no padding here
// (a plain __u32 followed by a __u8 array needs none), but the constant
// is named rather than inlined so that relationship is explicit.
const eventHeaderLen = 4

// Source is a capture.Source backed by a real XDP program attached to a
// network interface.
type Source struct {
	coll   *ebpf.Collection
	link   link.Link
	reader *ringbuf.Reader
}

// New loads the embedded XDP program and attaches it to the named
// interface (e.g. "eth0").
//
// Requires CAP_BPF and CAP_NET_ADMIN (or root). Per the privilege note in
// cmd/idsips/main.go, acquire exactly these two capabilities and drop
// everything else before calling New — this function does not manage
// privileges itself, since that decision belongs at the process's single
// entry point, not buried in a capture backend.
func New(iface string) (*Source, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("xdp: interface %q: %w", iface, err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(programObject))
	if err != nil {
		return nil, fmt.Errorf("xdp: parsing embedded program: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("xdp: kernel rejected program: %w", err)
	}

	prog, ok := coll.Programs["xdp_capture"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("xdp: embedded object missing xdp_capture program")
	}
	events, ok := coll.Maps["events"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("xdp: embedded object missing events map")
	}

	l, err := attachXDP(prog, ifi.Index)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("xdp: attaching to %q: %w", iface, err)
	}

	rd, err := ringbuf.NewReader(events)
	if err != nil {
		l.Close()
		coll.Close()
		return nil, fmt.Errorf("xdp: opening ring buffer reader: %w", err)
	}

	return &Source{coll: coll, link: l, reader: rd}, nil
}

// decodeEvent parses one ring-buffer record shaped like the C
// `struct event { __u32 len; __u8 data[SNAPLEN]; }` from xdp_capture.c.
// Bytes here come from the kernel program, not the network directly, but
// the same discipline as internal/parser applies regardless of source:
// every length is checked against what's actually present before it's
// used to slice anything.
func decodeEvent(raw []byte) ([]byte, bool) {
	if len(raw) < eventHeaderLen {
		return nil, false
	}
	n := binary.LittleEndian.Uint32(raw[:eventHeaderLen]) // BPF target is little-endian on x86/arm64
	body := raw[eventHeaderLen:]
	if uint64(n) > uint64(len(body)) || n > snapLen {
		return nil, false
	}
	frame := make([]byte, n)
	copy(frame, body[:n])
	return frame, true
}

// attachXDP tries the driver-native XDP mode first — required for genuine
// line-rate performance on hardware that supports it — and falls back to
// generic (SKB-path) mode if native attachment isn't available. This
// fallback was added after empirical testing: a bare AttachXDP call with
// no Flags can report success on some interfaces (loopback, and some
// virtualized/software interfaces in general) without the hook actually
// being invoked for real traffic, because there's no native driver to
// invoke it. Explicitly falling back to generic mode is what makes the
// hook fire in exactly that situation, verified against real loopback
// traffic during development of this package.
func attachXDP(prog *ebpf.Program, ifindex int) (link.Link, error) {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
		Flags:     link.XDPDriverMode,
	})
	if err == nil {
		return l, nil
	}
	return link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
		Flags:     link.XDPGenericMode,
	})
}

// Frames implements capture.Source. Each emitted []byte is a snapshot of
// one allowed frame, up to snapLen bytes — already the exact shape
// internal/parser.Parse expects.
func (s *Source) Frames(ctx context.Context) (<-chan []byte, error) {
	out := make(chan []byte, 256)
	go func() {
		defer close(out)
		go func() {
			<-ctx.Done()
			_ = s.reader.Close() // unblocks the Read() below on shutdown
		}()
		for {
			rec, err := s.reader.Read()
			if err != nil {
				return // reader closed (shutdown) or a real error either way
			}
			frame, ok := decodeEvent(rec.RawSample)
			if !ok {
				continue // malformed/short record; drop it and keep reading
			}
			select {
			case out <- frame:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// Close releases the XDP attachment, the ring buffer reader, and the
// loaded program/maps, in that order, so no reader is left pointing at
// freed kernel resources.
func (s *Source) Close() error {
	_ = s.reader.Close()
	_ = s.link.Close()
	s.coll.Close()
	return nil
}

// BlockIPv4 inserts src into the kernel-side blocklist_v4 map, causing the
// XDP program to XDP_DROP every subsequent packet from that address at
// line rate. This is the concrete implementation of the "block
// (in-kernel)" box in the architecture: internal/response.Blocker can
// wrap this to turn a types.VerdictBlock Decision into an actual,
// in-kernel enforcement action instead of only a dry-run log line.
func (s *Source) BlockIPv4(src net.IP) error {
	v4 := src.To4()
	if v4 == nil {
		return fmt.Errorf("xdp: %s is not an IPv4 address", src)
	}
	m, ok := s.coll.Maps["blocklist_v4"]
	if !ok {
		return fmt.Errorf("xdp: blocklist_v4 map not present")
	}
	key := binary.BigEndian.Uint32(v4) // matches ip->saddr network byte order read as __u32 in C
	return m.Put(key, uint8(1))
}

// UnblockIPv4 removes src from the kernel-side blocklist, e.g. once a
// temporary block expires.
func (s *Source) UnblockIPv4(src net.IP) error {
	v4 := src.To4()
	if v4 == nil {
		return fmt.Errorf("xdp: %s is not an IPv4 address", src)
	}
	m, ok := s.coll.Maps["blocklist_v4"]
	if !ok {
		return fmt.Errorf("xdp: blocklist_v4 map not present")
	}
	key := binary.BigEndian.Uint32(v4)
	return m.Delete(key)
}
