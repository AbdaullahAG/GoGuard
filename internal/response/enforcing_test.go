package response

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"ids-ips/pkg/types"
)

// fakeIPv4Blocker records every Block/Unblock call so tests can assert on
// exact call sequences without touching a real kernel map.
type fakeIPv4Blocker struct {
	mu      sync.Mutex
	blocked map[string]int // ip -> number of times BlockIPv4 was called
	events  []string       // ordered "block:IP" / "unblock:IP" trail
}

func newFakeBlocker() *fakeIPv4Blocker {
	return &fakeIPv4Blocker{blocked: make(map[string]int)}
}

func (f *fakeIPv4Blocker) BlockIPv4(ip net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked[ip.String()]++
	f.events = append(f.events, "block:"+ip.String())
	return nil
}

func (f *fakeIPv4Blocker) UnblockIPv4(ip net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "unblock:"+ip.String())
	return nil
}

func (f *fakeIPv4Blocker) blockCount(ip string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blocked[ip]
}

func (f *fakeIPv4Blocker) eventLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.events))
	copy(out, f.events)
	return out
}

func decisionFor(ip string) types.Decision {
	var d types.Decision
	copy(d.Flow.SrcIP[12:16], net.ParseIP(ip).To4())
	d.Verdict = types.VerdictBlock
	return d
}

func TestEnforcingBlocker_NewIPBlocksOnce(t *testing.T) {
	fb := newFakeBlocker()
	eb := NewEnforcingBlocker(fb, nil, time.Minute, 100, nil)

	if err := eb.Block(context.Background(), decisionFor("10.0.0.1")); err != nil {
		t.Fatalf("Block returned error: %v", err)
	}
	if got := fb.blockCount("10.0.0.1"); got != 1 {
		t.Fatalf("expected BlockIPv4 called once, got %d", got)
	}
	if got := eb.ActiveBlocks(); got != 1 {
		t.Fatalf("expected 1 active block, got %d", got)
	}
}

func TestEnforcingBlocker_RepeatedFlowRefreshesInsteadOfReblocking(t *testing.T) {
	fb := newFakeBlocker()
	eb := NewEnforcingBlocker(fb, nil, time.Minute, 100, nil)

	for i := 0; i < 5; i++ {
		if err := eb.Block(context.Background(), decisionFor("10.0.0.1")); err != nil {
			t.Fatalf("Block returned error: %v", err)
		}
	}
	// The whole point of refresh-on-repeat is that a real block action
	// (BlockIPv4) is only ever issued once per address, no matter how many
	// times malicious traffic from it is subsequently observed.
	if got := fb.blockCount("10.0.0.1"); got != 1 {
		t.Fatalf("expected exactly 1 BlockIPv4 call across repeats, got %d", got)
	}
	if got := eb.ActiveBlocks(); got != 1 {
		t.Fatalf("expected 1 active block (not 5), got %d", got)
	}
}

func TestEnforcingBlocker_CapacityEvictsOldest(t *testing.T) {
	fb := newFakeBlocker()
	eb := NewEnforcingBlocker(fb, nil, time.Minute, 2, nil)

	_ = eb.Block(context.Background(), decisionFor("10.0.0.1"))
	_ = eb.Block(context.Background(), decisionFor("10.0.0.2"))
	if got := eb.ActiveBlocks(); got != 2 {
		t.Fatalf("expected 2 active blocks before eviction, got %d", got)
	}

	// A third distinct address exceeds capacity=2; the oldest (10.0.0.1)
	// must be evicted and explicitly unblocked, not just forgotten.
	_ = eb.Block(context.Background(), decisionFor("10.0.0.3"))
	if got := eb.ActiveBlocks(); got != 2 {
		t.Fatalf("expected capacity to stay at 2 after eviction, got %d", got)
	}

	events := fb.eventLog()
	foundUnblock := false
	for _, e := range events {
		if e == "unblock:10.0.0.1" {
			foundUnblock = true
		}
	}
	if !foundUnblock {
		t.Fatalf("expected evicted entry 10.0.0.1 to be unblocked, events: %v", events)
	}
}

func TestEnforcingBlocker_TTLExpiryLiftsBlock(t *testing.T) {
	fb := newFakeBlocker()
	// A short TTL and fast sweep interval so the test runs quickly and
	// deterministically without needing to inject a fake clock.
	eb := NewEnforcingBlocker(fb, nil, 50*time.Millisecond, 100, nil)

	_ = eb.Block(context.Background(), decisionFor("10.0.0.9"))
	if got := eb.ActiveBlocks(); got != 1 {
		t.Fatalf("expected 1 active block, got %d", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eb.Run(ctx, 10*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for eb.ActiveBlocks() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := eb.ActiveBlocks(); got != 0 {
		t.Fatalf("expected block to expire and be lifted, still have %d active", got)
	}

	events := fb.eventLog()
	if len(events) < 2 || events[len(events)-1] != "unblock:10.0.0.9" {
		t.Fatalf("expected trailing unblock event for expired IP, events: %v", events)
	}
}

func TestEnforcingBlocker_NeverBlocksLoopbackOrUnspecified(t *testing.T) {
	fb := newFakeBlocker()
	eb := NewEnforcingBlocker(fb, nil, time.Minute, 100, nil)

	_ = eb.Block(context.Background(), decisionFor("127.0.0.1"))
	_ = eb.Block(context.Background(), decisionFor("0.0.0.0"))

	if got := eb.ActiveBlocks(); got != 0 {
		t.Fatalf("expected loopback/unspecified addresses to never be enforced, got %d active", got)
	}
	if len(fb.eventLog()) != 0 {
		t.Fatalf("expected zero calls to the underlying blocker, got %v", fb.eventLog())
	}
}
