package behavioral

import (
	"testing"
	"time"

	"ids-ips/pkg/types"
)

func flowFor(srcPort uint16) types.FlowKey {
	return types.FlowKey{SrcPort: srcPort, Protocol: types.ProtoTCP}
}

func TestEngine_NoFindingBeforeWindowElapses(t *testing.T) {
	e := New(100, 10*time.Second, 5.0)
	base := time.Now()
	flow := flowFor(1)

	// Even at an extreme rate, no verdict should be reached before the
	// observation window has elapsed — judging a brand new flow's rate
	// from its first couple of packets would be statistically meaningless.
	for i := 0; i < 50; i++ {
		pkt := types.Packet{Flow: flow, CapturedAt: base.Add(time.Duration(i) * time.Millisecond)}
		if _, ok := e.Inspect(pkt); ok {
			t.Fatalf("did not expect a finding before the observation window elapsed (iteration %d)", i)
		}
	}
}

func TestEngine_FlagsRateAboveThresholdAfterWindow(t *testing.T) {
	e := New(100, time.Second, 5.0) // >5 packets/sec is anomalous
	base := time.Now()
	flow := flowFor(2)

	var lastOK bool
	for i := 0; i < 200; i++ {
		// 200 packets spread across ~2 seconds is ~100 pkt/sec, well above
		// the 5 pkt/sec threshold, and comfortably exceeds the 1-second
		// observation window well before the loop ends.
		pkt := types.Packet{Flow: flow, CapturedAt: base.Add(time.Duration(i) * 10 * time.Millisecond)}
		_, ok := e.Inspect(pkt)
		lastOK = lastOK || ok
	}
	if !lastOK {
		t.Fatalf("expected the engine to flag a flow well above its rate threshold")
	}
}

func TestEngine_DoesNotFlagRateAtOrBelowThreshold(t *testing.T) {
	e := New(100, time.Second, 1000.0) // deliberately high threshold
	base := time.Now()
	flow := flowFor(3)

	for i := 0; i < 50; i++ {
		pkt := types.Packet{Flow: flow, CapturedAt: base.Add(time.Duration(i) * 100 * time.Millisecond)}
		if _, ok := e.Inspect(pkt); ok {
			t.Fatalf("did not expect a finding for a flow well under the rate threshold (iteration %d)", i)
		}
	}
}

func TestEngine_CapacityEvictsOldestFlow(t *testing.T) {
	// Capacity of 2: inserting a 3rd distinct flow must evict the first
	// (least-recently-used) one rather than growing the table further —
	// this is the resource-exhaustion guard the engine exists to provide.
	e := New(2, time.Hour, 1.0) // huge window so nothing resolves to a finding during this test
	base := time.Now()

	e.Inspect(types.Packet{Flow: flowFor(1), CapturedAt: base})
	e.Inspect(types.Packet{Flow: flowFor(2), CapturedAt: base})
	if got := e.ll.Len(); got != 2 {
		t.Fatalf("expected 2 tracked flows, got %d", got)
	}

	e.Inspect(types.Packet{Flow: flowFor(3), CapturedAt: base})
	if got := e.ll.Len(); got != 2 {
		t.Fatalf("expected table to stay capped at capacity 2 after eviction, got %d", got)
	}
	if _, tracked := e.index[flowFor(1)]; tracked {
		t.Fatalf("expected the least-recently-used flow (1) to have been evicted")
	}
	if _, tracked := e.index[flowFor(3)]; !tracked {
		t.Fatalf("expected the newest flow (3) to be tracked")
	}
}

func TestEngine_NameIsStable(t *testing.T) {
	e := New(10, time.Second, 1.0)
	if e.Name() != "behavioral" {
		t.Fatalf("expected engine name %q, got %q", "behavioral", e.Name())
	}
}
