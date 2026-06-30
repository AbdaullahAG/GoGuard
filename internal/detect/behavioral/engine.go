package behavioral

import (
	"container/list"
	"sync"
	"time"

	"ids-ips/internal/detect"
	"ids-ips/pkg/types"
)

// Engine flags flows whose packet rate exceeds a fixed threshold within a
// window. This is a simple, fully explainable rule rather than an ML
// model — see the project README for why that trade-off was made for a
// first version: every flag this engine raises can be explained in one
// sentence to a SOC analyst.
//
// Security note: per-flow state is the classic resource-exhaustion target
// for a stateful NIDS — an attacker spoofing many source addresses can
// otherwise grow this table without bound until the process is OOM-killed.
// capacity enforces a hard ceiling and evicts the least-recently-used flow
// once full, so memory use stays bounded no matter how much spoofed
// traffic arrives.
type Engine struct {
	mu       sync.Mutex
	capacity int
	window   time.Duration
	maxRate  float64 // packets/sec considered anomalous once window has elapsed

	ll    *list.List // front = most recently used
	index map[types.FlowKey]*list.Element
}

type entry struct {
	key       types.FlowKey
	packets   uint64
	firstSeen time.Time
}

// New constructs an Engine. capacity bounds the number of tracked flows;
// window is the minimum observation period before a rate judgement is
// made (avoids flagging the first few packets of a brand new flow); maxRate
// is the packets/sec threshold above which a flow is considered anomalous.
func New(capacity int, window time.Duration, maxRate float64) *Engine {
	if capacity < 1 {
		capacity = 1
	}
	return &Engine{
		capacity: capacity,
		window:   window,
		maxRate:  maxRate,
		ll:       list.New(),
		index:    make(map[types.FlowKey]*list.Element, capacity),
	}
}

func (e *Engine) Name() string { return "behavioral" }

func (e *Engine) Inspect(pkt types.Packet) (types.Finding, bool) {
	now := pkt.CapturedAt
	if now.IsZero() {
		now = time.Now()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	el, found := e.index[pkt.Flow]
	var ent *entry
	if found {
		ent = el.Value.(*entry)
		e.ll.MoveToFront(el)
	} else {
		ent = &entry{key: pkt.Flow, firstSeen: now}
		el = e.ll.PushFront(ent)
		e.index[pkt.Flow] = el
		e.evictIfNeeded()
	}
	ent.packets++

	elapsed := now.Sub(ent.firstSeen).Seconds()
	if elapsed <= 0 || elapsed < e.window.Seconds() {
		return types.Finding{}, false
	}

	rate := float64(ent.packets) / elapsed
	if rate <= e.maxRate {
		return types.Finding{}, false
	}

	return types.Finding{
		Engine:   e.Name(),
		Score:    clamp01(rate / (e.maxRate * 2)),
		Severity: types.SeverityMedium,
		Reason:   "flow packet rate exceeds baseline",
	}, true
}

// evictIfNeeded must be called while holding e.mu.
func (e *Engine) evictIfNeeded() {
	for e.ll.Len() > e.capacity {
		oldest := e.ll.Back()
		if oldest == nil {
			return
		}
		e.ll.Remove(oldest)
		delete(e.index, oldest.Value.(*entry).key)
	}
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

var _ detect.Engine = (*Engine)(nil)
