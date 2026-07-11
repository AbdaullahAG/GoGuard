package response

import (
	"container/list"
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"ids-ips/pkg/types"
)

// IPv4Blocker is the minimal capability EnforcingBlocker needs from a real
// capture backend. internal/capture/xdp.Source implements this today;
// keeping the dependency this small (rather than importing the xdp package
// directly) keeps internal/response buildable and unit-testable on every
// platform, not just Linux.
type IPv4Blocker interface {
	BlockIPv4(ip net.IP) error
	UnblockIPv4(ip net.IP) error
}

// EnforcingBlocker turns a types.VerdictBlock Decision into a real,
// in-kernel enforcement action, with two safety properties neither
// DryRunBlocker nor a naive "just call BlockIPv4" implementation would
// have on their own:
//
//  1. Bounded state with eviction. Without a cap, an attacker able to
//     trigger blocks from many distinct (possibly spoofed) source
//     addresses could grow the tracked-block set without limit — the same
//     resource-exhaustion shape internal/detect/behavioral's flow table
//     and internal/safety's queue both already guard against, so this
//     type follows the identical bounded + evict-oldest pattern.
//  2. Automatic expiry (TTL). A permanent, unreviewed block is itself an
//     operational risk: a false positive silently blocks a legitimate
//     host forever. Every block carries a lifetime, after which it's
//     lifted automatically and must be re-triggered by new evidence if
//     the behaviour continues — the same "temporary ban" philosophy tools
//     like fail2ban use, applied here at line rate instead of via a log
//     scraper.
type EnforcingBlocker struct {
	impl   IPv4Blocker
	audit  AuditLogger
	logger *slog.Logger
	ttl    time.Duration
	cap    int

	mu    sync.Mutex
	ll    *list.List // front = most recently (re-)blocked
	index map[[4]byte]*list.Element
}

type blockEntry struct {
	ip     [4]byte
	expiry time.Time
}

// NewEnforcingBlocker constructs an EnforcingBlocker. ttl is how long a
// block lasts before automatic expiry; capacity bounds how many distinct
// IPv4 addresses can be blocked at once. Both are clamped to sane minimums
// so a misconfiguration can't accidentally disable the safety property
// entirely (ttl<=0 would mean "never expire"; capacity<1 would mean
// "block nothing").
func NewEnforcingBlocker(impl IPv4Blocker, audit AuditLogger, ttl time.Duration, capacity int, logger *slog.Logger) *EnforcingBlocker {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if capacity < 1 {
		capacity = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &EnforcingBlocker{
		impl:   impl,
		audit:  audit,
		logger: logger,
		ttl:    ttl,
		cap:    capacity,
		ll:     list.New(),
		index:  make(map[[4]byte]*list.Element, capacity),
	}
}

// Block implements response.Blocker. A flow whose source is already
// blocked has its expiry refreshed rather than triggering a redundant
// kernel map write — repeated malicious traffic from an already-blocked
// address is the expected case, not an error.
func (b *EnforcingBlocker) Block(_ context.Context, d types.Decision) error {
	if b.audit != nil {
		b.audit.LogDecision(d)
	}

	var v4 [4]byte
	copy(v4[:], d.Flow.SrcIP[12:16])
	ip := net.IP(v4[:])
	if ip.IsUnspecified() || ip.IsLoopback() {
		// Never enforce against 0.0.0.0 or 127.0.0.1: the former is a
		// parsing artifact (never a real attacker address), and blocking
		// loopback would be actively harmful to the host it runs on for
		// most deployments. A deployment that genuinely wants loopback
		// enforcement can bypass this type entirely.
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if el, found := b.index[v4]; found {
		el.Value.(*blockEntry).expiry = now.Add(b.ttl)
		b.ll.MoveToFront(el)
		return nil
	}

	if err := b.impl.BlockIPv4(ip); err != nil {
		return err
	}
	el := b.ll.PushFront(&blockEntry{ip: v4, expiry: now.Add(b.ttl)})
	b.index[v4] = el
	b.logger.Warn("enforced in-kernel block", "ip", ip.String(), "ttl", b.ttl)
	b.evictIfNeeded()
	return nil
}

// evictIfNeeded must be called while holding b.mu. It evicts the
// least-recently-(re)blocked entry, mirroring
// internal/detect/behavioral's LRU eviction policy for the same reason:
// bounded memory over "which specific entry is theoretically most
// deserving of eviction".
func (b *EnforcingBlocker) evictIfNeeded() {
	for b.ll.Len() > b.cap {
		oldest := b.ll.Back()
		if oldest == nil {
			return
		}
		entry := oldest.Value.(*blockEntry)
		b.ll.Remove(oldest)
		delete(b.index, entry.ip)
		if err := b.impl.UnblockIPv4(net.IP(entry.ip[:])); err != nil {
			b.logger.Error("failed to unblock evicted entry", "ip", net.IP(entry.ip[:]).String(), "error", err)
		}
	}
}

// Run periodically sweeps for and lifts expired blocks. Intended to run
// in its own goroutine for the lifetime of the process.
func (b *EnforcingBlocker) Run(ctx context.Context, sweepInterval time.Duration) {
	if sweepInterval <= 0 {
		sweepInterval = 10 * time.Second
	}
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.sweepExpired()
		}
	}
}

func (b *EnforcingBlocker) sweepExpired() {
	now := time.Now()

	b.mu.Lock()
	var expired []blockEntry
	for el := b.ll.Back(); el != nil; {
		entry := el.Value.(*blockEntry)
		prev := el.Prev()
		if !entry.expiry.After(now) {
			b.ll.Remove(el)
			delete(b.index, entry.ip)
			expired = append(expired, *entry)
		}
		el = prev
	}
	b.mu.Unlock()

	// Unblock calls happen outside the lock: they may be slow (a real
	// kernel map delete), and holding b.mu across them would block Block()
	// on the hot decision path for no reason.
	for _, entry := range expired {
		ip := net.IP(entry.ip[:])
		if err := b.impl.UnblockIPv4(ip); err != nil {
			b.logger.Error("failed to lift expired block", "ip", ip.String(), "error", err)
			continue
		}
		b.logger.Info("lifted expired block", "ip", ip.String())
	}
}

// ActiveBlocks reports how many distinct addresses are currently blocked,
// mainly for health/metrics endpoints.
func (b *EnforcingBlocker) ActiveBlocks() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ll.Len()
}

var _ Blocker = (*EnforcingBlocker)(nil)
