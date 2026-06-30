package signature

import (
	"bytes"

	"ids-ips/internal/detect"
	"ids-ips/pkg/types"
)

// Rule is intentionally a plain byte-string match rather than a regular
// expression. A regex-based signature engine is a known denial-of-service
// vector (catastrophic backtracking, i.e. ReDoS) the moment rules are
// loaded from an externally-updatable file — a substring match has no such
// pathological case regardless of what an attacker controls. If regex
// support is ever needed, Go's regexp package already guarantees RE2
// (linear-time) semantics, but pattern count and length should still be
// capped at load time as a second line of defense.
type Rule struct {
	ID       string
	Pattern  []byte
	Severity types.Severity
	Reason   string
}

// Engine matches packet payloads against a fixed rule set.
type Engine struct {
	rules []Rule
}

// New takes a defensive copy of rules so the caller mutating its original
// slice after construction can't change engine behaviour underneath it.
func New(rules []Rule) *Engine {
	cp := make([]Rule, len(rules))
	copy(cp, rules)
	return &Engine{rules: cp}
}

func (e *Engine) Name() string { return "signature" }

func (e *Engine) Inspect(pkt types.Packet) (types.Finding, bool) {
	for _, r := range e.rules {
		if len(r.Pattern) == 0 {
			continue // an empty pattern would otherwise "match" every packet
		}
		if bytes.Contains(pkt.Payload, r.Pattern) {
			return types.Finding{
				Engine:   e.Name(),
				Score:    1.0,
				Severity: r.Severity,
				Reason:   "matched rule " + r.ID + ": " + r.Reason,
			}, true
		}
	}
	return types.Finding{}, false
}

var _ detect.Engine = (*Engine)(nil)
