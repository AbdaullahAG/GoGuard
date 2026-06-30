// Package decision maps a correlated score onto a final Verdict.
package decision

import (
	"time"

	"ids-ips/pkg/types"
)

// Thresholds controls where a combined score lands as a Verdict. Keeping
// these as named, swappable fields instead of inline magic numbers makes
// it possible to tune sensitivity per deployment without touching code,
// and lets every decision log exactly which threshold it crossed.
type Thresholds struct {
	Alert float64
	Block float64
}

type Engine struct {
	t Thresholds
}

func New(t Thresholds) *Engine {
	return &Engine{t: t}
}

// Decide produces a fully self-contained Decision: verdict, score, and the
// evidence behind it, ready to be logged or acted on without any further
// lookups.
func (e *Engine) Decide(flow types.FlowKey, score float64, findings []types.Finding) types.Decision {
	v := types.VerdictAllow
	switch {
	case score >= e.t.Block:
		v = types.VerdictBlock
	case score >= e.t.Alert:
		v = types.VerdictAlert
	}
	return types.Decision{
		Flow:     flow,
		Verdict:  v,
		Score:    score,
		Findings: findings,
		At:       time.Now(),
	}
}
