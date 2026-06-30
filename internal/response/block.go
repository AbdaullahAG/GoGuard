// Package response enforces Block verdicts against the network.
package response

import (
	"context"

	"ids-ips/pkg/types"
)

// Blocker enforces a Block verdict. Implementations might update an
// eBPF/XDP map or an nftables set; the DryRunBlocker below — the safe
// default — only records the intended action.
type Blocker interface {
	Block(ctx context.Context, d types.Decision) error
}

// AuditLogger records every enforcement decision. Enforcement actions
// without an audit trail are a recurring real-world incident cause
// ("why was this IP blocked at 3am"), so this is a first-class interface,
// not an afterthought bolted onto logging later.
type AuditLogger interface {
	LogDecision(d types.Decision)
}

// DryRunBlocker is the default Blocker: it never touches the network. A new
// deployment should run in dry-run mode until its false-positive rate has
// been validated against real traffic — flipping to a live Blocker is an
// explicit deployment decision, not a hardcoded default a new operator
// could miss.
type DryRunBlocker struct {
	Audit AuditLogger
}

func (b *DryRunBlocker) Block(_ context.Context, d types.Decision) error {
	if b.Audit != nil {
		b.Audit.LogDecision(d)
	}
	return nil
}
