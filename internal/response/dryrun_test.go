package response

import (
	"context"
	"testing"

	"ids-ips/pkg/types"
)

type fakeAuditLogger struct {
	decisions []types.Decision
}

func (f *fakeAuditLogger) LogDecision(d types.Decision) {
	f.decisions = append(f.decisions, d)
}

func TestDryRunBlocker_LogsButNeverEnforces(t *testing.T) {
	audit := &fakeAuditLogger{}
	b := &DryRunBlocker{Audit: audit}

	d := types.Decision{Verdict: types.VerdictBlock, Score: 0.95}
	if err := b.Block(context.Background(), d); err != nil {
		t.Fatalf("DryRunBlocker.Block returned an error: %v", err)
	}

	if len(audit.decisions) != 1 {
		t.Fatalf("expected exactly one audited decision, got %d", len(audit.decisions))
	}
	if audit.decisions[0].Score != 0.95 {
		t.Fatalf("expected the audited decision to match what was passed in")
	}
}

func TestDryRunBlocker_NilAuditIsSafe(t *testing.T) {
	b := &DryRunBlocker{} // Audit deliberately left nil
	if err := b.Block(context.Background(), types.Decision{}); err != nil {
		t.Fatalf("expected a nil Audit logger to be handled safely, got error: %v", err)
	}
}
