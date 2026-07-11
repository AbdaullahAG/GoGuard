package decision

import (
	"testing"

	"ids-ips/pkg/types"
)

func TestEngine_ThresholdBoundaries(t *testing.T) {
	e := New(Thresholds{Alert: 0.4, Block: 0.85})

	cases := []struct {
		name  string
		score float64
		want  types.Verdict
	}{
		{"below alert threshold", 0.39, types.VerdictAllow},
		{"exactly at alert threshold", 0.4, types.VerdictAlert},
		{"between alert and block", 0.6, types.VerdictAlert},
		{"exactly at block threshold", 0.85, types.VerdictBlock},
		{"above block threshold", 0.99, types.VerdictBlock},
		{"zero score", 0.0, types.VerdictAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Decide(types.FlowKey{}, tc.score, nil)
			if d.Verdict != tc.want {
				t.Fatalf("score %v: expected verdict %v, got %v", tc.score, tc.want, d.Verdict)
			}
		})
	}
}

func TestEngine_DecisionCarriesEvidence(t *testing.T) {
	e := New(Thresholds{Alert: 0.4, Block: 0.85})
	findings := []types.Finding{{Engine: "signature", Score: 1.0, Reason: "matched rule x"}}

	d := e.Decide(types.FlowKey{SrcPort: 1234}, 0.9, findings)

	if d.Verdict != types.VerdictBlock {
		t.Fatalf("expected block verdict, got %v", d.Verdict)
	}
	if len(d.Findings) != 1 || d.Findings[0].Reason != "matched rule x" {
		t.Fatalf("expected evidence to be carried through unchanged, got %+v", d.Findings)
	}
	if d.Flow.SrcPort != 1234 {
		t.Fatalf("expected flow key to be carried through unchanged, got %+v", d.Flow)
	}
	if d.At.IsZero() {
		t.Fatalf("expected decision timestamp to be set")
	}
}
