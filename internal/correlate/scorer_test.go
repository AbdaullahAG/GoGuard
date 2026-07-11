package correlate

import (
	"math"
	"testing"

	"ids-ips/pkg/types"
)

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

func TestScorer_NoFindingsScoresZero(t *testing.T) {
	s := New(map[string]float64{"signature": 1.0}, 0.5)
	score, findings := s.Combine(nil)
	if score != 0 {
		t.Fatalf("expected score 0 for no findings, got %v", score)
	}
	if findings != nil {
		t.Fatalf("expected findings to be passed through unchanged, got %v", findings)
	}
}

func TestScorer_SingleFindingWeightedByItsOwnWeight(t *testing.T) {
	s := New(map[string]float64{"signature": 1.0}, 0.5)
	score, _ := s.Combine([]types.Finding{{Engine: "signature", Score: 0.8}})
	// A single finding's weighted average always equals its own raw score,
	// regardless of the weight assigned to it (weight cancels out in a
	// single-entry weighted mean) — this is the correct, if slightly
	// counterintuitive, behaviour of a weighted-average formula and is
	// exactly what should be pinned down by a test.
	if !almostEqual(score, 0.8) {
		t.Fatalf("expected score 0.8, got %v", score)
	}
}

func TestScorer_WeightedFusionAcrossMultipleEngines(t *testing.T) {
	s := New(map[string]float64{
		"signature":  1.0,
		"behavioral": 0.5,
	}, 0.5)
	// weighted mean = (1.0*1.0 + 0.5*0.5) / (1.0+0.5) = 1.25/1.5 = 0.8333...
	score, findings := s.Combine([]types.Finding{
		{Engine: "signature", Score: 1.0},
		{Engine: "behavioral", Score: 0.5},
	})
	want := 1.25 / 1.5
	if !almostEqual(score, want) {
		t.Fatalf("expected score %v, got %v", want, score)
	}
	if len(findings) != 2 {
		t.Fatalf("expected findings preserved for explainability, got %d", len(findings))
	}
}

func TestScorer_UnknownEngineUsesDefaultWeight(t *testing.T) {
	s := New(map[string]float64{"signature": 1.0}, 0.25)
	// "mystery-engine" isn't in the weights map, so it must fall back to
	// defaultWeight (0.25) rather than being silently ignored or treated
	// as weight 0 (which would make it invisible to the fused score).
	score, _ := s.Combine([]types.Finding{
		{Engine: "signature", Score: 1.0},
		{Engine: "mystery-engine", Score: 0.0},
	})
	want := (1.0*1.0 + 0.0*0.25) / (1.0 + 0.25)
	if !almostEqual(score, want) {
		t.Fatalf("expected score %v, got %v", want, score)
	}
}

func TestScorer_ScoreClampedTo01(t *testing.T) {
	s := New(map[string]float64{"signature": 1.0}, 0.5)
	// Findings should already be in [0,1] by convention, but the combiner
	// must not produce an out-of-range fused score even if an engine
	// misbehaves and reports something outside that range.
	score, _ := s.Combine([]types.Finding{{Engine: "signature", Score: 5.0}})
	if score != 1.0 {
		t.Fatalf("expected score clamped to 1.0, got %v", score)
	}
	score, _ = s.Combine([]types.Finding{{Engine: "signature", Score: -5.0}})
	if score != 0.0 {
		t.Fatalf("expected score clamped to 0.0, got %v", score)
	}
}
