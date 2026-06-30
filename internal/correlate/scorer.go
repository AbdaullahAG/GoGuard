// Package correlate fuses findings from multiple detection engines into a
// single, explainable score.
package correlate

import "ids-ips/pkg/types"

// Scorer combines findings using an explicit weighted sum rather than a
// black-box model. This is a deliberate choice: every score produced here
// can be explained back to a SOC analyst by listing which engines fired
// and how much each contributed — that explainability is exactly the gap
// this project's analysis identified in existing tools, and a hidden model
// could not give it "for free".
type Scorer struct {
	weights map[string]float64 // engine name -> weight
	// defaultWeight applies to any engine name not explicitly listed, so a
	// newly added engine degrades gracefully instead of being silently
	// ignored.
	defaultWeight float64
}

// New takes a defensive copy of weights.
func New(weights map[string]float64, defaultWeight float64) *Scorer {
	cp := make(map[string]float64, len(weights))
	for k, v := range weights {
		cp[k] = v
	}
	return &Scorer{weights: cp, defaultWeight: defaultWeight}
}

// Combine returns an overall score in [0,1] alongside the original findings,
// preserved for the explainability trail attached to the eventual Decision.
func (s *Scorer) Combine(findings []types.Finding) (score float64, _ []types.Finding) {
	if len(findings) == 0 {
		return 0, findings
	}
	var weighted, totalWeight float64
	for _, f := range findings {
		w, ok := s.weights[f.Engine]
		if !ok {
			w = s.defaultWeight
		}
		weighted += f.Score * w
		totalWeight += w
	}
	if totalWeight == 0 {
		return 0, findings
	}
	score = weighted / totalWeight
	switch {
	case score < 0:
		score = 0
	case score > 1:
		score = 1
	}
	return score, findings
}
