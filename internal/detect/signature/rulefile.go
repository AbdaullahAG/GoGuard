package signature

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"ids-ips/pkg/types"
)

// Hard limits enforced on every loaded rule file, independent of what the
// signature check does. A valid signature only proves the file wasn't
// tampered with in transit/storage — it says nothing about whether the
// *signer* handed you something reasonable. Both checks are required.
const (
	MaxRuleFileBytes = 1 << 20 // 1 MiB; a legitimate rule set is nowhere near this
	MaxRuleCount     = 10_000
	MaxPatternBytes  = 4096
	MaxIDBytes       = 128
	MaxReasonBytes   = 512
)

// ruleFile is the on-disk JSON shape. Pattern is hex-encoded rather than a
// raw JSON string specifically so rule authors can express arbitrary binary
// byte patterns (shellcode fragments, non-UTF8 payloads) without fighting
// JSON string escaping — hex has no encoding ambiguity to exploit.
type ruleFile struct {
	Version int        `json:"version"`
	Rules   []ruleJSON `json:"rules"`
}

type ruleJSON struct {
	ID         string `json:"id"`
	PatternHex string `json:"pattern_hex"`
	Severity   string `json:"severity"`
	Reason     string `json:"reason"`
}

var severityByName = map[string]types.Severity{
	"info":     types.SeverityInfo,
	"low":      types.SeverityLow,
	"medium":   types.SeverityMedium,
	"high":     types.SeverityHigh,
	"critical": types.SeverityCritical,
}

// ParseRuleFile decodes and strictly validates raw rule-file bytes. It
// never returns a partially-valid rule set: any single bad rule fails the
// whole file, since a hot-reloader must never silently drop rules an
// operator believes are active.
func ParseRuleFile(raw []byte) ([]Rule, error) {
	if len(raw) > MaxRuleFileBytes {
		return nil, fmt.Errorf("signature: rule file exceeds %d bytes", MaxRuleFileBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rf ruleFile
	if err := dec.Decode(&rf); err != nil {
		return nil, fmt.Errorf("signature: invalid rule file JSON: %w", err)
	}
	if rf.Version != 1 {
		return nil, fmt.Errorf("signature: unsupported rule file version %d", rf.Version)
	}
	if len(rf.Rules) > MaxRuleCount {
		return nil, fmt.Errorf("signature: rule file has %d rules, limit is %d", len(rf.Rules), MaxRuleCount)
	}

	seen := make(map[string]struct{}, len(rf.Rules))
	rules := make([]Rule, 0, len(rf.Rules))
	for i, rj := range rf.Rules {
		rule, err := validateRule(rj)
		if err != nil {
			return nil, fmt.Errorf("signature: rule[%d]: %w", i, err)
		}
		if _, dup := seen[rule.ID]; dup {
			return nil, fmt.Errorf("signature: rule[%d]: duplicate id %q", i, rule.ID)
		}
		seen[rule.ID] = struct{}{}
		rules = append(rules, rule)
	}
	return rules, nil
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func validateRule(rj ruleJSON) (Rule, error) {
	if rj.ID == "" || len(rj.ID) > MaxIDBytes {
		return Rule{}, fmt.Errorf("id must be 1..%d bytes", MaxIDBytes)
	}
	if len(rj.Reason) > MaxReasonBytes {
		return Rule{}, fmt.Errorf("reason exceeds %d bytes", MaxReasonBytes)
	}
	sev, ok := severityByName[rj.Severity]
	if !ok {
		return Rule{}, fmt.Errorf("unknown severity %q", rj.Severity)
	}
	pattern, err := decodeHex(rj.PatternHex)
	if err != nil {
		return Rule{}, fmt.Errorf("pattern_hex: %w", err)
	}
	if len(pattern) == 0 {
		return Rule{}, fmt.Errorf("pattern must not be empty")
	}
	if len(pattern) > MaxPatternBytes {
		return Rule{}, fmt.Errorf("pattern exceeds %d bytes", MaxPatternBytes)
	}
	return Rule{ID: rj.ID, Pattern: pattern, Severity: sev, Reason: rj.Reason}, nil
}
