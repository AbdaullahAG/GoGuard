package signature

import (
	"strings"
	"testing"
)

func TestParseRuleFile_ValidFile(t *testing.T) {
	raw := []byte(`{"version":1,"rules":[
		{"id":"r1","pattern_hex":"6162","severity":"high","reason":"test"}
	]}`)
	rules, err := ParseRuleFile(raw)
	if err != nil {
		t.Fatalf("expected valid file to parse, got error: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "r1" || string(rules[0].Pattern) != "ab" {
		t.Fatalf("unexpected parsed rules: %+v", rules)
	}
}

func TestParseRuleFile_RejectsUnsupportedVersion(t *testing.T) {
	raw := []byte(`{"version":2,"rules":[]}`)
	if _, err := ParseRuleFile(raw); err == nil {
		t.Fatalf("expected an error for unsupported version")
	}
}

func TestParseRuleFile_RejectsDuplicateIDs(t *testing.T) {
	raw := []byte(`{"version":1,"rules":[
		{"id":"dup","pattern_hex":"61","severity":"low","reason":"a"},
		{"id":"dup","pattern_hex":"62","severity":"low","reason":"b"}
	]}`)
	_, err := ParseRuleFile(raw)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected a duplicate-id error, got: %v", err)
	}
}

func TestParseRuleFile_RejectsEmptyPattern(t *testing.T) {
	raw := []byte(`{"version":1,"rules":[{"id":"r1","pattern_hex":"","severity":"low","reason":"x"}]}`)
	if _, err := ParseRuleFile(raw); err == nil {
		t.Fatalf("expected an error for an empty pattern")
	}
}

func TestParseRuleFile_RejectsInvalidHex(t *testing.T) {
	raw := []byte(`{"version":1,"rules":[{"id":"r1","pattern_hex":"zz","severity":"low","reason":"x"}]}`)
	if _, err := ParseRuleFile(raw); err == nil {
		t.Fatalf("expected an error for invalid hex")
	}
}

func TestParseRuleFile_RejectsUnknownSeverity(t *testing.T) {
	raw := []byte(`{"version":1,"rules":[{"id":"r1","pattern_hex":"61","severity":"apocalyptic","reason":"x"}]}`)
	if _, err := ParseRuleFile(raw); err == nil {
		t.Fatalf("expected an error for an unknown severity")
	}
}

func TestParseRuleFile_RejectsUnknownFields(t *testing.T) {
	// DisallowUnknownFields catches typos and unexpected schema drift
	// early (at parse/sign time) rather than silently ignoring a field an
	// author thought was taking effect.
	raw := []byte(`{"version":1,"rules":[],"totally_unexpected_field":true}`)
	if _, err := ParseRuleFile(raw); err == nil {
		t.Fatalf("expected an error for an unknown top-level field")
	}
}

func TestParseRuleFile_RejectsOversizedFile(t *testing.T) {
	huge := make([]byte, MaxRuleFileBytes+1)
	if _, err := ParseRuleFile(huge); err == nil {
		t.Fatalf("expected an error for a file exceeding MaxRuleFileBytes")
	}
}

func TestParseRuleFile_RejectsTooManyRules(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"version":1,"rules":[`)
	for i := 0; i < MaxRuleCount+1; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"id":"r`)
		b.WriteString(itoa(i))
		b.WriteString(`","pattern_hex":"61","severity":"low","reason":"x"}`)
	}
	b.WriteString(`]}`)
	if _, err := ParseRuleFile([]byte(b.String())); err == nil {
		t.Fatalf("expected an error for exceeding MaxRuleCount")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
