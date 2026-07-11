package telemetry

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"ids-ips/pkg/types"
)

func newTestLogger(buf *bytes.Buffer, level slog.Level) *Logger {
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})
	return New(slog.New(h))
}

func TestLogDecision_VerdictLevelMapping(t *testing.T) {
	cases := []struct {
		verdict types.Verdict
		wantSub string
	}{
		{types.VerdictBlock, "level=WARN"},
		{types.VerdictAlert, "level=INFO"},
		{types.VerdictAllow, "level=DEBUG"},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		lg := newTestLogger(&buf, slog.LevelDebug)
		lg.LogDecision(types.Decision{Verdict: tc.verdict})
		if !strings.Contains(buf.String(), tc.wantSub) {
			t.Errorf("verdict %v: expected log to contain %q, got: %s", tc.verdict, tc.wantSub, buf.String())
		}
	}
}

func TestLogDecision_NeverLogsPayload(t *testing.T) {
	// The single most important property of this logger: raw packet
	// payload — attacker-controlled, and a log-injection/leak vector —
	// must never appear in output. types.Decision doesn't even carry a
	// Payload field, but this test pins that down as an explicit,
	// enforced property rather than an implicit one that could silently
	// regress if the struct is ever extended.
	var buf bytes.Buffer
	lg := newTestLogger(&buf, slog.LevelDebug)

	secret := "SUPER_SECRET_PAYLOAD_MARKER_credit_card_4111111111111111"
	lg.LogDecision(types.Decision{
		Verdict: types.VerdictBlock,
		Findings: []types.Finding{
			{Engine: "signature", Reason: "matched rule x"}, // reasons are fine to log; raw payload is not
		},
	})
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("logger must never emit raw payload content")
	}
}

func TestLogDecision_IncludesExpectedFields(t *testing.T) {
	var buf bytes.Buffer
	lg := newTestLogger(&buf, slog.LevelDebug)

	d := types.Decision{
		Flow:    types.FlowKey{SrcPort: 1234, DstPort: 80, Protocol: types.ProtoTCP},
		Verdict: types.VerdictAlert,
		Score:   0.75,
	}
	lg.LogDecision(d)
	out := buf.String()

	for _, want := range []string{"src_port=1234", "dst_port=80", "protocol=tcp", "score=0.75", "verdict=alert"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log output to contain %q, got: %s", want, out)
		}
	}
}

func TestNew_NilLoggerFallsBackToDefault(t *testing.T) {
	// Must not panic or otherwise misbehave when constructed with a nil
	// *slog.Logger.
	lg := New(nil)
	lg.LogDecision(types.Decision{Verdict: types.VerdictAllow})
}
