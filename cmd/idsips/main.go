// Command idsips wires capture, parsing, detection, correlation, decision,
// and response into a single runnable pipeline.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ids-ips/internal/capture"
	"ids-ips/internal/correlate"
	"ids-ips/internal/decision"
	"ids-ips/internal/detect"
	"ids-ips/internal/detect/behavioral"
	"ids-ips/internal/detect/signature"
	"ids-ips/internal/detect/tlsfp"
	"ids-ips/internal/parser"
	"ids-ips/internal/response"
	"ids-ips/internal/safety"
	"ids-ips/internal/telemetry"
	"ids-ips/pkg/types"
)

func main() {
	logger := telemetry.New(slog.Default())

	// Graceful shutdown on SIGINT/SIGTERM. A network security tool that
	// dies without releasing capture resources or flushing its audit log
	// cleanly is itself an operational risk during an incident.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	engines := []detect.Engine{
		signature.New(defaultRules()),
		behavioral.New(10_000, 10*time.Second, 50.0),
		tlsfp.New(map[string]string{}),
	}
	scorer := correlate.New(map[string]float64{
		"signature":       1.0,
		"behavioral":      0.6,
		"tls-fingerprint": 0.8,
	}, 0.5)
	decider := decision.New(decision.Thresholds{Alert: 0.4, Block: 0.85})
	blocker := &response.DryRunBlocker{Audit: logger}

	// NOTE for production: capability handling belongs here, before any
	// packet is touched — acquire CAP_NET_RAW/CAP_BPF via
	// golang.org/x/sys/unix, then drop every other capability and switch to
	// a non-root UID. The mock source below needs no privileges at all,
	// which is exactly why it is the default: privilege acquisition is
	// opt-in and explicit, never automatic.
	src := &capture.MockSource{
		Frame:    sampleFrame(),
		Interval: 200 * time.Millisecond,
	}
	frames, err := src.Frames(ctx)
	if err != nil {
		slog.Error("failed to start capture source", "error", err)
		os.Exit(1)
	}

	pool := safety.New(8, 1024)
	defer pool.Shutdown(ctx)

	for frame := range frames {
		frame := frame
		if !pool.Submit(func() {
			process(ctx, frame, engines, scorer, decider, blocker, logger)
		}) {
			slog.Warn("packet dropped: processing queue full", "total_dropped", pool.Dropped())
		}
	}
}

func process(
	ctx context.Context,
	raw []byte,
	engines []detect.Engine,
	scorer *correlate.Scorer,
	decider *decision.Engine,
	blocker response.Blocker,
	logger *telemetry.Logger,
) {
	pkt, err := parser.Parse(raw)
	if err != nil {
		// A parse failure is routine under adversarial traffic, not an
		// operational error — log at debug and move on, never crash.
		slog.Debug("dropping unparseable frame", "error", err)
		return
	}

	var findings []types.Finding
	for _, eng := range engines {
		if f, ok := eng.Inspect(pkt); ok {
			findings = append(findings, f)
		}
	}

	score, findings := scorer.Combine(findings)
	d := decider.Decide(pkt.Flow, score, findings)

	if d.Verdict == types.VerdictBlock {
		if err := blocker.Block(ctx, d); err != nil {
			slog.Error("block action failed", "error", err)
		}
		return
	}
	logger.LogDecision(d)
}

func defaultRules() []signature.Rule {
	return []signature.Rule{
		{ID: "demo-1", Pattern: []byte("/etc/passwd"), Severity: types.SeverityHigh, Reason: "path traversal indicator"},
	}
}

// sampleFrame is a minimal, well-formed IPv4/TCP frame used only by
// MockSource so the pipeline has something to parse out of the box.
// Replace capture.MockSource with a real capture.Source before pointing
// this at live traffic.
func sampleFrame() []byte {
	frame := make([]byte, 14+20+20)
	frame[12], frame[13] = 0x08, 0x00 // EtherType: IPv4
	ip := frame[14:]
	ip[0] = 0x45 // version 4, IHL 5
	ip[9] = 6    // protocol: TCP
	ip[2], ip[3] = 0, 40
	tcp := frame[14+20:]
	tcp[12] = 5 << 4 // data offset 5, no options
	return frame
}
