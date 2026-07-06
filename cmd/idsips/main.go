// Command idsips wires capture, parsing, detection, correlation, decision,
// and response into a single runnable pipeline.
package main

import (
	"context"
	"flag"
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
	rulesPath := flag.String("rules", "", "path to signed rule file (JSON); if unset, built-in default rules are used")
	rulesSigPath := flag.String("rules-sig", "", "path to detached signature for -rules (default: <rules>.sig)")
	rulesPubKey := flag.String("rules-pubkey", "", "path to hex-encoded ed25519 public key used to verify -rules")
	rulesReloadInterval := flag.Duration("rules-reload-interval", 30*time.Second, "how often to check the signed rule file for changes")
	iface := flag.String("iface", "", "network interface for real XDP capture (Linux only); if unset, synthetic mock traffic is used")
	flag.Parse()

	logger := telemetry.New(slog.Default())

	// Graceful shutdown on SIGINT/SIGTERM. A network security tool that
	// dies without releasing capture resources or flushing its audit log
	// cleanly is itself an operational risk during an incident.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sigEngine := signature.New(defaultRules())
	if *rulesPath != "" {
		setupSignedRules(ctx, sigEngine, *rulesPath, *rulesSigPath, *rulesPubKey, *rulesReloadInterval)
	}

	engines := []detect.Engine{
		sigEngine,
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
	// a non-root UID. The mock source remains the default specifically so
	// that privilege acquisition stays opt-in and explicit: it only
	// happens when an operator passes -iface, never automatically.
	var src capture.Source
	if *iface != "" {
		realSrc, closer, err := newRealCaptureSource(*iface)
		if err != nil {
			slog.Error("failed to start real capture source", "iface", *iface, "error", err)
			os.Exit(1)
		}
		defer closer.Close()
		src = realSrc
		slog.Info("using real XDP capture", "iface", *iface)
	} else {
		src = &capture.MockSource{
			Frame:    sampleFrame(),
			Interval: 200 * time.Millisecond,
		}
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

// setupSignedRules performs the mandatory, fail-loud initial load of a
// signed rule file and then starts a background watcher for hot-reload.
// Startup exits non-zero on a bad key, missing file, or failed signature —
// an operator who pointed idsips at a broken or tampered rule file must
// find out immediately, not have the process silently fall back to
// whatever default rules happened to be compiled in.
func setupSignedRules(ctx context.Context, sigEngine *signature.Engine, rulesPath, rulesSigPath, pubKeyPath string, interval time.Duration) {
	if pubKeyPath == "" {
		slog.Error("-rules given but -rules-pubkey is missing; refusing to load unverifiable rules")
		os.Exit(1)
	}
	pubHex, err := os.ReadFile(pubKeyPath)
	if err != nil {
		slog.Error("failed to read -rules-pubkey", "path", pubKeyPath, "error", err)
		os.Exit(1)
	}
	pk, err := signature.ParsePublicKeyHex(trimSpace(string(pubHex)))
	if err != nil {
		slog.Error("invalid -rules-pubkey", "error", err)
		os.Exit(1)
	}
	if rulesSigPath == "" {
		rulesSigPath = rulesPath + ".sig"
	}

	watcher := signature.NewWatcher(sigEngine, rulesPath, rulesSigPath, pk, interval, slog.Default())
	if err := watcher.LoadInitial(); err != nil {
		slog.Error("failed to load signed rule file at startup", "error", err)
		os.Exit(1)
	}
	go watcher.Run(ctx)
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && (s[0] == '\n' || s[0] == '\r' || s[0] == ' ') {
		s = s[1:]
	}
	return s
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
