// Package telemetry provides structured logging with rules specific to a
// network security tool: raw packet payload is never logged.
package telemetry

import (
	"log/slog"
	"net"

	"ids-ips/pkg/types"
)

// Logger wraps slog. It deliberately never logs pkt.Payload anywhere in the
// codebase: payload bytes are attacker-controlled and are simultaneously a
// log-injection vector, a log-flooding vector, and a possible accidental
// secret leak (credentials sent in cleartext by a victim, say). Only
// structured, fixed-shape fields derived from the parsed flow are logged.
type Logger struct {
	l *slog.Logger
}

func New(l *slog.Logger) *Logger {
	if l == nil {
		l = slog.Default()
	}
	return &Logger{l: l}
}

// LogDecision implements response.AuditLogger.
func (lg *Logger) LogDecision(d types.Decision) {
	attrs := []any{
		slog.String("src_ip", net.IP(d.Flow.SrcIP[:]).String()),
		slog.String("dst_ip", net.IP(d.Flow.DstIP[:]).String()),
		slog.Int("src_port", int(d.Flow.SrcPort)),
		slog.Int("dst_port", int(d.Flow.DstPort)),
		slog.String("protocol", d.Flow.Protocol.String()),
		slog.Float64("score", d.Score),
		slog.String("verdict", verdictString(d.Verdict)),
		slog.Int("finding_count", len(d.Findings)),
	}
	switch d.Verdict {
	case types.VerdictBlock:
		lg.l.Warn("blocked flow", attrs...)
	case types.VerdictAlert:
		lg.l.Info("alerted on flow", attrs...)
	default:
		lg.l.Debug("allowed flow", attrs...)
	}
}

func verdictString(v types.Verdict) string {
	switch v {
	case types.VerdictBlock:
		return "block"
	case types.VerdictAlert:
		return "alert"
	default:
		return "allow"
	}
}
