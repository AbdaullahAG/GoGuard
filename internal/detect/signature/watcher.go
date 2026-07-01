package signature

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// Watcher polls a signed rule file for changes and hot-reloads the target
// Engine when it changes. Polling (mtime comparison) is used instead of a
// filesystem-event library like fsnotify specifically to keep this
// project's zero-external-dependency policy for anything on the packet
// path — a rule reloader is adjacent enough to that path to hold it to the
// same bar.
//
// Fail-safe behaviour is the entire point of this type: any read error,
// signature failure, or validation failure during a reload attempt is
// logged and the engine's current rules are left untouched. A bad update
// must never take detection capability down to zero — that would turn "an
// attacker can't inject rules" into "an attacker can trigger a denial of
// service against rule updates instead", which is not a win.
type Watcher struct {
	engine    *Engine
	rulePath  string
	sigPath   string
	publicKey PublicKey
	interval  time.Duration
	logger    *slog.Logger

	lastModTime time.Time
}

// NewWatcher constructs a Watcher. It does not perform an initial load —
// call LoadInitial once at startup so a bad rule file fails process
// startup loudly rather than being silently deferred to the first poll.
func NewWatcher(engine *Engine, rulePath, sigPath string, pk PublicKey, interval time.Duration, logger *slog.Logger) *Watcher {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Watcher{
		engine:    engine,
		rulePath:  rulePath,
		sigPath:   sigPath,
		publicKey: pk,
		interval:  interval,
		logger:    logger,
	}
}

// LoadInitial performs the first, mandatory load. Unlike later polls, a
// failure here is returned to the caller rather than merely logged: an
// operator starting the process with a broken or unsigned rule file should
// find out immediately, not have the process silently start with zero
// signature coverage.
func (w *Watcher) LoadInitial() error {
	rules, err := LoadSignedRuleFile(w.rulePath, w.sigPath, w.publicKey)
	if err != nil {
		return err
	}
	w.engine.SetRules(rules)
	if fi, statErr := os.Stat(w.rulePath); statErr == nil {
		w.lastModTime = fi.ModTime()
	}
	w.logger.Info("loaded signed rule file", "path", w.rulePath, "rule_count", w.engine.RuleCount())
	return nil
}

// Run polls until ctx is cancelled. Intended to be started in its own
// goroutine after LoadInitial has succeeded.
func (w *Watcher) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.pollOnce()
		}
	}
}

func (w *Watcher) pollOnce() {
	fi, err := os.Stat(w.rulePath)
	if err != nil {
		w.logger.Warn("rule file stat failed, keeping current rules", "path", w.rulePath, "error", err)
		return
	}
	if !fi.ModTime().After(w.lastModTime) {
		return // unchanged, nothing to do
	}

	rules, err := LoadSignedRuleFile(w.rulePath, w.sigPath, w.publicKey)
	if err != nil {
		// Deliberately does not update lastModTime: an operator fixing a
		// bad file will produce a newer mtime on the next real save, which
		// naturally triggers another attempt without any extra logic here.
		w.logger.Error("rule file reload failed, keeping previous rules", "path", w.rulePath, "error", err)
		return
	}

	w.engine.SetRules(rules)
	w.lastModTime = fi.ModTime()
	w.logger.Info("hot-reloaded signed rule file", "path", w.rulePath, "rule_count", len(rules))
}
