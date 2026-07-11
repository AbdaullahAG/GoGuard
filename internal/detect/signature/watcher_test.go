package signature

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ids-ips/pkg/types"
)

func writeSignedRuleFile(t *testing.T, dir, name, content string, priv ed25519.PrivateKey) (rulePath, sigPath string) {
	t.Helper()
	rulePath = filepath.Join(dir, name)
	sigPath = rulePath + ".sig"
	if err := os.WriteFile(rulePath, []byte(content), 0o644); err != nil {
		t.Fatalf("writing rule file: %v", err)
	}
	sig := ed25519.Sign(priv, []byte(content))
	if err := os.WriteFile(sigPath, []byte(hex.EncodeToString(sig)), 0o644); err != nil {
		t.Fatalf("writing signature file: %v", err)
	}
	return rulePath, sigPath
}

func TestWatcher_LoadInitial_ValidFileSucceeds(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ParsePublicKeyHex(hex.EncodeToString(pub))
	dir := t.TempDir()
	rulePath, sigPath := writeSignedRuleFile(t, dir, "rules.json", testRuleFile, priv)

	e := New(nil)
	w := NewWatcher(e, rulePath, sigPath, pk, time.Hour, nil)
	if err := w.LoadInitial(); err != nil {
		t.Fatalf("expected valid signed file to load, got: %v", err)
	}
	if got := e.RuleCount(); got != 1 {
		t.Fatalf("expected 1 rule loaded, got %d", got)
	}
}

func TestWatcher_LoadInitial_TamperedFileFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ParsePublicKeyHex(hex.EncodeToString(pub))
	dir := t.TempDir()
	rulePath, sigPath := writeSignedRuleFile(t, dir, "rules.json", testRuleFile, priv)

	// Tamper with the rule file after signing, without re-signing —
	// exactly the injection attempt signed rule files exist to prevent.
	if err := os.WriteFile(rulePath, []byte(`{"version":1,"rules":[{"id":"evil","pattern_hex":"00","severity":"critical","reason":"injected"}]}`), 0o644); err != nil {
		t.Fatalf("tampering with rule file: %v", err)
	}

	e := New(nil)
	w := NewWatcher(e, rulePath, sigPath, pk, time.Hour, nil)
	if err := w.LoadInitial(); err == nil {
		t.Fatalf("expected tampered file to be rejected at startup")
	}
	if got := e.RuleCount(); got != 0 {
		t.Fatalf("expected zero rules loaded after a failed startup load, got %d", got)
	}
}

func TestWatcher_Run_HotReloadsOnValidUpdate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ParsePublicKeyHex(hex.EncodeToString(pub))
	dir := t.TempDir()
	rulePath, sigPath := writeSignedRuleFile(t, dir, "rules.json", testRuleFile, priv)

	e := New(nil)
	w := NewWatcher(e, rulePath, sigPath, pk, 20*time.Millisecond, nil)
	if err := w.LoadInitial(); err != nil {
		t.Fatalf("LoadInitial: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	// Ensure the new file's mtime is observably newer on filesystems with
	// coarse mtime resolution.
	time.Sleep(20 * time.Millisecond)
	updated := `{"version":1,"rules":[
		{"id":"r1","pattern_hex":"61626364","severity":"high","reason":"test"},
		{"id":"r2","pattern_hex":"65666768","severity":"medium","reason":"second rule"}
	]}`
	writeSignedRuleFile(t, dir, "rules.json", updated, priv)

	deadline := time.Now().Add(3 * time.Second)
	for e.RuleCount() != 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := e.RuleCount(); got != 2 {
		t.Fatalf("expected hot-reload to pick up the updated 2-rule file, got %d rules", got)
	}
}

func TestWatcher_Run_RejectsUnsignedUpdateAndKeepsOldRules(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ParsePublicKeyHex(hex.EncodeToString(pub))
	dir := t.TempDir()
	rulePath, _ := writeSignedRuleFile(t, dir, "rules.json", testRuleFile, priv)

	e := New(nil)
	w := NewWatcher(e, rulePath, rulePath+".sig", pk, 20*time.Millisecond, nil)
	if err := w.LoadInitial(); err != nil {
		t.Fatalf("LoadInitial: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	time.Sleep(20 * time.Millisecond)
	// Modify the rule file WITHOUT re-signing: simulates an attacker who
	// can write the file but doesn't hold the private key.
	if err := os.WriteFile(rulePath, []byte(`{"version":1,"rules":[{"id":"evil","pattern_hex":"00","severity":"critical","reason":"injected"}]}`), 0o644); err != nil {
		t.Fatalf("writing unsigned update: %v", err)
	}

	// Give the watcher several poll cycles to (fail to) pick this up.
	time.Sleep(300 * time.Millisecond)

	if got := e.RuleCount(); got != 1 {
		t.Fatalf("expected the engine to keep the last known-good rule set (1 rule), got %d", got)
	}
	// And specifically confirm the injected rule never became active: its
	// pattern_hex "00" is a single null byte, so a payload containing one
	// would match if (and only if) the injected rule had taken effect.
	if _, ok := e.Inspect(types.Packet{Payload: []byte{0x00}}); ok {
		t.Fatalf("the injected (unsigned) rule must never become active")
	}
}
