package signature

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

const testRuleFile = `{"version":1,"rules":[{"id":"r1","pattern_hex":"61626364","severity":"high","reason":"test"}]}`

func TestVerifyAndParse_ValidSignatureSucceeds(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	raw := []byte(testRuleFile)
	sig := ed25519.Sign(priv, raw)

	pk, err := ParsePublicKeyHex(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("ParsePublicKeyHex: %v", err)
	}
	rules, err := pk.VerifyAndParse(raw, sig)
	if err != nil {
		t.Fatalf("expected valid signature to verify, got: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "r1" {
		t.Fatalf("unexpected rules: %+v", rules)
	}
}

func TestVerifyAndParse_TamperedContentFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := []byte(testRuleFile)
	sig := ed25519.Sign(priv, raw)

	pk, _ := ParsePublicKeyHex(hex.EncodeToString(pub))

	tampered := []byte(`{"version":1,"rules":[{"id":"r1","pattern_hex":"00","severity":"critical","reason":"injected"}]}`)
	if _, err := pk.VerifyAndParse(tampered, sig); err == nil {
		t.Fatalf("expected tampered content with a stale signature to be rejected")
	}
}

func TestVerifyAndParse_WrongKeyFails(t *testing.T) {
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	realPub, _, _ := ed25519.GenerateKey(rand.Reader)

	raw := []byte(testRuleFile)
	sig := ed25519.Sign(attackerPriv, raw) // signed by a different keypair entirely

	pk, _ := ParsePublicKeyHex(hex.EncodeToString(realPub))
	if _, err := pk.VerifyAndParse(raw, sig); err == nil {
		t.Fatalf("expected a signature from a different keypair to be rejected against the real public key")
	}
}

func TestParsePublicKeyHex_RejectsWrongLength(t *testing.T) {
	if _, err := ParsePublicKeyHex("aabbcc"); err == nil {
		t.Fatalf("expected an error for a too-short public key")
	}
}

func TestParsePublicKeyHex_RejectsInvalidHex(t *testing.T) {
	if _, err := ParsePublicKeyHex("not-hex-at-all!!"); err == nil {
		t.Fatalf("expected an error for invalid hex")
	}
}
