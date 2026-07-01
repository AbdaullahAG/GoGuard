package signature

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

// Signed rule files close a specific hole: without this, "update the rule
// file" is a standing invitation to inject rules — anyone able to write to
// the rule file path (a compromised deployment pipeline, a misconfigured
// permission, a supply-chain-compromised update job) could silently add,
// remove, or neuter detection rules. A detached ed25519 signature makes
// tampering detectable rather than just theoretically undesirable.
//
// Ed25519 (not RSA) is used because it is small, fast to verify on the hot
// reload path, has no configurable parameters to get wrong, and is part of
// crypto/ed25519 in the standard library — no external dependency is
// pulled in for it, matching this project's zero-dependency policy.

// PublicKey wraps an ed25519 public key used to verify rule-file signatures.
type PublicKey struct {
	key ed25519.PublicKey
}

// ParsePublicKeyHex parses a hex-encoded ed25519 public key, as produced by
// the signrules keygen tool.
func ParsePublicKeyHex(s string) (PublicKey, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return PublicKey{}, fmt.Errorf("signature: invalid public key hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return PublicKey{}, fmt.Errorf("signature: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return PublicKey{key: ed25519.PublicKey(raw)}, nil
}

// VerifyAndParse verifies sig (raw, hex-decoded detached signature bytes)
// over ruleFileBytes, and only if verification succeeds, parses and
// validates the rule file. Verification is deliberately performed before
// any parsing: an unverified file must never reach the JSON decoder, since
// the decoder itself is attack surface that a signature check exists
// specifically to gate.
func (pk PublicKey) VerifyAndParse(ruleFileBytes, sig []byte) ([]Rule, error) {
	if !ed25519.Verify(pk.key, ruleFileBytes, sig) {
		return nil, fmt.Errorf("signature: rule file signature verification failed")
	}
	return ParseRuleFile(ruleFileBytes)
}

// LoadSignedRuleFile reads a rule file and its detached hex-encoded
// signature from disk, verifies, and returns validated rules. sigPath
// should point at the output of `signrules sign`.
func LoadSignedRuleFile(rulePath, sigPath string, pk PublicKey) ([]Rule, error) {
	raw, err := os.ReadFile(rulePath)
	if err != nil {
		return nil, fmt.Errorf("signature: reading rule file: %w", err)
	}
	if len(raw) > MaxRuleFileBytes {
		return nil, fmt.Errorf("signature: rule file exceeds %d bytes", MaxRuleFileBytes)
	}
	sigHex, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, fmt.Errorf("signature: reading signature file: %w", err)
	}
	sig, err := hex.DecodeString(trimNewline(string(sigHex)))
	if err != nil {
		return nil, fmt.Errorf("signature: invalid signature hex: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature: signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	return pk.VerifyAndParse(raw, sig)
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
