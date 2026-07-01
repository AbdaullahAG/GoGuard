// Command signrules is an offline tool for managing signed detection rule
// files. It is deliberately a separate binary from cmd/idsips: the running
// IDS/IPS process only ever needs the *public* key to verify rule files —
// giving it any path to a private key would defeat the point of signing in
// the first place. Run this tool on a separate, trusted signing machine (or
// a locked-down CI signing step) and ship only rules.json + rules.json.sig
// + the public key to deployments.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"ids-ips/internal/detect/signature"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "sign":
		err = runSign(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `signrules: manage signed IDS/IPS rule files

Usage:
  signrules keygen -out-priv priv.hex -out-pub pub.hex
  signrules sign   -rules rules.json -priv priv.hex -out rules.json.sig
  signrules verify -rules rules.json -sig rules.json.sig -pub pub.hex`)
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outPriv := fs.String("out-priv", "priv.hex", "output path for the private key (hex-encoded)")
	outPub := fs.String("out-pub", "pub.hex", "output path for the public key (hex-encoded)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	// 0600: the private key file must not be group/world readable. This is
	// a floor, not a substitute for keeping this file off any machine that
	// doesn't strictly need it — ideally an HSM or a CI secret store, never
	// committed to the same repo as the rules it signs.
	if err := os.WriteFile(*outPriv, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}
	if err := os.WriteFile(*outPub, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}
	fmt.Printf("generated keypair:\n  private (keep secret): %s\n  public  (ship to idsips): %s\n", *outPriv, *outPub)
	return nil
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	rulesPath := fs.String("rules", "rules.json", "path to the rule file to sign")
	privPath := fs.String("priv", "priv.hex", "path to the hex-encoded private key")
	outPath := fs.String("out", "", "output path for the signature (default: <rules>.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outPath == "" {
		*outPath = *rulesPath + ".sig"
	}

	// Validating the rule file before signing it catches authoring mistakes
	// (bad severity name, oversized pattern, duplicate ID) at sign time —
	// the one point in the pipeline where a human is actually looking —
	// rather than at deploy time when the watcher can only log and skip.
	raw, err := os.ReadFile(*rulesPath)
	if err != nil {
		return fmt.Errorf("reading rule file: %w", err)
	}
	if _, err := signature.ParseRuleFile(raw); err != nil {
		return fmt.Errorf("rule file failed validation, refusing to sign: %w", err)
	}

	privHex, err := os.ReadFile(*privPath)
	if err != nil {
		return fmt.Errorf("reading private key: %w", err)
	}
	privBytes, err := hex.DecodeString(trimSpace(string(privHex)))
	if err != nil {
		return fmt.Errorf("invalid private key hex: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(privBytes))
	}

	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), raw)
	if err := os.WriteFile(*outPath, []byte(hex.EncodeToString(sig)), 0o644); err != nil {
		return fmt.Errorf("writing signature: %w", err)
	}
	fmt.Printf("signed %s -> %s\n", *rulesPath, *outPath)
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	rulesPath := fs.String("rules", "rules.json", "path to the rule file")
	sigPath := fs.String("sig", "", "path to the signature file (default: <rules>.sig)")
	pubPath := fs.String("pub", "pub.hex", "path to the hex-encoded public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sigPath == "" {
		*sigPath = *rulesPath + ".sig"
	}

	pubHex, err := os.ReadFile(*pubPath)
	if err != nil {
		return fmt.Errorf("reading public key: %w", err)
	}
	pk, err := signature.ParsePublicKeyHex(trimSpace(string(pubHex)))
	if err != nil {
		return err
	}

	rules, err := signature.LoadSignedRuleFile(*rulesPath, *sigPath, pk)
	if err != nil {
		return err
	}
	fmt.Printf("OK: signature valid, %d rules loaded\n", len(rules))
	return nil
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
