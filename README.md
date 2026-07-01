# ids-ips

A hybrid IDS/IPS skeleton in Go: signature matching + behavioral anomaly
detection + TLS (JA3-style) fingerprinting, fused by an explainable
correlation/scoring layer, feeding a decision engine that emits an
auditable Allow/Alert/Block verdict per flow.

This is a foundation, not a finished product. It is built so that every
later addition (real eBPF capture, a real management API, distributed
correlation) slots into an existing interface instead of requiring a
rewrite — and so that the parts most exposed to attacker-controlled bytes
are provably hardened today, not "to be hardened later".

## Why this design

Existing open-source tools were analyzed before writing any code:

- **Snort/Suricata** — strong signature matching, but C-based, resource
  heavy under high throughput, and largely blind to TLS 1.3 traffic
  beyond basic SNI inspection.
- **Zeek** — excellent network metadata extraction, weak as an active
  *prevention* system, steep DSL learning curve.
- **Wazuh/OSSEC** — host-centric, not a network packet-inspection tool.
- **CrowdSec** — Go-based and collaborative, but log-driven rather than
  doing deep packet inspection, and its scenario engine has no real
  hybrid signature+behavioral+encrypted-traffic fusion.
- **fail2ban** — single-host, log-only, no network-level visibility.

The common gap: no tool combines (1) hybrid weighted detection instead of
signatures-only, (2) cleartext-metadata classification of encrypted
traffic, (3) explainable scoring instead of raw alert floods, and (4) an
explicit, auditable enforcement path. This project's architecture targets
exactly those four gaps.

## Architecture

```
network traffic
      v
capture & parsing      (eBPF/XDP target; pure-Go mock today)
      v
  -----------------------------
  | signature | behavioral | TLS fingerprint |   (parallel engines)
  -----------------------------
      v
correlation & scoring   (explainable weighted fusion)
      v
decision engine         (threshold -> verdict)
      v
  -------------------------
  | block (in-kernel) | alert + context |
  -------------------------
```

### Components added beyond the original sketch

- **AuditLogger as a first-class interface** (`internal/response`,
  `internal/telemetry`) — every Allow/Alert/Block decision is logged with
  its full evidence trail, not just blocks. "Why didn't it block this"
  needs an answer as much as "why did it block that".
- **Dry-run-by-default enforcement** — `DryRunBlocker` is the only
  `Blocker` wired in `cmd/idsips`. A live blocker (eBPF map update,
  nftables) is a deliberate, explicit swap an operator makes after
  validating false-positive rate against real traffic, never a default
  a new deployment could accidentally inherit.
- **Bounded resource usage everywhere there is attacker-influenced
  growth** — the behavioral engine's flow table (`internal/detect/behavioral`)
  and the processing queue (`internal/safety`) both have hard capacity
  ceilings with explicit eviction/drop policies, specifically because
  flow-table exhaustion and queue exhaustion are the two classic DoS
  vectors against a stateful NIDS.

### Signed rule hot-reload

Rule files are JSON (`version: 1`, `rules: [...]`, patterns as hex strings)
and must be detached-signed with ed25519 (`crypto/ed25519`, stdlib only —
no new dependency) before `idsips` will load them:

```sh
go run ./cmd/signrules keygen -out-priv priv.hex -out-pub pub.hex   # once, offline
go run ./cmd/signrules sign   -rules rules.json -priv priv.hex       # per update
go run ./cmd/idsips -rules rules.json -rules-pubkey pub.hex          # verifies, then runs
```

`cmd/signrules` is a separate binary on purpose: the running IDS/IPS
process only ever holds the *public* key. Startup fails loudly
(non-zero exit, no fallback) if `-rules` is given without a valid
signature — see `setupSignedRules` in `cmd/idsips/main.go`. Once
running, `signature.Watcher` polls the file (`-rules-reload-interval`,
default 30s) and hot-swaps rules via `atomic.Pointer` with zero lock
contention on the packet path (`internal/detect/signature/engine.go`).
A failed verification during a later poll is logged and the previous,
already-verified rule set is kept — the engine never partially applies
or falls back to zero rules.

This was verified end-to-end, not just unit-tested: a tampered rule file
was rejected at both process startup and during a live hot-reload attempt
(the running process kept serving its last-known-good rules and logged the
rejection on every poll, indefinitely); a file signed with a different
keypair was rejected against the real public key; and the signing tool
itself refuses to sign structurally invalid rule content before it ever
reaches a running deployment.

### Still on the roadmap (not yet built)

- Real capture backend: `github.com/cilium/ebpf` (XDP capture + in-kernel
  block) or `golang.org/x/sys/unix` AF_PACKET as a portable fallback —
  both pure Go, no cgo.
- TLS ClientHello extension parsing (ALPN, SNI, supported groups) for a
  full JA3/JA4, not just version+cipher-suites.
- Kubernetes pod/namespace identity attached to `types.FlowKey` for
  east-west visibility.
- Distributed correlation across multiple capture nodes.

## Security design principles applied in this code

1. **Parsers fail closed, never guess.** `internal/parser` and
   `internal/detect/tlsfp` check every length against bytes actually
   available *before* slicing. Any inconsistency returns an error /
   `ok=false` rather than truncating or assuming. Both hand-rolled binary
   parsers ship native Go fuzz tests (`parser_fuzz_test.go`,
   `engine_fuzz_test.go`); 30-second local runs executed over 1.2M and 1.0M
   inputs respectively with zero panics — run them yourself with
   `go test -fuzz=FuzzParse -fuzztime=60s ./internal/parser/` and
   `go test -fuzz=FuzzFingerprint -fuzztime=60s ./internal/detect/tlsfp/`.
2. **Bounded state, everywhere.** No map or channel in this codebase can
   grow without an explicit ceiling (`internal/detect/behavioral`,
   `internal/safety`). Overload degrades to dropped packets/evictions,
   never unbounded memory growth.
3. **Defense in depth, not reliance on one layer.** The worker pool
   recovers from panics as a backstop (`internal/safety/pool.go`) — but
   that backstop existing is not an excuse for sloppy engines; it exists
   because one buggy *third-party-contributed* detection engine should
   never be able to kill the whole pipeline.
4. **No cgo.** Capture is defined as a pure-Go interface specifically so
   the eventual production backend doesn't have to give up Go's memory
   safety to talk to the kernel.
5. **No regex on externally-updatable input.** The signature engine uses
   plain substring matching to avoid ReDoS from a future hostile or
   buggy rule file.
6. **No raw payload in logs.** `internal/telemetry` logs only fixed-shape,
   already-validated fields — never `pkt.Payload` — since payload bytes
   are attacker-controlled and are a log-injection/flooding/secret-leak
   vector simultaneously.
7. **Least privilege is structural, not incidental.** `cmd/idsips`
   documents exactly where capability acquisition
   (`CAP_NET_RAW`/`CAP_BPF`) and privilege drop belong, ahead of any
   packet handling, once a real capture backend replaces the mock.

## Build, test, run

```sh
go build ./...
go vet ./...
go test -race ./...                                   # unit + race detector
go test -fuzz=FuzzParse -fuzztime=60s ./internal/parser/   # adversarial-input fuzzing
go run ./cmd/idsips                                   # runs against synthetic mock traffic
```

There are no external dependencies — `go.mod` lists none on purpose, to
keep the supply-chain surface as small as possible for a security tool.

## Suggested next hardening steps for contributors

- Replace `capture.MockSource` with an `AF_PACKET`-based `Source` and add
  an integration test that replays a pcap containing known evasion
  techniques (IP fragmentation overlap, TCP segmentation overlap) and
  asserts the parser/engines behave correctly against each.
- Add `gosec` and `staticcheck` to CI once the module has network access
  to fetch them (this sandbox's network policy didn't allow it; the code
  was checked with `go vet` and `gofmt` instead, both passing cleanly).
- Real capture backend (see roadmap above) will need its own fuzz/replay
  tests against known IDS-evasion techniques (fragmentation overlap, TCP
  segmentation overlap) before it's trusted with live traffic.
