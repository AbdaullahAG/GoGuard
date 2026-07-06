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

### Real XDP capture and in-kernel blocking

`internal/capture/xdp` is a real, kernel-verified implementation of
`capture.Source`, not a stub. The eBPF program
(`internal/capture/xdp/bpf/xdp_capture.c`) runs at the XDP hook — before
the kernel even allocates an `sk_buff` — and does two things: looks up the
source IPv4 address in an in-kernel hash map and `XDP_DROP`s it
immediately if blocked (the concrete "block (in-kernel)" box from the
architecture diagram), and otherwise copies a bounded snapshot of the
frame into a ring buffer for the existing Go pipeline to parse and
inspect exactly as it already does for `capture.MockSource`.

```sh
go build -o idsips ./cmd/idsips
sudo setcap cap_bpf,cap_net_admin+ep ./idsips   # or run as root
./idsips -iface eth0 -rules rules.json -rules-pubkey pub.hex
```

This is Linux-only, gated behind `//go:build linux` (see
`cmd/idsips/capture_linux.go` / `capture_other.go`). `go build` on Windows
or macOS — this project's normal development platform — never attempts to
compile `cilium/ebpf` at all; passing `-iface` there fails with a clear
error message instead of a build break. `capture.MockSource` remains the
default when `-iface` is omitted, so running `idsips` with no flags never
requires root or Linux.

**This was verified against a real kernel, not just written and assumed
correct** — and that process surfaced two genuine bugs, fixed in the
current code:

1. The BPF verifier rejected the first version outright
   (`R4 min value is negative`) because a packet-length value derived
   through an intermediate signed-`long` cast can't be statically proven
   bounded when passed as a helper's length argument. Fixed by computing
   the copy through a fully-unrolled, compile-time-bounded loop that
   checks `data_end` before every single byte read instead.
2. Even after the verifier accepted it, the very first working version
   silently dropped almost every real packet: it asked
   `bpf_xdp_load_bytes` for a fixed 256-byte read regardless of actual
   frame size, and that helper fails outright — no partial read — the
   moment the requested length exceeds what's actually there, which is
   true for most ordinary small packets. Real generated UDP traffic on
   loopback (0 events captured) is what exposed this; it would not have
   been caught by reading the code alone. The bounded unrolled-copy fix
   above resolved this too, since it naturally copies `min(frame_len,
   SNAPLEN)` bytes.
3. A bare `link.AttachXDP` call with no flags reported success on
   loopback without the hook ever firing (no native XDP driver exists for
   `lo`, but the attach call didn't surface that as an error). Fixed with
   an explicit driver-mode-then-generic-mode fallback in `attachXDP()`
   in `source.go` — confirmed by testing that explicit driver mode
   correctly *does* fail with `operation not supported` on loopback,
   which is exactly the signal the fallback needs.

With those three fixes, a full real chain was confirmed end-to-end on
this development machine: real UDP traffic over loopback → real XDP
capture → real ring buffer → `internal/parser` → `internal/detect/signature`
correctly flagged a payload containing `/etc/passwd` and correctly passed
a benign payload through — and the compiled `idsips -iface lo` binary
produced the identical correct block/allow decisions in its own logs.

### Still on the roadmap (not yet built)

- IPv6 support in the XDP program (currently IPv4-only, matching the rest
  of the pipeline).
- A real `response.Blocker` that calls `xdp.Source.BlockIPv4` from a
  `types.VerdictBlock` decision — the capability exists and was tested
  directly, but `cmd/idsips` still wires only `DryRunBlocker` by default
  in this version, consistent with "dry-run until validated" above.
- TLS ClientHello extension parsing (ALPN, SNI, supported groups) for a
  full JA3/JA4, not just version+cipher-suites.
- Kubernetes pod/namespace identity attached to `types.FlowKey` for
  east-west visibility.
- Distributed correlation across multiple capture nodes.

## Security design principles applied in this code

1. **Parsers fail closed, never guess.** `internal/parser`,
   `internal/detect/tlsfp`, and `internal/capture/xdp` each check every
   length against bytes actually available *before* slicing. Any
   inconsistency returns an error / `ok=false` rather than truncating or
   assuming. All three hand-rolled binary parsers ship native Go fuzz
   tests (`parser_fuzz_test.go`, `engine_fuzz_test.go`,
   `decode_fuzz_test.go`); 30-second local runs executed over 1.2M, 1.0M,
   and 0.8M inputs respectively with zero panics — run them yourself with
   `go test -fuzz=FuzzParse -fuzztime=60s ./internal/parser/`,
   `go test -fuzz=FuzzFingerprint -fuzztime=60s ./internal/detect/tlsfp/`, and
   `go test -fuzz=FuzzDecodeEvent -fuzztime=60s ./internal/capture/xdp/`.
2. **Bounded state, everywhere.** No map or channel in this codebase can
   grow without an explicit ceiling (`internal/detect/behavioral`,
   `internal/safety`). Overload degrades to dropped packets/evictions,
   never unbounded memory growth.
3. **Defense in depth, not reliance on one layer.** The worker pool
   recovers from panics as a backstop (`internal/safety/pool.go`) — but
   that backstop existing is not an excuse for sloppy engines; it exists
   because one buggy *third-party-contributed* detection engine should
   never be able to kill the whole pipeline.
4. **No cgo.** Capture is defined as a pure-Go interface; the real XDP
   backend (`internal/capture/xdp`) uses `cilium/ebpf`, a pure-Go library
   that talks to the kernel directly via syscalls — no cgo anywhere in
   this codebase, still.
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

There are no external dependencies for the core detection/decision
pipeline — `go.mod` lists none beyond `cilium/ebpf` (and its own
transitive `golang.org/x/{sys,exp}`, pulled in only because `cilium/ebpf`
itself needs them), which is the one real external dependency in this
project, added specifically for the real XDP capture backend. Everything
else — parsing, all three detection engines, correlation, decision,
signed-rule verification — is standard library only.

`internal/capture/xdp/bpf/xdp_capture.o` is a pre-compiled, stripped BPF
object embedded via `go:embed`; regenerate it after editing
`xdp_capture.c` with:

```sh
clang -O2 -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include/bpf -I/usr/include/$(uname -m)-linux-gnu \
  -c internal/capture/xdp/bpf/xdp_capture.c \
  -o internal/capture/xdp/bpf/xdp_capture.o
```

## Continuous integration

`.github/workflows/security.yml` runs on every push/PR: build, vet,
gofmt check, race-detector tests, 60-second fuzz smoke tests for both
hand-rolled parsers, `gosec`, `staticcheck`, and `govulncheck`, plus a
nightly extended (10-minute) fuzz job. This was authored and syntax
-validated (`yaml.safe_load`) but **not** run against a live GitHub
Actions environment from here — `gosec`, `staticcheck`, and
`govulncheck` all depend on hosts outside this sandbox's network
allowlist (`proxy.golang.org`, `google.golang.org`, `honnef.co`), so they
couldn't be installed and exercised locally the way the parser fuzzing,
signing tool, and XDP program were. All three tools' GitHub Actions
(`securego/gosec`, `dominikh/staticcheck-action`,
`golang/govulncheck-action`) manage their own installation and will have
normal internet access once this runs on actual GitHub infrastructure —
but that first real run is the thing to watch, not an assumption to bank
on.

## Suggested next hardening steps for contributors

- Watch the first real CI run closely — see the caveat above.
- Wire a real `response.Blocker` on top of `xdp.Source.BlockIPv4` and
  flip `cmd/idsips` to use it once dry-run alerting has been validated
  against real traffic for a deployment.
- Add IPv6 handling to `xdp_capture.c`, mirroring the IPv4 path.
- Replace `capture.MockSource` with an `AF_PACKET`-based `Source` for
  non-Linux or non-XDP-capable environments, and add an integration test
  that replays a pcap containing known evasion techniques (IP
  fragmentation overlap, TCP segmentation overlap).
