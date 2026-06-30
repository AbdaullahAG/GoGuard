package tlsfp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"

	"ids-ips/internal/detect"
	"ids-ips/pkg/types"
)

// Engine computes a JA3-style fingerprint from the TLS ClientHello at the
// start of a flow's payload, without decrypting anything — only the
// handshake metadata (TLS version, cipher suite list) is read, all of which
// is sent in cleartext by design and is exactly what lets this engine
// classify encrypted traffic it can never see the content of.
//
// This parser follows the same defensive discipline as internal/parser:
// every length is checked against bytes actually available before any
// slice happens, and any inconsistency makes it report "no opinion"
// (ok=false) rather than guess or panic. Extension parsing is not yet
// implemented; a ClientHello using extensions safely degrades to "no
// fingerprint" instead of a wrong one. The fingerprint is a classification
// feature, not a security boundary — a missed ClientHello only costs
// detection coverage, never correctness.
type Engine struct {
	knownBad map[string]string // fingerprint -> human-readable label
}

// New takes a defensive copy of knownBad so the caller can't mutate engine
// state after construction.
func New(knownBad map[string]string) *Engine {
	cp := make(map[string]string, len(knownBad))
	for k, v := range knownBad {
		cp[k] = v
	}
	return &Engine{knownBad: cp}
}

func (e *Engine) Name() string { return "tls-fingerprint" }

func (e *Engine) Inspect(pkt types.Packet) (types.Finding, bool) {
	fp, ok := fingerprint(pkt.Payload)
	if !ok {
		return types.Finding{}, false
	}
	label, bad := e.knownBad[fp]
	if !bad {
		return types.Finding{}, false
	}
	return types.Finding{
		Engine:   e.Name(),
		Score:    0.8,
		Severity: types.SeverityHigh,
		Reason:   "TLS ClientHello fingerprint matches known-bad: " + label,
	}, true
}

const (
	recordHeaderLen    = 5
	handshakeHeaderLen = 4
	clientHelloMinLen  = 2 + 32 + 1 // client_version + random + session_id length byte
)

// fingerprint extracts (record version, cipher suites) from a TLS
// ClientHello and returns an MD5 hex digest, mirroring the original JA3
// construction. MD5 is used purely as a short, stable identifier for
// grouping identical handshakes — it carries no security property here and
// is never used to authenticate or verify anything.
func fingerprint(b []byte) (string, bool) {
	if len(b) < recordHeaderLen+handshakeHeaderLen+clientHelloMinLen {
		return "", false
	}
	if b[0] != 0x16 { // TLS record type: handshake
		return "", false
	}
	recVersion := binary.BigEndian.Uint16(b[1:3])

	hs := b[recordHeaderLen:]
	if hs[0] != 0x01 { // handshake type: ClientHello
		return "", false
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	body := hs[handshakeHeaderLen:]
	if hsLen > len(body) {
		return "", false
	}
	body = body[:hsLen]
	if len(body) < clientHelloMinLen {
		return "", false
	}

	pos := 2  // skip client_version (the record version above is used instead)
	pos += 32 // random
	sessIDLen := int(body[pos])
	pos++
	if pos+sessIDLen+2 > len(body) {
		return "", false
	}
	pos += sessIDLen

	cipherSuitesLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if cipherSuitesLen%2 != 0 || pos+cipherSuitesLen > len(body) {
		return "", false
	}
	suites := body[pos : pos+cipherSuitesLen]

	buf := make([]byte, 0, 2+len(suites)*5)
	buf = appendU16Dec(buf, recVersion)
	for i := 0; i+1 < len(suites); i += 2 {
		buf = append(buf, '-')
		buf = appendU16Dec(buf, binary.BigEndian.Uint16(suites[i:i+2]))
	}

	sum := md5.Sum(buf)
	return hex.EncodeToString(sum[:]), true
}

func appendU16Dec(buf []byte, v uint16) []byte {
	var tmp [5]byte
	i := len(tmp)
	if v == 0 {
		i--
		tmp[i] = '0'
	}
	for v > 0 {
		i--
		tmp[i] = byte('0' + v%10)
		v /= 10
	}
	return append(buf, tmp[i:]...)
}

var _ detect.Engine = (*Engine)(nil)
