// Package types holds the data structures shared across the whole pipeline.
// Keeping them in one dependency-free package avoids import cycles between
// the parser, detection engines, correlator, and decision engine.
package types

import "time"

// Protocol identifies a transport-layer protocol.
type Protocol uint8

const (
	ProtoUnknown Protocol = iota
	ProtoTCP
	ProtoUDP
	ProtoICMP
)

func (p Protocol) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	default:
		return "unknown"
	}
}

// FlowKey identifies a 5-tuple flow. It deliberately uses fixed-size byte
// arrays rather than net.IP (a slice), so FlowKey stays comparable and safe
// to use directly as a map key without any wrapper or hashing step.
type FlowKey struct {
	SrcIP    [16]byte // IPv4 addresses are stored right-aligned in the last 4 bytes
	DstIP    [16]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol Protocol
}

// Packet is the result of safely parsing one raw frame. By the time a Packet
// exists, every field has already been bounds-checked by the parser —
// but Payload still contains attacker-controlled bytes, so anything that
// re-slices it must re-validate length itself rather than trusting this far.
type Packet struct {
	CapturedAt time.Time
	Flow       FlowKey
	TTL        uint8
	Payload    []byte // application-layer bytes only, length already validated
	TotalLen   int    // on-wire IP total length, used for rate/volume checks
}

// Severity ranks how dangerous a single finding is.
type Severity uint8

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// Finding is what one detection engine reports about one packet/flow.
// Score lives in [0,1]. Reason must always be a human-readable sentence,
// since it feeds directly into the explainability shown to a SOC analyst —
// "matched rule X" is acceptable, a bare rule ID is not.
type Finding struct {
	Engine   string
	Score    float64
	Severity Severity
	Reason   string
}

// Verdict is the final action chosen for a flow after correlation.
type Verdict uint8

const (
	VerdictAllow Verdict = iota
	VerdictAlert
	VerdictBlock
)

// Decision bundles a verdict with the evidence that produced it. Every
// block (and every alert) carries its own explanation, so "why did it do
// that" never requires reconstructing state from logs after the fact.
type Decision struct {
	Flow     FlowKey
	Verdict  Verdict
	Score    float64
	Findings []Finding
	At       time.Time
}
