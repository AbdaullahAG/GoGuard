// Package parser turns raw captured frames into types.Packet.
//
// This file is the primary attack surface of the whole system: every byte
// it touches comes straight off the wire and is fully attacker-controlled,
// often deliberately malformed to crash or confuse the IDS itself rather
// than the host behind it. The rule followed throughout is simple and
// non-negotiable: every length used to slice a byte slice is checked
// against the bytes actually available *before* the slice happens, and any
// inconsistency is treated as "reject this packet", never as "guess and
// continue". Parse must never panic and must never read past frame's end.
//
// parser_fuzz_test.go fuzzes exactly this property.
package parser

import (
	"encoding/binary"
	"errors"

	"ids-ips/pkg/types"
)

// Defensive limits. These exist specifically to bound the work a single
// malicious packet can force onto the engine.
const (
	minEthernetLen = 14
	minIPv4Len     = 20
	minTCPLen      = 20
	minUDPLen      = 8
	maxPayloadLen  = 65535 // a single IPv4 packet can never legally exceed this
)

var (
	ErrTooShort         = errors.New("parser: frame shorter than minimum header length")
	ErrUnsupportedType  = errors.New("parser: unsupported ethertype or protocol")
	ErrInconsistentLen  = errors.New("parser: header-declared length disagrees with captured length")
	ErrHeaderLenInvalid = errors.New("parser: header length field out of range")
)

// Parse turns a raw captured Ethernet frame into a safely-bounded
// types.Packet, or returns an error if the frame is too short, internally
// inconsistent, or of an unsupported type. A non-nil error is the routine,
// expected outcome for adversarial or simply malformed traffic — callers
// must treat it as "drop this packet", never as a fatal condition.
func Parse(frame []byte) (types.Packet, error) {
	var pkt types.Packet

	if len(frame) < minEthernetLen {
		return pkt, ErrTooShort
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])

	switch etherType {
	case 0x0800: // IPv4
		return parseIPv4(frame[minEthernetLen:], pkt)
	default:
		return pkt, ErrUnsupportedType
	}
}

func parseIPv4(b []byte, pkt types.Packet) (types.Packet, error) {
	if len(b) < minIPv4Len {
		return pkt, ErrTooShort
	}

	verIHL := b[0]
	ihl := int(verIHL&0x0F) * 4
	if ihl < minIPv4Len || ihl > len(b) {
		return pkt, ErrHeaderLenInvalid
	}

	totalLen := int(binary.BigEndian.Uint16(b[2:4]))
	if totalLen < ihl || totalLen > len(b) {
		// The header's declared total length disagrees with what was
		// actually captured. Treat as malformed rather than truncating
		// silently and parsing whatever bytes happen to be there.
		return pkt, ErrInconsistentLen
	}

	pkt.TTL = b[8]
	protocol := b[9]
	pkt.TotalLen = totalLen

	copy(pkt.Flow.SrcIP[12:], b[12:16])
	copy(pkt.Flow.DstIP[12:], b[16:20])

	transport := b[ihl:totalLen]

	switch protocol {
	case 6: // TCP
		return parseTCP(transport, pkt)
	case 17: // UDP
		return parseUDP(transport, pkt)
	default:
		pkt.Flow.Protocol = types.ProtoUnknown
		return pkt, nil
	}
}

func parseTCP(b []byte, pkt types.Packet) (types.Packet, error) {
	if len(b) < minTCPLen {
		return pkt, ErrTooShort
	}
	dataOffset := int(b[12]>>4) * 4
	if dataOffset < minTCPLen || dataOffset > len(b) {
		return pkt, ErrHeaderLenInvalid
	}

	pkt.Flow.SrcPort = binary.BigEndian.Uint16(b[0:2])
	pkt.Flow.DstPort = binary.BigEndian.Uint16(b[2:4])
	pkt.Flow.Protocol = types.ProtoTCP

	payload := b[dataOffset:]
	if len(payload) > maxPayloadLen {
		payload = payload[:maxPayloadLen]
	}
	pkt.Payload = payload
	return pkt, nil
}

func parseUDP(b []byte, pkt types.Packet) (types.Packet, error) {
	if len(b) < minUDPLen {
		return pkt, ErrTooShort
	}
	udpLen := int(binary.BigEndian.Uint16(b[4:6]))
	if udpLen < minUDPLen || udpLen > len(b) {
		return pkt, ErrInconsistentLen
	}

	pkt.Flow.SrcPort = binary.BigEndian.Uint16(b[0:2])
	pkt.Flow.DstPort = binary.BigEndian.Uint16(b[2:4])
	pkt.Flow.Protocol = types.ProtoUDP
	pkt.Payload = b[minUDPLen:udpLen]
	return pkt, nil
}
