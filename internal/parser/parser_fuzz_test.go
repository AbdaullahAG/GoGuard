package parser

import "testing"

// FuzzParse feeds arbitrary byte slices into Parse. The only property under
// test is that parsing untrusted, attacker-shaped input always returns
// rather than panicking or hanging — Go's fuzzing harness fails the test
// automatically the moment Parse panics, so no extra assertion is needed.
// This directly targets the exact failure mode this package exists to
// prevent: one malformed packet taking down the whole IDS/IPS process.
//
// Run a real fuzzing session locally with:
//
//	go test -fuzz=FuzzParse -fuzztime=60s ./internal/parser/
func FuzzParse(f *testing.F) {
	seeds := [][]byte{
		{},
		make([]byte, minEthernetLen),
		validIPv4TCPSeed(),
		validIPv4UDPSeed(),
		truncatedIPv4Seed(),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}

func validIPv4TCPSeed() []byte {
	frame := make([]byte, 14+20+20)
	frame[12], frame[13] = 0x08, 0x00 // EtherType: IPv4
	ip := frame[14:]
	ip[0] = 0x45 // version 4, IHL 5 (20 bytes, no options)
	ip[9] = 6    // protocol: TCP
	putU16(ip[2:4], 40)
	tcp := frame[14+20:]
	tcp[12] = 5 << 4 // data offset 5 (20 bytes, no options)
	return frame
}

func validIPv4UDPSeed() []byte {
	frame := make([]byte, 14+20+8)
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14:]
	ip[0] = 0x45
	ip[9] = 17 // protocol: UDP
	putU16(ip[2:4], 28)
	udp := frame[14+20:]
	putU16(udp[4:6], 8)
	return frame
}

// truncatedIPv4Seed declares a total length larger than the captured frame —
// exactly the kind of inconsistency real attack traffic uses to try to
// trick a parser into reading past the buffer.
func truncatedIPv4Seed() []byte {
	frame := make([]byte, 14+20)
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14:]
	ip[0] = 0x45
	ip[9] = 6
	putU16(ip[2:4], 9000) // far larger than the actual 34-byte frame
	return frame
}

func putU16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}
