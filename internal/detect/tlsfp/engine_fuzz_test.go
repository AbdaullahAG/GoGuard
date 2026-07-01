package tlsfp

import "testing"

// FuzzFingerprint feeds arbitrary byte slices into fingerprint. Like
// FuzzParse in internal/parser, the only property under test is "never
// panics" — Go's fuzzing harness fails the test the instant fingerprint
// panics, so no further assertion is needed. This is the second hand-rolled
// binary parser in the codebase (after internal/parser) and reads bytes
// from the same untrusted source, so it gets the same scrutiny.
//
//	go test -fuzz=FuzzFingerprint -fuzztime=60s ./internal/detect/tlsfp/
func FuzzFingerprint(f *testing.F) {
	seeds := [][]byte{
		{},
		validClientHelloSeed(),
		truncatedAtSessionIDSeed(),
		truncatedAtCipherSuitesSeed(),
		oddCipherSuitesLenSeed(),
		wrongRecordTypeSeed(),
		wrongHandshakeTypeSeed(),
		oversizedHandshakeLenSeed(),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = fingerprint(data)
	})
}

// buildClientHello assembles a minimal, well-formed
// record-header + handshake-header + ClientHello-body byte slice with the
// given cipher suites, so seeds exercise the real field layout instead of
// being hand-jittered magic bytes.
func buildClientHello(cipherSuites []byte) []byte {
	body := make([]byte, 0, 2+32+1+2+len(cipherSuites))
	body = append(body, 0x03, 0x03)                                          // client_version
	body = append(body, make([]byte, 32)...)                                 // random
	body = append(body, 0x00)                                                // session_id length: 0
	body = append(body, byte(len(cipherSuites)>>8), byte(len(cipherSuites))) // cipher suites length
	body = append(body, cipherSuites...)

	hs := make([]byte, 0, handshakeHeaderLen+len(body))
	hs = append(hs, 0x01) // handshake type: ClientHello
	hsLen := len(body)
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	hs = append(hs, body...)

	frame := make([]byte, 0, recordHeaderLen+len(hs))
	frame = append(frame, 0x16, 0x03, 0x03) // record type: handshake, version
	frame = append(frame, byte(len(hs)>>8), byte(len(hs)))
	frame = append(frame, hs...)
	return frame
}

func validClientHelloSeed() []byte {
	return buildClientHello([]byte{0x00, 0x2f, 0x00, 0x35, 0xc0, 0x2f})
}

// truncatedAtSessionIDSeed declares a session_id length longer than the
// bytes actually remaining — the exact inconsistency an attacker would use
// to try to push the parser past the buffer.
func truncatedAtSessionIDSeed() []byte {
	f := buildClientHello([]byte{0x00, 0x2f})
	// session_id length byte lives at recordHeaderLen+handshakeHeaderLen+2+32
	idx := recordHeaderLen + handshakeHeaderLen + 2 + 32
	f[idx] = 0xFF // claim a 255-byte session ID that isn't there
	return f
}

func truncatedAtCipherSuitesSeed() []byte {
	f := buildClientHello([]byte{0x00, 0x2f})
	// cipher_suites length field: 2 bytes right after session_id (len 0)
	idx := recordHeaderLen + handshakeHeaderLen + 2 + 32 + 1
	f[idx], f[idx+1] = 0xFF, 0xFF // claim far more cipher suite bytes than present
	return f
}

func oddCipherSuitesLenSeed() []byte {
	f := buildClientHello([]byte{0x00, 0x2f, 0x00})
	idx := recordHeaderLen + handshakeHeaderLen + 2 + 32 + 1
	f[idx], f[idx+1] = 0x00, 0x03 // odd length: 3 bytes for a 2-byte-unit list
	return f
}

func wrongRecordTypeSeed() []byte {
	f := buildClientHello([]byte{0x00, 0x2f})
	f[0] = 0x17 // application_data, not handshake
	return f
}

func wrongHandshakeTypeSeed() []byte {
	f := buildClientHello([]byte{0x00, 0x2f})
	f[recordHeaderLen] = 0x02 // ServerHello, not ClientHello
	return f
}

func oversizedHandshakeLenSeed() []byte {
	f := buildClientHello([]byte{0x00, 0x2f})
	idx := recordHeaderLen + 1
	f[idx], f[idx+1], f[idx+2] = 0xFF, 0xFF, 0xFF // handshake length far exceeds actual body
	return f
}
