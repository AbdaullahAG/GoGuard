package types

import "testing"

func TestProtocol_String(t *testing.T) {
	cases := []struct {
		p    Protocol
		want string
	}{
		{ProtoTCP, "tcp"},
		{ProtoUDP, "udp"},
		{ProtoICMP, "icmp"},
		{ProtoUnknown, "unknown"},
		{Protocol(99), "unknown"}, // any undefined value must degrade safely
	}
	for _, tc := range cases {
		if got := tc.p.String(); got != tc.want {
			t.Errorf("Protocol(%d).String() = %q, want %q", tc.p, got, tc.want)
		}
	}
}

func TestFlowKey_IsComparable(t *testing.T) {
	// FlowKey must remain usable directly as a map key (fixed-size arrays,
	// no slices) — this is a compile-time property, but the test pins it
	// down as a map usage so a future edit that breaks comparability fails
	// loudly here instead of surfacing as a confusing compile error deep
	// in internal/detect/behavioral.
	m := map[FlowKey]int{}
	a := FlowKey{SrcPort: 1, Protocol: ProtoTCP}
	b := FlowKey{SrcPort: 1, Protocol: ProtoTCP}
	m[a] = 1
	if m[b] != 1 {
		t.Fatalf("expected two FlowKeys with identical field values to be equal map keys")
	}
}
