// xdp_capture.c — in-kernel capture + block point for the IDS/IPS.
//
// This is the concrete implementation of the "capture & parsing" and
// "block (in-kernel)" boxes from the architecture diagram: it runs at the
// earliest possible point in the receive path (XDP, before the kernel
// allocates an sk_buff), so a blocked source IP is dropped at line rate
// with none of the per-packet cost the rest of the pipeline pays.
//
// Design, in order of what each piece is for:
//
//   1. blocklist_v4: a hash map of source IPv4 -> 1, populated from
//      userspace by internal/response once a Decision is VerdictBlock.
//      Checked first, before anything else, so an already-blocked flow
//      costs the absolute minimum kernel-side work.
//   2. events: a BPF ring buffer carrying a bounded-size snapshot of each
//      *allowed* frame up to userspace, where the existing Go pipeline
//      (parser -> detect -> correlate -> decision) runs unchanged. XDP is
//      a capture and fast-block point, not a place to reimplement
//      detection logic — detection logic staying in Go, where it's
//      testable and fuzzable, is a deliberate choice, not a limitation.
//
// Every pointer walk below re-checks against data_end before the next
// dereference. This isn't a style preference: the BPF verifier rejects
// the program outright if it can't prove every access is in-bounds, so
// this discipline is *enforced*, not just followed voluntarily — the
// same property internal/parser's fuzz tests establish empirically for
// the userspace parser is proven statically here by the kernel itself.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Snapshot length: enough for Ethernet + IPv4 + TCP headers and a small
// slice of payload for signature matching, without paying ring-buffer
// bandwidth for full jumbo frames on every allowed packet.
#define SNAPLEN 256

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536); // hard ceiling: same resource-exhaustion
	                            // discipline as internal/detect/behavioral's
	                            // bounded, evicting flow table in userspace.
	__type(key, __u32);         // IPv4 address, network byte order
	__type(value, __u8);        // 1 = blocked; presence is the real signal
} blocklist_v4 SEC(".maps");

// event is the fixed-size record written to the ring buffer. len records
// how many of the SNAPLEN data bytes are real frame content — this
// matters because, unlike a naive fixed-length copy, most real frames
// (a bare TCP ACK, a small UDP datagram, a DNS query) are shorter than
// SNAPLEN, and userspace must not treat the unused tail as data.
struct event {
	__u32 len;
	__u8 data[SNAPLEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB ring buffer
} events SEC(".maps");

SEC("xdp")
int xdp_capture(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS; // too short to be meaningful; let the kernel's
		                 // normal stack decide what to do with it.

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS; // non-IPv4 traffic is out of scope for this
		                 // program; userspace can add IPv6 similarly later.

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	// Block check first and alone: this is the entire enforcement path,
	// deliberately kept to one map lookup with no further parsing, so a
	// blocked source pays the lowest possible fixed cost.
	__u32 src_ip = ip->saddr;
	if (bpf_map_lookup_elem(&blocklist_v4, &src_ip))
		return XDP_DROP;

	void *rec = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!rec)
		return XDP_PASS; // ring buffer full: drop the *event*, not the
		                 // packet — matches internal/safety.Pool's
		                 // fail-open-on-capacity policy for the same
		                 // reason: back-pressure here must never become
		                 // packet loss for legitimate traffic.

	// Bounded, unrolled byte-copy loop instead of a single
	// bpf_xdp_load_bytes(..., SNAPLEN) call. This was a deliberate change
	// after real testing surfaced a genuine bug in the first version: a
	// fixed-length load fails outright (and was silently discarded here)
	// whenever the actual frame is shorter than SNAPLEN — which is most
	// frames. A fixed trip count of SNAPLEN, fully unrolled, with a
	// data_end check before every single byte read, gives the verifier a
	// statically provable bound (same "prove it, don't assert it"
	// discipline as bpf_xdp_load_bytes was meant to buy, without its
	// all-or-nothing length requirement) while correctly handling frames
	// of any length up to SNAPLEN.
	struct event *ev = rec;
	__u8 *cursor = (__u8 *)data;
	__u32 copied = 0;
#pragma clang loop unroll(full)
	for (int i = 0; i < SNAPLEN; i++) {
		if ((void *)(cursor + 1) > data_end)
			break;
		ev->data[i] = *cursor;
		cursor++;
		copied++;
	}
	ev->len = copied;
	bpf_ringbuf_submit(rec, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
