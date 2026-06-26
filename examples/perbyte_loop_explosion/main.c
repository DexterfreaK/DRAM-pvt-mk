#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Minimal adversarial example #A: per-byte branch loop.
 *
 * Purpose: a program that the in-kernel eBPF verifier accepts cheaply, but that
 * forces DRACO/KrakenGuard's exhaustive symbolic execution into exponential
 * path explosion -- the failure mode the NSDI'26 paper's load-bearing
 * assumption ("passing the kernel verifier already ensures the lack of path
 * explosion") does NOT actually rule out.
 *
 * Why the verifier accepts it:
 *   - LOOP_BOUND is a compile-time constant => bounded loop (no unbounded loop).
 *   - Every packet read is guarded by `payload + i + 1 <= data_end`.
 *   - The verifier abstracts each register as tnum (known-bits) + min/max
 *     interval and prunes already-visited abstract states, so a loop that
 *     branches on each byte costs it only a bounded number of abstract states.
 *
 * Why KLEE explodes:
 *   - KLEE forks on every branch over a symbolic packet byte and never merges.
 *   - The 3-way per-iteration branch (sentinel-break / space / hash-update)
 *     yields a path count exponential in LOOP_BOUND.
 *
 * This is the *distilled essence* of the bmc-cache hash-keys loop that had to
 * be hand-trimmed (multi-key recursion + copy loop deleted) to make DRACO
 * terminate -- here with the maps and headers stripped away so the ONLY cause
 * of non-termination is the per-byte branching.
 *
 * Sweep LOOP_BOUND (e.g. -DLOOP_BOUND=8,16,24,32,...) to expose the knee where
 * wall-clock time goes superlinear.
 */
#ifndef LOOP_BOUND
#define LOOP_BOUND 32
#endif

#define FNV_OFFSET_BASIS_32 2166136261u
#define FNV_PRIME_32        16777619u

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	char *payload  = (char *)data;

	if (payload >= data_end)
		return XDP_PASS;

	unsigned int hash    = FNV_OFFSET_BASIS_32;
	unsigned int matches = 0;

	/* Bounded, in-bounds, per-byte branching loop.
	 * Each iteration forks symbolic state three ways; the `break` also
	 * spawns a distinct terminating path at every i. Path count ~ 3^i. */
#pragma clang loop unroll(disable)
	for (int i = 0; i < LOOP_BOUND && payload + i + 1 <= data_end; i++) {
		char c = payload[i];
		if (c == '\r')            /* sentinel -> divergent break path at each i */
			break;
		else if (c == ' ')        /* whitespace branch */
			matches++;
		else {                    /* hash-update branch (depends on byte) */
			hash ^= (unsigned char)c;
			hash *= FNV_PRIME_32;
		}
	}

	/* Couple the accumulated symbolic state into a final fork so nothing
	 * downstream can be constant-folded away. */
	if (hash % 1000u == matches)
		return XDP_DROP;

	return XDP_PASS;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include "../../verification_tools/verification_helpers.h"
#include <stdlib.h>
int main() {
	struct pkt *pkt = malloc(sizeof(struct pkt));
	klee_make_symbolic(pkt, sizeof(struct pkt), "constraint_access_user_pkt");
	pkt->ether.h_proto = htons(ETH_P_IP);

	struct xdp_md test;
	test.data           = (long)(&(pkt->ether));
	test.data_end       = (long)(pkt + 1);
	test.data_meta      = 0;
	test.ingress_ifindex = 0;

	__start_verification();
	xdp_main(&test);
	return 0;
}
#endif
