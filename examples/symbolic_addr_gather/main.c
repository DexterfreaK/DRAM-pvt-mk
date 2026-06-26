#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif
#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_map_def.h"

/*
 * Adversarial example #C: symbolic-index gather / pointer chasing.
 *
 * CONCEPTUALLY DIFFERENT from #A (perbyte_loop_explosion):
 *   - #A explodes from DATA-dependent CONTROL FLOW: each iteration has explicit
 *     `if (byte == ...)` branches, so the PATH COUNT blows up (~3^N states).
 *   - #C has essentially TWO control-flow paths total. It does NOT explode in
 *     path count at all. The cost comes from symbolic MEMORY INDEXING: it reads
 *     table[idx] where `idx` is symbolic, and the loaded value becomes the next
 *     index (pointer chasing). KLEE does not fork an in-object symbolic index;
 *     it builds a nested array-select expression. Chaining CHAIN of them yields
 *     a CHAIN-deep nest of 256-way selects over a symbolic table, which the SMT
 *     solver cannot untangle.
 *
 * This refutes the intuition baked into "passing the verifier ensures no path
 * explosion": here there is NO path explosion (2 paths), yet exhaustive symbolic
 * execution still fails. KrakenGuard's tractability does not depend only on path
 * count -- per-query solver cost is an independent failure axis, and a perfectly
 * ordinary verifier-legal array-map gather hits it.
 *
 * The table is a BPF_MAP_TYPE_ARRAY (verifier-legal variable-key lookup) whose
 * contents are made symbolic via BPF_MAP_RESET in the harness.
 *
 * Sweep CHAIN (e.g. -DCHAIN=8,32,64,128) to expose the knee.
 */
#ifndef CHAIN
#define CHAIN 128
#endif

#define TBL_SIZE 256

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

struct bpf_map_def SEC("maps") table = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = TBL_SIZE,
};

/* Gather loop extracted to do_gather() for function-level summarization.
 * Provide either do_gather.c (real loop, solver-cost explosion) or
 * do_gather_stub.c (AI-bounds stub, O(1) KLEE cost) at link time. */
uint32_t do_gather(struct bpf_map_def *tbl, unsigned int start_idx);

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	unsigned char *p = (unsigned char *)data;

	if ((void *)(p + sizeof(struct ethhdr)) > data_end)
		return XDP_PASS;

	unsigned int idx = p[0] & (TBL_SIZE - 1);   /* symbolic start index */

	/* Gather loop is now in do_gather() (do_gather.c / do_gather_stub.c).
	 * Link with do_gather.c for the real loop or do_gather_stub.c for the
	 * AI-bounds stub (see Makefile targets baseline_gathered / stub_gathered). */
	unsigned int acc = do_gather(&table, idx);

	if (acc == 0x42)
		return XDP_DROP;
	return XDP_PASS;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include "../../verification_tools/verification_helpers.h"
#include <stdlib.h>
int main() {
	BPF_MAP_INIT(&table, "table", "", "");
	BPF_MAP_RESET(&table);   /* make the 256 table entries symbolic */

	struct pkt *pkt = malloc(sizeof(struct pkt));
	klee_make_symbolic(pkt, sizeof(struct pkt), "constraint_access_user_pkt");
	pkt->ether.h_proto = htons(ETH_P_IP);

	struct xdp_md test;
	test.data            = (long)(&(pkt->ether));
	test.data_end        = (long)(pkt + 1);
	test.data_meta       = 0;
	test.ingress_ifindex = 0;

	__start_verification();
	xdp_main(&test);
	return 0;
}
#endif
