/*
 * KrakenGuard harness for Cilium bpf_lxc.c — cil_from_container entry.
 *
 * Compiles WITH the Cilium BPF headers so struct __sk_buff layout matches
 * exactly what bpf_lxc.bc expects.  Packet bytes and the TC context are
 * made symbolic; KLEE explores all possible packet shapes.
 *
 * Policy under test (see constraints.json):
 *   - Only bpf_map_lookup_elem / bpf_ktime_get_ns / bpf_skb_load_bytes permitted
 *   - Packet read-access 0-1500, no write-access (read-only observer policy)
 *
 * NOTE: packet is malloc()'d so its address sits in the kdalloc heap
 * (0x40000000..0x80000000), which fits in a u32.  This is required because
 * struct __sk_buff stores data/data_end as __u32 in the BPF ABI.
 */

#include <stdlib.h>

/* Pull in the same BPF type headers that bpf_lxc.c uses so struct layout
   is identical.  We compile this file with -target bpf just like the main
   program so sizes/offsets agree. */
#include "bpf/types_mapper.h"
#include <bpf/ctx/skb.h>   /* defines struct __sk_buff / __ctx_buff */

#include <klee/klee.h>

/* Declaration only — body is in bpf_lxc.bc, linked in by llvm-link. */
extern int cil_from_container(struct __sk_buff *ctx);

#define MAX_PKT_LEN 1500

int main(void)
{
    /* Allocate packet from heap (kdalloc at 0x40000000) so address fits in u32 */
    char *pkt = (char *)malloc(MAX_PKT_LEN);
    klee_make_symbolic(pkt, MAX_PKT_LEN, "packet");

    /* Symbolic packet length in [14, MAX_PKT_LEN] (at least Ethernet header) */
    __u32 pkt_len;
    klee_make_symbolic(&pkt_len, sizeof pkt_len, "pkt_len");
    klee_assume(pkt_len >= 14 && pkt_len <= MAX_PKT_LEN);

    /* Build a TC context pointing into the symbolic packet buffer.
       data/data_end are u32 in BPF ABI — heap pointer fits in u32. */
    struct __sk_buff ctx;
    klee_make_symbolic(&ctx, sizeof ctx, "skb");

    ctx.data     = (__u32)(__u64)pkt;
    ctx.data_end = (__u32)(__u64)(pkt + pkt_len);
    ctx.len      = pkt_len;

    int ret = cil_from_container(&ctx);

    /* Policy assertion: TC program must return a valid verdict. */
    klee_assert(ret == 0  /* TC_ACT_OK */ ||
                ret == 2  /* TC_ACT_SHOT */ ||
                ret == 7  /* TC_ACT_REDIRECT */ ||
                ret == -1 /* TC_ACT_UNSPEC */);

    return 0;
}
