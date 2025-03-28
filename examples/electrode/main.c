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

#ifndef USES_BPF_XDP_ADJUST_HEAD
#define USES_BPF_XDP_ADJUST_HEAD
#endif

#ifndef USES_BPF_XDP_ADJUST_TAIL
#define USES_BPF_XDP_ADJUST_TAIL
#endif

#ifndef FAST_QUORUM_PRUNE
#define FAST_QUORUM_PRUNE
#endif


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// include BMC related ebpf programs
#include "fast_kern.c"

#ifdef KLEE_VERIFICATION
#include "../../verification_tools/verification_helpers.h"

struct __attribute__((__packed__)) pkt {
    struct ethhdr ether;
    struct iphdr ipv4;
    struct tcphdr tcp;
    char payload[1500];
};



int main()
{
    // initialize maps
    BPF_MAP_INIT(&map_configure, "map_configure", "", "");
    BPF_MAP_INIT(&map_ctr_state, "map_ctr_state", "", "");
    BPF_MAP_INIT(&map_msg_lastOp, "map_msg_lastOp", "", "");
    BPF_MAP_INIT(&map_quorum, "map_quorum", "", "");
    BPF_MAP_INIT(&batch_context, "batch_context", "", "");

    map_progs_xdp[0] = HandlePrepare_main;
    map_progs_xdp[1] = HandleRequest_main;
    map_progs_xdp[2] = HandlePrepareOK_main;
    map_progs_xdp[3] = WriteBuffer_main;
    map_progs_xdp[4] = PrepareFastReply_main;

    // configuring maps
    // unsigned int zero = 0;
    // assume_map_contains_key(&map_stats, &zero);
    // assume_map_contains_key(&map_parsing_context, &zero);

    // verify ingress
    struct pkt *pkt = malloc(sizeof(struct pkt));
    klee_make_symbolic(pkt, sizeof(struct pkt), "user_pkt");
    pkt->ether.h_proto = htons(ETH_P_IP);
	struct xdp_md test_ingress;
	test_ingress.data = (long)(&(pkt->ether));
	test_ingress.data_end = (long)(pkt + 1);
	test_ingress.data_meta = 0;
	test_ingress.ingress_ifindex = 0;

    fastPaxos_main(&test_ingress);

    // // verify egress
    // struct __sk_buff *skb = malloc(sizeof(struct __sk_buff));
    // klee_make_symbolic(skb, sizeof(struct __sk_buff), "egress_pkt");
    // // set some required metadata

    // bmc_tx_filter_main(&skb);

    return 0;
}
#endif