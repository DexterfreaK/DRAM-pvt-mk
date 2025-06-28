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

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// include BMC related ebpf programs
#include "bmc_kern.c"



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
    BPF_MAP_INIT(&map_kcache, "map_kcache", "", "");
    BPF_MAP_INIT(&map_keys, "map_keys", "", "");
    BPF_MAP_INIT(&map_parsing_context, "map_parsing_context", "", "");
    BPF_MAP_INIT(&map_stats, "map_stats", "", "");

    map_progs_xdp[0] = bmc_hash_keys_main;
    map_progs_xdp[1] = bmc_prepare_packet_main;
    map_progs_xdp[2] = bmc_write_reply_main;
    map_progs_xdp[3] = bmc_invalidate_cache_main;

    map_progs_tc[0] = bmc_update_cache_main;


    // configuring maps
    unsigned int zero = 0;
    assume_map_contains_key(&map_stats, &zero);
    assume_map_contains_key(&map_parsing_context, &zero);

    // verify ingress
    struct pkt *pkt = malloc(sizeof(struct pkt));
    klee_make_symbolic(pkt, sizeof(struct pkt), "constraint_access_user_pkt");
    pkt->ether.h_proto = htons(ETH_P_IP);
	struct xdp_md test_ingress;
	test_ingress.data = (long)(&(pkt->ether));
	test_ingress.data_end = (long)(pkt + 1);
	test_ingress.data_meta = 0;
	test_ingress.ingress_ifindex = 0;

    __start_verification();
    bmc_hash_keys_main(&test_ingress);

    // // verify egress
    // struct __sk_buff *skb = malloc(sizeof(struct __sk_buff));
    // klee_make_symbolic(skb, sizeof(struct __sk_buff), "egress_pkt");
    // // set some required metadata

    // bmc_tx_filter_main(&skb);

    return 0;
}
#endif