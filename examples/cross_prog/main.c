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

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

#ifndef USES_BPF_GET_SMP_PROC_ID
#define USES_BPF_GET_SMP_PROC_ID
#endif

#ifndef USES_BPF_KTIME_GET_NS
#define USES_BPF_KTIME_GET_NS
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
#include "katran_pkts.h"
#include "../../verification_tools/partial_spec.h"
#include "../../verification_tools/parsing_helpers_spec.h"
#include "../../verification_tools/verification_helpers.h"

/*
Electrode works for process that is bounded to port 12345
1. Allow read and write to packets destined for port 12345
2. Program can read all header fields (54 bytes) and beginning part of payload which contains some control information like magic bytes etc (64 bytes max) => total(118 bytes)
3. Program can also edit those information as per need
*/

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
    BPF_TIME_INIT();
    BPF_MAP_INIT(&vip_map, "vip_map", "pkt.vip", "vip_metadata");
    BPF_MAP_OF_MAPS_INIT(&lru_mapping, &fallback_cache, "flowtable", "pkt.flow", "backend");
    BPF_MAP_INIT(&fallback_cache, "flowtable", "pkt.flow", "backend");
    BPF_MAP_INIT(&ch_rings, "vip_to_real_map", "", "backend_real_id");
    BPF_MAP_INIT(&reals, "backend_metadata_map", "", "backend_metadata");
    BPF_MAP_INIT(&reals_stats, "backend_stats_map", "", "backend_stats");
    BPF_MAP_INIT(&stats, "vip_stats_map", "", "vip_stats");
    BPF_MAP_INIT(&quic_mapping, "conn_id_to_real_map", "", "backend_real_id");
    BPF_MAP_INIT(&ctl_array, "backend_mac_addrs_map", "", "backend_mac_addrs");

    BPF_MAP_RESET(&reals);
    BPF_MAP_RESET(&reals_stats);
    BPF_MAP_RESET(&stats);
    BPF_MAP_RESET(&quic_mapping);
    BPF_MAP_RESET(&ctl_array);

    #ifdef LPM_SRC_LOOKUP
    BPF_MAP_INIT(lpm_src_v4);
    BPF_MAP_INIT(lpm_src_v6);
    #endif

    struct xdp_md test;
    // get_packet(IPV4,&test);
    // klee_print_expr("done creating packet", 0);
    enum PacketTypes type;

    if(klee_int("pkt.isIPv4")){
        if(klee_int("pkt.is_fragmented"))
        type = FRAGV4;
        // get_packet(FRAGV4,&test);
        else if(klee_int("pkt.isICMP"))
        type = ICMPV4;
        // get_packet(ICMPV4,&test);
        else
        type = IPV4;
        // get_packet(IPV4,&test);
    }
    else if(klee_int("pkt.isIPv6")) {
        // ipv6
        if(klee_int("pkt.is_fragmented"))
        type = FRAGV6;
        // get_packet(FRAGV6,&test);
        else if(klee_int("pkt.isICMP"))
        type = ICMPV6;
        // get_packet(ICMPV6,&test); 
        else
        type = IPV6;
        // get_packet(IPV6,&test);
    }
    else{
        type = NON_IP;
        // get_packet(NON_IP,&test);
    }

    get_packet(type, &test);

    test.data_meta = 0;
    test.ingress_ifindex = 0;
    test.rx_queue_index = 0;

    bpf_begin();

    // initialize maps
    BPF_MAP_INIT(&map_configure, "map_configure", "", "");
    BPF_MAP_INIT(&map_ctr_state, "map_ctr_state", "", "");
    BPF_MAP_INIT(&map_msg_lastOp, "map_msg_lastOp", "", "");
    BPF_MAP_INIT(&map_quorum, "map_quorum", "", "");
    BPF_MAP_INIT(&batch_context, "batch_context", "", "");


    struct paxos_ctr_state val2;
    __u32 zero = 0;
    klee_make_symbolic(&val2, sizeof(struct paxos_ctr_state), "map_ctr_state_entry");
    bpf_map_update_elem(&map_ctr_state, &zero, &val2, 0);

    __u64 val3;
    klee_make_symbolic(&val3, sizeof(__u64), "map_msg_lastOp_entry");
    bpf_map_update_elem(&map_msg_lastOp, &zero, &val3, 0);

    // for (int i = 0; i < 1; i++)
    // {
    //     struct paxos_quorum val;
    //     klee_make_symbolic(&val, sizeof(struct paxos_quorum), "map_quorum_entry");
    //     bpf_map_update_elem(&map_quorum, &i, &val, 0);
    // }

    struct paxos_batch val4;
    klee_make_symbolic(&val4, sizeof(struct paxos_batch), "batch_context_entry");
    bpf_map_update_elem(&batch_context, &zero, &val4, 0);

    map_progs_xdp[0] = HandlePrepare_main;
    map_progs_xdp[1] = HandleRequest_main;
    map_progs_xdp[2] = HandlePrepareOK_main;
    map_progs_xdp[3] = WriteBuffer_main;
    map_progs_xdp[4] = PrepareFastReply_main;

    __start_verification();
    balancer_ingress(&test); // katran
    __separate();
    fastPaxos_main(&test); // electrode


    // // verify egress
    // struct __sk_buff *skb = malloc(sizeof(struct __sk_buff));
    // klee_make_symbolic(skb, sizeof(struct __sk_buff), "egress_pkt");
    // // set some required metadata

    // bmc_tx_filter_main(&skb);

    return 0;
}
#endif