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

// #ifndef USES_BPF_MAP_UPDATE_ELEM
// #define USES_BPF_MAP_UPDATE_ELEM
// #endif


// #ifndef USES_BPF_XDP_ADJUST_HEAD
// #define USES_BPF_XDP_ADJUST_HEAD
// #endif

// #ifndef USES_BPF_XDP_ADJUST_TAIL
// #define USES_BPF_XDP_ADJUST_TAIL
// #endif

#ifndef FAST_QUORUM_PRUNE
#define FAST_QUORUM_PRUNE
#endif


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// include BMC related ebpf programs
#include "fast_kern.c"

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
    // initialize maps
    BPF_MAP_INIT(&map_configure, "map_configure", "", "");
    BPF_MAP_INIT(&map_ctr_state, "map_ctr_state", "", "");
    BPF_MAP_INIT(&map_msg_lastOp, "map_msg_lastOp", "", "");
    BPF_MAP_INIT(&map_quorum, "map_quorum", "", "");
    BPF_MAP_INIT(&batch_context, "batch_context", "", "");

    // struct paxos_ctr_state val2;
    // __u32 zero = 0;
    // klee_make_symbolic(&val2, sizeof(struct paxos_ctr_state), "map_ctr_state_entry");
    // bpf_map_update_elem(&map_ctr_state, &zero, &val2, 0);

    // __u64 val3;
    // klee_make_symbolic(&val3, sizeof(__u64), "map_msg_lastOp_entry");
    // bpf_map_update_elem(&map_msg_lastOp, &zero, &val3, 0);

    // struct paxos_batch val4;
    // klee_make_symbolic(&val4, sizeof(struct paxos_batch), "batch_context_entry");
    // bpf_map_update_elem(&batch_context, &zero, &val4, 0);

    map_progs_xdp[0] = HandlePrepare_main;
    map_progs_xdp[1] = HandleRequest_main;
    map_progs_xdp[2] = HandlePrepareOK_main;
    map_progs_xdp[3] = WriteBuffer_main;
    map_progs_xdp[4] = PrepareFastReply_main;

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
    fastPaxos_main(&test_ingress);

    return 0;
}
#endif