/*
 * Two-program no-overlap example - Lifter compatible version
 * 
 * This demonstrates verification of two XDP programs with no map overlap:
 * 1. xdp_first_prog - looks up MAC from macs map and writes to eth header
 * 2. xdp_second_prog - compares MAC addresses in eth header
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

char _license[] SEC("license") = "GPL";

/* BTF-style map definitions for lifter compatibility */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, unsigned char[6]);  // MAC address
} macs SEC(".maps");

/* Local memcmp for lifter compatibility */
static __always_inline int local_memcmp(const void *s1, const void *s2, unsigned long n) {
    const unsigned char *p1 = s1, *p2 = s2;
    for (unsigned long i = 0; i < n; i++) {
        if (p1[i] != p2[i])
            return p1[i] - p2[i];
    }
    return 0;
}

/* First program - lookup and update eth header */
SEC("xdp")
int xdp_first_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;
    struct iphdr *ip;
    __u64 nh_off = 0;
    void *target;

    eth = data;
    nh_off = sizeof(*eth);

    // Check if enough space for ethernet header
    if (data + nh_off > data_end)
        return XDP_DROP;

    // Check if ethernet protocol is IP
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        ip = data + nh_off;
        nh_off += sizeof(*ip);
        
        // Check if enough space for IP Header
        if (data + nh_off > data_end)
            return XDP_DROP;

        target = bpf_map_lookup_elem(&macs, &ip->daddr);
        if (!target)
            return XDP_DROP;
        
        __builtin_memcpy(eth->h_dest, target, sizeof(eth->h_dest));
        return XDP_PASS;
    }

    return XDP_PASS;
}

/* Second program - compare MAC addresses */
SEC("xdp")
int xdp_second_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;
    __u64 nh_off = 0;
    void *target;

    eth = data;
    nh_off = sizeof(*eth);

    // Check if enough space for ethernet header
    if (data + nh_off > data_end)
        return XDP_DROP;

    target = eth->h_source;

    // Check if ethernet protocol is IP
    if (eth->h_proto == bpf_htons(ETH_P_IP))
        return XDP_PASS;

    if (!local_memcmp(eth->h_dest, target, sizeof(eth->h_dest))) {
        return XDP_PASS;
    }

    return XDP_PASS;
}

/* Combined entry point that calls both programs in sequence */
SEC("xdp")
int xdp_combined(struct xdp_md *ctx) {
    // Run program 1
    int ret1 = xdp_first_prog(ctx);

    // Run program 2
    int ret2 = xdp_second_prog(ctx);

    // Return combined result
    if (ret1 != XDP_PASS)
        return ret1;
    return ret2;
}

