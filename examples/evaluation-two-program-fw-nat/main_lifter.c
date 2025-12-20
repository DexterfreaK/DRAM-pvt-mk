/*
 * Firewall and NAT two-program example - Lifter compatible version
 * 
 * This demonstrates verification of two XDP programs that share maps:
 * 1. Firewall (xdp_fw) - reads whitelist_addresses map
 * 2. NAT (xdp_nat) - reads/writes inner2outer and outer2inner maps
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
    __type(value, __u32);
} whitelist_addresses SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 12);
    __type(key, __u32);
    __type(value, __u32);
} inner2outer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 12);
    __type(key, __u32);
    __type(value, __u32);
} outer2inner SEC(".maps");

/* Helper function for NAT */
static __always_inline __u16 calculate_csum(struct iphdr *ip) {
    return ip->check;
}

static __always_inline __u32 getNextAvailableIPAddress(void) {
    return 1;
}

/* Firewall program - checks whitelist */
SEC("xdp")
int xdp_fw(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;
    struct iphdr *ip;
    __u64 nh_off = 0;
    __u32 *value;

    eth = data;
    nh_off = sizeof(*eth);

    // Check if enough space for ethernet header
    if (data + nh_off > data_end)
        return XDP_DROP;

    // Check if ethernet protocol is IP
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_DROP;

    ip = data + nh_off;
    nh_off += sizeof(*ip);

    // Check if enough space for IP Header
    if (data + nh_off > data_end)
        return XDP_DROP;

    value = bpf_map_lookup_elem(&whitelist_addresses, &ip->saddr);
    if (!value)
        return XDP_DROP;

    return XDP_PASS;
}

/* NAT program - performs network address translation */
SEC("xdp")
int xdp_nat(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;
    struct iphdr *ip;
    __u64 nh_off = 0;
    __u32 *value;

    eth = data;
    nh_off = sizeof(*eth);

    // Check if enough space for ethernet header
    if (data + nh_off > data_end)
        return XDP_DROP;

    // Check if ethernet protocol is IP
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_DROP;

    ip = data + nh_off;
    nh_off += sizeof(*ip);

    // Check if enough space for IP Header
    if (data + nh_off > data_end)
        return XDP_DROP;

    value = bpf_map_lookup_elem(&outer2inner, &ip->saddr);
    if (!value) {
        __u32 newIP = getNextAvailableIPAddress();
        if (bpf_map_update_elem(&outer2inner, &ip->saddr, &newIP, 0) < 0)
            return XDP_DROP;
        if (bpf_map_update_elem(&inner2outer, &newIP, &ip->saddr, 0) < 0)
            return XDP_DROP;
        ip->saddr = newIP;
    } else {
        ip->saddr = *value;
    }

    ip->check = calculate_csum(ip);

    return XDP_PASS;
}

/* Combined entry point that calls both programs in sequence */
SEC("xdp")
int xdp_fw_nat_combined(struct xdp_md *ctx) {
    int ret;
    
    // First run firewall
    ret = xdp_fw(ctx);
    if (ret != XDP_PASS)
        return ret;
    
    // Then run NAT
    ret = xdp_nat(ctx);
    return ret;
}

