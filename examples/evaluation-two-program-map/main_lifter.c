/*
 * Two-program map interaction example - Lifter compatible version
 * 
 * This demonstrates verification of two XDP programs that share maps:
 * 1. xdp_first_prog - reads from hash_map and array_map, writes to array_map
 * 2. xdp_second_prog - writes to hash_map and array_map, reads from array_map
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

char _license[] SEC("license") = "GPL";

/* Struct used as hash key */
struct simple_struct {
    char c;
    __u32 x;
    __u16 y;
};

/* BTF-style map definitions for lifter compatibility */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, struct simple_struct);
    __type(value, __u32);
} hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 12);
    __type(key, __u32);
    __type(value, __u32);
} array_map SEC(".maps");

/* First program - lookups and one update */
SEC("xdp")
int xdp_first_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;
    struct iphdr *ip;
    struct simple_struct hash_key;
    __u64 nh_off = 0;
    __u32 *value;
    __u32 new_value = 0;
    __u32 array_key;

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

    // Initialize hash key (c will be symbolic via map lookup behavior)
    hash_key.c = 'a';  // Use concrete value for lifter
    hash_key.x = 42;
    hash_key.y = 10;

    value = bpf_map_lookup_elem(&hash_map, &hash_key);
    if (!value)
        return XDP_DROP;

    array_key = 4;
    value = bpf_map_lookup_elem(&array_map, &array_key);
    if (!value)
        return XDP_DROP;

    array_key += 1;
    if (bpf_map_update_elem(&array_map, &array_key, &new_value, 0) < 0)
        return XDP_DROP;

    return XDP_PASS;
}

/* Second program - updates and one lookup */
SEC("xdp")
int xdp_second_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;
    struct iphdr *ip;
    __u64 nh_off = 0;
    __u32 *value;
    struct simple_struct hash_key;
    __u32 array_key;
    __u32 update_value = 229;

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

    // This could reference same key-value pair in map as program1
    hash_key.c = 'a';
    hash_key.x = 42;
    hash_key.y = 10;  // Added to match struct
    if (bpf_map_update_elem(&hash_map, &hash_key, &update_value, 0) < 0)
        return XDP_DROP;

    // This would not reference, as the x field in program1 is 42
    hash_key.x = 50;
    if (bpf_map_update_elem(&hash_map, &hash_key, &update_value, 0) < 0)
        return XDP_DROP;

    array_key = 4;
    if (bpf_map_update_elem(&array_map, &array_key, &update_value, 0) < 0)
        return XDP_DROP;

    array_key += 1;
    value = bpf_map_lookup_elem(&array_map, &array_key);
    if (!value)
        return XDP_DROP;

    return XDP_PASS;
}

/* Combined entry point that calls both programs in sequence */
SEC("xdp")
int xdp_combined(struct xdp_md *ctx) {
    int ret;

    // First run program 1
    ret = xdp_first_prog(ctx);
    if (ret != XDP_PASS)
        return ret;

    // Then run program 2
    ret = xdp_second_prog(ctx);
    return ret;
}

