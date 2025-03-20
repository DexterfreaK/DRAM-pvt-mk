// #include "common.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} packet_stats SEC(".maps");

SEC("xdp")
int xdp_reader(struct xdp_md *ctx)
{
    __u32 key = 0;
    void* count = bpf_map_lookup_elem(&packet_stats, &key);
    if (count) {
        return XDP_DROP;
    }
    
    return XDP_PASS;
}


char LICENSE[] SEC("license") = "GPL";