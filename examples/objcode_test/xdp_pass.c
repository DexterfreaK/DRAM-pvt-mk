#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// TESTED and WORKING on DRACO after lifting and linking

SEC("xdp")
int xdp_reader(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";