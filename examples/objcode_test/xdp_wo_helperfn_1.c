#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_reader(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }
    
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_DROP;
    }
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_DROP;
    }
    
    if (ip->protocol == 10) {
        return XDP_DROP;
    }

    if (ip->ttl == 20) {
        return XDP_DROP;
    }

    if (ip->tot_len < 10) {
        return XDP_DROP;
    }
    
    return XDP_PASS;

}