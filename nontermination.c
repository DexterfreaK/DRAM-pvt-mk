#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#include "klee/klee.h"

SEC("xdp")
int socket_handler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    char *payload = (char *) data;

    if (payload >= data_end)
        return XDP_PASS;

    __u32 hash = 2166136261;
    __u32 key_len = 0;
    __u32 done_parsing = 0;

#pragma clang loop unroll(disable)
    for (int off = 0; off < 251 && payload + off + 1 <= data_end; off++) {
        if (payload[off] == '\r') {
            done_parsing = 1;
            break;
        } else if (payload[off] == ' ') {
            break;
        } else if (payload[off] != ' ') {
            hash ^= payload[off];
            hash *= 16777619;
            key_len++;
        }
    }

    int entry_hash = 0;
    int cnt = 0;

    if (entry_hash == hash) {
        unsigned int i = 0;
		cnt++;
    }

    if (hash % 7 == 0) {
        hash += key_len;
    } else if (hash % 5 == 0) {
        hash -= key_len;
    } else if (hash % 3 == 0) {
        hash ^= done_parsing;
    }

    if (cnt > 100 && done_parsing)
        return hash % 2 ? XDP_DROP : XDP_PASS;
    else
        return 0;
}

struct __attribute__((__packed__)) pkt {
    struct ethhdr ether;
    struct iphdr ipv4;
    struct tcphdr tcp;
    char payload[1500];
};

int main()
{
    struct pkt *pkt = malloc(sizeof(struct pkt));
    klee_make_symbolic(pkt, sizeof(struct pkt), "constraint_access_user_pkt");
    pkt->ether.h_proto = htons(ETH_P_IP);
	struct xdp_md test_ingress;
	test_ingress.data = (long)(&(pkt->ether));
	test_ingress.data_end = (long)(pkt + 1);
	test_ingress.data_meta = 0;
	test_ingress.ingress_ifindex = 0;

    socket_handler(&test_ingress);

    return 0;
}