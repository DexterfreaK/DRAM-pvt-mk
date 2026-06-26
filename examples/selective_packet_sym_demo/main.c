#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  char payload[1500];
};

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth;
  struct iphdr *ip;
  uint64_t nh_off = 0;

  eth = data;
  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_PASS;

  ip = data + nh_off;
  nh_off += sizeof(*ip);
  if (data + nh_off > data_end)
    return XDP_PASS;

  if (ip->saddr == 12345) {
    if (ip->daddr == 67890)
      return XDP_DROP;
    return XDP_PASS;
  }

  return XDP_PASS;
}

#include "klee/klee.h"
#include "../../verification_tools/verification_helpers.h"
#include <stdlib.h>

int main() {
  struct pkt *pkt = malloc(sizeof(struct pkt));
  klee_make_symbolic(pkt, sizeof(struct pkt), "constraint_access_user_pkt");
  pkt->ether.h_proto = htons(ETH_P_IP);

  struct xdp_md test;
  test.data = (long)(&(pkt->ether));
  test.data_end = (long)(pkt + 1);
  test.data_meta = 0;
  test.ingress_ifindex = 0;

  __start_verification();
  xdp_main(&test);
  return 0;
}
