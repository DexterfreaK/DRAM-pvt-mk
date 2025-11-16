#ifndef __XDP_MAP_H
#define __XDP_MAP_H

#include <asm-generic/int-ll64.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>
#include "../../ebpf-se/examples/common/parsing_helpers.h"
#include "../../ebpf-se/examples/common/debug_tags.h"

struct addressInfo {
  int count;
};

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[100];
};

#ifdef KLEE_VERIFICATION
struct bpf_map_def SEC("maps") sourceAddressInfo = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct addressInfo),
	.max_entries = 10,
};

#else
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10);
  __type(key, __u32);
  __type(value, struct addressInfo);
} sourceAddressInfo SEC(".maps");

#endif // KLEE_VERIFICATION
#endif // XDP_MAP_H
