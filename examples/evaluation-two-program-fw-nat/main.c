#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../../ebpf-se/examples/common/parsing_helpers.h"
#include "../../ebpf-se/examples/common/debug_tags.h"
#include "../../verification_tools/verification_helpers.h"

#include "common_maps.h"
#include "firewall.h"
#include "nat.h"

/*
Firewall and NAT program need access to headers of the packet
1. Firewall does not edit any part of packet it just accepts or rejects packet
2. NAT also require read access to packet headers but can also write the ip "source address" and update the "checksum" for network address translation
*/

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
int main(int argc, char** argv) {
  BPF_MAP_INIT(&whitelist_addresses, "whitelist_addresses", "", "");
  BPF_MAP_INIT(&inner2outer, "inner2outer", "", "");
  BPF_MAP_INIT(&outer2inner, "outer2inner", "", "");
	struct pkt *pkt = malloc(sizeof(struct pkt));
	klee_make_symbolic(pkt, sizeof(struct pkt), "constraint_access_user_pkt");
	pkt->ether.h_proto = bpf_htons(ETH_P_IP);
	struct xdp_md test;
  test.data = (long)(&(pkt->ether));
  test.data_end = (long)(pkt + 1);
  test.data_meta = 0;
  test.ingress_ifindex = 0;

  __start_verification();
  xdp_fw(&test);
  __separate();
  xdp_nat(&test);
  return 0;
}
#endif