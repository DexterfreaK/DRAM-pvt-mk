/* Driver for klee verification */
#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#endif

#include <stdlib.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

// #ifndef USES_BPF_REDIRECT_MAP
// #define USES_BPF_REDIRECT_MAP
// #endif

#include "xdp_fw_kern.h"

#ifdef KLEE_VERIFICATION
struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

#include "../../verification_tools/verification_helpers.h"

/*
hXDP is a firewall Efficient Software Packet Processing on FPGA NICs
1. Again need read access to header of tha packet, no other access
*/

int main(int argc, char** argv){
  BPF_MAP_INIT(&tx_port, "tx_port", "", "tx_device");
  BPF_MAP_INIT(&flow_ctx_table, "flow_ctx_table", "pkt.flow", "output_port");
  addDependency(&tx_port, &flow_ctx_table);

  /* Init from xdp_fw_user.c */
  #define num_ports 2
  int key[num_ports] = {B_PORT,A_PORT};
	int ifindex_out[num_ports] = {B_PORT,A_PORT};

  for(uint i = 0; i < num_ports; i++){
    if(bpf_map_update_elem(&tx_port,&key[i], &ifindex_out[i],0) < 0)
      return -1;
  }
  /* Init done */


  struct pkt *pkt = malloc(sizeof(struct pkt));
  klee_make_symbolic(pkt, sizeof(struct pkt), "constraint_access_user_buf");
  pkt->ether.h_proto = bpf_htons(ETH_P_IP);
  pkt->ipv4.version = 4;
  pkt->ipv4.ihl = sizeof(struct iphdr) / 4;
  pkt->tcp.doff = sizeof(struct tcphdr) / 4;
  struct xdp_md test;
  test.data = (long)(&(pkt->ether));
  test.data_end = (long)(pkt + 1);
  test.data_meta = 0;
  __u32 temp;
  klee_make_symbolic(&(temp), sizeof(temp), "VIGOR_DEVICE");
  test.ingress_ifindex = temp;
  test.rx_queue_index = 0;
  
  bpf_begin();
  __start_verification();
  if (xdp_fw_prog(&test))
    return 1;
  return 0;
}

#endif