#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp1.bpf.h"

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
#include "../../verification_tools/verification_helpers.h"

struct __attribute__((__packed__)) pkt {
    struct ethhdr ether;
    struct iphdr ipv4;
    struct udphdr udp;
    char payload[1500];
};

int main() {

	// init the ctx: XDP computes udph as data + sizeof(ethhdr) + (ip->ihl*4).
	// So udph == &pkt->udp only when ip->ihl == 5. Otherwise udph points into
	// other bytes (still symbolic), so the port check can see 12345 and printf runs.
	struct pkt *pkt = malloc(sizeof(struct pkt));
	klee_make_symbolic(pkt, sizeof(struct pkt), "constraint_access_user_pkt");
	pkt->ether.h_proto = htons(ETH_P_IP);
	// pkt->ipv4.ihl = 5;   /* required so udph in XDP points at pkt->udp, not random offset */
	// pkt->udp.dest = htons(12345);
	struct xdp_md test;
	test.data = (long)(&(pkt->ether));
	test.data_end = (long)(pkt + 1);
	test.data_meta = 0;
	test.ingress_ifindex = 0;

	// execute
	__start_verification();
	// if(bpf_ntohs(pkt->udp.dest) == 12345) {
		udp_echo_prog_1(&test);
	// } else if (bpf_ntohs(pkt->udp.dest) == 13245) {
		__separate();
		udp_echo_prog_2(&test);
	// }

	return 0;
}
#endif