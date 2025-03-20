#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

// #ifndef USES_BPF_MAP_UPDATE_ELEM
// #define USES_BPF_MAP_UPDATE_ELEM
// #endif


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

// struct bpf_map_def SEC("maps") read_only = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(int),
// 	.value_size = sizeof(int),
// 	.max_entries = 100,
// };

// struct bpf_map_def SEC("maps") write_only = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(int),
// 	.value_size = sizeof(int),
// 	.max_entries = 100,
// };

// struct bpf_map_def SEC("maps") read_write = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(int),
// 	.value_size = sizeof(int),
// 	.max_entries = 100,
// };

// struct bpf_map_def SEC("maps") no_access = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(int),
// 	.value_size = sizeof(int),
// 	.max_entries = 100,
// };




// SEC("xdp")
// int xdp_main(struct xdp_md *ctx) {
// 	void* data     = (void*)(long)ctx->data;
// 	void* data_end = (void*)(long)ctx->data_end;
// 	struct ethhdr *eth;
// 	struct iphdr  *ip;
// 	struct tcphdr *tcp;
// 	// char		  *payload;
// 	uint64_t nh_off = 0;

// 	eth = data;
// 	nh_off = sizeof(*eth);
// 	if (data  + nh_off  > data_end)
// 		goto EOP;

// 	ip = data + nh_off;
// 	nh_off += sizeof(*ip);
// 	if (data + nh_off  > data_end)
// 		goto EOP;

// 	if(ip->protocol != IPPROTO_TCP){
// 		return XDP_PASS;
// 	}

// 	tcp = data + nh_off;
// 	nh_off += sizeof(*tcp);
// 	if (data + nh_off  > data_end)
// 	 	goto EOP;

// 	// payload = data + nh_off;
// 	nh_off += 3;
// 	if (data + nh_off  > data_end)
// 		goto EOP;

// 	int key = 1;
// 	int value = 42;
// 	int *result;

// 	// Valid map operations - read and write allowed
// 	bpf_map_update_elem(&read_write, &key, &value, BPF_ANY);
// 	result = bpf_map_lookup_elem(&read_write, &key);

// 	// // // Invalid map operations - attempt write to read-only map
// 	key = 2;
// 	value = 100;
// 	bpf_map_update_elem(&no_access, &key, &value, BPF_ANY); // This should fail verification
	
// 	// Valid map operations - read from read-only map
// 	key = 1;
// 	result = bpf_map_lookup_elem(&read_only, &key);
// 	if (result && *result == 100) { // This should pass verification since read is allowed
// 		return XDP_DROP;
// 	}

// 	return XDP_PASS;
// 	EOP:
// 		return XDP_DROP;
// }



struct bpf_map_def SEC(".maps") packet_stats = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 256,
};

SEC("xdp") extern int xdp_reader(struct xdp_md *ctx);
SEC("xdp")
int xdp_filter_program(struct xdp_md *ctx) {
    // Access packet data
    void *data_start = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Ensure we can read the Ethernet header
    struct ethhdr *eth = data_start;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;  // Malformed packet
    
    // Check if source MAC address matches a blacklisted address
    // Example blacklisted MAC: 00:11:22:33:44:55
    if (eth->h_source[0] == 0x00 &&
        eth->h_source[1] == 0x11 &&
        eth->h_source[2] == 0x22 &&
        eth->h_source[3] == 0x33 &&
        eth->h_source[4] == 0x44 &&
        eth->h_source[5] == 0x55) {
        return XDP_DROP;  // Drop packets from blacklisted MAC
    }
    
    // Check the EtherType field (in network byte order)
    unsigned char *eth_type = (unsigned char *)&eth->h_proto;
    
    // Process IPv4 packets (0x0800)
    if (eth_type[0] == 0x08 && eth_type[1] == 0x00) {
        // It's an IPv4 packet
        // Check if we can access IPv4 header (at least the first byte)
        unsigned char *ip_header = (unsigned char *)(eth + 1);
        if (ip_header + 1 > (unsigned char *)data_end)
            return XDP_DROP;  // Malformed packet
        
        // Check IP version (should be 4 for IPv4)
        // Version is in the top 4 bits of the first byte
        unsigned char version = (ip_header[0] >> 4) & 0xF;
        if (version != 4) {
            return XDP_DROP;  // Invalid IPv4 packet
        }
        
        return XDP_PASS;  // Pass valid IPv4 packets
    } 
    // Process IPv6 packets (0x86DD)
    else if (eth_type[0] == 0x86 && eth_type[1] == 0xDD) {
        // Simple policy: Drop all IPv6 traffic
        return XDP_DROP;
    } 
    // Process ARP packets (0x0806)
    else if (eth_type[0] == 0x08 && eth_type[1] == 0x06) {
        // Pass all ARP packets
        return XDP_PASS;
    }
    // Drop all other Ethernet types
    else {
        return XDP_DROP;
    }
}

SEC("xdp")
int xdp_reader2(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u32* count = bpf_map_lookup_elem(&packet_stats, &key);
    if (count) {
        return XDP_DROP;
    }
    
    return XDP_PASS;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
int main() {
	// init maps
	// BPF_MAP_INIT(&packet_stats, "packet_stats", "", "");
	// BPF_MAP_INIT(&read_write, "read_write", "", "");
	// BPF_MAP_INIT(&no_access, "no_access", "", "");
	// BPF_MAP_INIT(&write_only, "write_only", "", "");

	// init the ctx
	struct pkt *pkt = malloc(sizeof(struct pkt));
	klee_make_symbolic(pkt, sizeof(struct pkt), "user_pkt");
	pkt->ether.h_proto = htons(ETH_P_IP);
	struct xdp_md test;
	test.data = (long)(&(pkt->ether));
	test.data_end = (long)(pkt + 1);
	test.data_meta = 0;
	test.ingress_ifindex = 0;

	// execute
	int val = xdp_filter_program(&test);
	printf("Return value %d\n",val);
	return 0;
}
#endif