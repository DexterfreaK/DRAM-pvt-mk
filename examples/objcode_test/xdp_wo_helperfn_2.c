// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>

// Define the section for XDP program
#define SEC(NAME) __attribute__((section(NAME), used))

// Ethernet header structure
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    unsigned short h_proto;
} __attribute__((packed));

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

char _license[] SEC("license") = "GPL";
