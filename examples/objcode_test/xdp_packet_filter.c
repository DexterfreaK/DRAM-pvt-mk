// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp")
int xdp_packet_filter(struct xdp_md *ctx) {
    // Access packet data
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Calculate packet size
    unsigned int size = data_end - data;
    
    // Drop tiny packets (likely malformed)
    if (size < 14) {
        return XDP_DROP;
    }
    
    // Drop oversized packets (possible DoS)
    if (size > 9000) {
        return XDP_DROP;
    }
    
    // Access first byte of packet (start of destination MAC)
    unsigned char *pkt_data = data;
    if (pkt_data + 1 > (unsigned char *)data_end)
        return XDP_DROP;
    
    // Filter based on first byte pattern
    unsigned char first_byte = *pkt_data;
    
    // Broadcast/multicast packets (first bit set)
    if (first_byte & 0x01) {
        // Allow if it's a standard multicast address
        if ((first_byte & 0xF0) == 0x01) {
            return XDP_PASS;
        }
        // Drop other broadcast/multicast traffic
        return XDP_DROP;
    }
    
    // Check if packet starts with specific pattern
    // Example: Drop packets where first byte is 0xAA
    if (first_byte == 0xAA) {
        return XDP_DROP;
    }
    
    // Allow all other packets
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
