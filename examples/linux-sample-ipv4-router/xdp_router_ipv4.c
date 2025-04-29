/* Copyright (C) 2017 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stdint.h>
#include <bpf/bpf_endian.h>
#include <sys/socket.h>
#include <string.h>

#include <bpf/bpf_helpers.h>

#define ETH_ALEN	6
#define ETH_P_8021Q	0x8100
#define ETH_P_8021AD	0x88A8


#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif


struct trie_value {
    __u8 prefix[4];
    __be64 value;
    int ifindex;
    int metric;
    __be32 gw;
};

/* Key for lpm_trie */
union key_4 {
    __u32 b32[2];
    __u8 b8[8];
};

struct arp_entry {
    __be64 mac;
    __be32 dst;
};

struct direct_map {
    struct arp_entry arp;
    int ifindex;
    __be64 mac;
};

struct datarec {
	size_t processed;
	size_t dropped;
	size_t issue;
	union {
		size_t xdp_pass;
		size_t info;
	};
	size_t xdp_drop;
	size_t xdp_redirect;
} __attribute__((aligned(64)));

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/* Map for trie implementation */
struct bpf_map_def SEC("maps") lpm_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(8),
	.value_size = sizeof(struct trie_value),
	.max_entries = 50,
};

/* Map for ARP table */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, __be64);
    __uint(max_entries, 50);
} arp_table SEC(".maps");

/* Map to keep the exact match entries in the route table */
struct bpf_map_def SEC("maps") exact_match = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__be32),
	.value_size = sizeof(struct direct_map),
	.max_entries = 50,
};

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(struct datarec),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") rx_cnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct datarec),
	.max_entries = 1,
};

SEC("xdp")
int xdp_router_ipv4_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u64 nh_off = sizeof(*eth);
    struct datarec *rec;
    __be16 h_proto;
    __u32 key = 0;

    rec = bpf_map_lookup_elem(&rx_cnt, &key);
    if (rec)
        rec->processed++;

    if (data + nh_off > data_end)
        goto drop;

    h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_8021Q) ||
        h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            goto drop;

        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    switch (bpf_ntohs(h_proto)) {
    case ETH_P_ARP:
        if (rec)
            rec->xdp_pass++;
        return XDP_PASS;
    case ETH_P_IP: {
        struct iphdr *iph = data + nh_off;
        struct direct_map *direct_entry;
        __be64 *dest_mac, *src_mac;
        int forward_to;

        if (iph + 1 > data_end)
            goto drop;

        direct_entry = bpf_map_lookup_elem(&exact_match, &iph->daddr);

        /* Check for exact match, this would give a faster lookup */
        if (direct_entry && direct_entry->mac &&
            direct_entry->arp.mac) {
            src_mac = &direct_entry->mac;
            dest_mac = &direct_entry->arp.mac;
            forward_to = direct_entry->ifindex;
        } else {
            struct trie_value *prefix_value;
            union key_4 key4;

            /* Look up in the trie for lpm */
            key4.b32[0] = 32;
            key4.b8[4] = iph->daddr & 0xff;
            key4.b8[5] = (iph->daddr >> 8) & 0xff;
            key4.b8[6] = (iph->daddr >> 16) & 0xff;
            key4.b8[7] = (iph->daddr >> 24) & 0xff;

            prefix_value = bpf_map_lookup_elem(&lpm_map, &key4);
            if (!prefix_value)
                goto drop;

            forward_to = prefix_value->ifindex;
            src_mac = &prefix_value->value;
            if (!src_mac)
                goto drop;

            dest_mac = bpf_map_lookup_elem(&arp_table, &iph->daddr);
            if (!dest_mac) {
                if (!prefix_value->gw)
                    goto drop;

                dest_mac = bpf_map_lookup_elem(&arp_table,
                                &prefix_value->gw);
                if (!dest_mac) {
                    /* Forward the packet to the kernel in
                    * order to trigger ARP discovery for
                    * the default gw.
                    */
                    if (rec)
                        rec->xdp_pass++;
                    return XDP_PASS;
                }
            }
        }

        if (src_mac && dest_mac) {
            int ret;

            __builtin_memcpy(eth->h_dest, dest_mac, ETH_ALEN);
            __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

            ret = bpf_redirect_map(&tx_port, forward_to, 0);
            if (ret == XDP_REDIRECT) {
                if (rec)
                    rec->xdp_redirect++;
                return ret;
            }
        }
    }
    default:
        break;
    }
drop:
    if (rec)
        rec->xdp_drop++;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";


#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
#include "../../verification_tools/verification_helpers.h"

int main() {



    return 0;
}

#endif