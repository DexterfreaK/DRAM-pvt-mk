// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>

#define CHECK_OUT_OF_BOUNDS(PTR, OFFSET, END)                                  \
	(((void *)PTR) + OFFSET > ((void *)END))

__sum16 ip_checksum(struct iphdr *ip)
{
  __u32 csum = 0;
  __u16 *next_iph_u16 = (__u16 *)ip;
  for (__u64 i = 0; i < sizeof(struct iphdr) / 2; i++) {
    csum += *next_iph_u16++;
  }
  return ~((csum & 0xffff) + (csum >> 16));
}

SEC("xdp")
int udp_echo_prog_1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	if (CHECK_OUT_OF_BOUNDS(data, sizeof(struct ethhdr), data_end))
		return XDP_PASS;

	/* Extract the ethernet header. */
	struct ethhdr *eth = data;

	/* Extract the IP header. */
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (CHECK_OUT_OF_BOUNDS(ip, sizeof(struct iphdr), data_end))
		return XDP_PASS;

	/* Allow the packet to pass if not UDP. */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* Extract the UDP header. */
	struct udphdr *udph = data + sizeof(struct ethhdr) + (ip->ihl * 4);
	if (CHECK_OUT_OF_BOUNDS(udph, sizeof(struct udphdr), data_end))
		return XDP_PASS;

	/* Only process UDP packets with destination port 12345 */
	if (bpf_ntohs(udph->dest) != 12345)
		return XDP_PASS;

	__u8 tmp_mac[ETH_ALEN];
	__builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

	__be32 tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;

	__be16 tmp_port = udph->source;
	udph->source = udph->dest;
	udph->dest = tmp_port;

	ip->check = 0;
	ip->check = ip_checksum(ip);
	udph->check = 0;

	return XDP_TX;
}

SEC("xdp")
int udp_echo_prog_2(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	if (CHECK_OUT_OF_BOUNDS(data, sizeof(struct ethhdr), data_end))
		return XDP_PASS;

	/* Extract the ethernet header. */
	struct ethhdr *eth = data;

	/* Extract the IP header. */
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (CHECK_OUT_OF_BOUNDS(ip, sizeof(struct iphdr), data_end))
		return XDP_PASS;

	/* Allow the packet to pass if not UDP. */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* Extract the UDP header. */
	struct udphdr *udph = data + sizeof(struct ethhdr) + (ip->ihl * 4);
	if (CHECK_OUT_OF_BOUNDS(udph, sizeof(struct udphdr), data_end))
		return XDP_PASS;

	/* Only process UDP packets with destination port 13245 */
	if (bpf_ntohs(udph->dest) != 13245)
		return XDP_PASS;

	__u8 tmp_mac[ETH_ALEN];
	__builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

	__be32 tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;

	__be16 tmp_port = udph->source;
	udph->source = udph->dest;
	udph->dest = tmp_port;

	ip->check = 0;
	ip->check = ip_checksum(ip);
	udph->check = 0;

	return XDP_TX;
}
