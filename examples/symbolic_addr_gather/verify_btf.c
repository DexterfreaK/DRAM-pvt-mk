// Verifier-legality check ONLY. Identical logic to main.c's xdp_main, but using
// modern BTF map syntax (struct ... SEC(".maps")) so libbpf v1.0+ / the kernel
// verifier will load it. main.c keeps the legacy `bpf_map_def` form required by
// the ebpf-se/KLEE stub headers; that legacy "maps" section is what blocks the
// bundled xdp-loader, NOT the program logic. This file proves the logic is
// verifier-accepted.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef CHAIN
#define CHAIN 128
#endif
#define TBL_SIZE 256

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, unsigned int);
	__type(value, unsigned int);
	__uint(max_entries, TBL_SIZE);
} table SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	unsigned char *p = (unsigned char *)data;

	if ((void *)(p + 14) > data_end)   /* sizeof(struct ethhdr) */
		return XDP_PASS;

	unsigned int idx = p[0] & (TBL_SIZE - 1);
	unsigned int acc = 0;

#pragma clang loop unroll(disable)
	for (int i = 0; i < CHAIN; i++) {
		unsigned int *v = bpf_map_lookup_elem(&table, &idx);
		if (!v)
			return XDP_PASS;
		idx = (*v) & (TBL_SIZE - 1);
		acc ^= idx;
	}

	if (acc == 0x42)
		return XDP_DROP;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
