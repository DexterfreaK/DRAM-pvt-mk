#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_map_def.h"

#ifndef CHAIN
#define CHAIN 128
#endif
#define TBL_SIZE 256

/*
 * Pointer-chase gather extracted from xdp_main.
 *
 * Follows a CHAIN-length chain through a BPF array map starting at
 * start_idx.  Each iteration reads one entry and XORs its value into acc.
 *
 * KLEE failure axis: solver cost, NOT path count.  With symbolic map
 * contents, each bpf_map_lookup_elem builds a 256-way array-select
 * expression; chaining CHAIN of them yields a CHAIN-deep nested select
 * that Z3 cannot untangle.  Path count stays at 2 (acc==0x42 vs !=0x42).
 *
 * The AI-bounds stub in do_gather_stub.c replaces this body with one fresh
 * symbolic constrained to [0, TBL_SIZE-1], collapsing solver cost to O(1).
 */
uint32_t do_gather(struct bpf_map_def *tbl, unsigned int start_idx)
{
    unsigned int idx = start_idx & (TBL_SIZE - 1);
    unsigned int acc = 0;

#pragma clang loop unroll(disable)
    for (int i = 0; i < CHAIN; i++) {
        unsigned int *v = bpf_map_lookup_elem(tbl, &idx);
        if (!v)                        /* dead in KLEE (array map, valid key) */
            return acc;
        idx = (*v) & (TBL_SIZE - 1);
        acc ^= idx;
    }
    return acc;
}
