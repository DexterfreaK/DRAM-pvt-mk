#include <stdint.h>
#include <linux/bpf.h>
#include "bpf_map_def.h"
#include <klee/klee.h>

#define TBL_SIZE 256

/*
 * AI-derived function summary for do_gather().
 *
 * Abstract interpretation (known-bits domain, see ai_demo/hash_abstract_interp.py):
 *
 *   Each iteration: acc ^= ((*tbl)[idx] & (TBL_SIZE - 1))
 *   (*tbl)[idx] is an unknown 32-bit value, masked to 8 bits by & 0xFF.
 *   Known-bits transfer: AND with Bits.const(0xFF) forces high 24 bits to 0.
 *   XOR of 8-bit values stays 8-bit (no carries propagate above bit 7).
 *   Result after CHAIN iterations: acc ∈ [0, TBL_SIZE-1] = [0, 255].
 *   TBL_SIZE = 256 is a power of two → MOD_pow2 gives the exact tight bound.
 *
 * Replacement strategy (sound over-approximation):
 *   - Skip the pointer-chase loop entirely: no CHAIN-deep nested selects.
 *   - Fresh symbolic acc bounded to [0, 255].  KLEE forks cleanly on
 *     acc == 0x42 (2 paths, <1 s) vs. TIMEOUT at CHAIN=128.
 *
 * No side effects (no pointer-output params) → Stage 2 of the summarizer
 * is a no-op for this function.
 */
uint32_t do_gather(struct bpf_map_def *tbl, unsigned int start_idx)
{
    (void)tbl;
    (void)start_idx;

    /* AI-derived bound: XOR accumulation of 8-bit values ∈ [0, TBL_SIZE-1] */
    uint32_t acc;
    klee_make_symbolic(&acc, sizeof acc, "acc");
    klee_assume(acc < TBL_SIZE);
    return acc;
}
