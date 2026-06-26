#include <stdint.h>
#include <klee/klee.h>

#ifndef KEY_BYTES
# define KEY_BYTES 12u
#endif
#define TABLE_SIZE 3250u

/*
 * AI-derived function summary for hash_keys_mini().
 *
 * Abstract interpretation (see examples/ai_demo/hash_abstract_interp.py):
 *
 *   FNV-1a raw mixer (no final mask/shift):
 *     Known-bits domain: all 32 bits stay unknown after the first XOR+MUL
 *     because multiply propagates carries across all bit positions.
 *     Result: hash in [0, 2^32)  -- genuinely unbounded, no useful bit-bound.
 *
 *   hash % TABLE_SIZE  (TABLE_SIZE = 3250, non-power-of-two):
 *     Known-bits domain alone: rounds up to next 2^k = 4096, gives [0, 4095]
 *     (see h_maglev_ring() in hash_abstract_interp.py -- same situation).
 *     Reduced product (known-bits x interval): interval tracks "x mod c in
 *     [0, c-1]" exactly; reduced product gives [0, 3249] TIGHT.
 *
 * Replacement strategy (sound over-approximation):
 *   - Skip the hash loop body entirely: no more 3^KEY_BYTES path forks.
 *   - Introduce a fresh unconstrained symbolic for the raw hash
 *     (sound: it covers the full [0, 2^32) range of any real hash output).
 *   - Apply the mod-reduced bound as klee_assume: cache_idx < TABLE_SIZE.
 *   - KLEE sees one fresh symbol per invocation; the policy assertion
 *     klee_assert(cache_idx < TABLE_SIZE) is discharged trivially.
 *
 * key_len: independently bounded by KEY_BYTES via the loop structure.
 * We model it as a symbolic in [0, min(len, KEY_BYTES)] -- sound.
 */
uint32_t hash_keys_mini(const char *payload, unsigned int len,
                        unsigned int *out_key_len)
{
    (void)payload;

    /* sound model for the key length counter */
    unsigned key_len;
    klee_make_symbolic(&key_len, sizeof key_len, "key_len");
    unsigned cap = len < (unsigned)KEY_BYTES ? len : (unsigned)KEY_BYTES;
    klee_assume(key_len <= cap);
    *out_key_len = key_len;

    /* AI-derived bound: hash % TABLE_SIZE in [0, TABLE_SIZE-1] */
    uint32_t cache_idx;
    klee_make_symbolic(&cache_idx, sizeof cache_idx, "cache_idx");
    klee_assume(cache_idx < TABLE_SIZE);
    return cache_idx;
}
