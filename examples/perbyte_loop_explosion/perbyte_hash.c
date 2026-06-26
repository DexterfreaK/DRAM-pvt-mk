/*
 * perbyte_hash.c — FNV-1a per-byte loop extracted from xdp_main().
 *
 * Explosion type #A: 3-way branch per iteration ('\r' / ' ' / hash-update)
 * → ~3^LOOP_BOUND paths for symbolic input.
 *
 * Side effects: *out_matches = count of ' ' bytes seen.
 * Return:       hash % 1000u  ∈ [0, 999]
 */
#include <stdint.h>

#ifndef LOOP_BOUND
# define LOOP_BOUND 32
#endif

#define FNV_OFFSET_BASIS_32 2166136261u
#define FNV_PRIME_32        16777619u

uint32_t perbyte_hash(const char *payload, unsigned int len,
                      unsigned int *out_matches)
{
    uint32_t hash = FNV_OFFSET_BASIS_32;
    unsigned int matches = 0;
#pragma clang loop unroll(disable)
    for (int i = 0; i < LOOP_BOUND && (unsigned)i < len; i++) {
        char c = payload[i];
        if (c == '\r') {
            break;
        } else if (c == ' ') {
            matches++;
        } else {
            hash ^= (unsigned char)c;
            hash *= FNV_PRIME_32;
        }
    }
    *out_matches = matches;
    return hash % 1000u;
}
