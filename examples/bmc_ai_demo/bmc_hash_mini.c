#include <stdint.h>

#ifndef KEY_BYTES
# define KEY_BYTES 12u    /* tune via -DKEY_BYTES=N; 12 reliably blows up KLEE */
#endif
#define TABLE_SIZE 3250u  /* BMC_CACHE_ENTRY_COUNT from bmc_common.h */
#define FNV_OFFSET 2166136261u
#define FNV_PRIME  16777619u

/*
 * Distilled bmc_hash_keys_main / bmc_invalidate_cache_main hash loop.
 *
 * Structure (two non-break arms):
 *   '\r'   -> sentinel break (terminates one path per depth)
 *   ' '    -> delimiter: count but CONTINUE -- models the real bmc loop where
 *             a space is a field separator inside the payload, not end-of-key
 *   other  -> FNV byte update and CONTINUE
 *
 * Because both ' ' and 'other' continue, KLEE sees two live states at each
 * non-'\r' byte AND the loop upper bound (len) is symbolic, adding another
 * fork per iteration.  Combined explosion: roughly 3^KEY_BYTES paths.
 *
 * At KEY_BYTES=12: ~531K paths -- KLEE exhausts a 120-second budget.
 * The AI-bounds stub in bmc_hash_stub.c replaces this body with one fresh
 * symbolic + klee_assume, collapsing all paths to O(1).
 */

//  hash = ((((FNV_OFFSET ^ b0) * FNV_PRIME) ^ b1) * FNV_PRIME) ^ ... % 3250
uint32_t hash_keys_mini(const char *payload, signed int len,
                        unsigned int *out_key_len)
{
    uint32_t hash    = FNV_OFFSET;
    unsigned key_len = 0;
    unsigned off;

    for (off = 0; off < KEY_BYTES && off < len; off++) {
        if (payload[off] == '\r') break;    /* fork A: end-of-key sentinel */
        if (payload[off] != ' ') {          /* fork B: non-delimiter -> hash */
            hash ^= (uint32_t)(unsigned char)payload[off];
            hash *= FNV_PRIME;

        }
        key_len++;                          /* both ' ' and other reach here */
    }

    // [-inf,key_len] -> relational abstraction
    // key_len = -1 -> out_key_len = 0
    *out_key_len = key_len;
    return hash % TABLE_SIZE; // [0,3250]
}
