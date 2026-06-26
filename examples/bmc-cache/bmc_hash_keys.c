/*
 * bmc_hash_keys.c — FNV-1a hash loop extracted from bmc_hash_keys_main().
 *
 * This is the path-explosive sub-computation: 3 branches per iteration
 * ('\r', ' ', other) produce ~3^BMC_MAX_KEY_LENGTH paths at len=250.
 * Intended for use with lifting_tools/summarizer/summarize.py.
 *
 * API matches bmc_hash_mini.c (same structure, real key-length constant).
 */

#include <stdint.h>

/* Constants from bmc_common.h — repeated here so the file compiles without
 * BPF headers (bmc_common.h pulls in struct bpf_spin_lock which is opaque
 * outside -target bpf compilations). */
#ifndef BMC_MAX_KEY_LENGTH
# define BMC_MAX_KEY_LENGTH  250
#endif
#ifndef BMC_CACHE_ENTRY_COUNT
# define BMC_CACHE_ENTRY_COUNT  3250
#endif
#ifndef FNV_OFFSET_BASIS_32
# define FNV_OFFSET_BASIS_32  2166136261u
#endif
#ifndef FNV_PRIME_32
# define FNV_PRIME_32  16777619u
#endif

/*
 * Compute FNV-1a hash of `payload[0..len)`, stopping at '\r' or ' '.
 *
 * Returns: cache_idx = hash % BMC_CACHE_ENTRY_COUNT  ∈ [0, 3249]
 * Side effect: *out_key_len = number of bytes consumed before stop character
 */
uint32_t bmc_hash_keys(const char *payload, unsigned int len,
                       unsigned int *out_key_len)
{
    uint32_t hash = FNV_OFFSET_BASIS_32;
    unsigned int off, key_len = 0;
#pragma clang loop unroll(disable)
    for (off = 0; off < BMC_MAX_KEY_LENGTH + 1 && off < len; off++) {
        if (payload[off] == '\r') {
            break;
        } else if (payload[off] == ' ') {
            break;
        } else {
            hash ^= (uint32_t)(unsigned char)payload[off];
            hash *= FNV_PRIME_32;
            key_len++;
        }
    }
    *out_key_len = key_len;
    return hash % BMC_CACHE_ENTRY_COUNT;
}
