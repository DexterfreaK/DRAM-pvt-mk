#include <stdint.h>

#define BMC_MAX_KEY_LENGTH 250u
#define FNV_OFFSET_BASIS_32 2166136261u
#define FNV_PRIME_32 16777619u

unsigned int fnv_hash(const char *payload, unsigned int len, uint32_t *out_hash) {
    uint32_t hash = FNV_OFFSET_BASIS_32;
    unsigned int key_len = 0;
    unsigned int off;
    for (off = 0; off < BMC_MAX_KEY_LENGTH + 1u && off + 1u <= len; off++) {
        char c = payload[off];
        if (c == '\r') break;
        if (c == ' ') break;
        hash ^= (uint32_t)(unsigned char)c;
        hash *= FNV_PRIME_32;
        key_len++;
    }
    *out_hash = hash;
    return key_len;
}
