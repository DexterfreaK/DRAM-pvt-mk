#include "synth_common.h"
#include <stdint.h>

/* classify_type — Axis E: flat sequential byte classifier.
 * 3 branches x 4 byte comparisons each = ~12 forks on symbolic payload.
 * Mirrors compute_message_type from electrode. */
int classify_type(const char *p, int len) {
    if (len < 4) return TYPE_UNKNOWN;
    if (p[0]=='P' && p[1]=='R' && p[2]=='E' && p[3]=='P') return TYPE_PREPARE;
    if (p[0]=='R' && p[1]=='E' && p[2]=='Q' && p[3]=='U') return TYPE_REQUEST;
    if (p[0]=='A' && p[1]=='C' && p[2]=='K' && p[3]=='_') return TYPE_ACK;
    return TYPE_UNKNOWN;
}

/* hash_payload — Axis A: loop + per-byte branch on null terminator.
 * key[i] == '\0' forks on each symbolic byte => 2^KEY_MAXLEN paths.
 * Mirrors bmc_hash_keys from bmc-cache. */
uint32_t hash_payload(const char *key, int maxlen, int *out_key_len) {
    uint32_t h = 2166136261u;   /* FNV-1a offset basis */
    int i = 0;
    for (; i < maxlen; i++) {
        if (key[i] == '\0') break;   /* branch on symbolic byte => fork */
        h ^= (uint8_t)key[i];
        h *= 16777619u;              /* FNV prime */
    }
    *out_key_len = i;
    return h % NUM_BACKENDS;         /* result always in [0, NUM_BACKENDS) */
}

/* fold_csum — Axis D: loop + conditional branch per iteration.
 * 4 iterations x 1 branch = 2^4 = 16 paths per call.
 * Mirrors csum_fold_helper from katran. */
uint16_t fold_csum(uint32_t csum) {
    for (int i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return (uint16_t)~csum;
}
