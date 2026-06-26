/* synth_stubs.c — tight stubs with klee_assume bounds.
 *
 * Stage 3 (return bound): klee_assume matches the real function's output range.
 * Stage 2 (side effects): out_key_len bounded by Clam zones-domain invariant.
 *
 * Expected result: all policy assertions in synth_main.c PASS.
 * No false positives, no false negatives. */

#include "synth_common.h"
#include <klee/klee.h>

int classify_type(const char *p, int len) {
    (void)p; (void)len;
    int r;
    klee_make_symbolic(&r, sizeof r, "classify_type");
    klee_assume(r >= TYPE_UNKNOWN && r <= TYPE_ACK);  /* -1..2 */
    return r;
}

uint32_t hash_payload(const char *key, int maxlen, int *out_key_len) {
    (void)key;
    /* Stage 2: side effect bounded by loop exit invariant */
    int l;
    klee_make_symbolic(&l, sizeof l, "hash_key_len");
    klee_assume(l >= 0 && l <= maxlen);
    *out_key_len = l;
    /* Stage 3: urem NUM_BACKENDS guarantees result in [0, NUM_BACKENDS) */
    uint32_t r;
    klee_make_symbolic(&r, sizeof r, "hash_result");
    klee_assume(r < (uint32_t)NUM_BACKENDS);
    return r;
}

/* No klee_assume needed: uint16_t return type already bounds the value. */
uint16_t fold_csum(uint32_t csum) {
    (void)csum;
    uint16_t r;
    klee_make_symbolic(&r, sizeof r, "fold_csum");
    return r;
}
