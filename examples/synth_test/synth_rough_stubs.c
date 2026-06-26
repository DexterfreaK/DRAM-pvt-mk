/* synth_rough_stubs.c — rough stubs with NO klee_assume.
 *
 * This is what Strategy B injects at runtime when a budget is exceeded:
 * a fresh unconstrained symbolic of the right type, nothing more.
 *
 * Expected result:
 *   P1 FAILS — classify_type can return any int (e.g. 999), not just -1..2
 *   P2 FAILS — hash_payload can return any uint32_t, not just < NUM_BACKENDS
 *   P3 FAILS — out_key_len side effect unconstrained, can be negative
 * All three are FALSE POSITIVES: the real function never produces those values. */

#include "synth_common.h"
#include <klee/klee.h>

int classify_type(const char *p, int len) {
    (void)p; (void)len;
    int r;
    klee_make_symbolic(&r, sizeof r, "classify_type");
    return r;   /* unconstrained: any int */
}

uint32_t hash_payload(const char *key, int maxlen, int *out_key_len) {
    (void)key; (void)maxlen;
    int l;
    klee_make_symbolic(&l, sizeof l, "hash_key_len");
    *out_key_len = l;   /* unconstrained: can be negative or > maxlen */
    uint32_t r;
    klee_make_symbolic(&r, sizeof r, "hash_result");
    return r;           /* unconstrained: can be >= NUM_BACKENDS */
}

uint16_t fold_csum(uint32_t csum) {
    (void)csum;
    uint16_t r;
    klee_make_symbolic(&r, sizeof r, "fold_csum");
    return r;   /* uint16_t bounds this even without klee_assume */
}
