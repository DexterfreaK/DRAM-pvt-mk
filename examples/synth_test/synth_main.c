/* synth_main.c — synthetic KLEE harness for testing stub soundness.
 *
 * Three variants are linked against this file:
 *   synth_real.bc  — real expensive functions  (slow, path explosion)
 *   synth_tight.bc — tight stubs with klee_assume  (fast, sound)
 *   synth_rough.bc — rough stubs, no klee_assume   (fast, false positives)
 *
 * Policy assertions P1/P2/P3 should:
 *   PASS with real functions and tight stubs (correct behaviour)
 *   FAIL with rough stubs (false positives from over-approximation)
 */

#include "synth_common.h"
#include <klee/klee.h>

/* ── Simple helpers — no path explosion ─────────────────────────────────── */

/* Ephemeral port range check: 1 branch, O(1). */
static int is_valid_port(uint16_t port) {
    return port >= 1024;
}

/* Even-indexed backends are treated as "primary". 1 branch. */
static int is_primary_backend(uint32_t idx) {
    return (idx & 1) == 0;
}

/* Only REQUEST and ACK carry a checksum. 2 branches. */
static int needs_checksum(int type) {
    return type == TYPE_REQUEST || type == TYPE_ACK;
}

/* Safety clamp after hash — ensures downstream array access is safe
 * even if the policy check fires as assert (not abort). */
static uint32_t clamp_backend(uint32_t idx) {
    return (idx < (uint32_t)NUM_BACKENDS) ? idx : (uint32_t)(NUM_BACKENDS - 1);
}

/* ── Policy assertions ───────────────────────────────────────────────────── */

/* P1: classify_type must return a value in the defined sentinel range [-1, 2].
 *   Rough stub: FAILS — type can be any int (false positive).
 *   Tight stub / real: PASSES — klee_assume / real logic bounds it. */
static void p1_type_range(int type) {
    klee_assert(type >= TYPE_UNKNOWN && type <= TYPE_ACK);
}

/* P2: hash_payload return must index within the backend table.
 *   Rough stub: FAILS — hash can be any uint32_t (false positive).
 *   Tight stub / real: PASSES — klee_assume(r < NUM_BACKENDS) / urem. */
static void p2_backend_bounds(uint32_t idx) {
    klee_assert(idx < (uint32_t)NUM_BACKENDS);
}

/* P3: hash_payload side-effect out_key_len must be in [0, maxlen].
 *   Rough stub: FAILS — out_key_len is unconstrained (false positive).
 *   Tight stub / real: PASSES — klee_assume / loop exit invariant. */
static void p3_key_len(int klen, int maxlen) {
    klee_assert(klen >= 0 && klen <= maxlen);
}

/* ── KLEE harness ────────────────────────────────────────────────────────── */

int main(void) {
    char     payload[32];
    uint16_t src_port;
    uint32_t raw_csum;

    klee_make_symbolic(payload,   sizeof payload,   "payload");
    klee_make_symbolic(&src_port, sizeof src_port,  "src_port");
    klee_make_symbolic(&raw_csum, sizeof raw_csum,  "raw_csum");

    /* Step 1 — classify message type (Axis E: flat byte classifier) */
    int type = classify_type(payload, (int)sizeof payload);
    p1_type_range(type);                    /* P1 */

    if (type == TYPE_UNKNOWN)
        return 0;   /* drop unknown packets early */

    /* Step 2 — validate source port (cheap helper, 1 branch) */
    if (!is_valid_port(src_port))
        return 0;

    /* Step 3 — hash first KEY_MAXLEN bytes to pick a backend (Axis A) */
    int key_len = 0;
    uint32_t backend = hash_payload(payload, KEY_MAXLEN, &key_len);
    p2_backend_bounds(backend);             /* P2 */
    p3_key_len(key_len, KEY_MAXLEN);        /* P3 */
    backend = clamp_backend(backend);       /* safe to use after this */

    /* Step 4 — fold checksum for types that need it (Axis D) */
    uint16_t cs = 0;
    if (needs_checksum(type))
        cs = fold_csum(raw_csum);
    (void)cs;   /* checksum used downstream; uint16_t type bounds it implicitly */

    /* Step 5 — type-gated dispatch using cheap helpers only */
    if (type == TYPE_PREPARE) {
        /* PREPARE goes to any backend; prefer primary but not required */
        (void)is_primary_backend(backend);
    }

    if (type == TYPE_REQUEST) {
        /* REQUEST: backend already validated by P2; forward it */
        klee_assert(backend < (uint32_t)NUM_BACKENDS);  /* P2 re-check after clamp */
    }

    if (type == TYPE_ACK) {
        /* ACK: lightest path, no extra checks */
        (void)backend;
    }

    return 0;
}
