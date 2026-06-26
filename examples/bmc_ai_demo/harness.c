#include <stdint.h>
#include <klee/klee.h>

#ifndef KEY_BYTES
# define KEY_BYTES 12u
#endif
#define TABLE_SIZE 3250u   /* BMC_CACHE_ENTRY_COUNT */

/*
 * Function under analysis.
 * Linked from one of:
 *   bmc_hash_mini.bc  -- full FNV loop  -> ~3^KEY_BYTES paths -> TIMEOUT
 *   bmc_hash_stub.bc  -- AI summary     -> O(1) paths         -> OK
 */
uint32_t hash_keys_mini(const char *payload, unsigned int len,
                        unsigned int *out_key_len);

int main(void)
{
    char     payload[KEY_BYTES];
    unsigned len;
    unsigned key_len = 0;

    klee_make_symbolic(payload, sizeof payload, "payload");
    klee_make_symbolic(&len,    sizeof len,     "len");
    klee_assume(len <= (unsigned)KEY_BYTES);

    uint32_t cache_idx = hash_keys_mini(payload, len, &key_len);

    /*
     * Restricted policy (KrakenGuard-style map-access control):
     *
     *   P1  map_kcache is accessed READ-ONLY at index cache_idx,
     *       and cache_idx must be a valid slot: cache_idx < TABLE_SIZE.
     *
     *       Without AI bounds:
     *         KLEE must explore ~3^KEY_BYTES paths through the hash loop
     *         to verify this on every execution prefix -- infeasible within
     *         any practical time budget.
     *
     *       With AI bounds (bmc_hash_stub):
     *         cache_idx is a fresh symbolic already constrained by
     *         klee_assume(cache_idx < TABLE_SIZE).  The assertion below is
     *         discharged immediately in O(1) paths.
     *
     *   P2  key_len is bounded by the packet slice actually consumed:
     *       key_len <= KEY_BYTES.  Same story: loop-induced path explosion
     *       vs. direct klee_assume in the stub.
     */
    klee_assert(cache_idx < TABLE_SIZE);               /* P1 */
    klee_assert(key_len   <= (unsigned)KEY_BYTES);     /* P2 */

    return 0;
}
