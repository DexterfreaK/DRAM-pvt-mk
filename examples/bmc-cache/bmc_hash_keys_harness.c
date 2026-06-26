#include <stdint.h>
#include <klee/klee.h>

#ifndef BMC_MAX_KEY_LENGTH
# define BMC_MAX_KEY_LENGTH  250
#endif
#ifndef BMC_CACHE_ENTRY_COUNT
# define BMC_CACHE_ENTRY_COUNT  3250
#endif

/* Declared as extern — resolved by linking with either bmc_hash_keys.bc
 * (baseline, path-explosive) or bmc_hash_keys_stub.bc (AI-summarized). */
extern uint32_t bmc_hash_keys(const char *payload, unsigned int len,
                               unsigned int *out_key_len);

int main(void)
{
    char payload[BMC_MAX_KEY_LENGTH + 1];
    klee_make_symbolic(payload, sizeof payload, "payload");

    unsigned int len;
    klee_make_symbolic(&len, sizeof len, "len");
    klee_assume(len <= (unsigned)BMC_MAX_KEY_LENGTH);

    unsigned int key_len = 0;
    uint32_t cache_idx = bmc_hash_keys(payload, len, &key_len);

    /* Policy check: cache_idx must be a valid table slot. */
    klee_assert(cache_idx < BMC_CACHE_ENTRY_COUNT);

    return 0;
}
