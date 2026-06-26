#include <stdint.h>
#include <klee/klee.h>

#ifndef LOOP_BOUND
# define LOOP_BOUND 32
#endif

extern uint32_t perbyte_hash(const char *payload, unsigned int len,
                              unsigned int *out_matches);

int main(void)
{
    char payload[LOOP_BOUND];
    klee_make_symbolic(payload, sizeof payload, "payload");

    unsigned int len;
    klee_make_symbolic(&len, sizeof len, "len");
    klee_assume(len <= (unsigned)LOOP_BOUND);

    unsigned int matches = 0;
    uint32_t h = perbyte_hash(payload, len, &matches);

    /* Policy: result is a valid bucket and matches count is bounded. */
    klee_assert(h < 1000u);
    klee_assert(matches <= (unsigned)LOOP_BOUND);
    return 0;
}
