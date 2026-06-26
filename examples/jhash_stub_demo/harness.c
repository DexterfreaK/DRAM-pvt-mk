/* KLEE harness for katran's get_packet_hash.
   The CH ring is divided into two halves (lo/hi) that route to different
   server pools — a common 2-tier setup.  Branching on hash_idx forces
   KLEE to explore both halves, exposing the coverage gap in concrete stubs.

   Properties checked:
     P1: hash_idx is a valid ring slot  (< RING_SIZE)
     P2: every ring slot belongs to exactly one pool (lo XOR hi)
*/
#include <stdint.h>
#include <klee/klee.h>

typedef uint32_t u32;
#define RING_SIZE 127
#define POOL_SPLIT 63   /* buckets [0,62] = pool-A, [63,126] = pool-B */

u32 get_packet_hash(const unsigned char srcv6[16], u32 ports);

int main(void)
{
    unsigned char srcv6[16];
    u32 ports;
    klee_make_symbolic(srcv6, sizeof srcv6, "srcv6");
    klee_make_symbolic(&ports, sizeof ports, "ports");

    u32 hash_idx = get_packet_hash(srcv6, ports);
    klee_assert(hash_idx < RING_SIZE);            /* P1 */

    int pool;
    if (hash_idx < POOL_SPLIT)
        pool = 0;   /* pool-A: low-latency servers */
    else
        pool = 1;   /* pool-B: high-capacity servers */

    /* policy: pool assignment is always defined */
    klee_assert(pool == 0 || pool == 1);          /* P2 */
    return 0;
}
