/* Katran's existing approach: return a fixed constant.
   Terminates instantly but only explores 1 of 127 possible ring buckets.
   Policies that depend on "what happens at bucket != 42" are not checked. */
#include <stdint.h>

typedef uint32_t u32;
#define RING_SIZE 127

u32 get_packet_hash(const unsigned char srcv6[16], u32 ports)
{
    (void)srcv6; (void)ports;
    return 42 % RING_SIZE;   /* always bucket 42 */
}
