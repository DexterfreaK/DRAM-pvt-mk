#include <stdint.h>

typedef uint16_t __u16;
typedef uint64_t __u64;

/* One iteration of the carry-propagation fold: if the value has bits above
 * bit 15, add the high half into the low half.  Unrolled 4 times to ensure
 * full propagation regardless of the starting value.  Returns the one's
 * complement of the fully-folded 16-bit sum. */
__u16 csum_fold_helper(__u64 csum)
{
    int i;
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}
