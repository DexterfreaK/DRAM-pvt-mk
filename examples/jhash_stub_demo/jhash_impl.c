/* Real Jenkins hash — extracted from katran/jhash.h.
   Called by get_packet_hash() with a 16-byte symbolic IPv6 src address
   → chains two jhash calls → deeply nonlinear bitvector expr → Z3 hangs. */
#include <stdint.h>

typedef uint32_t u32;

static inline u32 rol32(u32 word, unsigned int shift) {
    return (word << shift) | (word >> ((-shift) & 31));
}

#define __jhash_mix(a, b, c) {          \
    a -= c; a ^= rol32(c,  4); c += b; \
    b -= a; b ^= rol32(a,  6); a += c; \
    c -= b; c ^= rol32(b,  8); b += a; \
    a -= c; a ^= rol32(c, 16); c += b; \
    b -= a; b ^= rol32(a, 19); a += c; \
    c -= b; c ^= rol32(b,  4); b += a; \
}

#define __jhash_final(a, b, c) {        \
    c ^= b; c -= rol32(b, 14);          \
    a ^= c; a -= rol32(c, 11);          \
    b ^= a; b -= rol32(a, 25);          \
    c ^= b; c -= rol32(b, 16);          \
    a ^= c; a -= rol32(c,  4);          \
    b ^= a; b -= rol32(a, 14);          \
    c ^= b; c -= rol32(b, 24);          \
}

#define JHASH_INITVAL  0xdeadbeef
#define INIT_JHASH_SEED_V6  32
#define INIT_JHASH_SEED     16129   /* RING_SIZE * MAX_VIPS */
#define RING_SIZE       127

static u32 jhash(const void *key, u32 length, u32 initval)
{
    u32 a, b, c;
    const unsigned char *k = (const unsigned char *)key;

    a = b = c = JHASH_INITVAL + length + initval;

    while (length > 12) {
        a += *(const u32 *)(k);
        b += *(const u32 *)(k + 4);
        c += *(const u32 *)(k + 8);
        __jhash_mix(a, b, c);
        length -= 12;
        k      += 12;
    }

    switch (length) {
    case 12: c += (u32)k[11] << 24;
    case 11: c += (u32)k[10] << 16;
    case 10: c += (u32)k[ 9] <<  8;
    case  9: c += k[8];
    case  8: b += (u32)k[ 7] << 24;
    case  7: b += (u32)k[ 6] << 16;
    case  6: b += (u32)k[ 5] <<  8;
    case  5: b += k[4];
    case  4: a += (u32)k[ 3] << 24;
    case  3: a += (u32)k[ 2] << 16;
    case  2: a += (u32)k[ 1] <<  8;
    case  1: a += k[0];
             __jhash_final(a, b, c);
    case  0: break;
    }
    return c;
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval) {
    u32 c = JHASH_INITVAL + (u32)(2 * sizeof(u32)) + initval;
    a += c; b += c;
    __jhash_final(a, b, c);
    return c;
}

/* Mirrors katran's get_packet_hash() without the KLEE_VERIFICATION guard. */
u32 get_packet_hash(const unsigned char srcv6[16], u32 ports)
{
    return jhash_2words(jhash(srcv6, 16, INIT_JHASH_SEED_V6),
                        ports,
                        INIT_JHASH_SEED)
           % RING_SIZE;
}
