#include <stdint.h>
#include <klee/klee.h>

#ifndef CRC_LEN
# define CRC_LEN 32
#endif

extern uint16_t crc16(const uint8_t *buf, unsigned int len);

int main(void)
{
    uint8_t buf[CRC_LEN];
    klee_make_symbolic(buf, sizeof buf, "buf");

    unsigned int len;
    klee_make_symbolic(&len, sizeof len, "len");
    klee_assume(len <= (unsigned)CRC_LEN);

    uint16_t crc = crc16(buf, len);

    /* Policy: CRC is always a valid 16-bit value. */
    klee_assert(crc <= 0xFFFF);
    return 0;
}
