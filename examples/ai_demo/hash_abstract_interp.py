#!/usr/bin/env python3
"""Abstract interpretation of hash functions in the *known-bits* domain.

Why not intervals?  Interval AI (what CLAM/Crab uses here, see clam_int.txt)
gives [-oo,+oo] for any value that flows through XOR or multiply -- it has to
havoc the hash.  So intervals tell you *nothing* about a hash's output limits.

The right abstract domain for bit-twiddling code is a ternary bit-vector:
each of the W bits is one of {0, 1, T(=unknown)}.  This survives AND/OR/XOR/
shift exactly, approximates ADD/MUL, and -- crucially -- a final mask or
power-of-two modulo collapses the high bits to 0.  From the known-bits you
read off the real limits: which bits are forced, and the [min,max] interval.

Usage:  python3 hash_abstract_interp.py
"""

from dataclasses import dataclass

W = 32                      # bit-width we reason about
MASK = (1 << W) - 1


@dataclass
class Bits:
    """Ternary bit-vector.  k1: bits known to be 1.  k0: bits known to be 0.
    A bit is unknown (T) iff it is in neither set.  Invariant: k1 & k0 == 0."""
    k1: int
    k0: int

    @staticmethod
    def const(c):
        c &= MASK
        return Bits(c, ~c & MASK)

    @staticmethod
    def top():                       # fully unknown W-bit value
        return Bits(0, 0)

    @property
    def known(self):                 # bits whose value we know
        return (self.k1 | self.k0) & MASK

    def interval(self):
        unknown = ~self.known & MASK
        return self.k1, self.k1 | unknown          # (min, max)

    def __repr__(self):
        s = "".join("1" if self.k1 >> b & 1 else
                    "0" if self.k0 >> b & 1 else "?"
                    for b in range(W - 1, -1, -1))
        lo, hi = self.interval()
        return f"{s}  min={lo} max={hi}"


# ---- abstract transfer functions ----------------------------------------

def AND(a, b):
    return Bits(a.k1 & b.k1, (a.k0 | b.k0) & MASK)

def OR(a, b):
    return Bits((a.k1 | b.k1) & MASK, a.k0 & b.k0)

def XOR(a, b):
    both = a.known & b.known          # determined only where both inputs known
    v1 = (a.k1 ^ b.k1) & both
    return Bits(v1, both & ~v1 & MASK)

def SHL(a, n):
    return Bits((a.k1 << n) & MASK,
                ((a.k0 << n) | ((1 << n) - 1)) & MASK)   # new low bits are 0

def SHR(a, n):
    hi_zero = MASK & ~(MASK >> n)     # vacated high bits are 0
    return Bits(a.k1 >> n, (a.k0 >> n) | hi_zero)

def ADD(a, b):
    """Carry-propagating ternary add: known low bits stay known until the
    first position where a carry could be ambiguous."""
    k1 = k0 = 0
    carry = Bits.const(0)             # 1-bit carry as a Bits we collapse per step
    c_known, c_val = True, 0
    for i in range(W):
        abit = (a.k1 >> i & 1, a.k0 >> i & 1)   # (is1, is0)
        bbit = (b.k1 >> i & 1, b.k0 >> i & 1)
        a_known, a_v = abit[0] | abit[1], abit[0]
        b_known, b_v = bbit[0] | bbit[1], bbit[0]
        if a_known and b_known and c_known:
            s = a_v + b_v + c_val
            bit, c_val = s & 1, s >> 1
            k1 |= bit << i
            k0 |= (bit ^ 1) << i
        else:
            # output bit and outgoing carry both become unknown
            c_known = False
    return Bits(k1, k0)

def MUL_const(a, c):
    """x * c  =  sum of shifted copies for each set bit of c."""
    acc = Bits.const(0)
    for i in range(W):
        if c >> i & 1:
            acc = ADD(acc, SHL(a, i))
    return acc

def MOD_pow2(a, n):                   # x % 2**n  ==  x & (2**n - 1)
    return AND(a, Bits.const((1 << n) - 1))

def MOD_const(a, m):
    """General modulo: bit-domain can't track it, but the *result* is bounded
    to [0, m-1].  We return the tightest Bits enclosing that interval."""
    hi = m - 1
    top_bit = hi.bit_length()
    forced0 = MASK & ~((1 << top_bit) - 1)    # bits above hi are 0
    return Bits(0, forced0)


# ---- hash functions, written as abstract programs ------------------------

def h_fnv1a(table_bits):
    """FNV-1a folded into a power-of-two table.  Input bytes are unknown,
    so the accumulated hash is T; the final mask is what creates the limit."""
    h = Bits.const(2166136261)
    for _ in range(8):               # a few unknown input bytes
        h = XOR(h, Bits.top())       # ^= byte  (byte unknown)
        h = MUL_const(h, 16777619)   # *= FNV_PRIME
    return MOD_pow2(h, table_bits)

def h_mult_shift(out_bits):
    """Multiplicative (Fibonacci) hash: (x * C) >> (W - out_bits)."""
    x = Bits.top()
    return SHR(MUL_const(x, 2654435761), W - out_bits)

def h_xorshift_mask(mask_bits):
    """xorshift mixer then AND mask."""
    x = Bits.top()
    x = XOR(x, SHL(x, 13))
    x = XOR(x, SHR(x, 17))
    x = XOR(x, SHL(x, 5))
    return AND(x, Bits.const((1 << mask_bits) - 1))

def h_maglev_ring(ring_size):
    """katran/maglev style: hash % ring_size  (ring_size not power of two)."""
    return MOD_const(Bits.top(), ring_size)


if __name__ == "__main__":
    cases = [
        ("FNV-1a -> & 0xFFF  (4096-entry table)", h_fnv1a(12)),
        ("multiplicative hash >> 20  (12-bit out)", h_mult_shift(12)),
        ("xorshift & 0xFF",                          h_xorshift_mask(8)),
        ("maglev hash %% 65537 (prime ring)",        h_maglev_ring(65537)),
        ("raw mixer, no masking (interval useless)", h_xorshift_mask(W)),
    ]
    print(f"{'hash function':42s}  result (known-bits, MSB..LSB)")
    print("-" * 90)
    for name, res in cases:
        lo, hi = res.interval()
        print(f"{name:42s}  {res}")
    print("\nReading: '?' = unknown bit, fixed 0/1 bits are the proven limit.")
    print("min/max is the interval you can hand to KLEE as a bound, e.g.")
    print("  klee_assume(hash <= max)  -- which CLAM's interval domain cannot derive.")
