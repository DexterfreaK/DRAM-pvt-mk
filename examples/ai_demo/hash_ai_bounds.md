# Hash bound experiment — known-bits abstract interpretation

**Tool:** `hash_abstract_interp.py` (this directory)
**Domain:** ternary known-bits (tnum) over 32-bit words; interval read off the bits.
**Date:** 2026-06-17
**Reproduce:** `python3 hash_abstract_interp.py`

## Purpose

Derive an *output bound* for several hash functions — the limit a symbolic
executor can `klee_assume` so it never explores the hash internals. This is the
analyzer half of the function summarizer (`docs/summarization_design.md`).

The motivating contrast is the **interval domain** that CLAM/Crab runs on
`fnv_hash` (`clam_int.txt`): it havocs the hash to `[-oo,+oo]` at the first
XOR/multiply, so it derives **no** usable bound. The known-bits domain survives
the bit-ops and recovers a real limit wherever the hash ends in a mask/shift.

## Results

```
hash function                               result (known-bits, MSB..LSB)        bound
------------------------------------------------------------------------------------------
FNV-1a -> & 0xFFF  (4096-entry table)       0000000000000000 0000???????????    [0, 4095]
multiplicative hash >> 20  (12-bit out)     0000000000000000 0000???????????    [0, 4095]
xorshift & 0xFF                             0000000000000000 00000000????????    [0, 255]
maglev hash % 65537 (prime ring)            000000000000000? ?????????????????   [0, 131071]
raw mixer, no masking                       ???????????????? ?????????????????   [0, 4294967295]
```
`?` = unknown bit; fixed `0`/`1` bits are the proven limit.

| hash | result `[min,max]` | true tightest bound | verdict |
|---|---|---|---|
| FNV-1a `& 0xFFF` | `[0, 4095]` | `[0, 4095]` | **exact** — all 4096 values reachable |
| multiplicative `>> 20` | `[0, 4095]` | `[0, 4095]` | **exact** |
| xorshift `& 0xFF` | `[0, 255]` | `[0, 255]` | **exact** |
| maglev `% 65537` | `[0, 131071]` | `[0, 65536]` | **loose** — snapped to next power of two |
| raw mixer (no mask) | `[0, 2^32)` | `[0, 2^32)` | **exact** — genuinely unbounded |

## Take-aways

1. **Masked/shifted hashes get a tight bound for free.** Every result is
   `2^k - 1`, and for the masked/shifted cases that *is* the tightest sound
   answer — every low bit is independently reachable, so no analysis can prove
   smaller. `4095` is exactly what proves the 4096-entry table index is in range.

2. **The interval domain learns nothing here; the bit domain is the right tool.**
   The raw-mixer row (`[0, 2^32)`) is the honest answer and matches what CLAM's
   interval domain produces — but CLAM produces it for *every* hash, masked or
   not, because it loses the value at the first XOR/multiply.

3. **One genuinely loose case: non-power-of-two modulo.** `maglev % 65537`
   reports `131071` (2^17 - 1) instead of the true `65536`. A pure known-bits
   domain cannot express a non-power-of-two ceiling, so it rounds up to the next
   power of two. Recovering the tight bound needs a **reduced product** of
   known-bits × interval — the pending analyzer upgrade noted in
   `docs/summarization_design.md` §6.

## How this feeds the summarizer

| bound result | summary mode | replacement |
|---|---|---|
| tight (`& mask`, `>> shift`) | Mode A or B | `klee_assume(out <= max)` is lossless |
| `[0, 2^32)` (raw mixer) | havoc / UF | no constraint; sound over-approximation |
| loose (`% prime`) | needs reduced product | bound is conservative until then |

See `docs/summarization_design.md` for how a symbolic executor consumes these.
