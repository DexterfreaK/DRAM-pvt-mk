# KLEE Stub Summarizer Results: Stub vs No Stub

This document summarizes only the **stub-summarizer** experiments: runs where a
real helper/hash function is linked into the KLEE harness and compared against a
manual or generated summary stub. It intentionally excludes selective packet
symbolization, policy pruning, and other non-stub rewrites.

## Final Results Table

| Experiment | Real implementation result | Stub result | Outcome | Remarks |
|---|---:|---:|---|---|
| BMC hash mini, `examples/bmc_ai_demo` | 37 completed, 22 partial, 62.00s, 1,417 insns | 1 completed, 0 partial, 0.11s, 65 insns | Stub much better |
| BMC hash keys, `examples/bmc-cache` | 48 completed, 98 partial, 32s, 2,603 insns | 1 completed, 0 partial, ~0s, 62 insns | Stub much better |
| Katran jhash demo, `examples/jhash_stub_demo` | Real jhash skipped; documented as `>>30s` / impractical | Symbolic stub: 2 completed, 0 partial, 0.12s, 57 insns | Stub better than real jhash; symbolic stub better than concrete stub for coverage |
| Katran csum fold, `examples/katran` | Reported: 26,788 completed, 305s, 46M insns | Reported: 57,190 completed, 549s, 55M insns | Stub worse | Bad target: cheap concrete helper paths replaced by unconstrained symbolic checksum |
| CRC hash, `examples/crc_hash` | 33 completed, 0 partial, 2.14s, 1,361 insns | 1 completed, 0 partial, 0.06s, 47 insns | Stub better, but baseline already finishes |

## Experiment 1: BMC Hash Mini (one we discussed)

Location: `examples/bmc_ai_demo`

The harness calls `hash_keys_mini()` and checks:

- `cache_idx < TABLE_SIZE`
- `key_len <= KEY_BYTES`

The baseline links the full FNV-style loop from `bmc_hash_mini.c`. The generated
stub `bmc_hash_stub_gen.c` replaces the loop with symbolic outputs plus bounds:

- `out_key_len <= 12`
- `result < 3250`

| Variant | Completed paths | Partial paths | Instructions | Queries | Wall time | Verdict |
|---|---:|---:|---:|---:|---:|---|
| Full loop | 37 | 22 | 1,417 | 60 | 62.00s | Timeout |
| Manual summary stub | 1 | 0 | 72 | 3 | 0.07s | Finished |
| Generated summary stub | 1 | 0 | 65 | 3 | 0.11s | Finished |

The generated stub gives the same practical result as the manual stub. This is a
clear win because the real function branches on symbolic payload bytes and
builds expensive FNV expressions.

## Experiment 2: BMC Hash Keys Extracted From bmc-cache

Location: `examples/bmc-cache`

The harness calls `bmc_hash_keys()` and checks:

```c
klee_assert(cache_idx < BMC_CACHE_ENTRY_COUNT);
```

The baseline links `bmc_hash_keys.c`; the stubbed run links
`bmc_hash_keys_stub.c`.

| Variant | Completed paths | Partial paths | Instructions | Queries | KLEE elapsed | Verdict |
|---|---:|---:|---:|---:|---:|---|
| Full extracted FNV loop | 48 | 98 | 2,603 | 243 | 00:00:32 | Timeout / incomplete |
| Summary stub | 1 | 0 | 62 | 3 | 00:00:00 | Finished |

The stub is a strong improvement because it directly encodes the table-index
bound that the policy needs, instead of forcing KLEE through the byte loop.

## Experiment 3: Katran jhash Stub Demo

Location: `examples/jhash_stub_demo`

This experiment compares the real packet hash against two stub styles:

- Concrete stub: always returns bucket `42`
- Symbolic stub: returns a symbolic value modulo `RING_SIZE`

The script documents the real jhash baseline as impractical because Z3 hangs on
the bit-vector mixing beyond the configured timeout.

| Variant | Completed paths | Partial paths | Instructions | Queries | Wall time | Coverage consequence |
|---|---:|---:|---:|---:|---:|---|
| Real jhash | ? | ? | ? | ? | `>>30s` | Solver timeout / impractical |
| Symbolic stub | 2 | 0 | 57 | 3 | 0.12s | Fast and checks both pool branches |

The concrete stub is fast but under-approximates behavior. The symbolic bounded
stub is the useful version for range/routing policies because it covers both
pool branches.

## Experiment 4: Katran `csum_fold_helper()`

Location: `examples/katran`

The helper is small:

```c
for (i = 0; i < 4; i++) {
    if (csum >> 16)
        csum = (csum & 0xffff) + (csum >> 16);
}
return ~csum;
```

The generated stub replaces this with a fresh symbolic `__u16`:

```c
__u16 result;
klee_make_symbolic(&result, sizeof result, "result");
klee_assume(result <= 65535);
return result;
```

Reported whole-Katran result:

| Version | Completed paths | Time | Instructions |
|---|---:|---:|---:|
| Original pre-existing `katran.bc`, with `--exit-on-error` | 16,110 | 179s | 14.7M |
| Real `csum_fold_helper`, extern, no `--exit-on-error` | 26,788 | 305s | 46M |
| Stubbed `csum_fold_helper`, no `--exit-on-error` | 57,190 | 549s | 55M |


csum_fold_helper is the wrong kind of target for the stub. It creates 16 paths per call (2⁴ from the unrolled if (csum >> 16) branches), but those 16 paths each
produce a concrete 16-bit checksum value. Concrete values make downstream Z3 queries fast — the solver sees ip->check = 0x1234 and can immediately discharge any constraints involving that field.

The stub replaces 16 cheap concrete paths with 1 path that has a fresh unconstrained symbolic __u16. That symbolic ip->check value is written into the packet struct,
which KLEE continues to explore symbolically. Every downstream operation that touches the IP header now has an extra free variable, causing:
1. More complex Z3 formulas per path
2. More downstream forks on packet-field comparisons


## Experiment 5: CRC Hash Summary


| Variant | Completed paths | Partial paths | Instructions | Wall time | Verdict |
|---|---:|---:|---:|---:|---|
| Real CRC | 33 | 0 | 1,361 | 2.14s | Finished |
| Summary stub | 1 | 0 | 47 | 0.06s | Finished |


## Takeaways

1. Stubs help when the target function is expensive in the way KLEE cares about:
   exponential symbolic branching or hard solver expressions.
2. A fresh symbolic stub can also be too weak as a performance summary. The
   `csum_fold_helper()` stub makes downstream packet state less constrained and
   performs worse.
3. The best stub targets in this project are `bmc_hash_keys` and jhash-style
   hashing. The worst target observed is Katran `csum_fold_helper()`.
