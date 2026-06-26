# KLEE Stub Summarizer Results: Stub vs No Stub

This document summarizes only the **stub-summarizer** experiments: runs where a
real helper/hash function is linked into the KLEE harness and compared against a
manual or generated summary stub. It intentionally excludes selective packet
symbolization, policy pruning, and other non-stub rewrites.

## Final Results Table

| Experiment | Real implementation result | Stub result | Outcome | Main lesson |
|---|---:|---:|---|---|
| BMC hash mini, `examples/bmc_ai_demo` | 37 completed, 22 partial, 62.00s, 1,417 insns | 1 completed, 0 partial, 0.11s, 65 insns | Stub much better | Good target: path-heavy FNV loop summarized by bounded symbolic result |
| BMC hash keys, `examples/bmc-cache` | 48 completed, 98 partial, 32s, 2,603 insns | 1 completed, 0 partial, ~0s, 62 insns | Stub much better | Good target: extracted cache hash loop causes unfinished paths |
| BMC hash keys (End-to-End), `examples/bmc-cache` | 0 completed, Timeout (~54.5s) | 1 completed, 0 partial, 0.46s, 6,117 insns | Stub much better | Good target: eliminates exponential paths in fully integrated ebpf map-lookup harness |
| Katran jhash demo, `examples/jhash_stub_demo` | Real jhash skipped; documented as `>>30s` / impractical | Symbolic stub: 2 completed, 0 partial, 0.12s, 57 insns | Stub better than real jhash; symbolic stub better than concrete stub for coverage | Good target: expensive bit-vector hash mixing |
| Katran csum fold, `examples/katran` | 57,190 completed, 551s, 54.8M insns | 26,788 completed, 302s, 46.0M insns | Stub better | Good target: eliminates 2⁴ carry-fold branches per call; nothing downstream branches on checksum |
| CRC hash, `examples/crc_hash` | 33 completed, 0 partial, 2.14s, 1,361 insns | 1 completed, 0 partial, 0.06s, 47 insns | Stub better, but baseline already finishes | Small positive micro-result; current stub bound is too narrow for general CRC-16 |
| Electrode `compute_message_type`, `examples/electrode` | 135 completed, 0 partial, 35s, 18,257 insns | 12 completed, 0 partial, 34s, 7,011 insns | Stub better | Good target: payload byte-compare classifier with many symbolic branches |

## Experiment 1: BMC Hash Mini

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

## Experiment 2b: BMC Hash Keys End-to-End Integration

Location: `examples/bmc-cache`

This experiment evaluates the stub summarizer integrated directly into the full BPF pipeline (`main.c` testing `bmc_hash_keys_main`) instead of an isolated harness. To prevent the KLEE solver from throwing an out-of-memory error upon attempting symbolic indexing over a 4.29MB map, the size of the array was constrained (`BMC_CACHE_ENTRY_COUNT = 2`).

The inline, path-explosive FNV-1a hash loop (`bmc_kern.c`) was refactored into a call to the external `bmc_hash_keys()` function, allowing the program to be linked against the full implementation or the stub.

| Variant | Completed paths | Instructions | Execution Time | Verdict |
|---|---:|---:|---:|---|
| Vanilla (Inlined FNV hash loop) | 0 (Timeout/Incomplete) | N/A | ~48.7s | Timeout / Path Explosion |
| Refactored + Real Hash | 0 (Timeout/Incomplete) | N/A | ~54.5s | Timeout / Path Explosion |
| Refactored + Stubbed Hash | 1 | 6,117 | ~0.46s | Finished |

Integrating the stub effectively replaces the symbolic payload-bound FNV loop with an unconstrained (but appropriately bounded) symbolic integer, enabling KLEE to reach the end of the packet handling logic and resolve the BPF Map lookups in under half a second without exponential branching.

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
| Concrete stub | 1 | 0 | 42 | 0 | 0.04s | Fast, but only checks pool A |
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

Whole-Katran results (confirmed by fresh re-runs, no `--exit-on-error`):

| Version | Completed paths | Partial paths | Time | Instructions | Queries | Avg constructs/query |
|---|---:|---:|---:|---:|---:|---:|
| Vanilla `katran.bc` (broken extern) | 11,587 | 16,241 | 267s | 42.4M | — | — |
| Real `csum_fold_helper` (`katran_with_real.bc`) | 57,190 | 1,040 | 551s | 54.8M | 525 | 76 |
| Stubbed `csum_fold_helper` (`katran_stub.bc`) | 26,788 | 1,040 | 302s | 46.0M | 253 | 21 |

The stub is better on every metric. The real `csum_fold_helper` has a 4-iteration
unrolled loop with a branch per iteration (`if (csum >> 16)`), producing 2⁴ = 16
concrete paths per call. Katran calls it from four wrappers (`ipv4_csum`,
`ipv4_csum_inline`, `ipv4_l4_csum`, `ipv6_csum`), so the carry-fold branching
multiplies across call sites — explaining the jump from 26,788 to 57,190 paths.

The stub eliminates all 16 internal branches per call while introducing a fresh
symbolic `__u16`. In theory, this unconstrained value could increase downstream
solver cost. In practice, nothing in Katran meaningfully branches on `ip->check`
after it is written, so the extra symbolic variable has negligible impact. The
query data confirms this: stub queries average 21 constructs vs 76 for real.


## Experiment 5: CRC Hash Summary

Location: `examples/crc_hash`

The real function is a table-driven CRC loop. The stub returns a fresh symbolic
result with a generated bound.

| Variant | Completed paths | Partial paths | Instructions | Wall time | Verdict |
|---|---:|---:|---:|---:|---|
| Real CRC | 33 | 0 | 1,361 | 2.14s | Finished |
| Summary stub | 1 | 0 | 47 | 0.06s | Finished |

The stub reduces work, but the baseline already finishes. This is a small
positive result rather than a timeout rescue.

Caveat: the current generated CRC stub constrains the return value to `<= 255`,
while CRC-16 can generally return values up to `0xffff`. That is harmless for
the current harness assertion `crc <= 0xffff`, but it is not a sound general
summary for policies that depend on the full checksum value.

## Experiment 6: Electrode `compute_message_type()`

Location: `examples/electrode`

The helper is a payload byte-compare classifier that identifies Paxos message
types by matching magic bytes at fixed offsets:

```c
int compute_message_type(char *payload, void *data_end) {
    if (payload + PREPARE_TYPE_LEN < data_end &&
        payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'P' && ...)
        return FAST_PROG_XDP_HANDLE_PREPARE;
    else if (...)
        return FAST_PROG_XDP_HANDLE_REQUEST;
    else if (...)
        return FAST_PROG_XDP_HANDLE_PREPAREOK;
    else if (...)
        return FAST_PROG_XDP_HANDLE_PREPAREOK;
    return -1;
}
```

The generated stub replaces this with a fresh unconstrained symbolic `int`:

```c
int result;
klee_make_symbolic(&result, sizeof result, "result");
return result;
```

Note: the vanilla `main.bc` declares `compute_message_type` as `extern` but
never links it, similar to the vanilla katran case. Both `electrode_refactored.bc`
and `electrode_stub.bc` link an implementation.

Results (no `--exit-on-error`):

| Version | Completed paths | Partial paths | Instructions | Wall time |
|---|---:|---:|---:|---:|
| Real `compute_message_type` (`electrode_refactored.bc`) | 135 | 0 | 18,257 | 35s |
| Stubbed `compute_message_type` (`electrode_stub.bc`) | 12 | 0 | 7,011 | 34s |

The stub reduces paths by 91% (135 → 12) and halves instructions. Wall time is
similar because the program is small and KLEE startup dominates. The real
function branches on ~8 symbolic payload bytes per message type across 4 type
checks, creating many forks. The stub collapses all of that into a single
symbolic return.

Caveat: the stub bound is fully unconstrained (`[0, 4294967295]`), while the
real function only returns `{0, 1, 2, -1}`. The stub is sound (it
over-approximates) but imprecise — downstream `bpf_tail_call` with an
out-of-range index will explore dead paths. Tightening the bound to
`result >= -1 && result <= 2` would be more precise.

## Takeaways

1. Stubs help when the target function is expensive in the way KLEE cares about:
   exponential symbolic branching or hard solver expressions.
2. A fixed concrete stub can be too weak for coverage. The jhash concrete stub
   is fast but misses one pool branch.
3. Even small helpers benefit from stubbing when they have internal branching
   that multiplies across call sites. `csum_fold_helper()` has only 16 paths
   per call, but across four call sites this drives total paths from 26K to 57K.
4. A fresh symbolic stub is safe when nothing downstream branches on the output.
   The `csum_fold_helper()` result is written to `ip->check` and never inspected
   again, so the unconstrained symbolic value has negligible solver cost.
5. Payload-matching classifiers like `compute_message_type()` are good stub
   targets: many byte comparisons on symbolic data create exponential forks.
6. Generated summaries need validation. Bounds must be checked against the real
   function contract, as shown by the CRC `<= 255` and electrode unbounded caveats.
7. All six experiments show the stub matching or outperforming the real
   implementation. The best targets are `bmc_hash_keys`, jhash-style hashing,
   `csum_fold_helper`, and `compute_message_type`.
