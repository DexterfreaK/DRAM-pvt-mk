# AI demo — empirical results so far

End-to-end pipeline now works:

```
fnv_hash.c
  → clang-13           → fnv_hash.bc
  → opt-13 mem2reg/... → fnv_hash.opt.bc
  → clam (soct + opt)  → fnv_hash.crab.bc      (verifier.assume / llvm.assume + !clam)
  → clam_bridge pass   → fnv_hash.bridged.bc   (klee_assume(i64))
  → llvm-link-14       → instrumented.bc       (linked with fnv_harness.bc)
  → klee               → verdict / paths / wall
```

## Numbers (TIMEOUT=120s, search=dfs, payload size = 256, len ≤ 256)

| Variant                 | klee_assume calls | completed paths | instructions | wall   | constructs/query |
|-------------------------|-------------------|-----------------|--------------|--------|------------------|
| baseline                | 1 (harness only)  | 503             | 11 091       | 39 s   |  57              |
| instrumented (block)    | 66 (1 + 65 clam)  | 464 + 495 part. | 77 673       | 165 s  | 256              |
| instrumented (loop-hdr) |  9 (1 + 8 clam)   | 495 (partial)   | 40 172       | 146 s  | (large)          |

## Take-aways

1. The bridge works: 65 of 66 Clam-emitted `llvm.assume` calls were rewritten
   into `klee_assume(i64)`; the trivial `assume(true)` was dropped.

2. On this tightly-bounded harness, naively materialising every Clam invariant
   makes KLEE *slower*. Constructs-per-query rises 4.5× because each assume
   adds a linear constraint, and most of these are facts KLEE could already
   derive cheaply (e.g. `add - idxprom = 1`).

3. Loop-header-only assumes are leaner (8 vs 65) but still net-negative on
   this micro-benchmark — the loop runs at most 251 times, KLEE already prunes
   well, and adding any solver-visible constraint per iteration costs more
   than it saves.

4. The win for AI annotations is in the regime where path explosion is the
   actual bottleneck (bmc-cache: 7m54s / 1 505 paths in `rx_filter_main`).
   Standalone fnv_hash with a 256-byte fixed payload is *not* that regime.

## Implication for the design

We can't blindly forward every Crab invariant. Need a **decision policy** that
selects which invariants are KLEE-actionable:

- Bounds that *prune branches* (e.g. `key_len ≤ 251` discharges the post-cond)
  are valuable.
- Equalities between intermediate SSA values (`add - idxprom = 1`) are not —
  KLEE derives them for free during execution.
- Per-block redundant restatement of the same loop invariant burns solver time.

This is what task #9 (JSON schema with summarize/augment/ignore decisions)
is for: encode the policy outside the C++ pass.
