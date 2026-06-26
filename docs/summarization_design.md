# Function Summarization for Symbolic Execution — Design Doc (v1)

**Status:** DRAFT — pre-implementation alignment.
**Audience:** project team.
**Foundation:** KrakenGuard (NSDI '26, Patel et al.); the `ai_demo/`
known-bits analyzer (`hash_abstract_interp.py`); the `policy_pass`
soundness invariants. Complements `docs/cegar_design.md` — summarization
is an *orthogonal* speedup that can sit underneath CEGAR or stand alone.

---

## 0. TL;DR

Symbolic execution explodes inside *opaque deterministic sub-computations*
— hashes, checksums, classifiers — whose internal detail is irrelevant to
the policy being verified. We **summarize** each such function with abstract
interpretation, then have the symbolic executor (KLEE) **replace the call
with the summary** instead of stepping into the body. Two summary modes:

- **Mode A — bounded havoc:** replace output with a fresh symbolic value
  constrained to its abstract bound. Sound when the property cares only that
  the output is *in range* (e.g. checksums written to a packet field).
- **Mode B — uninterpreted function (memoized):** replace with a fresh
  symbolic value that is *the same for the same inputs*, plus its bound.
  Required when the property depends on determinism (e.g. a hash used as a
  consistent-hashing key: same flow → same backend).

The bound itself comes from the **known-bits ⊗ interval** domain, not the
interval domain alone (intervals are havoc'd at the first XOR/multiply —
see `ai_demo/clam_int.txt`).

---

## 1. Why summarize

A hash/checksum contributes to path explosion in two ways, *neither* of
which is the output range:

1. **Internal control flow** — per-byte loops and `break`s. In the FNV
   experiment (`ai_demo/RESULTS.md`) inlining the hash took KLEE from 503
   completed paths / 11k instructions to 77k instructions and 165 s.
2. **Query complexity** — the mixed bit-vector term for the hash output
   makes every downstream constraint enormous (constructs/query rose 4.5×).

Summarization removes both: the body is never executed, and the output
becomes a single fresh symbol (optionally one linear bound constraint).

The key property that makes this *cheap and lossless* for many functions:
the policy almost never depends on the function's exact output — only on
the output being *in range* and/or *deterministic*.

---

## 2. The two summary modes

### Mode A — bounded havoc
```
out := fresh_symbolic(width)
assume(out <= BOUND)          // BOUND from known-bits⊗interval; omit if ⊤
```
Sound when the property is invariant under any in-range value of `out`.
Each call gets an independent fresh symbol — determinism is **not**
preserved.

### Mode B — uninterpreted function (memoized)
```
key := canonical(inputs)            // hash of the symbolic input term(s)
if key in memo: out := memo[key]
else:           out := fresh_symbolic(width); assume(out <= BOUND)
                memo[key] := out
```
Same inputs → same symbol, so `f(x) == f(x)` holds, while `f(x)` is
otherwise unconstrained. This is a quantifier-free encoding of an
uninterpreted function via memoization (no UF theory needed in STP).

**Choosing the mode** — decision rule:

| Question about the call | Mode |
|---|---|
| Output used only as a bounded index / written to a field, value irrelevant? | **A** |
| Property needs same-input → same-output (key, dedup, equality compare)? | **B** |
| Already an opaque helper to KLEE (`bpf_csum_diff`, `memcpy`)? | attach bound only |

When in doubt, **Mode B is strictly safer** than A (it adds the equality
constraints A omits) at the cost of the memo table. A wrong bound, or
Mode A where B was needed, is **unsound** (can miss real violations);
omitting the bound entirely is always sound but weaker.

---

## 3. Catalogue of candidates in this repo

| Function | File:line | Internals | Bound (known-bits⊗interval) | Mode | Consumer / why |
|---|---|---|---|---|---|
| `get_packet_hash` / `jhash` / `jhash_2words` | `katran/balancer_kern.h:32`, `katran/jhash.h` | rotate/xor/add mix | `⊤` raw; `[0,RING_SIZE)` after `% RING_SIZE` | **B** | `ch_rings` index; *same flow → same real* is the correctness property |
| `csum_fold_helper` / `ipv4_csum` | `katran/csum_helpers.h:29,47`; `fw/xdp_csum_kern.c:42`; `electrode/fast_kern.c:169` | unrolled fold loop | `[0, 0xFFFF]` (tight, 16-bit) | **A** | written to `iph->check`; policy doesn't verify checksum correctness |
| `compute_message_type` | `electrode/fast_kern.c:184` | payload byte-compare loop | small enum range (TBD — read body) | A or B | classifier; B if result compared across calls |
| `fnv_hash` | `ai_demo/fnv_hash.c` | xor/multiply loop | `⊤` raw; tight after table mask | B | reference / validation case |

Cut at the **outermost** boundary (`get_packet_hash`, not `jhash`) so one
summary collapses all nested mixing calls.

---

## 4. What a summarizer looks like

A summary is data the symbolic executor consumes — not code it runs.

### 4.1 Summary record (the artifact)
We **extend the existing `aisum.json` schema** (see `ai_demo/fnv_hash.aisum.json`)
rather than inventing a new one. Today each function entry carries
`side_effects` and per-region invariants with a `decision` (`augment` /
`ignore`). We add a function-level `"summary"` block that says *replace the
whole call*, alongside the region invariants that say *augment in place*:

```jsonc
{
  "name": "get_packet_hash",
  "side_effects": {                    // already in schema — drives soundness §5.3
    "calls_helpers": [], "writes_maps": [],
    "writes_memory_outof_region": [], "indirect_calls": false
  },
  "summary": {                         // NEW: call-replacement directive
    "mode":   "uf",                    // "havoc" | "uf"
    "inputs": ["pckt->flow.src", "pckt->flow.ports", "pckt->flow.srcv6"],
    "output": { "width": 32 },
    "bound":  { "known_zero_mask": "0x0", "max": 4294967295 },  // from known-bits⊗interval
    "preserve_consumers": ["ch_rings", "reals"]                 // must NOT be pruned
  }
}
```
`side_effects.writes_memory_outof_region` is exactly the `writes` set that
soundness obligation 3 (§5) must reproduce; `inputs` is the `reads` set for
obligation 2. A
function may have *both* a `summary` (replace the call) and `regions`
(augment if not replaced) — the apply pass prefers `summary` when present.

### 4.2 Pipeline
```
hash_fn.c
  → clang/opt              → hash_fn.bc
  → known-bits⊗interval    → bound  +  effect (reads/writes)   [analyzer]
  → mode classifier        → A or B  (decision rule §2)         [policy-aware]
  → emit summary record    → hash_fn.aisum.json                 [artifact]
  → summary-apply LLVM pass→ rewrites call sites in the program [instrumentation]
        Mode A:  call → klee_make_symbolic(out); klee_assume(out<=BOUND)
        Mode B:  call → __summary_uf("get_packet_hash", inputs, out)
  → KLEE                    → verifies against the summarized program
```

### 4.3 The runtime stub the symbolic executor calls (Mode B)
A tiny C runtime, linked into the harness, implements the memoized UF.
KLEE executes *this* instead of the real function:
```c
// summary_runtime.c  — UF via memoization, quantifier-free
#define MEMO_MAX 64
static struct { uint64_t key; uint32_t out; int used; } memo[MEMO_MAX];

uint32_t __summary_uf(const char *name, uint64_t input_digest, uint32_t bound) {
    for (int i = 0; i < MEMO_MAX && memo[i].used; i++)
        if (memo[i].key == input_digest) return memo[i].out;   // same in → same out

    uint32_t out;
    klee_make_symbolic(&out, sizeof out, name);                // fresh symbol
    klee_assume(out <= bound);                                 // §0 bound
    for (int i = 0; i < MEMO_MAX; i++)
        if (!memo[i].used) { memo[i] = (typeof(memo[i])){input_digest, out, 1}; break; }
    return out;
}
```
`input_digest` is a *concrete-or-symbolic-identity* token for the inputs
(see §6 caveat). Mode A is the same minus the memo lookup/store.

### 4.4 Analyzer core (already prototyped)
`ai_demo/hash_abstract_interp.py` computes `bound` in the known-bits ⊗
interval domain. The summarizer wraps it: run the analyzer on the
function's return value, read off `(known_zero_mask, max)`, write the
record. The reduced product (to fix the loose `maglev % prime` case) is
the one analyzer upgrade still pending.

---

## 5. Soundness obligations

Summarization is `policy_pass`-style pruning with a richer replacement, so
the documented pruning invariants carry over verbatim:

1. **Keep the consumer.** The `bpf_map_lookup_elem(&ch_rings, &key)` and
   the map globals must survive — only the mixing between source and
   consumer is removed.
2. **Keep the symbolic source.** The packet-field reads the summary
   depends on (`pckt->flow.*`) stay symbolic; they are the UF inputs.
3. **Model side effects.** If the summarized function writes memory
   (`writes` non-empty), the summary must reproduce those writes, or the
   verdict is unsound.
4. **Bound must be sound.** A known-bits⊗interval bound is an
   over-approximation by construction; never tighten it heuristically.
   Omitting the bound is safe; a wrong bound is not.
5. **Mode B when in doubt.** Mode A on a determinism-dependent property
   silently drops real violations. B → A is an optimization to justify
   per-call, not a default.

A summary that violates 1–4 can *flip a KLEE verdict* — the same failure
mode documented for the policy-prune pass.

---

## 6. Open problems / caveats

- **Input identity for Mode B.** `input_digest` must equal iff the input
  *terms* are equal. Hashing concrete bytes is wrong when inputs are
  symbolic. Options: (a) intern the symbolic expression pointers, (b) let
  KLEE compare the input expressions structurally, (c) restrict Mode B to
  inputs that are themselves named symbolics. Needs a KLEE-side hook.
- **Memo capacity.** A fixed table caps distinct inputs; overflow must
  fall back to Mode A (sound) or fail loudly, never silently reuse.
- **Reduced product not yet implemented** → loose bounds for non-power-of-two
  moduli (maglev rings). Tracked against the analyzer.
- **Side-effecting summaries** (functions that mutate maps/packet) are out
  of scope for v1; v1 targets pure-output functions only.
- **Interaction with CEGAR** (`docs/cegar_design.md`): summaries shrink the
  feasibility-check trace; a spurious counterexample caused by an
  over-loose summary should trigger refinement (un-summarize that call),
  not a false verdict.

---

## 7. Suggested v1 scope

1. Implement the **memoized-UF runtime** (§4.3) + Mode-A variant.
2. Emit `aisum.json` for `get_packet_hash` (Mode B) and the three
   `csum_fold_helper` copies (Mode A).
3. Summary-apply LLVM pass that rewrites those call sites.
4. Differential KLEE run (summarized vs inlined) on katran to measure
   path/instruction/wall reduction *and confirm identical verdicts* on the
   existing policy set — the soundness regression gate.
5. Defer: reduced-product analyzer, symbolic input-identity, side effects.
