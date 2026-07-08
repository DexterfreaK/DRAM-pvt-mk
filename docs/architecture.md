# DRACO — Implementation Architecture

**Status:** current implementation  
**Scope:** path-explosion detection, stub generation, KLEE integration  
**Foundation:** KrakenGuard (NSDI '26) — trusted user-space eBPF policy verifier

---

## 1. System Overview

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  USER PROVIDES                                                       │
  │                                                                      │
  │   program.c                    source_map.json                      │
  │   (harness + implementations                                         │
  │    in one file, or split —                                           │
  │    both work)                                                        │
  │        │                            │                                │
  │        ▼                            │                                │
  │   clang -O0 -emit-llvm -c           │                                │
  │   [llvm-link if split] ──► program.bc                               │
  │        │                            │                                │
  │        └────────────────────────────┘           (user builds once)  │
  └──────────────────────────────────────────────────────────────────────┘
                              │
                              │
          ┌───────────────────┴───────────────────┐
          │                                       │
          ▼                                       ▼
  ┌───────────────────┐               ┌─────────────────────────────────┐
  │  PASS 1           │               │  STATIC TRIAGE (offline)        │
  │  Runtime detector │               │                                  │
  │                   │               │  detect.py harness.bc            │
  │  klee             │               │                                  │
  │  --function-      │               │  → ranked candidates:            │
  │    budget=N       │               │    hash_payload  A  score=96     │
  │                   │               │    fold_csum     D  score=32     │
  │  counts forks per │               │    classify_type E  score=12     │
  │  call-stack frame │               └──────────────┬──────────────────┘
  │                   │                              │
  │  first F to hit N:│                              │
  │   → halt KLEE     │                              │
  │   → needs_stub.txt│                              │
  │                   │                              │
  │  ~200ms, 18 paths │                              │
  └────────┬──────────┘                              │
           │                                         │
           │  culprit names                          │  ranked candidates
           └──────────────┬──────────────────────────┘
                          │
                          ▼
  ┌───────────────────────────────────────────────────────────────────────┐
  │  PASS 2  —  auto_stub.py                                              │
  │                                                                        │
  │  Phase 1: run KLEE baseline                                            │
  │           TIMEOUT or paths > threshold? → proceed                     │
  │           SAFE + paths ≤ threshold?     → done, no stub needed        │
  │                                                                        │
  │  Phase 2: for each candidate:                                          │
  │                                                                        │
  │    source_map.json                                                     │
  │     func → source.c + [-D defines] + [preconditions]                 │
  │         │                                                              │
  │         ▼                                                              │
  │    summarize.py  (3-stage pipeline)                                    │
  │    ├─ Stage 2: Clam soct → side effects + bounds                      │
  │    ├─ Stage 3: regex on source → return bound                          │
  │    └─ stub_emitter → func_stub.c                                       │
  │                                                                        │
  │    clang → stub.bc                                                     │
  │    llvm-link --override → variant.bc                                   │
  │    KLEE on variant:                                                    │
  │      SAFE + paths↓                →  ACCEPT ✓                         │
  │      baseline SAFE  + stub UNSAFE →  REJECT (over-approx artifacts)   │
  │      baseline TIMEOUT + stub UNSAFE → ACCEPT + warn (possible bug)    │
  │      paths↑                       →  REJECT (no improvement)          │
  └────────────────────────────────────────────────────────────────────────┘
                          │
                          ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │  OUTPUT                                                              │
  │  variant_fold_csum.bc  — verified BC with tight stub linked in      │
  │  fold_csum_stub.c      — generated stub (auditable)                 │
  │  klee-last/needs_stub.txt  — culprit list from Pass 1               │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## 2. User Inputs

Three things are needed before running the pipeline:

**① Harness C file** — the program under verification with symbolic inputs and policy assertions:
```
klee_make_symbolic(&payload, sizeof payload, "payload")   // symbolic input
...
klee_assert(backend < NUM_BACKENDS)                        // policy to verify
```

**② The expensive implementations** — the real functions that cause path explosion. These can live in the same file as the harness or in separate files — it doesn't matter, since the pipeline works on the linked `.bc`. The user never writes stubs manually.

**③ `source_map.json`** — tells the pipeline where to find each function's source and how to compile it. Described in §3.

**Build step** (user runs once):
```
clang -O0 -emit-llvm -c harness.c     → harness.bc
clang -O0 -emit-llvm -c expensive.c   → expensive.bc
llvm-link harness.bc expensive.bc      → real.bc
```

Then the entire pipeline is one command:
```
python3 auto_stub.py --bc real.bc --source-map source_map.json
```

---

## 3. `source_map.json`

The pipeline knows which function is explosive (from `detect.py` or `--function-budget`) but not where its source lives or how it was compiled. The BC has constants baked in; `summarize.py` needs to recompile the source to run Clam analysis. `source_map.json` bridges that gap.

**Format:**
```json
{
  "function_name": {
    "source":         "relative/path/to/source.c",
    "defines":        ["NAME=VALUE", ...],
    "preconditions":  [{"param": "name", "op": ">=", "value": N}]
  }
}
```

| Field | Required | Purpose |
|-------|----------|---------|
| `source` | yes | C file containing the function definition |
| `defines` | no | `-D` flags the original build used (e.g. table sizes, constants) |
| `preconditions` | no | Caller-known parameter bounds — enables relational side-effect bounds (see §6) |

**Example:**
```json
{
  "hash_payload": {
    "source": "synth_expensive.c",
    "defines": ["NUM_BACKENDS=16", "KEY_MAXLEN=8"],
    "preconditions": [{"param": "maxlen", "op": ">=", "value": 1}]
  },
  "fold_csum": {
    "source": "synth_expensive.c",
    "defines": []
  }
}
```

**Why `defines`?** The BC has `16` baked in wherever `NUM_BACKENDS` was used. But to recompile `synth_expensive.c` for Clam analysis, clang needs `-DNUM_BACKENDS=16` or the file won't compile.

**Why `preconditions`?** When a parameter is always positive in practice (e.g. `maxlen` is always `KEY_MAXLEN=8`) but Clam can't prove it from the function alone, the relational bound `*out_key_len ≤ maxlen` can't be derived. Adding `maxlen>=1` injects `__builtin_assume(maxlen >= 1)` before Clam runs, pruning the infeasible `maxlen ≤ 0` path and making the octagon join tight enough to prove the bound. See §6 for detail.

---

## 4. Path Explosion — What We're Solving

A symbolic `payload` buffer causes KLEE to fork on every byte comparison:

```
hash_payload(symbolic key, maxlen=8):
  iteration 0: key[0] == '\0'?  fork → 2 paths
  iteration 1: key[1] == '\0'?  fork → 4 paths
  ...
  iteration 7: key[7] == '\0'?  fork → 256 paths
```

Each path is a separate solver query. At `KEY_MAXLEN=8` this is manageable, but real programs use larger keys, nested lookups, or multi-field classifiers — path counts reach tens of thousands and KLEE hangs.

**Three explosion patterns seen in practice:**

| Type | Example | Paths |
|------|---------|-------|
| Byte loop | `bmc_hash_keys` (12-byte key) | 2^12 = 4096 |
| Map lookup chain | `katran do_gather` | solver cost (2 paths, but Z3 hangs) |
| Flat byte classifier | `compute_message_type` (30 comparisons) | ~30 sequential forks |

---

## 5. Stage 1 — Static Detector (`detect.py`)

Disassembles the `.bc` to LLVM IR text, pattern-matches per function body.

**Four axes:**

| Axis | Trigger | Catches |
|------|---------|---------|
| A | loop + `load i8` + ≥2 `icmp`+`br` | byte-level hash loops |
| C | loop + `bpf_map_lookup_elem` | chained map lookups |
| D | loop + `icmp`+`br`, no byte load | csum-style fold loops |
| E | no loop + `load i8` + ≥5 `icmp eq`+`br i1` | flat header classifiers |

**Key IR signatures:**
```
Axis A:  for.body: { load i8 ... icmp ... br i1 ... } !llvm.loop
Axis E:  load i8 → zext i8 to i32 → icmp eq i32 %val, 80 → br i1
         (clang -O0 promotes i8 → i32 before comparison)
```

**Loop detection note:** `_has_loop()` checks `!llvm.loop` metadata and block names like `for.cond`, `while.body`. It deliberately ignores `phi` nodes — ternary expressions (`cond ? a : b`) also produce phi nodes at their join point and would cause false positives.

**Example output:**
```
$ python3 detect.py synth_real.bc

FUNCTION          AXIS  SCORE  DETAIL
hash_payload       A      96   loop+byte-load, est_loop_bound=32, branch_pairs=2
fold_csum          D      32   loop+branch, est_paths_per_call=2^4
classify_type      E      12   flat byte classifier, icmp_eq=12, byte_cmp_pairs=12
```

Score determines stub priority — higher score gets tried first.

---

## 6. Stage 2 — Side-Effect Extractor (`ir_analyzer.py`)

Finds what the function writes through pointer parameters, and bounds those writes.

**Process:**
```
source.c  →  clang -O1  →  func.bc  →  opt -mem2reg  →  func.opt.bc
                                                              │
                                                    clam --crab-dom=soct
                                                    --crab-print-invariants
                                                              │
                                                    invariants at loop exit
```

**What Clam produces (without precondition):**
```
for.end:
  INVARIANTS: { -i.0 <= 0               →  i.0 ≥ 0
                i.0 <= 4294967296        →  i.0 ≤ 2^32  (useless)
                -maxlen+i.0 <= 0 }       →  i.0 ≤ maxlen  ← exists but at join
                                                              only if path 3
                                                              (maxlen≤0) is pruned
```

**With `preconditions: [maxlen >= 1]` injected:**

`ir_analyzer.py` writes a modified source file with `__builtin_assume(maxlen >= 1)` at the function entry. This compiles to `@llvm.assume` in LLVM IR, which Clam treats as a hard constraint. The `maxlen ≤ 0` path becomes unreachable, and the octagon join at `for.end` can now prove:

```
-maxlen+i.0 <= 0   →   i.0 ≤ maxlen   ✓  (relational bound)
```

**Without precondition:** `out_key_len ∈ [0, 4294967296]` → stub emits `klee_assume(se <= 4294967296)` (useless)  
**With precondition:** `out_key_len ∈ [0, maxlen]` → stub emits `klee_assume(se >= 0 && se <= maxlen)` (tight)

**Limitation:** Clam's octagon domain cannot prove relational bounds that cross function calls or depend on aliased memory. It handles loop counters well; it cannot handle XOR/multiply outputs (that's Stage 3's job).

---

## 7. Stage 3 — Return Bound (`hash_bounds.py`)

Reads the source text and finds the final reduction on the return value.

**Two patterns recognized:**

```
return h % NUM_BACKENDS;      →  mod_type=urem    mod_val=16  → result ∈ [0, 15]
return (uint16_t)~csum;       →  mod_type=and_mask mod_val=65535 → result ∈ [0, 65535]
return h & (N - 1);           →  mod_type=and_mask mod_val=N-1
```

**What it misses:**
```
// Multiple return statements with enum values — no modular reduction
if (...) return TYPE_PREPARE;   // 0
if (...) return TYPE_REQUEST;   // 1
return TYPE_UNKNOWN;            // -1
→  mod_type=unbounded → no klee_assume generated → stub is unconstrained
```

**Stage 3 output for each function:**
```
hash_payload:   and_mask  mod_val=15    → result ∈ [0, 15]
fold_csum:      and_mask  mod_val=65535 → result ∈ [0, 65535]
classify_type:  unbounded mod_val=0     → result ∈ [0, 2^32-1]  ← problem
```

---

## 8. Stub Emitter (`stub_emitter.py`)

Combines Stage 2 + Stage 3 output into a tight KLEE stub.

**Generated stub — `hash_payload` (with precondition):**
```c
uint32_t hash_payload(const char *key, int maxlen, int *out_key_len)
{
    (void)key; (void)maxlen;

    /* Stage 2: relational side effect */
    int out_key_len_se;
    klee_make_symbolic(&out_key_len_se, sizeof out_key_len_se, "out_key_len");
    klee_assume(out_key_len_se >= 0 && out_key_len_se <= maxlen);  // ← tight
    *out_key_len = out_key_len_se;

    /* Stage 3: return ∈ [0, 15] */
    uint32_t result;
    klee_make_symbolic(&result, sizeof result, "result");
    klee_assume(result <= 15);
    return result;
}
```

**Generated stub — `classify_type` (unbounded — Stage 3 missed the pattern):**
```c
int classify_type(const char *p, int len)
{
    (void)p; (void)len;
    int result;
    klee_make_symbolic(&result, sizeof result, "result");
    // no klee_assume — result can be any int
    return result;
}
```

This unconstrained stub lets KLEE explore `type = 2147483647` — the real function never returns that, so downstream `klee_assert(type <= TYPE_ACK)` fires. **REJECT** (false positive from over-approximation).

**Rough stub (no klee_assume at all) vs tight stub:**
```
rough stub:  klee_make_symbolic(&r, ...)          → UNSAFE (P1/P2/P3 fire)
tight stub:  klee_make_symbolic + klee_assume(r <= 15) → SAFE
```

---

## 9. Strategy B — Runtime Detector (`--function-budget`)

Added to KLEE's `Executor`. Counts forks per function on the live call stack.

**Behaviour:**
```
klee --function-budget=10 harness.bc

→ KLEE runs normally
→ fold_csum forks for the 11th time
→ klee_warning: "fold_csum exceeded 10 forks; halting"
→ haltExecution = true  (existing KLEE field)
→ KLEE finishes current instruction, exits main loop cleanly
→ ~Executor() writes klee-last/needs_stub.txt
```

**`klee-last/needs_stub.txt`:**
```
# Functions that exceeded per-function fork budget (--function-budget=10)
# Pass each to lifting_tools/summarizer/summarize.py to generate tight stubs
fold_csum
```

**Why halt instead of continuing with a rough stub?**  
Original design injected an unconstrained symbolic return and continued the same KLEE run. For `bmc_hash_keys` (called once, 499 in-flight states), eviction killed all states — KLEE ran for 35s thrashing on nothing. Simplified design: detect + halt. Pass 2 starts a clean new KLEE process on the stub BC. 35s → 200ms.

**Limitation:** only detects non-inline functions. If `hash_payload` was `__always_inline`, all its forks would be attributed to the caller's frame.

---

## 10. Strategy A — Auto-Stub Loop (`auto_stub.py`)

```
Phase 0 — Static triage
  detect.py → ranked candidates [hash_payload=96, fold_csum=32, classify_type=12]

Phase 1 — Baseline KLEE
  klee harness.bc --max-time=T
  → SAFE + paths ≤ threshold:  stop (no stub needed)
  → TIMEOUT or paths > threshold:  proceed to Phase 2

Phase 2 — Stub injection (per candidate, in score order)
  for each candidate:
    source_map.json → source.c + defines + preconditions
    summarize.py    → func_stub.c         (Stage 2 + Stage 3)
    clang           → func_stub.bc
    llvm-link --override func_stub.bc harness.bc → variant.bc
    klee variant.bc → verdict + path count

  Acceptance:
    baseline SAFE + stub UNSAFE?   → REJECT  (maybe stub over-approx introduced artifacts)
    baseline TIMEOUT + stub UNSAFE → ACCEPT + warn  (may be a real bug)
    paths ≥ baseline?              → REJECT  (no improvement)
    SAFE + paths < baseline?       → ACCEPT  ✓
```

**Acceptance is a last-resort check, applied in order:**
1. Safety gate: did the stub introduce new assertion failures?
2. Progress gate: did the stub actually reduce work?
3. Only if both pass: ACCEPT

**Example run output:**
```
[auto_stub] Phase 1 — Baseline: verdict=SAFE paths=48 time=0.3s

[auto_stub] Phase 2
  [1] hash_payload (axis=A)
       stub(hash_payload)  verdict=SAFE   paths=20  → ACCEPT: 58% reduction
  [2] fold_csum (axis=D)
       stub(fold_csum)     verdict=SAFE   paths=28  → ACCEPT: 41% reduction
  [3] classify_type (axis=E)
       stub(classify_type) verdict=UNSAFE paths=65  → REJECT: baseline was SAFE, stub introduced artifacts

Best: hash_payload  48→20 paths (58% reduction)
Output: /tmp/synth_autostub/variant_hash_payload.bc
```

---

## 11. Two-Pass CEGAR Loop

```
┌─ Pass 1 ─────────────────────────────────────────────────────────────┐
│  klee --function-budget=10 harness.bc                                 │
│                                                                        │
│  fold_csum hits 11 forks → haltExecution                             │
│  klee-last/needs_stub.txt: [fold_csum]                               │
│  elapsed: ~200ms                                                       │
└────────────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─ Pass 2 ─────────────────────────────────────────────────────────────┐
│  python3 auto_stub.py --bc harness.bc --source-map source_map.json   │
│                                                                        │
│  detect.py  → hash_payload(A=96), fold_csum(D=32), classify_type(E=12)│
│  baseline   → 48 paths, SAFE                                          │
│                                                                        │
│  hash_payload stub:                                                    │
│    Stage 2: precondition maxlen>=1 → out_key_len ∈ [0, maxlen]       │
│    Stage 3: % NUM_BACKENDS → result ∈ [0, 15]                        │
│    klee variant → 20 paths, SAFE → ACCEPT                            │
│                                                                        │
│  fold_csum stub:                                                       │
│    Stage 2: no side effects                                            │
│    Stage 3: (uint16_t) cast → result ∈ [0, 65535]                    │
│    klee variant → 28 paths, SAFE → ACCEPT                            │
│                                                                        │
│  classify_type stub:                                                   │
│    Stage 3: unbounded (enum returns, no reduction)                    │
│    klee variant → 65 paths, UNSAFE → REJECT                          │
└────────────────────────────────────────────────────────────────────────┘
              │
              ▼
        variant_hash_payload.bc  (verified, 20 paths)
```

---

## 12. Stub Soundness — Three Conditions

| Condition | What it means | How guaranteed |
|-----------|--------------|----------------|
| **S1** Return over-approximation | stub return range ⊇ real return range | Stage 3 finds `% N` or `& mask`; unbounded is also sound (just weak) |
| **S2** Side-effect completeness | all `*out_param` writes modeled + bounded | Stage 2 Clam zones; preconditions enable relational bounds |
| **S3** No new path explosion | `paths_stub < paths_baseline` | Measured empirically; auto-rejected if violated |

**S1 failure** (`classify_type`): Stage 3 returns unbounded — stub returns any int. Downstream branches on all possible int values → UNSAFE, REJECT.

**S2 failure** (without precondition): Clam proves `out_key_len ∈ [0, 2^32]` (path 3: maxlen≤0 makes this unsound tighter). Stub allows negative values → P3 fires.

**S2 fix** (with precondition): `__builtin_assume(maxlen >= 1)` prunes path 3. Clam proves `out_key_len ∈ [0, maxlen]`. Stub tight. SAFE.

---

## 13. Synth Test — Reference Example

```
examples/synth_test/
  synth_common.h          shared types (NUM_BACKENDS=16, KEY_MAXLEN=8, TYPE_*)
  synth_expensive.c       three explosive functions:
                            classify_type → Axis E (12 forks, flat classifier)
                            hash_payload  → Axis A (2^8 paths, byte loop)
                            fold_csum     → Axis D (2^4 paths, conditional loop)
  synth_stubs.c           hand-written tight stubs (ground truth for comparison)
  synth_rough_stubs.c     unconstrained stubs — shows false positive behavior
  synth_main.c            harness: symbolic payload → classify → hash → fold
                            + policy assertions P1/P2/P3
  source_map.json         maps each function to source + defines + preconditions
  Makefile                builds synth_real.bc / synth_tight.bc / synth_rough.bc
```

**Policy assertions (in `synth_main.c`):**
```
P1: klee_assert(type >= -1 && type <= 2)     // classify_type output range
P2: klee_assert(backend < NUM_BACKENDS)      // hash stays in table bounds
P3: klee_assert(key_len >= 0 && key_len <= maxlen)  // hash side effect
```

**KLEE results across all three BC variants:**

| BC | time | paths | P1 | P2 | P3 | verdict |
|----|------|-------|----|----|-----|---------|
| `synth_real.bc` | 0.4s | 48 | ✓ | ✓ | ✓ | SAFE |
| `synth_tight.bc` | 0.3s | 5 | ✓ | ✓ | ✓ | SAFE |
| `synth_rough.bc` | 0.2s | 5 | ✗ | ✗ | ✗ | UNSAFE |
| `synth_real.bc --function-budget=10` | 0.2s | 18+halt | - | - | - | fold_csum detected |

**Why rough stubs produce false positives:**
```
classify_type rough stub → returns 2147483647  → P1: assert(type <= 2) FAILS
hash_payload rough stub  → returns 0xDEADBEEF  → P2: assert(idx < 16) FAILS
hash_payload rough stub  → sets key_len = -5   → P3: assert(klen >= 0) FAILS
```
None of these values are reachable in the real program. They are artifacts of the unconstrained symbolic return — over-approximation introducing paths that don't exist.

---

## 14. File Map

```
lifting_tools/summarizer/
  detect.py        Stage 1 — static IR explosion detector (4 axes A/C/D/E)
  ir_analyzer.py   Stage 2 — Clam soct side-effect extractor + relational bounds
  hash_bounds.py   Stage 3 — return bound (urem / and_mask patterns)
  stub_emitter.py  Stage 2+3 → tight stub .c writer
  summarize.py     Orchestrates Stages 2+3 for one named function
  auto_stub.py     Strategy A: detect → stub → link → verify loop

klee/lib/Core/
  Executor.h       + funcForkCount, needsStubFuncs fields
  Executor.cpp     + --function-budget flag, fork hook, writeNeedsStubLog()

examples/synth_test/          reference example (see §13)
examples/bmc-cache/source_map.json
examples/katran/source_map.json
examples/electrode/source_map.json
```
