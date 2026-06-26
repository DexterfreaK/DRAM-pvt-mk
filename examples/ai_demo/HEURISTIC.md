# Triage heuristic — which segments to summarize vs leave to KLEE

## Goal

Predict, *before* running KLEE, which code regions are good candidates for
"replace with AI summary" so KLEE never explores them. Two axes:

1. **AI precision on this region** — will the abstract interpreter actually
   produce a useful invariant, or will it widen to TOP almost immediately?
2. **KLEE pain on this region** — would naive symbolic execution explode
   the path tree, or does it handle it fine?

The summarize set is the intersection: regions where *AI is precise* AND
*KLEE would suffer*. The other quadrants:

|                       | KLEE explodes (risk HIGH)   | KLEE fine (risk LOW) |
|-----------------------|-----------------------------|----------------------|
| AI precise (HIGH)     | **SUMMARIZE** — best win    | IGNORE — KLEE is faster than the assumes (cf. RESULTS.md) |
| AI imprecise (LOW)    | hard case — bigger domain or partial summary | IGNORE  |

## Computing AI precision

We don't have to *predict* the precision — we can read it directly from
Clam's per-block invariants. For each region (typically a loop), look at
the SSA values defined by the region:

- **Bounded** in the invariants — Clam derived `var ∈ [a, b]`. Counts as
  AI-precise on that variable.
- **TOP / absent** — Clam widened it to `[-∞, +∞]`. AI-imprecise.

Region score:
```
ai_score(region) = |{v ∈ defs(region) : bounded(v)}| / |defs(region)|
```

This is the cleanest signal because it's measured, not estimated. It also
already accounts for non-linear ops: in `fnv_hash`, the `mul`/`xor` chain
on `hash` produces TOP in soct, so `bounded(hash) = false` and `hash`
correctly drags the score down.

A backup signal when invariants aren't available: count "AI-hostile"
opcodes in the region body (`mul`, `udiv`, `sdiv`, `urem`, `srem`, `xor`,
`and`, `or`, `shl`, `lshr`, `ashr`) vs "AI-friendly" ones (`add`, `sub`,
`icmp`, `phi` on integers, `select`). High hostile fraction ⇒ low precision
even before running Clam.

## Computing KLEE explosion risk

For each loop, two numbers from the IR + Clam:

- `bf` — branch factor inside the loop body (count of conditional branches
  + switch successor counts that depend on symbolic values; concrete
  branches don't fork).
- `tc` — trip count upper bound. Read from Clam's invariant on the loop
  counter. If unbounded, treat as ∞.

Risk is roughly `tc · log2(bf)` (entropy of the worst-case path tree),
clamped to a budget:
```
klee_risk(region) =
    if  bf <= 1                     -> LOW    (no branching, no explosion)
    elif tc unbounded                -> HIGH   (KLEE may not terminate)
    elif tc * log2(bf) > THRESHOLD   -> HIGH
    else                             -> LOW
```
Default `THRESHOLD = 8` (≈ 256 paths) — anything above that is when
solver-heavy summarization starts to win over enumeration.

A sharper variant adds the cost of *each* path's constraints: per-iteration
`load`/`store` count and per-iteration solver-relevant work. We start with
the simple `bf · tc` form and refine if needed.

## Decision policy

```
if  ai_score >= 0.5  and  klee_risk == HIGH:    SUMMARIZE
elif ai_score >= 0.5 and  klee_risk == LOW:     IGNORE       (matches our 165s>39s result)
elif ai_score <  0.5 and  klee_risk == HIGH:    IGNORE       (and emit a warning — fallback or pick a stronger domain)
else:                                           IGNORE
```

When SUMMARIZE wins, the bridge replaces the region body with:
- `klee_make_symbolic(...)` for each AI-precise output (bounded var).
- `klee_assume(bound)` for each invariant on those outputs.
- For AI-imprecise outputs (e.g. `hash` in fnv_hash), leave them as
  unconstrained `klee_make_symbolic`. KLEE will track them as fully
  symbolic — sound but loses information. This is the *partial*
  summarization that lets us still win when only some outputs are precise.

## What this predicts

- **Standalone fnv_hash with 256-byte fixed payload** —
  `ai_score(hash)=0`, `ai_score(key_len)=1`, `ai_score(off)=1` →
  region average 2/3. Loop body has 2 conditional branches, trip count
  ≤ 251 from Clam → `klee_risk = log2(2) * 251 = 251` ≫ 8 → HIGH.
  But empirically KLEE handles it in 39s with 503 paths. The heuristic
  *over*-predicts risk because the branches are correlated (terminator
  byte ⇒ exit, not 3-way fork per byte). Refinement: weigh by the number
  of distinct *unrelated* symbolic inputs feeding the branches.

- **bmc-cache rx_filter_main** — same loop body, but inside an XDP
  program with helper calls and map ops, plus an unbounded packet length.
  `tc` becomes effectively ∞ until the AI bound is applied. → HIGH risk,
  HIGH AI precision on `key_len/off` → SUMMARIZE wins.

So the prediction matches what we'd want to do in both cases. The fnv-hash
edge-case (heuristic says HIGH risk, reality says fine) is a known
limitation that the next iteration of the heuristic should address by
considering branch-input correlation.

## Implementation status

- `triage.py` (next deliverable) — reads `.ll` + `clam_soct.txt`, emits
  `*.triage.json` per the SCHEMA.md format with the heuristic-derived
  decision per region.
- `clam_bridge` extension (task #12) — consumes the JSON to emit only
  the assumes for SUMMARIZE/AUGMENT regions.
