# AI summary JSON schema (draft)

Single file per analysed bitcode module. Consumed by the `clam_bridge` pass
(future: an enriched bridge that filters by decision rather than blindly
forwarding every Clam assume).

```jsonc
{
  "module": "fnv_hash.opt.bc",
  "tool": { "name": "clam", "version": "dev13", "domain": "soct" },

  "functions": [
    {
      "name": "fnv_hash",

      // Coarse-grained side-effect summary. Used by the decision policy:
      // a region that touches maps / helpers / non-local memory cannot be
      // SUMMARIZED soundly, only AUGMENTED.
      "side_effects": {
        "calls_helpers":      [],          // e.g. ["bpf_map_lookup_elem"]
        "writes_maps":        [],          // map names touched by store
        "writes_memory_outof_region": ["out_hash"],  // pointer args written
        "indirect_calls":     false
      },

      "regions": [
        {
          "region_id": "fnv_hash::for.cond",
          "kind":      "loop_header",      // loop_header | basic_block | loop_body
          "decision":  "augment",          // summarize | augment | ignore
          "rationale": "Bounded loop; emit only widened bounds at header.",

          // Invariants curated for KLEE. Each entry has the linear
          // constraint in canonical form plus a rank used to pick the
          // top-K when the budget is tight.
          "invariants": [
            { "expr": "key_len.0 <= 250", "kind": "upper_bound",  "rank": 1.0 },
            { "expr": "off.0     <= 250", "kind": "upper_bound",  "rank": 1.0 },
            { "expr": "key_len.0 == off.0", "kind": "equality",   "rank": 0.8 },
            { "expr": "key_len.0 >= 0",   "kind": "lower_bound",  "rank": 0.2 }
          ]
        },

        {
          "region_id": "fnv_hash::for.body",
          "kind":      "basic_block",
          "decision":  "ignore",
          "rationale": "All facts here are SSA-locally derivable; emitting them adds solver work without pruning paths (see RESULTS.md)."
        },

        {
          "region_id": "fnv_hash::for.end",
          "kind":      "basic_block",
          "decision":  "augment",
          "rationale": "Post-condition discharges klee_assert(key_len <= 251).",
          "invariants": [
            { "expr": "key_len.0 <= 251", "kind": "upper_bound", "rank": 1.0 }
          ]
        }
      ]
    }
  ]
}
```

## Field semantics

- **decision**
  - `summarize` — replace the region body with `klee_make_symbolic(outputs)`
    plus the listed invariants. Sound only when `side_effects` is empty.
    *Not yet implemented.*
  - `augment` — leave the region body intact; emit `klee_assume(...)` calls
    for the listed invariants at the region entry. Always sound (assumes are
    facts proved by Crab). What the bridge currently does (modulo filtering).
  - `ignore` — emit nothing; let KLEE explore the region unchanged. Used
    when the empirical cost of the assumes exceeds the benefit.

- **kind**
  - `loop_header` — first block of a loop; cheapest place to put the widened
    bound, fires once per iteration.
  - `basic_block` — any other block; usually `ignore` unless the block
    discharges a post-condition.
  - `loop_body` — non-header inside a loop; almost always `ignore`.

- **invariants[].rank** — 0..1 priority for budget-bounded selection. Bounds
  derived by widening rank above equalities derivable by SSA-local
  propagation.

## Decision policy (default)

```
for region in function.regions:
  if region.side_effects.touches_maps_or_helpers:
    region.decision = "augment"   # never summarize, can never be sound
  elif region.kind == "loop_header":
    region.decision = "augment"
    region.invariants = top_k(crab_invariants_for_region, k=3,
                              prefer_kinds=["upper_bound", "equality"])
  elif region.kind == "basic_block" and discharges_postcondition(region):
    region.decision = "augment"
    region.invariants = postcondition_relevant(crab_invariants_for_region)
  else:
    region.decision = "ignore"
```

## Producer / consumer

- **Producer**: future tool `clam_summary_emitter` (small wrapper around
  Clam's analysis API). Takes `module.bc` + side-effect analysis output,
  emits `module.aisum.json`.

- **Consumer**: extended `clam_bridge` pass. New flag
  `--clam-bridge-spec=path/to/aisum.json`. If present, only emits assumes
  for regions with `decision == augment` and only the listed invariants
  (matching by `region_id`). Without the flag, falls back to current
  behaviour: forward every `!clam`-tagged assume.
