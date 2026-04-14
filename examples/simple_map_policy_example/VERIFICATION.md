# policy-prune soundness verification on simple_map_policy_example

Differential KLEE testing of the `policy-prune` LLVM module pass. The goal
is to catch verdict flips (false positives / false negatives) introduced
by pruning — every spec is run twice (baseline without the pass, pruned
with the pass) and the two verdicts must match.

This example is small enough that the baseline KLEE run always terminates,
so we get true baseline-vs-pruned verdict comparisons on every spec.

## Test corpus

Five hand-designed spec variants in `policy_P*.json`, each targeting a
different VALID/INVALID outcome under KLEE's map-access-control semantics.

| Spec | Intent | Expected verdict |
|------|--------|------------------|
| `P1_all_allowed` | every map accessible, permissive helpers/packet | VALID |
| `P2_no_access_missing` | `no_access` omitted; code writes to it | INVALID |
| `P3_rw_downgraded` | `read_write` listed as Read only; code writes to it | INVALID |
| `P4_readonly_writeonly_flipped` | swapped R/W modes on unused directions | VALID |
| `P5_minimal` | only `read_write` listed; code touches other maps | INVALID |

Code under test (`main.c`): writes/reads `read_write`, writes `no_access`,
reads `read_only`. Four helper calls total.

## Results (after pass fix — see "Bugs found" below)

| Spec | Baseline | Pruned | Match | Baseline IR | Pruned IR |
|------|---------|--------|-------|-------------|-----------|
| policy_P1_all_allowed | VALID | VALID | YES | 5607 | 3805 |
| policy_P2_no_access_missing | INVALID | INVALID | YES | 5607 | 3805 |
| policy_P3_rw_downgraded | INVALID | INVALID | YES | 5607 | 3805 |
| policy_P4_readonly_writeonly_flipped | VALID | VALID | YES | 5607 | 3805 |
| policy_P5_minimal | INVALID | INVALID | YES | 5607 | 3805 |

Every pair matches. IR shrinks ~32% on this tiny example; on katran with
the fixed pass the shrinkage is ~17% (was ~33% with the buggy pass).

## Bugs found during verification

The first run of this harness caught two real soundness bugs in the pass:

### 1. False positive from stubbing helper implementations

**Symptom:** `P3_rw_downgraded` — baseline INVALID, pruned VALID.

**Root cause:** The pass's relevance analysis only propagated UPWARD
through the call graph (caller is relevant if any callee is relevant).
Helper implementations like `bpf_map_update_elem` (defined in
`libbpf-stubbed` as real function bodies, not extern decls) were
classified as irrelevant and stubbed to `ret undef`. But those
implementations *are* where KLEE's map-access tracking fires — stubbing
them erases the very violation-detection hook.

**Fix:** (a) treat every function whose NAME matches a spec helper as
directly relevant; (b) add a DOWNWARD transitive closure step — callees
of relevant functions are kept, so the helper bodies (and anything they
depend on) are never stubbed.

### 2. Null-deref from erasing referenced map globals

**Symptom:** `P2_no_access_missing` and `P5_minimal` — baseline INVALID,
pruned ERROR (`null page access` at `bpf_map_init_stub`).

**Root cause:** The pass eagerly erased any `struct.bpf_map_def` global
whose name was not in `spec.maps`, replacing uses with `undef`. But the
KLEE entry `main()` still contained `BPF_MAP_INIT(&no_access, ...)`,
which then dereferenced `undef`. More importantly, this erasure *hides*
the very map reference KLEE would have flagged as a violation.

**Fix:** Stop erasing map globals in the pass. Strip only
`@llvm.used`/`@llvm.compiler.used` so the subsequent `globaldce` pass
can drop globals that truly have zero remaining uses (after stubbing).

Both fixes are in `lifting_tools/llvm_policy_pass/policy_pass.cpp`
(search for "Soundness guard" and "Downward transitive closure").

## Reproduction

```bash
cd examples/simple_map_policy_example
./run_differential.sh            # ~2 minutes
cat differential_results.md
```

The harness copies each `policy_P*.json` to `constraints.json`, compiles
`main.c`, runs KLEE twice (without / with the pass) on the same spec,
and records the verdict pair.
