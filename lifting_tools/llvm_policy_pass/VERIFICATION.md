# policy-prune verification on examples/katran

Differential testing per plan §Verification. All runs use the source-level
`verify-constraint-access` KLEE invocation (same flags as `examples/Makefile`
after this change's `policy-prune-bc` hook). KLEE budget: `-max-time=…s
-watchdog`. Bitcode is `examples/katran/katran.bc` from the existing build.

## IR shrinkage (no KLEE)

| spec                            | lifted-IR lines | Δ      | functions stubbed | functions kept |
|---------------------------------|----------------:|-------:|-------------------:|---------------:|
| baseline (no pass)              |          18,538 |      — |                   — |              — |
| constraints.full.json           |          12,336 | −6,202 |                  48 |              5 |
| constraints.read_only_maps.json |          12,331 | −6,207 |                  48 |              5 |
| constraints.narrow_packet.json  |          12,336 | −6,202 |                  48 |              5 |
| constraints.helpers_only.json   |          12,540 | −5,998 |                  44 |              9 |
| constraints.empty.json          |          12,327 | −6,211 |                  48 |              5 |

~33% line-count reduction across every spec. `helpers_only` keeps 9
functions because its `helper_func` list (`bpf_map_lookup_elem`,
`bpf_map_update_elem`, `bpf_ktime_get_ns`, `bpf_xdp_adjust_head`) legitimately
matches more call sites; the other specs use the checked-in placeholder helper
names (`testing1`, `testing_dhdhd`) which match nothing, so the pass retains
only functions reachable via relevant map globals.

IR is `opt -verify`-clean for every variant.

## KLEE pairs (baseline vs pruned)

| spec             | budget | baseline wall | baseline outcome                | pruned wall | pruned outcome                          |
|------------------|-------:|--------------:|---------------------------------|------------:|-----------------------------------------|
| full             |  180 s |       3:01.03 | halted by watchdog, no `done`   |     0:01.02 | 7 completed paths, 7 tests, VALID       |
| narrow_packet    |   90 s |       halted* | halted by watchdog, no `done`   |     0:01.02 | 7 completed paths, 7 tests              |
| helpers_only     |   90 s |       0:01.02 | KLEE error (see notes)          |     0:01.02 | KLEE error (see notes)                  |
| empty            |   60 s |       0:01.02 | KLEE error (see notes)          |     0:01.02 | KLEE error (see notes)                  |

\*timing output equivalent to `full`.

Pruned long-run sanity: `constraints.full.json` with `-max-time=600s`
completes in the same 1.02 s, yielding:
- `mapAccess.results`  → `Map Access control : VALID`
- `helperFunc.results` → `No use of restricted function detected in any execution path`
- `completed paths = 7`, `generated tests = 7`
- one `test000001.ktest` (the non-error exit).

### Notes on `helpers_only` / `empty`

Both specs set `map_access` and/or `packet_constraints` to `[]`. KLEE's
`--enable-map-access-control` and `--enable-packet-constr` flags treat an
empty allow-list as "deny all" and produce an unsatisfiable precondition
immediately, so *both* baseline and pruned KLEE exit with the same
`(query [] false)` constraints error within ~1 s. This is a KLEE policy
semantics artefact, independent of the pass — the pass emits a valid
module in both cases (`opt -verify` clean) and KLEE produces identical
error outputs with and without the pass. No behavioural divergence was
observed.

### Notes on `full` / `narrow_packet`

Baseline does not reach `done` within the 90–180 s budget (`KLEE:
HaltTimer invoked`); this is the path-explosion case the pass is designed
for. Pruned run completes in 1 s and produces a stable KLEE verdict.
Direct equal-paths comparison with baseline is infeasible on katran
precisely because baseline doesn't terminate; the pruned verdict itself
(VALID + all expected result files present) is what this exercise
validates.

## Example-agnostic sanity

```
grep -ciE 'katran|balancer|ch_rings|vip_map|reals|quic_mapping|fallback_cache' \
    lifting_tools/llvm_policy_pass/policy_pass.cpp \
    lifting_tools/llvm_policy_pass/CMakeLists.txt \
    lifting_tools/build.sh
# → 0 / 0 / 0
```

No katran-specific strings in the pass or its build glue; the same
`libpolicy_pass.so` works against any policy spec.

## Reproducing

```
# build
cd lifting_tools && ./build.sh

# pruned-vs-baseline pair
cd examples/katran
make clean-klee && make verify-constraint-access MAP_CONFIG_PATH=$(pwd)/constraints.full.json   # baseline
make clean-klee && POLICY_PRUNE_SPEC=$(pwd)/constraints.full.json \
                  make verify-constraint-access MAP_CONFIG_PATH=$(pwd)/constraints.full.json    # pruned
```
