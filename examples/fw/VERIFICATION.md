# policy-prune soundness verification on fw

Second differential-KLEE run, after the fixes landed from the
`simple_map_policy_example` verification (see sibling VERIFICATION.md
there). Goal: confirm the pass is sound on a second, larger example
with different map types (DEVMAP + HASH) and a helper in-between
(`biflow()` called from `xdp_fw_prog`).

## Test corpus

Five spec variants in `policy_F*.json`:

| Spec | Intent | Expected |
|------|--------|----------|
| F1 all_allowed | permissive maps/helpers/packet | VALID |
| F2 flow_ctx_readonly | `flow_ctx_table` listed as Read; code updates it | INVALID |
| F3 flow_ctx_missing | `flow_ctx_table` omitted entirely; code uses it | INVALID |
| F4 tx_port_write | `tx_port` listed as Write (unused by code), `flow_ctx_table` RW | VALID |
| F5 only_update_helper | only `bpf_map_update_elem` listed; code also uses lookup | VALID * |

\* F5's KLEE verdict for the map-access axis is VALID because the
helper-restriction axis doesn't flip the map-access verdict. Both
baseline and pruned observe the same behavior, which is what the
differential test checks.

## Results

| Spec | Baseline | Pruned | Match | Baseline IR | Pruned IR |
|------|---------|--------|-------|-------------|-----------|
| F1 all_allowed | VALID | VALID | YES | 6084 | 4285 |
| F2 flow_ctx_readonly | INVALID | INVALID | YES | 6084 | 4285 |
| F3 flow_ctx_missing | INVALID | INVALID | YES | 6084 | 4285 |
| F4 tx_port_write | VALID | VALID | YES | 6084 | 4285 |
| F5 only_update_helper | VALID | VALID | YES | 6084 | 4175 |

Every pair matches. IR shrinks ~30% consistently (a little more for F5
since the unwhitelisted lookup helper's body becomes unreachable after
stubbing, so `globaldce` drops it).

No new bugs surfaced. The two fixes from the first verification
(keep helper bodies via downward closure; don't erase map globals) are
sufficient on this example as well.

## Reproduction

```bash
cd examples/fw
./run_differential.sh            # ~5 minutes
cat differential_results.md
```
