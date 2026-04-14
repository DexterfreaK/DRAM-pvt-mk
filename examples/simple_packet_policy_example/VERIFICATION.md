# policy-prune soundness verification on simple_packet_policy_example

Third differential-KLEE run, targeting **packet-range edge cases**.
Prior rounds stressed map/helper axes; this one focuses on the packet
axis since `xdp_main` here does a conditional header write (`ip->tot_len
= 100` at packet offset 16–17) plus header reads at offsets 0–33.

The harness detects both map-access verdicts and packet-access verdicts
(`"Trying edit prohibited packet fields"` / `"Trying read prohibited
packet fields"`) so we can tell *which* axis flipped.

## Test corpus — packet edge cases

| Spec | Packet write range | Packet read range | Intent |
|------|--------------------|--------------------|--------|
| Q1 all_allowed     | `0-1500`          | `0-1500`          | happy path |
| Q2 write_excludes_totlen | `0-15` + `18-1500` | `0-1500` | **hole exactly at the write offset** — tests the pass's `rangesOverlap` logic on multi-interval ranges |
| Q3 exact_totlen    | `16-17` only      | `0-33` only       | range *exactly* covers the write — boundary case |
| Q4 read_too_narrow | `0-1500`          | `0-10`            | reads go past 10 — header parse violates |
| Q5 no_writes_allowed | `[]` (empty)    | `0-1500`          | empty write range — tests pass's empty-ranges early-return |

Q2 and Q5 are designed to catch a specific class of pass bug: if a
function's only policy-adjacent operation is an *out-of-range* packet
write, the pass's `checkPacket` currently returns without marking the
function relevant (`rangesOverlap` returns false). The function would
then be stubbed, and KLEE would never see the write — a false positive.
In this example `xdp_main` also does in-range packet *reads*, so it's
saved by the read check; the soundness hole is still open for
packet-write-only functions (noted below).

## Results

| Spec | Baseline | Pruned | Match | Baseline IR | Pruned IR |
|------|---------|--------|-------|-------------|-----------|
| Q1 all_allowed | VALID | VALID | YES | 5152 | 2176 |
| Q2 write_excludes_totlen | INVALID(pkt-write) | INVALID(pkt-write) | YES | 5152 | 2176 |
| Q3 exact_totlen | INVALID(pkt-write) | INVALID(pkt-write) | YES | 5152 | 2176 |
| Q4 read_too_narrow | INVALID(pkt-read) | INVALID(pkt-read) | YES | 5152 | 2176 |
| Q5 no_writes_allowed | INVALID(pkt-write) | INVALID(pkt-write) | YES | 5152 | 2176 |

Every pair matches. IR shrinks ~58% — larger than the map-centric
examples because this program has no map helpers, so after stubbing,
`globaldce` can drop whole swaths of libbpf-stubbed support code.

### Unexpected: Q3 off-by-one

Q3 was designed as a VALID case: 2-byte write at offset 16–17, with
write-access `["16-17"]`. Both baseline and pruned return INVALID,
which means the pass is consistent, but the underlying check at
`klee/lib/Core/Executor.cpp:5178` uses `ptr->second >= off + bytes`
rather than `>= off + bytes - 1`. So an inclusive range `[a,b]` only
allows writes whose *exclusive* end is ≤ b, effectively requiring the
range to extend one byte past the write. Pre-existing KLEE bug, not
a pass bug — flagged here so it's not mistaken for one.

## Latent gap found and fixed during this round

`checkPacket` in `policy_pass.cpp` previously returned without marking
the containing function relevant when a constant offset fell outside
every listed range for the access direction. If a function's *only*
policy-adjacent operation were such an out-of-range constant-offset
packet access, the pass would stub the function and KLEE would miss
the violation — silent verdict flip from INVALID to VALID.

This wasn't triggered by the Q1–Q5 specs above (because `xdp_main`
also does in-range packet reads that keep it relevant), but the gap
was real. **Fixed**: any packet store/load on a pointer derived from
`xdp_md->data` now marks the containing function relevant, regardless
of offset/range overlap. Range overlap is a hint about what the
program *should* be touching, not a license to erase what it *is*
touching. All 15 prior verdict pairs across the three examples
continue to match after the fix; no regression.

## Reproduction

```bash
cd examples/simple_packet_policy_example
./run_differential.sh            # ~3 minutes
cat differential_results.md
```
