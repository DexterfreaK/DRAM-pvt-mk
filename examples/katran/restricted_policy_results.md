# Katran — selective_packet_sym under a RESTRICTED policy

Companion to `katran_selective_sym_results.md` (which uses the permissive
`constraints.full.json`). Here the policy pins **`sIP="12345"`**, making sIP a
policy-relevant field. Pass + KLEE flags identical to the permissive sweep;
runner: `sweep_restricted_policy.sh`.

Policy: `constraints.selective_sym.relaxed.json` (sIP=12345, sPort/dPort/dIP=`*`,
read/write `0-1500`, full 9-map set).

## Result

| Case | Verdict | IR lines | Completed | Partial | Instructions | Wall ms | Pass guard |
|---|---|---:|---:|---:|---:|---:|---|
| baseline (none) | PKT-READ-PROHIBITED | 18538 | 0 | 7 | 15031 | 385 | - |
| protocol | PKT-READ-PROHIBITED | 18541 | 0 | 7 | 15040 | 387 | - |
| dPort | PKT-READ-PROHIBITED | 18541 | 0 | 7 | 15040 | 391 | - |
| dIP | PKT-READ-PROHIBITED | 18543 | 0 | 7 | 15046 | 388 | - |
| sIP | PKT-READ-PROHIBITED | 18538 | 0 | 7 | 15031 | 385 | **GUARD-FIRED** |
| sIP + dPort | PKT-READ-PROHIBITED | 18541 | 0 | 7 | 15040 | 389 | **GUARD-FIRED** |

Every path (7 of them, all *partial*) terminates with
`ERROR: ./balancer_kern.h:647: Trying read prohibited packet fields` in ~0.4 s.
**0 completed paths** in every case → the sweep yields no path-savings signal.

## Why — and the correction to the prior note

The previous `katran_selective_sym_results.md` claimed the narrow `0-146` access
range tripped enforcement. **That is wrong.** Isolation runs:

| Policy | sIP | range | Outcome |
|---|---|---|---|
| `sIP="*"`, `0-1500` | wildcard | 0-1500 | **VALID, 16,110 completed paths** |
| `sIP="12345"`, `0-1500` | pinned | 0-1500 | **PKT-READ-PROHIBITED, 0 completed** |
| `sIP="*"`, `0-146` (full.json) | wildcard | 0-146 | VALID, 16,110 completed |

So the **pinned field**, not the access range, is what trips enforcement.

Mechanism (`klee/lib/Core/Executor.cpp`):
`handlePacketDataLoad` → `isConstraintSatisfied` (line 5081). A pinned field
builds a rule condition `sIP_field == 12345` and requires
`solver->mustBeTrue(state.constraints, condition, ...)` — the packet must
**provably** match the rule before *any* read is allowed. At the first packet
access (ethertype, `balancer_kern.h:647`) nothing has constrained sIP yet, so
`mustBeTrue(sIP==12345)` is false → the read is prohibited and the path dies.
With `sIP="*"` the condition is never built (`!hasVal` short-circuits to allow),
which is why the permissive policy completes all 16,110 paths.

## Takeaways

1. **Selective concretization can't help under this policy as written.** Every
   path dies at the first read, before reaching any branch that concretizing
   protocol/dPort/etc. would prune. The IR-size deltas (+0..+8 lines) are the only
   visible effect.
2. **The relevance guard works.** Listing `sIP` (alone or with dPort) triggers
   `[selective-packet-sym] keeping policy-relevant field symbolic: sIP` — the pass
   correctly refuses to concretize the policy-relevant field. (This is the guard
   coverage that `constraints.full.json` could never exercise.)
3. **Enforcement semantics are strict-by-design.** A pinned field means "this
   policy only governs packets matching it," but enforcement demands the match be
   *provable at every access*. Programs that read header bytes before branching on
   the pinned field will always trip. This is arguably a limitation of the
   `mustBeTrue` check rather than a katran bug.
4. **To get a meaningful restricted-policy sweep**, the harness would need to
   *assume* `sIP==12345` up front (e.g. `klee_assume` on the field right after
   `klee_make_symbolic`, or have the selective pass pin sIP to the policy value
   `12345` instead of refusing it). Pinning sIP to its policy value — rather than
   leaving it symbolic or zeroing it — would both satisfy enforcement and shrink
   the state space. That is a pass change, not done here.

_Runner: `sweep_restricted_policy.sh`. Logs: `log_restricted_*.txt`._
