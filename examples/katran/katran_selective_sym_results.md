# Katran — selective_packet_sym results (consolidated)

Pass: `lifting_tools/llvm_selective_packet_sym/build/libselective_packet_sym.so`
(`-passes=selective-packet-sym`). Policy spec: `constraints.full.json` (all packet
fields `*`, read/write `0-146`, full map set). Outer wall-clock cap 2400 s — no run
hit it. Verdict guard ("refuse to concretize a policy-relevant field") unchanged.

> Scope: this file covers **only** the selective-packet-sym project. The policy-prune
> pass (`libpolicy_pass.so`) results live in `differential_results.md` and are a
> separate project — not included here.

Consolidates: `sweep_results.md`, `sweep_x_results.md`, `sweep_tcp_results.md`,
`sweep_x2_results.md`, `sweep_x_final_report.md`.

## Baseline (no concretization)

**16,110 completed paths · 14,746,978 instructions · 179.2 s · VALID**

Every case below preserves the `VALID` verdict → **0 false positives / false negatives**.

## Single-field concretization

| Field | Verdict | Paths | Δ paths | Wall (s) | Notes |
|---|---|---:|---:|---:|---|
| **protocol** | VALID | 12,119 | **−24.8%** | 138.0 | best single lever — drives the packet-type fanout |
| dPort | VALID | 13,408 | −16.8% | 150.4 | subsumed by protocol |
| tcp_ack_seq | VALID | 14,227 | −11.7% | 162.9 | ⚠️ non-deterministic (see crash section) |
| tcp_flags | VALID | 15,640 | −2.9% | 176.0 | ⚠️ non-deterministic |
| dIP | VALID | 16,110 | 0.0% | 179.1 | loaded, never branched on |
| sPort | VALID | 16,110 | 0.0% | 177.9 | loaded, never branched on |
| ttl | VALID | 16,110 | 0.0% | 180.2 | no effect |
| tot_len | VALID | 16,110 | 0.0% | 179.0 | no effect |
| frag_off | VALID | 16,110 | 0.0% | 180.0 | overridden by harness on IPV4/FRAGV4 |
| ip_id | VALID | 16,110 | 0.0% | 179.6 | no effect |
| ip_check | VALID | 16,110 | 0.0% | 180.9 | no effect |
| tcp_seq | VALID | 16,110 | 0.0% | 179.3 | no effect |
| tcp_check | VALID | 16,110 | 0.0% | 180.1 | no effect |
| tcp_urg_ptr | VALID | 16,110 | 0.0% | 184.5 | no effect |

## Multi-field combinations

| Combination | Verdict | Paths | Δ paths | Wall (s) | Notes |
|---|---|---:|---:|---:|---|
| {dPort} | VALID | 13,408 | −16.8% | 150.4 | — |
| {dIP, dPort} | VALID | 13,408 | −16.8% | 150.9 | dIP adds nothing |
| {sPort, dPort} | VALID | 13,408 | −16.8% | 152.1 | sPort adds nothing |
| {dIP, sPort, dPort} | VALID | 13,408 | −16.8% | 150.6 | full tuple ≈ dPort alone |
| {dIP} / {sPort} / {dIP, sPort} | VALID | 16,110 | 0.0% | ~178 | no branching driver |
| {protocol + 7 other IP fields} | VALID | 12,119 | −24.8% | 137.4 | identical to protocol alone |
| {dPort, protocol} | VALID | 12,119 | −24.8% | 137.9 | dPort subsumed by protocol |
| {ethertype, dPort, protocol} | VALID | 12,119 | −24.8% | 138.1 | identical to protocol alone |
| {protocol + tcp_safe} | VALID | 12,119 | −24.8% | 139.8 | identical to protocol alone |
| all6 (sIP,dIP,sPort,dPort,proto,ethertype) | VALID | 12,119 | −24.8% | 138.4 | protocol is the only contributor |
| {tcp_seq, tcp_check, tcp_urg_ptr} (tcp_safe) | VALID | 16,110 | 0.0% | 180.9 | no effect |

## Crash / instability cases (concretization made KLEE *worse*)

| Case | Result | Time to death |
|---|---|---:|
| tcp_ack_seq | SIGTERM (memory blow-up) | 44.6 s |
| tcp_flags | OOM kill | 6.7 s |
| tcp_window | OOM kill | ~7 s |
| ip_all (7 IP fields, no protocol) | OOM kill | ~10 s |
| everything_safe (15 fields) | OOM kill | ~7 s |

⚠️ **Non-determinism:** `tcp_ack_seq` and `tcp_flags` completed cleanly with savings in
`sweep_tcp_results.md` but OOM'd / SIGTERM'd in `sweep_x_results.md`. Their "savings"
numbers straddle the crash boundary and should be treated as unreliable. Shared symptom
across the crashes is the `Symbolic memory access ... 5120 bytes` warning firing right
before death — pinning bytes inside the symbolic packet changes how downstream symbolic
indices are formed, ballooning the SMT array sent to Z3 (cf. KrakenGuard paper §6,
packet bytes hashed into branch conditions).

## Findings

1. **Payoff is proportional to branching gated.** `protocol` gates the packet-type
   fanout → −24.8%. `dPort` gates a weaker, subsumed branch → −16.8%. Every field that
   is read but never branched on (dIP, sPort, ttl, ip_id, ip_check, tcp_seq, tcp_check,
   tcp_urg_ptr, …) saves **exactly 0 paths**. IR grows ~1 line per concretized field
   from the inserted `store i*`, but KLEE never forked on those values either way.

2. **`protocol` is the only meaningful lever for katran under this policy.** No single
   field and no runnable combination beats it; adding fields on top of `protocol` (or on
   top of `dPort`) is free noise.

3. **The floor is ~12,119 paths (−24.8%).** Set by the harness's 7-way packet-type
   fanout (`klee_int` decisions, `katran.c:89-115`) plus per-packet map lookup hit/miss
   forks. Going lower requires concretizing inside the harness (e.g. fixing
   `pkt.isIPv4`), which is a *policy* decision the operator must opt into.

4. **More concretization is not monotonically better.** Several TCP fields and IP-field
   supersets crash KLEE (OOM/SIGTERM) in seconds. The pass has a *soundness* guard but no
   *performance* guard — nothing stops an operator from listing `tcp_flags` and crashing
   verification. A fast pre-check (~30 s ceiling) that rejects any field which degrades
   wall time or OOMs is the recommended next step.

## Verdict-guard coverage gap

`constraints.full.json` has no policy-relevant (non-`*`) field, so the guard that refuses
to concretize a relevant field was never exercised in this sweep. It has now been
exercised separately with a pinned-`sIP` policy — see `restricted_policy_results.md`. The
guard fires correctly (`keeping policy-relevant field symbolic: sIP`).

**Correction to an earlier claim:** the guard-coverage gap was previously attributed to
the narrow `0-146` access range tripping enforcement at the ethertype read
(`balancer_kern.h:647`). That is wrong. Isolation runs show the **pinned `sIP` field**,
not the access range, is what trips enforcement: `sIP="*"` with range `0-1500` completes
all 16,110 paths, while `sIP="12345"` with the *same* `0-1500` range prohibits the read on
every path. The mechanism is `isConstraintSatisfied` (`Executor.cpp:5081`) requiring the
`sIP==12345` match to be `mustBeTrue` before any read — impossible at the first ethertype
read since nothing has constrained sIP yet. Details in `restricted_policy_results.md`.
