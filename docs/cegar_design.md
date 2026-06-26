# CEGAR-Guided Policy Verification for eBPF — Design Doc (v2, Design A)

**Status:** DRAFT — pre-implementation alignment.
**Audience:** project team.
**Foundation:** KrakenGuard (NSDI '26, Patel et al.) and the existing
`selective_packet_sym`, `policy_pass`, `ai_demo/` work in this repo.
**Supersedes:** v1 (which proposed Design B). The decision to use Design A
is explicit (see §4) and was made knowing that the soundness surface is
larger than B's; defensive measures in §9 are non-negotiable.

---

## 0. TL;DR

We build a CEGAR-based verifier in which **a new abstract analyzer
becomes the primary source of policy verdicts.** The abstract domain is
**predicate abstraction induced by the policy** — predicates are derived
automatically from the policy JSON, plus more added by CEGAR refinement.
KLEE is invoked **only on single abstract-counterexample traces** to
check feasibility and (via unsat cores) drive refinement.

This is **canonical CEGAR**: abstract verifier + feasibility oracle +
refinement loop. It has the strongest theoretical claim and the highest
empirical speedup ceiling of the options we considered (30–500× on the
KrakenGuard benchmark suite). It also has the largest soundness surface
of any candidate, which we mitigate with:

1. Conservative-by-construction abstract semantics (§6).
2. Differential testing against vanilla KLEE on every benchmark (§9).
3. Property-based testing of every abstract transfer function (§9).
4. Reusing a battle-tested AI framework (Clam/Crab) for the underlying
   dependence/points-to/widening infrastructure (§10).

The design commits us to **engineering discipline around soundness
testing**. If we cannot maintain the differential-testing gate, this
design must be reconsidered.

---

## 1. Problem statement

KrakenGuard verifies eBPF programs against operator policies via
exhaustive symbolic execution (KLEE + ebpf-se). On programs with rich
symbolic state, per-path cost dominates total verification time.

Empirical baseline (from this repo's sweeps):

| Program | Paths | Wall | Per-path cost | Notes |
|---|---:|---:|---:|---|
| Katran (full symbolic, permissive policy) | 16,110 | 179.2 s | 11.1 ms | All paths verify VALID — 1 equivalence class |
| Katran (concrete input floor) | 1 | 0.36 s | — | Lower bound for any sound approach |
| Electrode FAST_QUORUM_PRUNE (paper §5.4) | 77 | 28.3 s | 367 ms | SMT-heavy due to symbolic map indices |
| bmc-cache (`bmc_hash_keys_main`) | — | KLEE crashes at 55 s | — | Symbolic expression too deep for KLEE; orthogonal to path explosion |
| `selective_packet_sym` w/ best operator hint | 12,119 | 138 s | 11.4 ms | Caps at ~22% of the floor gap |

**Headroom on Katran:** ~498× between current SOTA wall time (179.2 s)
and the per-execution floor (0.36 s).

**Static observation:** under permissive policies (the common case),
the program produces many distinct paths that all map to the same
policy verdict equivalence class. KrakenGuard's exploration is
redundant by the ratio (path count : verdict-class count). For
`constraints.full.json` on Katran, this ratio is empirically ≥ 12,119 : 1.

**Goal:** eliminate the redundancy with a verifier whose precision is
calibrated to the policy.

---

## 2. Non-goals

- Replacing KLEE in KrakenGuard's pipeline as a tool. KLEE remains the
  feasibility oracle inside our CEGAR loop and remains available as a
  fallback for cases the abstract analyzer cannot handle.
- Solving bmc-cache's KLEE expression-size explosion via this work
  alone. (Function summarization, a separate work item, addresses it.
  But Design A's abstract domain *should* skip the symbolic hash chain
  entirely for permissive policies, indirectly fixing bmc-cache; see
  §14, prework experiment F.)
- Operator UX changes. The operator's input remains KrakenGuard's JSON
  policy.
- Cross-program (interference) analysis.
- Policy synthesis / mining.

---

## 3. Design goals (in priority order)

1. **Soundness — empirical equivalence with KrakenGuard.** For every
   (program, policy) pair in the KrakenGuard evaluation set, our
   pipeline's verdict must match vanilla KLEE's verdict. Differential
   testing is the soundness mechanism, not a theorem.
2. **Decidable termination.** The CEGAR loop terminates on every
   (program, policy) within ≤ `O(|branches in P|)` iterations.
3. **Net speedup ≥ 10×** on a representative subset of KrakenGuard's
   evaluation benchmarks (geomean over Katran, Electrode FAST_REPLY,
   Electrode FAST_QUORUM_PRUNE, hXDP).
4. **Handle bmc-cache.** Where KrakenGuard's KLEE crashes due to
   expression size, our pipeline returns a verdict.
5. **Bounded implementation complexity.** Total new code ≤ 5,000 LoC
   C++ + 500 LoC Python.

---

## 4. Why Design A (and not Design B)

In v1 of this doc, we initially recommended Design B (BEA + KLEE +
optional CEGAR), reasoning that it kept KLEE as the verifier and
therefore had a smaller soundness surface. After more discussion we
realized:

- **B's "CEGAR loop" is vestigial.** Without an optimistic-pruning
  layer, the refinement loop has no work to do; B is essentially
  policy-driven slicing.
- **B's speedup ceiling is lower** (5–30× vs A's 30–500×).
- **B doesn't fix bmc-cache.** The hash-chain expression explosion is
  outside B's reach because B doesn't change what KLEE sees inside
  basic blocks.
- **The soundness benefit of B is real but smaller than it first
  appeared.** B still depends on its static check being implemented
  correctly. The check is simpler than A's abstract transfer functions,
  but it's not free.
- **The killer demo for the paper is bmc-cache** — the case KrakenGuard
  declared infeasible. Without it, the contribution is "we made
  KrakenGuard faster on cases it already worked on," which is harder to
  motivate as flagship work.

We accept A's larger soundness surface in exchange for:
- A genuine CEGAR architecture (refinement is load-bearing, not a
  safety net).
- A meaningful theoretical claim (predicate abstraction induced by the
  policy is provably the coarsest sound domain for that policy).
- bmc-cache as the demonstrating case.
- 10×+ speedup goals on standard benchmarks.

The increased soundness burden is mitigated by §9's defensive measures.
None of those measures are optional.

---

## 5. Architecture overview

```
                ┌─────────────────┐
                │  Policy JSON    │
                └────────┬────────┘
                         │
              ┌──────────▼───────────┐
              │   Policy translator  │   produces Π_0 (initial
              │      (§6.1)          │   predicate set) and S
              │                      │   (policy-relevant op sites)
              └──────────┬───────────┘
                         │
   ┌───────────┐    ┌────▼──────────┐
   │ eBPF .o   │───▶│  KG lifter    │───▶ LLVM IR (original)
   └───────────┘    └───────────────┘
                                          │
                                          ▼
                ┌────────────────────────────────────────────┐
                │       Abstract analyzer (the verifier)     │
                │  - state: boolean valuation over Π         │
                │  - transition: per LLVM instruction (§6.3)│
                │  - fixpoint: worklist (§6.4)              │
                │  - checks policy at each relevant site    │
                └────────────────────┬───────────────────────┘
                                     │
                          ┌──────────▼───────────┐
                          │ Abstract verdict     │
                          │ + (if INVALID)       │
                          │   counterexample τ#  │
                          └──────────┬───────────┘
                                     │
                          ┌──────────▼───────────┐
                          │ VALID? → return VALID│
                          └──────────┬───────────┘
                                     │ INVALID
                                     ▼
                ┌────────────────────────────────────────────┐
                │   Counterexample stage (§7)                │
                │   - extract τ# from analyzer's worklist    │
                │   - rebuild path constraint C(τ#) via      │
                │     symbolic execution along τ#            │
                │   - hand to Z3                             │
                └────────────────────┬───────────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │ Z3 result                        │
                    └────┬──────────────────┬──────────┘
                       SAT                UNSAT
                         │                  │
                         ▼                  ▼
             ┌────────────────┐   ┌────────────────────────┐
             │ return INVALID │   │  Refinement (§6.6)     │
             │  + concrete    │   │  - extract unsat core  │
             │    witness     │   │  - lift to predicates  │
             └────────────────┘   │  - Π := Π ∪ new preds  │
                                  │  - re-run fixpoint     │
                                  └────────────┬───────────┘
                                               │
                                               └─→ back to abstract analyzer
```

---

## 6. Component specs

### 6.1 Policy translator

**Input:** KrakenGuard policy JSON.
**Output:**
- `Π_0` — initial set of policy predicates.
- `S` — set of policy-relevant op site signatures.

**Translation rules:**

| Policy element | `Π_0` addition | `S` addition |
|---|---|---|
| `MEM_CONDITION { offset, size, value }` | `mem[offset, offset+size) == value` | — |
| `MEM_CONDITION { fieldName: v }` | `pkt.<fieldName> == v` | — |
| `packet_constraints [{field: value}]` for non-`*` value | `pkt.<field> == value` | — |
| `packet_constraints` `read-access: [r0..rn]` | — | per-byte-load site: must be in covered range |
| `packet_constraints` `write-access: [r0..rn]` | — | per-byte-store site: must be in covered range |
| `map_access [{name, "Read"}]` (no key restriction) | — | site: lookup-against-`name` (any key OK) |
| `map_access [{name, "Read", keys: K}]` | `lookup_key_at_site_i ∈ K` | site: lookup-against-`name` constrained |
| `map_access [{name, "Write"}]` | — | site: update-against-`name` (Write privileges checked) |
| `helper_access [h1..hN]` | — | site: helper-call (must be in allowed set) |
| `return_value [r1..rN]` | — | site: ret (value must be in allowed set) |
| `conditional_policies` with `dependency` chain | `prev_actions ⊇ deps` (one predicate per rule with deps) | — |

**Implementation:** ~200 LoC Python or C++. Pure structural translation;
unit-tested against golden outputs for every policy file in `examples/`.

**Output sizes (measured / expected):**
- `constraints.full.json`: `|Π_0| = 0`, `|D| = 1`
- `constraints.selective_sym.json`: `|Π_0| = 1`, `|D| = 2`
- Most other KrakenGuard eval policies: `|Π_0| ≤ 5`, `|D| ≤ 32`
- Stretch: conditional-policy files with chained dependencies may reach
  `|Π_0| ≈ 10`, `|D| ≈ 1024` — still small.

### 6.2 Abstract domain

**Carrier:** boolean valuation over `Π` (the current predicate set).
`|D| = 2^|Π|`.

**Augmentations** for tracking values that predicates alone can't:
- **Equality classes** between SSA values. Useful for tracking "x == y"
  derived from a branch condition propagated forward.
- **Constants** for SSA values that the abstract analyzer can resolve
  to a single value (e.g., after a `klee_assume`).
- **Top** as the no-information value when the analyzer gives up.

We do **not** start with full interval domains (Clam-style). Reason:
- Most policy predicates are equality- or membership-style, not numeric
  range. Intervals are overkill for the common case.
- Each numeric abstraction adds its own transfer functions to debug.
- We can extend to intervals later if CEGAR refinement starts producing
  range-style predicates that boolean abstraction can't represent.

**Galois connection** with concrete domain (set of concrete eBPF states):
- `α(c) = {p ∈ Π : p holds in concrete state c}`
- `γ(σ) = {c : ∀p ∈ Π. (p ∈ σ) ⇒ p holds in c}`

This is the standard predicate abstraction Galois connection (Graf &
Saïdi '97). Soundness lemmas come for free from the literature.

### 6.3 Abstract transition rules

For each LLVM instruction `i`, define `T_i# : D → D`.

| Instruction class | `T_i#` rule |
|---|---|
| Arithmetic (`add`, `sub`, `mul`, `udiv`, `urem`, etc.) | If operands are constants in the abstract state, compute the constant; otherwise mark result as `Top`. Update predicates that depend on the result. |
| Logic (`and`, `or`, `xor`, `shl`) | Same as arithmetic. |
| Comparison (`icmp`) | If both operands' constraints can be evaluated against a predicate in `Π`, set the result predicate; otherwise `Top`. |
| Load (`load i*, ptr`) | If the loaded address can be resolved to a known field tracked by a predicate, update the loaded SSA value's predicate; otherwise `Top`. |
| Store (`store i*, ptr`) | If the stored value is a known constant and the address is tracked, update the location's predicate; otherwise invalidate predicates that depend on that address. |
| Branch (`br i1 %c`) | Propagate two abstract successors: one with `c = true` constraints added, one with `c = false`. (At join points, union.) |
| Call to listed helper | Check policy: is this helper in `helper_access`? If not, record violation. Use helper summary for state transition. |
| Call to bpf_map_op (lookup/update/delete) | Check policy: is `(map, op)` allowed? If `keys` restriction, check whether key SSA value satisfies the key predicate (use abstract state). Record violation if not. Update abstract state based on op semantics. |
| Call to non-bpf function | Use the function's summary (computed bottom-up; see §6.5). If no summary or function pointer, conservatively widen all tracked state involving its args/return to `Top`. |
| Ret | Check policy: is the return value in `return_value` allowed set? Use abstract state for the return SSA value. Record violation if it might be outside the allowed set. |
| Other (alloca, gep, phi, select, etc.) | Identity on `Π`; equality-class tracking only. |

**Critical correctness property** (per transfer function): for every
concrete instruction execution, the post-state's abstraction is `⊑` the
abstract result. This is checked by property-based testing in §9.

### 6.4 Fixpoint engine

Standard worklist algorithm:

```
worklist = [entry block with state ⊤]
seen     = empty map (block → abstract state)
violations = empty list

while worklist not empty:
    (block, state) = worklist.pop()
    if seen[block] already covers state:
        continue
    seen[block] := seen[block] ⊔ state
    
    new_state = state
    for instr in block.instructions:
        new_state = T_instr#(new_state)
        if instr is a policy site and new_state.violates(policy_at(instr)):
            violations.append((instr, new_state, current_path))
    
    for succ in block.successors:
        # account for branch terminators that introduce path predicates
        succ_state = strengthen(new_state, edge_condition(block → succ))
        worklist.push((succ, succ_state))

return violations
```

**Termination:** finite abstract domain (`|D|` is bounded by `2^|Π|`).
Standard fixpoint termination argument.

**Path tracking:** we annotate each abstract state with a `current_path`
field — the sequence of basic blocks traversed to reach this state.
Required for counterexample extraction (§7).

**Implementation:** ~600 LoC C++ on top of LLVM IR walkers.

### 6.5 Function summaries

Each non-leaf function gets a summary:

```
summary(f) = {
    reads:    set of memory regions read by f or its callees
    writes:   set of memory regions written by f or its callees
    helpers:  multiset of helper calls f or its callees make
    map_ops:  multiset of (map_name, op_kind, key_abstract_value)
    returns:  abstract value of f's return
    transfer: function (abstract_state, args) → abstract_state
}
```

Computed bottom-up over the call graph. Recursion past depth limit
defaults to "everything is `Top`" (sound but pessimistic).

Indirect calls (function pointers): use points-to from Clam or LLVM's
`BasicAA` to over-approximate the callee set; union summaries.

**Implementation:** ~500 LoC C++. Cached per function.

### 6.6 Refinement engine

**Input:** spurious counterexample τ# (UNSAT path).
**Output:** updated `Π` with new predicates.

```
# τ# is a sequence of (basic_block, abstract_state, instruction_indices)
# C(τ#) is the SMT formula built in §7

unsat_core = Z3.unsat_core(C(τ#))
new_predicates = []

for clause in unsat_core:
    # clause is an SMT subformula derived from an LLVM branch condition
    # or memory comparison.
    # Lift it to a predicate over program state.
    p = lift_clause_to_predicate(clause, program)
    if p not in Π:
        new_predicates.append(p)

if len(new_predicates) == 0:
    # CEGAR is failing to make progress. This shouldn't happen with
    # unsat-core extraction but indicates a bug.
    return ERROR("refinement stuck")

Π := Π ∪ new_predicates
```

**Lifting clauses to predicates:** the SMT formula clauses correspond to
specific LLVM instructions (branch conditions, memory accesses). We
track this mapping during formula construction. Lifting: for a branch
`%c = icmp eq %x, %y`, the corresponding predicate is `x == y`.

**Termination:** each refinement adds at least one new predicate. The
universe of "useful" predicates is bounded by `|branches in P| +
|memory accesses in P|`, which is finite. So CEGAR terminates after at
most that many iterations.

**Practical bound:** in published predicate-abstraction work
(BLAST, SLAM, CPAChecker), refinement count is single-digit for most
programs; pathological cases reach dozens. We target ≤ 10 iterations
as the engineering goal; > 20 indicates the program is poorly suited
to our abstraction and we should fall back.

**Alternative: Craig interpolation** (McMillan, CAV '03) extracts more
general predicates than unsat-core clauses. We start with unsat-core
(simpler); swap to interpolation later if predicate explosion is bad.

---

## 7. The counterexample stage in detail

This is the heart of CEGAR and where Design A's character is most
visible. The earlier conversation walked through this; restating it
here for completeness.

### 7.1 Counterexample extraction

When the abstract analyzer reports a violation, it has:
- `instr_v`: the LLVM instruction at the violation site.
- `state_v`: the abstract state at `instr_v` that triggers the
  violation.
- `path_v`: the sequence of basic blocks from entry to `instr_v` that
  produced `state_v`.

We reconstruct the trace:

```
τ# = [(b_0, σ_0), (b_1, σ_1), ..., (b_k, σ_k)]
       where b_0 = entry, b_k = instr_v's block,
             σ_i is the abstract state at the start of b_i.
```

### 7.2 Building the path constraint C(τ#)

For each consecutive pair `(b_i, σ_i) → (b_{i+1}, σ_{i+1})`, symbolically
execute `b_i`'s instructions and add the path condition for taking the
edge to `b_{i+1}`.

This is exactly what KLEE does internally when exploring a single path.
Two implementation choices:

- **Call out to KLEE in "force-path" mode.** KLEE has a hidden
  `forkOnExternalCalls=false` + `assume` mechanism that can be coaxed
  into following a specific path. We script this.
- **Implement our own single-path symbolic executor.** Smaller and more
  controllable. ~400 LoC C++.

Recommended: start with KLEE (path-forcing); switch to in-house if KLEE
overhead is too high per CEGAR iteration.

Output: an SMT formula `C(τ#)` over the program's symbolic inputs
(packet bytes, map return values, etc.).

### 7.3 Feasibility check

Hand `C(τ#)` to Z3:
- **SAT** with model M: the model is a concrete input that drives the
  program along τ#. Return INVALID with M as witness.
- **UNSAT**: no concrete input can follow τ#. The abstract trace is
  spurious. Proceed to refinement.
- **UNKNOWN / TIMEOUT**: Z3 gives up. Conservatively treat as SAT and
  return INVALID with τ# as the (unverified) witness. The operator can
  inspect.

### 7.4 Worked example

```c
int xdp_main(ctx) {
  int dport = pkt->dport;
  int magic = pkt->magic;
  bool flag = pkt->flag;
  
  if (dport == 80) {
    if (magic == 0xDEAD && magic == 0xBEEF) {  // dead
      if (flag) {
        bpf_map_update_elem(&ro_map, &k, &v);  // VIOLATION
      }
    }
  }
  return XDP_PASS;
}
```
Policy: `ro_map` is `Read`-only.

**Iteration 1.** `Π_0 = ∅`.
- Abstract analyzer can't reason about `dport`/`magic`/`flag`.
- All branches are abstractly "both arms reachable."
- The write to `ro_map` is reached. Violation recorded.
- τ# = `[entry, B1.true, B2.true, B3.true, write_site]`.

**Feasibility check.**
- Build `C(τ#) = (dport==80) ∧ (magic==0xDEAD) ∧ (magic==0xBEEF) ∧ (flag != 0)`.
- Z3: UNSAT (magic can't be both 0xDEAD and 0xBEEF). Spurious.
- Unsat core: `{(magic==0xDEAD), (magic==0xBEEF)}`.

**Refinement.** Lift core to predicates:
- `p_a ≡ (magic == 0xDEAD)`
- `p_b ≡ (magic == 0xBEEF)`
- `Π_1 = {p_a, p_b}`, `|D| = 4`.

**Iteration 2.** Re-run abstract analyzer with `Π_1`.
- At B2, we track `(p_a, p_b)`. The branch condition is `p_a ∧ p_b`.
- Abstract analyzer asks: is the state `(p_a = true, p_b = true)` ever
  reachable? Check: in any concrete state where both predicates are
  true, `magic == 0xDEAD ∧ magic == 0xBEEF` is unsatisfiable.
- The state is dropped. The true arm of B2 is unreachable abstractly.
- The write_site is unreachable. **No violation.**
- **Verdict: VALID.**

Two iterations, two cheap Z3 calls, no full KLEE exploration on the
whole program ever.

### 7.5 What the feasibility checker has to handle

To produce `C(τ#)` correctly, the symbolic-along-the-path step must
handle:
- Constants, arithmetic, comparisons (straightforward SMT).
- Memory loads/stores (model with SMT arrays).
- BPF helper calls — use the same helper models KLEE uses (from
  `libbpf-stubbed`).
- Map operations — model with SMT arrays per map.
- Indirect calls — must already be resolved before we get here (via
  points-to at the abstract-analyzer level).

If a helper or instruction has no SMT model, fall back to treating its
return value as unconstrained symbolic. Lose precision; not soundness.

---

## 8. Soundness argument

### 8.1 Statement

> **Theorem (end-to-end soundness).** For all programs P and policies
> Φ, the verdict produced by this pipeline equals the verdict
> KrakenGuard's vanilla KLEE-only pipeline would produce on (P, Φ).

### 8.2 Proof sketch

**Forward direction** (our VALID ⇒ KG VALID):
- VALID is returned only when the abstract analyzer's fixpoint completes
  with no recorded violations.
- By the abstract semantics' over-approximation property (a Galois
  connection invariant), every reachable concrete state c is in the
  concretization γ(σ) of some abstract state σ reached by the
  analyzer.
- If c violated the policy at some concrete site, then σ would have a
  state in which the policy site's check fails. The abstract analyzer
  would have recorded that. So no concrete state can violate the
  policy.
- Therefore KG (which would find a violation only if a concrete state
  reached a violation site) would also return VALID.

**Reverse direction** (our INVALID ⇒ KG INVALID):
- INVALID is returned with a witness — a concrete model M from Z3 that
  drives the program along τ# to the violation.
- M is an input to KG. KG's KLEE, executing P on M, would follow τ# and
  hit the same violation site, also reporting INVALID.

### 8.3 Where this proof can fail in practice

The proof is contingent on:

1. **Each abstract transfer function T_i# is sound** (over-approximates
   its concrete counterpart). If any transfer function under-approximates,
   the analyzer can miss reachable states → false VALID.
2. **The Galois connection between abstract and concrete domains is
   correct.** Subtle for non-standard predicates.
3. **The feasibility check correctly translates τ# to C(τ#).** A
   translation error can make SAT/UNSAT lie about feasibility.
4. **The fixpoint engine's join, widening, and merge operators are
   sound.** Standard but easy to get wrong.
5. **Helper models accurately reflect helper semantics.** We reuse
   `ebpf-se`'s models (already in KG); inherits their bugs.

Each of these is an implementation property that requires testing. §9
specifies how.

---

## 9. Defensive measures (mandatory, not optional)

Because soundness depends on the abstract analyzer being correctly
implemented, we commit to the following testing regime. None is
optional; if any cannot be maintained, the design should be
reconsidered.

### 9.1 Differential testing gate

For every benchmark (program × policy) in the KrakenGuard evaluation
set:
- Run vanilla KrakenGuard pipeline (KLEE only).
- Run our pipeline (abstract analyzer + CEGAR + KLEE feasibility).
- Compare verdicts. **Any divergence is a P0 bug.**

This gate must be:
- Part of CI.
- Run on every change to the abstract analyzer, refinement engine, or
  helper models.
- Block release on any divergence.

**Coverage:** at minimum, all programs in `examples/` × all policy
files for that program. Estimated ~80–100 (program, policy) pairs.

**Cost:** vanilla KG run + our run per pair. We're already paying for
the former during regular eval; the latter is the new cost. Budget:
overnight CI run, ~few hours wall.

### 9.2 Property-based testing of transfer functions

For each abstract transfer function `T_i#`:
- Generate N random concrete states `c_1, ..., c_N`.
- For each `c_j`, compute `c_j' = run instruction i concretely`.
- Compute `σ_j = α(c_j)` and `σ_j' = T_i#(σ_j)`.
- **Assert: `α(c_j') ⊑ σ_j'`.** (The abstract result over-approximates
  the concrete result.)

Run this for every instruction class in our abstract semantics. Use
QuickCheck-style PBT. ~200 LoC of test infrastructure.

**Catches:** transfer functions that under-approximate.

### 9.3 Property-based testing of join / widen

- Generate two random abstract states `σ_1`, `σ_2`.
- Compute `σ = σ_1 ⊔ σ_2`.
- **Assert: `γ(σ) ⊇ γ(σ_1) ∪ γ(σ_2)`.** (The join over-approximates
  the union of concretizations.)

Same for widening operators.

### 9.4 End-to-end soundness audit

Once a quarter (or at major milestones), do a manual audit:
- Pick 5 (program, policy) pairs from the eval set.
- Trace by hand what the abstract analyzer should compute.
- Verify implementation matches manual trace.

Cheap; catches subtle semantic bugs that property-based tests miss.

### 9.5 Framework choice as a defensive measure

Build on top of an existing abstract interpretation framework (Clam,
IKOS, Astrée) rather than from scratch where possible. These have
spent years hunting transfer-function bugs.

Specific framework choice is an open question (see §13).

### 9.6 Why these matter

Without §9.1, an undetected abstract-analyzer bug can produce false
VALID in production. The user has been clear: this is the primary
risk. The gate is the answer to that risk.

---

## 10. Implementation plan

### 10.1 Modules and effort

| Module | Description | LoC est. | Effort |
|---|---|---:|---:|
| Policy translator | JSON → `Π_0`, `S` | 200 | 1–2 days |
| Abstract domain types | `D`, predicate types, join/meet/widen | 400 | 1 week |
| Transfer functions | One per LLVM instruction class | 1200 | 2–3 weeks |
| Function summaries (intra/inter-proc) | Bottom-up summary computation | 600 | 1 week |
| Fixpoint engine | Worklist + state tracking | 600 | 1 week |
| Counterexample extractor | τ# from analyzer state | 200 | 2–3 days |
| Feasibility checker | C(τ#) via KLEE path-force | 400 | 1 week |
| Refinement engine | Unsat core → new predicates | 500 | 1–2 weeks |
| Driver / pipeline integration | Python wrapper | 300 | 3–5 days |
| Property-based test harness | PBT for transfer / join / widen | 300 | 3–5 days |
| Differential test harness | Compare verdicts vs vanilla KG | 200 | 2 days |
| **Total new code** | | **~4,900 LoC + 200 LoC Python** | **8–12 weeks** |

Within the 5,000-LoC budget.

### 10.2 Dependencies

- LLVM 13 (already in the project).
- Z3 (already in the project via KLEE).
- KLEE (already in the project) — used in feasibility-check phase.
- Optional: Clam (already in `dependencies/`) — for points-to and
  abstract-domain primitives.
- KrakenGuard's existing lifter and helper models.

### 10.3 Build integration

- New CMake targets under `lifting_tools/llvm_abs_analyzer/`,
  `lifting_tools/llvm_cegar_driver/`.
- New Python wrapper under `verification_tools/`.
- Opt-in via CLI flag `--cegar`. Default behavior reverts to vanilla
  KG pipeline.

### 10.4 Milestones

| # | Milestone | Exit criteria |
|---|---|---|
| 1 | Policy translator works | Unit tests pass on all policy files in `examples/` |
| 2 | Abstract domain primitives | PBT passes for join/meet/widen on random states |
| 3 | Transfer functions (arithmetic + branches) | PBT passes for these instruction classes |
| 4 | Transfer functions (memory + helpers + maps) | PBT passes; verifier handles a toy program end-to-end |
| 5 | Fixpoint engine | Single-pass analysis terminates on Katran in < 60 s |
| 6 | Counterexample stage | Spurious-CEX example produces correct refinement |
| 7 | End-to-end VALID demo | Katran w/ permissive policy returns VALID via abstract path (no KLEE invocation) |
| 8 | End-to-end INVALID demo | A modified Katran (with seeded violation) returns INVALID with concrete witness |
| 9 | Differential gate passing | Verdicts match vanilla KG on every program in `examples/` |
| 10 | Speedup target met | Geomean speedup ≥ 10× across eval set |
| 11 | bmc-cache demo | Returns VALID where vanilla KG crashes |

Milestones 1–6 are foundation; 7–9 prove correctness; 10–11 prove the
contribution.

---

## 11. Evaluation plan

### 11.1 Benchmark set

Reuse KrakenGuard's evaluation programs:
- Katran (with `constraints.full.json`, `constraints.selective_sym.json`)
- Electrode FAST_REPLY
- Electrode FAST_QUORUM_PRUNE
- hXDP firewall (`examples/fw`)
- Fluvia
- `xdp_fwd_kernel`, `xdp_tx_iptunnel`
- CVE examples (ekubelet-leak, rop.bpf, CVE-2022-23222 / 2020-8835 /
  2021-4204)
- **bmc-cache** (the failure case)

For each: run BOTH vanilla pipeline and `--cegar` pipeline.
Collect:
- Verdict (must match for soundness; bmc-cache is the exception where
  vanilla doesn't terminate)
- Wall time
- Number of refinement iterations
- Size of final `Π` (after refinement)
- Number of abstract states explored
- KLEE feasibility-check time vs full-KG time

### 11.2 Metrics and success criteria

| Metric | Target |
|---|---|
| Verdict match rate vs vanilla KG | 100% on terminating cases |
| Speedup geomean across eval set | ≥ 10× |
| Speedup on most permissive (Katran/full) | ≥ 100× |
| bmc-cache verdict produced | Yes (vanilla crashes) |
| CEGAR refinement iterations per program | ≤ 10 typical, ≤ 20 worst case |
| `|Π|` after refinement | ≤ 20 typical |

### 11.3 Comparison points

- KrakenGuard vanilla (paper baseline)
- `selective_packet_sym` with operator hints (existing pass — to be
  deprecated)
- ai_demo's Clam-based approach (to compare against)
- This work

### 11.4 Synthetic stress tests

Beyond KG's benchmarks, build synthetic programs to characterize:
- Programs with N policy-distinguishing branches (vary N from 1 to 20)
  to see when refinement explodes.
- Programs with M-depth nested infeasible branches to test refinement
  convergence speed.
- Programs with heavy floating-point or non-linear arithmetic (where
  Z3 may struggle).

---

## 12. Risks and mitigations

### 12.1 Soundness bug in abstract analyzer

**Risk:** Wrong transfer function or join produces false VALID.
**Mitigation:** §9 (differential + PBT + audit). Highest-priority
risk; mitigation must be rigorous.

### 12.2 CEGAR doesn't converge

**Risk:** Refinement adds predicates indefinitely without progress;
verifier loops.
**Mitigation:**
- Hard cap on refinement iterations (default 20).
- On hitting cap, fall back to vanilla KG on the full program for
  this (program, policy) pair. Sound, slower.
- Investigate: is the program's branching pattern inherently
  abstraction-hostile? If a class of programs always hits the cap,
  refine the cap logic or admit limitation in eval.

### 12.3 Z3 timeouts on feasibility checks

**Risk:** C(τ#) is too complex for Z3 in reasonable time; CEGAR stalls
on a single iteration.
**Mitigation:**
- Per-call timeout (default 60 s).
- On timeout, fall back to vanilla KG for this (program, policy).
- Long-term: replace Z3 with KLEE's path-condition machinery if it's
  more efficient on our specific formulas.

### 12.4 Helper model gap

**Risk:** A helper our abstract analyzer encounters has no transfer
function. Result: analyzer widens to `Top` at that call, loses
precision, refinement may fail to recover.
**Mitigation:**
- Inventory KrakenGuard's helper model coverage.
- Add abstract transfer functions for all helpers in the inventory.
- For unmodeled helpers: log warning, conservatively widen.

### 12.5 Differential gate finds discrepancies and we can't fix them

**Risk:** Some KG benchmark's vanilla verdict disagrees with our
verdict; we can't determine which is right.
**Mitigation:**
- Manual trace through the program to determine ground truth.
- If our verdict is wrong, fix the bug.
- If vanilla KG is wrong (rare, but KG has its own bugs), file a bug
  upstream and document in our eval.

### 12.6 bmc-cache doesn't actually demo well

**Risk:** Our abstract analyzer hits the same expression-size issue
KG's KLEE does (e.g., if our path-constraint construction also keeps
the full hash chain symbolic).
**Mitigation:**
- Architecturally, the abstract analyzer should NEVER materialize the
  full hash expression — under the bmc-cache permissive policy, the
  hash branch is policy-irrelevant. The analyzer merges both arms
  without forming the symbolic hash. Confirm by §14 prework
  experiment F.
- If confirmed: bmc-cache becomes a 1-iteration win.
- If not confirmed (architecture bug or unexpected dependency): bmc-cache
  drops out of the headline demo; we still have Katran-class speedups.

### 12.7 Implementation duration overruns

**Risk:** 8–12 week estimate slips badly.
**Mitigation:**
- Milestones 1–4 are gating: don't proceed if foundation is shaky.
- If milestone 7 isn't hit by week 6, reassess and consider falling
  back to Design B (which has working v1 design).

---

## 13. Open questions for discussion

The following need decisions, ideally before milestone 1:

1. **Framework choice for the abstract analyzer.**
   - **(a) Build on Clam.** Pros: existing in-repo, has points-to,
     interval, octagons. Cons: heavy dependency; we'd be adding
     predicate abstraction as a new domain. Maintenance burden.
   - **(b) Build on IKOS.** Pros: well-tested, modular. Cons: not in
     repo; new dependency.
   - **(c) Build from scratch.** Pros: minimal dependencies, exactly
     what we need. Cons: bigger LoC, less battle-testing.
   - **(d) Hybrid:** Use Clam for points-to and dataflow primitives,
     implement predicate abstraction on top.
   - Recommendation: **(d)**, but needs validation via prework experiment D.

2. **Refinement: unsat core vs Craig interpolation.**
   - Unsat-core is simpler; interpolation is more general. Both are in
     Z3.
   - Recommendation: start with unsat-core (easier debugging); migrate
     to interpolation if refinement count explodes.

3. **Feasibility check: KLEE vs custom symbolic executor.**
   - KLEE is heavy startup per invocation; custom is lighter but more
     LoC.
   - Recommendation: KLEE first (correctness via reuse); switch if
     overhead is dominant.

4. **Should the abstract domain include numeric (interval) primitives
   from day one?**
   - Policy-induced predicates are mostly boolean, so probably not.
   - But: programs that compute keys via arithmetic may need numeric
     tracking to refine usefully.
   - Recommendation: start boolean-only; add numeric if refinement
     reveals it's needed.

5. **How to handle loops?**
   - Standard answer: widening operator + invariants.
   - Without widening, loops may cause non-termination of the abstract
     fixpoint.
   - Recommendation: include widening from day one, even if the
     widening is naive (`Top` after N iterations).

6. **Indirect calls and tail calls.**
   - Function pointers in eBPF (via `bpf_tail_call` against
     `prog_array` maps) are a known precision-killer.
   - Recommendation: use Clam's points-to (or LLVM's BasicAA) to
     over-approximate target sets. If imprecise, widen.

7. **Differential gate scope.**
   - Run on every commit, or only on releases?
   - Recommendation: every commit to verifier-relevant code, with a
     fast subset (5–10 representative cases) on every CI run, and full
     suite nightly.

8. **What's "the operator's experience" for refinement?**
   - Do we expose `Π` after refinement to the operator?
   - Do we surface CEGAR iteration counts and times?
   - Recommendation: yes to both, behind a `--verbose` flag.

9. **Fallback policy when our pipeline gives up.**
   - Refinement cap hit, or Z3 timeout, or unsupported helper.
   - Fall back to vanilla KG, or report UNKNOWN?
   - Recommendation: fall back to vanilla KG with a warning. Operator
     sees a slow but correct verdict.

10. **Caching.**
    - Per the paper's open problem, can refined Π / abstract analysis
      results be cached across runs?
    - Recommendation: defer to V2. V1 doesn't cache.

---

## 14. Prework — experiments to validate the design before coding

The Design A claim is ambitious. Before committing 8–12 weeks of
engineering, do the following experiments. Each takes < 1 week. Total
prework: 2–3 weeks.

### Experiment A — Equivalence-class count across benchmark set

**Question:** Is the path-class collapse property (huge ratio of paths
to verdict equivalence classes) general across KG's benchmarks, or
specific to Katran?

**Method:**
- For each (program, policy) pair, parse the policy to count distinct
  predicates `|Π|`.
- Bound on verdict equivalence classes: `2^|Π|`. Note the actual count
  is typically smaller.
- Compare to KG's reported path count.

**Already-known:**
- Katran + `constraints.full.json`: |Π| = 0, classes = 1, paths
  = 16,110. Ratio 16,110:1.

**To do:**
- bmc-cache (constraints.json): |Π| = 0 confirmed, classes = 1.
  Vanilla KG path count not known (KLEE crashes). Estimate via partial
  run.
- Electrode FAST_REPLY: count |Π|. Paper says 21 paths.
- Electrode FAST_QUORUM_PRUNE: count |Π|. Paper says 77 paths.
- hXDP firewall: count |Π| for each fw policy variant.

**Stop sign:** if any benchmark has |Π| ≈ |branches|, the abstract
domain wouldn't help there and Design A is the wrong tool. Likely the
program needs a different abstraction or a different approach
(slicing, summarization).

**Effort:** 2–3 days, mostly Python on policy files + reading
KG's existing eval data.

### Experiment B — Single-path SMT cost via KLEE

**Question:** How expensive is one feasibility check per CEGAR
iteration? This bounds CEGAR iteration cost.

**Method:**
- Take Katran. Pick an arbitrary path through it (use one of the
  existing klee-out test cases).
- Force KLEE to follow only that path (via assumes that pin every
  branch decision).
- Measure KLEE wall time.

**Target:** < 5 s per path. If much higher, CEGAR with 10 refinement
iterations costs >> 50 s and may not beat vanilla KG.

**Effort:** 1 day.

### Experiment C — bmc-cache architecture compatibility

**Question:** Will our abstract analyzer actually skip the expensive
hash chain in bmc-cache, or will it inadvertently materialize it?

**Method:**
- Read bmc_kern.c's `bmc_hash_keys_main` carefully.
- Manually trace what the abstract analyzer would do given `Π_0 = ∅`.
- Confirm: at the hash loop, the analyzer sees no policy-relevant
  predicate to track over loop iterations. It should merge both arms
  of the inner branch, widen `hash` to `Top`, and continue. Hash
  expression never materializes.

**Stop sign:** if the analyzer materializes the hash (e.g., because
some predicate happens to depend on hash value), bmc-cache is the same
problem at the abstract level. Need to revisit.

**Effort:** 1 day, careful reading.

### Experiment D — Clam framework spike

**Question:** Can we cleanly add predicate abstraction as a new domain
to Clam? Or is the architecture cost prohibitive?

**Method:**
- Read Clam's domain interface.
- Spike a tiny predicate abstraction over 2–3 predicates on a 50-LoC
  toy program.
- Measure: integration complexity, generated artifacts, performance.

**Stop sign:** if Clam's domain interface is too rigid for our needs,
or the spike takes more than 3 days, fall back to building the
abstract analyzer from scratch (and absorb the LoC budget hit).

**Effort:** 3–5 days.

### Experiment E — Hand-craft refinement for tricky programs

**Question:** Does CEGAR refinement actually converge in a small number
of iterations on programs designed to stress it?

**Method:**
- Construct 5 toy programs with known unreachable violations of
  varying complexity:
  - Single dead branch (1 refinement expected)
  - Nested 3-deep dead branch (3 refinements expected)
  - Loop with invariant-bound infeasibility (1–2 refinements,
    depending on widening)
  - Function pointer to dead helper (1 refinement w/ good points-to)
  - Counter overflow infeasibility (numeric domain needed)
- For each, manually trace what predicates CEGAR should add.
- Verify the iteration count matches the design's claim.

**Stop sign:** if any toy program needs > 10 refinements, the
abstract domain isn't expressive enough; need richer predicates.

**Effort:** 3–5 days.

### Experiment F — Existing eBPF static analysis tools

**Question:** Has someone already built predicate abstraction over
eBPF that we can reuse?

**Method:**
- Survey: PREVAIL, MOAT, BeeGuard, Crab/IKOS for eBPF.
- For each: what predicates does it support? Could we reuse its
  analyzer?

**Stop sign:** if there's a clean reusable predicate-abstraction
implementation for eBPF, we should reuse rather than build. Re-evaluate
plan.

**Effort:** 2–3 days, mostly reading.

### Experiment G — Differential gate infrastructure

**Question:** Can we automate vanilla KG vs our pipeline comparison
across all benchmarks?

**Method:**
- Write the wrapper that runs both pipelines on a single (program,
  policy) and asserts verdict equality.
- Run on the eval set with both pipelines being vanilla KG (sanity
  check: should always agree).
- Measure: total wall time, output format, failure modes.

**Stop sign:** if the eval set takes > 8 hours to run vanilla KG on
all programs, CI integration is hard. Reduce scope or parallelize.

**Effort:** 2 days.

---

## 15. Stop signs (when to abandon Design A)

If any of the following happens, escalate and consider falling back to
Design B (policy-driven slicing + KLEE):

- **Experiment A:** any KG benchmark has |Π| ≈ |branches| (no equivalence
  collapse to exploit).
- **Experiment B:** single-path SMT cost > 30 s per check.
- **Experiment C:** bmc-cache will materialize hash chain abstractly.
- **Experiment D:** Clam spike fails AND from-scratch budget pushes us
  over 6,000 LoC.
- **Experiment E:** any toy program needs > 15 refinements.
- **Milestone 9:** differential gate finds verdict divergences we
  can't fix within 2 weeks.
- **Milestone 10:** speedup geomean < 5× on the eval set.

Each stop sign costs us time. The goal of doing prework first is to
hit them BEFORE the implementation budget is committed.

---

## 16. Relationship to existing repo passes

- `lifting_tools/llvm_policy_pass/` (policy-prune): function-level dead
  code elim based on policy. **Composes with this work** — run
  policy-prune first to shrink IR, then run abstract analyzer.
- `lifting_tools/llvm_selective_packet_sym/`: operator-trusted packet
  field concretization. **Deprecated by this work in the long term.**
  Short-term: keep available behind a flag while Design A matures.
- `examples/ai_demo/`: Clam-based AI hybrid with klee_assume injection.
  **Same family of approach as this work** but uses different
  integration model (assume injection vs verifier replacement). Lessons
  from `ai_demo/RESULTS.md` and `HEURISTIC.md` directly inform the
  refinement strategy and framework choice.
- `lifting_tools/llvm_func_pass/`, `llvm_ext_sym_pass/`,
  `llvm_clam_bridge/`: foundation passes. Reuse where appropriate.

---

## 17. Out-of-scope alternatives (for completeness)

These are not in this design, with explicit reasons:

- **Design B (BEA + KLEE + optional CEGAR).** Smaller soundness
  surface, smaller theoretical contribution. Documented in v1.
  Reconsidered if §15 stop signs are hit.
- **Pure operator hints with taint verification.** A safer-but-smaller
  contribution. Useful as a deprecation path for
  `selective_packet_sym`, not as the main paper.
- **Function summarization.** Orthogonal — addresses expression-size
  explosion. Separate work item. Combines with this design.
- **Policy mining / synthesis.** Different problem.
- **State merging in KLEE.** Engineering improvement to KLEE itself,
  not a new verifier. Lower theoretical contribution.

---

## 18. Summary

**What we're building.** A CEGAR-based eBPF policy verifier where the
abstract domain is predicate abstraction induced automatically by the
policy. The abstract analyzer is the primary verifier. KLEE is invoked
only on single abstract counterexamples for feasibility checks.
Refinement extracts new predicates from unsat cores.

**What we're getting.** Targeted 10–100× speedup on the KrakenGuard
evaluation set. Termination on bmc-cache (where SOTA crashes). A
genuine CEGAR architecture suitable for a theoretical-flagship paper.

**What we're risking.** A new verifier with a larger soundness surface
than vanilla KrakenGuard. Mitigated by mandatory differential testing,
property-based testing of every transfer function, and an
audit-and-fix discipline.

**What we're doing before coding.** Seven prework experiments (§14)
totaling 2–3 weeks. Each has a stop sign. We commit to the
implementation only after all green.

**Decision point.** §13's open questions need resolution before
milestone 1. §15's stop signs gate the project's continued investment
at every stage.

---

## Appendix A — Quick-reference glossary

- **CEGAR:** Counterexample-Guided Abstraction Refinement (Clarke et
  al. CAV '00).
- **Predicate abstraction:** Abstract domain whose elements are
  boolean valuations over a finite set of predicates (Graf & Saïdi '97).
- **`Π`:** The predicate set. `Π_0` = initial, derived from policy.
- **`D`:** The abstract domain. `|D| = 2^|Π|`.
- **`τ#`:** Abstract counterexample trace.
- **`C(τ#)`:** Concrete path constraint derived from τ#.
- **`α, γ`:** Abstraction and concretization functions forming a Galois
  connection.
- **BEA:** Branch-Equivalence Analyzer — the analyzer from Design B
  (v1). Not used in this design; mentioned for context.
- **Unsat core:** A minimal subset of an UNSAT formula's clauses that
  is itself UNSAT.
- **Craig interpolation:** Refinement technique that finds a small
  predicate "separating" two unsatisfiable parts of a trace.
