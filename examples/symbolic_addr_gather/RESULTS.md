# Adversarial example C — symbolic-index gather (a 2-path program KLEE can't solve)

**Claim demonstrated:** exhaustive symbolic execution can fail on a
verifier-accepted eBPF program **even when there is no path explosion at all.**
This program has a *constant* path count of **2**, yet KLEE/DRACO cannot finish
analyzing it. The failure axis is **per-query solver cost**, not the number of
paths — an axis KrakenGuard's "passing the verifier ensures no path explosion"
argument does not address.

This is conceptually distinct from `perbyte_loop_explosion` (#A), whose failure
is path-count explosion (~3^N forked states from data-dependent branches).

## Mechanism

A bounded loop chases pointers through a 256-entry array map whose contents are
symbolic: `idx = table[idx]`, repeated `CHAIN` times, seeded by one packet byte.

```c
unsigned int idx = p[0] & 255;        // symbolic start index
for (int i = 0; i < CHAIN; i++) {
    unsigned int *v = bpf_map_lookup_elem(&table, &idx);  // symbolic index
    if (!v) return XDP_PASS;          // verifier-required null check
    idx = (*v) & 255;                 // loaded value -> next index
    acc ^= idx;
}
if (acc == 0x42) return XDP_DROP;     // the ONLY data branch
```

- No branch in the loop body depends on table contents, so the program has just
  **2 control-flow paths** (the final `acc == 0x42`).
- KLEE does **not** fork an in-object symbolic index; it builds a symbolic
  array-select expression. Chaining `CHAIN` lookups nests `CHAIN` levels of
  256-way selects over a symbolic table. The SMT solver (Z3) cannot untangle a
  deep enough nest.

(Note: an array map is used rather than direct `p[idx]` packet indexing because
the kernel verifier rejects masked variable offsets into packet data —
`invalid access to packet`. Variable-key *array-map* lookups are verifier-legal.)

## Half 1 — the in-kernel verifier ACCEPTS it

The legacy `bpf_map_def` form required by the KLEE stubs cannot be loaded by
libbpf v1.0+ (legacy "maps" section — a tooling limitation, not a safety one), so
`verify_btf.c` holds the *identical logic* with modern BTF map syntax:

```
$ clang-13 -target bpf -O2 -DCHAIN=128 ... -c verify_btf.c -o saddr_btf.o
$ xdp-loader load -m skb lo saddr_btf.o -vv
  libxdp: Loaded XDP program xdp_main, got fd 10
  libxdp: Attached prog 'xdp_main' ... dispatcher entry 'prog0'
  libxdp: Loaded 1 programs on ifindex 1 in skb mode      <-- verifier PASSED (CHAIN=128)
```

## Half 2 — DRACO/KLEE cannot solve it (with a CONSTANT path count of 2)

`klee -search=dfs -max-memory=750000 -max-time=120s main_<CHAIN>.bc`

| CHAIN | completed paths | partial | wall time   | terminated? |
|---:|---:|---:|---:|:--|
| 8   | 2 | 0 | 0.16 s      | yes |
| 32  | 2 | 0 | 0.91 s      | yes |
| 64  | 2 | 0 | 38.3 s      | yes |
| 128 | 0 | 1 | 120 s (cap) | **NO — HaltTimer** |

Reading the curve:

- The path count is **pinned at 2** the entire time — this is categorically not
  path explosion.
- Wall time still goes `0.16 → 0.91 → 38.3 → timeout`. The growth is entirely in
  the cost of solving one path's nested-select constraint.
- At CHAIN=128 KLEE completed **zero** paths: it could not finish solving even
  **one** of the two paths within 120 s. Instruction count is tiny (11351) —
  almost all wall-time is inside Z3.

## Why this matters for KrakenGuard

"Few branches ⇒ easy to verify" is false. KrakenGuard's tractability rests on
path count (bounded by the kernel verifier), but symbolic execution has a second,
independent cost axis: **the size/shape of the symbolic expressions handed to the
SMT solver.** A verifier-legal array-map gather — an utterly ordinary lookup-table
pattern — produces deep nested selects that defeat the solver while generating
only two paths. The verifier's loop bound says nothing about this, so a safe
program is rejected (timeout) for reasons the load-bearing assumption never
considered.

Together with `perbyte_loop_explosion` (#A) this gives two *independent* ways a
verifier-accepted program breaks exhaustive symbolic execution:
| failure axis | example | symptom |
|---|---|---|
| path-count explosion | #A (per-byte branches) | many forked states, timeout with large `partial` |
| solver intractability | #C (symbolic-index gather) | 2 paths, timeout solving a single path |

## Reproduce

```
./run_gather_sweep.sh
```
