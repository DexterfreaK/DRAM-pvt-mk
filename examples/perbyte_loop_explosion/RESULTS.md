# Adversarial example A — per-byte branch loop

**Claim demonstrated:** a program the **in-kernel eBPF verifier accepts** can drive
DRACO/KrakenGuard's exhaustive symbolic execution into **exponential path
explosion**, so the analysis does *not* terminate within a time limit and
KrakenGuard — by its own conservative design — would **reject a safe program**.

This is a direct counterexample to the load-bearing assumption in the NSDI'26 /
eBPF'24 paper:

> "passing the kernel verifier already ensures the lack of path explosion"
> "DRACO uses exhaustive symbolic execution to reason about eBPF programs that
>  are guaranteed to terminate, given that the in-kernel verifier has already
>  accepted the programs under analysis."

The two analyses have different cost models. The verifier abstracts each register
as a tnum (known-bits) + min/max interval and **prunes/merges** already-visited
abstract states, so a loop that branches on each byte costs it only a bounded
number of abstract states. KLEE **forks on every symbolic branch and never
merges**, so the same loop is `~3^N` paths.

## The program (`main.c`)

A single bounded XDP loop, no maps, no tail calls — the distilled essence of the
`bmc-cache` hash-keys loop that had to be hand-trimmed to make DRACO terminate:

```c
for (int i = 0; i < LOOP_BOUND && payload + i + 1 <= data_end; i++) {
    char c = payload[i];
    if (c == '\r')      break;        // sentinel -> distinct break path at each i
    else if (c == ' ')  matches++;    // whitespace branch
    else { hash ^= (unsigned char)c; hash *= FNV_PRIME_32; }  // byte-dependent
}
if (hash % 1000u == matches) return XDP_DROP;
```

Every iteration forks symbolic state 3 ways; the `break` also spawns a distinct
terminating path at each `i`. `LOOP_BOUND` is a compile-time constant and every
read is guarded by `data_end`, so the program is verifier-legal.

## Half 1 — the in-kernel verifier ACCEPTS it

```
$ clang-13 -target bpf -O2 -DLOOP_BOUND=32 ... -c main.c -o perbyte_bpf.o
$ xdp-loader load -m skb lo perbyte_bpf.o -vv
  libxdp: Loaded XDP program xdp_main, got fd 9
  libxdp: Attached prog 'xdp_main' ... in dispatcher entry 'prog0'
  libxdp: Loaded 1 programs on ifindex 1 in skb mode      <-- verifier PASSED
```

BPF asm confirms the canonical shape: constant loop bound (`if r5 != 32`),
per-iteration `data_end` guard (`if r6 > r3`), guarded byte loads (`ldxb`),
branches on `'\r'`(13) and `' '`(32).

## Half 2 — DRACO/KLEE exhaustive symbolic execution EXPLODES

`klee -search=dfs -max-memory=750000 -max-time=<cap> main_<N>.bc`

| N (loop bound) | completed paths | partial paths | wall time | terminated? |
|---:|---:|---:|---:|:--|
| 2  | 8   | 0  | 0.39 s     | yes |
| 4  | 47  | 0  | 3.1 s      | yes |
| 6  | 226 | 0  | 17.0 s     | yes |
| 8   | 833 | 12  | 90 s (cap)   | **NO — HaltTimer** |
| 16  | 316 | 28  | 180 s (cap)  | **NO — HaltTimer** |
| 32  | 74  | 57  | 180 s (cap)  | **NO — HaltTimer** |
| 128 | 0   | 254 | 1483 s (!!)  | **NO — HaltTimer, overran 300 s cap ~5×** |

Reading the curve:

- N=2,4,6 terminate (`partial = 0`) — the program is **finite**, so this is path
  explosion, not an unbounded loop. Path count `8 → 47 → 226` grows ~exponentially.
- N>=8 never terminate within the budget: `partial paths > 0` + `HaltTimer`.
- N=32 completes **fewer** paths (74) than N=8/16 in *more* time, because DFS
  dives into deep paths whose FNV-hash constraint chains are very expensive to
  solve — throughput collapses as the bound grows.
- N=128 completes **zero** paths: in ~25 min KLEE could not drive a single path
  to completion. Total instructions actually *drop* (9263) because nearly all
  wall-time is spent inside the SMT solver, not stepping bytecode.

Under KrakenGuard's "reject if analysis does not terminate within the time limit"
policy, **every N>=8 case is a false rejection of a verifier-accepted program.**
A 32-byte parse loop is utterly ordinary in real XDP code.

## Two distinct failure modes — and the time limit itself leaks

This one program exhibits **two** different reasons exhaustive symbolic execution
fails, depending on the bound:

1. **Path explosion** (N=8–32): the path count is exponential; KLEE times out
   with many partially-completed paths.
2. **Solver intractability** (N=128): the bottleneck shifts from *number of paths*
   to *cost per query*. Each deep path carries 128 chained nonlinear
   `hash *= FNV_PRIME_32` multiplies over symbolic bytes — pathological for Z3.

The N=128 run also exposes a subtler, sharper point: **`-max-time` is not
reliably enforceable.** The cap was 300 s, but the run took **1483 s** — a ~5×
overrun. KLEE checks `HaltTimer` *between* operations and cannot preempt an
in-flight solver query; with nonlinear constraints, a *single* Z3 query ran for
~24 minutes before returning, and only then did KLEE notice the deadline.

Consequence for KrakenGuard's design: its safety story implicitly assumes that if
exhaustive symbolic execution doesn't finish, the time limit at least bounds the
cost (so "reject after T seconds" returns in ~T seconds). It does not. A single
un-preemptible nonlinear query can overrun the deadline by multiples, so the
conservative-timeout policy cannot actually promise the liveness bound it relies
on. The deadline leaks.

## Reproduce

```
./run_explosion_sweep.sh          # builds the LOOP_BOUND variants + runs the sweep
```
