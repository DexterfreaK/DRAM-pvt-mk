#!/usr/bin/env bash
# Adversarial example A: per-byte branch loop.
# Builds LOOP_BOUND variants and runs DRACO/KLEE exhaustive symbolic execution,
# showing the verifier-accepted program does not terminate within a time limit.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

KLEE=/root/DRACO-pvt/klee/build/bin/klee
INCS="-I../headers/ -I/root/DRACO-pvt/examples/../ebpf-se/libbpf-stubbed/src/build/usr/include/ -I/root/DRACO-pvt/klee/include"
BPF_DEFS="-D__USE_VMLINUX__ -D__TARGET_ARCH_x86 -DBPF_NO_PRESERVE_ACCESS_INDEX -Wno-pointer-sign -Wno-compare-distinct-pointer-types -fno-builtin"

# (N, time-cap) pairs: small bounds run to completion, large ones hit the cap.
# NOTE: N=128 overruns its cap ~5x (single Z3 query is not preemptible), so it
# can run ~25 min despite the 300s limit -- expected, see RESULTS.md.
PAIRS="2:300s 4:300s 6:300s 8:90s 16:180s 32:180s 128:300s"

echo "== Half 1: in-kernel verifier check (needs root + xdp-loader) =="
clang-13 -target bpf -O2 -g -DLOOP_BOUND=32 -I../headers/ $BPF_DEFS -c main.c -o /tmp/perbyte_bpf.o \
  && ../../verification_tools/xdp-loader load -m skb lo /tmp/perbyte_bpf.o -vv 2>&1 | grep -iE 'Loaded|Attached|failed' \
  ; ../../verification_tools/xdp-loader unload lo --all 2>/dev/null

echo "== Half 2: DRACO/KLEE exhaustive symbolic execution sweep =="
for P in $PAIRS; do
  N="${P%%:*}"; T="${P##*:}"
  clang-13 -target bpf -DKLEE_VERIFICATION -DLOOP_BOUND=$N $INCS $BPF_DEFS \
    -O0 -emit-llvm -c -g main.c -o main_$N.bc 2>/dev/null
  /usr/bin/time -v $KLEE -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 \
    -libc=uclibc --external-calls=all --disable-verify -solver-backend=z3 -max-memory=750000 \
    -search=dfs -max-time=$T -output-dir=klee-out-$N main_$N.bc > log_$N.txt 2>&1
  echo "=== N=$N (cap $T) ==="
  grep -iE 'done: (total|completed|partially)|HaltTimer|wall clock' log_$N.txt
done
