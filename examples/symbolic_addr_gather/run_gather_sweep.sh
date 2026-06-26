#!/usr/bin/env bash
# Adversarial example C: symbolic-index gather.
# A verifier-accepted array-map pointer-chase with a CONSTANT path count of 2
# that DRACO/KLEE still cannot solve as CHAIN grows (solver-cost failure axis).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

KLEE=/root/DRACO-pvt/klee/build/bin/klee
INCS="-I../headers/ -I/root/DRACO-pvt/ebpf-se/libbpf-stubbed/src/build/usr/include/ -I/root/DRACO-pvt/klee/include"
BPF_DEFS="-D__USE_VMLINUX__ -D__TARGET_ARCH_x86 -DBPF_NO_PRESERVE_ACCESS_INDEX -Wno-pointer-sign -Wno-compare-distinct-pointer-types -fno-builtin"

echo "== Half 1: in-kernel verifier check (BTF-map variant, identical logic) =="
clang-13 -target bpf -O2 -g -DCHAIN=128 -I../headers/ -D__TARGET_ARCH_x86 \
  -fno-builtin -Wno-pointer-sign -c verify_btf.c -o /tmp/saddr_btf.o \
  && ../../verification_tools/xdp-loader unload lo --all 2>/dev/null \
  ; ../../verification_tools/xdp-loader load -m skb lo /tmp/saddr_btf.o -vv 2>&1 \
      | grep -iE 'Loaded XDP program xdp_main|Attached prog .xdp_main|Loaded 1 program|failed to load|invalid access' \
  ; ../../verification_tools/xdp-loader unload lo --all 2>/dev/null

echo "== Half 2: DRACO/KLEE sweep (path count stays 2; wall time runs away) =="
for N in 8 32 64 128; do
  clang-13 -target bpf -DKLEE_VERIFICATION -DCHAIN=$N $INCS $BPF_DEFS \
    -O0 -emit-llvm -c -g main.c -o main_$N.bc 2>/dev/null
  clang-13 -target bpf -DKLEE_VERIFICATION -DCHAIN=$N $INCS $BPF_DEFS \
    -O0 -emit-llvm -c -g do_gather.c -o do_gather_$N.bc 2>/dev/null
  llvm-link-14 main_$N.bc do_gather_$N.bc -o main_$N.bc
  /usr/bin/time -v $KLEE -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 \
    -libc=uclibc --external-calls=all --disable-verify -solver-backend=z3 -max-memory=750000 \
    -search=dfs -max-time=120s -output-dir=klee-out-$N main_$N.bc > log_$N.txt 2>&1
  echo "=== CHAIN=$N ==="
  grep -iE 'done: (total|completed|partially)|HaltTimer|wall clock' log_$N.txt
done
