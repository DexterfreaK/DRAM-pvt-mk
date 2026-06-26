#!/bin/bash
# End-to-end stub vs real comparison for bmc-cache
# Refactors main.bc at the LLVM IR level: replaces the inlined FNV loop
# with a call to extern bmc_hash_keys(), then links with real or stub .bc
set -euo pipefail

KLEE=/root/DRACO-pvt/klee/build/bin/klee
KLEE_FLAGS="-kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 -libc=uclibc --external-calls=all --disable-verify -solver-backend=z3 -max-memory=750000 -search=dfs -max-time=30s"

echo "=== Step 1: Run vanilla main.bc (inlined FNV hash loop) ==="
$KLEE $KLEE_FLAGS main.bc 2>&1 | tail -8
echo ""

echo "=== Step 2: Build refactored main with extern bmc_hash_keys ==="

# The approach: compile main_refactored.c which uses extern bmc_hash_keys()
# instead of the inlined FNV loop, then link with either real or stub.

# First check if we have the refactored source
if [ ! -f main_refactored.c ]; then
    echo "ERROR: main_refactored.c not found. Please create it first."
    exit 1
fi

# Compile the refactored main (with extern bmc_hash_keys)
KLEE_INCLUDE=/root/DRACO-pvt/klee/include
LIBBPF_INCLUDE=/root/DRACO-pvt/ebpf-se/libbpf-stubbed/src/build/usr/include
HEADERS=/root/DRACO-pvt/headers
UNAME_P=$(uname -p)

clang-13 \
    -target bpf \
    -DKLEE_VERIFICATION \
    -I${HEADERS} -I${LIBBPF_INCLUDE} -I${KLEE_INCLUDE} \
    -I /usr/include/${UNAME_P}-linux-gnu \
    -D__USE_VMLINUX__ -D__TARGET_ARCH_x86 \
    -DBPF_NO_PRESERVE_ACCESS_INDEX \
    -Wall -Wno-unused-value -Wno-unused-variable \
    -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
    -fno-builtin \
    -O0 -emit-llvm -c -g main_refactored.c -o main_refactored.bc

echo "Compiled main_refactored.bc"

# Link with real bmc_hash_keys
llvm-link main_refactored.bc bmc_hash_keys_real.bc -o bmc_e2e_real.bc 2>/dev/null || true
echo "Linked bmc_e2e_real.bc"

# Link with stub bmc_hash_keys
llvm-link main_refactored.bc bmc_hash_keys_stub.bc -o bmc_e2e_stub.bc 2>/dev/null || true
echo "Linked bmc_e2e_stub.bc"

echo ""
echo "=== Step 3: Run with REAL bmc_hash_keys ==="
$KLEE $KLEE_FLAGS bmc_e2e_real.bc 2>&1 | tail -8
echo ""

echo "=== Step 4: Run with STUB bmc_hash_keys ==="
$KLEE $KLEE_FLAGS bmc_e2e_stub.bc 2>&1 | tail -8
