#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
export PATH="/root/DRACO-pvt/klee/build/bin:$PATH"
PASS_LIB="/root/DRACO-pvt/lifting_tools/llvm_selective_packet_sym/build/libselective_packet_sym.so"
CAP=2400
POLICY=constraints.full.json
SRC=katran.c BC=katran.bc LL=katran.ll
RESULTS=sweep_x3_results.md
: > "$RESULTS"

run_one() {
    local label="$1" irrel="$2" logfile="$3"
    cp "$POLICY" constraints.json
    : > "$logfile"
    clang-13 -target bpf -DKLEE_VERIFICATION -DVERIFY_INTERACTIONS \
        -I/root/DRACO-pvt/headers/ -I/usr/include/x86_64-linux-gnu \
        -I/root/DRACO-pvt/ebpf-se/libbpf-stubbed/src/build/usr/include/ \
        -I/root/DRACO-pvt/klee/include \
        -D__USE_VMLINUX__ -D__TARGET_ARCH_x86 -DBPF_NO_PRESERVE_ACCESS_INDEX \
        -Wno-unused-value -Wno-unused-variable -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types -fno-discard-value-names \
        -fno-builtin -O0 -emit-llvm -c -g "$SRC" -o "$BC" 2>>"$logfile" || { echo "BUILD_ERR"; return; }
    [[ -n "$irrel" ]] && opt -load "$PASS_LIB" -load-pass-plugin="$PASS_LIB" \
        -passes=selective-packet-sym -packet-policy-spec="$(pwd)/constraints.json" \
        -packet-irrelevance-spec="$(pwd)/$irrel" "$BC" -o "$BC" >>"$logfile" 2>&1
    llvm-dis "$BC" -o "$LL" 2>>"$logfile"
    local ll_lines; ll_lines=$(wc -l < "$LL")
    rm -rf klee-out-*
    local t0 t1 elapsed_ms rc
    t0=$(date +%s%3N)
    timeout "$CAP" klee -kdalloc -kdalloc-heap-start-address=0x00040000000 \
        -kdalloc-heap-size=1 -libc=uclibc --external-calls=all \
        --disable-verify -solver-backend=z3 -silent-klee-assume=true \
        -max-memory=750000 -search=dfs -single-object-resolution=true \
        -verification=true -read-set=true -write-set=true -map-correlation=true \
        -restrict-helper-function=true -enable-map-access-control=true \
        -enable-packet-constr=true -config-file="$(pwd)/constraints.json" \
        "$BC" >>"$logfile" 2>&1
    rc=$?; t1=$(date +%s%3N); elapsed_ms=$((t1 - t0))
    local verdict="UNKNOWN"
    if grep -q "Map Access control : VALID" "$logfile"; then verdict="VALID"
    elif [[ $rc -eq 124 ]]; then verdict="TIMEOUT"
    elif [[ $rc -eq 137 ]]; then verdict="OOM_KILL"
    elif [[ $rc -eq 143 ]]; then verdict="SIGTERM"
    else verdict="ERR(rc=$rc)"; fi
    local paths partial insns
    paths=$(grep -oP "^KLEE: done: completed paths = \K[0-9]+" "$logfile" | tail -1)
    partial=$(grep -oP "^KLEE: done: partially completed paths = \K[0-9]+" "$logfile" | tail -1)
    insns=$(grep -oP "^KLEE: done: total instructions = \K[0-9]+" "$logfile" | tail -1)
    echo "$verdict|$ll_lines|${paths:-?}|${partial:-?}|${insns:-?}|$elapsed_ms"
}

echo "| Case | Verdict | IR lines | Completed | Partial | Instructions | Wall ms |" | tee -a "$RESULTS"
echo "|---|---|---:|---:|---:|---:|---:|" | tee -a "$RESULTS"

for c in "tcp_safe|irrel.x_tcp_safe.json" "proto_plus_tcp_safe|irrel.x_proto_plus_tcp_safe.json"; do
    IFS='|' read -r label irrel <<<"$c"
    logfile="log_x3_${label}.txt"
    echo ">>> $label" >&2
    set +e
    out=$(run_one "$label" "$irrel" "$logfile")
    set -e
    IFS='|' read -r verdict lines completed partial insns ms <<<"$out"
    echo "| $label | $verdict | $lines | $completed | $partial | $insns | $ms |" | tee -a "$RESULTS"
done
