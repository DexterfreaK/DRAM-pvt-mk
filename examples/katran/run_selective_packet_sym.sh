#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"

export PATH="/root/DRACO-pvt/klee/build/bin:$PATH"
PASS_LIB="/root/DRACO-pvt/lifting_tools/llvm_selective_packet_sym/build/libselective_packet_sym.so"
MAX_TIME=${MAX_TIME:-180}
SRC=katran.c
BC=katran.bc
LL=katran.ll

RESULTS_FILE="selective_packet_sym_results.md"
: > "$RESULTS_FILE"

run_one() {
    local mode="$1"
    local logfile="$2"

    cp constraints.selective_sym.json constraints.json

    clang-13 -target bpf -DKLEE_VERIFICATION -DVERIFY_INTERACTIONS \
        -I/root/DRACO-pvt/headers/ -I/usr/include/x86_64-linux-gnu \
        -I/root/DRACO-pvt/ebpf-se/libbpf-stubbed/src/build/usr/include/ \
        -I/root/DRACO-pvt/klee/include \
        -D__USE_VMLINUX__ -D__TARGET_ARCH_x86 -DBPF_NO_PRESERVE_ACCESS_INDEX \
        -Wno-unused-value -Wno-unused-variable -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types -fno-discard-value-names \
        -fno-builtin -O0 -emit-llvm -c -g "$SRC" -o "$BC" 2>>"$logfile"
    local rc_c=$?
    if [[ $rc_c -ne 0 ]]; then
        echo "BUILD_ERR|0|?|?"
        return
    fi

    if [[ "$mode" == "rewritten" ]]; then
        opt -load "$PASS_LIB" -load-pass-plugin="$PASS_LIB" \
            -passes=selective-packet-sym \
            -packet-policy-spec="$(pwd)/constraints.json" \
            -packet-irrelevance-spec="$(pwd)/irrelevant_packet_items.selective_sym.json" \
            "$BC" -o "$BC" >>"$logfile" 2>&1
    fi

    llvm-dis "$BC" -o "$LL" 2>>"$logfile"
    local ll_lines
    ll_lines=$(wc -l < "$LL")

    rm -rf klee-out-*
    timeout "${MAX_TIME}" \
        klee -kdalloc -kdalloc-heap-start-address=0x00040000000 \
             -kdalloc-heap-size=1 -libc=uclibc --external-calls=all \
             --disable-verify -solver-backend=z3 -silent-klee-assume=true \
             -max-memory=750000 -search=dfs \
             -single-object-resolution=true -verification=true \
             -read-set=true -write-set=true -map-correlation=true \
             -restrict-helper-function=true -enable-map-access-control=true \
             -enable-packet-constr=true \
             -config-file="$(pwd)/constraints.json" \
             -max-time="${MAX_TIME}" -watchdog \
             "$BC" >>"$logfile" 2>&1
    local rc=$?

    local verdict="UNKNOWN"
    if grep -q "Map Access control : VALID" "$logfile"; then
        verdict="VALID"
    elif grep -q "Map Access control condition violated" "$logfile"; then
        verdict="INVALID"
    elif [[ $rc -eq 124 ]]; then
        verdict="TIMEOUT"
    else
        verdict="ERROR(rc=$rc)"
    fi

    local paths insns
    paths=$(grep -oP "^KLEE: done: completed paths = \\K[0-9]+" "$logfile" | tail -1)
    insns=$(grep -oP "^KLEE: done: total instructions = \\K[0-9]+" "$logfile" | tail -1)
    paths=${paths:-?}
    insns=${insns:-?}
    echo "$verdict|$ll_lines|$paths|$insns"
}

blog="log_selective_sym_baseline.txt"
rlog="log_selective_sym_rewritten.txt"
: > "$blog"; : > "$rlog"

echo ">>> baseline"
IFS='|' read -r b_verdict b_lines b_paths b_insns < <(run_one baseline "$blog")

echo ">>> rewritten"
IFS='|' read -r r_verdict r_lines r_paths r_insns < <(run_one rewritten "$rlog")

match="YES"
[[ "$b_verdict" != "$r_verdict" ]] && match="**NO (FP/FN)**"

echo "| Mode | Verdict | IR lines | Completed paths | Total instructions |" >> "$RESULTS_FILE"
echo "|---|---|---:|---:|---:|" >> "$RESULTS_FILE"
echo "| baseline | $b_verdict | $b_lines | $b_paths | $b_insns |" >> "$RESULTS_FILE"
echo "| rewritten | $r_verdict | $r_lines | $r_paths | $r_insns |" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "Match: $match" >> "$RESULTS_FILE"

cat "$RESULTS_FILE"
