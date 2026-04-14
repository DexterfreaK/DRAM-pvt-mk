#!/usr/bin/env bash
# Differential KLEE harness for policy-prune on fw example.
# Each policy_F*.json: runs baseline (no pass) and pruned (pass applied)
# and checks verdicts match.

set -u
cd "$(dirname "$0")"

export PATH="/root/DRACO-pvt/klee/build/bin:$PATH"
PASS_LIB="/root/DRACO-pvt/lifting_tools/llvm_policy_pass/build/libpolicy_pass.so"
MAX_TIME=${MAX_TIME:-120}
SRC=fw.c
BC=fw.bc
LL=fw.ll

RESULTS_FILE="differential_results.md"
: > "$RESULTS_FILE"

run_one() {
    local mode="$1"
    local spec="$2"
    local logfile="$3"
    local ir_lines_var="$4"

    cp "$spec" constraints.json

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
        eval "$ir_lines_var=0"
        echo "BUILD_ERR|0|?"
        return
    fi

    if [[ "$mode" == "pruned" ]]; then
        opt -load "$PASS_LIB" -load-pass-plugin="$PASS_LIB" \
            -passes=policy-prune,globaldce,dce,simplifycfg \
            -policy-spec="$(pwd)/constraints.json" \
            "$BC" -o "$BC" >>"$logfile" 2>&1
    fi

    local ll_lines
    llvm-dis "$BC" -o "$LL" 2>>"$logfile"
    ll_lines=$(wc -l < "$LL")
    eval "$ir_lines_var=$ll_lines"

    rm -rf klee-out-*
    timeout "${MAX_TIME}" \
        klee -kdalloc -kdalloc-heap-start-address=0x00040000000 \
             -kdalloc-heap-size=1 -libc=uclibc --external-calls=all \
             --disable-verify -solver-backend=z3 -silent-klee-assume=true \
             --exit-on-error -max-memory=750000 -search=dfs \
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

    local paths
    paths=$(grep -oP "completed paths = \K[0-9]+" "$logfile" | tail -1)
    paths=${paths:-?}

    echo "$verdict|$ll_lines|$paths"
}

echo "| Spec | Baseline verdict | Pruned verdict | Match | Baseline IR | Pruned IR | Baseline paths | Pruned paths |" >> "$RESULTS_FILE"
echo "|---|---|---|---|---|---|---|---|" >> "$RESULTS_FILE"

for spec in policy_F*.json; do
    bname=$(basename "$spec" .json)
    blog="log_${bname}_baseline.txt"
    plog="log_${bname}_pruned.txt"
    : > "$blog"; : > "$plog"

    echo ">>> Running spec $spec (baseline)"
    b_ir=0
    IFS='|' read -r b_verdict b_lines b_paths < <(run_one baseline "$spec" "$blog" b_ir)

    echo ">>> Running spec $spec (pruned)"
    p_ir=0
    IFS='|' read -r p_verdict p_lines p_paths < <(run_one pruned "$spec" "$plog" p_ir)

    match="YES"
    [[ "$b_verdict" != "$p_verdict" ]] && match="**NO (FP/FN)**"

    echo "| $bname | $b_verdict | $p_verdict | $match | $b_lines | $p_lines | $b_paths | $p_paths |" >> "$RESULTS_FILE"
    echo "  -> baseline=$b_verdict (ir=$b_lines, paths=$b_paths), pruned=$p_verdict (ir=$p_lines, paths=$p_paths), match=$match"
done

echo ""
echo "Results written to $RESULTS_FILE"
cat "$RESULTS_FILE"
