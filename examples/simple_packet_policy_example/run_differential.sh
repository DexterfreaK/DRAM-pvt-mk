#!/usr/bin/env bash
# Differential KLEE harness for policy-prune on simple_packet_policy_example.
# Detects BOTH map-access and packet-access violation signals.
# Every spec must produce matching verdicts baseline vs pruned.

set -u
cd "$(dirname "$0")"

export PATH="/root/DRACO-pvt/klee/build/bin:$PATH"
PASS_LIB="/root/DRACO-pvt/lifting_tools/llvm_policy_pass/build/libpolicy_pass.so"
MAX_TIME=${MAX_TIME:-60}
SRC=main.c
BC=main.bc
LL=main.ll

RESULTS_FILE="differential_results.md"
: > "$RESULTS_FILE"

detect_verdict() {
    local logfile="$1"
    local rc="$2"
    # Prefer most-specific violation signals
    if   grep -q "Trying edit prohibited packet fields" "$logfile"; then echo "INVALID(pkt-write)"
    elif grep -q "Trying read prohibited packet fields" "$logfile"; then echo "INVALID(pkt-read)"
    elif grep -q "Map Access control condition violated" "$logfile"; then echo "INVALID(map)"
    elif grep -q "Map Access control : VALID" "$logfile"; then echo "VALID"
    elif [[ $rc -eq 124 ]]; then echo "TIMEOUT"
    else echo "ERROR(rc=$rc)"
    fi
}

run_one() {
    local mode="$1"
    local spec="$2"
    local logfile="$3"

    cp "$spec" constraints.json

    clang-13 -target bpf -DKLEE_VERIFICATION -DVERIFY_INTERACTIONS \
        -I/root/DRACO-pvt/headers/ -I/usr/include/x86_64-linux-gnu \
        -I/root/DRACO-pvt/ebpf-se/libbpf-stubbed/src/build/usr/include/ \
        -I/root/DRACO-pvt/klee/include \
        -D__USE_VMLINUX__ -D__TARGET_ARCH_x86 -DBPF_NO_PRESERVE_ACCESS_INDEX \
        -Wno-unused-value -Wno-unused-variable -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types -fno-discard-value-names \
        -fno-builtin -O0 -emit-llvm -c -g "$SRC" -o "$BC" 2>>"$logfile"

    if [[ "$mode" == "pruned" ]]; then
        opt -load "$PASS_LIB" -load-pass-plugin="$PASS_LIB" \
            -passes=policy-prune,globaldce,dce,simplifycfg \
            -policy-spec="$(pwd)/constraints.json" \
            "$BC" -o "$BC" >>"$logfile" 2>&1
    fi

    local ll_lines
    llvm-dis "$BC" -o "$LL" 2>>"$logfile"
    ll_lines=$(wc -l < "$LL")

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

    local verdict
    verdict=$(detect_verdict "$logfile" "$rc")
    echo "$verdict|$ll_lines"
}

echo "| Spec | Baseline verdict | Pruned verdict | Match | Baseline IR | Pruned IR |" >> "$RESULTS_FILE"
echo "|---|---|---|---|---|---|" >> "$RESULTS_FILE"

for spec in policy_Q*.json; do
    bname=$(basename "$spec" .json)
    blog="log_${bname}_baseline.txt"
    plog="log_${bname}_pruned.txt"
    : > "$blog"; : > "$plog"

    echo ">>> $spec (baseline)"
    IFS='|' read -r b_verdict b_lines < <(run_one baseline "$spec" "$blog")

    echo ">>> $spec (pruned)"
    IFS='|' read -r p_verdict p_lines < <(run_one pruned "$spec" "$plog")

    match="YES"
    [[ "$b_verdict" != "$p_verdict" ]] && match="**NO (FP/FN)**"

    echo "| $bname | $b_verdict | $p_verdict | $match | $b_lines | $p_lines |" >> "$RESULTS_FILE"
    echo "  -> baseline=$b_verdict, pruned=$p_verdict, match=$match"
done

echo ""
cat "$RESULTS_FILE"
