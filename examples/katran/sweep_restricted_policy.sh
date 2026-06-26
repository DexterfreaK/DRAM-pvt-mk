#!/usr/bin/env bash
# Re-run the selective_packet_sym sweep under a RESTRICTED policy (sIP pinned to
# 12345), which makes sIP policy-relevant and exercises the pass's relevance guard.
# Mirrors sweep_selective_sym.sh's KLEE flags exactly.
set -u
cd "$(dirname "$0")"

export PATH="/root/DRACO-pvt/klee/build/bin:$PATH"
PASS_LIB="/root/DRACO-pvt/lifting_tools/llvm_selective_packet_sym/build/libselective_packet_sym.so"

CAP=${CAP:-600}
# Restricted policy: sIP="12345", wide access 0-1500 (relaxed variant).
POLICY=${POLICY:-constraints.selective_sym.relaxed.json}

SRC=katran.c
BC=katran.bc
LL=katran.ll
RESULTS=${RESULTS:-sweep_restricted_results.md}
: > "$RESULTS"

build_bc() {
    clang-13 -target bpf -DKLEE_VERIFICATION -DVERIFY_INTERACTIONS \
        -I/root/DRACO-pvt/headers/ -I/usr/include/x86_64-linux-gnu \
        -I/root/DRACO-pvt/ebpf-se/libbpf-stubbed/src/build/usr/include/ \
        -I/root/DRACO-pvt/klee/include \
        -D__USE_VMLINUX__ -D__TARGET_ARCH_x86 -DBPF_NO_PRESERVE_ACCESS_INDEX \
        -Wno-unused-value -Wno-unused-variable -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types -fno-discard-value-names \
        -fno-builtin -O0 -emit-llvm -c -g "$SRC" -o "$BC" 2>>"$1"
}

run_one() {
    local label="$1" irrel="$2" logfile="$3"
    cp "$POLICY" constraints.json
    : > "$logfile"
    build_bc "$logfile" || { echo "$label|BUILD_ERR|0|?|?|?|?|0"; return; }

    local guard="-"
    if [[ -n "$irrel" ]]; then
        opt -load "$PASS_LIB" -load-pass-plugin="$PASS_LIB" \
            -passes=selective-packet-sym \
            -packet-policy-spec="$(pwd)/constraints.json" \
            -packet-irrelevance-spec="$(pwd)/$irrel" \
            "$BC" -o "$BC" >>"$logfile" 2>&1
        grep -q "keeping policy-relevant field symbolic" "$logfile" && guard="GUARD-FIRED"
    fi

    llvm-dis "$BC" -o "$LL" 2>>"$logfile"
    local ll_lines; ll_lines=$(wc -l < "$LL")

    rm -rf klee-out-*
    local t0 t1; t0=$(date +%s%3N)
    timeout "$CAP" \
        klee -kdalloc -kdalloc-heap-start-address=0x00040000000 \
             -kdalloc-heap-size=1 -libc=uclibc --external-calls=all \
             --disable-verify -solver-backend=z3 -silent-klee-assume=true \
             -max-memory=750000 -search=dfs \
             -single-object-resolution=true -verification=true \
             -read-set=true -write-set=true -map-correlation=true \
             -restrict-helper-function=true -enable-map-access-control=true \
             -enable-packet-constr=true \
             -config-file="$(pwd)/constraints.json" \
             "$BC" >>"$logfile" 2>&1
    local rc=$?; t1=$(date +%s%3N)
    local elapsed_ms=$((t1 - t0))

    # Check enforcement terminations BEFORE the always-printed "VALID" banner.
    local nread nwrite
    nread=$(grep -c "Trying read prohibited packet fields" "$logfile")
    nwrite=$(grep -c "Trying edit prohibited packet fields" "$logfile")
    local verdict="UNKNOWN"
    if [[ $rc -eq 124 ]]; then verdict="TIMEOUT"
    elif [[ $rc -eq 137 ]]; then verdict="OOM_KILL"
    elif [[ $rc -eq 143 ]]; then verdict="SIGTERM"
    elif [[ $nread -gt 0 ]]; then verdict="PKT-READ-PROHIBITED(x$nread)"
    elif [[ $nwrite -gt 0 ]]; then verdict="PKT-WRITE-PROHIBITED(x$nwrite)"
    elif grep -q "Map Access control condition violated" "$logfile"; then verdict="INVALID(map)"
    elif grep -q "Map Access control : VALID" "$logfile"; then verdict="VALID"
    else verdict="ERR(rc=$rc)"; fi

    # Anchor regexes so "partially completed paths" doesn't masquerade as "completed paths".
    local paths partial insns
    paths=$(grep -oP "^KLEE: done: completed paths = \K[0-9]+" "$logfile" | tail -1)
    partial=$(grep -oP "^KLEE: done: partially completed paths = \K[0-9]+" "$logfile" | tail -1)
    insns=$(grep -oP "^KLEE: done: total instructions = \K[0-9]+" "$logfile" | tail -1)
    echo "$label|$verdict|$ll_lines|${paths:-?}|${partial:-?}|${insns:-?}|$elapsed_ms|$guard"
}

CASES=(
  "baseline:none|"
  "protocol|irrel.proto.json"
  "dPort|irrel.dPort.json"
  "dIP|irrel.dIP.json"
  "sIP (relevant->guard)|irrel.sIP.json"
  "sIP+dPort|irrel.sIP_dPort.json"
)

echo "RESTRICTED policy: $POLICY  (sIP=12345 pinned, outer cap=${CAP}s)" | tee -a "$RESULTS"
echo "" | tee -a "$RESULTS"
echo "| Case | Verdict | IR lines | Completed | Partial | Instructions | Wall ms | Pass guard |" | tee -a "$RESULTS"
echo "|---|---|---:|---:|---:|---:|---:|---|" | tee -a "$RESULTS"

for c in "${CASES[@]}"; do
    IFS='|' read -r label irrel <<<"$c"
    logfile="log_restricted_${label//[: ()>+-]/_}.txt"
    echo ">>> $label (log=$logfile)"
    IFS='|' read -r _l verdict lines paths partial insns ms guard < <(run_one "$label" "$irrel" "$logfile")
    echo "| $label | $verdict | $lines | $paths | $partial | $insns | $ms | $guard |" | tee -a "$RESULTS"
done

echo "" | tee -a "$RESULTS"
echo "_policy file: ${POLICY}_" | tee -a "$RESULTS"
