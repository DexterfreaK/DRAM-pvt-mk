#!/usr/bin/env bash
# Sweep katran KLEE over different selective-symbolization policies.
# No KLEE max-time cap; uses an outer wall-clock CAP for safety.
set -u
cd "$(dirname "$0")"

export PATH="/root/DRACO-pvt/klee/build/bin:$PATH"
PASS_LIB="/root/DRACO-pvt/lifting_tools/llvm_selective_packet_sym/build/libselective_packet_sym.so"

# Outer safety cap (seconds). 0 means truly no cap.
CAP=${CAP:-3600}
# Which constraint file to use as the main policy spec.
POLICY=${POLICY:-constraints.selective_sym.relaxed.json}

SRC=katran.c
BC=katran.bc
LL=katran.ll

RESULTS=sweep_results.md
: > "$RESULTS"

build_bc() {
    local logfile="$1"
    clang-13 -target bpf -DKLEE_VERIFICATION -DVERIFY_INTERACTIONS \
        -I/root/DRACO-pvt/headers/ -I/usr/include/x86_64-linux-gnu \
        -I/root/DRACO-pvt/ebpf-se/libbpf-stubbed/src/build/usr/include/ \
        -I/root/DRACO-pvt/klee/include \
        -D__USE_VMLINUX__ -D__TARGET_ARCH_x86 -DBPF_NO_PRESERVE_ACCESS_INDEX \
        -Wno-unused-value -Wno-unused-variable -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types -fno-discard-value-names \
        -fno-builtin -O0 -emit-llvm -c -g "$SRC" -o "$BC" 2>>"$logfile"
}

run_one() {
    # Args: label irrelevance_file logfile
    local label="$1"
    local irrel="$2"
    local logfile="$3"

    cp "$POLICY" constraints.json

    : > "$logfile"
    build_bc "$logfile"
    local rc_c=$?
    if [[ $rc_c -ne 0 ]]; then
        echo "$label|BUILD_ERR|0|?|?|?|?"
        return
    fi

    if [[ -n "$irrel" ]]; then
        opt -load "$PASS_LIB" -load-pass-plugin="$PASS_LIB" \
            -passes=selective-packet-sym \
            -packet-policy-spec="$(pwd)/constraints.json" \
            -packet-irrelevance-spec="$(pwd)/$irrel" \
            "$BC" -o "$BC" >>"$logfile" 2>&1
    fi

    llvm-dis "$BC" -o "$LL" 2>>"$logfile"
    local ll_lines
    ll_lines=$(wc -l < "$LL")

    rm -rf klee-out-*
    local t0 t1 elapsed_ms
    t0=$(date +%s%3N)
    if [[ "$CAP" -gt 0 ]]; then
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
    else
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
    fi
    local rc=$?
    t1=$(date +%s%3N)
    elapsed_ms=$((t1 - t0))

    local verdict="UNKNOWN"
    if grep -q "Map Access control : VALID" "$logfile"; then
        verdict="VALID"
    elif grep -q "Map Access control condition violated" "$logfile"; then
        verdict="INVALID"
    elif [[ $rc -eq 124 ]]; then
        verdict="TIMEOUT"
    else
        verdict="ERR(rc=$rc)"
    fi

    local paths partial insns errs
    paths=$(grep -oP "^KLEE: done: completed paths = \K[0-9]+" "$logfile" | tail -1)
    partial=$(grep -oP "^KLEE: done: partially completed paths = \K[0-9]+" "$logfile" | tail -1)
    insns=$(grep -oP "^KLEE: done: total instructions = \K[0-9]+" "$logfile" | tail -1)
    errs=$(grep -c "^KLEE: ERROR:" "$logfile")
    paths=${paths:-?}
    partial=${partial:-?}
    insns=${insns:-?}
    echo "$label|$verdict|$ll_lines|$paths|$partial|$insns|$elapsed_ms|$errs"
}

# Define cases: label|irrelevance_file
CASES=(
  "baseline:none|"
  "irrel:dIP|irrel.dIP.json"
  "irrel:sPort|irrel.sPort.json"
  "irrel:dPort|irrel.dPort.json"
  "irrel:dIP+sPort|irrel.dIP_sPort.json"
  "irrel:dIP+dPort|irrel.dIP_dPort.json"
  "irrel:sPort+dPort|irrel.sPort_dPort.json"
  "irrel:dIP+sPort+dPort|irrel.all3.json"
)

# Write sidecar files
cat > irrel.dIP.json <<'EOF'
{"irrelevant_packet_items": ["dIP"]}
EOF
cat > irrel.sPort.json <<'EOF'
{"irrelevant_packet_items": ["sPort"]}
EOF
cat > irrel.dPort.json <<'EOF'
{"irrelevant_packet_items": ["dPort"]}
EOF
cat > irrel.dIP_sPort.json <<'EOF'
{"irrelevant_packet_items": ["dIP","sPort"]}
EOF
cat > irrel.dIP_dPort.json <<'EOF'
{"irrelevant_packet_items": ["dIP","dPort"]}
EOF
cat > irrel.sPort_dPort.json <<'EOF'
{"irrelevant_packet_items": ["sPort","dPort"]}
EOF
cat > irrel.all3.json <<'EOF'
{"irrelevant_packet_items": ["dIP","sPort","dPort"]}
EOF

echo "Policy: $POLICY  (outer cap=${CAP}s)" | tee -a "$RESULTS"
echo "" | tee -a "$RESULTS"
echo "| Case | Verdict | IR lines | Completed | Partial | Instructions | Wall ms | KLEE errors |" | tee -a "$RESULTS"
echo "|---|---|---:|---:|---:|---:|---:|---:|" | tee -a "$RESULTS"

for c in "${CASES[@]}"; do
    IFS='|' read -r label irrel <<<"$c"
    logfile="log_sweep_${label//[:+]/_}.txt"
    echo ">>> $label  (log=$logfile)"
    IFS='|' read -r _l verdict lines completed partial insns ms errs < <(run_one "$label" "$irrel" "$logfile")
    line="| $label | $verdict | $lines | $completed | $partial | $insns | $ms | $errs |"
    echo "$line" | tee -a "$RESULTS"
done

echo "" | tee -a "$RESULTS"
echo "_constraints file: $POLICY_" | tee -a "$RESULTS"
