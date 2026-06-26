#!/usr/bin/env bash
# Symbolic-address gather AI-bounds experiment.
#
# Demonstrates that abstract interpretation (known-bits domain) can supply
# a klee_assume bound for the XOR-accumulation result of a pointer-chase
# gather loop, letting KLEE terminate where solver cost otherwise explodes.
#
# Baseline : main.c + do_gather.c (real loop) -> CHAIN-deep nested selects -> TIMEOUT
# AI stub  : main.c + do_gather_stub.c        -> one fresh symbolic        -> OK
#
# Usage: bash run_stub_experiment.sh          # default CHAIN=128 TIMEOUT=120s
#        CHAIN=64 TIMEOUT=60s bash run_stub_experiment.sh

set -eu
cd "$(dirname "$0")"

KLEE=/root/DRACO-pvt/klee/build/bin/klee
TIMEOUT=${TIMEOUT:-120s}
CHAIN=${CHAIN:-128}

CHAIN=$CHAIN make -s gathered-all

run_one() {
    local label="$1" bc="$2"
    local outdir="klee-out-gathered-$label"
    rm -rf "$outdir"

    /usr/bin/time -f "wall=%es rss=%MKB" \
        "$KLEE" --output-dir="$outdir" \
                --max-time="$TIMEOUT" \
                --search=dfs \
                --solver-backend=z3 \
                --silent-klee-assume \
                -kdalloc \
                -kdalloc-heap-start-address=0x00040000000 \
                -kdalloc-heap-size=1 \
                -libc=uclibc \
                --external-calls=all \
                --disable-verify \
                -max-memory=750000 \
                "$bc" > "${outdir}.log" 2>&1 || true

    local paths partial verdict wall
    paths=$(grep -oE "^KLEE: done: completed paths = [0-9]+" "$outdir/info" 2>/dev/null \
            | grep -oE "[0-9]+$" | tail -1)
    partial=$(grep -oE "^KLEE: done: partially completed paths = [0-9]+" "$outdir/info" 2>/dev/null \
              | grep -oE "[0-9]+$" | tail -1)
    verdict="OK"
    if grep -q "ASSERTION FAIL" "$outdir/messages.txt" 2>/dev/null; then
        verdict="ASSERT_FAIL"
    fi
    if grep -q "HaltTimer" "$outdir/messages.txt" 2>/dev/null; then
        verdict="TIMEOUT (hit ${TIMEOUT})"
    fi
    wall=$(grep -oE "wall=[0-9.]+s" "${outdir}.log" | tail -1)

    printf "%-18s | completed=%-6s partial=%-6s verdict=%-22s %s\n" \
        "$label" "${paths:-?}" "${partial:-?}" "$verdict" "${wall:-?}"
}

echo "======================================================================"
echo " Symbolic-address gather AI-bounds experiment"
echo " CHAIN=${CHAIN}  TBL_SIZE=256  TIMEOUT=${TIMEOUT}"
echo ""
echo " Policy: acc == 0x42 -> XDP_DROP, else XDP_PASS"
echo ""
echo " AI bound derivation (see examples/ai_demo/hash_abstract_interp.py):"
echo "   Each iter: acc ^= table[idx] & 0xFF  (8-bit mask)"
echo "   Known-bits: XOR of 8-bit values stays 8-bit -> acc in [0, 255]"
echo "   TBL_SIZE=256 is power-of-two -> MOD_pow2 gives exact bound"
echo "   => klee_assume(acc < 256) replaces the CHAIN-deep gather loop"
echo "======================================================================"
run_one baseline   baseline_gathered.bc
run_one ai_stub    stub_gathered.bc
echo "======================================================================"
echo "Baseline log : klee-out-gathered-baseline.log"
echo "AI stub log  : klee-out-gathered-ai_stub.log"
