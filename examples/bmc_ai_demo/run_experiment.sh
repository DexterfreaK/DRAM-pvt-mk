#!/usr/bin/env bash
# BMC-cache hash AI-bounds experiment.
#
# Demonstrates that abstract interpretation (known-bits x interval) can supply
# a klee_assume bound for the FNV hash output, letting KrakenGuard's symbolic
# executor terminate where it otherwise explodes.
#
# Baseline : harness + full FNV loop -> path explosion -> TIMEOUT
# AI bounds: harness + AI stub       -> one fresh symbolic -> OK
#
# Usage: bash run_experiment.sh          # default KEY_BYTES=12 TIMEOUT=120s
#        KEY_BYTES=8 TIMEOUT=60s bash run_experiment.sh

set -eu
cd "$(dirname "$0")"

KLEE=/root/DRACO-pvt/klee/build/bin/klee
TIMEOUT=${TIMEOUT:-60s}
KEY_BYTES=${KEY_BYTES:-12}

KEY_BYTES=$KEY_BYTES make -s all

run_one() {
    local label="$1" bc="$2"
    local outdir="klee-out-$label"
    rm -rf "$outdir"

    /usr/bin/time -f "wall=%es rss=%MKB" \
        "$KLEE" --output-dir="$outdir" \
                --max-time="$TIMEOUT" \
                --search=dfs \
                --solver-backend=z3 \
                --silent-klee-assume \
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

    printf "%-14s | completed=%-6s partial=%-6s verdict=%-22s %s\n" \
        "$label" "${paths:-?}" "${partial:-?}" "$verdict" "${wall:-?}"
}

echo "==================================================================="
echo " BMC hash abstract-interpretation bounds experiment"
echo " KEY_BYTES=${KEY_BYTES}  TABLE_SIZE=3250  TIMEOUT=${TIMEOUT}"
echo ""
echo " Policy P1: cache_idx < TABLE_SIZE (valid map_kcache slot)"
echo " Policy P2: key_len   <= KEY_BYTES  (bounded key consumption)"
echo ""
echo " AI bound derivation (see examples/ai_demo/hash_abstract_interp.py):"
echo "   FNV raw mixer: hash in [0, 2^32)  (known-bits: all unknown)"
echo "   hash % 3250:   result in [0, 3249] (reduced product: kb x interval)"
echo "   => klee_assume(cache_idx < 3250) replaces the entire loop body"
echo "==================================================================="
run_one baseline   baseline.bc
run_one ai_bounds  ai_bounds.bc
echo "==================================================================="
echo "Baseline log  : klee-out-baseline.log"
echo "AI bounds log : klee-out-ai_bounds.log"
