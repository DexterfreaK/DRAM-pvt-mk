#!/usr/bin/env bash
# Run KLEE on baseline.bc and instrumented.bc with a wall-clock budget,
# then dump path counts, instruction counts, and verdict so we can see what
# the Crab-derived invariants buy us.

set -e
cd "$(dirname "$0")"

KLEE=/root/DRACO-pvt/klee/build/bin/klee
TIMEOUT=${TIMEOUT:-300}
DEPTH=${DEPTH:-0}

make -s baseline.bc instrumented.bc

run_one() {
    local label="$1"
    local bc="$2"
    local outdir="klee-out-$label"
    rm -rf "$outdir"

    /usr/bin/time -f "wall=%es rss=%MKB" \
        "$KLEE" --output-dir="$outdir" \
                --max-time="${TIMEOUT}s" \
                --search=dfs \
                --solver-backend=z3 \
                --silent-klee-assume \
                "$bc" \
                > "${outdir}.log" 2>&1 || true

    local paths instr verdict
    paths=$(grep -oE "completed paths = [0-9]+" "${outdir}/info" 2>/dev/null \
            | awk '{print $4}' | tail -1)
    instr=$(grep -oE "instructions = [0-9]+" "${outdir}/info" 2>/dev/null \
            | awk '{print $3}' | tail -1)
    verdict="OK"
    if grep -q "ASSERTION FAIL" "${outdir}/messages.txt" 2>/dev/null; then
        verdict="ASSERT_FAIL"
    elif grep -q "halting execution" "${outdir}/messages.txt" 2>/dev/null \
        && grep -q "max-time" "${outdir}/messages.txt" 2>/dev/null; then
        verdict="TIMEOUT"
    fi
    local wall
    wall=$(grep -oE "wall=[0-9.]+s" "${outdir}.log" | tail -1)

    printf "%-12s | paths=%-6s instr=%-8s verdict=%-12s %s\n" \
        "$label" "${paths:-?}" "${instr:-?}" "$verdict" "${wall:-?}"
}

echo "TIMEOUT=${TIMEOUT}s per run"
echo "----------------------------------------------------------------"
run_one baseline      baseline.bc
run_one instrumented  instrumented.bc
echo "----------------------------------------------------------------"
echo "baseline log:     ./klee-out-baseline.log"
echo "instrumented log: ./klee-out-instrumented.log"
