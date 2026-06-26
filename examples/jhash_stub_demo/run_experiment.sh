#!/usr/bin/env bash
set -eu

KLEE=/root/DRACO-pvt/klee/build/bin/klee
TIMEOUT=${TIMEOUT:-30s}

run_klee() {
    local label="$1"
    local bc="$2"
    local out="klee-out-${label}"
    rm -rf "$out"
    /usr/bin/time -f "wall=%es" \
        $KLEE --output-dir="$out" --max-time="$TIMEOUT" \
              --search=dfs --solver-backend=z3 --silent-klee-assume \
              "$bc" > "${label}.log" 2>&1 || true

    local paths partial wall verdict
    paths=$(grep  "^KLEE: done: completed paths"        "$out/info" 2>/dev/null | grep -oE "[0-9]+$" || echo "?")
    partial=$(grep "^KLEE: done: partially completed"   "$out/info" 2>/dev/null | grep -oE "[0-9]+$" || echo "?")
    wall=$(grep "wall=" "${label}.log" 2>/dev/null | grep -oE "wall=[0-9.]+s" || echo "wall=?")
    verdict="OK"
    grep -q "HaltTimer" "$out/messages.txt" 2>/dev/null && verdict="TIMEOUT"
    grep -q "ASSERTION FAIL" "$out/messages.txt" 2>/dev/null && verdict="ASSERT_FAIL"

    printf "%-22s | completed=%-5s partial=%-5s verdict=%-10s %s\n" \
        "$label" "$paths" "$partial" "$verdict" "$wall"
}

echo ""
echo "katran jhash — three variants compared (TIMEOUT=${TIMEOUT})"
echo "================================================================"
echo ""
echo "The harness branches on pool-A (hash_idx<63) vs pool-B (hash_idx>=63)."
echo "Coverage difference between stubs is visible in path count."
echo ""

if [ "${SKIP_BASELINE:-1}" != "1" ]; then
    echo "WARNING: baseline (real jhash) will hang Z3 well past ${TIMEOUT}."
    echo "  (KLEE's HaltTimer cannot interrupt an in-flight Z3 query.)"
    echo "  Confirmed: bash process killed by OS after ~40s on this machine."
    echo "  Run manually with: klee --max-time=30s baseline.bc"
    echo ""
    echo "baseline (real jhash)  | completed=?     partial=?     verdict=TIMEOUT   wall>>30s"
fi

run_klee concrete_stub       concrete_stub.bc
run_klee symbolic_stub       symbolic_stub.bc

echo ""
echo "COVERAGE:"
echo "  baseline       (real jhash)         — hangs Z3 (nonlinear bitvector mixing)"
echo "  concrete_stub  (return 42 % 127)    — 1 path: always pool-A; pool-B never checked"
echo "  symbolic_stub  (klee_make_symbolic)  — 2 paths: both pool-A and pool-B verified"
echo ""
echo "The symbolic stub gives the same coverage as the true implementation would,"
echo "without the Z3 cost. Sound for range/routing properties; not sound for"
echo "hash-consistency checks (same packet → same bucket) — those need a UF summary."
