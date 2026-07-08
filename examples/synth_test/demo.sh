#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SYNTH_DIR="$REPO_ROOT/examples/synth_test"
KLEE="$REPO_ROOT/klee/build/bin/klee"
KLEE_FLAGS="--search=dfs --solver-backend=z3 --silent-klee-assume"

cd "$SYNTH_DIR"

echo "============================================================"
echo " DRACO synth_test demo"
echo "============================================================"

# ── Build ─────────────────────────────────────────────────────────────────────
echo ""
echo ">>> Step 1: Build BCs"
make -s clean && make -s all
echo "    Built: synth_real.bc  synth_tight.bc  synth_rough.bc"

# ── Step 2: Real functions → explosion ────────────────────────────────────────
echo ""
echo ">>> Step 2: KLEE on real functions (expect timeout/slow)"
$KLEE $KLEE_FLAGS --max-time=10s synth_real.bc 2>&1 | tail -5

# ── Step 3: Pass 1 — runtime detector ─────────────────────────────────────────
echo ""
echo ">>> Step 3: Pass 1 — --function-budget detects culprit"
$KLEE $KLEE_FLAGS --function-budget=10 synth_real.bc 2>&1 | tail -5
echo ""
echo "    needs_stub.txt:"
cat klee-last/needs_stub.txt

# ── Step 5: Tight hand-written stubs → correct ───────────────────────────────
echo ""
echo ">>> SideStep : KLEE on tight hand-written stubs — expect SAFE"
$KLEE $KLEE_FLAGS synth_tight.bc 2>&1 | tail -5

# ── Step 6: Pass 2 — auto_stub generates and verifies tight stubs ─────────────
echo ""
echo ">>> Step 6: Pass 2 — auto_stub.py generates tight stubs automatically"
cd "$REPO_ROOT"
python3 lifting_tools/summarizer/auto_stub.py \
    --bc examples/synth_test/synth_real.bc \
    --source-map examples/synth_test/source_map.json \
    --timeout 30

echo ""
echo "============================================================"
echo " Demo complete"
echo "============================================================"
