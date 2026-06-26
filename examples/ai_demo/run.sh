#!/usr/bin/env bash
# Two passes over fnv_hash.opt.bc:
#   (1) print per-block invariants for several domains (text, for inspection)
#   (2) emit instrumented IR (verifier.assume(...) calls at block entries)
#
# Caveat: --oll writes the IR *before* the optimizer pass. To capture the
# instrumented IR we must use -S -o <file.ll>.

set -eu
cd "$(dirname "$0")"
CLAM=/root/clam/build/bin/clam

make -s fnv_hash.opt.bc

for dom in int zones w-int soct term-dis-int; do
    echo ">>> Running clam --crab-dom=$dom (print-only)"
    "$CLAM" fnv_hash.opt.bc --crab-dom="$dom" --crab-print-invariants \
        > "clam_${dom}.txt" 2>&1
done

echo
echo "=== Key invariants inside the FNV loop per domain ==="
for dom in int zones w-int soct term-dis-int; do
    echo "--- $dom ---"
    grep -A1 "^for\.body:\|^for\.inc:\|^for\.end:" "clam_${dom}.txt" \
        | grep -oE "off\.0 -> [^;,}]*|key_len\.0 -> [^;,}]*|off\.0-key_len\.0[^,}]*|key_len\.0-off\.0[^,}]*" \
        | sort -u | head -12
done

echo
echo ">>> Instrumenting IR with soct invariants -> fnv_hash.crab.ll"
"$CLAM" fnv_hash.opt.bc \
    --crab-dom=soct \
    --crab-opt \
    --crab-opt-add-invariants=block-entry \
    -S -o fnv_hash.crab.ll \
    > clam_instrument.log 2>&1

echo "verifier.assume calls inserted: $(grep -c 'call void @verifier.assume' fnv_hash.crab.ll)"
