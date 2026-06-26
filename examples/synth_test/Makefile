KLEE      := /root/DRACO-pvt/klee/build/bin/klee
CLANG     := clang-13
LLVMLINK  := llvm-link-14
KLEE_INC  := /root/DRACO-pvt/klee/include

CFLAGS := -O0 -g -Xclang -disable-O0-optnone -fno-discard-value-names \
          -emit-llvm -c -I$(KLEE_INC)

KLEE_FLAGS := --search=dfs --solver-backend=z3 --silent-klee-assume

.PHONY: all klee-real klee-tight klee-rough klee-detect clean

all: synth_real.bc synth_tight.bc synth_rough.bc

# ── Component BCs ─────────────────────────────────────────────────────────────
synth_main.bc: synth_main.c synth_common.h
	$(CLANG) $(CFLAGS) $< -o $@

synth_expensive.bc: synth_expensive.c synth_common.h
	$(CLANG) $(CFLAGS) $< -o $@

synth_stubs.bc: synth_stubs.c synth_common.h
	$(CLANG) $(CFLAGS) $< -o $@

synth_rough_stubs.bc: synth_rough_stubs.c synth_common.h
	$(CLANG) $(CFLAGS) $< -o $@

# ── Linked variants ───────────────────────────────────────────────────────────
# Real functions: path explosion expected, use --max-time or --function-budget
synth_real.bc: synth_main.bc synth_expensive.bc
	$(LLVMLINK) $^ -o $@

# Tight stubs: fast, sound — P1/P2/P3 should all pass
synth_tight.bc: synth_main.bc synth_stubs.bc
	$(LLVMLINK) $^ -o $@

# Rough stubs: fast but unsound — P1/P2/P3 expected to fail (false positives)
synth_rough.bc: synth_main.bc synth_rough_stubs.bc
	$(LLVMLINK) $^ -o $@

# ── KLEE runs ─────────────────────────────────────────────────────────────────
# Real: will explode — stop after 15s or when budget hit
klee-real: synth_real.bc
	$(KLEE) $(KLEE_FLAGS) --max-time=15s $<

# Real with budget: detects culprits fast, writes needs_stub.txt
klee-detect: synth_real.bc
	$(KLEE) $(KLEE_FLAGS) --function-budget=10 $<
	@echo "--- needs_stub.txt ---"
	@cat klee-last/needs_stub.txt

# Tight stubs: should finish cleanly with no assertion failures
klee-tight: synth_tight.bc
	$(KLEE) $(KLEE_FLAGS) $<

# Rough stubs: should show assertion failures (false positives) on P1/P2/P3
klee-rough: synth_rough.bc
	$(KLEE) $(KLEE_FLAGS) $<

clean:
	rm -f *.bc
	rm -rf klee-out-* klee-last
