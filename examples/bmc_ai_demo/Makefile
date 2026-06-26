CLANG    ?= clang-13
LLVMLINK ?= llvm-link-14
KLEE     := /root/DRACO-pvt/klee/build/bin/klee
KLEE_INC := /root/DRACO-pvt/klee/include
TIMEOUT  ?= 60s

# Tune KEY_BYTES for faster/slower explosion; 12 reliably hits the cap at 120 s.
KEY_BYTES ?= 12

CFLAGS = -O0 -g \
         -DKEY_BYTES=$(KEY_BYTES) \
         -Xclang -disable-O0-optnone \
         -fno-discard-value-names \
         -emit-llvm -c

all: baseline.bc ai_bounds.bc ai_bounds_gen.bc

bmc_hash_mini.bc: bmc_hash_mini.c
	$(CLANG) $(CFLAGS) $< -o $@

bmc_hash_stub.bc: bmc_hash_stub.c
	$(CLANG) -I$(KLEE_INC) $(CFLAGS) $< -o $@

harness.bc: harness.c
	$(CLANG) -I$(KLEE_INC) $(CFLAGS) $< -o $@

# Baseline: harness linked with the real hash loop (path explosion expected)
baseline.bc: bmc_hash_mini.bc harness.bc
	$(LLVMLINK) $^ -o $@

# AI bounds: harness linked with the abstract-interpretation stub
ai_bounds.bc: bmc_hash_stub.bc harness.bc
	$(LLVMLINK) $^ -o $@

bmc_hash_stub_gen.bc: bmc_hash_stub_gen.c
	$(CLANG) -I$(KLEE_INC) $(CFLAGS) $< -o $@

# AI bounds using the auto-generated stub (should match ai_bounds behaviour)
ai_bounds_gen.bc: bmc_hash_stub_gen.bc harness.bc
	$(LLVMLINK) $^ -o $@

run: all
	@bash run_experiment.sh

clean:
	rm -f *.bc
	rm -rf klee-out-*
