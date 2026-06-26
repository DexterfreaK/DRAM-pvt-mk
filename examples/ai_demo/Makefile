CLANG ?= clang-13
OPT   ?= opt-13
# After the clam_bridge pass (built against LLVM 14) we must use the LLVM 14
# linker/disassembler — bitcode written by opt-14 is not readable by
# llvm-link-13. Clang-13 output is forward-compatible to LLVM 14.
LLVMLINK ?= llvm-link-14
LLVMDIS  ?= llvm-dis-14

CLAM = /root/clam/build/bin/clam
BRIDGE_LIB = /root/DRACO-pvt/lifting_tools/llvm_clam_bridge/build/libclam_bridge.so
KLEE_INCLUDE = /root/DRACO-pvt/klee/include

CFLAGS = -O0 -g -Xclang -disable-O0-optnone -fno-discard-value-names \
         -emit-llvm -c

# Library bitcode (the function under analysis).
all: fnv_hash.bc fnv_hash.opt.bc fnv_hash.ll fnv_hash.opt.ll \
     fnv_harness.bc \
     baseline.bc instrumented.bc

fnv_hash.bc: fnv_hash.c
	$(CLANG) $(CFLAGS) $< -o $@

fnv_hash.opt.bc: fnv_hash.bc
	$(OPT) -mem2reg -instcombine -simplifycfg $< -o $@

fnv_harness.bc: fnv_harness.c
	$(CLANG) -I $(KLEE_INCLUDE) $(CFLAGS) $< -o $@

# Baseline: the unmodified function linked with the harness.
baseline.bc: fnv_hash.opt.bc fnv_harness.bc
	$(LLVMLINK) fnv_hash.opt.bc fnv_harness.bc -o $@

# Crab-instrumented: invariants materialised as llvm.assume(!clam),
# then bridged to klee_assume(i64) for KLEE consumption.
CLAM_LOC ?= loop-header
fnv_hash.crab.bc: fnv_hash.opt.bc
	$(CLAM) $< \
	    --crab-dom=soct \
	    --crab-opt \
	    --crab-opt-add-invariants=$(CLAM_LOC) \
	    --crab-promote-assume \
	    -o $@

fnv_hash.bridged.bc: fnv_hash.crab.bc
	opt -load-pass-plugin $(BRIDGE_LIB) -passes=clam-bridge $< -o $@

instrumented.bc: fnv_hash.bridged.bc fnv_harness.bc
	$(LLVMLINK) fnv_hash.bridged.bc fnv_harness.bc -o $@

%.ll: %.bc
	$(LLVMDIS) $< -o $@

clean:
	rm -f *.bc *.ll *.txt clam_*.log
	rm -rf klee-out-*
