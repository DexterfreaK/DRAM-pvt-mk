CLANG    ?= clang-13
LLVMLINK ?= llvm-link-14
KLEE     := /root/DRACO-pvt/klee/build/bin/klee
KLEE_INC := /root/DRACO-pvt/klee/include
TIMEOUT  ?= 30s

CFLAGS = -O0 -g -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -c

all: baseline.bc concrete_stub.bc symbolic_stub.bc

harness.bc: harness.c
	$(CLANG) -I$(KLEE_INC) $(CFLAGS) $< -o $@

jhash_impl.bc: jhash_impl.c
	$(CLANG) $(CFLAGS) $< -o $@

jhash_stub_concrete.bc: jhash_stub_concrete.c
	$(CLANG) $(CFLAGS) $< -o $@

jhash_stub_symbolic.bc: jhash_stub_symbolic.c
	$(CLANG) -I$(KLEE_INC) $(CFLAGS) $< -o $@

baseline.bc: jhash_impl.bc harness.bc
	$(LLVMLINK) $^ -o $@

concrete_stub.bc: jhash_stub_concrete.bc harness.bc
	$(LLVMLINK) $^ -o $@

symbolic_stub.bc: jhash_stub_symbolic.bc harness.bc
	$(LLVMLINK) $^ -o $@

run: all
	@bash run_experiment.sh

clean:
	rm -f *.bc
	rm -rf klee-out-*
