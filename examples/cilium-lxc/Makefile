CLANG    ?= clang-13
LLVMLINK ?= llvm-link-14
KLEE     := /root/DRACO-pvt/klee/build/bin/klee
KLEE_INC := /root/DRACO-pvt/klee/include
LIBBPF_INC := /root/DRACO-pvt/ebpf-se/libbpf-stubbed/src/build/usr/include
CILIUM_BPF := $(CURDIR)/bpf
TIMEOUT  ?= 60s

CFLAGS_COMMON = \
    -target bpf \
    -DKLEE_VERIFICATION \
    -D__USE_VMLINUX__ \
    -D__TARGET_ARCH_x86 \
    -DBPF_NO_PRESERVE_ACCESS_INDEX \
    -DENABLE_IPV4 \
    -D__NR_CPUS__=8 \
    -I$(CILIUM_BPF) \
    -I$(CILIUM_BPF)/include \
    -I$(LIBBPF_INC) \
    -Wall \
    -Wno-unused-value \
    -Wno-unused-variable \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -Wno-unknown-pragmas \
    -Wno-error \
    -fno-builtin \
    -O0 -g -emit-llvm -c

all: final_linked_ir.bc

bpf_lxc.bc: bpf/bpf_lxc.c
	$(CLANG) $(CFLAGS_COMMON) $< -o $@

main.bc: main.c
	$(CLANG) $(CFLAGS_COMMON) -I$(KLEE_INC) $< -o $@

final_linked_ir.bc: bpf_lxc.bc main.bc
	$(LLVMLINK) $^ -o $@

run: final_linked_ir.bc
	/usr/bin/time -v \
	$(KLEE) \
	    -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 \
	    -libc=uclibc --external-calls=all --disable-verify \
	    -solver-backend=z3 -silent-klee-assume=true \
	    -max-memory=750000 -search=dfs \
	    --max-time=$(TIMEOUT) \
	    -single-object-resolution=true \
	    -verification=true \
	    -read-set=true -write-set=true \
	    -map-correlation=true \
	    -restrict-helper-function=true \
	    -enable-map-access-control=true \
	    -enable-packet-constr=true \
	    -config-file=$(CURDIR)/constraints.json \
	    final_linked_ir.bc 2>&1 | tee run.log

# ── Synthetic (x86-64, no BPF asm, self-contained) ──────────────────
CLANG_X86 ?= clang-13
SYN_CFLAGS = \
    -DKLEE_VERIFICATION \
    -I$(KLEE_INC) \
    -Wall -Wno-unused-value -Wno-unused-variable -Wno-pointer-sign \
    -Wno-error \
    -fno-builtin -O0 -g -emit-llvm -c

cilium_lxc_syn.bc: cilium_lxc_syn.c
	$(CLANG_X86) $(SYN_CFLAGS) $< -o $@

run_syn: cilium_lxc_syn.bc
	/usr/bin/time -f "wall=%es peak_kb=%M" \
	$(KLEE) \
	    -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 \
	    -libc=uclibc --external-calls=all --disable-verify \
	    -solver-backend=z3 -silent-klee-assume=true \
	    -max-memory=750000 -search=dfs \
	    --max-time=$(TIMEOUT) \
	    -single-object-resolution=true \
	    -verification=true \
	    -read-set=true -write-set=true \
	    -map-correlation=true \
	    -restrict-helper-function=true \
	    -enable-map-access-control=true \
	    -enable-packet-constr=true \
	    -config-file=$(CURDIR)/constraints_syn.json \
	    cilium_lxc_syn.bc 2>&1 | tee run_syn.log

cilium_lxc_stub.bc: cilium_lxc_stub.c
	$(CLANG_X86) $(SYN_CFLAGS) $< -o $@

run_stub: cilium_lxc_stub.bc
	/usr/bin/time -f "wall=%es peak_kb=%M" \
	$(KLEE) \
	    -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 \
	    -libc=uclibc --external-calls=all --disable-verify \
	    -solver-backend=z3 -silent-klee-assume=true \
	    -max-memory=750000 -search=dfs \
	    --max-time=$(TIMEOUT) \
	    -single-object-resolution=true \
	    -verification=true \
	    -read-set=true -write-set=true \
	    -map-correlation=true \
	    -restrict-helper-function=true \
	    -enable-map-access-control=true \
	    -enable-packet-constr=true \
	    -config-file=$(CURDIR)/constraints_syn.json \
	    cilium_lxc_stub.bc 2>&1 | tee run_stub.log

clean:
	rm -f *.bc *.ll run.log run_syn.log run_stub.log
	rm -rf klee-out-*
