# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

include ../Makefile

XDP_TARGETS := main
XDP_SECTION := xdp
XDP_FUNCTION := xdp_main

# ── Stub summarizer comparison targets ──────────────────────────────────────
# Test case #2 for the abstract-interpreter stub summarizer (see
# lifting_tools/summarizer/).  main.c calls do_gather(); link it with the
# real loop (baseline_gathered) or the AI-bounds stub (stub_gathered).
#
#   baseline_gathered.bc : solver-cost explosion (CHAIN-deep nested selects)
#   stub_gathered.bc     : O(1) KLEE cost, 2 paths, same verdict

CLANG_S   ?= clang-13
LLVMLINK  ?= llvm-link-14
KLEE_S    := /root/DRACO-pvt/klee/build/bin/klee
KLEE_INC  := /root/DRACO-pvt/klee/include
LIBBPF_INC := /root/DRACO-pvt/ebpf-se/libbpf-stubbed/src/build/usr/include

CHAIN     ?= 128

BPF_KLEE_CFLAGS = \
    -target bpf -DKLEE_VERIFICATION -DCHAIN=$(CHAIN) \
    -I../headers/ -I$(LIBBPF_INC) -I$(KLEE_INC) \
    -D__USE_VMLINUX__ -D__TARGET_ARCH_x86 -DBPF_NO_PRESERVE_ACCESS_INDEX \
    -Wno-pointer-sign -Wno-compare-distinct-pointer-types -fno-builtin \
    -O0 -g -emit-llvm -c

main_gathered.bc: main.c
	$(CLANG_S) $(BPF_KLEE_CFLAGS) $< -o $@

do_gather_real.bc: do_gather.c
	$(CLANG_S) $(BPF_KLEE_CFLAGS) $< -o $@

do_gather_stub.bc: do_gather_stub.c
	$(CLANG_S) $(BPF_KLEE_CFLAGS) $< -o $@

baseline_gathered.bc: main_gathered.bc do_gather_real.bc
	$(LLVMLINK) $^ -o $@

stub_gathered.bc: main_gathered.bc do_gather_stub.bc
	$(LLVMLINK) $^ -o $@

gathered-all: baseline_gathered.bc stub_gathered.bc

run-gathered: gathered-all
	@bash run_stub_experiment.sh

.PHONY: gathered-all run-gathered
