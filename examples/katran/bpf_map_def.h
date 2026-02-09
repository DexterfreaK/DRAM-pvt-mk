#ifndef __BPF_MAP_DEF_H
#define __BPF_MAP_DEF_H

#ifdef KLEE_VERIFICATION
// When using KLEE verification, bpf_map_def is already defined in ebpf-se's bpf_helper_defs.h
// We just need to provide the BPF_ANNOTATE_KV_PAIR macro (as no-op for KLEE)
#define BPF_ANNOTATE_KV_PAIR(name, kt, vt)
#else
/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
  unsigned int inner_map_idx;
  unsigned int numa_node;
};

// BPF_ANNOTATE_KV_PAIR is needed for BTF generation with older libbpf
#define BPF_ANNOTATE_KV_PAIR(name, kt, vt) \
  struct ____btf_map_##name { \
    kt key; \
    vt value; \
  }; \
  struct ____btf_map_##name __attribute__((section(".maps." #name), used)) \
    ____btf_map_##name = {}
#endif

#endif
