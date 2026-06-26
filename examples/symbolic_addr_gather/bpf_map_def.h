#ifndef __BPF_MAP_DEF_H
#define __BPF_MAP_DEF_H

#ifndef KLEE_VERIFICATION
/* For the real BPF (verifier) build, define the legacy map descriptor.
 * Under KLEE_VERIFICATION it is already provided by ebpf-se's stub headers. */
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
  unsigned int inner_map_idx;
  unsigned int numa_node;
};
#endif

#endif
