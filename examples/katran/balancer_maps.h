/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __BALANCER_MAPS_H
#define __BALANCER_MAPS_H

/*
 * This file contains definition of maps used by the balancer typically
 * involving information pertaining to proper forwarding of packets
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "balancer_consts.h"
#include "balancer_structs.h"

#ifdef DRACO_LIFTER_MODE
// ============================================================================
// BTF-style map definitions for DRACO lifter mode (libbpf v1.0+ compatible)
// ============================================================================

// map, which contains all the vips for which we are doing load balancing
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_VIPS);
  __type(key, struct vip_definition);
  __type(value, struct vip_meta);
} vip_map SEC(".maps");

// map which contains cpu core to lru mapping (simplified for lifter compatibility)
// Note: In DRACO_LIFTER_MODE, we use a single LRU hash map instead of array-of-maps
// fallback_cache is not needed since we access lru_mapping directly
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, DEFAULT_LRU_SIZE);
  __type(key, struct flow_key);
  __type(value, struct real_pos_lru);
} lru_mapping SEC(".maps");

// map which contains all vip to real id mappings
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, CH_RINGS_SIZE);
  __type(key, __u32);
  __type(value, __u32);
} ch_rings SEC(".maps");

// map which contains opaque real's id to real definition mapping
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_REALS);
  __type(key, __u32);
  __type(value, struct real_definition);
} reals SEC(".maps");

// map with per real pps/bps statistic
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, MAX_REALS);
  __type(key, __u32);
  __type(value, struct lb_stats);
} reals_stats SEC(".maps");

// map w/ per vip statistics
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, STATS_MAP_SIZE);
  __type(key, __u32);
  __type(value, struct lb_stats);
} stats SEC(".maps");

// map for quic connection-id to real's id mapping
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_REALS);
  __type(key, __u32);
  __type(value, __u32);
} quic_mapping SEC(".maps");

#ifdef LPM_SRC_LOOKUP
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_LPM_SRC);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct v4_lpm_key);
  __type(value, __u32);
} lpm_src_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_LPM_SRC);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct v6_lpm_key);
  __type(value, __u32);
} lpm_src_v6 SEC(".maps");
#endif

#else
// ============================================================================
// Legacy map definitions for default/normal BPF compilation mode
// ============================================================================

#include "bpf_map_def.h"

// map, which contains all the vips for which we are doing load balancing
struct bpf_map_def SEC("maps") vip_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct vip_definition),
  .value_size = sizeof(struct vip_meta),
  .max_entries = MAX_VIPS,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(vip_map, struct vip_definition, struct vip_meta);

// fallback lru. iterate over it if sobind to cpu is not working or sobind
// is not enabled
struct bpf_map_def SEC("maps") fallback_cache = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(struct flow_key),
  .value_size = sizeof(struct real_pos_lru),
  .max_entries = DEFAULT_LRU_SIZE,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(fallback_cache, struct flow_key, struct real_pos_lru);

// map which contains cpu core to lru mapping
struct bpf_map_def SEC("maps") lru_mapping = {
  .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
  .key_size = sizeof(__u32),
  .max_entries = MAX_SUPPORTED_CPUS,
  .map_flags = NO_FLAGS,
#ifndef KLEE_VERIFICATION
  .inner_map_idx = 0,
#endif
};

// map which contains all vip to real id mappings
struct bpf_map_def SEC("maps") ch_rings = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = CH_RINGS_SIZE,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(ch_rings, __u32, __u32);

// map which contains opaque real's id to real definition mapping
struct bpf_map_def SEC("maps") reals = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct real_definition),
  .max_entries = MAX_REALS,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(reals, __u32, struct real_definition);

// map with per real pps/bps statistic
struct bpf_map_def SEC("maps") reals_stats = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct lb_stats),
  .max_entries = MAX_REALS,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(reals_stats, __u32, struct lb_stats);

// map w/ per vip statistics
struct bpf_map_def SEC("maps") stats = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct lb_stats),
  .max_entries = STATS_MAP_SIZE,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(stats, __u32, struct lb_stats);

// map for quic connection-id to real's id mapping
struct bpf_map_def SEC("maps") quic_mapping = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = MAX_REALS,
  .map_flags = NO_FLAGS,
};
BPF_ANNOTATE_KV_PAIR(quic_mapping, __u32, __u32);

#ifdef LPM_SRC_LOOKUP
struct bpf_map_def SEC("maps") lpm_src_v4 = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct v4_lpm_key),
  .value_size = sizeof(__u32),
  .max_entries = MAX_LPM_SRC,
  .map_flags = BPF_F_NO_PREALLOC,
};
BPF_ANNOTATE_KV_PAIR(lpm_src_v4, struct v4_lpm_key, __u32);

struct bpf_map_def SEC("maps") lpm_src_v6 = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct v6_lpm_key),
  .value_size = sizeof(__u32),
  .max_entries = MAX_LPM_SRC,
  .map_flags = BPF_F_NO_PREALLOC,
};
BPF_ANNOTATE_KV_PAIR(lpm_src_v6, struct v6_lpm_key, __u32);
#endif

#endif // DRACO_LIFTER_MODE

#endif // of _BALANCER_MAPS
