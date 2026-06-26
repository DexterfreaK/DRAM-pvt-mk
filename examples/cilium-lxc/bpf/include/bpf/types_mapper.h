/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_TYPES_MAPPER__
#define __BPF_TYPES_MAPPER__

typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

typedef __signed__ long long __s64;
typedef unsigned long long __u64;

typedef __u16 __le16;
typedef __u16 __be16;

typedef __u32 __le32;
typedef __u32 __be32;

typedef __u64 __le64;
typedef __u64 __be64;

typedef __u16 __sum16;
typedef __u32 __wsum;

typedef __u64 __aligned_u64;

typedef __u64 __net_cookie;
typedef __u64 __sock_cookie;

#define UINT8_MAX 0xffff

#ifdef KLEE_VERIFICATION
/* ---------------------------------------------------------------
 * KLEE stubs: override BPF_FUNC before api.h/helpers.h defines it,
 * and provide actual noinline stub functions that KrakenGuard can
 * intercept by name (Executor.cpp:1748 matches "bpf_map_lookup_elem"
 * etc.).  Cilium uses unprefixed names (map_lookup_elem), so we
 * redirect them via #define to the bpf_-prefixed stubs.
 * --------------------------------------------------------------- */

/* 1. Suppress helpers.h's BPF_FUNC / BPF_STUB / BPF_FUNC_REMAP so
 *    they don't emit function-pointer globals pointing to integer 1. */
#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)       /* no-op: stub defined below */
#endif
#ifndef BPF_STUB
# define BPF_STUB(NAME, ...)       /* no-op */
#endif
#ifndef BPF_FUNC_REMAP
# define BPF_FUNC_REMAP(NAME, ...) /* no-op */
#endif

/* 2. Actual noinline stub functions so KLEE can call them by name.
 *    Return values: NULL / 0 (conservative; policy checks don't
 *    depend on return values, only on which helpers are called). */
static __attribute__((noinline)) __attribute__((unused))
void *bpf_map_lookup_elem(const void *map, const void *key) { return (void *)0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_map_update_elem(const void *map, const void *key,
                        const void *value, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_map_delete_elem(const void *map, const void *key) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
__u64 bpf_ktime_get_ns(void) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
__u64 bpf_ktime_get_boot_ns(void) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_trace_printk(const char *fmt, int fmt_size, ...) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_load_bytes(const void *ctx, __u32 off,
                       void *to, __u32 len) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_load_bytes_relative(const void *ctx, __u32 off,
                                void *to, __u32 len, __u32 start_header) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_store_bytes(void *ctx, __u32 off,
                        const void *from, __u32 len, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_l3_csum_replace(void *ctx, __u32 off, __u64 from,
                        __u64 to, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_l4_csum_replace(void *ctx, __u32 off, __u64 from,
                        __u64 to, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
__s64 bpf_csum_diff(const void *from, __u32 from_size,
                    const void *to, __u32 to_size,
                    __u32 seed) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_redirect(int ifindex, __u64 flags) { return 7 /* TC_ACT_REDIRECT */; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_redirect_neigh(int ifindex, void *params,
                       int plen, __u64 flags) { return 7; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_redirect_map(void *map, __u32 key, __u64 flags) { return 7; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_perf_event_output(void *ctx, void *map, __u64 flags,
                          void *data, __u64 size) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_change_tail(void *ctx, __u32 new_len, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_change_head(void *ctx, __u32 head_room, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_change_proto(void *ctx, __u16 proto, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_change_type(void *ctx, __u32 type) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
__u64 bpf_get_socket_cookie(void *ctx) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
__u64 bpf_get_netns_cookie(void *ctx) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_get_tunnel_key(void *ctx, void *key,
                           __u32 size, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_set_tunnel_key(void *ctx, const void *key,
                           __u32 size, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_get_tunnel_opt(void *ctx, void *opt, __u32 size) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_set_tunnel_opt(void *ctx, const void *opt, __u32 size) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_fib_lookup(void *ctx, void *params, int plen, __u32 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_sk_lookup_tcp(void *ctx, void *tuple, __u32 tuple_size,
                      __u64 netns, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_sk_lookup_udp(void *ctx, void *tuple, __u32 tuple_size,
                      __u64 netns, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
void bpf_sk_release(void *sk) {}

static __attribute__((noinline)) __attribute__((unused))
int bpf_get_prandom_u32(void) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_get_smp_processor_id(void) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_xdp_adjust_head(void *ctx, int delta) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_xdp_adjust_tail(void *ctx, int delta) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_xdp_adjust_meta(void *ctx, int delta) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_map_push_elem(void *map, const void *value, __u64 flags) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_map_pop_elem(void *map, void *value) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_map_peek_elem(void *map, void *value) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
void *bpf_map_lookup_percpu_elem(void *map, const void *key, __u32 cpu) { return (void *)0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_jiffies64(void) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
__u32 bpf_get_hash_recalc(void *ctx) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_set_hash_invalid(void *ctx) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
__u32 bpf_get_cgroup_classid(void *ctx) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_vlan_push(void *ctx, __be16 vlan_proto, __u16 vlan_tci) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_vlan_pop(void *ctx) { return 0; }

static __attribute__((noinline)) __attribute__((unused))
int bpf_skb_cb_access(void *ctx) { return 0; }

/* 3. Redirect Cilium's unprefixed names to the bpf_-prefixed stubs.
 *    This makes KrakenGuard see "bpf_map_lookup_elem" etc. in fName. */
#define map_lookup_elem          bpf_map_lookup_elem
#define map_update_elem          bpf_map_update_elem
#define map_delete_elem          bpf_map_delete_elem
#define ktime_get_ns             bpf_ktime_get_ns
#define ktime_get_boot_ns        bpf_ktime_get_boot_ns
#define jiffies64                bpf_jiffies64
#define skb_load_bytes           bpf_skb_load_bytes
#define skb_load_bytes_relative  bpf_skb_load_bytes_relative
#define skb_store_bytes          bpf_skb_store_bytes
#define l3_csum_replace          bpf_l3_csum_replace
#define l4_csum_replace          bpf_l4_csum_replace
#define csum_diff                bpf_csum_diff
#define redirect                 bpf_redirect
#define redirect_neigh           bpf_redirect_neigh
#define redirect_map             bpf_redirect_map
#define perf_event_output        bpf_perf_event_output
#define skb_change_tail          bpf_skb_change_tail
#define skb_change_head          bpf_skb_change_head
#define skb_change_proto         bpf_skb_change_proto
#define skb_change_type          bpf_skb_change_type
#define get_socket_cookie        bpf_get_socket_cookie
#define get_netns_cookie         bpf_get_netns_cookie
#define skb_get_tunnel_key       bpf_skb_get_tunnel_key
#define skb_set_tunnel_key       bpf_skb_set_tunnel_key
#define skb_get_tunnel_opt       bpf_skb_get_tunnel_opt
#define skb_set_tunnel_opt       bpf_skb_set_tunnel_opt
#define fib_lookup               bpf_fib_lookup
#define sk_lookup_tcp            bpf_sk_lookup_tcp
#define sk_lookup_udp            bpf_sk_lookup_udp
#define sk_release               bpf_sk_release
#define get_prandom_u32          bpf_get_prandom_u32
#define get_smp_processor_id     bpf_get_smp_processor_id
#define get_hash_recalc          bpf_get_hash_recalc
#define set_hash_invalid         bpf_set_hash_invalid
#define get_cgroup_classid       bpf_get_cgroup_classid
#define skb_vlan_push            bpf_skb_vlan_push
#define skb_vlan_pop             bpf_skb_vlan_pop
#define map_push_elem            bpf_map_push_elem
#define map_pop_elem             bpf_map_pop_elem
#define map_peek_elem            bpf_map_peek_elem
#define map_lookup_percpu_elem   bpf_map_lookup_percpu_elem

#endif /* KLEE_VERIFICATION */

#endif /* __BPF_TYPES_MAPPER__ */
