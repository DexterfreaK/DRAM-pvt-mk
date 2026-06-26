/*
 * cilium_lxc_syn.c  —  Synthetic Cilium bpf_lxc path-explosion demo
 *
 * Mirrors the structural logic of Cilium's real cil_from_container
 * (bpf_lxc.c) without BPF-specific inline asm or complex header deps,
 * so it compiles cleanly for KLEE with -target x86_64.
 *
 * PATH EXPLOSION DRIVERS (same as real bpf_lxc.c):
 *
 *   1. L3 dispatch:  ETH_P_IP / ETH_P_IPV6 / ETH_P_ARP / other       × 4
 *   2. L4 dispatch:  TCP / UDP / ICMP / other                          × 4
 *   3. CT lookup:    miss (CT_NEW) / hit (CT_ESTABLISHED/REPLY/RELATED) × 5
 *   4. Policy check: miss (deny) / hit-allow / hit-deny                × 3
 *   5. Metrics:      hit / miss                                         × 2
 *   6. Auth map:     hit / miss                                         × 2
 *
 * Lower-bound: 4 × 4 × 5 × 3 × 2 × 2 = 960 paths.
 * KLEE exhausts the 60s budget after exploring a fraction of them.
 *
 * POLICY DEMO:
 *   constraints_syn.json restricts bpf_map_update_elem.
 *   cil_from_container_syn() CALLS bpf_map_update_elem on CT_NEW
 *   (connection-tracking entry creation), so KrakenGuard reports:
 *     "Restriction on use of helper function : bpf_map_update_elem"
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <klee/klee.h>

/* KrakenGuard verification phase markers */
void __start_verification(void) {}  /* tells KrakenGuard to start tracking */
void __separate(void) {}            /* switches from generate to check phase */

/* ------------------------------------------------------------------ */
/* BPF helper stubs                                                     */
/* Named bpf_map_lookup_elem / bpf_map_update_elem so KrakenGuard's    */
/* Executor.cpp:1748 pattern matches them for policy tracking.          */
/* ------------------------------------------------------------------ */

/* Each call to bpf_map_lookup_elem causes KLEE to fork:
 *   branch A: return NULL  (map miss)
 *   branch B: return ptr-to-symbolic-data  (map hit, contents unknown)
 * That doubles the live path count per call.                           */
static __attribute__((noinline)) void *
bpf_map_lookup_elem(const void *map, const void *key)
{
    int hit;
    klee_make_symbolic(&hit, sizeof hit, "map_hit");
    if (!hit)
        return (void *)0;
    void *val = malloc(128);
    klee_make_symbolic(val, 128, "map_val");
    return val;
}

static __attribute__((noinline)) int
bpf_map_update_elem(const void *map, const void *key,
                    const void *val, uint64_t flags)
{
    return 0;
}

static __attribute__((noinline)) int
bpf_map_delete_elem(const void *map, const void *key)
{
    return 0;
}

static __attribute__((noinline)) uint64_t bpf_ktime_get_ns(void) { return 0; }

static __attribute__((noinline)) int
bpf_perf_event_output(const void *ctx, const void *map,
                      uint64_t flags, void *data, uint64_t size)
{
    return 0;
}

static __attribute__((noinline)) int
bpf_trace_printk(const char *fmt, int fmt_size, ...) { return 0; }

/* ------------------------------------------------------------------ */
/* Return codes                                                         */
/* ------------------------------------------------------------------ */
#define TC_ACT_OK          0
#define TC_ACT_SHOT        2
#define TC_ACT_REDIRECT    7

/* ------------------------------------------------------------------ */
/* Ethernet / IP / transport constants                                  */
/* ------------------------------------------------------------------ */
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_ARP   0x0806

#define IPPROTO_ICMP   1
#define IPPROTO_TCP    6
#define IPPROTO_UDP   17
#define IPPROTO_ESP   50
#define IPPROTO_ICMPV6 58

/* Cilium drop reasons (negative ints, same as real code) */
#define DROP_INVALID          -1
#define DROP_UNKNOWN_L3       -3
#define DROP_POLICY          -13
#define DROP_CT_INVALID_HDR  -15

/* CT state codes */
#define CT_NEW          0
#define CT_ESTABLISHED  1
#define CT_REPLY        2
#define CT_RELATED      3
#define CT_REOPENED     4

/* ------------------------------------------------------------------ */
/* Packet header structs (inline — no kernel headers needed)            */
/* ------------------------------------------------------------------ */
struct ethhdr {
    uint8_t  h_dest[6];
    uint8_t  h_source[6];
    uint16_t h_proto;        /* big-endian */
} __attribute__((packed));

struct iphdr {
    uint8_t  ihl_version;    /* ihl:4 | version:4 */
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

struct ipv6hdr {
    uint8_t  prio_ver;       /* priority:4 | version:4 */
    uint8_t  flow_lbl[3];
    uint16_t payload_len;
    uint8_t  nexthdr;
    uint8_t  hop_limit;
    uint8_t  saddr[16];
    uint8_t  daddr[16];
} __attribute__((packed));

struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed));

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed));

/* ------------------------------------------------------------------ */
/* Cilium map key / value types (simplified but structurally identical) */
/* ------------------------------------------------------------------ */
struct ipv4_ct_tuple {
    uint32_t daddr, saddr;
    uint16_t dport, sport;
    uint8_t  nexthdr, flags;
};

struct ipv6_ct_tuple {
    uint8_t  daddr[16], saddr[16];
    uint16_t dport, sport;
    uint8_t  nexthdr, flags;
};

struct ct_entry {
    uint64_t rx_packets, rx_bytes;
    uint64_t tx_packets, tx_bytes;
    uint32_t lifetime;
    uint16_t flags;
    uint8_t  ct_state;   /* CT_NEW / CT_ESTABLISHED / CT_REPLY / CT_RELATED */
    uint8_t  rev_nat_index;
};

struct policy_key {
    uint32_t sec_label;
    uint16_t dport;
    uint8_t  protocol;
    uint8_t  egress;
};

struct policy_entry {
    uint16_t deny  : 1;
    uint16_t pad   : 15;
    uint16_t proxy_port;
    uint32_t auth_type;
};

struct metrics_key {
    uint8_t  reason;
    uint8_t  dir;
    uint16_t pad[3];
};

struct metrics_value {
    uint64_t count;
    uint64_t bytes;
};

struct auth_key {
    uint32_t local_sec_label;
    uint32_t remote_sec_label;
    uint16_t remote_node_id;
    uint8_t  auth_type;
    uint8_t  pad;
};

/* ------------------------------------------------------------------ */
/* Fake map handles (used only as opaque pointers by the stubs)         */
/* ------------------------------------------------------------------ */
static int g_ct_map4;
static int g_ct_map6;
static int g_policy_map;
static int g_metrics_map;
static int g_auth_map;
/* Additional maps matching real bpf_lxc.c — each adds a fork per path */
static int g_ipcache_map;        /* IP → security-label cache */
static int g_lxc_map;            /* local endpoint table */
static int g_lb_svc_map;         /* load-balancer service table */
static int g_lb_backends_map;    /* LB backend entry */
static int g_egress_policy_map;  /* per-endpoint egress policy */
static int g_encrypt_map;        /* node encryption state */
static int g_world_cidrs_map;    /* world CIDR prefix match */

/* ------------------------------------------------------------------ */
/* Connection-tracking lookup                                           */
/* Branch: CT miss (CT_NEW) or hit (symbolic ct_state byte)            */
/* ------------------------------------------------------------------ */
static int ct_lookup4(const void *ctx,
                      struct ipv4_ct_tuple *tuple,
                      const void *data, const void *data_end)
{
    struct ct_entry *entry =
        (struct ct_entry *)bpf_map_lookup_elem(&g_ct_map4, tuple);
    if (!entry) {
        /* New connection — insert CT entry (this is what the read-only
         * policy in constraints_syn.json RESTRICTS) */
        struct ct_entry new_e;
        memset(&new_e, 0, sizeof new_e);
        new_e.ct_state = CT_NEW;
        bpf_map_update_elem(&g_ct_map4, tuple, &new_e, 0 /* BPF_ANY */);
        return CT_NEW;
    }
    /* Hit: return the symbolic state — KLEE branches on each switch arm */
    return (int)entry->ct_state;
}

static int ct_lookup6(const void *ctx,
                      struct ipv6_ct_tuple *tuple,
                      const void *data, const void *data_end)
{
    struct ct_entry *entry =
        (struct ct_entry *)bpf_map_lookup_elem(&g_ct_map6, tuple);
    if (!entry) {
        struct ct_entry new_e;
        memset(&new_e, 0, sizeof new_e);
        new_e.ct_state = CT_NEW;
        bpf_map_update_elem(&g_ct_map6, tuple, &new_e, 0);
        return CT_NEW;
    }
    return (int)entry->ct_state;
}

/* ------------------------------------------------------------------ */
/* Policy check                                                         */
/* Branch: miss (deny) / hit-allow / hit-deny                          */
/* ------------------------------------------------------------------ */
static int policy_can_access(uint32_t src_label, uint16_t dport, uint8_t proto)
{
    struct policy_key key = {
        .sec_label = src_label,
        .dport     = dport,
        .protocol  = proto,
        .egress    = 0,
    };
    struct policy_entry *e =
        (struct policy_entry *)bpf_map_lookup_elem(&g_policy_map, &key);
    if (!e)
        return DROP_POLICY;
    if (e->deny)
        return DROP_POLICY;
    return TC_ACT_OK;
}

/* ------------------------------------------------------------------ */
/* Auth check (Cilium 1.14+ mutual auth)                               */
/* Extra map branch                                                     */
/* ------------------------------------------------------------------ */
static int auth_lookup(uint32_t src_label, uint32_t dst_label)
{
    struct auth_key key = {
        .local_sec_label  = dst_label,
        .remote_sec_label = src_label,
        .remote_node_id   = 0,
        .auth_type        = 0,
    };
    void *e = bpf_map_lookup_elem(&g_auth_map, &key);
    return e ? 0 : DROP_POLICY;
}

/* ------------------------------------------------------------------ */
/* Metrics update                                                       */
/* Another map branch (hit = update counter / miss = insert)            */
/* ------------------------------------------------------------------ */
static void update_metrics(uint8_t reason, uint8_t dir)
{
    struct metrics_key   key = { .reason = reason, .dir = dir };
    struct metrics_value *e  =
        (struct metrics_value *)bpf_map_lookup_elem(&g_metrics_map, &key);
    if (e) {
        e->count++;
    } else {
        struct metrics_value nv = { .count = 1, .bytes = 0 };
        bpf_map_update_elem(&g_metrics_map, &key, &nv, 0);
    }
}

/* ------------------------------------------------------------------ */
/* Drop-notify shim (mirrors Cilium's send_drop_notify)                 */
/* ------------------------------------------------------------------ */
static void send_drop_notify(const void *ctx, uint32_t src, uint32_t dst,
                             int reason)
{
    update_metrics((uint8_t)(unsigned int)(-reason), 0 /* INGRESS */);
    bpf_perf_event_output(ctx, &g_metrics_map, 0, &reason, sizeof reason);
}

/* ------------------------------------------------------------------ */
/* Extra lookups mirroring real bpf_lxc.c                              */
/* Each call adds one binary fork (map hit / miss) per path.            */
/* With 7 extra lookups below: 2^7=128 × existing 192 = path explosion  */
/* ------------------------------------------------------------------ */

/* ipcache: IP address → Cilium security identity */
static uint32_t ipcache_lookup4(uint32_t addr)
{
    struct { uint32_t addr; uint8_t plen, pad[3]; } key;
    key.addr = addr; key.plen = 32;
    struct { uint32_t sec_label; uint32_t tunnel_endpoint; } *e =
        bpf_map_lookup_elem(&g_ipcache_map, &key);
    return e ? e->sec_label : 0;
}

/* lxcmap: is the destination a local endpoint? */
static int lxc_lookup4(uint32_t dst_ip)
{
    struct { uint32_t ip; } key; key.ip = dst_ip;
    return bpf_map_lookup_elem(&g_lxc_map, &key) ? 1 : 0;
}

/* load-balancer service lookup */
struct lb4_key { uint32_t address; uint16_t dport; uint8_t proto, scope; };
struct lb4_service { uint32_t backend_id; uint16_t count; uint8_t flags, pad; };
struct lb4_backend { uint32_t address; uint16_t port; uint8_t proto, flags; };

static struct lb4_service *lb_svc_lookup4(uint32_t addr, uint16_t port, uint8_t proto)
{
    struct lb4_key key; key.address = addr; key.dport = port;
    key.proto = proto; key.scope = 0;
    return (struct lb4_service *)bpf_map_lookup_elem(&g_lb_svc_map, &key);
}

static struct lb4_backend *lb_backend_lookup(uint32_t id)
{
    return (struct lb4_backend *)bpf_map_lookup_elem(&g_lb_backends_map, &id);
}

/* egress policy map — separate from ingress */
static int egress_policy_can_access(uint32_t dst_label, uint16_t dport, uint8_t proto)
{
    struct policy_key key;
    key.sec_label = dst_label; key.dport = dport;
    key.protocol = proto; key.egress = 1;
    struct policy_entry *e =
        (struct policy_entry *)bpf_map_lookup_elem(&g_egress_policy_map, &key);
    if (!e)  return DROP_POLICY;
    if (e->deny) return DROP_POLICY;
    return TC_ACT_OK;
}

/* encryption state (IPSec / WireGuard) */
static int encrypt_lookup(uint32_t remote_node_id)
{
    struct { uint32_t node_id; } key; key.node_id = remote_node_id;
    return bpf_map_lookup_elem(&g_encrypt_map, &key) ? 1 : 0;
}

/* world-CIDR lookup (classify WORLD identity) */
static int world_lookup4(uint32_t addr)
{
    struct { uint32_t addr; uint8_t plen, pad[3]; } key;
    key.addr = addr; key.plen = 0;
    return bpf_map_lookup_elem(&g_world_cidrs_map, &key) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* IPv4 L4 handler                                                      */
/* ------------------------------------------------------------------ */
static int handle_ipv4_l4(const void *ctx,
                          const struct iphdr *ip,
                          const void *data, const void *data_end,
                          uint32_t seclabel)
{
    struct ipv4_ct_tuple tuple;
    memset(&tuple, 0, sizeof tuple);
    tuple.saddr   = ip->saddr;
    tuple.daddr   = ip->daddr;
    tuple.nexthdr = ip->protocol;

    unsigned int ihl = (ip->ihl_version & 0x0f) * 4;
    const void *l4 = (const void *)ip + ihl;

    if (ip->protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr *)l4;
        if ((const void *)(tcp + 1) > data_end)
            return DROP_INVALID;
        tuple.sport = tcp->source;
        tuple.dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        const struct udphdr *udp = (const struct udphdr *)l4;
        if ((const void *)(udp + 1) > data_end)
            return DROP_INVALID;
        tuple.sport = udp->source;
        tuple.dport = udp->dest;
    }

    /* -- CT lookup: KLEE forks on hit/miss, then on ct_state value -- */
    int ct_ret = ct_lookup4(ctx, &tuple, data, data_end);

    /* -- bandwidth / rate-limit policy lookup (real Cilium EDT path) --
     * Unconditional before CT → applies to every IPv4 path.            */
    {
        struct { uint32_t ifindex; } bw_key; bw_key.ifindex = 1;
        bpf_map_lookup_elem(&g_egress_policy_map, &bw_key); /* fork ×2 */
    }
    /* -- VTEP tunnel endpoint lookup (VXlan/Geneve encap check) --     */
    {
        struct { uint32_t vtep_ip; } vtep_key; vtep_key.vtep_ip = ip->daddr;
        bpf_map_lookup_elem(&g_world_cidrs_map, &vtep_key); /* fork ×2 */
    }

    /* -- ipcache: resolve src and dst IPs to security identities --
     * Two more map lookups → ×4 paths compared to no ipcache.         */
    uint32_t src_id = ipcache_lookup4(ip->saddr);  /* fork: miss→0 or hit→symbolic */
    uint32_t dst_id = ipcache_lookup4(ip->daddr);  /* fork: miss→0 or hit→symbolic */

    /* -- LB service check: is dst a virtual service IP? --
     * Two more map lookups → ×4 paths.                                 */
    struct lb4_service *svc = lb_svc_lookup4(ip->daddr, tuple.dport, ip->protocol);
    if (svc) {
        /* Service hit: look up backend — another fork */
        struct lb4_backend *backend = lb_backend_lookup(svc->backend_id);
        if (!backend) {
            return DROP_INVALID;
        }
        /* In real Cilium: DNAT to backend, update CT */
        bpf_map_update_elem(&g_ct_map4, &tuple, &(struct ct_entry){0}, 0);
    }

    /* -- World-range lookup: is src from the internet? --
     * One more map lookup → ×2 paths.                                  */
    int from_world = world_lookup4(ip->saddr);

    /* -- Encrypt state check -- one more map lookup → ×2 paths        */
    int needs_encrypt = encrypt_lookup(dst_id);

    /* -- CT state machine -- */
    switch (ct_ret) {
    case CT_NEW: {
        /* Ingress policy for new connections */
        int verdict = policy_can_access(seclabel ? seclabel : src_id,
                                        tuple.dport, ip->protocol);
        if (verdict != TC_ACT_OK) {
            send_drop_notify(ctx, ip->saddr, ip->daddr, DROP_POLICY);
            update_metrics((uint8_t)(unsigned int)(-DROP_POLICY), 0);
            return TC_ACT_SHOT;
        }
        /* Egress policy check for the return direction */
        int ev = egress_policy_can_access(dst_id, tuple.dport, ip->protocol);
        if (ev != TC_ACT_OK) {
            send_drop_notify(ctx, ip->saddr, ip->daddr, DROP_POLICY);
            return TC_ACT_SHOT;
        }
        /* Mutual-auth check */
        int auth = auth_lookup(seclabel, src_id);
        if (auth != 0) {
            send_drop_notify(ctx, ip->saddr, ip->daddr, DROP_POLICY);
            return TC_ACT_SHOT;
        }
        /* Local endpoint check */
        int is_local = lxc_lookup4(ip->daddr);
        (void)is_local;
        update_metrics(0, 1 /* METRIC_INGRESS */);
        break;
    }
    case CT_ESTABLISHED:
    case CT_REOPENED:
        update_metrics(0, 1);
        break;

    case CT_REPLY:
        /* Reply traffic: check encrypt on egress */
        if (needs_encrypt)
            update_metrics(0, 2 /* METRIC_EGRESS */);
        else
            update_metrics(0, 2);
        break;

    case CT_RELATED:
        /* ICMP error: re-check policy */
        if (policy_can_access(seclabel ? seclabel : src_id,
                              0, ip->protocol) != TC_ACT_OK) {
            send_drop_notify(ctx, ip->saddr, ip->daddr, DROP_POLICY);
            return TC_ACT_SHOT;
        }
        update_metrics(0, 1);
        break;

    default:
        return DROP_CT_INVALID_HDR;
    }

    (void)from_world;
    return TC_ACT_OK;
}

/* ------------------------------------------------------------------ */
/* IPv4 entry                                                           */
/* ------------------------------------------------------------------ */
static int handle_ipv4(const void *ctx,
                       const void *data, const void *data_end,
                       uint32_t seclabel)
{
    const struct iphdr *ip =
        (const struct iphdr *)((const uint8_t *)data + sizeof(struct ethhdr));
    if ((const void *)(ip + 1) > data_end)
        return DROP_INVALID;

    /* Fragmented packets: simplified passthrough (real code is more complex) */
    if (ip->frag_off & 0xFF1F)
        return TC_ACT_OK;

    switch (ip->protocol) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_ICMP:
        return handle_ipv4_l4(ctx, ip, data, data_end, seclabel);
    case IPPROTO_ESP:
        return TC_ACT_OK;  /* Encrypted — just pass */
    default:
        return TC_ACT_OK;
    }
}

/* ------------------------------------------------------------------ */
/* IPv6 entry (mirrors IPv4 structure, separate CT map)                 */
/* ------------------------------------------------------------------ */
static int handle_ipv6(const void *ctx,
                       const void *data, const void *data_end,
                       uint32_t seclabel)
{
    const struct ipv6hdr *ip6 =
        (const struct ipv6hdr *)((const uint8_t *)data + sizeof(struct ethhdr));
    if ((const void *)(ip6 + 1) > data_end)
        return DROP_INVALID;

    struct ipv6_ct_tuple tuple6;
    memset(&tuple6, 0, sizeof tuple6);
    memcpy(tuple6.saddr, ip6->saddr, 16);
    memcpy(tuple6.daddr, ip6->daddr, 16);
    tuple6.nexthdr = ip6->nexthdr;

    const void *l4 = (const void *)(ip6 + 1);
    if (ip6->nexthdr == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr *)l4;
        if ((const void *)(tcp + 1) > data_end) return DROP_INVALID;
        tuple6.sport = tcp->source;
        tuple6.dport = tcp->dest;
    } else if (ip6->nexthdr == IPPROTO_UDP) {
        const struct udphdr *udp = (const struct udphdr *)l4;
        if ((const void *)(udp + 1) > data_end) return DROP_INVALID;
        tuple6.sport = udp->source;
        tuple6.dport = udp->dest;
    }

    int ct_ret = ct_lookup6(ctx, &tuple6, data, data_end);

    switch (ct_ret) {
    case CT_NEW: {
        int verdict = policy_can_access(seclabel, tuple6.dport, ip6->nexthdr);
        if (verdict != TC_ACT_OK) {
            send_drop_notify(ctx, 0, 0, DROP_POLICY);
            return TC_ACT_SHOT;
        }
        int auth = auth_lookup(seclabel, 0);
        if (auth != 0) {
            send_drop_notify(ctx, 0, 0, DROP_POLICY);
            return TC_ACT_SHOT;
        }
        update_metrics(0, 1);
        break;
    }
    case CT_ESTABLISHED:
    case CT_REOPENED:
    case CT_REPLY:
        update_metrics(0, 1);
        break;
    case CT_RELATED:
        if (policy_can_access(seclabel, 0, ip6->nexthdr) != TC_ACT_OK) {
            send_drop_notify(ctx, 0, 0, DROP_POLICY);
            return TC_ACT_SHOT;
        }
        update_metrics(0, 1);
        break;
    default:
        return DROP_CT_INVALID_HDR;
    }

    return TC_ACT_OK;
}

/* ------------------------------------------------------------------ */
/* ARP (real Cilium does ARP reply + neighbor cache update)             */
/* ------------------------------------------------------------------ */
static int handle_arp(const void *ctx,
                      const void *data, const void *data_end)
{
    /* Simplified: one policy-map check to mirror real Cilium's ARP path */
    struct policy_key key = { .sec_label = 1, .dport = 0,
                              .protocol = 0, .egress = 0 };
    bpf_map_lookup_elem(&g_policy_map, &key);
    return TC_ACT_OK;
}

/* ------------------------------------------------------------------ */
/* Main entry — cil_from_container (TC ingress hook)                    */
/* ------------------------------------------------------------------ */
int cil_from_container_syn(const void *ctx,
                           const void *data, const void *data_end,
                           uint32_t seclabel)
{
    const struct ethhdr *eth = (const struct ethhdr *)data;
    if ((const void *)(eth + 1) > data_end)
        return DROP_INVALID;

    /* h_proto is big-endian; compare with swapped constants */
    uint16_t proto = eth->h_proto;

    if (proto == (uint16_t)((ETH_P_IP   >> 8) | (ETH_P_IP   << 8)))
        return handle_ipv4(ctx, data, data_end, seclabel);
    if (proto == (uint16_t)((ETH_P_IPV6 >> 8) | (ETH_P_IPV6 << 8)))
        return handle_ipv6(ctx, data, data_end, seclabel);
    if (proto == (uint16_t)((ETH_P_ARP  >> 8) | (ETH_P_ARP  << 8)))
        return handle_arp(ctx, data, data_end);

    return TC_ACT_OK;   /* unknown L3 → pass */
}

/* ================================================================== */
/* KLEE harness                                                         */
/* ================================================================== */
#define MAX_PKT 256

int main(void)
{
    /*
     * Symbolic packet:  every byte is unconstrained so KLEE explores
     * all L3/L4 protocol combinations simultaneously.
     *
     * Packet is heap-allocated (kdalloc at 0x40000000) so its address
     * fits in a u32 if needed by map-stub infrastructure.
     */
    char *pkt = (char *)malloc(MAX_PKT);
    klee_make_symbolic(pkt, MAX_PKT, "packet");

    uint32_t pkt_len;
    klee_make_symbolic(&pkt_len, sizeof pkt_len, "pkt_len");
    klee_assume(pkt_len >= (uint32_t)sizeof(struct ethhdr) &&
                pkt_len <= MAX_PKT);

    /* Symbolic source security label (Cilium identity of the sending pod) */
    uint32_t seclabel;
    klee_make_symbolic(&seclabel, sizeof seclabel, "seclabel");
    klee_assume(seclabel >= 256);   /* labels below 256 are reserved IDs */

    const void *data     = pkt;
    const void *data_end = pkt + pkt_len;

    __start_verification();  /* begin KrakenGuard helper-function tracking */
    int ret = cil_from_container_syn(NULL, data, data_end, seclabel);

    /* Reachable verdict set */
    klee_assert(ret == TC_ACT_OK      ||
                ret == TC_ACT_SHOT    ||
                ret == TC_ACT_REDIRECT ||
                ret == DROP_INVALID   ||
                ret == DROP_POLICY    ||
                ret == DROP_CT_INVALID_HDR);

    return 0;
}
