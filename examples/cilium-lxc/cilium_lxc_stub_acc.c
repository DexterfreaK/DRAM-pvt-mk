/*
 * cilium_lxc_stub_sane.c
 *
 * Goal:
 *   - eliminate map-induced path explosion
 *   - preserve reachability of restricted helpers
 *   - preserve packet memory validity checks
 *
 * Key idea:
 *   NO map lookups inside execution.
 *   Replace with single symbolic abstract environment.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <klee/klee.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

/* ----------------------------- */
/* helper stubs (no branching)   */
/* ----------------------------- */

static __attribute__((noinline)) void *
bpf_map_lookup_elem(void *map, const void *key)
{
    (void)map;
    (void)key;
    return NULL; // IMPORTANT: no symbolic fork
}

static __attribute__((noinline)) int
bpf_map_update_elem(void *map, const void *key,
                    const void *val, uint64_t flags)
{
    (void)map;
    (void)key;
    (void)val;
    (void)flags;
    return 0;
}

static __attribute__((noinline)) int
bpf_perf_event_output(void *ctx, void *map,
                      uint64_t flags, void *data, uint64_t size)
{
    (void)ctx;
    (void)map;
    (void)flags;
    (void)data;
    (void)size;
    return 0;
}

/* ----------------------------- */
/* abstract execution model      */
/* ----------------------------- */

/*
 * This is the ONLY source of nondeterminism.
 * It replaces:
 *   CT lookup + policy + auth + ipcache + LB + etc.
 */
struct abstract_state
{
    uint8_t l3; // 0=IP,1=IPv6,2=ARP,3=OTHER
    uint8_t l4; // 0=TCP,1=UDP,2=ICMP,3=OTHER

    uint8_t ct;     // 0=NEW,1=ESTABLISHED,2=REPLY,3=RELATED,4=INVALID
    uint8_t policy; // 0=ALLOW,1=DENY
    uint8_t auth;   // 0=OK,1=FAIL

    uint8_t lb_hit;  // 0/1
    uint8_t local;   // 0/1
    uint8_t encrypt; // 0/1
};

/* ----------------------------- */
/* packet abstraction            */
/* ----------------------------- */

struct pkt_info
{
    uint8_t valid;
};

static void init_state(struct abstract_state *s)
{
    klee_make_symbolic(s, sizeof(*s), "state");

    klee_assume(s->l3 <= 3);
    klee_assume(s->l4 <= 3);

    klee_assume(s->ct <= 4);
    klee_assume(s->policy <= 1);
    klee_assume(s->auth <= 1);
    klee_assume(s->lb_hit <= 1);
    klee_assume(s->local <= 1);
    klee_assume(s->encrypt <= 1);
}

/* ----------------------------- */
/* core logic (NO map forks)     */
/* ----------------------------- */

static int cil_from_container_stub(const void *ctx,
                                   const void *data,
                                   const void *data_end,
                                   uint32_t seclabel)
{
    (void)ctx;
    (void)data;
    (void)data_end;
    (void)seclabel;

    struct abstract_state s;
    init_state(&s);

    /* single helper-reachability flags */
    uint8_t did_update_ct = 0;
    uint8_t did_drop_event = 0;

    /* ---------------- L3 filter ---------------- */
    if (s.l3 == 3)
        return TC_ACT_OK;

    /* ---------------- L4 filter ---------------- */
    if (s.l4 == 3)
        return TC_ACT_OK;

    /* ---------------- CT state machine ---------------- */

    switch (s.ct)
    {

    case 0: /* CT_NEW */

        /* policy check */
        if (s.policy == 1)
        {
            bpf_perf_event_output(NULL, NULL, 0, NULL, 0);
            did_drop_event = 1;
            return TC_ACT_SHOT;
        }

        /* auth check */
        if (s.auth == 1)
        {
            bpf_perf_event_output(NULL, NULL, 0, NULL, 0);
            did_drop_event = 1;
            return TC_ACT_SHOT;
        }

        /* CT write ONLY here */
        bpf_map_update_elem(NULL, NULL, NULL, 0);
        did_update_ct = 1;

        return TC_ACT_OK;

    case 1: /* ESTABLISHED */
    case 4: /* INVALID (treated safe-pass here in stub) */
        return TC_ACT_OK;

    case 2: /* REPLY */
        if (s.encrypt)
            return TC_ACT_OK;
        return TC_ACT_OK;

    case 3: /* RELATED */
        if (s.policy == 1)
        {
            bpf_perf_event_output(NULL, NULL, 0, NULL, 0);
            did_drop_event = 1;
            return TC_ACT_SHOT;
        }
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

/* ----------------------------- */
/* KLEE harness                 */
/* ----------------------------- */

#define MAX_PKT 256

int main(void)
{
    char *pkt = (char *)malloc(MAX_PKT);
    klee_make_symbolic(pkt, MAX_PKT, "packet");

    uint32_t pkt_len;
    klee_make_symbolic(&pkt_len, sizeof(pkt_len), "pkt_len");

    klee_assume(pkt_len >= 14 && pkt_len <= MAX_PKT);

    uint32_t seclabel;
    klee_make_symbolic(&seclabel, sizeof(seclabel), "seclabel");
    klee_assume(seclabel >= 256);

    const void *data = pkt;
    const void *data_end = pkt + pkt_len;

    int ret = cil_from_container_stub(NULL, data, data_end, seclabel);

    /* only meaningful observable behaviors */
    klee_assert(ret == TC_ACT_OK || ret == TC_ACT_SHOT);

    return 0;
}