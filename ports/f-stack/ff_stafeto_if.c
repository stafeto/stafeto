/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * The host layer of F-Stack on stafeto, in place of ff_dpdk_if.c: what the
 * FreeBSD stack expects of DPDK. This first stage has no network device:
 * the stack runs on its loopback interface alone.
 *
 * - Memory: the stack takes its memory through ff_mmap and ff_malloc
 *   (ff_host_interface.c), anonymous memory of the process.
 * - Frames: an interface without a device drops what it is given to send
 *   and counts it; no frame is ever received.
 * - Time: ff_get_tsc_ns reads CLOCK_MONOTONIC (the C library reads the
 *   counter of the core without a call to the kernel), and a pass of the
 *   loop runs ff_hardclock once per 1/hz that has passed, at most
 *   FF_STAFETO_MAX_TICKS in one pass.
 * - The loop: ff_stafeto_pass is one step of the stack (clock ticks, the
 *   queued work of the stack's software interrupts, which delivers the
 *   loopback's packets); ff_run calls it, then the program's function,
 *   and sleeps until the next tick when neither found anything to do (the
 *   function returns more than 0 when it did work) and no work is queued.
 * - Settings: ff_load_config reads the file (the [dpdk] section only for
 *   its form); no port is attached.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ff_api.h"
#include "ff_config.h"
#include "ff_dpdk_if.h"
#include "ff_host_interface.h"
#include "ff_stafeto_rte.h"
#include "ff_veth.h"

/* At most this many clock ticks in one pass, when the loop was late. */
#define FF_STAFETO_MAX_TICKS 10
#define NSEC_PER_SEC 1000000000ULL

extern void ff_hardclock(void);
/* The workstreams of the stack's software interrupts that had work
 * (freebsd/net/netisr.c, FF_STAFETO). */
extern unsigned long ff_stafeto_netisr_runs;
extern int ff_stafeto_netisr_pending(void);
struct ff_flow_key;

/* The log of ff_stafeto_rte.h: everything to stderr, a type's messages up
 * to INFO (the stack's console). */
FILE *ff_stafeto_log_stream;
uint32_t ff_stafeto_log_global = FF_STAFETO_LOG_DEBUG;
uint32_t ff_stafeto_log_levels[FF_STAFETO_LOG_TYPES] = {
    [0 ... FF_STAFETO_LOG_TYPES - 1] = FF_STAFETO_LOG_INFO,
};

/* Counters of the layer (ff_stafeto_counters). */
static uint64_t tx_dropped;
static uint64_t ticks_done;
static uint64_t passes;

/* The clock of the stack: the time of the next tick and its period. */
static uint64_t next_tick_ns;
static uint64_t tick_ns;
static volatile int stop_loop;

struct ff_dpdk_if_context {
    void *sc;
    void *ifp;
    uint16_t port_id;
    uint16_t mtu;
};

uint64_t
ff_get_tsc_ns(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * NSEC_PER_SEC + (uint64_t)now.tv_nsec;
}

int
ff_cur_proc_id(void)
{
    return 0;
}

int
ff_dpdk_init(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (ff_global_cfg.freebsd.hz <= 0 || ff_global_cfg.freebsd.hz > 1000) {
        fprintf(stderr, "f-stack: freebsd.boot hz %d is out of 1..1000\n",
            ff_global_cfg.freebsd.hz);
        return -1;
    }
    tick_ns = NSEC_PER_SEC / (uint64_t)ff_global_cfg.freebsd.hz;
    return 0;
}

int
ff_dpdk_if_up(void)
{
    /* No device: the loopback interface of the stack is the only one. */
    next_tick_ns = ff_get_tsc_ns() + tick_ns;
    ff_update_current_ts();
    return 0;
}

struct ff_dpdk_if_context *
ff_dpdk_register_if(void *sc, void *ifp, struct ff_port_cfg *cfg)
{
    struct ff_dpdk_if_context *ctx = calloc(1, sizeof(*ctx));

    if (ctx == NULL)
        return NULL;
    ctx->sc = sc;
    ctx->ifp = ifp;
    ctx->port_id = cfg->port_id;
    ctx->mtu = cfg->mtu;
    return ctx;
}

void
ff_dpdk_deregister_if(struct ff_dpdk_if_context *ctx)
{
    free(ctx);
}

int
ff_dpdk_if_get_mtu(struct ff_dpdk_if_context *ctx, uint16_t *mtu)
{
    *mtu = ctx->mtu ? ctx->mtu : 1500;
    return 0;
}

int
ff_dpdk_if_set_mtu(struct ff_dpdk_if_context *ctx, uint16_t mtu)
{
    ctx->mtu = mtu;
    return 0;
}

int
ff_dpdk_if_send(struct ff_dpdk_if_context *ctx, void *m, int total)
{
    (void)ctx;
    (void)total;
    /* No device to send on: the frame is dropped and counted. */
    tx_dropped++;
    ff_mbuf_free(m);
    return 0;
}

void
ff_dpdk_pktmbuf_free(void *m)
{
    /* Only frames of a device are external buffers of the stack's mbufs. */
    (void)m;
}

/*
 * One step of the stack: the clock ticks that are due, then the queued
 * work of the software interrupts. Returns the units of work done (the
 * workstreams that had work), 0 when the step found the stack idle.
 */
int
ff_stafeto_pass(void)
{
    unsigned long runs = ff_stafeto_netisr_runs;
    uint64_t now = ff_get_tsc_ns();
    int ticks = 0;

    passes++;
    while (now >= next_tick_ns && ticks < FF_STAFETO_MAX_TICKS) {
        ff_hardclock();
        ff_update_current_ts();
        next_tick_ns += tick_ns;
        ticks++;
    }
    /* A loop late by more than the bound starts the clock again from now. */
    if (now >= next_tick_ns)
        next_tick_ns = now + tick_ns;
    ticks_done += (uint64_t)ticks;
    ff_swi_net_excute();
    return (int)(ff_stafeto_netisr_runs - runs);
}

/* The time to the next clock tick in nanoseconds, 0 when it is due. */
uint64_t
ff_stafeto_next_tick_ns(void)
{
    uint64_t now = ff_get_tsc_ns();

    return now >= next_tick_ns ? 0 : next_tick_ns - now;
}

void
ff_dpdk_run(loop_func_t loop, void *arg)
{
    stop_loop = 0;
    while (!stop_loop) {
        int work = ff_stafeto_pass();
        int busy = loop(arg);

        if (work == 0 && busy <= 0 && ff_stafeto_netisr_pending() == 0) {
            uint64_t wait = ff_stafeto_next_tick_ns();
            struct timespec ts = {
                .tv_sec = (time_t)(wait / NSEC_PER_SEC),
                .tv_nsec = (long)(wait % NSEC_PER_SEC),
            };

            if (wait)
                nanosleep(&ts, NULL);
        }
    }
}

void
ff_dpdk_stop(void)
{
    stop_loop = 1;
}

/* The counters of the layer, for the probes. */
void
ff_stafeto_counters(uint64_t *dropped, uint64_t *ticks, uint64_t *pass_count)
{
    if (dropped)
        *dropped = tx_dropped;
    if (ticks)
        *ticks = ticks_done;
    if (pass_count)
        *pass_count = passes;
}

/* `len` bytes of the stack's random source (ff_arc4rand), for the probe. */
void
ff_stafeto_random(void *buf, unsigned int len)
{
    ff_arc4rand(buf, len, 0);
}

/*
 * The flow map and receive-side scaling of F-Stack serve several processes
 * on the queues of one device; a single stack has neither. Every local
 * port is open to it, no flow is recorded, no RSS table exists.
 */
int
ff_flow_map_active(void)
{
    return 0;
}

int
ff_flow_map_lport_ok(uint16_t lport)
{
    (void)lport;
    return 1;
}

int
ff_flow_map_lookup(const struct ff_flow_key *key)
{
    (void)key;
    return 0;
}

int
ff_flow_map_admit(const struct ff_flow_key *key, int *created)
{
    (void)key;
    *created = 0;
    return 1;
}

int
ff_flow_map_revoke(const struct ff_flow_key *key)
{
    (void)key;
    return 0;
}

int
ff_flow_peer_recording(void)
{
    return 0;
}

void
ff_flow_peer_note(const struct ff_flow_key *key)
{
    (void)key;
}

int
ff_in_pcbladdr(uint16_t family, void *faddr, uint16_t fport, void *laddr)
{
    /* The stack chooses the local address by its routes. */
    (void)family;
    (void)faddr;
    (void)fport;
    (void)laddr;
    return 0;
}

int
ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport)
{
    (void)softc;
    (void)saddr;
    (void)daddr;
    (void)sport;
    (void)dport;
    return 1;
}

int
ff_rss_tbl_set_portrange(uint16_t first, uint16_t last)
{
    (void)first;
    (void)last;
    return -1;
}

int
ff_rss_tbl_get_portrange(uint32_t saddr, uint32_t daddr, uint16_t sport,
    uint16_t *rss_first, uint16_t *rss_last, uint16_t **rss_portrange)
{
    (void)saddr;
    (void)daddr;
    (void)sport;
    (void)rss_first;
    (void)rss_last;
    (void)rss_portrange;
    return -ENOENT;
}

int
ff_rss_adjust_sport(void *softc, uint32_t saddr, uint32_t daddr, uint16_t dport,
    uint16_t *out_sport, uint16_t first, uint16_t last)
{
    (void)softc;
    (void)saddr;
    (void)daddr;
    (void)dport;
    (void)out_sport;
    (void)first;
    (void)last;
    return -1;
}

int
ff_stafeto_errno(int error)
{
    int saved = errno, mapped;

    ff_os_errno(error);
    mapped = errno;
    errno = saved;
    return mapped;
}
