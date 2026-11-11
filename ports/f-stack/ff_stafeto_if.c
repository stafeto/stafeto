/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * The host layer of F-Stack on stafeto, in place of ff_dpdk_if.c: what the
 * FreeBSD stack expects of DPDK.
 *
 * - Memory: the stack takes its memory through ff_mmap and ff_malloc
 *   (ff_host_interface.c), anonymous memory of the process. The frames of
 *   the device lie in the four objects of 4 MiB of the claim.
 * - Frames: with a claim (ff_stafeto_attach) the stack has the second
 *   network device as its interface, driven with libvirtio_net.a. Frames
 *   come in without a copy while the pool holds FF_STAFETO_RX_LOW free
 *   buffers (the mbuf's storage is the buffer, which goes back to the pool
 *   when the stack frees the mbuf) and with one copy below that; a frame
 *   goes out with one copy into a buffer of the pool. A DHCP message from
 *   the server (UDP 67 to 68) goes to the network service through the
 *   bypass ring, and so does a copy of every ARP reply for the stack's
 *   address; the frames the service puts in the ring go out on the wire.
 *   Without a claim an interface drops what it is given to send and counts
 *   it, and no frame is received: the stack has its loopback alone.
 * - Time: ff_get_tsc_ns reads CLOCK_MONOTONIC (the C library reads the
 *   counter of the core without a call to the kernel), and a pass of the
 *   loop runs ff_hardclock once per 1/hz that has passed, at most
 *   FF_STAFETO_MAX_TICKS in one pass.
 * - The loop: ff_stafeto_pass is one step of the stack (clock ticks, the
 *   frames of the device, the queued work of the stack's software
 *   interrupts, the frames to send); ff_run calls it, then the program's
 *   function, and ff_stafeto_sleep when neither found anything to do.
 *   Under load the device's interrupts stay off. Idle, they go on, the
 *   queue is looked at once more, and the thread waits on the network
 *   service's notification for at most the time to the next tick (10 ms at
 *   hz 100).
 * - The switch: when the claim is of kind STAFETO_FAST_PORT the process
 *   attached to the network service's switch instead of owning a device
 *   (ff_stafeto_attach, <stafeto/fast.h>). The interface is a virtual device
 *   over the ring of the consumer (vnet_port_*): frames of the wire come
 *   from DONE in cells the process owns (the mbuf's storage is the cell, which
 *   goes back to FILL when the mbuf is freed, as long as FILL holds
 *   FF_STAFETO_PORT_RX_LOW cells; below that one copy), a frame goes out
 *   with one copy into a cell of TX, the sum of a TCP segment is the
 *   switch's to complete (entry flag TX_SUM; the stack leaves the sum of its
 *   pseudo-header) and a received segment whose sum is good comes with
 *   DONE_SUM_OK; the other sums are the stack's, the
 *   address and the MAC are the shared ones of the attach. ARP and DHCP
 *   belong to the service. The switch is poked only while it sleeps, and
 *   the thread sleeps with consumer_idle set (full barrier on both sides).
 *   A frame to the shared address goes into the ring like any other: the
 *   switch turns it round (stafeto.patch keeps it off lo0).
 * - Settings: ff_load_config reads the file (the [dpdk] section only for
 *   its form); the interface of the device takes its address, mask,
 *   gateway and MAC from the claim, with no [port0] section.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <stafeto/fast.h>
#include <vnet.h>

#include "ff_api.h"
#include "ff_config.h"
#include "ff_dpdk_if.h"
#include "ff_errno.h"
#include "ff_host_interface.h"
#include "ff_stafeto.h"
#include "ff_stafeto_rte.h"
#include "ff_veth.h"

/* Time stamps along the packet path (lib/trace; the build of the measurement
 * `cargo xtask net-trace` defines STAFETO_TRACE): the points of the worker, the numbers
 * of lib/trace's `P_W_*`. Without the definition they are empty. */
#ifdef STAFETO_TRACE
extern void stafeto_trace_point(unsigned id, unsigned key);
extern void stafeto_trace_frame(unsigned id, const void *frame, unsigned len, int from_client);
#define TRACE_POINT(id, key) stafeto_trace_point((id), (key))
#define TRACE_FRAME(id, frame, len, from_client) stafeto_trace_frame((id), (frame), (len), (from_client))
#else
#define TRACE_POINT(id, key) ((void)0)
#define TRACE_FRAME(id, frame, len, from_client) ((void)0)
#endif
#define TP_WAKE 32
#define TP_RX 33
#define TP_TX 34
#define TP_KICK 35
#define TP_SLEEP 36
#define TP_FOUND 37

/* At most this many clock ticks in one pass, when the loop was late. */
#define FF_STAFETO_MAX_TICKS 10
#define NSEC_PER_SEC 1000000000ULL
/* Frames taken from the queue of receiving, and frames put in the queue
 * of sending before the doorbell, in one pass. */
#define FF_STAFETO_RX_BURST 32
#define FF_STAFETO_TX_BATCH 32
/* Frames come in without a copy while the pool holds this many free
 * buffers or more: the stack keeps a buffer as long as its data lies in a
 * socket's queue, and an empty queue of receiving drops frames silently. */
#define FF_STAFETO_RX_LOW 1024
/* The same threshold for the cells of the switch's FILL. */
#define FF_STAFETO_PORT_RX_LOW 512
/* The bits of the switch's notifications (proto_net::switch WAKE_*): the
 * ring, a broken ring, a new address, the end of the consumer. */
#define PORT_WAKE_BROKEN 2u
#define PORT_WAKE_ADDRESS 4u
#define PORT_WAKE_GONE 8u
/* The longest frame of the wire the interface takes: header and MTU. */
#define FF_STAFETO_FRAME_MAX 1514
#define FF_STAFETO_FRAME_MIN 60
#define BYPASS_KICK_MAX 16
/* How long a frame waits for room in the full queue of sending. */
#define FF_STAFETO_TX_WAIT_US 500

extern void ff_hardclock(void);
/* The workstreams of the stack's software interrupts that had work
 * (freebsd/net/netisr.c, FF_STAFETO). */
extern unsigned long ff_stafeto_netisr_runs;
extern int ff_stafeto_netisr_pending(void);
/* The loopback interface takes in a packet of the loopback network that
 * came through the switch (freebsd/net/if_loop.c, FF_STAFETO). */
extern void ff_stafeto_lo_input(void *mbuf);
#define VNET_PORT_DONE_LOOP 4
/* The sum of the TCP segment is good (the device checked it, or the frame never left the
 * service); the stack does not check it. */
#define VNET_PORT_DONE_SUM_OK 0x100
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

/* The device: the claim, the interface the stack made of it, what the
 * network service told, the frames put in the queue of sending since the
 * doorbell, and the frames put in the bypass ring since the last kick. */
static struct stafeto_fast_claim dev_claim;
static int dev_on;
static int dev_lost;
/* The device is the switch's ring (the claim is of kind PORT). */
static int port_on;
static struct ff_dpdk_if_context *dev_ctx;
static uint32_t notified;
/* The service let go of its notifications (STAFETO_FAST_GONE): from then on
 * every pass asks the device whether it is still the program's. */
static int service_gone;
static int tx_batch;
static int tx_stalled;
static int bypass_batch;
static struct ff_stafeto_device_stats stats;

/* The clock of the stack: the time of the next tick and its period. */
static uint64_t next_tick_ns;
static uint64_t tick_ns;
static volatile int stop_loop;
#define dev_notify ff_stafeto_notify

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

#define ETH 14

static inline uint64_t
counter(void)
{
    uint64_t v;

    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(v) : : "memory");
    return v;
}

static inline uint16_t
be16(const uint8_t *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

static int
same(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

/* The IPv4 header of a frame: its length, or 0 when the frame holds no
 * whole, unfragmented IPv4 datagram. */
static unsigned
ipv4(const uint8_t *f, uint32_t len)
{
    unsigned header, total;

    if (len < ETH + 20 || f[12] != 0x08 || f[13] != 0x00 || f[14] >> 4 != 4)
        return 0;
    header = (f[14] & 0x0f) * 4u;
    total = be16(f + ETH + 2);
    if (header < 20 || total < header || ETH + total > len ||
        (be16(f + ETH + 6) & 0x3fff) != 0)
        return 0;
    return header;
}

int
ff_stafeto_attach(const struct stafeto_fast_claim *claim)
{
    if (dev_on || claim == NULL)
        return -1;
    dev_claim = *claim;
    dev_on = 1;
    port_on = claim->kind == STAFETO_FAST_PORT;
    return 0;
}

/* The cells of FILL the switch may still take, or the buffers of the pool
 * that are free: what the threshold of the copy path measures. */
static uint32_t
rx_free(void)
{
    return port_on ? vnet_port_fill_free() : vnet_buf_free();
}

int
ff_stafeto_device_lost(void)
{
    return dev_lost;
}

/* The word the program's loop gives ff_stafeto_absorb when its sleep ended by the
 * deadline (no notification, no event): the ring is looked at now, before the
 * interrupts go off, and a frame in it waited through the sleep. */
#define FF_STAFETO_DEADLINE_MARK 0x80000000u

void
ff_stafeto_absorb(uint32_t bits)
{
    if (bits == 0)
        return;
    if (bits == FF_STAFETO_DEADLINE_MARK) {
        if (port_on ? vnet_port_rx_pending() : vnet_rx_pending())
            stats.deadline_found++;
        return;
    }
    __atomic_fetch_or(&notified, bits, __ATOMIC_RELAXED);
    stats.notifications++;
}

/* What the network service told since the last look: its end or the
 * device's loss, and a new address (a lease; the stack keeps its own). */
static void
take_notifications(void)
{
    uint32_t bits;

    /* The service ends before init resets the device: the bit is kept until
     * the reset shows. */
    if (!port_on && service_gone && vnet_lost())
        dev_lost = 1;
    if (__atomic_load_n(&notified, __ATOMIC_RELAXED) == 0)
        return;
    bits = __atomic_exchange_n(&notified, 0, __ATOMIC_RELAXED);
    if (port_on) {
        /* A broken ring or a new address (the stack keeps its own address,
         * so the worker ends and the master starts one that has the new
         * address): status 1, which nginx's master answers with a new
         * worker. The end of the consumer or of the service (the program's
         * loop sees CLIENT_GONE itself): status 2, which it does not. */
        if (bits & (PORT_WAKE_BROKEN | PORT_WAKE_ADDRESS)) {
            fprintf(stderr, "f-stack: the switch says the ring %s; the process ends\n",
                (bits & PORT_WAKE_BROKEN) ? "is broken" : "has a new address");
            fflush(stderr);
            exit(1);
        }
        if (bits & (PORT_WAKE_GONE | STAFETO_FAST_GONE)) {
            service_gone = 1;
            dev_lost = 1;
            if (bits & PORT_WAKE_GONE) {
                fprintf(stderr, "f-stack: the switch let the consumer go; the process ends\n");
                fflush(stderr);
                exit(2);
            }
        }
        return;
    }
    if (bits & STAFETO_FAST_GONE) {
        service_gone = 1;
        if (vnet_lost())
            dev_lost = 1;
    }
    if (bits & STAFETO_FAST_ADDRESS) {
        struct stafeto_fast_config c;

        if (stafeto_fast_config(&c) == 0)
            fprintf(stderr, "f-stack: the service says the address is now %u.%u.%u.%u/%u\n",
                c.address[0], c.address[1], c.address[2], c.address[3], c.prefix);
    }
}

/* One look at the service's channel, without waiting. */
static void
look_at_channel(void)
{
    uint32_t bits = 0;

    if (stafeto_fast_wait(0, &bits) == 0)
        ff_stafeto_absorb(bits);
    /* The bit GONE comes once. A loop that took it off the channel (the
     * POSIX layer's epoll_pwait) gives it to ff_stafeto_absorb through the
     * table; the loss itself is sticky in the layer, so a look here that
     * missed the bit still learns it. */
    if (!service_gone && stafeto_fast_lost())
        ff_stafeto_absorb(STAFETO_FAST_GONE);
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
    if (dev_on && port_on) {
        uint64_t frequency;

        /* The ring object is mapped at `window`; the sizes are in the
         * words of the snapshot (<stafeto/fast.h>, kind PORT). */
        if (vnet_port_open((void *)(uintptr_t)dev_claim.window, dev_claim.snapshot[2],
                dev_claim.snapshot[3]) != 0) {
            fprintf(stderr, "f-stack: vnet_port_open failed\n");
            return -1;
        }
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
        stats.ticks_per_second = frequency;
        stats.free_low = vnet_port_fill_free();
    } else if (dev_on) {
        int opened = vnet_open(&dev_claim);

        if (opened != 0) {
            fprintf(stderr, "f-stack: vnet_open failed %d\n", opened);
            return -1;
        }
        {
            uint64_t frequency;

            __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
            stats.ticks_per_second = frequency;
        }
        stats.free_low = vnet_buf_free();
    }
    return 0;
}

static void
dotted(char *out, uint32_t a)
{
    snprintf(out, 16, "%u.%u.%u.%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255);
}

int
ff_dpdk_if_up(void)
{
    next_tick_ns = ff_get_tsc_ns() + tick_ns;
    ff_update_current_ts();
    if (dev_on) {
        /* The interface of the device: the address, mask, broadcast and
         * gateway of the claim as the strings F-Stack's attach reads. On the
         * device of the second claim a checksum is the stack's to make and to
         * check (no feature of the device is negotiated); on the switch's ring
         * the switch completes the sum of a TCP segment (TX_SUM) and says when a
         * received segment's sum is good (DONE_SUM_OK), the sums of UDP stay
         * the layer's (ff_dpdk_if_send) and the stack's own header sum of IPv4
         * is made and checked here (tx_csum_ip stays 0). */
        const struct stafeto_fast_config *c = &dev_claim.config;
        struct ff_port_cfg cfg;
        char addr[16], mask[16], bcast[16], gateway[16];
        uint32_t a = (uint32_t)c->address[0] << 24 | (uint32_t)c->address[1] << 16 |
            (uint32_t)c->address[2] << 8 | c->address[3];
        uint32_t g = (uint32_t)c->gateway[0] << 24 | (uint32_t)c->gateway[1] << 16 |
            (uint32_t)c->gateway[2] << 8 | c->gateway[3];
        uint32_t m = c->prefix == 0 ? 0 : ~0u << (32 - c->prefix);

        dotted(addr, a);
        dotted(mask, m);
        dotted(bcast, a | ~m);
        dotted(gateway, g);
        memset(&cfg, 0, sizeof(cfg));
        cfg.port_id = 0;
        memcpy(cfg.mac, c->mac, 6);
        cfg.addr = addr;
        cfg.netmask = mask;
        cfg.broadcast = bcast;
        cfg.gateway = gateway;
        if (port_on) {
            cfg.hw_features.rx_csum = 1;
            /* Only a device that completes the sums (snapshot[6]) takes
             * segments without them; else the stack sums its own. */
            cfg.hw_features.tx_csum_l4 = dev_claim.snapshot[6] != 0;
        }
        dev_ctx = ff_veth_attach(&cfg);
        if (dev_ctx == NULL) {
            fprintf(stderr, "f-stack: the interface of the device did not attach\n");
            return -1;
        }
    }
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
    /* The stack sends (the announcement of the address) while it attaches. */
    if (dev_on && dev_ctx == NULL)
        dev_ctx = ctx;
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

/* The doorbell of the queue of sending, when frames went in since the last. */
static void
tx_flush(void)
{
    if (tx_batch > 0) {
        if (port_on) {
            /* The entries are published; the switch is poked only while it
             * sleeps (it checks the ring itself when it runs). */
            int poked = vnet_port_tx_flush();

            if (poked) {
                (void)stafeto_fast_poke();
                stats.kicks++;
            }
            TRACE_POINT(TP_KICK, poked);
        } else {
            vnet_tx_kick();
            stats.kicks++;
            TRACE_POINT(TP_KICK, 2);
        }
        tx_batch = 0;
    }
}

/* A frame of `len` bytes, already in buffer `buf` at vnet_buf_ptr, to the
 * queue of sending (padded to the shortest frame of the wire). A full queue
 * is rung and waited for, at most FF_STAFETO_TX_WAIT_US per frame: the stack
 * can make hundreds of frames in one step (every delayed acknowledgement of
 * a thousand connections falls due in one clock tick), and the device takes
 * them as it runs. A queue that did not move within the wait is left alone
 * for the rest of the pass and drops what comes. */
static int
tx_queue(uint32_t buf, uint32_t len)
{
    uint8_t *to = vnet_buf_ptr(buf);

    if (len < FF_STAFETO_FRAME_MIN) {
        memset(to + len, 0, FF_STAFETO_FRAME_MIN - len);
        len = FF_STAFETO_FRAME_MIN;
    }
    if (vnet_tx(buf, (uint16_t)len) != 0) {
        uint64_t until = counter() + stats.ticks_per_second * FF_STAFETO_TX_WAIT_US / 1000000;
        int queued = -1;

        while (!tx_stalled) {
            tx_flush();
            vnet_tx_reclaim();
            queued = vnet_tx(buf, (uint16_t)len);
            if (queued == 0)
                break;
            if (counter() >= until)
                tx_stalled = 1;
        }
        if (queued != 0) {
            vnet_rx_return(buf);
            stats.tx_full++;
            return -1;
        }
        stats.tx_waited++;
    }
    TRACE_FRAME(TP_TX, to, len, 0);
    stats.tx_frames++;
    if (++tx_batch >= FF_STAFETO_TX_BATCH)
        tx_flush();
    return 0;
}

/*
 * The frame of the stack (a chain of mbufs) is copied once into a buffer
 * of the pool, and the mbufs are freed. The answer goes up through
 * if_transmit to tcp_output, which reads it as FreeBSD's errno: 0 for a
 * frame sent; ENOBUFS for a frame lost to a full queue (TCP takes its
 * sequence back and shrinks the window); ENETDOWN for a device that is
 * gone (a soft error of the socket); EMSGSIZE for a frame past the MTU. A
 * negative answer is ERESTART there, and the wrapper of tcp_output
 * (tcp_var.h) takes any negative answer as a request to drop the
 * connection with a reset: it must never come back.
 */
int
ff_dpdk_if_send(struct ff_dpdk_if_context *ctx, void *m, int total)
{
    uint64_t began;
    uint32_t buf;
    uint8_t *to;
    void *cur;
    int off = 0, sent;
    struct ff_tx_offload offload;

    memset(&offload, 0, sizeof(offload));
    if (!dev_on || ctx != dev_ctx || dev_lost) {
        /* No device to send on: the frame is dropped and counted. */
        tx_dropped++;
        ff_mbuf_free(m);
        return dev_on ? ff_ENETDOWN : 0;
    }
    began = counter();
    if (total <= 0 || total > FF_STAFETO_FRAME_MAX) {
        stats.tx_long++;
        ff_mbuf_free(m);
        return ff_EMSGSIZE;
    }
    if (port_on) {
        uint64_t until;

        to = vnet_port_tx_cell();
        if (to == NULL && !tx_stalled) {
            /* TX is full: publish what waits and give the switch up to
             * FF_STAFETO_TX_WAIT_US to take entries. */
            until = counter() + stats.ticks_per_second * FF_STAFETO_TX_WAIT_US / 1000000;
            tx_flush();
            while ((to = vnet_port_tx_cell()) == NULL) {
                if (counter() >= until) {
                    tx_stalled = 1;
                    break;
                }
            }
            if (to != NULL)
                stats.tx_waited++;
        }
        if (to == NULL) {
            stats.tx_full++;
            ff_mbuf_free(m);
            return ff_ENOBUFS;
        }
        cur = m;
        while (cur != NULL && off < total) {
            void *data;
            unsigned len;

            ff_next_mbuf(&cur, &data, &len);
            if (len > (unsigned)(total - off))
                len = (unsigned)(total - off);
            vnet_copy(to + off, data, len);
            off += (int)len;
        }
        ff_mbuf_tx_offload(m, &offload);
        ff_mbuf_free(m);
        if (off < FF_STAFETO_FRAME_MIN) {
            memset(to + off, 0, FF_STAFETO_FRAME_MIN - off);
            off = FF_STAFETO_FRAME_MIN;
        }
        TRACE_FRAME(TP_TX, to, off, 0);
        if (offload.tcp_csum) {
            /* The switch writes the sum of the pseudo-header and has the device
             * complete the segment's sum. */
            vnet_port_tx_submit_sum((uint32_t)off);
            stats.tx_sum++;
        } else {
            /* UDP has the sum of its pseudo-header in the field (the interface
             * offers CSUM_DELAY_DATA, which names UDP too): the layer completes
             * it. */
            if (offload.udp_csum || offload.ip_csum)
                vnet_fill_sums(to, (size_t)off);
            vnet_port_tx_submit((uint32_t)off);
        }
        stats.tx_frames++;
        if (++tx_batch >= FF_STAFETO_TX_BATCH)
            tx_flush();
        stats.tx_send_ticks += counter() - began;
        return 0;
    }
    buf = vnet_buf_take();
    if (buf == VNET_NONE) {
        /* No buffer: the frame is lost, and TCP sends it again. */
        stats.tx_no_buffer++;
        ff_mbuf_free(m);
        return ff_ENOBUFS;
    }
    to = vnet_buf_ptr(buf);
    cur = m;
    while (cur != NULL && off < total) {
        void *data;
        unsigned len;

        ff_next_mbuf(&cur, &data, &len);
        if (len > (unsigned)(total - off))
            len = (unsigned)(total - off);
        vnet_copy(to + off, data, len);
        off += (int)len;
    }
    ff_mbuf_free(m);
    /* A queue that stays full loses the frame the same way. */
    sent = tx_queue(buf, (uint32_t)off);
    stats.tx_send_ticks += counter() - began;
    return sent == 0 ? 0 : ff_ENOBUFS;
}

/* looutput of the loopback interface offers the packet in `m` (total bytes of
 * IPv4, no Ethernet header): a TCP or UDP packet between addresses of
 * 127.0.0.0/8 for a port that is no port of this stack goes out in the ring
 * as a packet of the loopback network (flag 4) behind an Ethernet header of
 * the interface's own MAC, which the switch checks and routes by the port.
 * 1 when the packet went (or was dropped for want of room, as a frame the
 * wire loses; TCP sends it again), 0 when the loopback interface keeps it. */
int
ff_stafeto_loop_tx(void *m, int total)
{
    uint8_t *to;
    uint8_t *ip;
    void *cur = m;
    void *data;
    unsigned len;
    unsigned header;
    uint16_t dport;
    int off = ETH;

    if (!port_on || dev_lost || total < 20 + 4)
        return 0;
    /* The headers lie in the first segment (the output path pulled them up). */
    ff_next_mbuf(&cur, &data, &len);
    ip = data;
    if (len < 20 || ip[0] >> 4 != 4)
        return 0;
    header = (unsigned)(ip[0] & 15) * 4;
    if (header < 20 || len < header + 4 || ip[12] != 127 || ip[16] != 127 ||
        (ip[9] != 6 && ip[9] != 17))
        return 0;
    dport = (uint16_t)(ip[header + 2] << 8 | ip[header + 3]);
    if (stafeto_fast_own_port(dport))
        return 0;
    /* A packet for another stack that the ring cannot carry (the interface's MTU is 1500, so
     * this is a stray) is dropped and counted: the loopback interface must not take it in
     * for a port that is not this stack's. */
    if (total + ETH > FF_STAFETO_FRAME_MAX) {
        stats.tx_long++;
        ff_mbuf_free(m);
        return 1;
    }
    to = vnet_port_tx_cell();
    if (to == NULL) {
        tx_flush();
        to = vnet_port_tx_cell();
    }
    if (to == NULL) {
        stats.tx_full++;
        ff_mbuf_free(m);
        return 1;
    }
    memcpy(to, dev_claim.config.mac, 6);
    memcpy(to + 6, dev_claim.config.mac, 6);
    to[12] = 0x08;
    to[13] = 0x00;
    cur = m;
    while (cur != NULL && off < total + ETH) {
        ff_next_mbuf(&cur, &data, &len);
        if (len > (unsigned)(total + ETH - off))
            len = (unsigned)(total + ETH - off);
        vnet_copy(to + off, data, len);
        off += (int)len;
    }
    ff_mbuf_free(m);
    if (off < FF_STAFETO_FRAME_MIN) {
        memset(to + off, 0, FF_STAFETO_FRAME_MIN - off);
        off = FF_STAFETO_FRAME_MIN;
    }
    vnet_port_tx_submit_loop((uint32_t)off);
    stats.tx_frames++;
    if (++tx_batch >= FF_STAFETO_TX_BATCH)
        tx_flush();
    return 1;
}

/* A buffer of the pool, or a block of the copy path, is free: the tag in
 * the mbuf's argument tells which (the low bit is set for a buffer, whose
 * number is in the rest). */
void
ff_dpdk_pktmbuf_free(void *m)
{
    if ((uintptr_t)m & 1) {
        if (port_on)
            vnet_port_rx_return((uint32_t)((uintptr_t)m >> 1));
        else
            vnet_rx_return((uint32_t)((uintptr_t)m >> 1));
    } else {
        free(m);
    }
}

/* A frame for the network service through the bypass ring. */
static void
bypass_push(const uint8_t *f, uint32_t len)
{
    if (vnet_bypass_push(f, len)) {
        stats.rx_bypass++;
        bypass_batch++;
    } else {
        stats.rx_bypass_full++;
    }
}

/* Tells the service how many frames wait in the ring (at most 16 a time). */
static void
bypass_kick(void)
{
    while (bypass_batch > 0) {
        int n = bypass_batch > BYPASS_KICK_MAX ? BYPASS_KICK_MAX : bypass_batch;

        (void)stafeto_fast_kick((uint32_t)n);
        bypass_batch -= n;
    }
}

/* What the service's interface of the device may get from the wire: a
 * server's DHCP message (UDP from 67 to 68). */
static int
dhcp_for_service(const uint8_t *f, unsigned header)
{
    return header != 0 && be16(f + ETH + 2) >= header + 8 && f[ETH + 9] == 17 &&
        be16(f + ETH + header) == 67 &&
        be16(f + ETH + header + 2) == 68;
}

/* An ARP reply for the address of the interface: the service's interface
 * asks for the gateway's hardware address too, and the stack needs the
 * reply as well, so it goes to both. */
static int
arp_reply_for_us(const uint8_t *f, uint32_t len)
{
    return len >= 42 && f[12] == 0x08 && f[13] == 0x06 && f[ETH + 7] == 2 &&
        same(f + 38, dev_claim.config.address, 4);
}

/* One received frame, in the buffer `b`: to the service, to the stack
 * without a copy while the pool is full enough, or to the stack with one
 * copy. The buffer is the stack's until its mbuf is freed, or the pool's
 * at once. */
static void
rx_one(const struct vnet_buf *b)
{
    const uint8_t *f = b->frame;
    uint32_t len = b->len;
    uint64_t began, handed;
    void *hdr;

    stats.rx_frames++;
    if (len < ETH || len > FF_STAFETO_FRAME_MAX + 4) {
        vnet_rx_return(b->buf);
        return;
    }
    TRACE_FRAME(TP_RX, f, len, 1);
    began = counter();
    if (dhcp_for_service(f, ipv4(f, len))) {
        bypass_push(f, len);
        vnet_rx_return(b->buf);
        return;
    }
    if (arp_reply_for_us(f, len))
        bypass_push(f, len);
    if (vnet_buf_free() >= FF_STAFETO_RX_LOW) {
        hdr = ff_mbuf_gethdr((void *)(((uintptr_t)b->buf << 1) | 1), (uint16_t)len,
            (void *)f, (uint16_t)len, 0);
        if (hdr == NULL) {
            stats.rx_no_mbuf++;
            vnet_rx_return(b->buf);
            return;
        }
        stats.rx_zero_copy++;
    } else {
        void *block = malloc(len);

        if (block == NULL) {
            stats.rx_no_mbuf++;
            vnet_rx_return(b->buf);
            return;
        }
        vnet_copy(block, f, len);
        vnet_rx_return(b->buf);
        hdr = ff_mbuf_gethdr(block, (uint16_t)len, block, (uint16_t)len, 0);
        if (hdr == NULL) {
            stats.rx_no_mbuf++;
            free(block);
            return;
        }
        stats.rx_copied++;
    }
    handed = counter();
    stats.rx_layer_ticks += handed - began;
    ff_veth_process_packet(dev_ctx->ifp, hdr);
    stats.rx_input_ticks += counter() - handed;
}

/* One frame of DONE, in the cell `r`: to the stack without a copy while
 * FILL holds enough cells, or with one copy. The cell is the stack's until
 * its mbuf is freed, or FILL's at once. An ARP reply (flag 1) is a frame
 * like any other for the stack. A packet of the loopback network (flag 4,
 * from another stack) goes to the loopback interface instead of the
 * Ethernet one (freebsd/net/if_loop.c, ff_stafeto_lo_input). */
static void
port_rx_one(const struct vnet_port_rx *r)
{
    const uint8_t *f = r->frame;
    uint32_t len = r->len;
    uint64_t began, handed;
    void *hdr;
    uint8_t sum_ok = (r->flags & VNET_PORT_DONE_SUM_OK) != 0;

    stats.rx_frames++;
    if (len < ETH || len > FF_STAFETO_FRAME_MAX + 4) {
        vnet_port_rx_return(r->cell);
        return;
    }
    if (sum_ok)
        stats.rx_sum_ok++;
    TRACE_FRAME(TP_RX, f, len, 1);
    began = counter();
    if (vnet_port_fill_free() >= FF_STAFETO_PORT_RX_LOW) {
        hdr = ff_mbuf_gethdr((void *)(((uintptr_t)r->cell << 1) | 1), (uint16_t)len,
            (void *)f, (uint16_t)len, sum_ok);
        if (hdr == NULL) {
            stats.rx_no_mbuf++;
            vnet_port_rx_return(r->cell);
            return;
        }
        stats.rx_zero_copy++;
    } else {
        void *block = malloc(len);

        if (block == NULL) {
            stats.rx_no_mbuf++;
            vnet_port_rx_return(r->cell);
            return;
        }
        vnet_copy(block, f, len);
        vnet_port_rx_return(r->cell);
        hdr = ff_mbuf_gethdr(block, (uint16_t)len, block, (uint16_t)len, sum_ok);
        if (hdr == NULL) {
            stats.rx_no_mbuf++;
            free(block);
            return;
        }
        stats.rx_copied++;
    }
    handed = counter();
    stats.rx_layer_ticks += handed - began;
    if (r->flags & VNET_PORT_DONE_LOOP)
        ff_stafeto_lo_input(hdr);
    else
        ff_veth_process_packet(dev_ctx->ifp, hdr);
    stats.rx_input_ticks += counter() - handed;
}

/* Up to a burst of frames from DONE. The number taken. */
static int
port_rx_pass(void)
{
    struct vnet_port_rx got[FF_STAFETO_RX_BURST];
    uint32_t free_now;
    int n, i;

    n = vnet_port_rx_burst(got, FF_STAFETO_RX_BURST);
    if (n < 0) {
        fprintf(stderr, "f-stack: the switch's ring broke its rules\n");
        dev_lost = 1;
        return 0;
    }
    for (i = 0; i < n; i++)
        port_rx_one(&got[i]);
    free_now = vnet_port_fill_free();
    if (free_now < stats.free_low)
        stats.free_low = free_now;
    return n;
}

/* Up to a burst of frames from the queue of receiving. The number taken. */
static int
rx_pass(void)
{
    struct vnet_buf got[FF_STAFETO_RX_BURST];
    uint32_t free_now;
    int n, i;

    n = vnet_rx_burst(got, FF_STAFETO_RX_BURST);
    if (n < 0) {
        /* The device broke the protocol of the queue: no more use of it. */
        fprintf(stderr, "f-stack: the device broke the protocol of its queue\n");
        dev_lost = 1;
        return 0;
    }
    for (i = 0; i < n; i++)
        rx_one(&got[i]);
    free_now = vnet_buf_free();
    if (free_now < stats.free_low)
        stats.free_low = free_now;
    if (bypass_batch > 0)
        bypass_kick();
    return n;
}

/* The frames the service put in the bypass ring go to the wire once they
 * look like what its interface may send: from the device's MAC, ARP or a
 * client's DHCP message (UDP from 68 to 67). */
static void
from_service(void)
{
    uint8_t f[FF_STAFETO_FRAME_MAX];
    size_t len;

    while ((len = vnet_bypass_pop(f, sizeof(f))) != 0) {
        unsigned header;
        int arp, dhcp;
        uint32_t buf;

        if (len < ETH || !same(f + 6, dev_claim.config.mac, 6)) {
            stats.tx_foreign++;
            continue;
        }
        header = ipv4(f, (uint32_t)len);
        arp = f[12] == 0x08 && f[13] == 0x06;
        dhcp = header != 0 && be16(f + ETH + 2) >= header + 8 && f[ETH + 9] == 17 &&
            be16(f + ETH + header) == 68 &&
            be16(f + ETH + header + 2) == 67;
        if (!arp && !dhcp) {
            stats.tx_foreign++;
            continue;
        }
        buf = vnet_buf_take();
        if (buf == VNET_NONE) {
            stats.tx_no_buffer++;
            continue;
        }
        vnet_copy(vnet_buf_ptr(buf), f, len);
        if (tx_queue(buf, (uint32_t)len) == 0)
            stats.tx_bypass++;
    }
}

/*
 * One step of the stack: the clock ticks that are due, the device's frames
 * (the sent buffers back to the pool, the service's frames to the wire,
 * the received frames to the stack), then the queued work of the software
 * interrupts and the doorbell of the frames that work sent. Returns the
 * units of work done (the frames received and the workstreams that had
 * work), 0 when the step found the stack idle.
 */
int
ff_stafeto_pass(void)
{
    unsigned long runs = ff_stafeto_netisr_runs;
    uint64_t now = ff_get_tsc_ns();
    int ticks = 0, received = 0;

    passes++;
    tx_stalled = 0;
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
    if (dev_on && !dev_lost) {
        /* Once per clock tick a look at the service's channel: its end
         * must reach a stack that never sleeps. */
        if (ticks > 0)
            look_at_channel();
        take_notifications();
        if (!dev_lost && port_on) {
            received = port_rx_pass();
        } else if (!dev_lost) {
            vnet_tx_reclaim();
            from_service();
            received = rx_pass();
        }
    }
    ff_swi_net_excute();
    if (dev_on && !dev_lost)
        tx_flush();
    return (int)(ff_stafeto_netisr_runs - runs) + received;
}

/* The time to the next clock tick in nanoseconds, 0 when it is due. */
uint64_t
ff_stafeto_next_tick_ns(void)
{
    uint64_t now = ff_get_tsc_ns();

    return now >= next_tick_ns ? 0 : next_tick_ns - now;
}

/* The wake flag of the device on (with a full barrier and a look at the
 * ring) or off: the interrupts of the device, or `consumer_idle` of the
 * switch's ring. */
void
ff_stafeto_notify(int on)
{
    if (!port_on)
        vnet_notify(on);
    else if (on)
        (void)vnet_port_sleep_begin();
    else
        vnet_port_sleep_end();
}

int
ff_stafeto_sleep(uint64_t max_ns)
{
    uint64_t wait;
    uint32_t bits = 0;

    if (!dev_on || dev_lost) {
        struct timespec ts;

        wait = ff_stafeto_next_tick_ns();
        if (wait > max_ns)
            wait = max_ns;
        ts.tv_sec = (time_t)(wait / NSEC_PER_SEC);
        ts.tv_nsec = (long)(wait % NSEC_PER_SEC);
        if (wait)
            nanosleep(&ts, NULL);
        return 0;
    }
    stats.sleeps++;
    TRACE_POINT(TP_SLEEP, 0);
    /* The interrupts (the idle flag of the ring) on, then a look at the
     * queue once more: a frame that came in between brings no interrupt. */
    dev_notify(1);
    if (ff_stafeto_pass() > 0 || __atomic_load_n(&notified, __ATOMIC_RELAXED) != 0) {
        dev_notify(0);
        TRACE_POINT(TP_FOUND, 0);
        stats.sleeps_found_work++;
        return 1;
    }
    wait = ff_stafeto_next_tick_ns();
    if (wait > max_ns)
        wait = max_ns;
    if (wait == 0) {
        dev_notify(0);
        return 1;
    }
    if (stafeto_fast_wait(wait, &bits) == 0) {
        TRACE_POINT(TP_WAKE, bits);
        ff_stafeto_absorb(bits);
    } else {
        TRACE_POINT(TP_WAKE, 0xffffffffu);
    }
    dev_notify(0);
    return 0;
}

void
ff_dpdk_run(loop_func_t loop, void *arg)
{
    stop_loop = 0;
    while (!stop_loop && !dev_lost) {
        int work = ff_stafeto_pass();
        int busy = loop(arg);

        if (work == 0 && busy <= 0 && ff_stafeto_netisr_pending() == 0)
            ff_stafeto_sleep(UINT64_MAX);
    }
    if (dev_lost)
        fprintf(stderr, "f-stack: the device was taken away\n");
}

void
ff_dpdk_stop(void)
{
    stop_loop = 1;
}

void
ff_stafeto_device_stats(struct ff_stafeto_device_stats *out)
{
    *out = stats;
    out->free_now = dev_on ? rx_free() : 0;
    if (dev_on && !port_on) {
        uint64_t b[3] = { 0, 0, 0 };

        vnet_bells(b);
        out->bell_rx_passes = b[0];
        out->bell_rx = b[1];
        out->bell_tx = b[2];
    }
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
