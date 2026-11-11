/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * The table through which the POSIX layer of stafeto (libc.so) reaches the
 * TCP/IP stack of F-Stack inside the process (<stafeto/fast.h>). A program
 * that links the stack (libfstack.a, with libvirtio_net.a) links this file
 * too: its constructor registers the table, and from then on the layer turns
 * every socket(AF_INET, SOCK_STREAM, ...) of the process into a socket of the
 * stack. libc.so names nothing of the program; the table is the one way.
 *
 * Each function answers a count not below zero or the negated errno of
 * Linux: F-Stack translates the errno of FreeBSD to relibc's, and the
 * function reads it right after the call.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <stafeto/fast.h>
#include <vnet.h>

#include "ff_api.h"
#include "ff_stafeto.h"

#define CONF "/etc/fstack.ini"

void ff_stafeto_counters(uint64_t *dropped, uint64_t *ticks, uint64_t *pass_count);

_Static_assert(sizeof(struct kevent) == 64, "struct kevent of FreeBSD");

/* The flags of a message: Linux's from the layer, FreeBSD's for the stack. */
#define LINUX_MSG_PEEK 0x2
#define LINUX_MSG_DONTWAIT 0x40
#define LINUX_MSG_WAITALL 0x100
#define LINUX_MSG_NOSIGNAL 0x4000
#define BSD_MSG_PEEK 0x2
#define BSD_MSG_WAITALL 0x40
#define BSD_MSG_DONTWAIT 0x80
#define BSD_MSG_NOSIGNAL 0x20000

/* The layer's counts of the process (libc.so, posix-platform). */
extern void stafeto_probe_heap(uint64_t *out);
/* The requests that may fail the process refused (stafeto.patch, ff_glue.c). */
extern unsigned long ff_stafeto_refused;

static long
done(long r)
{
    return r < 0 ? -(long)errno : r;
}

/* -1 for a flag the layer does not pass (it refuses those itself). */
static int
flags_of(int linux_flags)
{
    int r = 0;

    if (linux_flags & ~(LINUX_MSG_PEEK | LINUX_MSG_DONTWAIT | LINUX_MSG_WAITALL | LINUX_MSG_NOSIGNAL))
        return -1;
    if (linux_flags & LINUX_MSG_PEEK)
        r |= BSD_MSG_PEEK;
    if (linux_flags & LINUX_MSG_DONTWAIT)
        r |= BSD_MSG_DONTWAIT;
    if (linux_flags & LINUX_MSG_WAITALL)
        r |= BSD_MSG_WAITALL;
    if (linux_flags & LINUX_MSG_NOSIGNAL)
        r |= BSD_MSG_NOSIGNAL;
    return r;
}

/*
 * With STAFETO_FAST_STATS in the environment the process says every 500 ticks
 * of the stack's clock (5 s) how often the device's notifications woke the
 * stack and how many steps it made, in totals (the probes subtract two lines
 * and divide by the time between them). A process that ends by exit() runs
 * no handler of the library here, so the totals are said as they stand.
 */
static int stats_on;
static uint64_t stats_said;

/* A number of the stack's sysctl tree (4 or 8 bytes), -1 when it has none. */
static long long
sysctl_number(const char *name)
{
    int mib[24];
    int query[2] = { 0, 3 };
    size_t len = sizeof(mib);
    union { int32_t i; int64_t l; } value = { 0 };
    size_t size = sizeof(value);

    if (ff_sysctl(query, 2, mib, &len, name, strlen(name)) != 0)
        return -1;
    if (ff_sysctl(mib, (unsigned)(len / sizeof(int)), &value, &size, NULL, 0) != 0)
        return -1;
    return size == sizeof(value.i) ? value.i : size == sizeof(value.l) ? value.l : -1;
}

/* Sets a number of the stack's sysctl tree (an int); 0, or -1. */
static int
sysctl_set_int(const char *name, int value)
{
    int mib[24];
    int query[2] = { 0, 3 };
    size_t len = sizeof(mib);

    if (ff_sysctl(query, 2, mib, &len, name, strlen(name)) != 0)
        return -1;
    return ff_sysctl(mib, (unsigned)(len / sizeof(int)), NULL, NULL, &value, sizeof(value));
}

/* The ephemeral ports of a consumer of the switch are the block its attach
 * gave (the switch refuses a SYN from any other port): `first` then
 * `last`, for the low and the high ranges both, so that the choice of a
 * port of any program of the stack stays inside the block. */
static int
set_port_block(unsigned first, unsigned count)
{
    int bad = 0;
    int last = (int)(first + count - 1);

    bad |= sysctl_set_int("net.inet.ip.portrange.first", (int)first);
    bad |= sysctl_set_int("net.inet.ip.portrange.last", last);
    bad |= sysctl_set_int("net.inet.ip.portrange.hifirst", (int)first);
    bad |= sysctl_set_int("net.inet.ip.portrange.hilast", last);
    return bad;
}

static uint64_t
monotonic_ns(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;
}

/* The longest step of the stack and the longest gap between two steps since
 * the last line of `fast: scale`, in microseconds. */
static uint64_t pass_longest_us, gap_longest_us, pass_ended_ns;

/* The limits the stack runs under, said once at the start: the settings
 * of fstack.ini are the ones the image wants, and these are the ones the
 * stack took. */
static void
glue_limits(void)
{
    static const char *const names[] = {
        "kern.ipc.maxsockets", "kern.maxfiles", "kern.maxfilesperproc",
        "net.inet.tcp.tcbhashsize", "net.inet.tcp.syncache.hashsize",
        "net.inet.tcp.syncache.bucketlimit",
        "kern.ipc.somaxconn", "kern.ipc.nmbclusters", "kern.ipc.nmbufs",
        "kern.ncallout", "net.inet.tcp.sendspace", "net.inet.tcp.recvspace",
    };

    fprintf(stderr, "fast: start");
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        fprintf(stderr, " %s=%lld", names[i], sysctl_number(names[i]));
    fprintf(stderr, "\n");
    fflush(stderr);
}

/*
 * The state of the stack's memory and of the process's, beside `fast:
 * stats`: the open sockets, for the zones that hold a connection their item
 * size and items (the sysctl tree of UMA), the quota and what the
 * process uses, the heap of the layer (pages of the room unbacked, free,
 * user and own, the places of the kernel's table the layer's map holds and
 * the entries it does not show, the chunks taken and the longest time one
 * held the heap's lock) and the longest step and gap of the stack.
 */
static void
glue_scale(void)
{
    static const char *const zones[] = { "socket", "tcp_inpcb", "mbuf", "mbuf_cluster", "KNOTE", "Files" };
    uint64_t heap[11];
    char name[96];
    struct rlimit data;
    int tight;

    /* A sysctl of the stack takes memory that may not be refused, and a
     * process within a megabyte of its data limit or its quota ends in it:
     * the line then holds the heap alone. */
    stafeto_probe_heap(heap);
    tight = heap[10] - heap[9] < (1u << 20);
    if (getrlimit(RLIMIT_DATA, &data) == 0 && data.rlim_cur != RLIM_INFINITY &&
        (heap[3] + heap[4]) * 4096 + (1u << 20) > data.rlim_cur)
        tight = 1;
    fprintf(stderr, "fast: scale sockets=%lld", tight ? -1 : sysctl_number("kern.ipc.numopensockets"));
    for (unsigned i = 0; i < sizeof(zones) / sizeof(zones[0]) && !tight; i++) {
        long long size, items;

        snprintf(name, sizeof(name), "vm.uma.%s.size", zones[i]);
        size = sysctl_number(name);
        snprintf(name, sizeof(name), "vm.uma.%s.stats.current", zones[i]);
        items = sysctl_number(name);
        fprintf(stderr, " %s=%lld/%lld", zones[i], size, items);
    }
    fprintf(stderr,
        " refused=%lu quota=%llu used=%llu room=%llu unbacked=%llu free=%llu user=%llu own=%llu places=%llu hidden=%llu grows=%llu grow_longest_us=%llu pass_longest_us=%llu gap_longest_us=%llu\n",
        ff_stafeto_refused, (unsigned long long)heap[10], (unsigned long long)heap[9],
        (unsigned long long)heap[0], (unsigned long long)heap[1], (unsigned long long)heap[2],
        (unsigned long long)heap[3], (unsigned long long)heap[4], (unsigned long long)heap[5],
        (unsigned long long)heap[6], (unsigned long long)heap[7], (unsigned long long)(heap[8] / 1000),
        (unsigned long long)pass_longest_us, (unsigned long long)gap_longest_us);
    pass_longest_us = gap_longest_us = 0;
}

/*
 * With STAFETO_FAST_EXIT_IN_PASS=N the process ends with status 1 inside its
 * Nth step of the stack, as the stack's ff_mmap does when mmap fails: the
 * probe of the layer checks that an exit from inside a call of the table
 * completes (the layer must not enter the stack again from its end).
 */
static long exit_in_pass;

static void
glue_stats(void)
{
    struct ff_stafeto_device_stats st;
    uint64_t dropped, ticks, passes, wakes[4];

    ff_stafeto_counters(&dropped, &ticks, &passes);
    if (ticks < stats_said + 500)
        return;
    stats_said = ticks;
    ff_stafeto_device_stats(&st);
    stafeto_fast_wake_counts(wakes);
    fprintf(stderr,
        "fast: wakes sleeps=%llu bell=%llu deadline=%llu deadline_found=%llu\n",
        (unsigned long long)wakes[0], (unsigned long long)wakes[1],
        (unsigned long long)wakes[2], (unsigned long long)wakes[3]);
    fprintf(stderr,
        "fast: stats ticks=%llu notifications=%llu kicks=%llu sleeps=%llu found_work=%llu passes=%llu rx=%llu tx=%llu bell_rx_passes=%llu bell_rx=%llu bell_tx=%llu sum_tx=%llu sum_rx=%llu\n",
        (unsigned long long)ticks, (unsigned long long)st.notifications,
        (unsigned long long)st.kicks, (unsigned long long)st.sleeps,
        (unsigned long long)st.sleeps_found_work, (unsigned long long)passes,
        (unsigned long long)st.rx_frames, (unsigned long long)st.tx_frames,
        (unsigned long long)st.bell_rx_passes, (unsigned long long)st.bell_rx,
        (unsigned long long)st.bell_tx, (unsigned long long)st.tx_sum,
        (unsigned long long)st.rx_sum_ok);
    glue_scale();
    fflush(stderr);
}

static int
glue_start(const struct stafeto_fast_claim *claim)
{
    char *args[] = { "stafeto-fast", "--conf", CONF, NULL };

    if (ff_stafeto_attach(claim) != 0)
        return -EINVAL;
    if (ff_init(3, args) != 0)
        return -EIO;
    if (claim->kind == STAFETO_FAST_PORT && set_port_block(claim->snapshot[4], claim->snapshot[5]) != 0) {
        fprintf(stderr, "fast: the block of ephemeral ports %u+%u was not taken\n",
            claim->snapshot[4], claim->snapshot[5]);
        return -EIO;
    }
    fprintf(stderr, "fast: the stack is up on %u.%u.%u.%u/%u\n", claim->config.address[0],
        claim->config.address[1], claim->config.address[2], claim->config.address[3],
        claim->config.prefix);
    fflush(stderr);
    glue_limits();
    stats_on = getenv("STAFETO_FAST_STATS") != NULL;
    if (getenv("STAFETO_FAST_EXIT_IN_PASS") != NULL)
        exit_in_pass = atol(getenv("STAFETO_FAST_EXIT_IN_PASS"));
    return 0;
}

static int
glue_pass(void)
{
    uint64_t began = stats_on ? monotonic_ns() : 0;
    int work = ff_stafeto_pass();

    if (stats_on) {
        uint64_t ended = monotonic_ns();

        if (pass_ended_ns != 0 && (began - pass_ended_ns) / 1000 > gap_longest_us)
            gap_longest_us = (began - pass_ended_ns) / 1000;
        if ((ended - began) / 1000 > pass_longest_us)
            pass_longest_us = (ended - began) / 1000;
        pass_ended_ns = ended;
    }
    if (exit_in_pass > 0 && --exit_in_pass == 0)
        exit(1);
    if (stats_on)
        glue_stats();
    return work;
}

static uint64_t
glue_next_tick_ns(void)
{
    return ff_stafeto_next_tick_ns();
}

static void
glue_notify(int on)
{
    ff_stafeto_notify(on);
}

static void
glue_absorb(uint32_t bits)
{
    ff_stafeto_absorb(bits);
}

static int
glue_socket(int domain, int type, int protocol)
{
    return (int)done(ff_socket(domain, type, protocol));
}

static int
glue_bind(int s, const void *addr, uint32_t len)
{
    return (int)done(ff_bind(s, (const struct linux_sockaddr *)addr, len));
}

static int
glue_listen(int s, int backlog)
{
    return (int)done(ff_listen(s, backlog));
}

static int
glue_accept4(int s, void *addr, uint32_t *len, int flags)
{
    return (int)done(ff_accept4(s, (struct linux_sockaddr *)addr, len, flags));
}

static int
glue_connect(int s, const void *addr, uint32_t len)
{
    return (int)done(ff_connect(s, (const struct linux_sockaddr *)addr, len));
}

static long
glue_read(int s, void *buf, size_t n)
{
    return done(ff_read(s, buf, n));
}

static long
glue_write(int s, const void *buf, size_t n)
{
    return done(ff_write(s, buf, n));
}

static long
glue_readv(int s, const void *iov, int count)
{
    return done(ff_readv(s, (const struct iovec *)iov, count));
}

static long
glue_writev(int s, const void *iov, int count)
{
    return done(ff_writev(s, (const struct iovec *)iov, count));
}

static long
glue_recvfrom(int s, void *buf, size_t n, int flags, void *from, uint32_t *from_len)
{
    int f = flags_of(flags);

    if (f < 0)
        return -EOPNOTSUPP;
    return done(ff_recvfrom(s, buf, n, f, (struct linux_sockaddr *)from, from_len));
}

static long
glue_sendto(int s, const void *buf, size_t n, int flags, const void *to, uint32_t to_len)
{
    int f = flags_of(flags);

    if (f < 0)
        return -EOPNOTSUPP;
    return done(ff_sendto(s, buf, n, f, (const struct linux_sockaddr *)to, to_len));
}

static long
glue_recvmsg(int s, void *msg, int flags)
{
    int f = flags_of(flags);

    if (f < 0)
        return -EOPNOTSUPP;
    return done(ff_recvmsg(s, (struct msghdr *)msg, f));
}

static long
glue_sendmsg(int s, const void *msg, int flags)
{
    int f = flags_of(flags);

    if (f < 0)
        return -EOPNOTSUPP;
    return done(ff_sendmsg(s, (const struct msghdr *)msg, f));
}

static int
glue_close(int s)
{
    return (int)done(ff_close(s));
}

static int
glue_shutdown(int s, int how)
{
    return (int)done(ff_shutdown(s, how));
}

static int
glue_getsockopt(int s, int level, int name, void *value, uint32_t *len)
{
    return (int)done(ff_getsockopt(s, level, name, value, len));
}

static int
glue_setsockopt(int s, int level, int name, const void *value, uint32_t len)
{
    return (int)done(ff_setsockopt(s, level, name, value, len));
}

static int
glue_getsockname(int s, void *addr, uint32_t *len)
{
    return (int)done(ff_getsockname(s, (struct linux_sockaddr *)addr, len));
}

static int
glue_getpeername(int s, void *addr, uint32_t *len)
{
    return (int)done(ff_getpeername(s, (struct linux_sockaddr *)addr, len));
}

static int
glue_ioctl(int s, unsigned long request, void *argument)
{
    return (int)done(ff_ioctl(s, request, argument));
}

static int
glue_kqueue(void)
{
    return (int)done(ff_kqueue());
}

/* The time is always zero: the layer's loop looks, and sleeps elsewhere. */
static int
glue_kevent(int kq, const void *changes, int n_changes, void *events, int n_events)
{
    struct timespec zero = { 0, 0 };

    return (int)done(ff_kevent(kq, (const struct kevent *)changes, n_changes,
        (struct kevent *)events, n_events, &zero));
}

static const struct stafeto_fast_table table = {
    .version = STAFETO_FAST_TABLE_VERSION,
    .flags = STAFETO_FAST_EXIT_ON_LOSS,
    .start = glue_start,
    .pass = glue_pass,
    .next_tick_ns = glue_next_tick_ns,
    .notify = glue_notify,
    .absorb = glue_absorb,
    .socket = glue_socket,
    .bind = glue_bind,
    .listen = glue_listen,
    .accept4 = glue_accept4,
    .connect = glue_connect,
    .read = glue_read,
    .write = glue_write,
    .readv = glue_readv,
    .writev = glue_writev,
    .recvfrom = glue_recvfrom,
    .sendto = glue_sendto,
    .recvmsg = glue_recvmsg,
    .sendmsg = glue_sendmsg,
    .close = glue_close,
    .shutdown = glue_shutdown,
    .getsockopt = glue_getsockopt,
    .setsockopt = glue_setsockopt,
    .getsockname = glue_getsockname,
    .getpeername = glue_getpeername,
    .ioctl = glue_ioctl,
    .kqueue = glue_kqueue,
    .kevent = glue_kevent,
};

/*
 * The constructors of libc.so run before those of the program, so the layer
 * is ready. The constructor only registers: it takes no memory and calls
 * nothing of the stack. Without the table the program's sockets would go to
 * the network service on the same second address, so a refusal ends it.
 */
__attribute__((constructor)) static void
glue_register(void)
{
    if (stafeto_fast_register(&table) != 0) {
        fprintf(stderr, "fast: the layer refused the table of the stack (errno %d)\n", errno);
        fflush(stderr);
        _exit(1);
    }
}
