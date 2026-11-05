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
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <stafeto/fast.h>
#include <vnet.h>

#include "ff_api.h"
#include "ff_stafeto.h"

#define CONF "/etc/fstack.ini"

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

static int
glue_start(const struct stafeto_fast_claim *claim)
{
    char *args[] = { "stafeto-fast", "--conf", CONF, NULL };

    if (ff_stafeto_attach(claim) != 0)
        return -EINVAL;
    if (ff_init(3, args) != 0)
        return -EIO;
    fprintf(stderr, "fast: the stack is up on %u.%u.%u.%u/%u\n", claim->config.address[0],
        claim->config.address[1], claim->config.address[2], claim->config.address[3],
        claim->config.prefix);
    fflush(stderr);
    return 0;
}

static int
glue_pass(void)
{
    return ff_stafeto_pass();
}

static uint64_t
glue_next_tick_ns(void)
{
    return ff_stafeto_next_tick_ns();
}

static void
glue_notify(int on)
{
    vnet_notify(on);
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
