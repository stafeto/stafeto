/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * fstack-probe: the TCP/IP stack of FreeBSD 15 (F-Stack's libfstack.a,
 * tools/build-fstack.py) in a process of stafeto, on its own loopback
 * interface, with no network device (`cargo xtask fstack-probe`).
 *
 * The program starts the stack with /etc/fstack.ini and runs its checks
 * from the function ff_run calls; the waits inside a check step the stack
 * themselves (ff_stafeto_pass) and sleep until its next clock tick when it
 * is idle. Each check prints `fstack-probe: <check> ok`, a failure prints
 * `fstack-probe: check failed: ...` and ends the program with 1.
 *
 * `fstack-probe write-blocking` prints what one ff_write of 1 MiB does on a
 * blocking socket that nobody reads.
 */

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include "ff_api.h"

/* The host layer's own names (ports/f-stack/ff_stafeto_if.c). */
int ff_stafeto_pass(void);
uint64_t ff_stafeto_next_tick_ns(void);
void ff_stafeto_random(void *buf, unsigned int len);
void ff_stafeto_counters(uint64_t *dropped, uint64_t *ticks, uint64_t *passes);

#define CONF "/etc/fstack.ini"
#define BASE_PORT 7000
#define STREAM_BYTES (16u << 20)
#define BIG_WRITE (1u << 20)
#define CONNECTIONS 1000
#define CHUNK 65536

static const char *role = "";
static int status = 0;
/* The buffer of the writes of 1 MiB. */
static unsigned char big[BIG_WRITE];

static uint64_t
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void
fail(const char *format, ...)
{
    va_list ap;

    printf("fstack-probe: check failed: ");
    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
    printf(" (errno %d)\n", errno);
    fflush(stdout);
    exit(1);
}

static void
ok(const char *check)
{
    printf("fstack-probe: %s ok\n", check);
    fflush(stdout);
}

/* One step of the stack, then a sleep until its next tick when the step
 * found nothing to do. */
static void
step(void)
{
    if (ff_stafeto_pass() == 0) {
        uint64_t wait = ff_stafeto_next_tick_ns();
        struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)wait };

        if (wait > 0 && wait < 1000000000ull)
            nanosleep(&ts, NULL);
    }
}

static struct sockaddr_in
loopback(int port)
{
    struct sockaddr_in a;

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

static void
nonblocking(int fd)
{
    int on = 1;

    if (ff_ioctl(fd, FIONBIO, &on) != 0)
        fail("FIONBIO on %d", fd);
}

static int
listener(int port, int backlog)
{
    struct sockaddr_in a = loopback(port);
    int on = 1;
    int fd = ff_socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        fail("socket for the listener of %d", port);
    if (ff_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0)
        fail("SO_REUSEADDR");
    if (ff_bind(fd, (struct linux_sockaddr *)&a, sizeof(a)) != 0)
        fail("bind to %d", port);
    if (ff_listen(fd, backlog) != 0)
        fail("listen on %d", port);
    nonblocking(fd);
    return fd;
}

/* A non-blocking connect to the port, in progress or done. */
static int
connect_to(int port)
{
    struct sockaddr_in a = loopback(port);
    int fd = ff_socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        fail("socket for a connect to %d", port);
    nonblocking(fd);
    if (ff_connect(fd, (struct linux_sockaddr *)&a, sizeof(a)) != 0 && errno != EINPROGRESS)
        fail("connect to %d", port);
    return fd;
}

/* The pending error of a socket (SO_ERROR), -1 while a connect is in
 * progress (not yet writable). */
static int
connect_result(int fd)
{
    int error = 0;
    socklen_t len = sizeof(error);
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);

    if (ff_getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0)
        fail("SO_ERROR");
    if (error != 0)
        return error;
    if (ff_getpeername(fd, (struct linux_sockaddr *)&peer, &plen) == 0)
        return 0;
    return -1;
}

static int
wait_connected(int fd, uint64_t within_ms)
{
    uint64_t until = now_ms() + within_ms;
    int r;

    while ((r = connect_result(fd)) < 0) {
        if (now_ms() > until)
            return -1;
        step();
    }
    return r;
}

static int
accept_one(int lfd, uint64_t within_ms)
{
    uint64_t until = now_ms() + within_ms;

    for (;;) {
        int fd = ff_accept(lfd, NULL, NULL);

        if (fd >= 0) {
            nonblocking(fd);
            return fd;
        }
        if (errno != EAGAIN)
            fail("accept");
        if (now_ms() > until)
            fail("no connection to accept within %llu ms", (unsigned long long)within_ms);
        step();
    }
}

static unsigned
local_port(int fd)
{
    struct sockaddr_in a;
    socklen_t len = sizeof(a);

    if (ff_getsockname(fd, (struct linux_sockaddr *)&a, &len) != 0)
        fail("getsockname");
    return ntohs(a.sin_port);
}

/* The byte at `offset` of the stream of the 16 MiB check. */
static unsigned char
pattern(uint32_t offset)
{
    uint32_t x = offset * 2654435761u;

    return (unsigned char)(x >> 24 ^ offset);
}

static int
sysctl_name(const char *name, int value, int *old)
{
    int mib[24];
    int query[2] = { 0, 3 };
    size_t len = sizeof(mib);
    size_t oldlen = sizeof(*old);

    if (ff_sysctl(query, 2, mib, &len, name, strlen(name)) != 0)
        return -1;
    return ff_sysctl(mib, (unsigned)(len / sizeof(int)), old, &oldlen, &value, sizeof(value));
}

static void
check_random(void)
{
    unsigned char a[64], b[64];
    int zero_a = 1, zero_b = 1;

    ff_stafeto_random(a, sizeof(a));
    ff_stafeto_random(b, sizeof(b));
    for (unsigned i = 0; i < sizeof(a); i++) {
        zero_a &= a[i] == 0;
        zero_b &= b[i] == 0;
    }
    if (zero_a || zero_b || memcmp(a, b, sizeof(a)) == 0)
        fail("two fills of 64 bytes are equal or all zero");
    ok("random");
}

/* A listener's readiness through kqueue, then 16 MiB through the pair. */
static void
check_kevent_and_stream(void)
{
    int lfd = listener(BASE_PORT + 1, 16);
    int kq = ff_kqueue();
    struct kevent change, event;
    struct timespec zero = { 0, 0 };
    uint64_t until;
    int cfd, sfd, got = 0;

    if (kq < 0)
        fail("kqueue");
    EV_SET(&change, lfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (ff_kevent(kq, &change, 1, NULL, 0, NULL) != 0)
        fail("kevent EV_ADD");
    if (ff_kevent(kq, NULL, 0, &event, 1, &zero) != 0)
        fail("a listener without a connection is ready");
    cfd = connect_to(BASE_PORT + 1);
    until = now_ms() + 2000;
    while (got == 0) {
        got = ff_kevent(kq, NULL, 0, &event, 1, &zero);
        if (got < 0)
            fail("kevent");
        if (now_ms() > until)
            fail("the listener did not become ready within 2 s");
        if (got == 0)
            step();
    }
    if ((int)event.ident != lfd || event.filter != EVFILT_READ || event.data != 1)
        fail("kevent gave ident %d filter %d data %lld", (int)event.ident, event.filter,
            (long long)event.data);
    sfd = accept_one(lfd, 1000);
    if (wait_connected(cfd, 1000) != 0)
        fail("the connect did not complete");
    ok("kevent");

    /* 16 MiB from the client to the server, checked byte by byte. */
    static unsigned char out[CHUNK], in[CHUNK];
    uint32_t sent = 0, received = 0;
    uint64_t started = now_ms();

    until = started + 60000;
    while (received < STREAM_BYTES) {
        int progress = 0;

        if (sent < STREAM_BYTES) {
            uint32_t n = STREAM_BYTES - sent < CHUNK ? STREAM_BYTES - sent : CHUNK;
            ssize_t w;

            for (uint32_t i = 0; i < n; i++)
                out[i] = pattern(sent + i);
            w = ff_write(cfd, out, n);
            if (w > 0) {
                sent += (uint32_t)w;
                progress = 1;
            } else if (w < 0 && errno != EAGAIN) {
                fail("write at %u", sent);
            }
        }
        for (;;) {
            ssize_t r = ff_read(sfd, in, sizeof(in));

            if (r > 0) {
                for (ssize_t i = 0; i < r; i++)
                    if (in[i] != pattern(received + (uint32_t)i))
                        fail("byte %u of the stream differs", received + (uint32_t)i);
                received += (uint32_t)r;
                progress = 1;
                continue;
            }
            if (r == 0)
                fail("end of stream at %u", received);
            if (errno != EAGAIN)
                fail("read at %u", received);
            break;
        }
        if (now_ms() > until)
            fail("16 MiB not through in 60 s: %u sent, %u received", sent, received);
        if (!progress)
            step();
        else
            ff_stafeto_pass();
    }
    printf("fstack-probe: 16 MiB in %llu ms\n", (unsigned long long)(now_ms() - started));
    ok("stream-16m");

    /* One write of 1 MiB on a new non-blocking connection nobody reads:
     * its buffers have their first sizes, and the send buffer takes part
     * of it. (The pair above grew its buffers by their automatic sizing.) */
    ssize_t w;

    ff_close(cfd);
    ff_close(sfd);
    cfd = connect_to(BASE_PORT + 1);
    sfd = accept_one(lfd, 1000);
    if (wait_connected(cfd, 1000) != 0)
        fail("the second connect did not complete");
    memset(big, 0x5a, sizeof(big));
    w = ff_write(cfd, big, sizeof(big));
    if (w <= 0 || (size_t)w >= sizeof(big))
        fail("one write of 1 MiB gave %zd", w);
    printf("fstack-probe: one write of 1 MiB took %zd bytes\n", w);
    ok("write-partial");
    ff_close(cfd);
    ff_close(sfd);
    ff_close(lfd);
    ff_close(kq);
}

static void
check_ephemeral(void)
{
    int lfd = listener(BASE_PORT + 2, 16);
    int a = connect_to(BASE_PORT + 2), b = connect_to(BASE_PORT + 2);
    unsigned pa = local_port(a), pb = local_port(b);

    if (pa == 0 || pb == 0 || pa == pb)
        fail("the local ports of two connects are %u and %u", pa, pb);
    printf("fstack-probe: local ports %u and %u\n", pa, pb);
    ok("ephemeral");
    for (int i = 0; i < 2; i++)
        ff_close(accept_one(lfd, 1000));
    ff_close(a);
    ff_close(b);
    ff_close(lfd);
}

static void
check_connections(void)
{
    static int clients[CONNECTIONS], servers[CONNECTIONS];
    int lfd = listener(BASE_PORT + 3, 256);
    int accepted = 0;
    uint64_t started = now_ms();

    for (int i = 0; i < CONNECTIONS; i++) {
        clients[i] = connect_to(BASE_PORT + 3);
        /* Take what is ready now, the queue of the listener stays short. */
        for (;;) {
            int fd = ff_accept(lfd, NULL, NULL);

            if (fd < 0)
                break;
            servers[accepted++] = fd;
        }
        if (i % 64 == 63)
            ff_stafeto_pass();
    }
    while (accepted < CONNECTIONS)
        servers[accepted++] = accept_one(lfd, 5000);
    for (int i = 0; i < CONNECTIONS; i++)
        if (wait_connected(clients[i], 2000) != 0)
            fail("connection %d did not complete", i);
    printf("fstack-probe: %d connections in %llu ms\n", CONNECTIONS,
        (unsigned long long)(now_ms() - started));
    for (int i = 0; i < CONNECTIONS; i++) {
        if (ff_close(clients[i]) != 0 || ff_close(servers[i]) != 0)
            fail("close of connection %d", i);
    }
    for (int i = 0; i < 20; i++)
        step();
    ok("connections-1000");
    ff_close(lfd);
}

static void
check_refused(void)
{
    int fd = connect_to(BASE_PORT + 9);
    int r = wait_connected(fd, 1000);

    if (r != ECONNREFUSED)
        fail("a connect to a closed port gave %d", r);
    ff_close(fd);
    ok("refused");
}

/*
 * The clock of the stack: with the blackhole of local SYNs on, a connect
 * to a closed port gets no answer; the listener opens 200 ms later, and
 * only the retransmission of the SYN after its timer (one second) connects.
 */
static void
check_syn_timer(void)
{
    int old_bh = 0, old_local = 0, fd, lfd, r;
    uint64_t started;

    if (sysctl_name("net.inet.tcp.blackhole", 1, &old_bh) != 0
        || sysctl_name("net.inet.tcp.blackhole_local", 1, &old_local) != 0)
        fail("sysctl of the blackhole");
    started = now_ms();
    fd = connect_to(BASE_PORT + 10);
    while (now_ms() < started + 200)
        step();
    if (connect_result(fd) >= 0)
        fail("the first SYN was answered");
    lfd = listener(BASE_PORT + 10, 16);
    r = wait_connected(fd, 5000);
    if (r != 0)
        fail("the SYN was not sent again within 5 s: %d", r);
    {
        uint64_t took = now_ms() - started;

        printf("fstack-probe: the connect took %llu ms\n", (unsigned long long)took);
        if (took < 800)
            fail("the connect took %llu ms, under the first timeout", (unsigned long long)took);
    }
    ff_close(accept_one(lfd, 1000));
    ff_close(fd);
    ff_close(lfd);
    sysctl_name("net.inet.tcp.blackhole", old_bh, &old_bh);
    sysctl_name("net.inet.tcp.blackhole_local", old_local, &old_local);
    ok("syn-timer");
}

/* One ff_write of 1 MiB on a blocking socket that nobody reads. */
static void
write_blocking(void)
{
    int lfd = listener(BASE_PORT + 20, 16);
    int cfd = connect_to(BASE_PORT + 20);
    int off = 0, sfd = accept_one(lfd, 1000);
    ssize_t w;

    if (wait_connected(cfd, 1000) != 0)
        fail("the connect did not complete");
    if (ff_ioctl(cfd, FIONBIO, &off) != 0)
        fail("FIONBIO off");
    errno = 0;
    w = ff_write(cfd, big, sizeof(big));
    printf("fstack-probe: one write of 1 MiB on a blocking socket gave %zd (errno %d)\n", w, errno);
    ff_close(cfd);
    ff_close(sfd);
    ff_close(lfd);
}

static int
probe(void *arg)
{
    uint64_t dropped, ticks, passes;

    (void)arg;
    if (strcmp(role, "write-blocking") == 0) {
        write_blocking();
    } else {
        check_random();
        check_kevent_and_stream();
        check_ephemeral();
        check_connections();
        check_refused();
        check_syn_timer();
    }
    ff_stafeto_counters(&dropped, &ticks, &passes);
    printf("fstack-probe: %llu clock ticks, %llu passes, %llu frames dropped\n",
        (unsigned long long)ticks, (unsigned long long)passes, (unsigned long long)dropped);
    ok("all");
    ff_stop_run();
    return 0;
}

/* A fault of the stack names its address and the instruction, for the
 * symbols of the program's ELF file. */
static void
on_fault(int sig, siginfo_t *info, void *context)
{
    ucontext_t *uc = context;
    char line[160];
    int n = snprintf(line, sizeof(line),
        "fstack-probe: check failed: signal %d at address %p, pc %#llx, lr %#llx\n", sig,
        info->si_addr, (unsigned long long)uc->uc_mcontext.pc,
        (unsigned long long)uc->uc_mcontext.regs[30]);

    write(1, line, (size_t)n);
    _exit(1);
}

int
main(int argc, char **argv)
{
    char *args[] = { "fstack-probe", "--conf", CONF, NULL };
    uint64_t started;

    struct sigaction fault;

    memset(&fault, 0, sizeof(fault));
    fault.sa_sigaction = on_fault;
    fault.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &fault, NULL);
    sigaction(SIGBUS, &fault, NULL);
    sigaction(SIGILL, &fault, NULL);
    if (argc > 1)
        role = argv[1];
    started = now_ms();
    if (ff_init(3, args) != 0) {
        printf("fstack-probe: check failed: ff_init\n");
        return 1;
    }
    printf("fstack-probe: ff_init took %llu ms\n", (unsigned long long)(now_ms() - started));
    ok("init");
    ff_run(probe, NULL);
    return status;
}
