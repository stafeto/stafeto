/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * `fast-layer`: the sockets of the POSIX layer over the stack of F-Stack in
 * the process (cargo xtask fast-probe layer). The program calls no ff_*
 * function: it makes sockets, epoll and the rest as any server does, and
 * the table that ff_stafeto_glue.c registered sends them to the stack. It is
 * linked as nginx-fast will be (libfstack.a, libvirtio_net.a, the glue).
 *
 * First the checks of the calls, on the loopback of the stack and on the
 * layer's refusals (lines `fast-layer: <name> ok`; a failure ends the
 * program with 1). Then it serves from one epoll instance, as nginx does
 * (connections added once with EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP,
 * the listeners by level):
 *
 *   TCP 7    echo; the line `?stats` gets the counters of the stack's steps,
 *            `?stop` ends the program
 *   TCP 80   any request (up to the empty line) gets the page: a head and
 *            1 MiB of a fixed pattern (page_byte), then the connection closes
 *
 * Built with -fno-builtin; every result is compared.
 */

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define ECHO_PORT 7
#define PAGE_PORT 80
#define SCRATCH_PORT 9000
#define PAGE_BYTES (1u << 20)
#define MAX_CONNECTIONS 64
#define OUT_BYTES 65536
#define FAST_BASE (1 << 20)

void ff_stafeto_counters(uint64_t *dropped, uint64_t *ticks, uint64_t *pass_count);

static int epfd = -1;
static int mixed[2];
static volatile int alarms;
static int stop;
static unsigned char page[PAGE_BYTES];
static char head[128];
static int head_len;

static void
fail(const char *what)
{
    printf("fast-layer: check failed: %s (errno %d)\n", what, errno);
    fflush(stdout);
    _exit(1);
}

#define REQUIRE(cond) do { if (!(cond)) fail(#cond); } while (0)
/* A call that must fail with the errno `e`. */
#define REFUSED(call, e) do { errno = 0; if ((call) != -1 || errno != (e)) fail(#call " is not " #e); } while (0)

static void
ok(const char *name)
{
    printf("fast-layer: %s ok\n", name);
    fflush(stdout);
}

static unsigned char
page_byte(unsigned i)
{
    return (unsigned char)(i * 7u + (i >> 8) + (i >> 16));
}

static uint64_t
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int
tcp_socket(int port, int backlog)
{
    struct sockaddr_in a;
    int on = 1, fd = socket(AF_INET, SOCK_STREAM, 0);

    REQUIRE(fd >= 0);
    REQUIRE(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == 0);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    REQUIRE(bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    REQUIRE(listen(fd, backlog) == 0);
    return fd;
}

static void
add(int fd, uint32_t events, void *who)
{
    struct epoll_event ev;

    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = who;
    REQUIRE(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == 0);
}

/* The events up to `ms` (the stack runs inside the call). */
static int
wait_events(struct epoll_event *ev, int n, int ms)
{
    return epoll_wait(epfd, ev, n, ms);
}

/* Waits for an event whose data is `who`, up to 3 s; its events. */
static uint32_t
wait_for(void *who)
{
    uint64_t end = now_ms() + 3000;

    while (now_ms() < end) {
        struct epoll_event ev[8];
        int n = wait_events(ev, 8, 100), i;

        for (i = 0; i < n; i++)
            if (ev[i].data.ptr == who)
                return ev[i].events;
    }
    fail("an event did not come");
    return 0;
}

/* ------------------------------------------------------------- the checks */

static int
scratch_pair(int *client, int *server, int *listener)
{
    struct sockaddr_in a;
    struct epoll_event ev[4];
    int c, l, s = -1, k;
    uint64_t end;

    l = tcp_socket(SCRATCH_PORT, 16);
    c = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(c >= FAST_BASE);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(SCRATCH_PORT);
    a.sin_addr.s_addr = htonl(0x7f000001);
    errno = 0;
    REQUIRE(connect(c, (struct sockaddr *)&a, sizeof(a)) == -1 && errno == EINPROGRESS);
    add(l, EPOLLIN, (void *)1);
    end = now_ms() + 3000;
    while (s < 0 && now_ms() < end) {
        int n = wait_events(ev, 4, 100);

        for (k = 0; k < n; k++)
            if (ev[k].data.ptr == (void *)1)
                s = accept4(l, NULL, NULL, 0);
    }
    REQUIRE(s >= FAST_BASE);
    *client = c;
    *server = s;
    *listener = l;
    return 0;
}

static void
check_calls(void)
{
    int c, s, l, n, flag, on;
    struct sockaddr_in a;
    socklen_t len;
    char buf[64];
    struct stat st;
    struct iovec iov[2];
    struct epoll_event ev, out[4];

    epfd = epoll_create1(0);
    REQUIRE(epfd >= 0);
    scratch_pair(&c, &s, &l);
    ok("range");

    /* The numbers: above the table, non-blocking, kept on exec and fork. */
    flag = fcntl(c, F_GETFL);
    REQUIRE(flag >= 0 && (flag & O_NONBLOCK) != 0);
    REQUIRE(fcntl(c, F_GETFD) >= 0);
    REQUIRE(fcntl(c, F_SETFD, 0) == 0);
    REQUIRE(fcntl(c, F_SETFL, flag) == 0);
    REQUIRE(fstat(c, &st) == 0 && S_ISSOCK(st.st_mode));
    ok("flags");

    /* The loopback of the stack: the addresses of both ends. */
    len = sizeof(a);
    REQUIRE(getpeername(s, (struct sockaddr *)&a, &len) == 0);
    REQUIRE(a.sin_family == AF_INET && a.sin_addr.s_addr == htonl(0x7f000001));
    len = sizeof(a);
    REQUIRE(getsockname(c, (struct sockaddr *)&a, &len) == 0);
    len = sizeof(a);
    REQUIRE(getpeername(c, (struct sockaddr *)&a, &len) == 0);
    REQUIRE(a.sin_port == htons(SCRATCH_PORT));
    {
        /* An address is cut to the program's length, and the bytes behind it
         * stay: the stack writes into a buffer of the layer. */
        struct {
            unsigned char room[4];
            unsigned char guard[16];
        } cut;
        struct sockaddr_in wrong;

        memset(&cut, 0xee, sizeof(cut));
        len = 4;
        REQUIRE(getsockname(c, (struct sockaddr *)cut.room, &len) == 0);
        REQUIRE(len == sizeof(struct sockaddr_in));
        REQUIRE(cut.room[0] == AF_INET && cut.room[1] == 0);
        for (n = 0; n < 16; n++)
            REQUIRE(cut.guard[n] == 0xee);
        memset(&cut, 0xee, sizeof(cut));
        len = 0;
        REQUIRE(getpeername(c, (struct sockaddr *)cut.room, &len) == 0);
        REQUIRE(len == sizeof(struct sockaddr_in) && cut.room[0] == 0xee);
        /* An address of the wrong length or family never reaches the stack. */
        memset(&wrong, 0, sizeof(wrong));
        wrong.sin_family = AF_INET;
        {
            int u = socket(AF_INET, SOCK_STREAM, 0);

            REQUIRE(u >= FAST_BASE);
            REFUSED(bind(u, (struct sockaddr *)&wrong, 0), EINVAL);
            REFUSED(bind(u, (struct sockaddr *)&wrong, 4), EINVAL);
            REFUSED(connect(u, (struct sockaddr *)&wrong, 15), EINVAL);
            {
                unsigned char big[256];

                memset(big, 0, sizeof(big));
                big[0] = AF_INET;
                REFUSED(bind(u, (struct sockaddr *)big, 200), EINVAL);
            }
            wrong.sin_family = AF_UNIX;
            REFUSED(bind(u, (struct sockaddr *)&wrong, sizeof(wrong)), EAFNOSUPPORT);
            REQUIRE(close(u) == 0);
        }
    }
    ok("names");

    /* The queue is empty: accept answers at once even though the program
     * never asked for O_NONBLOCK. */
    REFUSED(accept(l, NULL, NULL), EAGAIN);
    ok("accept_empty");

    /* The data both ways, with the vectors and the flags that nginx uses. */
    on = 1;
    REQUIRE(setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == 0);
    len = sizeof(n);
    REQUIRE(getsockopt(c, SOL_SOCKET, SO_ERROR, &n, &len) == 0 && n == 0);
    REQUIRE(write(c, "ping", 4) == 4);
    {
        uint64_t end = now_ms() + 3000;
        ssize_t got = -1;

        while (now_ms() < end) {
            got = recv(s, buf, 3, MSG_PEEK);
            if (got == 3)
                break;
            wait_events(out, 4, 20);
        }
        REQUIRE(got == 3 && memcmp(buf, "pin", 3) == 0);
    }
    REQUIRE(read(s, buf, sizeof(buf)) == 4 && memcmp(buf, "ping", 4) == 0);
    REFUSED(read(s, buf, sizeof(buf)), EAGAIN);
    iov[0].iov_base = (void *)"po";
    iov[0].iov_len = 2;
    iov[1].iov_base = (void *)"ng";
    iov[1].iov_len = 2;
    REQUIRE(writev(s, iov, 2) == 4);
    {
        uint64_t end = now_ms() + 3000;
        ssize_t got = -1;

        while (now_ms() < end) {
            got = recv(c, buf, sizeof(buf), MSG_DONTWAIT);
            if (got == 4)
                break;
            wait_events(out, 4, 20);
        }
        REQUIRE(got == 4 && memcmp(buf, "pong", 4) == 0);
    }
    REQUIRE(send(c, "x", 1, MSG_NOSIGNAL) == 1);
    REFUSED(send(c, "x", 1, MSG_OOB), EOPNOTSUPP);
    ok("data");

    /* Edge and oneshot records. */
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.ptr = (void *)2;
    REQUIRE(epoll_ctl(epfd, EPOLL_CTL_ADD, s, &ev) == 0);
    n = wait_events(out, 4, 3000);
    REQUIRE(n >= 1 && out[0].data.ptr == (void *)2 && (out[0].events & EPOLLIN));
    REQUIRE(read(s, buf, sizeof(buf)) == 1);
    REQUIRE(write(c, "y", 1) == 1);
    /* The record is off after its event: nothing comes until MOD. */
    n = wait_events(out, 4, 150);
    REQUIRE(n == 0);
    REQUIRE(epoll_ctl(epfd, EPOLL_CTL_MOD, s, &ev) == 0);
    n = wait_events(out, 4, 3000);
    REQUIRE(n >= 1 && out[0].data.ptr == (void *)2);
    REQUIRE(read(s, buf, sizeof(buf)) == 1);
    /* A oneshot record that fired is off but still there (EV_ONESHOT would
     * have deleted it): DEL finds it. */
    REQUIRE(epoll_ctl(epfd, EPOLL_CTL_DEL, s, NULL) == 0);
    REFUSED(epoll_ctl(epfd, EPOLL_CTL_DEL, s, NULL), ENOENT);
    ok("oneshot");

    /* The end of the stream: EPOLLRDHUP with the read, and 0 from read. */
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
    REQUIRE(epoll_ctl(epfd, EPOLL_CTL_ADD, s, &ev) == 0);
    REQUIRE(shutdown(c, SHUT_WR) == 0);
    REQUIRE((wait_for((void *)2) & EPOLLRDHUP) != 0);
    REQUIRE(read(s, buf, sizeof(buf)) == 0);
    REQUIRE(epoll_ctl(epfd, EPOLL_CTL_DEL, s, NULL) == 0);
    ok("rdhup");

    /* What the layer refuses. */
    REFUSED(dup(c), EOPNOTSUPP);
    REFUSED(dup2(c, 5), EOPNOTSUPP);
    REFUSED(dup2(0, FAST_BASE + 7), EBADF);
    REFUSED(fcntl(c, F_DUPFD, 0), EOPNOTSUPP);
    {
        struct pollfd p;

        p.fd = c;
        p.events = POLLIN;
        p.revents = 0;
        REFUSED(poll(&p, 1, 0), EINVAL);
    }
    REFUSED(fcntl(c, F_SETFL, 0), EINVAL);
    on = 0;
    REFUSED(ioctl(c, FIONBIO, &on), EINVAL);
    on = 1;
    REQUIRE(ioctl(c, FIONBIO, &on) == 0);
    REFUSED(lseek(c, 0, SEEK_SET), ESPIPE);
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLEXCLUSIVE;
    REFUSED(epoll_ctl(epfd, EPOLL_CTL_ADD, c, &ev), EINVAL);
    REFUSED(fork(), EPERM);
    ok("refusals");

    /* An error of the stack arrives in the numbers of Linux: a connect to a
     * port nobody listens on ends with ECONNREFUSED, which SO_ERROR gives
     * and the record reports as an error. */
    {
        int r = socket(AF_INET, SOCK_STREAM, 0), err = 0;
        struct sockaddr_in to;
        uint32_t got;
        socklen_t elen = sizeof(err);

        REQUIRE(r >= FAST_BASE);
        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_port = htons(9);
        to.sin_addr.s_addr = htonl(0x7f000001);
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLOUT | EPOLLIN | EPOLLET;
        ev.data.ptr = (void *)3;
        REQUIRE(epoll_ctl(epfd, EPOLL_CTL_ADD, r, &ev) == 0);
        errno = 0;
        REQUIRE(connect(r, (struct sockaddr *)&to, sizeof(to)) == -1 && errno == EINPROGRESS);
        got = wait_for((void *)3);
        REQUIRE((got & (EPOLLERR | EPOLLHUP | EPOLLRDHUP | EPOLLIN)) != 0);
        REQUIRE(getsockopt(r, SOL_SOCKET, SO_ERROR, &err, &elen) == 0);
        REQUIRE(err == ECONNREFUSED);
        REQUIRE(close(r) == 0);
    }
    ok("refused_connect");

    /* A descriptor of the stack does not travel over a socket pair. */
    {
        int pair[2];
        struct msghdr m;
        struct iovec v;
        char control[CMSG_SPACE(sizeof(int))];
        struct cmsghdr *cm;
        char byte = 'x';

        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        memset(&m, 0, sizeof(m));
        memset(control, 0, sizeof(control));
        v.iov_base = &byte;
        v.iov_len = 1;
        m.msg_iov = &v;
        m.msg_iovlen = 1;
        m.msg_control = control;
        m.msg_controllen = sizeof(control);
        cm = CMSG_FIRSTHDR(&m);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &c, sizeof(int));
        errno = 0;
        REQUIRE(sendmsg(pair[0], &m, 0) == -1 && errno == EOPNOTSUPP);
        close(pair[0]);
        close(pair[1]);
    }
    ok("scm_rights");

    /* Other sockets keep their ways. */
    {
        int u = socket(AF_INET, SOCK_DGRAM, 0);

        REQUIRE(u >= 0 && u < FAST_BASE);
        close(u);
    }
    ok("datagram_unchanged");

    REQUIRE(close(c) == 0);
    REQUIRE(close(s) == 0);
    REQUIRE(close(l) == 0);
    REFUSED(close(c), EBADF);
    ok("close");

    /* One instance for both kinds of descriptors, as nginx has it (its
     * channel to the main process next to the sockets): the end of a pipe
     * and the sockets of the stack in the same set. The command `?mix` of
     * the echo puts the pipe back into the set while the program serves, so
     * that the loop looks at it once for each clock tick and sleeps on it. */
    {
        char byte;

        REQUIRE(pipe(mixed) == 0);
        add(mixed[0], EPOLLIN, (void *)4);
        REQUIRE(write(mixed[1], "z", 1) == 1);
        wait_for((void *)4);
        REQUIRE(read(mixed[0], &byte, 1) == 1 && byte == 'z');
        REQUIRE(epoll_ctl(epfd, EPOLL_CTL_DEL, mixed[0], NULL) == 0);
    }
    ok("mixed_set");
}

/* -------------------------------------------------------------- the server */

struct connection {
    int fd;
    int port;
    int readable;
    int writable;
    unsigned asked, head_sent, body_sent;
    char seen[4];
    unsigned char out[OUT_BYTES];
    unsigned out_len, out_sent;
};

static struct connection connections[MAX_CONNECTIONS];
static int echo_listener, page_listener;

static void
on_alarm(int sig)
{
    (void)sig;
    alarms++;
}

static void
drop(struct connection *c)
{
    epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    c->fd = -1;
}

static void
stats(struct connection *c)
{
    uint64_t dropped = 0, ticks = 0, passes = 0;

    ff_stafeto_counters(&dropped, &ticks, &passes);
    c->out_len = (unsigned)snprintf((char *)c->out, sizeof(c->out), "ticks=%llu passes=%llu\n",
        (unsigned long long)ticks, (unsigned long long)passes);
    c->out_sent = 0;
}

/* The echo: what came goes back as the socket takes it. */
static void
serve_echo(struct connection *c)
{
    for (;;) {
        if (c->out_sent < c->out_len) {
            ssize_t w = send(c->fd, c->out + c->out_sent, c->out_len - c->out_sent, MSG_NOSIGNAL);

            if (w < 0) {
                if (errno == EAGAIN)
                    return;
                drop(c);
                return;
            }
            c->out_sent += (unsigned)w;
            if (c->out_sent < c->out_len)
                continue;
            c->out_len = c->out_sent = 0;
        }
        {
            ssize_t got = recv(c->fd, c->out, sizeof(c->out), 0);

            if (got == 0) {
                drop(c);
                return;
            }
            if (got < 0) {
                if (errno != EAGAIN)
                    drop(c);
                return;
            }
            if (got >= 5 && memcmp(c->out, "?stop", 5) == 0) {
                stop = 1;
                return;
            }
            if (got >= 6 && memcmp(c->out, "?alarm", 6) == 0) {
                struct sigaction sa;
                struct itimerval it;

                memset(&sa, 0, sizeof(sa));
                sa.sa_handler = on_alarm;
                REQUIRE(sigaction(SIGALRM, &sa, NULL) == 0);
                memset(&it, 0, sizeof(it));
                it.it_interval.tv_usec = 1000;
                it.it_value.tv_usec = 1000;
                REQUIRE(setitimer(ITIMER_REAL, &it, NULL) == 0);
                c->out_len = (unsigned)snprintf((char *)c->out, sizeof(c->out), "alarm\n");
            } else if (got >= 6 && memcmp(c->out, "?quiet", 6) == 0) {
                struct itimerval it;

                memset(&it, 0, sizeof(it));
                REQUIRE(setitimer(ITIMER_REAL, &it, NULL) == 0);
                c->out_len = (unsigned)snprintf((char *)c->out, sizeof(c->out), "quiet %d\n",
                    alarms > 0);
            } else if (got >= 6 && memcmp(c->out, "?unmix", 6) == 0) {
                REQUIRE(epoll_ctl(epfd, EPOLL_CTL_DEL, mixed[0], NULL) == 0);
                c->out_len = (unsigned)snprintf((char *)c->out, sizeof(c->out), "unmixed\n");
            } else if (got >= 4 && memcmp(c->out, "?mix", 4) == 0) {
                add(mixed[0], EPOLLIN, (void *)4);
                c->out_len = (unsigned)snprintf((char *)c->out, sizeof(c->out), "mixed\n");
            } else if (got >= 6 && memcmp(c->out, "?stats", 6) == 0)
                stats(c);
            else
                c->out_len = (unsigned)got;
            c->out_sent = 0;
        }
    }
}

/* The page: the head and the body as far as the stack takes them. */
static void
serve_page(struct connection *c)
{
    if (!c->asked) {
        for (;;) {
            char buf[512];
            ssize_t got = read(c->fd, buf, sizeof(buf)), i;

            if (got == 0) {
                drop(c);
                return;
            }
            if (got < 0) {
                if (errno != EAGAIN)
                    drop(c);
                return;
            }
            for (i = 0; i < got; i++) {
                memmove(c->seen, c->seen + 1, 3);
                c->seen[3] = buf[i];
                if (memcmp(c->seen, "\r\n\r\n", 4) == 0)
                    c->asked = 1;
            }
            if (c->asked)
                break;
        }
    }
    while (c->head_sent < (unsigned)head_len || c->body_sent < PAGE_BYTES) {
        struct iovec iov[2];
        int count = 0;
        unsigned room = PAGE_BYTES - c->body_sent;
        ssize_t w;

        if (c->head_sent < (unsigned)head_len) {
            iov[count].iov_base = head + c->head_sent;
            iov[count].iov_len = (size_t)head_len - c->head_sent;
            count++;
        }
        if (room > 65536)
            room = 65536;
        iov[count].iov_base = page + c->body_sent;
        iov[count].iov_len = room;
        count++;
        w = writev(c->fd, iov, count);
        if (w < 0) {
            if (errno != EAGAIN)
                drop(c);
            return;
        }
        {
            unsigned left = (unsigned)w;

            if (c->head_sent < (unsigned)head_len) {
                unsigned part = (unsigned)head_len - c->head_sent;

                if (part > left)
                    part = left;
                c->head_sent += part;
                left -= part;
            }
            c->body_sent += left;
        }
    }
    drop(c);
}

static void
accept_all(int listener, int port)
{
    for (;;) {
        int fd = accept4(listener, NULL, NULL, SOCK_NONBLOCK);
        int i;

        if (fd < 0) {
            REQUIRE(errno == EAGAIN);
            return;
        }
        for (i = 0; i < MAX_CONNECTIONS; i++)
            if (connections[i].fd < 0)
                break;
        if (i == MAX_CONNECTIONS) {
            close(fd);
            continue;
        }
        memset(&connections[i], 0, sizeof(connections[i]));
        connections[i].fd = fd;
        connections[i].port = port;
        add(fd, EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP, &connections[i]);
        /* An edge record reports what is already there only once; look. */
        if (port == ECHO_PORT)
            serve_echo(&connections[i]);
        else
            serve_page(&connections[i]);
    }
}

static void
serve(void)
{
    struct epoll_event ev[32];
    unsigned i;

    for (i = 0; i < MAX_CONNECTIONS; i++)
        connections[i].fd = -1;
    echo_listener = tcp_socket(ECHO_PORT, 1024);
    page_listener = tcp_socket(PAGE_PORT, 1024);
    add(echo_listener, EPOLLIN, &echo_listener);
    add(page_listener, EPOLLIN, &page_listener);
    printf("fast-layer: serving\n");
    fflush(stdout);
    while (!stop) {
        int n = epoll_wait(epfd, ev, 32, -1), k;

        if (n < 0) {
            REQUIRE(errno == EINTR);
            continue;
        }
        for (k = 0; k < n; k++) {
            if (ev[k].data.ptr == &echo_listener) {
                accept_all(echo_listener, ECHO_PORT);
            } else if (ev[k].data.ptr == &page_listener) {
                accept_all(page_listener, PAGE_PORT);
            } else if (ev[k].data.ptr == (void *)4) {
                continue;
            } else {
                struct connection *c = ev[k].data.ptr;

                if (c->fd < 0)
                    continue;
                if (c->port == ECHO_PORT)
                    serve_echo(c);
                else
                    serve_page(c);
            }
        }
    }
}

int
main(int argc, char **argv)
{
    unsigned i;

    (void)argc;
    (void)argv;
    for (i = 0; i < PAGE_BYTES; i++)
        page[i] = page_byte(i);
    head_len = snprintf(head, sizeof(head),
        "HTTP/1.1 200 OK\r\nContent-Length: %u\r\nConnection: close\r\n\r\n", PAGE_BYTES);
    check_calls();
    serve();
    printf("fast-layer: ended\n");
    fflush(stdout);
    return 0;
}
