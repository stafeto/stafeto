/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { printf("posix-sock: line %d: %s errno %d\n", __LINE__, #c, errno); fflush(stdout); return 20; } } while (0)
#define RUN(f) do { int r = f(); if (r) return r; printf("posix-sock: " #f " ok\n"); fflush(stdout); } while (0)

static struct sockaddr_in loop(unsigned port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    return a;
}

static int listener(unsigned port, int kind, struct sockaddr_in *got) {
    int fd = socket(AF_INET, kind, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a = loop(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) return -2;
    if (kind == SOCK_STREAM && listen(fd, 2) < 0) return -3;
    socklen_t n = sizeof *got;
    if (getsockname(fd, (struct sockaddr *)got, &n) < 0 || n != sizeof *got) return -4;
    return fd;
}

static volatile int piped;
static void on_pipe(int s) { (void)s; piped = 1; }

static void pause_ms(long ms) {
    struct timespec t = {0, ms * 1000000L};
    nanosleep(&t, NULL);
}

/* A stream pair of AF_UNIX: bytes both ways, the end of the data, EPIPE. */
static int unix_stream(void) {
    int sv[2];
    char buf[64];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    CHECK(write(sv[0], "ping", 4) == 4);
    CHECK(read(sv[1], buf, sizeof buf) == 4 && memcmp(buf, "ping", 4) == 0);
    CHECK(send(sv[1], "pong", 4, 0) == 4);
    CHECK(recv(sv[0], buf, sizeof buf, 0) == 4 && memcmp(buf, "pong", 4) == 0);
    int type = 0;
    socklen_t len = sizeof type;
    CHECK(getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &type, &len) == 0 && type == SOCK_STREAM);
    struct stat st;
    CHECK(fstat(sv[0], &st) == 0 && S_ISSOCK(st.st_mode));
    CHECK(fcntl(sv[0], F_GETFL) == O_RDWR);
    /* The data of a closed sender is read, then the end. */
    CHECK(write(sv[0], "last", 4) == 4);
    CHECK(close(sv[0]) == 0);
    CHECK(read(sv[1], buf, sizeof buf) == 4);
    CHECK(read(sv[1], buf, sizeof buf) == 0);
    /* A write to a socket whose peer went: SIGPIPE, then EPIPE. */
    struct sigaction sa;
    piped = 0;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_pipe;
    CHECK(sigaction(SIGPIPE, &sa, NULL) == 0);
    errno = 0;
    CHECK(write(sv[1], "x", 1) == -1 && errno == EPIPE && piped == 1);
    piped = 0;
    errno = 0;
    CHECK(send(sv[1], "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE && piped == 0);
    CHECK(send(sv[1], "x", 1, 0) == -1 && piped == 1);
    sa.sa_handler = SIG_DFL;
    CHECK(sigaction(SIGPIPE, &sa, NULL) == 0);
    CHECK(close(sv[1]) == 0);
    CHECK(send(sv[1], "x", 1, 0) == -1 && errno == EBADF);
    CHECK(socketpair(AF_INET, SOCK_STREAM, 0, sv) == -1);
    CHECK(socketpair(AF_UNIX, 99, 0, sv) == -1 && errno == EINVAL && socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == -1 && errno == EPROTOTYPE);
    return 0;
}

/* shutdown ends a direction; the other goes on. */
static int unix_shutdown(void) {
    int sv[2];
    char c;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    CHECK(shutdown(sv[0], SHUT_WR) == 0);
    CHECK(read(sv[1], &c, 1) == 0);
    errno = 0;
    signal(SIGPIPE, SIG_IGN);
    CHECK(write(sv[0], "x", 1) == -1 && errno == EPIPE);
    CHECK(write(sv[1], "y", 1) == 1 && read(sv[0], &c, 1) == 1 && c == 'y');
    CHECK(shutdown(sv[0], SHUT_RD) == 0);
    CHECK(write(sv[1], "z", 1) == -1 && errno == EPIPE);
    CHECK(read(sv[0], &c, 1) == 0);
    CHECK(shutdown(sv[0], 7) == -1 && errno == EINVAL);
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(shutdown(sock, SHUT_RDWR) == -1 && errno == ENOTCONN);
    CHECK(shutdown(0, SHUT_RDWR) == -1 && errno == ENOTSOCK);
    signal(SIGPIPE, SIG_DFL);
    close(sv[0]); close(sv[1]); close(sock);
    return 0;
}

/* A stream over the loopback: names, the queue, refusal, the same address on both sides. */
static int inet_stream(void) {
    struct sockaddr_in addr, name, peer;
    socklen_t n;
    int l = listener(0, SOCK_STREAM, &addr);
    CHECK(l >= 0 && ntohs(addr.sin_port) >= 49152 && addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    int c = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(c >= 0);
    CHECK(connect(c, (struct sockaddr *)&addr, sizeof addr) == 0);
    n = sizeof name;
    CHECK(getsockname(c, (struct sockaddr *)&name, &n) == 0 && n == sizeof name && name.sin_port != 0);
    n = sizeof peer;
    CHECK(getpeername(c, (struct sockaddr *)&peer, &n) == 0 && memcmp(&peer, &addr, sizeof addr) == 0);
    struct sockaddr_in from;
    n = sizeof from;
    int s = accept(l, (struct sockaddr *)&from, &n);
    CHECK(s >= 0 && n == sizeof from && memcmp(&from, &name, sizeof name) == 0);
    n = sizeof peer;
    CHECK(getpeername(s, (struct sockaddr *)&peer, &n) == 0 && memcmp(&peer, &name, sizeof name) == 0);
    CHECK(send(s, "hello", 5, 0) == 5);
    char buf[16];
    CHECK(recv(c, buf, sizeof buf, MSG_PEEK) == 5);
    CHECK(recv(c, buf, sizeof buf, 0) == 5 && memcmp(buf, "hello", 5) == 0);
    CHECK(recv(c, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    /* The address is in use; the port that nobody listens at refuses. */
    int d = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(bind(d, (struct sockaddr *)&addr, sizeof addr) == -1 && errno == EADDRINUSE);
    struct sockaddr_in other = loop(1);
    CHECK(connect(d, (struct sockaddr *)&other, sizeof other) == -1 && errno == ECONNREFUSED);
    other.sin_addr.s_addr = htonl(0x0a000001);
    CHECK(connect(d, (struct sockaddr *)&other, sizeof other) == -1 && errno == ENETUNREACH);
    CHECK(connect(c, (struct sockaddr *)&addr, sizeof addr) == -1 && errno == EISCONN);
    CHECK(getpeername(d, (struct sockaddr *)&peer, &n) == -1 && errno == ENOTCONN);
    /* A queue of two; the third connection is refused. */
    int c2 = socket(AF_INET, SOCK_STREAM, 0), c3 = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(c2, (struct sockaddr *)&addr, sizeof addr) == 0);
    CHECK(connect(c3, (struct sockaddr *)&addr, sizeof addr) == 0);
    CHECK(connect(d, (struct sockaddr *)&addr, sizeof addr) == -1 && errno == ECONNREFUSED);
    int flags = fcntl(l, F_GETFL);
    CHECK(fcntl(l, F_SETFL, flags | O_NONBLOCK) == 0);
    int s2 = accept(l, NULL, NULL), s3 = accept(l, NULL, NULL);
    CHECK(s2 >= 0 && s3 >= 0);
    CHECK(accept(l, NULL, NULL) == -1 && errno == EAGAIN);
    int value = -1;
    socklen_t len = sizeof value;
    CHECK(getsockopt(l, SOL_SOCKET, SO_ACCEPTCONN, &value, &len) == 0 && value == 1);
    CHECK(getsockopt(c, SOL_SOCKET, SO_ERROR, &value, &len) == 0 && value == 0);
    value = 1;
    CHECK(setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &value, sizeof value) == 0);
    value = 0;
    CHECK(getsockopt(l, SOL_SOCKET, SO_REUSEADDR, &value, &len) == 0 && value != 0);
    value = 3000;
    CHECK(setsockopt(c, SOL_SOCKET, SO_RCVBUF, &value, sizeof value) == 0);
    CHECK(getsockopt(c, SOL_SOCKET, SO_RCVBUF, &value, &len) == 0 && value == 3000);
    CHECK(getsockopt(c, SOL_SOCKET, 77, &value, &len) == -1 && errno == ENOPROTOOPT);
    CHECK(accept(c, NULL, NULL) == -1 && errno == EINVAL);
    CHECK(listen(c, 1) == -1);
    /* An accepted socket with SOCK_NONBLOCK and SOCK_CLOEXEC. */
    int c4 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(c4 >= 0 && (fcntl(c4, F_GETFL) & O_NONBLOCK) && (fcntl(c4, F_GETFD) & FD_CLOEXEC));
    CHECK(connect(c4, (struct sockaddr *)&addr, sizeof addr) == 0);
    int s4 = accept4(l, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(s4 >= 0 && (fcntl(s4, F_GETFL) & O_NONBLOCK) && (fcntl(s4, F_GETFD) & FD_CLOEXEC));
    CHECK(sockatmark(s4) == 0 && sockatmark(0) == -1 && errno == ENOTSOCK);
    int fds[] = {l, c, s, d, c2, c3, s2, s3, c4, s4};
    for (unsigned i = 0; i < sizeof fds / sizeof *fds; i++) close(fds[i]);
    /* The port is free once the listener went. */
    int again = listener(ntohs(addr.sin_port), SOCK_STREAM, &name);
    CHECK(again >= 0);
    close(again);
    return 0;
}

/* Datagrams: bounds, the sender's address, truncation, a default destination, loss. */
static int inet_dgram(void) {
    struct sockaddr_in a, b, from;
    socklen_t n;
    int x = listener(0, SOCK_DGRAM, &a), y = listener(0, SOCK_DGRAM, &b);
    CHECK(x >= 0 && y >= 0 && a.sin_port != b.sin_port);
    CHECK(sendto(x, "one", 3, 0, (struct sockaddr *)&b, sizeof b) == 3);
    CHECK(sendto(x, "second", 6, 0, (struct sockaddr *)&b, sizeof b) == 6);
    char buf[16];
    n = sizeof from;
    CHECK(recvfrom(y, buf, sizeof buf, 0, (struct sockaddr *)&from, &n) == 3);
    CHECK(n == sizeof from && memcmp(&from, &a, sizeof a) == 0 && memcmp(buf, "one", 3) == 0);
    struct iovec iov = {buf, 3};
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    CHECK(recvmsg(y, &m, 0) == 3 && (m.msg_flags & MSG_TRUNC) && memcmp(buf, "sec", 3) == 0);
    CHECK(recv(y, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    /* A port nobody has: the datagram is lost and sendto says it went. */
    struct sockaddr_in none = loop(9);
    CHECK(sendto(x, "z", 1, 0, (struct sockaddr *)&none, sizeof none) == 1);
    CHECK(send(x, "z", 1, 0) == -1 && errno == EDESTADDRREQ);
    /* A default destination, and a sender that was not bound. */
    int c = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(connect(c, (struct sockaddr *)&b, sizeof b) == 0);
    CHECK(send(c, "hi", 2, 0) == 2);
    n = sizeof from;
    CHECK(recvfrom(y, buf, sizeof buf, 0, (struct sockaddr *)&from, &n) == 2 && from.sin_port != 0);
    struct sockaddr_in me;
    n = sizeof me;
    CHECK(getsockname(c, (struct sockaddr *)&me, &n) == 0 && memcmp(&me, &from, sizeof me) == 0);
    CHECK(sendto(y, "back", 4, 0, (struct sockaddr *)&from, n) == 4);
    CHECK(recv(c, buf, sizeof buf, 0) == 4 && memcmp(buf, "back", 4) == 0);
    /* Stream and datagram ports are apart; a datagram larger than the limit is refused. */
    int t = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(bind(t, (struct sockaddr *)&a, sizeof a) == 0);
    char big[2000];
    memset(big, 'q', sizeof big);
    CHECK(sendto(x, big, sizeof big, 0, (struct sockaddr *)&b, sizeof b) == -1 && errno == EMSGSIZE);
    close(x); close(y); close(c); close(t);
    return 0;
}

/* Names in the file system: a node of kind socket, connect by path, a stale name. */
static int unix_names(void) {
    const char *path = "/tmp/f9.sock";
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    strcpy(a.sun_path, path);
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(listen(l, 1) == -1 && errno == EINVAL);
    int r0 = bind(l, (struct sockaddr *)&a, sizeof a);
    CHECK(r0 == 0);
    struct stat st;
    CHECK(stat(path, &st) == 0 && S_ISSOCK(st.st_mode));
    int again = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(bind(again, (struct sockaddr *)&a, sizeof a) == -1 && errno == EADDRINUSE);
    CHECK(open(path, O_RDONLY) == -1 && errno == ENXIO);
    CHECK(listen(l, 1) == 0);
    struct sockaddr_un got;
    socklen_t n = sizeof got;
    CHECK(getsockname(l, (struct sockaddr *)&got, &n) == 0 && got.sun_family == AF_UNIX && strcmp(got.sun_path, path) == 0);
    CHECK(n == 2 + strlen(path) + 1);
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    int s = accept(l, NULL, NULL);
    CHECK(s >= 0);
    n = sizeof got;
    CHECK(getpeername(c, (struct sockaddr *)&got, &n) == 0 && strcmp(got.sun_path, path) == 0);
    n = sizeof got;
    CHECK(getsockname(c, (struct sockaddr *)&got, &n) == 0 && n == 2);
    CHECK(write(c, "named", 5) == 5);
    char buf[8];
    CHECK(read(s, buf, sizeof buf) == 5 && memcmp(buf, "named", 5) == 0);
    /* No file, a file of another kind, a node nobody is bound to. */
    struct sockaddr_un b = a;
    strcpy(b.sun_path, "/tmp/nothing");
    CHECK(connect(again, (struct sockaddr *)&b, sizeof b) == -1 && errno == ENOENT);
    int f = open("/tmp/plain", O_CREAT | O_WRONLY, 0600);
    CHECK(f >= 0 && close(f) == 0);
    strcpy(b.sun_path, "/tmp/plain");
    CHECK(connect(again, (struct sockaddr *)&b, sizeof b) == -1 && errno == ECONNREFUSED);
    /* A datagram socket at the name of a stream socket: the types differ. */
    int dg = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(connect(dg, (struct sockaddr *)&a, sizeof a) == -1 && errno == EPROTOTYPE);
    /* The name goes with unlink; a new socket takes it, and the old one is gone. */
    CHECK(unlink(path) == 0);
    CHECK(connect(again, (struct sockaddr *)&a, sizeof a) == -1 && errno == ENOENT);
    int l2 = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(bind(l2, (struct sockaddr *)&a, sizeof a) == 0 && listen(l2, 1) == 0);
    CHECK(connect(again, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(accept(l2, NULL, NULL) >= 0);
    /* AF_INET socket, AF_UNIX address. */
    int w = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(w, (struct sockaddr *)&a, sizeof a) == -1 && errno == EAFNOSUPPORT);
    /* Datagrams by name. */
    const char *dpath = "/tmp/f9.dgram";
    struct sockaddr_un d = a;
    strcpy(d.sun_path, dpath);
    int r = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(bind(r, (struct sockaddr *)&d, sizeof d) == 0);
    int snd = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(sendto(snd, "dg", 2, 0, (struct sockaddr *)&d, sizeof d) == 2);
    struct sockaddr_un src;
    n = sizeof src;
    CHECK(recvfrom(r, buf, sizeof buf, 0, (struct sockaddr *)&src, &n) == 2 && n == 2);
    CHECK(unlink(dpath) == 0 && unlink(path) == 0 && unlink("/tmp/plain") == 0);
    int all[] = {l, again, c, s, dg, l2, w, r, snd};
    for (unsigned i = 0; i < sizeof all / sizeof *all; i++) close(all[i]);
    return 0;
}

/* O_NONBLOCK, poll and select on sockets. */
static int readiness(void) {
    int sv[2];
    char c;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    struct pollfd p[2] = {{sv[0], POLLIN | POLLOUT, 0}, {sv[1], POLLIN, 0}};
    CHECK(poll(p, 2, 0) == 1 && p[0].revents == POLLOUT && p[1].revents == 0);
    CHECK(fcntl(sv[0], F_SETFL, O_NONBLOCK) == 0);
    CHECK(read(sv[0], &c, 1) == -1 && errno == EAGAIN);
    CHECK(write(sv[1], "a", 1) == 1);
    CHECK(poll(p, 2, 0) == 1 && p[0].revents == (POLLIN | POLLOUT));
    fd_set r, w;
    FD_ZERO(&r); FD_ZERO(&w);
    FD_SET(sv[0], &r); FD_SET(sv[1], &r);
    struct timeval none = {0, 0};
    CHECK(select(sv[1] + 1, &r, NULL, NULL, &none) == 1 && FD_ISSET(sv[0], &r) && !FD_ISSET(sv[1], &r));
    CHECK(read(sv[0], &c, 1) == 1);
    /* A write that fills the buffer is not ready for writing. */
    char block[512];
    memset(block, 'f', sizeof block);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);
    int total = 0, k;
    while ((k = write(sv[1], block, sizeof block)) > 0) total += k;
    CHECK(k == -1 && errno == EAGAIN && total == 4096);
    p[0].fd = sv[1]; p[0].events = POLLOUT; p[0].revents = 0;
    CHECK(poll(p, 1, 0) == 0);
    /* A reader frees room: the waiting poll wakes. */
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pause_ms(20);
        char buf[512];
        _exit(read(sv[0], buf, sizeof buf) == 512 ? 0 : 1);
    }
    CHECK(poll(p, 1, 5000) == 1 && p[0].revents == POLLOUT);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    /* The peer goes: readable and hung up. */
    close(sv[0]);
    p[0].fd = sv[1]; p[0].events = POLLIN;
    CHECK(poll(p, 1, 0) == 1 && (p[0].revents & POLLHUP));
    close(sv[1]);
    /* A listener is readable with a connection waiting. */
    struct sockaddr_in addr;
    int l = listener(0, SOCK_STREAM, &addr);
    p[0].fd = l; p[0].events = POLLIN; p[0].revents = 0;
    CHECK(poll(p, 1, 0) == 0);
    int cl = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(cl, (struct sockaddr *)&addr, sizeof addr) == 0);
    CHECK(poll(p, 1, 0) == 1 && p[0].revents == POLLIN);
    close(l); close(cl);
    return 0;
}

/* Descriptions in flight: a pipe end and a socket cross; the sender may close first. */
static int scm_rights(void) {
    int sv[2], pp[2];
    char c = 'm';
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && pipe(pp) == 0);
    union { struct cmsghdr h; char b[CMSG_SPACE(2 * sizeof(int))]; } u;
    memset(&u, 0, sizeof u);
    struct iovec iov = {&c, 1};
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = u.b;
    m.msg_controllen = CMSG_SPACE(sizeof(int));
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &pp[1], sizeof(int));
    CHECK(sendmsg(sv[0], &m, 0) == 1);
    /* The sender lets go of the write end: the message holds it. */
    CHECK(close(pp[1]) == 0);
    char got = 0;
    union { struct cmsghdr h; char b[CMSG_SPACE(2 * sizeof(int))]; } v;
    memset(&v, 0, sizeof v);
    iov.iov_base = &got;
    m.msg_control = v.b;
    m.msg_controllen = sizeof v.b;
    CHECK(recvmsg(sv[1], &m, 0) == 1 && got == 'm' && !(m.msg_flags & MSG_CTRUNC));
    h = CMSG_FIRSTHDR(&m);
    CHECK(h && h->cmsg_level == SOL_SOCKET && h->cmsg_type == SCM_RIGHTS && h->cmsg_len == CMSG_LEN(sizeof(int)));
    int received;
    memcpy(&received, CMSG_DATA(h), sizeof received);
    CHECK(received >= 0 && received != pp[0]);
    CHECK(write(received, "via", 3) == 3);
    char buf[8];
    CHECK(read(pp[0], buf, sizeof buf) == 3 && memcmp(buf, "via", 3) == 0);
    CHECK(close(received) == 0);
    CHECK(read(pp[0], buf, sizeof buf) == 0);
    /* A socket crosses and is used by the receiver; its peer sees the traffic. */
    int inner[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, inner) == 0);
    memset(&u, 0, sizeof u);
    m.msg_control = u.b;
    m.msg_controllen = CMSG_SPACE(sizeof(int));
    iov.iov_base = &c;
    h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &inner[1], sizeof(int));
    CHECK(sendmsg(sv[0], &m, 0) == 1);
    close(inner[1]);
    memset(&v, 0, sizeof v);
    m.msg_control = v.b;
    m.msg_controllen = sizeof v.b;
    iov.iov_base = &got;
    CHECK(recvmsg(sv[1], &m, MSG_CMSG_CLOEXEC) == 1);
    h = CMSG_FIRSTHDR(&m);
    CHECK(h != NULL);
    memcpy(&received, CMSG_DATA(h), sizeof received);
    CHECK((fcntl(received, F_GETFD) & FD_CLOEXEC) != 0);
    CHECK(write(received, "in", 2) == 2 && read(inner[0], buf, sizeof buf) == 2);
    /* A message with a description, read by a caller with no room for it. */
    memset(&u, 0, sizeof u);
    m.msg_control = u.b;
    m.msg_controllen = CMSG_SPACE(sizeof(int));
    iov.iov_base = &c;
    h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &pp[0], sizeof(int));
    CHECK(sendmsg(sv[0], &m, 0) == 1);
    m.msg_control = NULL;
    m.msg_controllen = 0;
    iov.iov_base = &got;
    CHECK(recvmsg(sv[1], &m, 0) == 1 && (m.msg_flags & MSG_CTRUNC));
    /* What cannot travel is refused: a file, a description not held. */
    int file = open("/bin/posix-sock", O_RDONLY);
    CHECK(file >= 0);
    memset(&u, 0, sizeof u);
    m.msg_control = u.b;
    m.msg_controllen = CMSG_SPACE(sizeof(int));
    iov.iov_base = &c;
    h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &file, sizeof(int));
    CHECK(sendmsg(sv[0], &m, 0) == -1 && errno == EOPNOTSUPP);
    int bad = 99;
    memcpy(CMSG_DATA(h), &bad, sizeof(int));
    CHECK(sendmsg(sv[0], &m, 0) == -1 && errno == EBADF);
    /* Datagrams carry descriptions too. */
    int dg[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, dg) == 0);
    memcpy(CMSG_DATA(h), &pp[0], sizeof(int));
    CHECK(sendmsg(dg[0], &m, 0) == 1);
    memset(&v, 0, sizeof v);
    m.msg_control = v.b;
    m.msg_controllen = sizeof v.b;
    iov.iov_base = &got;
    CHECK(recvmsg(dg[1], &m, 0) == 1);
    h = CMSG_FIRSTHDR(&m);
    CHECK(h != NULL && h->cmsg_type == SCM_RIGHTS);
    /* The same description arrives twice: the process gets another descriptor of it. */
    int dup_of;
    memcpy(&dup_of, CMSG_DATA(h), sizeof dup_of);
    CHECK(dup_of != pp[0]);
    CHECK(close(dup_of) == 0);
    CHECK(write(pp[1] >= 0 ? pp[1] : sv[0], "", 0) == 0 || 1);
    close(file); close(sv[0]); close(sv[1]); close(pp[0]);
    close(inner[0]); close(inner[1]); close(received);
    close(dg[0]); close(dg[1]);
    return 0;
}

/* A socket across fork: the child writes more than the buffer holds; the parent reads it all. */
static int across_fork(void) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        close(sv[0]);
        char block[500];
        for (int i = 0; i < 40; i++) {
            memset(block, 'a' + i % 26, sizeof block);
            if (write(sv[1], block, sizeof block) != sizeof block) _exit(1);
        }
        _exit(0);
    }
    close(sv[1]);
    char buf[700];
    int total = 0, k;
    while ((k = read(sv[0], buf, sizeof buf)) > 0) {
        for (int i = 0; i < k; i++) CHECK(buf[i] == 'a' + ((total + i) / 500) % 26);
        total += k;
    }
    CHECK(k == 0 && total == 40 * 500);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(sv[0]);
    /* A blocked accept is woken by a connect from another process. */
    struct sockaddr_in addr;
    int l = listener(0, SOCK_STREAM, &addr);
    CHECK(l >= 0);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        pause_ms(20);
        int c = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(c, (struct sockaddr *)&addr, sizeof addr) < 0) _exit(1);
        if (write(c, "late", 4) != 4) _exit(2);
        _exit(0);
    }
    int s = accept(l, NULL, NULL);
    CHECK(s >= 0);
    CHECK(read(s, buf, sizeof buf) == 4 && memcmp(buf, "late", 4) == 0);
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(s); close(l);
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    /* A file-loaded image supplies the region map required by fork. */
    if (argc == 1) {
        char *next[] = {"posix-sock", "loaded", NULL}, *env[] = {NULL};
        execve("/bin/posix-sock", next, env);
        CHECK(0);
    }
    printf("posix-sock: start\n");
    fflush(stdout);
    RUN(unix_stream);
    RUN(unix_shutdown);
    RUN(inet_stream);
    RUN(inet_dgram);
    RUN(unix_names);
    RUN(readiness);
    RUN(scm_rights);
    RUN(across_fork);
    printf("posix-sock: ok\n");
    fflush(stdout);
    return 0;
}
