/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <stdio.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

int stafeto_watch_start(const uint32_t *, const uint32_t *, uint32_t, uint64_t *, uint32_t *);
int stafeto_watch_keyed(uint32_t, uint64_t, uint32_t, uint32_t, uint32_t *, uint32_t);
int stafeto_watch_bit(uint64_t);
int stafeto_watch_full_pipe(uint32_t, uint32_t);
int stafeto_watch_full_tty(uint32_t, uint32_t);
void stafeto_watch_close_channel(void);
int stafeto_watch_stats(uint32_t, uint32_t);
int stafeto_poll_level(uint32_t);
#define CHECK(c) do { if (!(c)) { printf("posix-poll: line %d: %s errno %d\n", __LINE__, #c, errno); fflush(stdout); return 20; } } while (0)
#define IN 1u
#define OUT 4u
#define HUP 16u

static int service_watches(void) {
    int first[2], second[2];
    CHECK(pipe(first) == 0 && pipe(second) == 0);
    uint32_t fds[32], events[32], ready[32];
    uint64_t key, keys[8];
    int alias = dup(first[0]);
    CHECK(alias >= 0);
    for (unsigned i = 0; i < 32; i++) { fds[i] = i % 2 ? alias : first[0]; events[i] = i % 4 == 1 ? OUT : (i % 2 ? 0 : IN); }
    CHECK(stafeto_watch_start(fds, events, 32, &key, ready) == 1 && key != 0);
    CHECK(stafeto_watch_keyed(first[0], key, 0, 1, ready, 32) == 1);
    CHECK(write(first[1], "x", 1) == 1);
    CHECK(stafeto_watch_bit(key) == 0);
    CHECK(stafeto_watch_keyed(first[0], key, 0, 0, ready, 32) == 0);
    for (unsigned i = 0; i < 32; i++) CHECK(ready[i] == (i % 2 ? 0 : IN));
    CHECK(close(first[1]) == 0);
    CHECK(stafeto_watch_keyed(first[0], key, 1, 0, ready, 32) == 0);
    for (unsigned i = 0; i < 32; i++) CHECK(ready[i] == (i % 2 ? HUP : IN | HUP));
    CHECK(stafeto_watch_keyed(first[0], key, 1, 0, ready, 32) < 0);
    char byte;
    CHECK(read(first[0], &byte, 1) == 1 && byte == 'x');
    int reused_fd = first[0];
    uint64_t old_key = key;
    CHECK(close(alias) == 0 && close(first[0]) == 0);
    CHECK(pipe(first) == 0 && first[0] == reused_fd);
    fds[0] = first[0]; events[0] = IN;
    CHECK(stafeto_watch_start(fds, events, 1, &key, ready) == 1);
    CHECK((uint32_t)key == (uint32_t)old_key && (key >> 32) != (old_key >> 32));
    CHECK(stafeto_watch_keyed(first[0], key, 0, 1, ready, 1) == 1);
    CHECK(write(first[1], "n", 1) == 1 && stafeto_watch_bit(key) == 0);
    CHECK(stafeto_watch_keyed(first[0], key, 1, 0, ready, 1) == 0 && ready[0] == IN);
    CHECK(read(first[0], &byte, 1) == 1 && byte == 'n');
    CHECK(close(first[0]) == 0 && close(first[1]) == 0);

    fds[0] = second[0]; events[0] = IN;
    for (unsigned i = 0; i < 8; i++) CHECK(stafeto_watch_start(fds, events, 1, &keys[i], ready) == 1);
    CHECK(stafeto_watch_start(fds, events, 1, &key, ready) == -EAGAIN);
    CHECK(pipe(first) == 0);
    fds[0] = first[0]; fds[1] = second[0]; events[1] = IN;
    CHECK(stafeto_watch_start(fds, events, 2, &key, ready) == -EAGAIN);
    fds[0] = first[0];
    uint64_t rollback[8];
    for (unsigned i = 0; i < 8; i++) CHECK(stafeto_watch_start(fds, events, 1, &rollback[i], ready) == 1);
    CHECK(stafeto_watch_start(fds, events, 1, &key, ready) == -EAGAIN);
    for (unsigned i = 0; i < 8; i++) {
        CHECK(stafeto_watch_keyed(first[0], rollback[i], 1, 0, ready, 1) == 0);
        CHECK(ready[0] == 0);
        CHECK(stafeto_watch_keyed(second[0], keys[i], 1, 0, ready, 1) == 0);
    }
    CHECK(stafeto_watch_full_pipe(first[0], 0) == 0);
    CHECK(stafeto_watch_full_pipe(first[0], 1) == 0);
    CHECK(close(first[0]) == 0 && close(first[1]) == 0);
    CHECK(close(second[0]) == 0 && close(second[1]) == 0);

    int tty = open("/dev/console", O_RDWR | O_NOCTTY);
    CHECK(tty >= 0);
    struct termios old, raw;
    CHECK(tcgetattr(tty, &old) == 0);
    raw = old; raw.c_lflag &= ~ICANON; raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 1;
    CHECK(tcsetattr(tty, TCSANOW, &raw) == 0);
    /* The terminal's Watch holds 16 elements at most (proto_tty
     * WATCH_MAX); a longer one is refused. */
    for (unsigned i = 0; i < 17; i++) { fds[i] = tty; events[i] = IN; }
    CHECK(stafeto_watch_start(fds, events, 17, &key, ready) < 0);
    for (unsigned i = 0; i < 16; i++) { fds[i] = tty; events[i] = IN; }
    CHECK(stafeto_watch_start(fds, events, 16, &key, ready) == 1);
    CHECK(stafeto_watch_keyed(tty, key, 0, 1, ready, 16) == 1);
    raw.c_cc[VTIME] = 0;
    CHECK(tcsetattr(tty, TCSANOW, &raw) == 0);
    CHECK(stafeto_watch_bit(key) == 0);
    CHECK(stafeto_watch_keyed(tty, key, 0, 0, ready, 16) == 0);
    CHECK(stafeto_watch_keyed(tty, key, 1, 0, ready, 16) == 0);
    for (unsigned i = 0; i < 16; i++) CHECK(ready[i] == IN);
    CHECK(stafeto_watch_full_tty(tty, 0) == 0);
    CHECK(stafeto_watch_full_tty(tty, 1) == 0);
    CHECK(tcsetattr(tty, TCSANOW, &old) == 0);
    CHECK(close(tty) == 0);
    return 0;
}

/* The worst Watch of the terminal: 32 different open descriptions of the
 * console in one poll, which the library splits into two Watches of 16.
 * The file table holds 32 descriptors, so all are closed and the console
 * is opened on each of them (0, 1 and 2 are then descriptions of their
 * own). The first poll waits and pins them all; the second answers by
 * position. A 33rd element is refused. */
static int tty_distinct_watches(void) {
    fflush(stdout);
    for (int fd = 0; fd < 32; fd++) close(fd);
    struct pollfd p[33];
    for (int i = 0; i < 32; i++) {
        int fd = open("/dev/console", O_RDWR | O_NOCTTY);
        CHECK(fd == i);
        p[i].fd = fd; p[i].events = POLLIN; p[i].revents = 77;
    }
    struct termios old, raw;
    CHECK(tcgetattr(0, &old) == 0);
    raw = old; raw.c_lflag &= ~ICANON; raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;
    CHECK(tcsetattr(0, TCSANOW, &raw) == 0);
    /* The steps grow with the number of different descriptions: one,
     * sixteen (one Watch), then 32 (two Watches of 16). */
    struct pollfd same[16];
    for (int i = 0; i < 16; i++) same[i] = (struct pollfd){p[0].fd, POLLIN, 77};
    printf("posix-poll: tty poll of 16 elements, 1 description\n");
    CHECK(poll(same, 16, 3) == 0);
    printf("posix-poll: tty poll of 16 elements, 16 descriptions\n");
    CHECK(poll(p, 16, 3) == 0);
    printf("posix-poll: tty poll of 32 elements, 32 descriptions\n");
    CHECK(poll(p, 32, 3) == 0);
    for (int i = 0; i < 32; i++) CHECK(p[i].revents == 0);
    p[3].events = POLLOUT; p[20].events = POLLOUT;
    CHECK(poll(p, 32, 3) == 2);
    for (int i = 0; i < 32; i++) CHECK(p[i].revents == (i == 3 || i == 20 ? POLLOUT : 0));
    p[32] = p[0];
    CHECK(poll(p, 33, 0) < 0 && errno == EINVAL);
    CHECK(tcsetattr(0, TCSANOW, &old) == 0);
    for (int fd = 3; fd < 32; fd++) CHECK(close(fd) == 0);
    return 0;
}

struct writer { int fd; int signal; pthread_t target; int close_fd; };
static void *wake_writer(void *arg) {
    struct writer *w = arg;
    struct timespec pause = {0, 2000000};
    if (nanosleep(&pause, NULL) != 0) return (void *)1;
    if (w->close_fd >= 0 && close(w->close_fd) != 0) return (void *)1;
    if (w->signal) return (void *)(intptr_t)pthread_kill(w->target, w->signal);
    return write(w->fd, "p", 1) == 1 ? NULL : (void *)1;
}
static void *blocking_wait(void *arg) {
    struct pollfd *fds = arg;
    return (void *)(intptr_t)poll(fds, 2, -1);
}
static volatile sig_atomic_t caught, nested;
static void handler(int signal) { (void)signal; caught++; }
static void nested_handler(int signal) {
    (void)signal;
    struct pollfd local = {-1, POLLIN, 77};
    nested = poll(&local, 1, 1) == 0 && local.revents == 0;
    caught++;
}
static uint64_t monotonic_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0;
    return (uint64_t)t.tv_sec * 1000000000u + t.tv_nsec;
}

struct lower_writer { int fd; int ready; };
static void *lower_write(void *arg) {
    struct lower_writer *w = arg;
    if (stafeto_poll_level(28) != 0) {
        __atomic_store_n(&w->ready, -1, __ATOMIC_RELEASE);
        return (void *)1;
    }
    __atomic_store_n(&w->ready, 1, __ATOMIC_RELEASE);
    struct timespec delay = {0, 20000000};
    if (nanosleep(&delay, NULL) != 0) return (void *)1;
    return write(w->fd, "L", 1) == 1 ? NULL : (void *)1;
}

/* A spinning reader at 30 would starve this already registered writer
 * at 28. The ordinary poll must block until the actual byte arrives. */
static int lower_writer_ready(void) {
    CHECK(stafeto_poll_level(30) == 0);
    int ends[2];
    CHECK(pipe(ends) == 0);
    struct lower_writer w = {.fd = ends[1], .ready = 0};
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, lower_write, &w) == 0);
    uint64_t began = monotonic_ns();
    while (__atomic_load_n(&w.ready, __ATOMIC_ACQUIRE) == 0) {
        struct timespec delay = {0, 1000000};
        CHECK(monotonic_ns() - began < 1000000000 && nanosleep(&delay, NULL) == 0);
    }
    CHECK(__atomic_load_n(&w.ready, __ATOMIC_ACQUIRE) == 1);
    struct pollfd p = {ends[0], POLLIN, 0};
    began = monotonic_ns();
    CHECK(poll(&p, 1, 1000) == 1 && p.revents == POLLIN);
    CHECK(monotonic_ns() - began < 1000000000);
    char byte;
    void *result;
    CHECK(read(ends[0], &byte, 1) == 1 && byte == 'L');
    CHECK(pthread_join(worker, &result) == 0 && result == NULL);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
    printf("posix-poll: reader 30 receives the real byte from writer 28 before timeout\n");
    return 0;
}
static volatile int cleanup_mask_restored;
struct masked_wait { struct pollfd *fds; int select_call; };
static void cancelled_mask(void *unused) {
    (void)unused;
    sigset_t after;
    cleanup_mask_restored = pthread_sigmask(SIG_SETMASK, NULL, &after) == 0 && sigismember(&after, SIGUSR1) == 1;
}
static void *masked_wait(void *arg) {
    struct masked_wait *input = arg;
    sigset_t block, empty;
    sigemptyset(&block); sigaddset(&block, SIGUSR1); sigemptyset(&empty);
    if (pthread_sigmask(SIG_BLOCK, &block, NULL) != 0) return (void *)1;
    pthread_cleanup_push(cancelled_mask, NULL);
    if (input->select_call) {
        fd_set reads; FD_ZERO(&reads);
        int max = 0;
        for (int i = 0; i < 2; i++) { FD_SET(input->fds[i].fd, &reads); if (input->fds[i].fd > max) max = input->fds[i].fd; }
        pselect(max + 1, &reads, NULL, NULL, NULL, &empty);
    } else ppoll(input->fds, 2, NULL, &empty);
    pthread_cleanup_pop(0);
    return (void *)2;
}


static int frontends(void) {
    int ends[2];
    CHECK(pipe(ends) == 0);
    struct pollfd p[4] = {{ends[0], POLLIN, 77}, {ends[0], 0, 77}, {-1, POLLIN, 77}, {999, 0, 77}};
    CHECK(poll(p, 4, 0) == 1 && p[3].revents == POLLNVAL && p[0].revents == 0 && p[2].revents == 0);
    p[3].fd = -1;
    pthread_t worker;
    struct writer w = {ends[1], 0, pthread_self(), -1};
    CHECK(pthread_create(&worker, NULL, wake_writer, &w) == 0);
    CHECK(poll(p, 4, 100) == 1 && p[0].revents == POLLIN && p[1].revents == 0);
    void *result;
    CHECK(pthread_join(worker, &result) == 0 && result == NULL);
    char byte;
    CHECK(read(ends[0], &byte, 1) == 1 && byte == 'p');
    CHECK(pthread_create(&worker, NULL, wake_writer, &w) == 0);
    fd_set ready_read; FD_ZERO(&ready_read); FD_SET(ends[0], &ready_read);
    struct timeval remaining = {0, 100000};
    CHECK(select(ends[0] + 1, &ready_read, NULL, NULL, &remaining) == 1 && FD_ISSET(ends[0], &ready_read));
    CHECK(remaining.tv_sec == 0 && remaining.tv_usec > 0 && remaining.tv_usec < 100000);
    CHECK(pthread_join(worker, &result) == 0 && result == NULL);
    CHECK(read(ends[0], &byte, 1) == 1 && byte == 'p');
    CHECK(close(ends[1]) == 0);
    CHECK(poll(p, 4, 0) == 2 && (p[0].revents & POLLHUP) && p[1].revents == POLLHUP);
    CHECK(close(ends[0]) == 0);
    CHECK(pipe(ends) == 0 && close(ends[0]) == 0);
    struct pollfd broken = {ends[1], 0, 77};
    CHECK(poll(&broken, 1, 0) == 1 && broken.revents == POLLERR);
    CHECK(close(ends[1]) == 0);
    CHECK(pipe(ends) == 0);
    p[0] = (struct pollfd){ends[0], POLLIN, 77};
    w.fd = ends[1]; w.close_fd = ends[0];
    CHECK(pthread_create(&worker, NULL, wake_writer, &w) == 0);
    CHECK(poll(p, 1, 100) == 1 && p[0].revents == POLLIN);
    CHECK(pthread_join(worker, &result) == 0 && result == NULL);
    broken = (struct pollfd){ends[1], 0, 77};
    CHECK(poll(&broken, 1, 0) == 1 && broken.revents == POLLERR);
    CHECK(close(ends[1]) == 0);
    w.close_fd = -1;
    int file = open("/bin/posix-poll", O_RDONLY);
    CHECK(file >= 0);
    fd_set readset, writeset, exceptset;
    FD_ZERO(&readset); FD_ZERO(&writeset); FD_ZERO(&exceptset);
    FD_SET(file, &exceptset);
    struct timeval zero = {0, 0};
    CHECK(select(file + 1, NULL, NULL, &exceptset, &zero) == 1 && FD_ISSET(file, &exceptset));
    FD_SET(file, &readset); FD_SET(file, &writeset); FD_SET(file, &exceptset);
    CHECK(select(file + 1, &readset, &writeset, &exceptset, &zero) == 3);
    int null = open("/dev/null", O_RDWR), random = open("/dev/urandom", O_RDONLY);
    CHECK(null >= 0 && random >= 0);
    FD_ZERO(&exceptset); FD_SET(null, &exceptset);
    CHECK(select(null + 1, NULL, NULL, &exceptset, &zero) == 0);
    FD_ZERO(&exceptset); FD_SET(random, &exceptset);
    CHECK(select(random + 1, NULL, NULL, &exceptset, &zero) == 0);
    CHECK(close(null) == 0 && close(random) == 0);
    struct pollfd regular = {file, POLLPRI, 99};
    CHECK(poll(&regular, 1, 0) == 0 && regular.revents == 0);
    int bad = file;
    CHECK(close(file) == 0);
    FD_ZERO(&readset); FD_SET(bad, &readset);
    fd_set before = readset;
    struct timeval time = {0, 123456}, saved = time;
    errno = 0;
    CHECK(select(bad + 1, &readset, NULL, NULL, &time) == -1 && errno == EBADF);
    CHECK(memcmp(&readset, &before, sizeof before) == 0 && memcmp(&time, &saved, sizeof time) == 0);
    CHECK(select(-1, NULL, NULL, NULL, &zero) == -1 && errno == EINVAL);
    FD_ZERO(&readset); for (int i = 0; i <= 32; i++) FD_SET(i, &readset); before = readset;
    CHECK(select(33, &readset, NULL, NULL, &time) == -1 && errno == EBADF);
    CHECK(memcmp(&readset, &before, sizeof before) == 0 && memcmp(&time, &saved, sizeof time) == 0);
    struct timespec ns = {0, 1234567}, ns_before = ns;
    uint64_t start = monotonic_ns();
    CHECK(ppoll(NULL, 0, &ns, NULL) == 0 && monotonic_ns() - start >= 1234567);
    CHECK(memcmp(&ns, &ns_before, sizeof ns) == 0);
    CHECK(pselect(0, NULL, NULL, NULL, &ns, NULL) == 0);
    CHECK(memcmp(&ns, &ns_before, sizeof ns) == 0);
    for (unsigned i = 0; i < 48; i++) CHECK(poll(NULL, 0, 1) == 0);
    ns.tv_nsec = 1000000000;
    CHECK(ppoll(NULL, 0, &ns, NULL) == -1 && errno == EINVAL);
    CHECK(pipe(ends) == 0);
    struct sigaction action;
    memset(&action, 0, sizeof action); action.sa_handler = handler; action.sa_flags = SA_RESTART;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, NULL) == 0);
    w.signal = SIGUSR1;
    p[0] = (struct pollfd){ends[0], POLLIN, 77};
    CHECK(pthread_create(&worker, NULL, wake_writer, &w) == 0);
    errno = 0;
    CHECK(poll(p, 1, 100) == -1 && errno == EINTR && caught == 1 && p[0].revents == 77);
    CHECK(pthread_join(worker, &result) == 0 && result == NULL);
    sigset_t blocked, original, empty, after;
    CHECK(sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGUSR1) == 0 && sigemptyset(&empty) == 0);
    CHECK(pthread_sigmask(SIG_BLOCK, &blocked, &original) == 0);
    CHECK(pthread_kill(pthread_self(), SIGUSR1) == 0 && caught == 1);
    ns = (struct timespec){0, 100000000}; ns_before = ns;
    CHECK(ppoll(p, 1, &ns, &empty) == -1 && errno == EINTR && caught == 2);
    CHECK(memcmp(&ns, &ns_before, sizeof ns) == 0 && p[0].revents == 77);
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &after) == 0 && sigismember(&after, SIGUSR1) == 1);
    CHECK(pthread_kill(pthread_self(), SIGUSR1) == 0 && caught == 2);
    FD_ZERO(&readset); FD_SET(ends[0], &readset); before = readset;
    CHECK(pselect(ends[0] + 1, &readset, NULL, NULL, &ns, &empty) == -1 && errno == EINTR && caught == 3);
    CHECK(memcmp(&readset, &before, sizeof before) == 0 && memcmp(&ns, &ns_before, sizeof ns) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &after) == 0 && sigismember(&after, SIGUSR1) == 1);
    CHECK(pthread_sigmask(SIG_SETMASK, &original, NULL) == 0);
    action.sa_handler = nested_handler;
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    CHECK(pthread_create(&worker, NULL, wake_writer, &w) == 0);
    CHECK(poll(p, 1, 100) == -1 && errno == EINTR && nested == 1 && caught == 4);
    CHECK(pthread_join(worker, &result) == 0 && result == NULL);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
    int tty = open("/dev/console", O_RDWR | O_NOCTTY);
    CHECK(tty >= 0 && pipe(ends) == 0);
    struct termios old, raw;
    CHECK(tcgetattr(tty, &old) == 0);
    raw = old; raw.c_lflag &= ~ICANON; raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 1;
    CHECK(tcsetattr(tty, TCSANOW, &raw) == 0);
    p[0] = (struct pollfd){ends[0], POLLIN, 99}; p[1] = (struct pollfd){tty, POLLIN, 99};
    w.fd = ends[1]; w.signal = 0;
    CHECK(pthread_create(&worker, NULL, wake_writer, &w) == 0);
    CHECK(poll(p, 2, 100) == 1 && p[0].revents == POLLIN && p[1].revents == 0);
    CHECK(pthread_join(worker, &result) == 0 && result == NULL);
    CHECK(read(ends[0], &byte, 1) == 1 && byte == 'p');
    uint32_t fds[1] = {(uint32_t)tty}, events[1] = {IN}, ready[1];
    uint64_t keys[8], key;
    for (unsigned i = 0; i < 8; i++) CHECK(stafeto_watch_start(fds, events, 1, &keys[i], ready) == 1);
    errno = 0;
    CHECK(poll(p, 2, 100) == -1 && errno == EAGAIN);
    fds[0] = ends[0];
    uint64_t pipe_keys[8];
    for (unsigned i = 0; i < 8; i++) CHECK(stafeto_watch_start(fds, events, 1, &pipe_keys[i], ready) == 1);
    CHECK(stafeto_watch_start(fds, events, 1, &key, ready) == -EAGAIN);
    for (unsigned i = 0; i < 8; i++) {
        CHECK(stafeto_watch_keyed(ends[0], pipe_keys[i], 1, 0, ready, 1) == 0);
        CHECK(stafeto_watch_keyed(tty, keys[i], 1, 0, ready, 1) == 0);
    }
    CHECK(pthread_create(&worker, NULL, blocking_wait, p) == 0);
    ns = (struct timespec){0, 2000000}; CHECK(nanosleep(&ns, NULL) == 0);
    CHECK(pthread_cancel(worker) == 0 && pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
    struct masked_wait masked = {p, 0};
    for (int variant = 0; variant < 2; variant++) {
        masked.select_call = variant; cleanup_mask_restored = 0;
        CHECK(pthread_create(&worker, NULL, masked_wait, &masked) == 0);
        CHECK(nanosleep(&ns, NULL) == 0);
        CHECK(pthread_cancel(worker) == 0 && pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
        CHECK(cleanup_mask_restored == 1);
    }

    fds[0] = ends[0];
    for (unsigned i = 0; i < 8; i++) CHECK(stafeto_watch_start(fds, events, 1, &pipe_keys[i], ready) == 1);
    fds[0] = tty;
    for (unsigned i = 0; i < 8; i++) CHECK(stafeto_watch_start(fds, events, 1, &keys[i], ready) == 1);
    for (unsigned i = 0; i < 8; i++) {
        CHECK(stafeto_watch_keyed(ends[0], pipe_keys[i], 1, 0, ready, 1) == 0);
        CHECK(stafeto_watch_keyed(tty, keys[i], 1, 0, ready, 1) == 0);
    }
    raw.c_cc[VTIME] = 0;
    CHECK(tcsetattr(tty, TCSANOW, &raw) == 0);
    CHECK(poll(p, 2, 0) == 1 && p[1].revents == POLLIN);
    CHECK(tcsetattr(tty, TCSANOW, &old) == 0);
    CHECK(close(tty) == 0 && close(ends[0]) == 0 && close(ends[1]) == 0);
    int sync[2];
    CHECK(pipe(ends) == 0 && pipe(sync) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (close(ends[1]) != 0 || close(sync[0]) != 0 || write(sync[1], "s", 1) != 1) _exit(31);
        struct pollfd waiting = {ends[0], POLLIN, 0};
        if (poll(&waiting, 1, 1000) != 1 || waiting.revents != POLLIN) _exit(32);
        if (read(ends[0], &byte, 1) != 1 || byte != 'c') _exit(33);
        _exit(0);
    }
    CHECK(close(ends[0]) == 0 && close(sync[1]) == 0);
    CHECK(read(sync[0], &byte, 1) == 1 && byte == 's');
    ns = (struct timespec){0, 10000000}; CHECK(nanosleep(&ns, NULL) == 0);
    CHECK(kill(child, SIGSTOP) == 0);
    int status;
    CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    CHECK(kill(child, SIGCONT) == 0 && write(ends[1], "c", 1) == 1);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(ends[1]) == 0 && close(sync[0]) == 0);
    return 0;
}



static void *lifecycle_wait(void *arg) {
    return (void *)(intptr_t)poll(arg, 3, -1);
}
static int watch_capacity(int readfd, int tty, unsigned limit) {
    uint32_t fds[1], events[1] = {IN}, ready[1];
    uint64_t pipekeys[8], ttykeys[8];
    fds[0] = (uint32_t)readfd;
    for (unsigned i = 0; i < limit; i++) CHECK(stafeto_watch_start(fds, events, 1, &pipekeys[i], ready) == 1);
    fds[0] = (uint32_t)tty;
    for (unsigned i = 0; i < limit; i++) CHECK(stafeto_watch_start(fds, events, 1, &ttykeys[i], ready) == 1);
    for (unsigned i = 0; i < limit; i++) {
        CHECK(stafeto_watch_keyed(readfd, pipekeys[i], 1, 0, ready, 1) == 0);
        CHECK(stafeto_watch_keyed(tty, ttykeys[i], 1, 0, ready, 1) == 0);
    }
    return 0;
}
static int lifecycle_start(void) {
    int keep[2], held[2], tty = open("/dev/console", O_RDWR | O_NOCTTY);
    CHECK(tty >= 0 && pipe(keep) == 0 && pipe(held) == 0);
    struct termios raw;
    CHECK(tcgetattr(tty, &raw) == 0);
    raw.c_lflag &= ~ICANON; raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 1;
    CHECK(tcsetattr(tty, TCSANOW, &raw) == 0);
    struct pollfd pending[3] = {{keep[0], POLLIN, 0}, {held[0], POLLIN, 0}, {tty, POLLIN, 0}};
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, lifecycle_wait, pending) == 0);
    struct timespec delay = {0, 10000000};
    CHECK(nanosleep(&delay, NULL) == 0);
    CHECK(close(held[0]) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) _exit(watch_capacity(keep[0], tty, 7));
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    char a[20], b[20], c[20], d[20];
    CHECK(snprintf(a, sizeof a, "%d", keep[0]) > 0 && snprintf(b, sizeof b, "%d", keep[1]) > 0);
    CHECK(snprintf(c, sizeof c, "%d", held[1]) > 0 && snprintf(d, sizeof d, "%d", tty) > 0);
    char *next[] = {"posix-poll", "lifecycle-resume", a, b, c, d, NULL}, *env[] = {NULL};
    execve("/bin/posix-poll", next, env);
    CHECK(0);
    return 0;
}
static int lifecycle_resume(char **argv) {
    int readfd = atoi(argv[2]), writefd = atoi(argv[3]), heldwrite = atoi(argv[4]), tty = atoi(argv[5]);
    CHECK(watch_capacity(readfd, tty, 8) == 0);
    struct pollfd closed_reader = {heldwrite, 0, 0};
    CHECK(poll(&closed_reader, 1, 0) == 1 && closed_reader.revents == POLLERR);
    struct termios raw;
    CHECK(tcgetattr(tty, &raw) == 0);
    raw.c_lflag |= ICANON; raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;
    CHECK(tcsetattr(tty, TCSANOW, &raw) == 0);
    CHECK(close(readfd) == 0 && close(writefd) == 0 && close(heldwrite) == 0 && close(tty) == 0);
    printf("posix-poll: exec/fork watch cleanup ok\n");
    return 0;
}

int main(int argc, char **argv) {
    /* A file-loaded image supplies the region map required by fork. */
    if (argc == 1) {
        char *next[] = {"posix-poll", "loaded", NULL}, *env[] = {NULL};
        execve("/bin/posix-poll", next, env);
        CHECK(0);
    }
    if (argc == 2) return lifecycle_start();
    CHECK(argc == 6 && lifecycle_resume(argv) == 0);
    CHECK(lower_writer_ready() == 0);
    int result = frontends();
    if (result != 0) return result;
    result = service_watches();
    if (result != 0) return result;
    result = tty_distinct_watches();
    if (result != 0) return result;
    int ends[2], tty = open("/dev/console", O_RDWR | O_NOCTTY);
    CHECK(tty >= 0 && pipe(ends) == 0);
    /* Cover the services' 250 ms heartbeat, including init reply and rearm. */
    struct timespec heartbeat = { .tv_sec = 0, .tv_nsec = 300000000 };
    CHECK(nanosleep(&heartbeat, NULL) == 0);
    CHECK(stafeto_watch_stats(ends[0], tty) == 0);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0 && close(tty) == 0);
    stafeto_watch_close_channel();
    printf("posix-poll: ok\n");
    fflush(stdout);
    return 0;
}
