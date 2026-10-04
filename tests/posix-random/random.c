/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The probe of the source of entropy on relibc (step 5e'). Built with
 * -fno-builtin; every result is compared, so no check folds away.
 *
 * Started by init: getentropy gives 256 bytes twice, which differ and are
 * not all zero; 257 bytes give EINVAL; getrandom with GRND_NONBLOCK gives
 * every byte, an unknown flag and GRND_RANDOM with GRND_INSECURE give
 * EINVAL, GRND_RANDOM gives 4096 bytes. Then it starts itself from its
 * file (/bin/posix-random fork), whose copy can fork.
 *
 * Then the nodes /dev/random and /dev/urandom: both are character devices
 * by stat and fstat, read 4096 bytes each (all different and nonzero) and take a
 * write; arc4random, arc4random_buf and arc4random_uniform; the names of
 * mkstemp and mkdtemp (no file can be created yet, so each call fails and
 * leaves its last name of six letters and digits in the template).
 *
 * Role `fork`: the parent takes 16 bytes (its buffer now holds the rest of
 * a turn), forks; parent and child each take 32 bytes, the child sends its
 * bytes through a pipe, and the parent checks that they differ from its
 * own: the child forgot the parent's key and buffer.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
extern uint64_t random_probe_calls(void);

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            printf("posix-random: check failed at line %d: %s (errno %d)\n", __LINE__, \
                   #cond, errno);                                                    \
            return 20;                                                               \
        }                                                                            \
    } while (0)

static int all_zero(const unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (bytes[i] != 0) return 0;
    return 1;
}

static unsigned long long head(const unsigned char *bytes) {
    unsigned long long word = 0;
    for (int i = 0; i < 8; i++) word = word << 8 | bytes[i];
    return word;
}

/* Reads `len` bytes of `fd`, which may come in pieces; the count. */
static ssize_t read_all(int fd, unsigned char *out, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, out + got, len - got);
        if (n <= 0) return n < 0 ? n : (ssize_t)got;
        got += (size_t)n;
    }
    return (ssize_t)got;
}

/* The nodes of the random devices. */
static int devices(void) {
    static unsigned char a[4096], b[4096], c[4096];
    struct stat st;
    memset(&st, 0, sizeof st);
    CHECK(stat("/dev/urandom", &st) == 0);
    CHECK(S_ISCHR(st.st_mode));
    memset(&st, 0, sizeof st);
    CHECK(stat("/dev/random", &st) == 0);
    CHECK(S_ISCHR(st.st_mode));
    int fd = open("/dev/urandom", O_RDONLY);
    CHECK(fd >= 0);
    memset(&st, 0, sizeof st);
    CHECK(fstat(fd, &st) == 0);
    CHECK(S_ISCHR(st.st_mode));
    CHECK(read_all(fd, a, sizeof a) == (ssize_t)sizeof a);
    CHECK(read_all(fd, b, sizeof b) == (ssize_t)sizeof b);
    CHECK(close(fd) == 0);
    int fd2 = open("/dev/random", O_RDONLY);
    CHECK(fd2 >= 0);
    CHECK(read_all(fd2, c, sizeof c) == (ssize_t)sizeof c);
    CHECK(close(fd2) == 0);
    CHECK(!all_zero(a, sizeof a) && !all_zero(b, sizeof b) && !all_zero(c, sizeof c));
    CHECK(memcmp(a, b, sizeof a) != 0);
    CHECK(memcmp(a, c, sizeof a) != 0);
    CHECK(memcmp(b, c, sizeof b) != 0);
    printf("posix-random: /dev/urandom and /dev/random are character devices that give "
           "4096 bytes each, all different (%016llx, %016llx, %016llx)\n",
           head(a), head(b), head(c));
    /* A write is taken whole and dropped. */
    fd = open("/dev/urandom", O_WRONLY);
    CHECK(fd >= 0);
    CHECK(write(fd, a, 100) == 100);
    /* A description opened for writing alone cannot be read. */
    errno = 0;
    CHECK(read(fd, b, 8) == -1);
    CHECK(errno == EBADF);
    CHECK(close(fd) == 0);
    fd = open("/dev/random", O_RDWR);
    CHECK(fd >= 0);
    CHECK(write(fd, a, 7) == 7);
    CHECK(read_all(fd, b, 32) == 32);
    CHECK(!all_zero(b, 32));
    CHECK(close(fd) == 0);
    printf("posix-random: writes to the devices are accepted\n");
    /* A dup keeps the device: the copy reads too, after the original closed. */
    fd = open("/dev/urandom", O_RDONLY);
    CHECK(fd >= 0);
    int copy = dup(fd);
    CHECK(copy >= 0 && copy != fd);
    CHECK(close(fd) == 0);
    memset(b, 0, 32);
    CHECK(read_all(copy, b, 32) == 32);
    CHECK(!all_zero(b, 32));
    CHECK(close(copy) == 0);
    /* The device is a file of the directory /dev. */
    CHECK(stat("/dev/nosuch", &st) == -1 && errno == ENOENT);
    printf("posix-random: a dup of a device reads\n");
    return 0;
}

/* The random functions of the C library. */
static int arc4(void) {
    unsigned char a[64] = {0}, b[64] = {0};
    unsigned int x = arc4random(), y = arc4random(), z = arc4random();
    CHECK(!(x == y && y == z));
    arc4random_buf(a, sizeof a);
    arc4random_buf(b, sizeof b);
    CHECK(memcmp(a, b, sizeof a) != 0);
    CHECK(!all_zero(a, sizeof a) && !all_zero(b, sizeof b));
    arc4random_buf(a, 0);
    CHECK(arc4random_uniform(0) == 0);
    CHECK(arc4random_uniform(1) == 0);
    int seen[10] = {0};
    for (int i = 0; i < 4000; i++) {
        unsigned int v = arc4random_uniform(10);
        CHECK(v < 10);
        seen[v]++;
    }
    for (int i = 0; i < 10; i++) CHECK(seen[i] >= 250 && seen[i] <= 550);
    /* A bound that is no power of two and one past 2^31 stay below it. */
    for (int i = 0; i < 200; i++) {
        CHECK(arc4random_uniform(3) < 3);
        CHECK(arc4random_uniform(0x80000001u) < 0x80000001u);
    }
    printf("posix-random: arc4random, arc4random_buf and arc4random_uniform (%08x %08x)\n", x, y);
    return 0;
}

static int name_is_random(const char *name, size_t from) {
    for (size_t i = from; i < from + 6; i++)
        if (!isalnum((unsigned char)name[i])) return 0;
    return 1;
}

/* mkstemp and mkdtemp make their names from the generator. No file can
 * be created yet (5i), so each call fails after its tries and the
 * template keeps the last name. */
static int temporary(void) {
    char a[] = "/tmp/probe-XXXXXX", b[] = "/tmp/probe-XXXXXX", d[] = "/tmp/dir-XXXXXX";
    char bad[] = "/tmp/short-XXXXX";
    errno = 0;
    CHECK(mkstemp(bad) == -1);
    CHECK(errno == EINVAL);
    CHECK(strcmp(bad, "/tmp/short-XXXXX") == 0);
    int fa = mkstemp(a);
    int ea = errno;
    int fb = mkstemp(b);
    CHECK(strncmp(a, "/tmp/probe-", 11) == 0 && strncmp(b, "/tmp/probe-", 11) == 0);
    CHECK(name_is_random(a, 11) && name_is_random(b, 11));
    CHECK(strcmp(a, b) != 0);
    CHECK(strcmp(a, "/tmp/probe-XXXXXX") != 0);
    char *made = mkdtemp(d);
    int ed = errno;
    CHECK(strncmp(d, "/tmp/dir-", 9) == 0 && name_is_random(d, 9));
    printf("posix-random: mkstemp gave %d (errno %d) with the names %s and %s, mkdtemp %s "
           "(errno %d) as %s\n",
           fa, ea, a, b, made ? "made" : "failed", ed, d);
    if (fa >= 0) close(fa);
    if (fb >= 0) close(fb);
    return 0;
}

/* Runs this program in the role `role` with the number of `fd`; its exit
 * status. */
static int spawn_role(const char *role, int fd) {
    char number[16];
    CHECK(snprintf(number, sizeof number, "%d", fd) > 0);
    char *argv[] = {"posix-random", (char *)role, number, NULL};
    pid_t pid = 0;
    CHECK(posix_spawn(&pid, "/bin/posix-random", NULL, NULL, argv, environ) == 0);
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status));
    return WEXITSTATUS(status);
}

/* A descriptor of a device crosses posix_spawn (without FD_CLOEXEC). */
static int descriptor(void) {
    int fd = open("/dev/urandom", O_RDONLY);
    CHECK(fd >= 0);
    int closed = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    CHECK(closed >= 0);
    CHECK(spawn_role("fdread", fd) == 0);
    CHECK(spawn_role("fdclosed", closed) == 0);
    printf("posix-random: a device descriptor crosses posix_spawn, FD_CLOEXEC closes it\n");
    CHECK(close(fd) == 0 && close(closed) == 0);
    return 0;
}

/*
 * A wait in two steps nested in a signal handler (SA_RESTART) on the
 * thread whose own wait it interrupted: the service tells both labels,
 * and the inner wait may take the outer's notification; the outer wait
 * looks again once a handler ran. Mode 0: getentropy before the first
 * seed in both. Mode 1: a read of a pipe in both; another thread writes
 * the outer pipe while the handler waits on the inner one, then the
 * inner.
 */
static volatile sig_atomic_t nested_mode, nested_done;
static int outer_pipe[2], inner_pipe[2];
static pthread_t main_thread;

static void on_usr1(int sig) {
    (void)sig;
    if (nested_mode == 0) {
        unsigned char inner[32];
        nested_done = getentropy(inner, sizeof inner) == 0 && !all_zero(inner, sizeof inner) ? 1 : -1;
    } else {
        unsigned char b = 0;
        nested_done = read(inner_pipe[0], &b, 1) == 1 && b == 'i' ? 1 : -1;
    }
}

static void pause_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000};
    while (nanosleep(&t, &t) != 0 && errno == EINTR) {
    }
}

/*
 * Beside the main thread's wait before the first seed: a thread in
 * arc4random gets SIGUSR2, whose handler has no SA_RESTART, and goes on
 * (arc4random has no way to fail); a thread in getentropy gets a request
 * of cancellation, and getentropy, no point of cancellation, returns its
 * bytes; the request waits for the thread's next point.
 */
static volatile sig_atomic_t usr2_ran, arc4_done, cancel_returned;
static pthread_t arc4_thread, cancel_thread;
static uint32_t arc4_value;
static uint64_t cancel_wait_calls;

static void on_usr2(int sig) {
    (void)sig;
    usr2_ran = 1;
}

static void *in_arc4random(void *arg) {
    (void)arg;
    arc4_value = arc4random();
    arc4_done = 1;
    return NULL;
}

static void *in_getentropy(void *arg) {
    (void)arg;
    unsigned char bytes[32];
    uint64_t before = random_probe_calls();
    if (getentropy(bytes, sizeof bytes) == 0 && !all_zero(bytes, sizeof bytes)) cancel_returned = 1;
    cancel_wait_calls = random_probe_calls() - before;
    pthread_testcancel();
    return NULL;
}

static void *poker(void *arg) {
    (void)arg;
    pause_ms(100);
    pthread_kill(main_thread, SIGUSR1);
    if (nested_mode == 0) {
        pthread_kill(arc4_thread, SIGUSR2);
        pthread_cancel(cancel_thread);
    }
    if (nested_mode == 1) {
        pause_ms(100);
        if (write(outer_pipe[1], "o", 1) != 1) return (void *)1;
        pause_ms(100);
        if (write(inner_pipe[1], "i", 1) != 1) return (void *)2;
    }
    return NULL;
}

/* Two threads read /dev/urandom at once, each through its own descriptor. */
static unsigned char urandom_bytes[2][4096];

static void *read_urandom(void *arg) {
    unsigned char *out = urandom_bytes[(long)arg];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return (void *)1;
    ssize_t n = read_all(fd, out, sizeof urandom_bytes[0]);
    close(fd);
    return n == (ssize_t)sizeof urandom_bytes[0] ? NULL : (void *)2;
}

static int urandom_threads(void) {
    pthread_t t[2];
    void *ended[2] = {(void *)9, (void *)9};
    for (long i = 0; i < 2; i++) CHECK(pthread_create(&t[i], NULL, read_urandom, (void *)i) == 0);
    for (int i = 0; i < 2; i++) CHECK(pthread_join(t[i], &ended[i]) == 0 && ended[i] == NULL);
    CHECK(memcmp(urandom_bytes[0], urandom_bytes[1], sizeof urandom_bytes[0]) != 0);
    CHECK(!all_zero(urandom_bytes[0], 4096) && !all_zero(urandom_bytes[1], 4096));
    printf("posix-random: two threads read 4096 bytes of /dev/urandom at once, all different\n");
    return 0;
}

static int nested(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sa.sa_flags = SA_RESTART;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    main_thread = pthread_self();
    unsigned char outer[32];
    void *poked = NULL;
    pthread_t t;
    /* The service's first fill waits 500 ms (slow-start). */
    errno = 0;
    CHECK(getrandom(outer, sizeof outer, GRND_NONBLOCK) == -1);
    CHECK(errno == EAGAIN);
    printf("posix-random: getrandom with GRND_NONBLOCK before the first seed gave EAGAIN\n");
    struct sigaction quiet;
    memset(&quiet, 0, sizeof quiet);
    quiet.sa_handler = on_usr2;
    CHECK(sigaction(SIGUSR2, &quiet, NULL) == 0);
    nested_mode = 0;
    nested_done = 0;
    CHECK(pthread_create(&arc4_thread, NULL, in_arc4random, NULL) == 0);
    CHECK(pthread_create(&cancel_thread, NULL, in_getentropy, NULL) == 0);
    CHECK(pthread_create(&t, NULL, poker, NULL) == 0);
    CHECK(getentropy(outer, sizeof outer) == 0);
    CHECK(pthread_join(t, &poked) == 0 && poked == NULL);
    CHECK(nested_done == 1);
    CHECK(!all_zero(outer, sizeof outer));
    printf("posix-random: getentropy waited for the first seed with another inside a handler\n");
    void *ended = NULL;
    CHECK(pthread_join(arc4_thread, &ended) == 0 && ended == NULL);
    CHECK(usr2_ran == 1 && arc4_done == 1);
    printf("posix-random: arc4random went on after a handler without SA_RESTART (%08x)\n",
           (unsigned)arc4_value);
    CHECK(pthread_join(cancel_thread, &ended) == 0);
    CHECK(ended == PTHREAD_CANCELED && cancel_returned == 1);
    printf("posix-random: getentropy is no point of cancellation: it returned, the next point "
           "cancelled\n");
    /* The counter includes the other three threads, the signal handlers
     * and their joins while this thread waits for the first key. A finite
     * set of requests fits well below this allowance. Retrying SEED on
     * every cancellation EINTR turns the wait into thousands of calls. */
    printf("posix-random: first seed wait used %llu kernel calls\n",
           (unsigned long long)cancel_wait_calls);
    CHECK(cancel_wait_calls <= 1024);
    printf("posix-random: cancellation left the first seed wait bounded\n");
    CHECK(pipe(outer_pipe) == 0 && pipe(inner_pipe) == 0);
    nested_mode = 1;
    nested_done = 0;
    CHECK(pthread_create(&t, NULL, poker, NULL) == 0);
    unsigned char b = 0;
    CHECK(read(outer_pipe[0], &b, 1) == 1);
    CHECK(b == 'o');
    CHECK(pthread_join(t, &poked) == 0 && poked == NULL);
    CHECK(nested_done == 1);
    CHECK(close(outer_pipe[0]) == 0 && close(outer_pipe[1]) == 0);
    CHECK(close(inner_pipe[0]) == 0 && close(inner_pipe[1]) == 0);
    printf("posix-random: a pipe read went on after another inside a handler\n");
    return urandom_threads();
}

static int first(void) {
    static unsigned char a[256], b[256], big[4096];
    unsigned char c[257], d[64];
    if (nested() != 0) return 21;
    CHECK(getentropy(a, sizeof a) == 0);
    CHECK(getentropy(b, sizeof b) == 0);
    CHECK(memcmp(a, b, sizeof a) != 0);
    CHECK(!all_zero(a, sizeof a) && !all_zero(b, sizeof b));
    printf("posix-random: getentropy gave 256 bytes twice, they differ (%016llx, %016llx)\n",
           head(a), head(b));
    errno = 0;
    CHECK(getentropy(c, sizeof c) == -1);
    CHECK(errno == EINVAL);
    printf("posix-random: getentropy of 257 bytes gave EINVAL\n");
    CHECK(getrandom(d, sizeof d, GRND_NONBLOCK) == (ssize_t)sizeof d);
    CHECK(!all_zero(d, sizeof d));
    errno = 0;
    CHECK(getrandom(d, 8, 8) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(getrandom(d, 8, GRND_RANDOM | GRND_INSECURE) == -1);
    CHECK(errno == EINVAL);
    CHECK(getrandom(big, sizeof big, GRND_RANDOM) == (ssize_t)sizeof big);
    CHECK(!all_zero(big, sizeof big));
    printf("posix-random: getrandom: GRND_NONBLOCK and GRND_RANDOM give every byte, "
           "bad flags EINVAL\n");
    pid_t pid = 0;
    char *argv[] = {"posix-random", "fork", NULL};
    CHECK(posix_spawn(&pid, "/bin/posix-random", NULL, NULL, argv, environ) == 0);
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(devices() == 0);
    CHECK(arc4() == 0);
    CHECK(temporary() == 0);
    CHECK(descriptor() == 0);
    return 0;
}

/* A descriptor of a device crosses fork, and the child's bytes differ from
 * the parent's. */
static int device_forked(void) {
    unsigned char warm[16], mine[32], theirs[32];
    int ends[2];
    int fd = open("/dev/urandom", O_RDONLY);
    CHECK(fd >= 0);
    CHECK(read_all(fd, warm, sizeof warm) == (ssize_t)sizeof warm);
    CHECK(pipe(ends) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        unsigned char child[32];
        if (read_all(fd, child, sizeof child) != (ssize_t)sizeof child) _exit(3);
        if (write(ends[1], child, sizeof child) != (ssize_t)sizeof child) _exit(4);
        _exit(0);
    }
    CHECK(read_all(fd, mine, sizeof mine) == (ssize_t)sizeof mine);
    CHECK(close(ends[1]) == 0);
    CHECK(read_all(ends[0], theirs, sizeof theirs) == (ssize_t)sizeof theirs);
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(memcmp(mine, theirs, sizeof mine) != 0);
    CHECK(!all_zero(theirs, sizeof theirs));
    CHECK(close(fd) == 0);
    printf("posix-random: a device descriptor crosses fork, the bytes of parent and child "
           "differ (%016llx, %016llx)\n",
           head(mine), head(theirs));
    return 0;
}

static int forked(void) {
    unsigned char warm[16], mine[32], theirs[32];
    int ends[2];
    CHECK(getentropy(warm, sizeof warm) == 0);
    CHECK(pipe(ends) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        unsigned char child[32];
        if (getentropy(child, sizeof child) != 0) _exit(3);
        if (write(ends[1], child, sizeof child) != (ssize_t)sizeof child) _exit(4);
        _exit(0);
    }
    CHECK(getentropy(mine, sizeof mine) == 0);
    CHECK(close(ends[1]) == 0);
    size_t got = 0;
    while (got < sizeof theirs) {
        ssize_t n = read(ends[0], theirs + got, sizeof theirs - got);
        CHECK(n > 0);
        got += (size_t)n;
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(memcmp(mine, theirs, sizeof mine) != 0);
    CHECK(!all_zero(theirs, sizeof theirs));
    printf("posix-random: after fork the child's bytes differ from the parent's "
           "(%016llx, %016llx)\n",
           head(mine), head(theirs));
    return device_forked();
}

/* Role `fdread`: 16 bytes of the descriptor the parent names. */
static int fd_read(const char *number) {
    unsigned char bytes[16];
    CHECK(read_all(atoi(number), bytes, sizeof bytes) == (ssize_t)sizeof bytes);
    CHECK(!all_zero(bytes, sizeof bytes));
    return 0;
}

/* Role `fdclosed`: the descriptor of a parent's FD_CLOEXEC is no descriptor. */
static int fd_closed(const char *number) {
    unsigned char bytes[16];
    errno = 0;
    CHECK(read(atoi(number), bytes, sizeof bytes) == -1);
    CHECK(errno == EBADF);
    return 0;
}

int main(int argc, char **argv) {
    int status;
    if (argc > 2 && strcmp(argv[1], "fdread") == 0) return fd_read(argv[2]);
    if (argc > 2 && strcmp(argv[1], "fdclosed") == 0) return fd_closed(argv[2]);
    status = argc > 1 && strcmp(argv[1], "fork") == 0 ? forked() : first();
    if (status == 0 && argc == 1) printf("posix-random: ok\n");
    return status;
}
