/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* Dynamically linked programs on libc.so (spec 2, 3.12.3, 3.12.4), started
 * by this static one. The programs are in dyn/: /bin/so-hello and
 * /bin/so-image are good, the /bin/bad-* files are each refused in one way.
 * The result is one line with the bits of the checks that failed. */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int bits;
static char *envp[] = {(char *)"SO_PROBE=1", (char *)"PATH=/bin", NULL};

static void check(int bit, const char *what, int good) {
    if (!good) {
        printf("posix-so: %s failed (errno %d)\n", what, errno);
        bits |= bit;
    }
}

/* A child with its output and input on pipes. */
struct child {
    pid_t pid;
    int out;
    int in;
};

/* Starts `path` with `argv`; the return value of posix_spawn. */
static int start(struct child *c, char *const argv[]) {
    int out[2], in[2];
    c->pid = -1;
    c->out = c->in = -1;
    if (pipe(out) != 0 || pipe(in) != 0) return errno;
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, in[0], 0);
    posix_spawn_file_actions_adddup2(&actions, out[1], 1);
    posix_spawn_file_actions_addclose(&actions, in[0]);
    posix_spawn_file_actions_addclose(&actions, in[1]);
    posix_spawn_file_actions_addclose(&actions, out[0]);
    posix_spawn_file_actions_addclose(&actions, out[1]);
    int error = posix_spawn(&c->pid, argv[0], &actions, NULL, argv, envp);
    posix_spawn_file_actions_destroy(&actions);
    close(in[0]);
    close(out[1]);
    c->out = out[0];
    c->in = in[1];
    return error;
}

/* Reads what the child writes until `stop` (a newline for one line, 0 for the
 * end of its output). */
static size_t slurp(struct child *c, char *buf, size_t size, char stop) {
    size_t have = 0;
    while (have < size - 1) {
        ssize_t n = read(c->out, buf + have, size - 1 - have);
        if (n <= 0) break;
        have += (size_t)n;
        if (stop != 0 && memchr(buf, stop, have) != NULL) break;
    }
    buf[have] = 0;
    return have;
}

/* Closes the child's input, reads the rest of its output and waits; the
 * status, -1 for a failed wait. */
static int finish(struct child *c, char *buf, size_t size) {
    close(c->in);
    size_t have = strlen(buf);
    while (have < size - 1) {
        ssize_t n = read(c->out, buf + have, size - 1 - have);
        if (n <= 0) break;
        have += (size_t)n;
    }
    buf[have] = 0;
    close(c->out);
    int status = 0;
    return waitpid(c->pid, &status, 0) == c->pid ? status : -1;
}

static int exited_with(int status, int code) { return WIFEXITED(status) && WEXITSTATUS(status) == code; }

/* Runs `path` with the arguments to its end; returns the posix_spawn error
 * or the status in `status`. */
static int run(char *const argv[], char *buf, size_t size, int *status) {
    struct child c;
    buf[0] = 0;
    int error = start(&c, argv);
    if (error != 0) {
        /* No process: nothing may have been written. */
        close(c.in);
        size_t n = slurp(&c, buf, size, 0);
        close(c.out);
        if (n != 0) return -1;
        return error;
    }
    *status = finish(&c, buf, size);
    return 0;
}

/* 1: the good program starts, prints and ends with 0. */
static void hello(void) {
    char buf[512];
    int status = -1;
    char *argv[] = {(char *)"/bin/so-hello", NULL};
    int error = run(argv, buf, sizeof buf, &status);
    check(1, "so-hello starts", error == 0 && exited_with(status, 0));
    check(1, "so-hello sees arguments, environment, stdout, errno and the constructors",
          strstr(buf, "so-hello: argc=1 order=123 bits=0\n") != NULL);
    check(1, "the destructor of the program runs after main",
          strstr(buf, "so-hello: argc=1 order=123 bits=0\nso-hello: destructor\n") != NULL);
    if (bits & 1) printf("posix-so: so-hello said: %s", buf);
}

/* 2: two live processes share the objects of libc.so; a third shows at
 * least three mappings of each. */
static void shared(void) {
    struct child c[2];
    char line[2][128];
    char *argv[] = {(char *)"/bin/so-hello", (char *)"wait", NULL};
    int started = 0;
    for (int i = 0; i < 2; i++) {
        if (start(&c[i], argv) != 0) break;
        slurp(&c[i], line[i], sizeof line[i], '\n');
        if (strcmp(line[i], "so-hello: waiting\n") == 0) started++;
    }
    check(2, "two so-hello wait are alive", started == 2);
    if (started == 2) {
        char buf[256];
        int status = -1;
        char *image[] = {(char *)"/bin/so-image", NULL};
        int error = run(image, buf, sizeof buf, &status);
        unsigned long long code = 0, data = 0;
        const char *at = strstr(buf, "code=");
        if (at != NULL) sscanf(at, "code=%llu data=%llu", &code, &data);
        check(2, "so-image runs", error == 0 && exited_with(status, 0));
        check(2, "so-image sees three mappings of the code and of the data of libc.so",
              strstr(buf, "found=11") != NULL && code >= 3 && data >= 3);
        printf("posix-so: so-image says: %s", buf);
    }
    for (int i = 0; i < started; i++) {
        char rest[128];
        if (write(c[i].in, "x", 1) != 1) bits |= 2;
        rest[0] = 0;
        check(2, "so-hello wait ends with 0", exited_with(finish(&c[i], rest, sizeof rest), 0));
    }
}

/* 3: fork and exec from a dynamic program. */
static void fork_and_exec(void) {
    char buf[512];
    int status = -1;
    char *fork_argv[] = {(char *)"/bin/so-hello", (char *)"fork", NULL};
    int error = run(fork_argv, buf, sizeof buf, &status);
    check(4, "so-hello fork", error == 0 && exited_with(status, 0) &&
          strstr(buf, "so-hello: child ok\n") != NULL && strstr(buf, "so-hello: fork ok\n") != NULL);
    char *exec_argv[] = {(char *)"/bin/so-hello", (char *)"exec", NULL};
    error = run(exec_argv, buf, sizeof buf, &status);
    check(8, "so-hello exec", error == 0 && exited_with(status, 0) &&
          strstr(buf, "so-hello: argc=2 order=123 bits=0\n") != NULL);
}

/* 4: each bad program is refused with ENOEXEC and prints nothing. */
static void bad(void) {
    static const char *const names[] = {"bad-interp", "bad-copy", "bad-tls", "bad-needed",
                                        "bad-symbol", "bad-ifunc", "bad-pie"};
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++) {
        char path[64], buf[128];
        int status = -1;
        snprintf(path, sizeof path, "/bin/%s", names[i]);
        char *argv[] = {path, NULL};
        int error = run(argv, buf, sizeof buf, &status);
        if (error != ENOEXEC) printf("posix-so: %s: posix_spawn gave %d, status %d\n", names[i], error, status);
        check(16, "a bad program is refused with ENOEXEC and prints nothing", error == ENOEXEC);
    }
}

/* 5: a set-ID library is refused; without the bits it works again. */
static void set_id(void) {
    char buf[512];
    int status = -1;
    char *argv[] = {(char *)"/bin/so-hello", NULL};
    if (getuid() != 0) {
        printf("posix-so: not root\n");
        bits |= 64;
        return;
    }
    check(64, "chmod 04755 libc.so", chmod("/lib/libc.so", 04755) == 0);
    int error = run(argv, buf, sizeof buf, &status);
    check(64, "so-hello with a set-ID libc.so is refused with ENOEXEC", error == ENOEXEC);
    check(64, "chmod 0755 libc.so", chmod("/lib/libc.so", 0755) == 0);
    error = run(argv, buf, sizeof buf, &status);
    check(64, "so-hello works again", error == 0 && exited_with(status, 0));
}

/* The time from posix_spawn to the main of the child, for a static child (this
 * program in the role "quick") and a dynamic one (so-hello quick), the first
 * run with no live process of the file (cold) and 20 more with one alive
 * (warm). The child writes its counter at main to its output. */
static uint64_t ticks(void) {
    uint64_t value;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(value)::"memory");
    return value;
}

static uint64_t tick_ns(uint64_t t) {
    uint64_t hz;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(hz));
    return t / hz * 1000000000ULL + t % hz * 1000000000ULL / hz;
}

static uint64_t sample(const char *path, int *bad) {
    char *argv[] = {(char *)path, (char *)"quick", NULL};
    struct child c;
    uint64_t t0 = ticks();
    if (start(&c, argv) != 0) {
        *bad = 1;
        return 0;
    }
    uint64_t at = 0;
    size_t have = 0;
    while (have < sizeof at) {
        ssize_t n = read(c.out, (char *)&at + have, sizeof at - have);
        if (n <= 0) break;
        have += (size_t)n;
    }
    char rest[16] = "";
    int status = finish(&c, rest, sizeof rest);
    if (have != sizeof at || !exited_with(status, 0) || at < t0) {
        *bad = 1;
        return 0;
    }
    return tick_ns(at - t0);
}

static int by_ns(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static void spawn_times(void) {
    static const char *const paths[2] = {"/bin/procs-child", "/bin/so-hello"};
    static const char *const names[2] = {"static", "dynamic"};
    int bad = 0;
    for (int k = 0; k < 2; k++) {
        uint64_t cold = sample(paths[k], &bad);
        struct child holder;
        char *wait_argv[] = {(char *)paths[k], (char *)"wait", NULL};
        char line[64];
        uint64_t warm[20];
        if (start(&holder, wait_argv) != 0) {
            bad = 1;
            continue;
        }
        slurp(&holder, line, sizeof line, '\n');
        for (int i = 0; i < 20; i++) warm[i] = sample(paths[k], &bad);
        qsort(warm, 20, sizeof warm[0], by_ns);
        printf("posix-so: spawn to main, %s: cold %llu ns, warm p50 %llu ns min %llu ns\n", names[k],
               (unsigned long long)cold, (unsigned long long)warm[10], (unsigned long long)warm[0]);
        if (write(holder.in, "x", 1) != 1) bad = 1;
        finish(&holder, line, sizeof line);
    }
    check(128, "the spawn timing runs", !bad);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "quick") == 0) {
        uint64_t at = ticks();
        return write(1, &at, sizeof at) == (ssize_t)sizeof at ? 0 : 1;
    }
    if (argc > 1 && strcmp(argv[1], "wait") == 0) {
        char byte;
        printf("posix-so: waiting\n");
        fflush(stdout);
        return read(0, &byte, 1) == 1 ? 0 : 1;
    }
    signal(SIGPIPE, SIG_IGN);
    hello();
    shared();
    fork_and_exec();
    bad();
    set_id();
    spawn_times();
    if (bits) {
        printf("posix-so: failed checks, bits %d\n", bits);
        return 1;
    }
    printf("posix-so: dynamic programs on libc.so ok\n");
    return 0;
}
