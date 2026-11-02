/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The probe of the display service's place in a process (sub-project 3,
 * part 3a). Built with -fno-builtin; every result is compared.
 *
 * Started by init with a session from its record: the session answers a
 * CLONE. Then it starts itself from its file (/bin/posix-display fork), the
 * copy that can fork. That role maps a buffer as the display piece and
 * checks: munmap, mprotect and mmap with MAP_FIXED over it give EINVAL and
 * leave it as it was; a forked child has a session of its own that answers
 * a CLONE and no display piece, and a read at the parent's address ends it
 * with SIGSEGV; a spawned program has a session, and so has the program a
 * forked child execs, which has no display piece either; the parent's
 * piece is intact through all of it, goes with dp_unmap, and a second one
 * can be mapped. At the end the price of the session in a fork is
 * measured: the time of fork() with and without it, in turns.
 */

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
extern int dp_session(void);
extern int dp_clone_ok(void);
extern int64_t dp_map(uint64_t pages);
extern int dp_unmap(void);
extern uint64_t dp_buffer(void);
extern void dp_hide(int hide);
extern uint64_t dp_ns(void);

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            printf("posix-display: check failed at line %d: %s (errno %d)\n", __LINE__, \
                   #cond, errno);                                                    \
            return 20;                                                               \
        }                                                                            \
    } while (0)

#define PAGES 250
#define BYTES (PAGES * 4096UL)

static int run_file(const char *path, const char *role, int *status) {
    char *argv[] = {"posix-display", (char *)role, NULL};
    pid_t pid = 0;
    if (posix_spawn(&pid, path, NULL, NULL, argv, environ) != 0) return -1;
    if (waitpid(pid, status, 0) != pid) return -1;
    return 0;
}

static int run(const char *role, int *status) {
    return run_file("/bin/posix-display", role, status);
}

/* A set-ID program has no session, whatever its caller put in the place. */
static int no_session(void) {
    CHECK(dp_session() == 0);
    CHECK(dp_clone_ok() != 0);
    CHECK(dp_buffer() == 0);
    return 0;
}

/* The checks of a process that has a session of its own and no piece. */
static int session_without_piece(void) {
    CHECK(dp_session() == 1);
    CHECK(dp_clone_ok() == 0);
    CHECK(dp_buffer() == 0);
    return 0;
}

static int refusals(volatile unsigned char *p) {
    errno = 0;
    CHECK(munmap((void *)p, 4096) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(munmap((void *)(p + 100 * 4096), 3 * 4096) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(mprotect((void *)p, BYTES, PROT_READ) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(mprotect((void *)(p + 4096), 4096, PROT_NONE) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(mmap((void *)p, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
               -1, 0) == MAP_FAILED);
    CHECK(errno == EINVAL);
    CHECK(dp_buffer() == (uint64_t)(uintptr_t)p);
    CHECK(p[0] == 0x5a && p[BYTES - 1] == 0xa5);
    return 0;
}

static int piece_checks(void) {
    int64_t at = dp_map(PAGES);
    CHECK(at > 0);
    volatile unsigned char *p = (volatile unsigned char *)(uintptr_t)at;
    for (unsigned long i = 0; i < BYTES; i += 4096) p[i] = (unsigned char)(i >> 12);
    p[0] = 0x5a;
    p[BYTES - 1] = 0xa5;
    CHECK(dp_buffer() == (uint64_t)at);
    CHECK(dp_map(PAGES) == -16); /* EBUSY: one piece for a process */
    printf("posix-display: the buffer is the display piece, one for a process\n");
    CHECK(refusals(p) == 0);
    printf("posix-display: munmap, mprotect and MAP_FIXED over the piece are EINVAL, the piece is as it was\n");

    int status = 0;
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(session_without_piece());
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("posix-display: a forked child has a session of its own that answers a CLONE, and no piece\n");

    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        volatile unsigned char c = *p;
        _exit(c == 0x5a ? 30 : 31);
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
    CHECK(p[0] == 0x5a && p[BYTES - 1] == 0xa5 && p[4096] == 1);
    printf("posix-display: the child's read at the parent's buffer is SIGSEGV, the parent's pieces are intact\n");

    CHECK(run("spawned", &status) == 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("posix-display: a spawned program has a session of its own\n");

    CHECK(run_file("/bin/posix-display-suid", "setid", &status) == 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("posix-display: a set-ID program gets no session\n");

    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (dp_map(PAGES) <= 0) _exit(40);
        char *argv[] = {"posix-display", "execd", NULL};
        execve("/bin/posix-display", argv, environ);
        _exit(41);
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("posix-display: exec takes the child's piece away and keeps its session\n");

    CHECK(dp_unmap() == 0);
    CHECK(dp_buffer() == 0);
    CHECK(dp_unmap() == 0);
    int64_t again = dp_map(PAGES);
    CHECK(again > 0);
    ((volatile unsigned char *)(uintptr_t)again)[0] = 1;
    CHECK(munmap((void *)(uintptr_t)again, 4096) == -1 && errno == EINVAL);
    CHECK(dp_unmap() == 0);
    printf("posix-display: the piece goes with its unmap, a second one can be mapped\n");
    return 0;
}

/* The mean ns the parent spends in fork() (the child's exit and the wait
 * are outside the time), over rounds * per forks; 0 for a failure. */
static uint64_t forks(int rounds, int per) {
    uint64_t total = 0;
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < per; i++) {
            uint64_t from = dp_ns();
            pid_t pid = fork();
            if (pid == 0) _exit(0);
            total += dp_ns() - from;
            if (pid < 0) return 0;
            int status = 0;
            if (waitpid(pid, &status, 0) != pid) return 0;
        }
    }
    return total / (uint64_t)(rounds * per);
}

/* The price of the session in a fork: forks with and without it, in
 * turns, mean ns of the call; and a CLONE alone. */
static int price(void) {
    uint64_t with = 0, without = 0;
    forks(1, 8);
    for (int turn = 0; turn < 4; turn++) {
        dp_hide(0);
        uint64_t a = forks(1, 25);
        dp_hide(1);
        uint64_t b = forks(1, 25);
        dp_hide(0);
        CHECK(a != 0 && b != 0);
        with += a;
        without += b;
    }
    with /= 4;
    without /= 4;
    CHECK(dp_session() == 1);
    uint64_t from = dp_ns();
    for (int i = 0; i < 100; i++) CHECK(dp_clone_ok() == 0);
    uint64_t clone = (dp_ns() - from) / 100;
    printf("posix-display: fork with the session %llu ns, without it %llu ns, a CLONE alone %llu ns\n",
           (unsigned long long)with, (unsigned long long)without, (unsigned long long)clone);
    return 0;
}

static int forker(void) {
    CHECK(dp_session() == 1 && dp_clone_ok() == 0);
    CHECK(piece_checks() == 0);
    CHECK(price() == 0);
    return 0;
}

static int first(void) {
    CHECK(dp_session() == 1);
    CHECK(dp_clone_ok() == 0);
    CHECK(dp_buffer() == 0);
    printf("posix-display: the start gave a session that answers a CLONE\n");
    int status = 0;
    CHECK(run("fork", &status) == 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

int main(int argc, char **argv) {
    int status;
    if (argc > 1 && strcmp(argv[1], "spawned") == 0) return session_without_piece();
    if (argc > 1 && strcmp(argv[1], "setid") == 0) return no_session();
    if (argc > 1 && strcmp(argv[1], "execd") == 0) return session_without_piece();
    status = argc > 1 && strcmp(argv[1], "fork") == 0 ? forker() : first();
    if (status == 0 && argc == 1) printf("posix-display: ok\n");
    return status;
}
