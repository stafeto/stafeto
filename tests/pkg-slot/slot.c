/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The probe of the package service's place in a process (sub-project 5, part 3b). Built with
 * -fno-builtin; every result is compared.
 *
 * Started by init with a session from its record: the session answers a LIST and a CLONE. Then
 * it starts itself from its file (/bin/pkg-slot fork), the copy that can fork. That role checks:
 * a forked child has a session of its own (a CLONE the parent made) that answers a LIST, and
 * when the child has ended the parent's session still answers (a child that kept the parent's
 * session would close it); a spawned program has a session; the program a forked child execs
 * keeps it, and the parent's session lives after that child ends; a set-ID program, which the
 * loader starts with a real ID other than the effective one, has none, whatever its caller put in
 * the place; a process that is not the superuser is refused INSTALL_BEGIN with NOT_ALLOWED
 * (1201) and the superuser is not. At the end the price of the session in a fork is measured: the
 * time of fork() with and without it, in turns.
 */

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
extern int ps_session(void);
extern int ps_list(void);
extern int ps_begin(void);
extern int ps_clone_ok(void);
extern void ps_hide(int hide);
extern uint64_t ps_ns(void);

#define NOT_ALLOWED 1201

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            printf("pkg-slot: check failed at line %d: %s (errno %d)\n", __LINE__,   \
                   #cond, errno);                                                    \
            return 20;                                                               \
        }                                                                            \
    } while (0)

static int run_file(const char *path, const char *role, int *status) {
    char *argv[] = {"pkg-slot", (char *)role, NULL};
    pid_t pid = 0;
    if (posix_spawn(&pid, path, NULL, NULL, argv, environ) != 0) return -1;
    if (waitpid(pid, status, 0) != pid) return -1;
    return 0;
}

static int run(const char *role, int *status) {
    return run_file("/bin/pkg-slot", role, status);
}

/* A set-ID program has no session, whatever its caller put in the place. */
static int no_session(void) {
    CHECK(ps_session() == 0);
    CHECK(ps_clone_ok() != 0);
    CHECK(ps_list() != 0);
    return 0;
}

/* The checks of a process that has a session of its own. */
static int has_session(void) {
    CHECK(ps_session() == 1);
    CHECK(ps_list() == 0);
    CHECK(ps_clone_ok() == 0);
    return 0;
}

static int checks(void) {
    int status = 0;
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) _exit(has_session());
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    /* The child ended: its session is closed, and the parent's goes on. */
    CHECK(ps_list() == 0);
    printf("pkg-slot: a forked child has a session of its own that answers, the parent's answers after the child ended\n");

    CHECK(run("spawned", &status) == 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(ps_list() == 0);
    printf("pkg-slot: a spawned program has a session of its own\n");

    CHECK(run_file("/bin/pkg-slot-suid", "setid", &status) == 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(ps_list() == 0);
    printf("pkg-slot: a set-ID program gets no session\n");

    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        char *argv[] = {"pkg-slot", "execd", NULL};
        execve("/bin/pkg-slot", argv, environ);
        _exit(41);
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(ps_list() == 0);
    printf("pkg-slot: exec keeps the session, and the parent's answers after the program ended\n");

    /* The superuser's INSTALL_BEGIN is taken; the same process as user 1000 is refused. */
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (ps_begin() != 0) _exit(50);
        if (setuid(1000) != 0) _exit(51);
        if (ps_begin() != NOT_ALLOWED) _exit(52);
        if (ps_list() != 0) _exit(53); /* a read is open to everyone */
        _exit(0);
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("pkg-slot: INSTALL_BEGIN is NOT_ALLOWED for a process that is not the superuser, and taken from the superuser\n");
    return 0;
}

/* The mean ns the parent spends in fork() (the child's exit and the wait are outside the time),
 * over rounds * per forks; 0 for a failure. */
static uint64_t forks(int rounds, int per) {
    uint64_t total = 0;
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < per; i++) {
            uint64_t from = ps_ns();
            pid_t pid = fork();
            if (pid == 0) _exit(0);
            total += ps_ns() - from;
            if (pid < 0) return 0;
            int status = 0;
            if (waitpid(pid, &status, 0) != pid) return 0;
        }
    }
    return total / (uint64_t)(rounds * per);
}

/* The price of the session in a fork: forks with and without it, in turns, mean ns of the call;
 * and a CLONE alone. */
static int price(void) {
    uint64_t with = 0, without = 0;
    forks(1, 8);
    for (int turn = 0; turn < 4; turn++) {
        ps_hide(0);
        uint64_t a = forks(1, 25);
        ps_hide(1);
        uint64_t b = forks(1, 25);
        ps_hide(0);
        CHECK(a != 0 && b != 0);
        with += a;
        without += b;
    }
    with /= 4;
    without /= 4;
    CHECK(ps_session() == 1);
    uint64_t from = ps_ns();
    for (int i = 0; i < 100; i++) CHECK(ps_clone_ok() == 0);
    uint64_t clone = (ps_ns() - from) / 100;
    printf("pkg-slot: fork with the session %llu ns, without it %llu ns, a CLONE alone %llu ns\n",
           (unsigned long long)with, (unsigned long long)without, (unsigned long long)clone);
    return 0;
}

static int forker(void) {
    CHECK(has_session() == 0);
    CHECK(checks() == 0);
    CHECK(price() == 0);
    return 0;
}

static int first(void) {
    CHECK(has_session() == 0);
    printf("pkg-slot: the start gave a session that answers a LIST and a CLONE\n");
    int status = 0;
    CHECK(run("fork", &status) == 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

int main(int argc, char **argv) {
    int status;
    if (argc > 1 && strcmp(argv[1], "spawned") == 0) return has_session();
    if (argc > 1 && strcmp(argv[1], "setid") == 0) return no_session();
    if (argc > 1 && strcmp(argv[1], "execd") == 0) return has_session();
    status = argc > 1 && strcmp(argv[1], "fork") == 0 ? forker() : first();
    if (status == 0 && argc == 1) printf("pkg-slot: ok\n");
    return status;
}
