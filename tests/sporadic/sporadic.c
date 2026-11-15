/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* SCHED_SPORADIC in 0.5.0: the policy and its options exist for compilation
 * and no thread can take it. The option macros are 0 and sysconf says -1;
 * every call that would give a thread the policy is refused, for root and
 * for a user alike (EINVAL, ENOTSUP for the attribute object); the process
 * service refuses every operation of its budget method and gives a program
 * no handle of a budget, so nothing can be bound. The other policies and
 * their parameters go on as before. */
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* From the program's Rust side (src/main.rs): the budget method of the
 * process service, asked by hand. The status of the reply is the service's
 * (500 INVALID, 501 PERMISSION, 502 FULL), 0 for a reply with a body. */
unsigned sporadic_set(unsigned flags);
unsigned sporadic_query(unsigned *mask);
unsigned sporadic_work(void);

#define FAIL(...) do { printf("sporadic: " __VA_ARGS__); printf("\n"); exit(10 + __LINE__ % 80); } while (0)
#define CHECK(cond) do { if (!(cond)) FAIL("check failed at line %d: %s", __LINE__, #cond); } while (0)

extern char **environ;

static struct sched_param ss_param(int priority) {
    struct sched_param p;
    memset(&p, 0, sizeof p);
    p.sched_priority = priority;
    p.sched_ss_low_priority = 5;
    p.sched_ss_init_budget.tv_nsec = 1000000;
    p.sched_ss_repl_period.tv_nsec = 10000000;
    p.sched_ss_max_repl = 4;
    return p;
}

/* The options and the constants. */
static void options(void) {
#if !defined(_POSIX_SPORADIC_SERVER) || _POSIX_SPORADIC_SERVER != 0
    FAIL("_POSIX_SPORADIC_SERVER is not 0");
#endif
#if !defined(_POSIX_THREAD_SPORADIC_SERVER) || _POSIX_THREAD_SPORADIC_SERVER != 0
    FAIL("_POSIX_THREAD_SPORADIC_SERVER is not 0");
#endif
    errno = 0;
    CHECK(sysconf(_SC_SPORADIC_SERVER) == -1 && errno == 0);
    CHECK(sysconf(_SC_THREAD_SPORADIC_SERVER) == -1 && errno == 0);
    CHECK(SS_REPL_MAX == 4 && sysconf(_SC_SS_REPL_MAX) == 4);
    CHECK(SCHED_SPORADIC == 4);
    CHECK(sched_get_priority_min(SCHED_SPORADIC) == 1 && sched_get_priority_max(SCHED_SPORADIC) == 32);
    CHECK(sizeof(struct sched_param) == 48);
    unsigned mask = 99;
    CHECK(sporadic_query(&mask) == 0 && mask == 0);
    printf("sporadic: the options, SS_REPL_MAX and the range of SCHED_SPORADIC ok\n");
}

static void *refusing_thread(void *arg) {
    struct sched_param p = ss_param(20);
    int policy = sched_getscheduler(0);
    errno = 0;
    CHECK(sched_setscheduler(0, SCHED_SPORADIC, &p) == -1 && errno == EINVAL);
    CHECK(sched_getscheduler(0) == policy);
    return arg;
}

/* Every call that would give a thread the policy, and the service's answers. */
static void refusals(const char *who) {
    int policy = sched_getscheduler(0);
    struct sched_param p = ss_param(20), got;
    int seen;
    errno = 0;
    CHECK(sched_setscheduler(0, SCHED_SPORADIC, &p) == -1 && errno == EINVAL);
    CHECK(sched_getscheduler(0) == policy);
    CHECK(sched_getscheduler(getpid()) == policy);
    CHECK(pthread_setschedparam(pthread_self(), SCHED_SPORADIC, &p) == EINVAL);
    CHECK(pthread_getschedparam(pthread_self(), &seen, &got) == 0 && seen == policy);
    /* The members of the server have no effect on the other policies. */
    pthread_t t;
    CHECK(pthread_create(&t, NULL, refusing_thread, NULL) == 0);
    CHECK(pthread_join(t, NULL) == 0);
    /* The attribute object refuses the policy (ENOTSUP), so no thread is made with it. */
    pthread_attr_t attr;
    CHECK(pthread_attr_init(&attr) == 0);
    CHECK(pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) == 0);
    CHECK(pthread_attr_setschedpolicy(&attr, SCHED_SPORADIC) == ENOTSUP);
    CHECK(pthread_attr_getschedpolicy(&attr, &seen) == 0 && seen != SCHED_SPORADIC);
    CHECK(pthread_attr_destroy(&attr) == 0);
    /* posix_spawn with the policy: EINVAL, and no child. */
    posix_spawnattr_t spawn;
    CHECK(posix_spawnattr_init(&spawn) == 0);
    CHECK(posix_spawnattr_setflags(&spawn, POSIX_SPAWN_SETSCHEDULER) == 0);
    CHECK(posix_spawnattr_setschedpolicy(&spawn, SCHED_SPORADIC) == 0);
    CHECK(posix_spawnattr_setschedparam(&spawn, &p) == 0);
    char *argv[] = {"procs-child", "checked", NULL};
    pid_t pid = -1;
    CHECK(posix_spawn(&pid, "/bin/procs-child", NULL, &spawn, argv, environ) == EINVAL);
    CHECK(posix_spawnattr_destroy(&spawn) == 0);
    /* The service: every operation is refused, a handle of the thread goes
     * with the request and no handle comes back. */
    CHECK(sporadic_set(0) == 502);
    CHECK(sporadic_set(1) == 500);
    CHECK(sporadic_work() == 501);
    CHECK(sched_getscheduler(0) == policy);
    printf("sporadic: %s: every call that would give the policy is refused ok\n", who);
}

/* The other policies and their parameters round trip as before. */
static void round_trip(void) {
    struct sched_param p = {.sched_priority = 20}, got;
    int seen;
    CHECK(sched_setscheduler(0, SCHED_FIFO, &p) >= 0);
    memset(&got, 0xff, sizeof got);
    CHECK(sched_getparam(0, &got) == 0 && got.sched_priority == 20);
    CHECK(got.sched_ss_low_priority == 0 && got.sched_ss_max_repl == 0);
    CHECK(got.sched_ss_init_budget.tv_sec == 0 && got.sched_ss_init_budget.tv_nsec == 0);
    CHECK(got.sched_ss_repl_period.tv_sec == 0 && got.sched_ss_repl_period.tv_nsec == 0);
    memset(&got, 0xff, sizeof got);
    CHECK(pthread_getschedparam(pthread_self(), &seen, &got) == 0 && seen == SCHED_FIFO && got.sched_priority == 20);
    CHECK(got.sched_ss_max_repl == 0);
    p.sched_priority = 21;
    CHECK(sched_setparam(0, &p) == 0);
    CHECK(sched_getparam(0, &got) == 0 && got.sched_priority == 21);
    CHECK(pthread_setschedprio(pthread_self(), 22) == 0);
    CHECK(sched_getparam(0, &got) == 0 && got.sched_priority == 22);
    printf("sporadic: no thread has a budget: the other policies and their parameters round trip ok\n");
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "checked") == 0) return 0;
    if (argc > 1 && strcmp(argv[1], "user") == 0) {
        /* A user, not root: the refusal is the same (EINVAL), not a refusal of privilege. */
        if (setuid(1000) != 0 || geteuid() != 1000) return 51;
        refusals("user");
        return 0;
    }
    options();
    refusals("root");
    round_trip();
    char *child_argv[] = {"procs-child", "user", NULL};
    pid_t pid;
    int e = posix_spawn(&pid, "/bin/procs-child", NULL, NULL, child_argv, environ);
    if (e != 0) FAIL("the spawn of the probe's child gave %d", e);
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) FAIL("the user child ended with status %#x", status);
    printf("sporadic: ok\n");
    return 0;
}
