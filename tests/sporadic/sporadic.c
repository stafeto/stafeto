/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* SCHED_SPORADIC through relibc, the Rust POSIX layer, the process service
 * and init (plan 4b): the option macros, the parameters that are refused,
 * a thread under a sporadic server that reads back what it set, the share
 * of each CPU (none on CPU 0, a fifth of CPU 1, a half of CPUs 2 and 3)
 * that init admits and takes back at the end of a thread and of a process,
 * and the time a thread under a server leaves to the thread below it. */
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* The kernel that has the unbind and the atomic rebind (stafeto#358) lets a
 * thread change its parameters and leave the policy. */
#ifndef SS_REBIND
#define SS_REBIND 1
#endif

#define MS 1000000L
#define FAIL(...) do { printf("sporadic: " __VA_ARGS__); printf("\n"); exit(10 + __LINE__ % 80); } while (0)
#define CHECK(cond) do { if (!(cond)) FAIL("check failed at line %d: %s", __LINE__, #cond); } while (0)

static long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}
static void sleep_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) != 0 && errno == EINTR) {}
}
static long long thread_cpu_ns(void) {
    struct timespec t;
    CHECK(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t) == 0);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

static struct sched_param ss_param(int priority, int low, long c_ns, long t_ns, int repl) {
    struct sched_param p;
    memset(&p, 0, sizeof p);
    p.sched_priority = priority;
    p.sched_ss_low_priority = low;
    p.sched_ss_init_budget.tv_sec = c_ns / 1000000000L;
    p.sched_ss_init_budget.tv_nsec = c_ns % 1000000000L;
    p.sched_ss_repl_period.tv_sec = t_ns / 1000000000L;
    p.sched_ss_repl_period.tv_nsec = t_ns % 1000000000L;
    p.sched_ss_max_repl = repl;
    return p;
}

static int same(const struct sched_param *a, const struct sched_param *b) {
    return a->sched_priority == b->sched_priority && a->sched_ss_low_priority == b->sched_ss_low_priority
        && a->sched_ss_init_budget.tv_sec == b->sched_ss_init_budget.tv_sec
        && a->sched_ss_init_budget.tv_nsec == b->sched_ss_init_budget.tv_nsec
        && a->sched_ss_repl_period.tv_sec == b->sched_ss_repl_period.tv_sec
        && a->sched_ss_repl_period.tv_nsec == b->sched_ss_repl_period.tv_nsec
        && a->sched_ss_max_repl == b->sched_ss_max_repl;
}

/* The options of the policy. */
static void options(void) {
#if !(defined(_POSIX_SPORADIC_SERVER) && _POSIX_SPORADIC_SERVER > 0)
    FAIL("_POSIX_SPORADIC_SERVER is not claimed");
#endif
#if !(defined(_POSIX_THREAD_SPORADIC_SERVER) && _POSIX_THREAD_SPORADIC_SERVER > 0)
    FAIL("_POSIX_THREAD_SPORADIC_SERVER is not claimed");
#endif
    CHECK(sysconf(_SC_SPORADIC_SERVER) == _POSIX_SPORADIC_SERVER);
    CHECK(sysconf(_SC_THREAD_SPORADIC_SERVER) == _POSIX_THREAD_SPORADIC_SERVER);
    CHECK(SS_REPL_MAX == 4 && sysconf(_SC_SS_REPL_MAX) == 4 && _POSIX_SS_REPL_MAX == 4);
    CHECK(SCHED_SPORADIC == 4);
    CHECK(sched_get_priority_min(SCHED_SPORADIC) == 1 && sched_get_priority_max(SCHED_SPORADIC) == 32);
    CHECK(sizeof(struct sched_param) == 48);
    printf("sporadic: the options, SS_REPL_MAX and the priority range of SCHED_SPORADIC ok\n");
}

/* Parameters the layer refuses (EINVAL), and the policy that stays. */
static void *never(void *arg) {
    FAIL("a thread ran that pthread_create refused");
    return arg;
}
static void bad_parameters(void) {
    int policy = sched_getscheduler(0);
    struct sched_param good = ss_param(20, 5, 1 * MS, 10 * MS, 3);
    struct sched_param bad[12];
    int n = 0;
    bad[n] = good; bad[n++].sched_ss_low_priority = 20;     /* low is not below the base */
    bad[n] = good; bad[n++].sched_ss_low_priority = 0;
    bad[n] = good; bad[n++].sched_ss_max_repl = 0;
    bad[n] = good; bad[n++].sched_ss_max_repl = SS_REPL_MAX + 1;
    bad[n] = good; bad[n].sched_ss_init_budget.tv_sec = 2; bad[n++].sched_ss_repl_period.tv_sec = 1; /* C above T */
    bad[n] = good; bad[n++].sched_ss_repl_period.tv_nsec = 99999;     /* T under 100 us */
    bad[n] = good; bad[n++].sched_ss_init_budget.tv_nsec = 9999;      /* C under 10 us */
    bad[n] = good; bad[n++].sched_ss_repl_period.tv_nsec = 1000000000L; /* a time out of range */
    bad[n] = good; bad[n++].sched_priority = 0;
    bad[n] = good; bad[n++].sched_priority = 33;
    for (int i = 0; i < n; i++) {
        errno = 0;
        CHECK(sched_setscheduler(0, SCHED_SPORADIC, &bad[i]) == -1 && errno == EINVAL);
        CHECK(sched_getscheduler(0) == policy);
        CHECK(pthread_setschedparam(pthread_self(), SCHED_SPORADIC, &bad[i]) == EINVAL);
        CHECK(sched_getscheduler(0) == policy);
        pthread_attr_t attr;
        CHECK(pthread_attr_init(&attr) == 0);
        CHECK(pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) == 0);
        CHECK(pthread_attr_setschedpolicy(&attr, SCHED_SPORADIC) == 0);
        CHECK(pthread_attr_setschedparam(&attr, &bad[i]) == 0 || bad[i].sched_priority == 0 || bad[i].sched_priority == 33);
        pthread_t t;
        CHECK(pthread_create(&t, &attr, never, NULL) == EINVAL);
        CHECK(pthread_attr_destroy(&attr) == 0);
    }
    /* The members of the server have no effect on the other policies. */
    struct sched_param other = ss_param(0, 99, 1, 2, 77);
    if (policy == SCHED_OTHER) CHECK(sched_setparam(0, &other) == 0);
    printf("sporadic: %d parameters off the rules give EINVAL and leave the policy ok\n", n);
}

/* A thread that runs a function under a flag. */
static int cpus_up;
static volatile int rc;

static pthread_t make(void *(*body)(void *), void *arg, const pthread_attr_t *attr, int *err) {
    pthread_t t = 0;
    *err = pthread_create(&t, attr, body, arg);
    return t;
}
static void run(void *(*body)(void *), void *arg) {
    int err;
    pthread_t t = make(body, arg, NULL, &err);
    CHECK(err == 0);
    CHECK(pthread_join(t, NULL) == 0);
}

static int row_ns(int cpu, long period) { /* the share of the CPU for POSIX threads, in ns of `period` */
    return (int)(cpu == 1 ? period / 5 : cpu == 2 || cpu == 3 ? period / 2 : 0);
}

/* The thread sets itself under a server and reads the parameters back. */
static void *basic_thread(void *arg) {
    (void)arg;
    struct sched_param p = ss_param(20, 5, 1 * MS, 10 * MS, 3), got, got2;
    int old = sched_getscheduler(0);
    int set = sched_setscheduler(0, SCHED_SPORADIC, &p);
    if (set != old) FAIL("sched_setscheduler gave %d, errno %d (the old policy is %d, CPU %d)", set, errno, old, sched_getcpu());
    CHECK(sched_getscheduler(0) == SCHED_SPORADIC);
    CHECK(sched_getparam(0, &got) == 0 && same(&got, &p));
    int policy = -1;
    CHECK(pthread_getschedparam(pthread_self(), &policy, &got2) == 0);
    CHECK(policy == SCHED_SPORADIC && same(&got2, &p));
    /* The base priority changes with the parameters of the server kept. */
    CHECK(pthread_setschedprio(pthread_self(), 21) == 0);
    CHECK(sched_getparam(0, &got) == 0 && got.sched_priority == 21 && got.sched_ss_max_repl == 3);
    errno = 0;
    CHECK(pthread_setschedprio(pthread_self(), 5) == EINVAL); /* the base may not reach `low` */
#if SS_REBIND
    /* A change of the parameters moves the thread to a new budget at once. */
    struct sched_param q = ss_param(22, 6, 2 * MS, 20 * MS, 2);
    CHECK(sched_setparam(0, &q) == 0);
    CHECK(sched_getparam(0, &got) == 0 && same(&got, &q));
    /* Leaving the policy takes the budget off. */
    struct sched_param f = {.sched_priority = 22};
    CHECK(sched_setscheduler(0, SCHED_FIFO, &f) == SCHED_SPORADIC);
    CHECK(sched_getscheduler(0) == SCHED_FIFO);
#endif
    return NULL;
}

/* A request for more than the row (60 % of a CPU) is refused and changes nothing. */
static void *refused_thread(void *arg) {
    (void)arg;
    int old = sched_getscheduler(0);
    struct sched_param before, after, big = ss_param(20, 5, 6 * MS, 10 * MS, 4);
    CHECK(sched_getparam(0, &before) == 0);
    errno = 0;
    CHECK(sched_setscheduler(0, SCHED_SPORADIC, &big) == -1 && errno == EPERM);
    CHECK(sched_getscheduler(0) == old);
    CHECK(sched_getparam(0, &after) == 0 && same(&before, &after));
    CHECK(pthread_setschedparam(pthread_self(), SCHED_SPORADIC, &big) == EPERM);
    CHECK(sched_getscheduler(0) == old);
    return NULL;
}

/* A thread that holds the whole row until told to let it go. */
static volatile int hold_ready, hold_go;
static void *holder_thread(void *arg) {
    int cpu = (int)(long)arg;
    struct sched_param p = ss_param(20, 5, row_ns(cpu, 10 * MS), 10 * MS, 4);
    rc = 0;
    if (sched_setscheduler(0, SCHED_SPORADIC, &p) == -1) { rc = errno; hold_ready = -1; return NULL; }
    hold_ready = 1;
    while (!hold_go) sleep_ms(2);
    return NULL;
}

/* One percent of the CPU: a thread that asks it while the row is full. */
static void *small_thread(void *arg) {
    (void)arg;
    struct sched_param p = ss_param(20, 5, 100000, 10 * MS, 1);
    errno = 0;
    rc = sched_setscheduler(0, SCHED_SPORADIC, &p) == -1 ? errno : 0;
    return NULL;
}

/* The thread made with the server in its attributes starts under it. */
static volatile int attr_seen;
static struct sched_param attr_param;
static void *attr_thread(void *arg) {
    (void)arg;
    struct sched_param got;
    int policy = -1;
    CHECK(pthread_getschedparam(pthread_self(), &policy, &got) == 0);
    CHECK(policy == SCHED_SPORADIC && same(&got, &attr_param));
    CHECK(sched_getscheduler(0) == SCHED_SPORADIC);
    attr_seen = 1;
    return NULL;
}
static pthread_t make_ss(void *(*body)(void *), const struct sched_param *p, int *err) {
    pthread_attr_t attr;
    CHECK(pthread_attr_init(&attr) == 0);
    CHECK(pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) == 0);
    CHECK(pthread_attr_setschedpolicy(&attr, SCHED_SPORADIC) == 0);
    CHECK(pthread_attr_setschedparam(&attr, p) == 0);
    pthread_t t = make(body, NULL, &attr, err);
    CHECK(pthread_attr_destroy(&attr) == 0);
    return t;
}

/* The thread under a server spins; a thread below its base and above its
 * low priority gets what the server leaves. */
static volatile int stop;
static volatile long long spin_cpu[2];
static void *spin_thread(void *arg) {
    int slot = (int)(long)arg;
    while (!stop) {}
    spin_cpu[slot] = thread_cpu_ns();
    return NULL;
}
static void leaving_time(void) {
    struct sched_param p = ss_param(20, 5, 1 * MS, 10 * MS, 4);
    struct sched_param victim = {.sched_priority = 10};
    pthread_attr_t attr;
    int err;
    stop = 0;
    spin_cpu[0] = spin_cpu[1] = 0;
    pthread_t v;
    CHECK(pthread_attr_init(&attr) == 0);
    CHECK(pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) == 0);
    CHECK(pthread_attr_setschedpolicy(&attr, SCHED_FIFO) == 0);
    CHECK(pthread_attr_setschedparam(&attr, &victim) == 0);
    v = make(spin_thread, (void *)1L, &attr, &err);
    CHECK(err == 0);
    CHECK(pthread_attr_destroy(&attr) == 0);
    long long start = now_ns();
    pthread_attr_t sattr;
    CHECK(pthread_attr_init(&sattr) == 0);
    CHECK(pthread_attr_setinheritsched(&sattr, PTHREAD_EXPLICIT_SCHED) == 0);
    CHECK(pthread_attr_setschedpolicy(&sattr, SCHED_SPORADIC) == 0);
    CHECK(pthread_attr_setschedparam(&sattr, &p) == 0);
    pthread_t s = make(spin_thread, (void *)0L, &sattr, &err);
    CHECK(err == 0);
    CHECK(pthread_attr_destroy(&sattr) == 0);
    sleep_ms(400);
    stop = 1;
    CHECK(pthread_join(s, NULL) == 0);
    CHECK(pthread_join(v, NULL) == 0);
    long long wall = now_ns() - start;
    long ss_pm = (long)(spin_cpu[0] * 1000 / wall), victim_pm = (long)(spin_cpu[1] * 1000 / wall);
    printf("sporadic: spin wall=%lld us server=%ld per mille victim=%ld per mille\n", wall / 1000, ss_pm, victim_pm);
    /* C of T is 100 per mille; the thread at `low` runs when nothing above it
     * does, and the victim is above `low`. */
    CHECK(ss_pm >= 40 && ss_pm <= 200);
    CHECK(victim_pm >= 700);
}

/* Names what a hung join waits for: the thread's levels and kernel state. */
int sporadic_info(pthread_t thread, int *base, int *priority, int *state);
static pthread_t watched;
static volatile int watch_over;
static void *watchdog(void *arg) {
    (void)arg;
    sleep_ms(3000);
    if (watch_over) return NULL;
    int base = -1, priority = -1, state = -1;
    int e = sporadic_info(watched, &base, &priority, &state);
    printf("sporadic: WATCHDOG: the thread: %d, base %d, working at %d, state %d\n", e, base, priority, state);
    exit(77);
}
static void watch(pthread_t target) {
    watched = target;
    watch_over = 0;
    pthread_attr_t attr;
    struct sched_param p = {.sched_priority = 31};
    pthread_t w;
    CHECK(pthread_attr_init(&attr) == 0);
    CHECK(pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) == 0);
    CHECK(pthread_attr_setschedpolicy(&attr, SCHED_FIFO) == 0);
    CHECK(pthread_attr_setschedparam(&attr, &p) == 0);
    CHECK(pthread_create(&w, &attr, watchdog, NULL) == 0);
    CHECK(pthread_detach(w) == 0);
}

/* A thread that ends under its budget: with it untouched, with it spent, and
 * after it left the policy. */
static void *ending_thread(void *arg) {
    int v = (int)(long)arg;
    struct sched_param p = ss_param(20, 5, 1 * MS, 10 * MS, 4);
    CHECK(sched_setscheduler(0, SCHED_SPORADIC, &p) >= 0);
    if (v >= 1) {
        long long until = thread_cpu_ns() + 3 * MS;
        while (thread_cpu_ns() < until) {}
    }
#if SS_REBIND
    if (v == 2) {
        struct sched_param f = {.sched_priority = 20};
        CHECK(sched_setscheduler(0, SCHED_FIFO, &f) == SCHED_SPORADIC);
    }
#endif
    return NULL;
}
static void endings(int cpu) {
    static const int order[3] = {2, 0, 1};
    for (int i = 0; i < (SS_REBIND ? 3 : 2); i++) {
        int v = SS_REBIND ? order[i] : i;
        printf("sporadic: CPU %d: a thread ends, variant %d\n", cpu, v);
        int err;
        pthread_t t = make(ending_thread, (void *)(long)v, NULL, &err);
        CHECK(err == 0);
        if (v == 1) watch(t);
        CHECK(pthread_join(t, NULL) == 0);
        watch_over = 1;
        printf("sporadic: CPU %d: variant %d joined\n", cpu, v);
    }
}

/* A thread that leaves the policy gives its share back: another takes the whole row. */
static void *leaver_thread(void *arg) {
    int cpu = (int)(long)arg;
    struct sched_param p = ss_param(20, 5, row_ns(cpu, 10 * MS), 10 * MS, 4);
    CHECK(sched_setscheduler(0, SCHED_SPORADIC, &p) >= 0);
    struct sched_param f = {.sched_priority = 20};
    CHECK(sched_setscheduler(0, SCHED_FIFO, &f) == SCHED_SPORADIC);
    CHECK(sched_getscheduler(0) == SCHED_FIFO);
    /* Still running, off the policy: the row is free. */
    hold_ready = hold_go = 0;
    rc = 0;
    int err;
    pthread_t holder = make(holder_thread, (void *)(long)cpu, NULL, &err);
    CHECK(err == 0);
    while (hold_ready == 0) sleep_ms(2);
    CHECK(hold_ready == 1 && rc == 0);
    hold_go = 1;
    CHECK(pthread_join(holder, NULL) == 0);
    return NULL;
}
static void leaving(int cpu) {
    run(leaver_thread, (void *)(long)cpu);
    printf("sporadic: CPU %d: leaving the policy gave the share back ok\n", cpu);
}

/* fork by a thread under a server: the child gets a budget of its own from the
 * service before the call returns, a refused share is EAGAIN and no child. */
static int fork_cpu;
static void *forker_thread(void *arg) {
    int whole = (int)(long)arg; /* 1: the thread takes half the row, 0: a quarter */
    long c = row_ns(fork_cpu, 10 * MS) / (whole ? 2 : 4);
    struct sched_param p = ss_param(20, 5, c, 10 * MS, 4), got;
    CHECK(sched_setscheduler(0, SCHED_SPORADIC, &p) >= 0);
    pid_t child = fork();
    if (child < 0) FAIL("fork gave -1, errno %d (CPU %d, the thread holds %ld ns)", errno, sched_getcpu(), c);
    if (child == 0) {
        /* The child's main thread runs under the same server. */
        if (sched_getscheduler(0) != SCHED_SPORADIC) _exit(41);
        if (sched_getparam(0, &got) != 0 || !same(&got, &p)) _exit(42);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return NULL;
}
static void forks(int cpu) {
    fork_cpu = cpu;
    run(forker_thread, (void *)1L);
    run(forker_thread, (void *)0L);
    printf("sporadic: CPU %d: fork under a server gives the child its budget ok\n", cpu);
}

/* Everything on one CPU: threads made by a thread go where it runs. */
static void *scenario(void *arg) {
    int cpu = (int)(long)arg;
    CHECK(sched_getcpu() == cpu);
    /* Above everything the scenario makes, so that its waits end. */
    struct sched_param top = {.sched_priority = 30};
    CHECK(pthread_setschedparam(pthread_self(), SCHED_FIFO, &top) == 0);
    int err;
    if (cpu >= 1) {
        endings(cpu);
        run(basic_thread, NULL);
        run(refused_thread, NULL);
        /* A thread holds the whole row: a small request and the creation of
         * a thread under a server are refused, EPERM and EAGAIN. */
        hold_ready = hold_go = 0;
        pthread_t holder = make(holder_thread, (void *)(long)cpu, NULL, &err);
        CHECK(err == 0);
        while (hold_ready == 0) sleep_ms(2);
        CHECK(hold_ready == 1);
        rc = 0;
        run(small_thread, NULL);
        CHECK(rc == EPERM);
        struct sched_param p = ss_param(20, 5, 1 * MS, 10 * MS, 4);
        pthread_t refused = make_ss(attr_thread, &p, &err);
        (void)refused;
        CHECK(err == EAGAIN);
        hold_go = 1;
        CHECK(pthread_join(holder, NULL) == 0);
        /* The end of the holder gave the row back. */
        attr_seen = 0;
        attr_param = p;
        pthread_t made = make_ss(attr_thread, &p, &err);
        CHECK(err == 0);
        CHECK(pthread_join(made, NULL) == 0);
        CHECK(attr_seen == 1);
        /* ... and so did the end of a thread that was made under a server. */
        hold_ready = hold_go = 0;
        holder = make(holder_thread, (void *)(long)cpu, NULL, &err);
        CHECK(err == 0);
        while (hold_ready == 0) sleep_ms(2);
        CHECK(hold_ready == 1);
        hold_go = 1;
        CHECK(pthread_join(holder, NULL) == 0);
        leaving_time();
        forks(cpu);
#if SS_REBIND
        leaving(cpu);
#endif
    } else {
        /* CPU 0 has no share: no thread there runs under a server. */
        struct sched_param p = ss_param(20, 5, 1 * MS, 10 * MS, 4);
        errno = 0;
        CHECK(sched_setscheduler(0, SCHED_SPORADIC, &p) == -1 && errno == EPERM);
    }
    printf("sporadic: CPU %d: set, read back, refused over its share, given back at the end of a thread ok\n", cpu);
    return NULL;
}

static void on_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    CHECK(sched_setaffinity(0, sizeof set, &set) == 0);
    int err;
    pthread_t t = make(scenario, (void *)(long)cpu, NULL, &err);
    CHECK(err == 0);
    CHECK(pthread_join(t, NULL) == 0);
}

/* The end of a process gives back its threads' shares. */
static void process_end(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    CHECK(sched_setaffinity(0, sizeof set, &set) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        struct sched_param p = ss_param(20, 5, row_ns(cpu, 10 * MS), 10 * MS, 4);
        _exit(sched_setscheduler(0, SCHED_SPORADIC, &p) == -1 ? 40 + errno : 0);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status));
    if (WEXITSTATUS(status) != 0) FAIL("the child could not take the row of CPU %d: %d", cpu, WEXITSTATUS(status));
    int err = EPERM;
    for (int i = 0; i < 20 && err != 0; i++) {
        hold_ready = hold_go = 0;
        rc = 0;
        pthread_t holder = make(holder_thread, (void *)(long)cpu, NULL, &err);
        CHECK(err == 0);
        while (hold_ready == 0) sleep_ms(2);
        err = rc;
        hold_go = 1;
        CHECK(pthread_join(holder, NULL) == 0);
        if (err != 0) sleep_ms(50);
    }
    CHECK(err == 0);
    printf("sporadic: CPU %d: the end of a process gave its share back ok\n", cpu);
}

int main(void) {
    cpus_up = (int)sysconf(_SC_NPROCESSORS_ONLN);
    options();
    bad_parameters();
    if (cpus_up < 2) {
        /* One CPU, no share: no sporadic server. */
        struct sched_param p = ss_param(20, 5, 1 * MS, 10 * MS, 4);
        errno = 0;
        CHECK(sched_setscheduler(0, SCHED_SPORADIC, &p) == -1 && errno == EPERM);
        printf("sporadic: one CPU: no share, EPERM ok\n");
        printf("sporadic: ok\n");
        return 0;
    }
    on_cpu(0);
    for (int cpu = 1; cpu < cpus_up && cpu <= 3; cpu++) on_cpu(cpu);
    process_end(cpus_up > 2 ? 2 : 1);
    printf("sporadic: ok\n");
    return 0;
}
