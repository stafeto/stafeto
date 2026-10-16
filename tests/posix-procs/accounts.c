/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* CPU time and the nice value (F13): a child that computes for 50 ms is
 * counted in its parent's RUSAGE_CHILDREN and times() once the parent waited
 * for it; the process and thread clocks run; the nice value is set, read and
 * inherited by a child. */
#include <sys/times.h>

static long long cpu_ns(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t) != 0) return -1;
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* The role: computes until its process has run 50 ms. */
static int burn50_role(void) {
    long long began = cpu_ns(CLOCK_PROCESS_CPUTIME_ID);
    while (cpu_ns(CLOCK_PROCESS_CPUTIME_ID) - began < 50000000LL) {}
    return 0;
}

/* The role: ends with its nice value + 20 as its status. */
static int nice_role(void) {
    errno = 0;
    int value = getpriority(PRIO_PROCESS, 0);
    if (errno) return 1;
    return value + 20;
}

static void accounts(void) {
    /* The clocks of the process and of the thread run with the work. */
    long long process_before = cpu_ns(CLOCK_PROCESS_CPUTIME_ID);
    long long thread_before = cpu_ns(CLOCK_THREAD_CPUTIME_ID);
    expect("the CPU-time clocks read", process_before >= 0 && thread_before >= 0, 1);
    long long wall = cpu_ns(CLOCK_MONOTONIC);
    while (cpu_ns(CLOCK_MONOTONIC) - wall < 20000000LL) {}
    long long process_after = cpu_ns(CLOCK_PROCESS_CPUTIME_ID);
    long long thread_after = cpu_ns(CLOCK_THREAD_CPUTIME_ID);
    expect("the process clock ran at least 15 ms in 20 ms of work",
           process_after - process_before >= 15000000LL, 1);
    expect("the thread clock ran at least 15 ms in 20 ms of work",
           thread_after - thread_before >= 15000000LL, 1);
    clockid_t own;
    expect("clock_getcpuclockid of the caller", clock_getcpuclockid(0, &own), 0);
    expect("its clock reads", cpu_ns(own) >= process_after, 1);
    clockid_t thread_clock;
    expect("pthread_getcpuclockid", pthread_getcpuclockid(pthread_self(), &thread_clock), 0);
    expect("the clock of the thread reads", cpu_ns(thread_clock) >= thread_after, 1);
    struct rusage self;
    expect("getrusage RUSAGE_SELF", getrusage(RUSAGE_SELF, &self), 0);
    expect("its user time covers the work", self.ru_utime.tv_sec * 1000000LL + self.ru_utime.tv_usec >= 20000, 1);

    /* A child that computes 50 ms is in the parent's children's time. */
    struct rusage none;
    expect("getrusage RUSAGE_CHILDREN before", getrusage(RUSAGE_CHILDREN, &none), 0);
    long long children_before = none.ru_utime.tv_sec * 1000000LL + none.ru_utime.tv_usec;
    struct tms before;
    times(&before);
    run_role("/bin/procs-child", "burn50", NULL);
    struct rusage children;
    expect("getrusage RUSAGE_CHILDREN after", getrusage(RUSAGE_CHILDREN, &children), 0);
    long long children_after = children.ru_utime.tv_sec * 1000000LL + children.ru_utime.tv_usec;
    if (children_after - children_before < 40000) {
        printf("posix-procs: accounts: the child ran 50 ms and the parent's children's time grew %lld us\n",
               children_after - children_before);
        failures++;
    }
    struct tms after;
    times(&after);
    expect("times() counts the child (cutime grew at least 4 ticks of 10 ms)",
           after.tms_cutime - before.tms_cutime >= 4, 1);

    /* The nice value: set, read, inherited, shown by /proc. */
    errno = 0;
    expect("nice of a fresh process is 0", getpriority(PRIO_PROCESS, 0), 0);
    expect("nice(5) answers 5", nice(5), 5);
    expect("getpriority reads 5", getpriority(PRIO_PROCESS, 0), 5);
    expect("setpriority of the group", setpriority(PRIO_PGRP, 0, 7), 0);
    expect("getpriority of the group reads 7", getpriority(PRIO_PGRP, 0), 7);
    expect("setpriority of this process", setpriority(PRIO_PROCESS, getpid(), 9), 0);
    expect("getpriority reads 9", getpriority(PRIO_PROCESS, 0), 9);
    /* A child inherits it (its exit status is the nice value + 20). */
    char *argv[] = {"procs-child", "nicechild", NULL};
    char *envp[] = {NULL};
    pid_t pid = -1;
    expect("spawn of the nice child", spawn_file(&pid, "/bin/procs-child", argv, envp, NULL), 0);
    if (pid > 0) reap("the nice child inherited the nice value 9", pid, 29, 0);
    errno = 0;
    expect("setpriority of a process that is none", setpriority(PRIO_PROCESS, 99999, 3) == -1 && errno == ESRCH, 1);
    printf("posix-procs: accounts ok\n");
}
