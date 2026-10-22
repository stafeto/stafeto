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

/* The role: computes until its process has run 50 ms, nearly all of it in
 * EL0 (#413): a loop of arithmetic with no call, and a look at the clock of
 * the process between rounds of it, a call each 100 000 turns. */
static int burn50_role(void) {
    long long began = cpu_ns(CLOCK_PROCESS_CPUTIME_ID);
    volatile unsigned long sink = 1;
    while (cpu_ns(CLOCK_PROCESS_CPUTIME_ID) - began < 50000000LL) {
        for (int i = 0; i < 100000; i++) sink = sink * 2862933555777941757UL + 3037000493UL;
    }
    return sink == 0;
}

/* The role: ends with its nice value + 20 as its status. */
static int nice_role(void) {
    errno = 0;
    int value = getpriority(PRIO_PROCESS, 0);
    if (errno) return 1;
    return value + 20;
}

/* The role: ends with its scheduling as its status, policy * 64 + priority. */
static int sched_role(void) {
    struct sched_param param;
    if (sched_getparam(0, &param) != 0) return 1;
    int policy = sched_getscheduler(0);
    if (policy < 0) return 2;
    printf("posix-procs: schedchild policy %d priority %d\n", policy, param.sched_priority);
    return policy * 64 + param.sched_priority;
}

/* posix_spawn with the scheduling attributes: the child starts with the
 * policy and priority they name (SETSCHEDULER; SETSCHEDPARAM keeps the
 * caller's policy), and inherits the caller's without them. */
static void spawned_scheduling(void) {
    char *argv[] = {"procs-child", "schedchild", NULL};
    char *envp[] = {NULL};
    struct sched_param param = {7};
    posix_spawnattr_t attr;
    pid_t pid = -1;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSCHEDULER);
    posix_spawnattr_setschedpolicy(&attr, SCHED_FIFO);
    posix_spawnattr_setschedparam(&attr, &param);
    expect("spawn with SETSCHEDULER", spawn_file(&pid, "/bin/procs-child", argv, envp, &attr), 0);
    if (pid > 0) reap("the child is SCHED_FIFO at 7", pid, 1 * 64 + 7, 0);
    /* A priority out of range is EINVAL, before anything is made. */
    param.sched_priority = 33;
    posix_spawnattr_setschedparam(&attr, &param);
    expect("SETSCHEDULER with priority 33", spawn_file(&pid, "/bin/procs-child", argv, envp, &attr), EINVAL);
    posix_spawnattr_destroy(&attr);
    /* The caller's own scheduling goes to a child without attributes, and
     * SETSCHEDPARAM changes only the priority. */
    param.sched_priority = 20;
    int moved = sched_setscheduler(0, SCHED_RR, &param);
    if (moved < 0) printf("posix-procs: sched_setscheduler gave errno %d, uid %d euid %d\n", errno, (int)getuid(), (int)geteuid());
    expect("the caller to SCHED_RR 20", moved >= 0, 1);
    pid = -1;
    expect("spawn without attributes", spawn_file(&pid, "/bin/procs-child", argv, envp, NULL), 0);
    if (pid > 0) reap("the child inherits SCHED_RR at 20", pid, 2 * 64 + 20, 0);
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSCHEDPARAM);
    param.sched_priority = 9;
    posix_spawnattr_setschedparam(&attr, &param);
    pid = -1;
    expect("spawn with SETSCHEDPARAM", spawn_file(&pid, "/bin/procs-child", argv, envp, &attr), 0);
    if (pid > 0) reap("the child is SCHED_RR at 9", pid, 2 * 64 + 9, 0);
    posix_spawnattr_destroy(&attr);
    param.sched_priority = 0;
    expect("the caller back to SCHED_OTHER", sched_setscheduler(0, SCHED_OTHER, &param) >= 0, 1);
}

/* clock() is the processor time of the process, as times() and
 * CLOCK_PROCESS_CPUTIME_ID give it: a process that slept 40 ms has not run
 * them. */
static void clock_is_cpu_time(void) {
    struct timespec nap = {0, 40000000};
    nanosleep(&nap, NULL);
    long long cpu = cpu_ns(CLOCK_PROCESS_CPUTIME_ID);
    clock_t c = clock();
    long long since = (long long)c * (1000000000LL / CLOCKS_PER_SEC);
    expect("clock() agrees with the process CPU clock (within 15 ms)",
           since - cpu < 15000000LL && cpu - since < 15000000LL, 1);
    if (!(since - cpu < 15000000LL)) printf("posix-procs: clock() %lld ns, CPU clock %lld ns\n", since, cpu);
}

/* The same as a user without privilege: a rise to a real-time policy by
 * posix_spawn is EPERM and nothing is made. */
static void spawned_scheduling_refused(void) {
    char *argv[] = {"procs-child", "schedchild", NULL};
    char *envp[] = {NULL};
    struct sched_param param = {7};
    posix_spawnattr_t attr;
    pid_t pid = -1;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSCHEDULER);
    posix_spawnattr_setschedpolicy(&attr, SCHED_FIFO);
    posix_spawnattr_setschedparam(&attr, &param);
    expect("spawn with SETSCHEDULER without privilege", spawn_file(&pid, "/bin/procs-child", argv, envp, &attr), EPERM);
    posix_spawnattr_destroy(&attr);
}

static void accounts(void) {
    clock_is_cpu_time();
    spawned_scheduling_refused();
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
    long long children_before = none.ru_utime.tv_sec * 1000000LL + none.ru_utime.tv_usec
                                + none.ru_stime.tv_sec * 1000000LL + none.ru_stime.tv_usec;
    struct tms before;
    times(&before);
    run_role("/bin/procs-child", "burn50", NULL);
    struct rusage children;
    expect("getrusage RUSAGE_CHILDREN after", getrusage(RUSAGE_CHILDREN, &children), 0);
    long long children_after = children.ru_utime.tv_sec * 1000000LL + children.ru_utime.tv_usec
                               + children.ru_stime.tv_sec * 1000000LL + children.ru_stime.tv_usec;
    long long children_user = (children.ru_utime.tv_sec - none.ru_utime.tv_sec) * 1000000LL
                              + children.ru_utime.tv_usec - none.ru_utime.tv_usec;
    if (children_after - children_before < 40000 || children_user < 40000) {
        printf("posix-procs: accounts: the child ran 50 ms and the parent's children's time grew %lld us, "
               "%lld us of it user time\n",
               children_after - children_before, children_user);
        failures++;
    }
    struct tms after;
    times(&after);
    /* The child ran in EL0: its user time alone is the 50 ms, and its
     * system time is less. */
    long user = (long)(after.tms_cutime - before.tms_cutime);
    long system = (long)(after.tms_cstime - before.tms_cstime);
    if (user < 4 || system >= user)
        printf("posix-procs: accounts: the child ran 50 ms in EL0: cutime grew %ld ticks of 10 ms, cstime %ld\n",
               user, system);
    expect("times() counts the child's user time (cutime grew at least 4 ticks of 10 ms)", user >= 4, 1);
    expect("times() counts the child's system time apart (cstime grew less than cutime)", system < user, 1);

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
