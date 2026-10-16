/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* Locks on as many inodes as the processes of the image can hold, 63 records
 * on each. The file service sweeps its lock table for records of dead owners;
 * the circle over such inodes takes much of a period of its wait timer, and
 * the service must still leave the processor to the clients below its
 * priority. Children hold the locks, since a process has few descriptors; a
 * one-millisecond sleep of the parent has to end within 20 ms while the
 * sweep runs, and again after the children die. */
#include <sys/statvfs.h>

enum { SS_FILES = 24, SS_RECORDS = 63, SS_MAX_CHILDREN = 64, SS_KEEP_FREE = 24, SS_SLEEPS = 24,
       SS_MIN_CHILDREN = 6 };
#define SS_LIMIT_NS 20000000LL

static long long ss_now(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (long long)now.tv_sec * 1000000000LL + now.tv_nsec;
}
static void ss_path(char *path, size_t size, unsigned child, unsigned file) {
    snprintf(path, size, "/tmp/sweep-%u-%u", child, file);
}
/* The longest of SS_SLEEPS sleeps of one millisecond, in nanoseconds; spread
 * over about 300 ms of the machine's time so that one full period of the
 * service's timer is covered. */
static long long ss_worst_sleep(void) {
    long long worst = 0;
    for (unsigned i = 0; i < SS_SLEEPS; i++) {
        long long start = ss_now();
        const struct timespec delay = {0, 1000000};
        if (start < 0 || nanosleep(&delay, NULL)) return -1;
        long long end = ss_now();
        if (end < 0) return -1;
        if (end - start > worst) worst = end - start;
        const struct timespec gap = {0, 12000000};
        nanosleep(&gap, NULL);
    }
    return worst;
}
static void ss_child(unsigned index, int ready, unsigned files) {
    unsigned made = 0;
    for (; made < files; made++) {
        char path[48];
        ss_path(path, sizeof path, index, made);
        int fd = open(path, O_CREAT | O_RDWR | O_EXCL, 0666);
        if (fd < 0) break;
        for (unsigned record = 0; record < SS_RECORDS; record++) {
            struct flock lock = {0};
            lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
            lock.l_start = 2 * record; lock.l_len = 1;
            if (fcntl(fd, F_SETLK, &lock)) _exit(71);
        }
    }
    if (write(ready, &made, sizeof made) != sizeof made) _exit(72);
    for (;;) pause();
}
#define SS_FAIL() do { \
    printf("posix-procs: lock sweep share failed line=%d errno=%d\n", __LINE__, errno); \
    failed = 1; } while (0)
static int public_lock_sweep_share(void) {
    struct statvfs usage;
    int failed = 0;
    if (statvfs("/tmp", &usage) || usage.f_ffree <= SS_KEEP_FREE) {
        SS_FAIL();
        return failed;
    }
    unsigned long wanted = usage.f_ffree - SS_KEEP_FREE;
    unsigned count = (unsigned)((wanted + SS_FILES - 1) / SS_FILES);
    if (count > SS_MAX_CHILDREN) count = SS_MAX_CHILDREN;
    pid_t pids[SS_MAX_CHILDREN];
    unsigned started = 0, locked = 0;
    for (unsigned i = 0; i < count; i++) pids[i] = -1;
    for (unsigned i = 0; i < count && !failed; i++) {
        unsigned files = wanted - (unsigned long)i * SS_FILES < SS_FILES
                             ? (unsigned)(wanted - (unsigned long)i * SS_FILES) : SS_FILES;
        int ready[2];
        if (pipe(ready)) { SS_FAIL(); break; }
        pids[i] = fork();
        if (pids[i] < 0) {
            /* The image has room for so many processes and no more. */
            close(ready[0]); close(ready[1]);
            if (started < SS_MIN_CHILDREN) SS_FAIL();
            break;
        }
        if (pids[i] == 0) {
            close(ready[0]);
            ss_child(i, ready[1], files);
        }
        close(ready[1]);
        unsigned made = 0;
        ssize_t got = read(ready[0], &made, sizeof made);
        close(ready[0]);
        if (got != sizeof made) { SS_FAIL(); break; }
        locked += made;
        started++;
    }
    if (!failed) {
        long long busy = ss_worst_sleep();
        printf("posix-procs: lock sweep share: %u inodes locked by %u children, worst 1 ms sleep %lld us\n",
               locked, started, busy < 0 ? -1 : busy / 1000);
        if (busy < 0 || busy > SS_LIMIT_NS) SS_FAIL();
    }
    for (unsigned i = 0; i < count; i++) {
        if (pids[i] > 0) {
            kill(pids[i], SIGKILL);
            int status;
            waitpid(pids[i], &status, 0);
        }
    }
    if (!failed) {
        /* The sweep reclaims every dead record under the same load. */
        long long busy = ss_worst_sleep();
        if (busy < 0 || busy > SS_LIMIT_NS) SS_FAIL();
    }
    for (unsigned i = 0; i < started; i++) {
        for (unsigned j = 0; j < SS_FILES; j++) {
            char path[48];
            ss_path(path, sizeof path, i, j);
            unlink(path);
        }
    }
    if (!failed)
        puts("posix-procs: lock sweep share: clients below the service keep their time through the sweep of locked inodes");
    return failed;
}
