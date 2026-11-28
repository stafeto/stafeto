/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The measurement of the layered root on a machine. A fresh process of the shell that the boot
 * script runs (/etc/rc.d/layer-time) once the layer service said READY (the image of `cargo xtask
 * aws image --layered`). It prints one line for each number and ends with "layer-time: done":
 *
 *   the first path of a fresh process: the stat of /etc binds the identity to the session the
 *   process has from its parent (BIND) and does the STAT; a process with no session takes the root
 *   (TakeRoot) and a session (SESSION) first. The line tells how many of each it made; the second
 *   stat is the steady cost
 *   the copy up of lower files of 1 KiB, 1 MiB and 16 MiB: the time of the open for writing, which
 *   returns when the copy is visible, and the MiB per second
 *   the open of the same files again, after the copy (the file of the layer)
 *   the open that truncates a lower file: an empty copy with the attributes of the lower file
 *   the answers STARTING this process had from the layer service
 *
 * The lower files are in the image (xtask rootfs, /usr/share/layer-time/).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

extern uint32_t lt_starting(void);
extern uint32_t lt_take_roots(void);
extern uint32_t lt_sessions(void);
extern uint32_t lt_binds(void);

#define DIR "/usr/share/layer-time/"
#define KIB (1024ULL)
#define MIB (1024ULL * 1024ULL)

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/* The microseconds an open for writing takes, with the flags; -1 when it fails. */
static int64_t open_us(const char *path, int flags) {
    uint64_t t0 = now_us();
    int fd = open(path, flags);
    uint64_t t1 = now_us();
    if (fd < 0) {
        printf("layer-time: open of %s failed, errno %d\n", path, errno);
        return -1;
    }
    close(fd);
    return (int64_t)(t1 - t0);
}

/* MiB per second times 100 for `bytes` in `us` (integers: the probe has no floating point output). */
static uint64_t mib_s_x100(uint64_t bytes, uint64_t us) {
    if (us == 0) {
        return 0;
    }
    return bytes * 100ULL * 1000000ULL / (MIB * us);
}

static int copy_up(const char *what, const char *name, uint64_t bytes) {
    char path[128];
    snprintf(path, sizeof path, "%s%s", DIR, name);
    int64_t us = open_us(path, O_WRONLY);
    if (us < 0) {
        return 1;
    }
    uint64_t rate = mib_s_x100(bytes, (uint64_t)us);
    printf("layer-time: copy up of %s: %lld us, %llu.%02llu MiB/s\n", what, (long long)us,
           (unsigned long long)(rate / 100), (unsigned long long)(rate % 100));
    int64_t again = open_us(path, O_WRONLY);
    if (again < 0) {
        return 1;
    }
    printf("layer-time: open of the copy of %s again: %lld us\n", what, (long long)again);
    return 0;
}

int main(void) {
    int failed = 0;
    /* A line at a time: the console shows each measurement when it is made. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct stat st;
    uint64_t t0 = now_us();
    int r = stat("/etc", &st);
    uint64_t t1 = now_us();
    if (r != 0) {
        printf("layer-time: stat of /etc failed, errno %d\n", errno);
        failed++;
    } else {
        /* The label of the line says what the first path does: the calls are counted, and a
         * line that names TakeRoot, SESSION and BIND needs one of each. */
        uint32_t roots = lt_take_roots(), sessions = lt_sessions(), binds = lt_binds();
        printf("layer-time: first path of a fresh process (TakeRoot %u, SESSION %u, BIND %u, STAT "
               "of /etc): %llu us\n",
               (unsigned)roots, (unsigned)sessions, (unsigned)binds,
               (unsigned long long)(t1 - t0));
        /* A child of the shell has its session with the layer service from the parent (a clone
         * made at the spawn): its first path is a BIND and the STAT. A process with no session
         * takes the root and a session first, one of each. Anything else is a label that is wrong. */
        if (binds != 1 || sessions != roots || roots > 1) {
            printf("layer-time: the first path made %u TakeRoot, %u SESSION, %u BIND calls: not "
                   "the BIND of a child and not the TakeRoot, SESSION, BIND of a process with no "
                   "session\n",
                   (unsigned)roots, (unsigned)sessions, (unsigned)binds);
            failed++;
        }
    }
    t0 = now_us();
    r = stat("/etc", &st);
    t1 = now_us();
    if (r == 0) {
        printf("layer-time: second path (STAT of /etc): %llu us\n", (unsigned long long)(t1 - t0));
    }
    failed += copy_up("1 KiB", "small", KIB);
    failed += copy_up("1 MiB", "medium", MIB);
    failed += copy_up("16 MiB", "big", 16 * MIB);
    char path[128];
    snprintf(path, sizeof path, "%s%s", DIR, "trunc");
    int64_t us = open_us(path, O_WRONLY | O_TRUNC);
    if (us < 0) {
        failed++;
    } else {
        printf("layer-time: copy of an open that truncates (empty copy of a file of 1 MiB): "
               "%lld us\n",
               (long long)us);
    }
    /* The layer service prints the counts of the answers STARTING by cause when they grow and a
     * request comes after half a second: wait, and ask once more. */
    struct timespec pause = {0, 700000000L};
    nanosleep(&pause, NULL);
    r = stat("/etc", &st);
    printf("layer-time: answers STARTING of the layer service to this process: %u\n",
           (unsigned)lt_starting());
    if (failed != 0) {
        printf("layer-time: %d measurements failed\n", failed);
    }
    printf("layer-time: done\n");
    return failed != 0;
}
