/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#include <pthread.h>
#include <signal.h>
#include <time.h>
extern int files_pending_begin(int, int);
extern int files_pending_waiting(void);
extern int files_pending_finish(int, int);
extern int files_pending_ack(int, int);
extern int files_pending_dup(int, int, int);
extern void files_pending_end(void);
extern int files_pending_owner_status(void);
extern int files_pending_ended_clean(void);
struct pending_worker { int source, target, flags, result; int entered, done; };
static struct pending_worker *pending_signal_worker;
static int pending_signal_entered, pending_signal_result, pending_signal_duplicate;
static void pending_signal(int number) {
    (void)number;
    __atomic_store_n(&pending_signal_entered, 1, __ATOMIC_SEQ_CST);
    if (pending_signal_duplicate) {
        struct pending_worker *work = pending_signal_worker;
        int result = files_pending_dup(work->source, work->target, 0);
        __atomic_store_n(&pending_signal_result, result, __ATOMIC_SEQ_CST);
    }
}
static void pending_pause(void) {
    struct timespec delay = {0, 1000000};
    nanosleep(&delay, NULL);
}
static void *pending_duplicate(void *argument) {
    struct pending_worker *work = argument;
    __atomic_store_n(&work->entered, 1, __ATOMIC_SEQ_CST);
    work->result = files_pending_dup(work->source, work->target, work->flags);
    __atomic_store_n(&work->done, 1, __ATOMIC_SEQ_CST);
    return NULL;
}
static int check_pending_dup(void) {
    struct sigaction action = {0}, previous;
    action.sa_handler = pending_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, &previous)) return 20;
    for (int scenario = 0; scenario != 8; ++scenario) {
        int source = open("/etc/motd", O_RDONLY);
        if (source < 0) return 1;
        int other = scenario == 3 ? open("/etc/motd", O_RDONLY) : -1;
        if (scenario == 3 && other < 0) return 1;
        int target = files_pending_begin(source, scenario == 4);
        if (target < 0) return 2;
        struct pending_worker work = {.source = source, .target = target, .flags = scenario == 1};
        pending_signal_worker = &work;
        pending_signal_duplicate = scenario == 5;
        __atomic_store_n(&pending_signal_entered, 0, __ATOMIC_SEQ_CST);
        __atomic_store_n(&pending_signal_result, -1, __ATOMIC_SEQ_CST);
        pthread_t worker;
        if (pthread_create(&worker, NULL, pending_duplicate, &work)) return 3;
        int observed = 0;
        for (int retry = 0; retry < 500; ++retry) {
            if (__atomic_load_n(&work.done, __ATOMIC_SEQ_CST)) return 4;
            if (scenario == 4 ? __atomic_load_n(&work.entered, __ATOMIC_SEQ_CST) : files_pending_waiting() > 0) {
                observed = 1; break;
            }
            pending_pause();
        }
        if (!observed) return 5;
        int cancel = scenario == 7 ? 2 : scenario >= 2 && scenario <= 4;
        if (scenario == 2 && close(source)) return 6;
        if (scenario == 4) {
            for (int retry = 0; retry < 5; ++retry) {
                pending_pause();
                if (files_pending_waiting() > 0) return 16;
            }
            if (__atomic_load_n(&work.done, __ATOMIC_SEQ_CST)) return 7;
        }
        if (scenario == 5 || scenario == 6) {
            if (pthread_kill(worker, SIGUSR1)) return 21;
            int delivered = 0;
            for (int retry = 0; retry < 500; ++retry) {
                if (__atomic_load_n(&pending_signal_entered, __ATOMIC_SEQ_CST)) {
                    delivered = 1; break;
                }
                pending_pause();
            }
            if (!delivered || __atomic_load_n(&work.done, __ATOMIC_SEQ_CST)) return 22;
        }
        if (files_pending_finish(cancel, other)) return 8;
        if (scenario == 3 && close(other)) return 9;
        if (pthread_join(worker, NULL)) return 10;
        if (work.result != (scenario == 2 ? -EBADF : target)) return 11;
        if (scenario == 5 && __atomic_load_n(&pending_signal_result, __ATOMIC_SEQ_CST) != target)
            return 23;
        if (files_pending_ack(cancel, target)) return 12;
        if (scenario != 2) {
            char bytes[3];
            if (read(target, bytes, 3) != 3 || memcmp(bytes, "sta", 3)) return 13;
            if (scenario == 1 && !(fcntl(target, F_GETFD) & FD_CLOEXEC)) return 14;
            if (close(target) || close(source)) return 15;
        }
    }
    if (sigaction(SIGUSR1, &previous, NULL)) return 24;
    puts("posix-files: Pending dup2/dup3 publish cancel reuse MAX signal and unread Cancel ok");
    return 0;
}
struct pending_owner { int source, target, ready; };
static void *pending_end_owner(void *argument) {
    struct pending_owner *owner = argument;
    owner->target = files_pending_begin(owner->source, 0);
    __atomic_store_n(&owner->ready, 1, __ATOMIC_SEQ_CST);
    files_pending_end();
    return NULL;
}
static int check_pending_ended(void) {
    puts("posix-files: native Ended owner begin");
    int source = open("/etc/motd", O_RDONLY);
    if (source < 0) return 1;
    struct pending_owner owner = {.source = source, .target = -1};
    pthread_t native_owner;
    if (pthread_create(&native_owner, NULL, pending_end_owner, &owner)) return 2;
    int ready = 0;
    for (int retry = 0; retry < 500; ++retry) {
        if (__atomic_load_n(&owner.ready, __ATOMIC_SEQ_CST)) { ready = 1; break; }
        pending_pause();
    }
    if (!ready || owner.target < 0) return 3;
    puts("posix-files: native Ended owner reserved");
    int detached = 0;
    for (int retry = 0; retry < 500; ++retry) {
        if (files_pending_owner_status() == 2) { detached = 1; break; }
        pending_pause();
    }
    if (!detached) return 4;
    puts("posix-files: native Ended owner observed without detach");
    if (files_pending_dup(source, owner.target, 0) != owner.target) return 4;
    puts("posix-files: native Ended owner duplicate completed");
    if (files_pending_ended_clean()) return 5;
    char bytes[3];
    if (read(owner.target, bytes, 3) != 3 || memcmp(bytes, "sta", 3)) return 6;
    if (close(owner.target) || close(source)) return 7;
    /* The native Ended owner keeps its relibc allocation until process exit. */
    puts("posix-files: native Ended owner exact Pending cleanup with live sibling ok");
    return 0;
}
