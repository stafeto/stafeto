/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <limits.h>
#include <spawn.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
extern int stafeto_sync(void);
extern int sync_full_io(int, int);
static int failures;
static void check(const char *what, int good) {
    if (!good) { printf("posix-sync: %s failed (errno %d)\n", what, errno); failures++; }
}
static void both_ok(const char *what, int fd) {
    check(what, fsync(fd) == 0 && fdatasync(fd) == 0);
}
static void both_error(const char *what, int fd, int error) {
    errno = 0; int a = fsync(fd), ae = errno;
    errno = 0; int b = fdatasync(fd), be = errno;
    check(what, a == -1 && ae == error && b == -1 && be == error);
}
static int await(const unsigned *cell) {
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 1;
    while (!__atomic_load_n(cell, __ATOMIC_ACQUIRE)) {
        sched_yield();
        if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec - start.tv_sec >= 3) return 1;
    }
    return 0;
}

struct full_pool { int file, directory, result; };
int sync_at_full_pool(int file, int directory) {
    /* Both RAM targets have no loan. An ordinary hold would need slot33. */
    if (fsync(file) || fdatasync(file) || fsync(directory) || fdatasync(directory)) return -errno;
    return stafeto_sync();
}
static void *full_pool_worker(void *argument) {
    struct full_pool *work = argument;
    work->result = sync_full_io(work->file, work->directory);
    return NULL;
}
static void full_io_pool(int file, int directory) {
    struct full_pool work = {.file = file, .directory = directory};
    pthread_attr_t attr;
    check("loan attributes", pthread_attr_init(&attr) == 0);
    check("loan stack", pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN) == 0);
    pthread_t worker;
    int failed = pthread_create(&worker, &attr, full_pool_worker, &work);
    pthread_attr_destroy(&attr);
    if (!failed) failed = pthread_join(worker, NULL) || work.result;
    if (failed) printf("posix-sync: full I/O pool returned %d\n", work.result);
    check("full ordinary I/O pool leaves synchronization available", !failed);
    if (!failed) puts("posix-sync: 32 held I/O loans preserve sync success");
}

struct cancellation { int fd, data; unsigned ready, gate, after, cleaned; };
static void cleaned(void *argument) {
    struct cancellation *state = argument;
    __atomic_store_n(&state->cleaned, 1, __ATOMIC_RELEASE);
}
static void *cancel_worker(void *argument) {
    struct cancellation *state = argument;
    pthread_cleanup_push(cleaned, state);
    __atomic_store_n(&state->ready, 1, __ATOMIC_RELEASE);
    /* sched_yield is not a cancellation point: the request stays pending. */
    while (!__atomic_load_n(&state->gate, __ATOMIC_ACQUIRE)) sched_yield();
    if (state->data) fdatasync(state->fd); else fsync(state->fd);
    __atomic_store_n(&state->after, 1, __ATOMIC_RELEASE);
    pthread_cleanup_pop(0);
    return NULL;
}
static void cancellations(int file) {
    int failed = 0;
    pthread_attr_t attr;
    check("cancel attributes", pthread_attr_init(&attr) == 0);
    check("cancel small stacks", pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN) == 0);
    for (int data = 0; data < 2; data++) {
        struct cancellation state = {.fd = file, .data = data};
        pthread_t worker;
        if (pthread_create(&worker, &attr, cancel_worker, &state)) { failed = 1; break; }
        if (await(&state.ready) || pthread_cancel(worker)) failed = 1;
        __atomic_store_n(&state.gate, 1, __ATOMIC_RELEASE);
        void *result = NULL;
        if (pthread_join(worker, &result) || result != PTHREAD_CANCELED
            || state.after || state.cleaned != 1) failed = 1;
        both_ok("descriptor table remains usable after cancelled synchronization", file);
    }
    pthread_attr_destroy(&attr);
    check("fsync and fdatasync consume pending deferred cancellation", !failed);
    if (!failed) puts("posix-sync: deferred cancellation points ok");
}

int main(int argc, char **argv) {
    if (argc == 1) {
        char *args[] = {"posix-procs", "run", NULL};
        pid_t child;
        int error = posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, environ);
        if (error) { printf("posix-sync: launcher failed %d\n", error); return 1; }
        int status = 0;
        return waitpid(child, &status, 0) == child && WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
    if (argc == 4 && strcmp(argv[1], "after-exec") == 0) {
        int file = atoi(argv[2]), directory = atoi(argv[3]);
        return fsync(file) || fdatasync(file) || fsync(directory) || fdatasync(directory) ? 8 : 9;
    }
    int writable = open("/tmp/sync-probe", O_CREAT | O_TRUNC | O_RDWR, 0600);
    check("create regular RAM file", writable >= 0);
    if (writable < 0) return 1;
    check("RAM write completes", write(writable, "completed", 9) == 9);
    both_ok("writable regular file", writable);
    int file = open("/tmp/sync-probe", O_RDONLY);
    int directory = open("/tmp", O_RDONLY | O_DIRECTORY);
    int null = open("/dev/null", O_RDWR);
    check("open readonly file, directory and null", file >= 0 && directory >= 0 && null >= 0);
    if (file < 0 || directory < 0 || null < 0) return 1;
    both_ok("readonly regular file", file);
    both_ok("readonly RAM directory", directory);
    both_error("negative fd", -1, EBADF);
    both_error("out of range fd", 1000, EBADF);
    both_error("null character device", null, EINVAL);
    both_error("standard console", STDOUT_FILENO, EINVAL);
    int ends[2];
    if (pipe(ends)) return 1;
    both_error("pipe read end", ends[0], EINVAL);
    both_error("pipe write end", ends[1], EINVAL);
    close(ends[0]); close(ends[1]);
    int old = writable;
    check("close regular descriptor", close(writable) == 0);
    both_error("closed fd", old, EBADF);
    check("reuse fd for null", dup2(null, old) == old);
    both_error("reused fd is now character", old, EINVAL);
    close(old);
    check("reuse fd for readonly regular", dup2(file, old) == old);
    both_ok("reused fd is now regular", old);
    close(old);
    check("platform sync reports success", stafeto_sync() == 0);
    sync();
    pid_t child = fork();
    if (child == 0) {
        if (fsync(file) || fdatasync(directory)) _exit(7);
        char a[16], b[16];
        snprintf(a, sizeof a, "%d", file); snprintf(b, sizeof b, "%d", directory);
        execl("/bin/procs-child", "posix-procs", "after-exec", a, b, (char *)NULL);
        _exit(6);
    }
    check("fork descriptor types", child > 0);
    if (child > 0) {
        int status = 0;
        check("exec import preserves readonly file and directory types", waitpid(child, &status, 0) == child
            && WIFEXITED(status) && WEXITSTATUS(status) == 9);
    }
    if (!failures) puts("posix-sync: descriptor types and RAM completion ok");
    close(null);
    full_io_pool(file, directory);
    cancellations(file);
    close(file); close(directory);
    return failures != 0;
}
