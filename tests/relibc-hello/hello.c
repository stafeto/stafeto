/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The first C program on relibc over the Rust POSIX layer: stdio with a
 * float, malloc, a file of the RAM file service through fopen and fread,
 * ENOENT, clock_gettime, and errno in the static TLS relibc built. */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stddef.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* The TCB relibc installed: TPIDR_EL0 names a word that holds it; the TCB
 * starts with the end of the static TLS and its length (generic-rt). */
struct tcb {
    char *tls_end;
    size_t tls_len;
};

static int errno_in_tls(void) {
    uintptr_t word;
    __asm__("mrs %0, tpidr_el0" : "=r"(word));
    if (word == 0) return 0;
    const struct tcb *tcb = *(const struct tcb *const *)word;
    const char *at = (const char *)&errno;
    return tcb->tls_len != 0 && at >= tcb->tls_end - tcb->tls_len &&
           at + sizeof errno <= tcb->tls_end;
}

static void *exits_at_once(void *arg) { return arg; }

/* The numbers and structures relibc gives C are those of AArch64 Linux,
 * which the layer's posix-platform writes (its const assertions say the
 * same on the Rust side). */
_Static_assert(sizeof(struct stat) == 128, "struct stat of asm-generic");
_Static_assert(offsetof(struct stat, st_nlink) == 20, "st_nlink");
_Static_assert(offsetof(struct stat, st_size) == 48, "st_size");
_Static_assert(offsetof(struct stat, st_mtim) == 88, "st_mtim");
_Static_assert(O_DIRECTORY == 040000, "O_DIRECTORY of arm64");
_Static_assert(O_NOFOLLOW == 0100000, "O_NOFOLLOW of arm64");
_Static_assert(SIGRTMIN == 35 && SIGRTMAX == 64, "relibc's real-time signals");
_Static_assert(O_CLOEXEC == 02000000, "O_CLOEXEC of Linux");
_Static_assert(F_DUPFD_CLOEXEC == 1030, "F_DUPFD_CLOEXEC of Linux");
_Static_assert(sizeof(struct termios) == 60, "termios of Linux");
_Static_assert(sizeof(sigjmp_buf) == 312, "sigjmp_buf: 39 words, the mask at word 23");

#define CHECK(cond) do { if (!(cond)) { \
    printf("relibc-hello: check failed at line %d: %s (errno %d)\n", __LINE__, #cond, errno); \
    return 20; } } while (0)

/* Directories, metadata, descriptors and anonymous memory. */
static int files(void) {
    DIR *etc = opendir("/etc");
    CHECK(etc != NULL);
    int seen = 0;
    struct dirent *entry;
    while ((entry = readdir(etc)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0) { CHECK(entry->d_type == DT_DIR); seen |= 1; }
        else if (strcmp(entry->d_name, "..") == 0) { CHECK(entry->d_type == DT_DIR); seen |= 2; }
        else if (strcmp(entry->d_name, "motd") == 0) { CHECK(entry->d_type == DT_REG); seen |= 4; }
        else CHECK(!"an entry /etc does not have");
    }
    CHECK(seen == 7);
    rewinddir(etc);
    CHECK(readdir(etc) != NULL);
    CHECK(closedir(etc) == 0);

    struct stat info;
    CHECK(stat("/etc", &info) == 0 && S_ISDIR(info.st_mode));
    CHECK(stat("/etc/motd", &info) == 0 && S_ISREG(info.st_mode) && info.st_size == 14);
    CHECK(stat("/absent", &info) == -1 && errno == ENOENT);
    errno = 0;
    CHECK(open("/etc/motd", O_RDONLY | O_DIRECTORY) == -1 && errno == ENOTDIR);
    int fd = open("/etc/motd", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    CHECK(fstat(fd, &info) == 0 && info.st_size == 14);
    int high = fcntl(fd, F_DUPFD_CLOEXEC, 10);
    CHECK(high >= 10 && (fcntl(high, F_GETFD) & FD_CLOEXEC));
    int copy = dup(fd);
    CHECK(copy >= 0 && copy < 10 && !(fcntl(copy, F_GETFD) & FD_CLOEXEC));
    char text[8] = {0};
    CHECK(pread(high, text, 7, 8) == 6 && strcmp(text, "ramfs\n") == 0);
    CHECK(close(high) == 0 && close(copy) == 0 && close(fd) == 0);
    CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);

    char cwd[64];
    CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/") == 0);
    CHECK(chdir("/etc") == 0 && getcwd(cwd, sizeof cwd) && strcmp(cwd, "/etc") == 0);
    CHECK(chdir("/") == 0);
    CHECK(isatty(1));
    struct utsname name;
    CHECK(uname(&name) == 0 && strcmp(name.sysname, "stafeto") == 0);
    struct rlimit limit;
    CHECK(getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur == 32);

    /* Pages back from an edge and from the middle, which splits the
     * mapping: then each piece left goes alone. */
    long page = 4096;
    char *pages = mmap(NULL, 5 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED && pages[4 * page] == 0);
    memset(pages, 'x', 5 * page);
    CHECK(munmap(pages, page) == 0);
    CHECK(munmap(pages + 2 * page, page) == 0);
    CHECK(pages[page] == 'x' && pages[3 * page] == 'x');
    CHECK(munmap(pages + 4 * page, page) == 0);
    CHECK(munmap(pages + 3 * page, page) == 0);
    CHECK(munmap(pages + page, page) == 0);
    /* A range with no mapping left: nothing to do, success (POSIX). */
    CHECK(munmap(pages + page, page) == 0);

    /* The access mode follows the descriptor: a file moved onto standard
     * input is no longer the console's input. F_SETFL takes no change. */
    int input = dup(0), file = open("/etc/motd", O_RDONLY);
    CHECK(input >= 0 && file >= 0 && (fcntl(0, F_GETFL) & O_ACCMODE) == O_RDONLY);
    CHECK(dup2(file, 0) == 0 && (fcntl(0, F_GETFL) & O_ACCMODE) == O_RDWR);
    CHECK(fcntl(0, F_SETFL, fcntl(0, F_GETFL)) == 0);
    CHECK(fcntl(0, F_SETFL, O_NONBLOCK) == -1 && errno == EINVAL);
    CHECK(dup2(input, 0) == 0 && close(input) == 0 && close(file) == 0);

    /* writev keeps the bytes of the parts before one that fails; a count
     * of parts outside 1 to IOV_MAX is EINVAL. */
    int scratch = open("/tmp/probe", O_RDWR);
    struct iovec parts[2] = {{"ab", 2}, {NULL, 5}};
    CHECK(scratch >= 0 && writev(scratch, parts, 2) == 2);
    CHECK(writev(scratch, parts, 0) == -1 && errno == EINVAL && close(scratch) == 0);

    volatile double two = 2.0, ten = 10.0, zero = 0.0;
    CHECK(fabs(sqrt(two) - 1.41421356) < 1e-6 && pow(two, ten) == 1024.0 && sin(zero) == 0.0);
    printf("relibc-hello: directories, stat, descriptors, mmap, math\n");
    return 0;
}

/* The ways a C program ends badly: each ends the process with status
 * 134, as SIGABRT would, after a word on fd 2 where there is one. */
static int end_badly(const char *how) {
    if (strcmp(how, "abort") == 0) abort();
    if (strcmp(how, "assert") == 0) assert(how == NULL);
    if (strcmp(how, "panic") == 0) {
        /* A broken attribute object: relibc's pthread_create panics on a
         * detach state it does not know. */
        pthread_attr_t attr, detached;
        pthread_t thread;
        pthread_attr_init(&attr);
        pthread_attr_init(&detached);
        pthread_attr_setdetachstate(&detached, PTHREAD_CREATE_DETACHED);
        /* The byte the detach state changes is the state. */
        for (size_t i = 0; i < sizeof attr; i++)
            if (((unsigned char *)&attr)[i] != ((unsigned char *)&detached)[i])
                ((unsigned char *)&attr)[i] = 99;
        pthread_create(&thread, &attr, exits_at_once, NULL);
    }
    return 1;
}

/* The constants of <unistd.h> and what sysconf answers. The system claims a
 * subprofile of POSIX.1-2024: the version is 202405, _POSIX_TIMERS stays out
 * until timer_create works, and sysconf gives each option macro's value (-1,
 * with errno untouched, for an option the header leaves out). */
#ifndef _POSIX_SUBPROFILE
#error "unistd.h does not define _POSIX_SUBPROFILE"
#endif
#ifdef _POSIX_TIMERS
#error "unistd.h defines _POSIX_TIMERS while timer_create answers ENOSYS"
#endif
_Static_assert(_POSIX_VERSION == 202405L, "_POSIX_VERSION is not POSIX.1-2024");

static int constants(void) {
    struct {
        const char *name;
        int key;
        long macro;
    } options[] = {
        {"_POSIX_VERSION", _SC_VERSION, _POSIX_VERSION},
        {"_POSIX_BARRIERS", _SC_BARRIERS, _POSIX_BARRIERS},
        {"_POSIX_MONOTONIC_CLOCK", _SC_MONOTONIC_CLOCK, _POSIX_MONOTONIC_CLOCK},
        {"_POSIX_REALTIME_SIGNALS", _SC_REALTIME_SIGNALS, _POSIX_REALTIME_SIGNALS},
        {"_POSIX_SEMAPHORES", _SC_SEMAPHORES, _POSIX_SEMAPHORES},
        {"_POSIX_SHELL", _SC_SHELL, _POSIX_SHELL},
        {"_POSIX_SHARED_MEMORY_OBJECTS", _SC_SHARED_MEMORY_OBJECTS,
         _POSIX_SHARED_MEMORY_OBJECTS},
        {"_POSIX_THREADS", _SC_THREADS, _POSIX_THREADS},
        {"_POSIX_THREAD_ATTR_STACKADDR", _SC_THREAD_ATTR_STACKADDR,
         _POSIX_THREAD_ATTR_STACKADDR},
        {"_POSIX_THREAD_ATTR_STACKSIZE", _SC_THREAD_ATTR_STACKSIZE,
         _POSIX_THREAD_ATTR_STACKSIZE},
        {"_POSIX_TIMEOUTS", _SC_TIMEOUTS, _POSIX_TIMEOUTS},
        {"_XOPEN_SHM", _SC_XOPEN_SHM, _XOPEN_SHM},
    };
    for (size_t i = 0; i < sizeof options / sizeof options[0]; i++) {
        long got = sysconf(options[i].key);
        if (got != options[i].macro) {
            printf("relibc-hello: sysconf(%s) is %ld, the header says %ld\n", options[i].name, got,
                   options[i].macro);
            return 21;
        }
    }
    /* The options the header leaves out: -1 and no errno. */
    int left_out[] = {_SC_TIMERS, _SC_ASYNCHRONOUS_IO, _SC_MESSAGE_PASSING, _SC_MEMLOCK};
    for (size_t i = 0; i < sizeof left_out / sizeof left_out[0]; i++) {
        errno = 0;
        long got = sysconf(left_out[i]);
        if (got != -1 || errno != 0) {
            printf("relibc-hello: sysconf(%d) is %ld, errno %d; expected -1 and no errno\n",
                   left_out[i], got, errno);
            return 22;
        }
    }
    printf("relibc-hello: constants: _POSIX_VERSION %ld, _POSIX_SUBPROFILE %ld, timers %ld\n",
           sysconf(_SC_VERSION), (long)_POSIX_SUBPROFILE, sysconf(_SC_TIMERS));
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) return end_badly(argv[1]);
    printf("relibc-hello: printf argc=%d argv0=%s pi=%.3f\n", argc, argv[0], 3.14159);
    if (!errno_in_tls()) {
        printf("relibc-hello: errno at %p is outside the static TLS\n", (void *)&errno);
        return 2;
    }
    errno = 0;
    if (close(-1) != -1 || errno != EBADF) {
        printf("relibc-hello: close(-1) left errno %d\n", errno);
        return 3;
    }
    char *block = malloc(100000);
    char *small = malloc(24);
    if (!block || !small) return 4;
    memset(block, 'x', 100000);
    strcpy(small, "heap");
    printf("relibc-hello: malloc %s %c\n", small, block[99999]);
    free(small);
    free(block);
    FILE *motd = fopen("/etc/motd", "r");
    if (!motd) {
        printf("relibc-hello: fopen /etc/motd failed, errno %d\n", errno);
        return 5;
    }
    char text[128] = {0};
    size_t got = fread(text, 1, sizeof text - 1, motd);
    fclose(motd);
    printf("relibc-hello: fread %zu bytes: %s", got, text);
    if (got == 0) return 6;
    errno = 0;
    if (fopen("/absent", "r") || errno != ENOENT) {
        printf("relibc-hello: /absent left errno %d\n", errno);
        return 7;
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 8;
    printf("relibc-hello: monotonic %lld.%09ld\n", (long long)now.tv_sec, now.tv_nsec);
    int status = files();
    if (status) return status;
    status = constants();
    if (status) return status;
    /* No entropy service in this image: getentropy has no source. */
    unsigned char random_bytes[16];
    errno = 0;
    int got_entropy = getentropy(random_bytes, sizeof random_bytes);
    if (got_entropy != -1 || errno != ENOSYS) {
        printf("relibc-hello: getentropy without the service gave %d, errno %d\n", got_entropy,
               errno);
        return 9;
    }
    printf("relibc-hello: getentropy without the service: ENOSYS\n");
    printf("relibc-hello: ok\n");
    return 0;
}
