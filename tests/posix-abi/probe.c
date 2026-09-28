/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <pthread.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

_Static_assert(PTHREAD_THREADS_MAX >= _POSIX_THREAD_THREADS_MAX, "minimum thread capacity");
_Static_assert(sizeof(pthread_t) == 8, "pthread ID ABI");
_Static_assert(sizeof(sigset_t) == 8, "signal set ABI");
_Static_assert(sizeof(struct sigaction) == 24, "signal action ABI");
_Static_assert(offsetof(struct sigaction, sa_flags) == 16, "signal flags offset");
_Static_assert(offsetof(struct sigaction, sa_sigaction) == 0, "handler union ABI");
_Static_assert(sizeof(stack_t) == 24, "signal stack ABI");
_Static_assert(sizeof(mcontext_t) == 800, "machine context ABI");
_Static_assert(_Alignof(mcontext_t) == 16, "machine context alignment");
_Static_assert(offsetof(mcontext_t, vectors) == 272, "vector context offset");
_Static_assert(sizeof(ucontext_t) == 848, "user context ABI");
_Static_assert(offsetof(ucontext_t, uc_mcontext) == 48, "machine context offset");
_Static_assert(sizeof(union sigval) == 8, "signal value ABI");
_Static_assert(sizeof(siginfo_t) == 40, "signal information ABI");
_Static_assert(_Alignof(siginfo_t) == 8, "signal information alignment");
_Static_assert(offsetof(siginfo_t, si_code) == 8, "signal cause offset");
_Static_assert(offsetof(siginfo_t, si_pid) == 12, "signal sender offset");
_Static_assert(offsetof(siginfo_t, si_addr) == 24, "signal address offset");
_Static_assert(offsetof(siginfo_t, si_value) == 32, "signal value offset");
_Static_assert(SI_THREAD != SI_USER && SI_THREAD != SI_QUEUE && SI_THREAD != SI_TIMER
        && SI_THREAD != SI_ASYNCIO && SI_THREAD != SI_MESGQ, "thread cause is distinct");
_Static_assert(sizeof(pthread_attr_t) == 32, "pthread attributes ABI");
_Static_assert(_Alignof(pthread_attr_t) == 8, "pthread attribute alignment");
_Static_assert(_Generic(INT64_C(1), int64_t: 1, default: 0), "signed 64-bit constant ABI");
_Static_assert(_Generic(UINT64_C(1), uint64_t: 1, default: 0), "unsigned 64-bit constant ABI");
_Static_assert(sizeof(void *) == 8, "pointer ABI");
_Static_assert(sizeof(pid_t) == 4, "signed process identity ABI");
_Static_assert(_Generic(getpid(), pid_t: 1, default: 0), "getpid result ABI");
_Static_assert(_Generic(getppid(), pid_t: 1, default: 0), "getppid result ABI");
_Static_assert(sizeof(int) == 4, "int ABI");
_Static_assert(sizeof(long) == 8, "long ABI");
_Static_assert(sizeof(size_t) == 8, "size_t ABI");
_Static_assert(sizeof(ssize_t) == 8, "ssize_t ABI");
_Static_assert(sizeof(off_t) == 8, "off_t ABI");
_Static_assert(ABI_VERSION == 1, "ABI version");
_Static_assert(sizeof(struct stat) == STAFETO_STAT_SIZE, "stat ABI");
_Static_assert(_Alignof(struct stat) == 8, "stat alignment");
_Static_assert(offsetof(struct stat, st_size) == 48, "stat size offset");
_Static_assert(offsetof(struct stat, st_atim) == 72, "stat timestamp offset");
_Static_assert(sizeof(struct timespec) == 16, "timespec ABI");
_Static_assert(sizeof(struct dirent) == STAFETO_DIRENT_SIZE, "dirent ABI");
_Static_assert(offsetof(struct dirent, d_name) == 9, "dirent name offset");
_Static_assert(_Alignof(max_align_t) == 16, "malloc fundamental alignment");

static volatile sig_atomic_t signal_calls;
static volatile sig_atomic_t signal_bad;
static void signal_handler(int sig) {
    sigset_t mask;
    if (sig != SIGUSR1 || pthread_sigmask(-99, NULL, &mask)
            || !sigismember(&mask, SIGUSR1)) signal_bad = 1;
    signal_calls++;
    if (getpid() <= 1 || getppid() != 1) signal_bad = 1;
    errno = 901;
}
static volatile sig_atomic_t info_calls;
static volatile sig_atomic_t info_bad;
static void info_handler(int sig, siginfo_t *info, void *raw) {
    ucontext_t *context = raw;
    sigset_t mask;
    struct sigaction previous;
    if (sig != SIGUSR1 || !info || !context || info->si_signo != sig
            || info->si_code != SI_THREAD || info->si_errno || info->si_value.sival_ptr
            || context->uc_link || context->uc_sigmask || context->uc_stack.ss_sp
            || context->uc_stack.ss_size || context->uc_stack.ss_flags != SS_DISABLE
            || !context->uc_mcontext.sp || context->uc_mcontext.sp % 16
            || !context->uc_mcontext.pc || context->uc_mcontext.pc % 4
            || pthread_sigmask(-99, NULL, &mask) || !sigismember(&mask, SIGUSR1)
            || sigaction(SIGUSR1, NULL, &previous) || previous.sa_handler != SIG_DFL
            || (previous.sa_flags & SA_SIGINFO)) info_bad = 1;
    info_calls++;
    sigemptyset(&context->uc_sigmask);
    sigaddset(&context->uc_sigmask, SIGUSR2);
    errno = 901;
}
static int signals(void) {
    sigset_t set, old, pending;
    struct sigaction action = { .sa_handler = signal_handler, .sa_mask = 0, .sa_flags = 0 }, previous;
    errno = 777;
    if (sigemptyset(&set) || sigaddset(&set, SIGUSR1) || !sigismember(&set, SIGUSR1)
            || sigismember(&set, SIGUSR2) || sigaction(SIGUSR1, &action, &previous)
            || previous.sa_handler != SIG_DFL || errno != 777) return 150;
    if (pthread_sigmask(SIG_BLOCK, &set, &old) || old || raise(SIGUSR1) || raise(SIGUSR1)
            || signal_calls || sigpending(&pending) || pending != set || errno != 777) return 151;
    if (pthread_sigmask(SIG_UNBLOCK, &set, NULL) || signal_calls != 1 || signal_bad || errno != 777) return 152;
    old = 999;
    if (pthread_sigmask(-99, &set, &old) != EINVAL || old != 999 || errno != 777) return 153;
    if (sigprocmask(-99, &set, &old) != -1 || errno != EINVAL || old != 999) return 154;
    if (sigaction(SIGKILL, &action, NULL) != -1 || errno != EINVAL) return 155;
    if (signal(SIGUSR1, SIG_IGN) != signal_handler || raise(SIGUSR1) || signal_calls != 1) return 156;
    if (signal(SIGUSR1, SIG_DFL) != SIG_IGN || pthread_kill(pthread_self(), 0)) return 157;
    if (sigfillset(&set) || !sigismember(&set, SIGKILL) || !sigismember(&set, SIGSTOP)) return 158;
    if (pthread_sigmask(SIG_SETMASK, &set, NULL) || pthread_sigmask(-1, NULL, &old)
            || sigismember(&old, SIGKILL) || sigismember(&old, SIGSTOP)) return 159;
    if (sigemptyset(&set) || pthread_sigmask(SIG_SETMASK, &set, NULL)) return 160;
    if (sigaddset(&set, 0) != -1 || errno != EINVAL || set) return 161;
    action.sa_flags = 8;
    previous.sa_handler = signal_handler;
    previous.sa_mask = 123;
    previous.sa_flags = 456;
    if (sigaction(SIGUSR1, &action, &previous) != -1 || errno != EINVAL
            || previous.sa_handler != signal_handler || previous.sa_mask != 123
            || previous.sa_flags != 456) return 162;
    if (sigaction(SIGUSR1, NULL, &previous) || previous.sa_handler != SIG_DFL) return 163;
    action.sa_flags = SA_RESETHAND;
    if (sigaction(SIGUSR1, &action, NULL) || sigaddset(&set, SIGUSR1)
            || pthread_sigmask(SIG_BLOCK, &set, NULL) || raise(SIGUSR1) || raise(SIGUSR1)) return 164;
    int accepted = 999;
    errno = 777;
    if (sigwait(&set, &accepted) || accepted != SIGUSR1 || errno != 777
            || sigpending(&pending) || pending || signal_calls != 1
            || sigaction(SIGUSR1, NULL, &previous) || previous.sa_handler != signal_handler
            || previous.sa_flags != SA_RESETHAND) return 165;
    set = UINT64_C(1) << 63;
    accepted = 999;
    if (sigwait(&set, &accepted) != EINVAL || accepted != 999 || errno != 777
            || sigwait(NULL, &accepted) != EFAULT || accepted != 999 || errno != 777) return 166;
    siginfo_t info = { .si_signo = 999, .si_code = -999, .si_value.sival_ptr = (void *)UINT64_C(18446744073709551615) };
    if (sigwaitinfo(&set, &info) != -1 || errno != EINVAL || info.si_signo != 999
            || info.si_code != -999 || info.si_value.sival_ptr != (void *)UINT64_C(18446744073709551615)) return 168;
    if (sigwaitinfo(NULL, &info) != -1 || errno != EFAULT || info.si_signo != 999
            || info.si_code != -999 || info.si_value.sival_ptr != (void *)UINT64_C(18446744073709551615)) return 169;
    if (sigemptyset(&set) || sigaddset(&set, SIGUSR1) || raise(SIGUSR1) || raise(SIGUSR1)) return 170;
    errno = 777;
    if (sigwaitinfo(&set, &info) != SIGUSR1 || errno != 777 || info.si_signo != SIGUSR1
            || info.si_code != SI_THREAD || info.si_errno || info.si_pid || info.si_uid
            || info.si_status || info.si_addr || info.si_value.sival_ptr || sigpending(&pending)
            || pending || signal_calls != 1 || sigaction(SIGUSR1, NULL, &previous)
            || previous.sa_handler != signal_handler || previous.sa_flags != SA_RESETHAND) return 171;
    if (raise(SIGUSR1) || sigwaitinfo(&set, NULL) != SIGUSR1 || errno != 777
            || sigpending(&pending) || pending || signal_calls != 1) return 172;
    if (sigemptyset(&set) || pthread_sigmask(SIG_SETMASK, &set, NULL)
            || signal(SIGUSR1, SIG_DFL) != signal_handler) return 167;
    action.sa_sigaction = info_handler;
    action.sa_flags = SA_SIGINFO | SA_RESETHAND;
    if (sigaction(SIGUSR1, &action, &previous) || previous.sa_handler != SIG_DFL
            || sigaction(SIGUSR1, NULL, &previous) || previous.sa_sigaction != info_handler
            || previous.sa_flags != (SA_SIGINFO | SA_RESETHAND)) return 173;
    errno = 777;
    if (raise(SIGUSR1) || info_calls != 1 || info_bad || errno != 777
            || pthread_sigmask(-99, NULL, &set) || !sigismember(&set, SIGUSR2)
            || sigismember(&set, SIGUSR1)) return 174;
    if (sigemptyset(&set) || pthread_sigmask(SIG_SETMASK, &set, NULL)) return 175;
    if (sigaddset(&set, SIGUSR1) || pthread_sigmask(SIG_BLOCK, &set, NULL)) return 176;
    struct timespec timeout = { .tv_sec = 0, .tv_nsec = 0 };
    info.si_code = -999;
    info.si_value.sival_ptr = (void *)UINT64_C(18446744073709551615);
    if (sigtimedwait(&set, &info, &timeout) != -1 || errno != EAGAIN
            || info.si_code != -999 || info.si_value.sival_ptr != (void *)UINT64_C(18446744073709551615)) return 177;
    const struct timespec invalid[] = { { 0, -1 }, { 0, 1000000000 }, { -1, 0 } };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        if (sigtimedwait(&set, &info, &invalid[i]) != -1 || errno != EINVAL
                || info.si_code != -999 || info.si_value.sival_ptr != (void *)UINT64_C(18446744073709551615)) return 178;
        if (raise(SIGUSR1)) return 179;
        errno = 777;
        if (sigtimedwait(&set, &info, &invalid[i]) != SIGUSR1 || errno != 777
                || info.si_signo != SIGUSR1 || info.si_code != SI_THREAD || sigpending(&pending) || pending) return 180;
        info.si_code = -999;
        info.si_value.sival_ptr = (void *)UINT64_C(18446744073709551615);
    }
    if (raise(SIGUSR1) || sigtimedwait(&set, NULL, &timeout) != SIGUSR1 || errno != 777
            || raise(SIGUSR1) || sigtimedwait(&set, NULL, NULL) != SIGUSR1 || errno != 777) return 181;
    struct timespec before, after;
    timeout.tv_nsec = 2000000;
    if (clock_gettime(CLOCK_MONOTONIC, &before) || sigtimedwait(&set, &info, &timeout) != -1
            || errno != EAGAIN || info.si_code != -999 || clock_gettime(CLOCK_MONOTONIC, &after)
            || (after.tv_sec - before.tv_sec) * INT64_C(1000000000) + after.tv_nsec - before.tv_nsec < timeout.tv_nsec) return 182;
    if (sigtimedwait(NULL, &info, &timeout) != -1 || errno != EFAULT || info.si_code != -999) return 183;
    if (sigemptyset(&set) || pthread_sigmask(SIG_SETMASK, &set, NULL)) return 184;
    return 0;
}

static int same(const char *a, const char *b, size_t count) {
    for (size_t i = 0; i < count; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static int metadata(void) {
    struct stat value, copy;
    errno = 123;
    if (stat("/", &value) || errno != 123 || !S_ISDIR(value.st_mode)
            || (value.st_mode & 07777) != 0555 || value.st_ino != 1
            || value.st_nlink != 4 || value.st_dev != 1 || value.st_uid || value.st_gid) return 40;
    if (stat("motd", &value) || !S_ISREG(value.st_mode) || value.st_ino != 4
            || value.st_size != 14 || value.st_nlink != 1 || value.st_blocks != 1
            || value.st_blksize != 1024 || (value.st_mode & 07777) != 0444) return 41;
    int fd = open("motd", O_RDONLY), alias = dup(fd);
    if (fd < 0 || alias < 0 || fstat(alias, &copy) || copy.st_ino != value.st_ino
            || copy.st_dev != value.st_dev || copy.st_size != value.st_size) return 42;
    if (close(fd) || fstat(alias, &copy) || close(alias)) return 43;
    if (lstat("motd", &copy) || copy.st_ino != value.st_ino) return 44;
    if (fstat(1, &copy) || !S_ISCHR(copy.st_mode) || copy.st_rdev != 1) return 45;
    if (open("motd", O_WRONLY) != -1 || errno != EACCES) return 46;
    value.st_ino = 987;
    if (stat("/missing", &value) != -1 || errno != ENOENT || value.st_ino != 987) return 47;
    if (stat("motd/", &value) != -1 || errno != ENOTDIR) return 48;
    if (fstat(-1, &value) != -1 || errno != EBADF || value.st_ino != 987) return 49;
    if (stat(NULL, &value) != -1 || errno != EFAULT) return 50;
    if (stat("/", NULL) != -1 || errno != EFAULT) return 51;
    if (fstat(1, NULL) != -1 || errno != EFAULT) return 52;
    fd = open("/tmp/probe", O_RDWR);
    if (fd < 0 || lseek(fd, 10, SEEK_SET) != 10 || write(fd, "x", 1) != 1
            || fstat(fd, &value) || value.st_size != 11 || value.st_ino != 5) return 53;
    if (value.st_mtim.tv_nsec < 0 || value.st_mtim.tv_nsec >= 1000000000
            || value.st_mtim.tv_sec != value.st_ctim.tv_sec
            || value.st_mtim.tv_nsec != value.st_ctim.tv_nsec) return 54;
    if (write(fd, NULL, 0) != 0 || fstat(fd, &copy)
            || copy.st_mtim.tv_sec != value.st_mtim.tv_sec
            || copy.st_mtim.tv_nsec != value.st_mtim.tv_nsec) return 55;
    char byte;
    if (read(fd, &byte, 1) != 0 || fstat(fd, &copy)
            || copy.st_atim.tv_sec < value.st_atim.tv_sec
            || (copy.st_atim.tv_sec == value.st_atim.tv_sec
                && copy.st_atim.tv_nsec < value.st_atim.tv_nsec)) return 56;
    if (close(fd) || fstat(fd, &copy) != -1 || errno != EBADF) return 57;
    return 0;
}

static int directories(void) {
    if (opendir("motd") != NULL || errno != ENOTDIR) return 60;
    if (opendir("/absent") != NULL || errno != ENOENT) return 61;
    if (opendir(NULL) != NULL || errno != EFAULT) return 62;
    DIR *dir = opendir(".");
    if (!dir || dirfd(dir) != 0 || telldir(dir) != 0) return 63;
    struct stat info;
    if (fstat(dirfd(dir), &info) || !S_ISDIR(info.st_mode) || info.st_ino != 2) return 64;
    struct dirent *entry = readdir(dir);
    if (!entry || !same(entry->d_name, ".", 2) || entry->d_ino != 2 || entry->d_type != DT_DIR) return 65;
    long cookie = telldir(dir);
    DIR *other = opendir("/tmp");
    struct dirent *other_entry = readdir(other);
    if (!other || !other_entry || other_entry == entry || other_entry->d_ino != 3
            || entry->d_ino != 2 || !same(entry->d_name, ".", 2) || cookie != 1) return 66;
    entry = readdir(dir);
    if (!entry || !same(entry->d_name, "..", 3) || entry->d_ino != 1) return 67;
    entry = readdir(dir);
    if (!entry || !same(entry->d_name, "motd", 5) || entry->d_ino != 4 || entry->d_type != DT_REG) return 68;
    errno = 123;
    if (readdir(dir) != NULL || errno != 123 || telldir(dir) != 3) return 69;
    seekdir(dir, cookie);
    entry = readdir(dir);
    if (!entry || !same(entry->d_name, "..", 3)) return 70;
    rewinddir(dir);
    if (telldir(dir) != 0 || !readdir(dir)) return 71;
    int saved_fd = dirfd(dir), duplicate = dup(saved_fd);
    if (closedir(other) || closedir(dir) || fstat(saved_fd, &info) != -1 || errno != EBADF) return 72;
    if (fstat(duplicate, &info) || !S_ISDIR(info.st_mode)) return 73;
    dir = fdopendir(duplicate);
    if (!dir || dirfd(dir) != duplicate || telldir(dir) != 1) return 74;
    entry = readdir(dir);
    if (!entry || entry->d_ino != 1 || !same(entry->d_name, "..", 3) || closedir(dir)) return 75;
    int fd = open("motd", O_RDONLY);
    if (fdopendir(fd) != NULL || errno != ENOTDIR || fstat(fd, &info) || close(fd)) return 76;
    if (fdopendir(-1) != NULL || errno != EBADF || readdir(NULL) != NULL || errno != EBADF) return 77;
    if (dirfd(NULL) != -1 || errno != EBADF || closedir(NULL) != -1 || errno != EBADF) return 78;
    if (open("motd", O_RDONLY | O_DIRECTORY) != -1 || errno != ENOTDIR) return 79;
    fd = open("/", O_RDONLY | O_DIRECTORY);
    if (fd < 0 || (dir = fdopendir(fd)) == NULL || dirfd(dir) != fd || closedir(dir)) return 80;
    DIR *held[30];
    for (int i = 0; i < 30; i++) if ((held[i] = opendir("/")) == NULL) return 81;
    if (opendir("/") != NULL || errno != EMFILE || open("motd", O_RDONLY) != -1 || errno != EMFILE) return 82;
    saved_fd = dirfd(held[7]);
    if (closedir(held[7]) || (held[7] = opendir("/tmp")) == NULL || dirfd(held[7]) != saved_fd) return 83;
    for (int i = 0; i < 30; i++) if (closedir(held[i])) return 84;
    fd = open("motd", O_RDONLY);
    if (fd != 0 || close(fd)) return 85;
    return 0;
}

static int allocations(void) {
    errno = 123;
    unsigned char *p = malloc(37);
    if (!p || (uintptr_t)p % _Alignof(max_align_t) || errno != 123) return 90;
    for (size_t i = 0; i < 37; i++) p[i] = (unsigned char)(i + 1);
    unsigned char *q = realloc(p, 127);
    if (!q) return 91;
    for (size_t i = 0; i < 37; i++) if (q[i] != i + 1) return 92;
    p = realloc(q, 8);
    if (!p || p != q) return 93;
    if (realloc(p, SIZE_MAX) != NULL || errno != ENOMEM) return 94;
    if (reallocarray(p, SIZE_MAX, 2) != NULL || errno != ENOMEM) return 95;
    for (size_t i = 0; i < 8; i++) if (p[i] != i + 1) return 96;
    errno = 456;
    free(p); free(NULL);
    if (errno != 456) return 97;
    p = calloc(83, 5);
    if (!p) return 98;
    for (size_t i = 0; i < 415; i++) if (p[i]) return 99;
    free(p);
    if (calloc(SIZE_MAX, 2) != NULL || errno != ENOMEM) return 100;
    p = malloc(0); q = malloc(0);
    if (!p || !q || p == q) return 101;
    free(p); free(q);
    p = realloc(NULL, 19);
    if (!p || (q = realloc(p, 0)) != p) return 102;
    free(q);
    p = aligned_alloc(256, 512);
    if (!p || (uintptr_t)p % 256) return 103;
    free(p);
    if (aligned_alloc(3, 12) != NULL || errno != EINVAL
            || aligned_alloc(256, 513) != NULL || errno != EINVAL) return 104;
    void *out = (void *)17;
    errno = 456;
    if (posix_memalign(&out, 3, 128) != EINVAL || out != (void *)17 || errno != 456) return 105;
    if (posix_memalign(&out, 4096, 300) || (uintptr_t)out % 4096 || errno != 456) return 106;
    free(out); out = (void *)17;
    if (posix_memalign(&out, 16, SIZE_MAX) != ENOMEM || out != (void *)17 || errno != 456) return 107;
    p = calloc(70000, 1);
    if (!p) return 108;
    for (size_t i = 0; i < 70000; i++) if (p[i]) return 109;
    free(p);
    p = malloc(64);
    if (!p) return 110;
    p[0] = 77;
    if (malloc(8 * 1024 * 1024) != NULL || errno != ENOMEM || p[0] != 77) return 111;
    free(p);
    p = malloc(64);
    if (!p) return 112;
    free(p);
    return 0;
}

static int integer_compare(const void *a, const void *b) {
    int left = *(const int *)a, right = *(const int *)b;
    return (left > right) - (left < right);
}

static int context_compare(const void *a, const void *b, void *context) {
    int nested[] = {9, 1, 3};
    qsort(nested, 3, sizeof(int), integer_compare);
    if (nested[0] != 1 || nested[2] != 9) *(int *)context = 0;
    return integer_compare(a, b) * *(int *)context;
}

static int byte_record_compare(const void *a, const void *b) {
    return (int)*(const unsigned char *)a - (int)*(const unsigned char *)b;
}

static int collation(void) {
    errno = 321;
    if (!setlocale(LC_ALL, NULL) || strcmp(setlocale(LC_ALL, NULL), "C")
            || !setlocale(LC_ALL, "POSIX") || !setlocale(LC_COLLATE, "C")
            || setlocale(LC_ALL, "unsupported") || setlocale(999, "C")
            || errno != 321 || !setlocale(LC_ALL, "")) return 120;
    char **saved = environ;
    char *environment[] = {"LANG=unsupported", "LC_COLLATE=POSIX", "LC_ALL=", NULL};
    environ = environment;
    int accepted = setlocale(LC_COLLATE, "") != NULL;
    int rejected = setlocale(LC_ALL, "") == NULL;
    environment[2] = "LC_ALL=C";
    int override = setlocale(LC_ALL, "") != NULL;
    environment[2] = "LC_ALL=unsupported";
    int invalid = setlocale(LC_COLLATE, "") == NULL;
    environ = saved;
    if (!accepted || !rejected || !override || !invalid || errno != 321
            || strcmp(setlocale(LC_ALL, NULL), "C")) return 121;
    const char high[] = {(char)0x80, 0}, low[] = {(char)0x7f, 0};
    if (strcmp(high, low) <= 0 || strcoll(high, low) <= 0
            || strcoll("A", "a") >= 0 || strcoll("abc", "abcd") >= 0
            || strcoll("same", "same") != 0 || errno != 321) return 122;
    char out[8] = {7, 7, 7, 7, 7, 7, 7, 7};
    if (strxfrm(NULL, "abc", 0) != 3 || strxfrm(out, "abc", 4) != 3
            || strcmp(out, "abc") || out[4] != 7 || errno != 321) return 123;
    out[0] = out[1] = out[2] = out[3] = 7;
    if (strxfrm(out, "abc", 2) != 3 || out[2] != 7 || out[3] != 7) return 124;
    int values[] = {5, 1, 8, 5, -1, 2};
    qsort(values, 6, sizeof(int), integer_compare);
    for (int i = 1; i < 6; i++) if (values[i - 1] > values[i]) return 125;
    int direction = -1;
    qsort_r(values, 6, sizeof(int), context_compare, &direction);
    if (direction != -1) return 126;
    for (int i = 1; i < 6; i++) if (values[i - 1] < values[i]) return 127;
    qsort(NULL, 0, sizeof(int), integer_compare);
    qsort(values, 1, sizeof(int), integer_compare);
    if (errno != 321) return 128;
    unsigned char records[] = {99, 3, 30, 31, 1, 10, 11, 2, 20, 21, 88};
    qsort(records + 1, 3, 3, byte_record_compare);
    const unsigned char expected[] = {99, 1, 10, 11, 2, 20, 21, 3, 30, 31, 88};
    for (size_t i = 0; i < sizeof records; i++) if (records[i] != expected[i]) return 129;
    return 0;
}

static int select_visible(const struct dirent *entry) {
    DIR *nested = opendir("/tmp");
    int ok = nested && readdir(nested) && closedir(nested) == 0;
    errno = EIO;
    return ok && entry->d_name[0] != '.';
}

static int select_none(const struct dirent *entry) {
    (void)entry;
    errno = ENOENT;
    return 0;
}

static int reverse_names(const struct dirent **a, const struct dirent **b) {
    errno = EIO;
    return -alphasort(a, b);
}

static void release_names(struct dirent **names, int count) {
    for (int i = 0; i < count; i++) free(names[i]);
    free(names);
}

#define PRESSURE_LIMIT 16384
static void *pressure[PRESSURE_LIMIT];
static int pressure_count, pressure_failed, select_count;

static int select_pressure(const struct dirent *entry) {
    (void)entry;
    if (++select_count == 2) {
        const size_t sizes[] = {1024, 144, 64, 1};
        for (int i = 0; i < 4; i++) {
            void *block;
            while ((block = malloc(sizes[i])) != NULL) {
                if (pressure_count == PRESSURE_LIMIT) { free(block); pressure_failed = 1; return 1; }
                pressure[pressure_count++] = block;
            }
        }
    }
    return 1;
}

static int scans(void) {
    struct dirent **names = NULL;
    errno = 321;
    int count = scandir("/", &names, NULL, alphasort);
    if (count != 4 || !names || errno != 321
            || strcmp(names[0]->d_name, ".") || strcmp(names[1]->d_name, "..")
            || strcmp(names[2]->d_name, "etc") || strcmp(names[3]->d_name, "tmp")
            || names[2]->d_ino != 2 || names[2]->d_type != DT_DIR
            || names[0] == names[1]) return 130;
    DIR *dir = opendir("/tmp");
    if (!dir || !readdir(dir) || closedir(dir) || strcmp(names[2]->d_name, "etc")) return 131;
    release_names(names, count);
    errno = 321;
    count = scandir("/", &names, select_visible, reverse_names);
    if (count != 2 || errno != 321 || strcmp(names[0]->d_name, "tmp")
            || strcmp(names[1]->d_name, "etc")) return 132;
    release_names(names, count);
    count = scandir("/etc", &names, select_none, NULL);
    if (count != 0 || !names || errno != 321) return 133;
    free(names);
    count = scandir("/etc", &names, NULL, NULL);
    if (count != 3 || strcmp(names[2]->d_name, "motd")) return 134;
    release_names(names, count);
    names = (void *)17;
    if (scandir("/absent", &names, NULL, NULL) != -1 || errno != ENOENT || names != (void *)17
            || scandir("/etc/motd", &names, NULL, NULL) != -1 || errno != ENOTDIR
            || names != (void *)17 || scandir("/", NULL, NULL, NULL) != -1 || errno != EFAULT) return 135;
    for (int i = 0; i < 80; i++) {
        count = scandir("/", &names, NULL, alphasort);
        if (count != 4) return 136;
        release_names(names, count);
    }
    names = (void *)17;
    count = scandir("/", &names, select_pressure, alphasort);
    int allocation_error = errno;
    void *reused = malloc(144);
    for (int i = 0; i < pressure_count; i++) free(pressure[i]);
    if (count != -1 || allocation_error != ENOMEM || names != (void *)17
            || pressure_failed || !reused || select_count != 2) return 137;
    free(reused);
    for (int i = 0; i < 40; i++) {
        count = scandir("/", &names, NULL, alphasort);
        if (count != 4) return 138;
        release_names(names, count);
    }
    return 0;
}

static uint64_t fp_environment(void) {
    uint64_t control, status;
    __asm__ volatile ("mrs %0, fpcr; mrs %1, fpsr" : "=r"(control), "=r"(status));
    return control | (status << 32);
}
static void set_fp_environment(uint64_t environment) {
    uint64_t control = (uint32_t)environment, status = environment >> 32;
    __asm__ volatile ("msr fpcr, %0; msr fpsr, %1" : : "r"(control), "r"(status) : "memory");
}
struct thread_context { pthread_t parent, self; int fd; char byte; int failure; uint64_t floating; pid_t pid, ppid; };

static void *thread_files(void *argument) {
    struct thread_context *context = argument;
    context->self = pthread_self();
    if (!context->self || pthread_equal(context->self, context->parent) || errno != 0) {
        context->failure = 1;
        return NULL;
    }
    if (fp_environment() != context->floating) { context->failure = 4; return NULL; }
    set_fp_environment(0);
    errno = 777;
    if (getpid() != context->pid || getppid() != context->ppid || errno != 777) {
        context->failure = 5;
        return NULL;
    }
    if (read(context->fd, &context->byte, 1) != 1 || context->byte != 's' || errno != 777) {
        context->failure = 2;
        return NULL;
    }
    char *owned = malloc(32);
    if (!owned || errno != 777) { context->failure = 3; return NULL; }
    owned[0] = 'p'; owned[31] = 't';
    return owned;
}

static void *thread_exit_value(void *argument) { pthread_exit(argument); }
static void *thread_return(void *argument) { return argument; }
static void *thread_nested(void *argument) {
    pthread_t child;
    void *value = NULL;
    errno = 777;
    if (pthread_join(pthread_self(), &value) != EDEADLK || value != NULL
            || pthread_create(&child, NULL, thread_exit_value, argument)
            || pthread_join(child, &value) || value != argument || errno != 777) return NULL;
    return value;
}

static int threads(void) {
    pthread_t main_thread = pthread_self(), child = 0;
    pthread_attr_t attr;
    size_t size = 0;
    int state = -1;
    void *value = (void *)(uintptr_t)1234;
    errno = 123;
    if (getpid() <= 1 || getppid() != 1 || getpid() == getppid() || errno != 123) return 199;
    if (!main_thread || !pthread_equal(main_thread, main_thread)
            || pthread_join(main_thread, &value) != EDEADLK
            || value != (void *)(uintptr_t)1234 || errno != 123) return 200;
    if (pthread_attr_init(&attr) || pthread_attr_getstacksize(&attr, &size) || size != 65536
            || pthread_attr_getguardsize(&attr, &size) || size != 4096
            || pthread_attr_getdetachstate(&attr, &state) || state != PTHREAD_CREATE_JOINABLE) return 201;
    if (pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN - 1) != EINVAL
            || pthread_attr_getstacksize(&attr, &size) || size != 65536
            || pthread_attr_setguardsize(&attr, SIZE_MAX) != EINVAL
            || pthread_attr_setdetachstate(&attr, 123) != EINVAL
            || pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN)
            || pthread_attr_setguardsize(&attr, 1)
            || pthread_attr_getguardsize(&attr, &size) || size != 1 || errno != 123) return 202;
    if (pthread_create(NULL, &attr, thread_return, NULL) != EINVAL
            || pthread_create(&child, &attr, NULL, NULL) != EINVAL || child != 0 || errno != 123) return 203;
    uint64_t original_floating = fp_environment();
    // Non-default rounding mode and exception status must be inherited.
    set_fp_environment((1ULL << 22) | (1ULL << 32));
    struct thread_context context = { .parent = main_thread, .fd = open("/etc/motd", O_RDONLY),
        .floating = fp_environment(), .pid = getpid(), .ppid = getppid() };
    if (context.fd < 0 || pthread_create(&child, NULL, thread_files, &context)
            || pthread_join(child, &value) || context.failure || context.self != child
            || !value || ((char *)value)[0] != 'p' || ((char *)value)[31] != 't' || errno != 123
            || fp_environment() != context.floating) return 204;
    set_fp_environment(original_floating);
    free(value);
    char byte;
    if (read(context.fd, &byte, 1) != 1 || byte != 't' || close(context.fd)) return 205;
    value = (void *)(uintptr_t)1234;
    if (pthread_join(child, &value) != ESRCH || pthread_detach(child) != ESRCH
            || value != (void *)(uintptr_t)1234 || errno != 123) return 206;
    pthread_t previous = child;
    for (unsigned int i = 0; i < 64; i++) {
        void *expected = (void *)(uintptr_t)(i + 1);
        if (pthread_create(&child, &attr, thread_exit_value, expected)
                || child <= previous || pthread_join(child, &value) || value != expected) return 207;
        previous = child;
    }
    if (pthread_create(&child, NULL, thread_nested, &context)
            || pthread_join(child, &value) || value != &context || errno != 123) return 208;
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)
            || pthread_create(&child, &attr, thread_return, NULL)) return 209;
    int detached_join = pthread_join(child, NULL);
    if (detached_join != EINVAL && detached_join != ESRCH) return 210;
    // The witness join lets the detached child finish before testing slot reuse.
    if (pthread_create(&child, NULL, thread_return, &context)
            || pthread_detach(child)) return 211;
    pthread_t witness;
    if (pthread_create(&witness, NULL, thread_return, &context)
            || pthread_join(witness, &value) || value != &context) return 212;
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE)) return 213;
    pthread_t children[PTHREAD_THREADS_MAX - 1];
    for (size_t i = 0; i < PTHREAD_THREADS_MAX - 1; i++) {
        if (pthread_create(&children[i], &attr, thread_return, (void *)(uintptr_t)(i + 1))) return 214;
    }
    child = 987;
    if (pthread_create(&child, &attr, thread_return, NULL) != EAGAIN || child != 987 || errno != 123) return 215;
    for (size_t i = 0; i < PTHREAD_THREADS_MAX - 1; i++) {
        if (pthread_join(children[i], &value) || value != (void *)(uintptr_t)(i + 1)) return 216;
    }
    if (pthread_create(&child, &attr, thread_return, NULL) || pthread_join(child, NULL)
            || pthread_attr_destroy(&attr) || pthread_attr_getstacksize(&attr, &size) != EINVAL
            || pthread_create(&child, &attr, thread_return, NULL) != EINVAL || errno != 123) return 217;
    return 0;
}

struct cancellation_context { int errors, sequence[4], count, survived, fd, output, mode; };
static void cleanup_first(void *argument) {
    struct cancellation_context *context = argument;
    context->sequence[context->count++] = 1;
}
static void cleanup_second(void *argument) {
    struct cancellation_context *context = argument;
    int old = 99;
    context->sequence[context->count++] = 2;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old) || old != PTHREAD_CANCEL_DISABLE) context->errors++;
    pthread_testcancel();
    // Cancellation must stay disabled throughout exit handlers, so this code runs.
    context->survived++;
    void *block = malloc(32);
    if (!block) context->errors++;
    free(block);
}
static void *cancel_pending(void *argument) {
    struct cancellation_context *context = argument;
    int old = 99, type = 99;
    char byte;
    errno = 777;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old) || old != PTHREAD_CANCEL_ENABLE
            || pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &type) || type != PTHREAD_CANCEL_DEFERRED) context->errors++;
    old = 99; type = 99;
    if (pthread_setcancelstate(123, &old) != EINVAL || old != 99
            || pthread_setcanceltype(123, &type) != EINVAL || type != 99
            || pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &type) != ENOSYS || type != 99 || errno != 777) context->errors++;
    pthread_cleanup_push(cleanup_first, context);
    pthread_cleanup_push(cleanup_second, context);
    if (pthread_cancel(pthread_self())) context->errors++;
    pthread_testcancel();
    if (read(context->fd, &byte, 1) != 1 || byte != 's') context->errors++;
    context->survived++;
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old) || old != PTHREAD_CANCEL_DISABLE
            || lseek(context->fd, 0, SEEK_CUR) != 1 || errno != 777) context->errors++;
    // Deferred enabling and lseek are not cancellation points.
    context->survived++;
    if (context->mode == 0) pthread_testcancel();
    if (context->mode == 1) (void)read(context->fd, &byte, 1);
    if (context->mode == 2) (void)write(context->output, "z", 1);
    context->errors++;
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    return NULL;
}
static void *cleanup_exit(void *argument) {
    struct cancellation_context *context = argument;
    pthread_cleanup_push(cleanup_first, context);
    pthread_cleanup_push(cleanup_first, context);
    pthread_cleanup_pop(0);
    pthread_cleanup_push(cleanup_first, context);
    pthread_cleanup_pop(1);
    pthread_cleanup_push(cleanup_second, context);
    // Explicit exit retains its supplied value even with a pending request.
    if (pthread_cancel(pthread_self())) context->errors++;
    pthread_exit(argument);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
}
static void *fresh_cancel_state(void *argument) {
    int old = 99, type = 99;
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old) || old != PTHREAD_CANCEL_ENABLE
            || pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &type) || type != PTHREAD_CANCEL_DEFERRED) return NULL;
    pthread_testcancel();
    return argument;
}
static int cancellation(void) {
    _Static_assert(sizeof(struct __stafeto_cleanup_buffer) == 24, "cleanup ABI");
    pthread_t child;
    void *value = NULL;
    errno = 123;
    for (int mode = 0; mode < 3; mode++) {
        struct cancellation_context context = { .fd = open("/etc/motd", O_RDONLY),
            .output = open("/tmp/probe", O_RDWR), .mode = mode };
        if (context.fd < 0 || context.output < 0
                || pthread_create(&child, NULL, cancel_pending, &context)
                || pthread_join(child, &value) || value != PTHREAD_CANCELED
                || context.errors || context.count != 2 || context.sequence[0] != 2
                || context.sequence[1] != 1 || context.survived != 3
                || lseek(context.fd, 0, SEEK_CUR) != 1 || lseek(context.output, 0, SEEK_CUR) != 0
                || close(context.fd) || close(context.output) || errno != 123) return 220 + mode;
        if (pthread_cancel(child) != ESRCH
                || pthread_create(&child, NULL, fresh_cancel_state, &context)
                || pthread_join(child, &value) || value != &context) return 223;
    }
    struct cancellation_context context = {0};
    if (pthread_create(&child, NULL, cleanup_exit, &context)
            || pthread_join(child, &value) || value != &context || context.errors
            || context.count != 3 || context.sequence[0] != 1 || context.sequence[1] != 2
            || context.sequence[2] != 1 || context.survived != 1 || errno != 123) return 224;
    return 0;
}


_Static_assert(sizeof(pthread_key_t) == 8, "pthread key ABI");
_Static_assert(PTHREAD_KEYS_MAX >= _POSIX_THREAD_KEYS_MAX, "minimum key capacity");
_Static_assert(PTHREAD_DESTRUCTOR_ITERATIONS >= _POSIX_THREAD_DESTRUCTOR_ITERATIONS, "minimum destructor iterations");

struct specific_context {
    pthread_key_t key, plain;
    int calls, cleaned, errors, mode;
};
static void specific_cleanup(void *argument) {
    struct specific_context *context = argument;
    if (pthread_getspecific(context->key) != context) context->errors++;
    context->cleaned++;
}
static void specific_destructor(void *argument) {
    struct specific_context *context = argument;
    int old = 99;
    if (pthread_getspecific(context->key) != NULL
            || pthread_getspecific(context->plain) != context
            || context->cleaned != (context->mode == 1 || context->mode == 2)
            || pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old)
            || old != PTHREAD_CANCEL_DISABLE || errno != 777) context->errors++;
    pthread_testcancel();
    pthread_key_t temporary;
    if (pthread_key_create(&temporary, NULL)
            || pthread_getspecific(temporary) != NULL
            || pthread_setspecific(temporary, context)
            || pthread_key_delete(temporary)) context->errors++;
    void *block = malloc(64);
    if (!block) context->errors++;
    free(block);
    context->calls++;
    if (context->mode == 3) {
        if (pthread_key_delete(context->key)
                || pthread_key_create(&context->key, specific_destructor)
                || pthread_getspecific(context->key) != NULL) context->errors++;
        return;
    }
    /* Re-arm even the final pass: the implementation must bound destruction. */
    if (pthread_setspecific(context->key, context)) context->errors++;
}
static void *specific_thread(void *argument) {
    struct specific_context *context = argument;
    errno = 777;
    if (pthread_getspecific(context->key) != NULL || pthread_getspecific(context->plain) != NULL
            || pthread_setspecific(context->key, context)
            || pthread_setspecific(context->plain, context)) context->errors++;
    pthread_cleanup_push(specific_cleanup, context);
    if (context->mode == 1) pthread_exit(context);
    if (context->mode == 2) {
        if (pthread_cancel(pthread_self())
                || pthread_setspecific(context->plain, NULL)
                || pthread_getspecific(context->plain) != NULL
                || pthread_setspecific(context->plain, context)) context->errors++;
        /* The key operations above must return before the cancellation point. */
        pthread_testcancel();
        context->errors++;
    }
    pthread_cleanup_pop(0);
    return context;
}
static int specifics(void) {
    errno = 123;
    pthread_key_t keys[PTHREAD_KEYS_MAX];
    for (unsigned i = 0; i < PTHREAD_KEYS_MAX; i++) {
        if (pthread_key_create(&keys[i], NULL) || pthread_getspecific(keys[i]) != NULL) return 230;
    }
    pthread_key_t extra = 987;
    if (pthread_key_create(&extra, NULL) != EAGAIN || extra != 987 || errno != 123) return 231;
    if (pthread_setspecific(keys[0], keys) || pthread_key_delete(keys[0])
            || pthread_key_create(&extra, NULL) || extra == keys[0]
            || pthread_getspecific(extra) != NULL || pthread_key_delete(extra)
            || pthread_key_delete(keys[0]) != EINVAL || errno != 123) return 232;
    for (unsigned i = 1; i < PTHREAD_KEYS_MAX; i++) {
        if (pthread_key_delete(keys[i])) return 233;
    }
    struct specific_context context = {0};
    if (pthread_key_create(&context.key, specific_destructor)
            || pthread_key_create(&context.plain, NULL)
            || pthread_setspecific(context.key, &extra)) return 234;
    for (int mode = 0; mode < 4; mode++) {
        context.mode = mode;
        context.calls = context.cleaned = context.errors = 0;
        pthread_t thread;
        void *result = NULL;
        if (pthread_create(&thread, NULL, specific_thread, &context)
                || pthread_join(thread, &result)
                || result != (mode == 2 ? PTHREAD_CANCELED : &context)
                || context.calls != (mode == 3 ? 1 : PTHREAD_DESTRUCTOR_ITERATIONS)
                || context.cleaned != (mode == 1 || mode == 2) || context.errors
                || pthread_getspecific(context.key) != (mode == 3 ? NULL : &extra) || errno != 123) return 235 + mode;
    }
    if (pthread_setspecific(context.key, NULL) || pthread_key_delete(context.key)
            || pthread_key_delete(context.plain) || errno != 123) return 238;
    return 0;
}


_Static_assert(sizeof(pthread_once_t) == 8, "once control ABI");
_Static_assert(_Alignof(pthread_once_t) == 8, "once control alignment");
static pthread_once_t basic_once = PTHREAD_ONCE_INIT;
static pthread_once_t inner_once = PTHREAD_ONCE_INIT;
static pthread_once_t pending_once = PTHREAD_ONCE_INIT;
static pthread_once_t exited_once = PTHREAD_ONCE_INIT;
static int once_calls, inner_calls, pending_calls, exit_calls, once_errors, many_calls;
static pthread_once_t many_once[129] = { PTHREAD_ONCE_INIT };
static void initialize_many(void) { many_calls++; }
static void initialize_inner(void) { inner_calls++; }
static void initialize_basic(void) {
    once_calls++;
    if (pthread_once(&inner_once, initialize_inner)) once_errors++;
    pthread_key_t key;
    if (pthread_key_create(&key, NULL) || pthread_setspecific(key, &once_calls)
            || pthread_getspecific(key) != &once_calls || pthread_key_delete(key)) once_errors++;
    void *block = malloc(64);
    if (!block) once_errors++;
    free(block);
}
static void initialize_pending(void) { pending_calls++; }
static void initialize_exit(void) {
    exit_calls++;
    pthread_exit(&exit_calls);
}
static void initialize_retry(void) { exit_calls++; }
static void *once_pending_thread(void *argument) {
    if (pthread_cancel(pthread_self()) || pthread_once(&pending_once, initialize_pending)
            || pending_calls != 1 || errno != 0) once_errors++;
    /* A pending request survives both initialization and the completed fast path. */
    if (pthread_once(&pending_once, initialize_pending)) once_errors++;
    pthread_testcancel();
    return argument;
}
static void *once_exit_thread(void *argument) {
    (void)argument;
    pthread_once(&exited_once, initialize_exit);
    return NULL;
}
static int once_initialization(void) {
    errno = 123;
    if (pthread_once(&basic_once, initialize_basic) || pthread_once(&basic_once, initialize_basic)
            || pthread_once(&inner_once, initialize_inner) || once_calls != 1 || inner_calls != 1
            || once_errors || errno != 123) return 240;
    for (unsigned i = 0; i < 129; i++) {
        if (pthread_once(&many_once[i], initialize_many)
                || pthread_once(&many_once[i], initialize_many)) return 243;
    }
    if (many_calls != 129) return 243;
    pthread_t thread;
    void *value = NULL;
    if (pthread_create(&thread, NULL, once_pending_thread, NULL) || pthread_join(thread, &value)
            || value != PTHREAD_CANCELED || once_errors || pending_calls != 1
            || pthread_once(&pending_once, initialize_pending) || pending_calls != 1) return 241;
    if (pthread_create(&thread, NULL, once_exit_thread, NULL) || pthread_join(thread, &value)
            || value != &exit_calls || exit_calls != 1
            || pthread_once(&exited_once, initialize_retry) || exit_calls != 2 || errno != 123) return 242;
    return 0;
}

_Static_assert(sizeof(pthread_mutex_t) == 32, "mutex ABI");
_Static_assert(_Alignof(pthread_mutex_t) == 8, "mutex alignment");
_Static_assert(sizeof(pthread_mutexattr_t) == 16, "mutex attribute ABI");
_Static_assert(_Alignof(pthread_mutexattr_t) == 8, "mutex attribute alignment");
static pthread_mutex_t static_mutex = PTHREAD_MUTEX_INITIALIZER;
static void *foreign_mutex(void *argument) {
    pthread_mutex_t *mutex = argument;
    errno = 777;
    if (pthread_mutex_trylock(mutex) != EBUSY || pthread_mutex_unlock(mutex) != EPERM
            || errno != 777) return (void *)1;
    return NULL;
}
static int mutexes(void) {
    pthread_mutexattr_t attr;
    pthread_mutex_t mutex;
    int kind = 99;
    errno = 123;
    if (pthread_mutexattr_init(&attr) || pthread_mutexattr_gettype(&attr, &kind)
            || kind != PTHREAD_MUTEX_DEFAULT || errno != 123) return 250;
    if (pthread_mutexattr_settype(&attr, 99) != EINVAL
            || pthread_mutexattr_gettype(&attr, &kind) || kind != PTHREAD_MUTEX_DEFAULT) return 251;
    if (pthread_mutex_lock(&static_mutex) || pthread_mutex_trylock(&static_mutex) != EBUSY
            || pthread_mutex_destroy(&static_mutex) != EBUSY
            || pthread_mutex_unlock(&static_mutex) || pthread_mutex_destroy(&static_mutex)) return 252;
    if (pthread_mutex_lock(&static_mutex) != EINVAL || pthread_mutex_destroy(&static_mutex) != EINVAL
            || pthread_mutex_init(&static_mutex, NULL) || pthread_mutex_trylock(&static_mutex)
            || pthread_mutex_unlock(&static_mutex) || pthread_mutex_destroy(&static_mutex)) return 253;
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK)
            || pthread_mutex_init(&mutex, &attr) || pthread_mutex_lock(&mutex)
            || pthread_mutex_lock(&mutex) != EDEADLK || pthread_mutex_trylock(&mutex) != EBUSY) return 254;
    pthread_t child;
    void *value = (void *)99;
    if (pthread_create(&child, NULL, foreign_mutex, &mutex) || pthread_join(child, &value)
            || value != NULL || pthread_mutex_unlock(&mutex)
            || pthread_mutex_unlock(&mutex) != EPERM || pthread_mutex_destroy(&mutex)) return 255;
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)
            || pthread_mutex_init(&mutex, &attr) || pthread_mutex_lock(&mutex)
            || pthread_mutex_trylock(&mutex) || pthread_mutex_lock(&mutex)
            || pthread_mutex_unlock(&mutex) || pthread_mutex_unlock(&mutex)
            || pthread_mutex_destroy(&mutex) != EBUSY || pthread_mutex_unlock(&mutex)
            || pthread_mutex_destroy(&mutex)) return 256;
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL)
            || pthread_mutexattr_gettype(&attr, &kind) || kind != PTHREAD_MUTEX_NORMAL
            || pthread_mutex_init(&mutex, &attr) || pthread_mutex_trylock(&mutex)
            || pthread_mutex_unlock(&mutex) || pthread_mutex_destroy(&mutex)
            || pthread_mutexattr_destroy(&attr) || pthread_mutexattr_gettype(&attr, &kind) != EINVAL
            || pthread_mutex_init(&mutex, &attr) != EINVAL || errno != 123) return 257;
    if (pthread_mutex_init(NULL, NULL) != EINVAL || pthread_mutex_lock(NULL) != EINVAL
            || pthread_mutex_trylock(NULL) != EINVAL || pthread_mutex_unlock(NULL) != EINVAL
            || pthread_mutex_destroy(NULL) != EINVAL || pthread_mutexattr_init(NULL) != EINVAL
            || errno != 123) return 258;
    pthread_mutex_t many[129];
    for (unsigned int i = 0; i < 129; ++i) {
        if (pthread_mutex_init(&many[i], NULL) || pthread_mutex_trylock(&many[i])) return 259;
    }
    for (unsigned int i = 0; i < 129; ++i) {
        if (pthread_mutex_unlock(&many[i]) || pthread_mutex_destroy(&many[i])) return 260;
    }
    return errno == 123 ? 0 : 261;
}

static int timed_mutexes(void) {
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    const struct timespec invalid = {0, 1000000000}, past = {-1, 0};
    errno = 123;
    if (pthread_mutex_clocklock(&mutex, 99, &past) != EINVAL || errno != 123) return 283;
    if (pthread_mutex_timedlock(&mutex, &invalid) || errno != 123
            || pthread_mutex_unlock(&mutex) || pthread_mutex_clocklock(&mutex, CLOCK_MONOTONIC, &past)
            || pthread_mutex_unlock(&mutex) || pthread_mutex_destroy(&mutex)) return 282;
    if (pthread_mutex_init(&mutex, NULL) || pthread_mutex_lock(&mutex)
            || pthread_mutex_timedlock(&mutex, &invalid) != EINVAL
            || pthread_mutex_timedlock(&mutex, &past) != ETIMEDOUT
            || pthread_mutex_clocklock(&mutex, CLOCK_MONOTONIC, &past) != ETIMEDOUT
            || errno != 123 || pthread_mutex_unlock(&mutex) || pthread_mutex_destroy(&mutex)) return 284;
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) || pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)
            || pthread_mutex_init(&mutex, &attr) || pthread_mutex_lock(&mutex)
            || pthread_mutex_timedlock(&mutex, &invalid) || pthread_mutex_clocklock(&mutex, CLOCK_MONOTONIC, &past)
            || pthread_mutex_unlock(&mutex) || pthread_mutex_unlock(&mutex)
            || pthread_mutex_unlock(&mutex) || pthread_mutex_destroy(&mutex)) return 285;
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK)
            || pthread_mutex_init(&mutex, &attr) || pthread_mutex_lock(&mutex)
            || pthread_mutex_timedlock(&mutex, &past) != EDEADLK
            || pthread_mutex_unlock(&mutex) || pthread_mutex_destroy(&mutex)
            || pthread_mutexattr_destroy(&attr) || errno != 123) return 286;
    return 0;
}

static void *clock_reader(void *expected) {
    struct timespec value;
    errno = 777;
    if (clock_gettime(CLOCK_REALTIME, &value) || errno != 777
            || value.tv_sec < *(time_t *)expected || value.tv_sec > *(time_t *)expected + 1)
        return (void *)1;
    return NULL;
}
static int sleeps(void) {
    struct timespec request = {0, 0};
    struct timespec remaining = {777, 888};
    errno = 123;
    if (nanosleep(&request, 0) || errno != 123) return 287;
    if (nanosleep(&request, &remaining) || errno != 123
        || remaining.tv_sec != 777 || remaining.tv_nsec != 888) return 287;
    if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &request, &remaining)
        || errno != 123 || remaining.tv_sec != 777 || remaining.tv_nsec != 888) return 288;
    request.tv_nsec = 1000000000;
    if (nanosleep(&request, &remaining) != -1 || errno != EINVAL
        || remaining.tv_sec != 777 || remaining.tv_nsec != 888) return 289;
    errno = 123;
    if (clock_nanosleep(CLOCK_REALTIME, 0, &request, &remaining) != EINVAL
        || errno != 123 || remaining.tv_sec != 777 || remaining.tv_nsec != 888) return 290;
    request.tv_nsec = 0;
    request.tv_sec = -1;
    if (clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &request, &remaining) != EINVAL
        || errno != 123) return 291;
    request.tv_sec = 0;
    if (clock_nanosleep(17, 0, &request, &remaining) != EINVAL
        || clock_nanosleep(CLOCK_MONOTONIC, 2, &request, &remaining) != EINVAL
        || clock_nanosleep(CLOCK_REALTIME, 0, 0, &remaining) != EFAULT
        || errno != 123) return 292;
    if (nanosleep(0, &remaining) != -1 || errno != EFAULT) return 293;
    errno = 123;
    if (clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &request, &remaining)
        || errno != 123 || remaining.tv_sec != 777 || remaining.tv_nsec != 888) return 294;
    return 0;
}

static int clocks(void) {
    struct timespec saved, before, after, value = {987, 654}, resolution;
    errno = 123;
    if (clock_getres(CLOCK_REALTIME, NULL) || clock_getres(CLOCK_MONOTONIC, &resolution)
            || errno != 123 || resolution.tv_sec || resolution.tv_nsec < 1
            || resolution.tv_nsec > 20000000 || sizeof(clockid_t) != 4) return 270;
    if (clock_gettime(CLOCK_REALTIME, &saved) || clock_gettime(CLOCK_MONOTONIC, &before)
            || errno != 123 || saved.tv_nsec < 0 || saved.tv_nsec >= 1000000000) return 271;
    if (clock_gettime(99, &value) != -1 || errno != EINVAL || value.tv_sec != 987
            || value.tv_nsec != 654 || clock_getres(99, NULL) != -1 || errno != EINVAL) return 272;
    if (clock_gettime(CLOCK_REALTIME, NULL) != -1 || errno != EFAULT
            || clock_settime(CLOCK_REALTIME, NULL) != -1 || errno != EFAULT) return 273;
    if (clock_settime(CLOCK_MONOTONIC, &value) != -1 || errno != EINVAL) return 274;
    const struct timespec invalid[] = {{-1, 0}, {0, -1}, {0, 1000000000}};
    for (unsigned int i = 0; i < 3; i++)
        if (clock_settime(CLOCK_REALTIME, &invalid[i]) != -1 || errno != EINVAL) return 275;
    value.tv_sec = 20000000000LL; value.tv_nsec = 12345;
    errno = 123;
    if (clock_settime(CLOCK_REALTIME, &value) || errno != 123
            || clock_gettime(CLOCK_REALTIME, &after) || errno != 123
            || after.tv_sec < value.tv_sec - 1 || after.tv_sec > value.tv_sec + 1) return 276;
    pthread_t child;
    time_t expected = value.tv_sec - 1;
    void *result = (void *)99;
    if (pthread_create(&child, NULL, clock_reader, &expected)
            || pthread_join(child, &result) || result) return 277;
    value.tv_sec = 2; value.tv_nsec = 0;
    if (clock_settime(CLOCK_REALTIME, &value) || clock_gettime(CLOCK_REALTIME, &after)
            || after.tv_sec < 1 || after.tv_sec > 3
            || clock_gettime(CLOCK_MONOTONIC, &after) || after.tv_sec < before.tv_sec
            || (after.tv_sec == before.tv_sec && after.tv_nsec < before.tv_nsec)) return 278;
    value.tv_sec = INT64_MAX; value.tv_nsec = 999999999;
    if (clock_settime(CLOCK_REALTIME, &value)) return 279;
    after.tv_sec = 987; after.tv_nsec = 654;
    if (clock_gettime(CLOCK_REALTIME, &after) != -1 || errno != EOVERFLOW
            || after.tv_sec != 987 || after.tv_nsec != 654) return 280;
    if (clock_settime(CLOCK_REALTIME, &saved)) return 281;
    return 0;
}

static int credentials(void) {
    errno = 777;
    if (getuid() || geteuid() || getgid() || getegid() || errno != 777) return 185;
    if (setuid((uid_t)-1) != -1 || errno != EINVAL
            || seteuid((uid_t)-1) != -1 || errno != EINVAL
            || setgid((gid_t)-1) != -1 || errno != EINVAL
            || setegid((gid_t)-1) != -1 || errno != EINVAL) return 186;
    errno = 888;
    if (getuid() || geteuid() || getgid() || getegid() || errno != 888) return 187;
    if (setegid(77) || getgid() || getegid() != 77 || errno != 888) return 188;
    if (setgid(33) || getgid() != 33 || getegid() != 33 || errno != 888) return 189;
    if (seteuid(1000) || getuid() || geteuid() != 1000 || errno != 888) return 190;
    if (setgid(0) != -1 || errno != EPERM || getgid() != 33 || getegid() != 33) return 191;
    errno = 999;
    if (setegid(33) || seteuid(0) || getuid() || geteuid() || errno != 999) return 192;
    if (setgid(0) || setegid(0) || getgid() || getegid() || errno != 999) return 193;
    if (setuid(1000) || getuid() != 1000 || geteuid() != 1000 || errno != 999) return 194;
    if (setuid(0) != -1 || errno != EPERM || seteuid(0) != -1 || errno != EPERM
            || getuid() != 1000 || geteuid() != 1000) return 195;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || !argv || argv[2] != NULL || !same(argv[0], "posix-abi-probe", 15)
            || !same(argv[1], "argument", 9) || !environ || environ[0] != NULL) return 1;
    if (stafeto_posix_abi_version() != ABI_VERSION ||
            (char *)__errno_location() - (char *)__builtin_thread_pointer() != STAFETO_ERRNO_OFFSET) return 33;
    errno = 123;
    int fd = open("/etc/motd", O_RDONLY | O_CLOEXEC);
    if (fd != 3 || errno != 123) return 2;
    int copy = dup(fd);
    char text[32] = {0};
    if (copy != 4 || read(fd, text, 3) != 3 || !same(text, "sta", 3)) return 3;
    if (read(copy, text, 4) != 4 || !same(text, "feto", 4)) return 4;
    if (close(fd) != 0 || read(copy, text, 7) != 7 || !same(text, " ramfs\n", 7)) return 5;
    if (read(fd, NULL, 0) != -1 || errno != EBADF || close(copy) != 0) return 6;
    if (open("/missing", O_RDONLY) != -1 || errno != ENOENT) return 7;
    if (open(NULL, O_RDONLY) != -1 || errno != EFAULT) return 8;
    if (open("/etc/motd", O_ACCMODE) != -1 || errno != EINVAL) return 9;
    char too_long[130];
    for (size_t i = 0; i < sizeof(too_long) - 1; i++) too_long[i] = 'x';
    too_long[129] = 0;
    if (open(too_long, O_RDONLY) != -1 || errno != ENAMETOOLONG) return 10;
    if (chdir("/etc") != 0 || getcwd(text, sizeof(text)) != text || !same(text, "/etc", 5)) return 11;
    if (getcwd(text, 4) != NULL || errno != ERANGE) return 12;
    fd = open("motd", O_RDONLY);
    if (fd != 3 || lseek(fd, -1, SEEK_END) != 13 || read(fd, text, 1) != 1 || text[0] != '\n') return 13;
    if (lseek(fd, INT64_MAX, SEEK_SET) != INT64_MAX) return 14;
    if (lseek(fd, 1, SEEK_CUR) != -1 || errno != EOVERFLOW || lseek(fd, 0, SEEK_CUR) != INT64_MAX) return 15;
    if (lseek(fd, -1, SEEK_SET) != -1 || errno != EINVAL) return 16;
    if (lseek(fd, 0, 99) != -1 || errno != EINVAL) return 17;
    if (lseek(fd, 0, SEEK_DATA) != 0 || lseek(fd, 0, SEEK_HOLE) != 14) return 18;
    if (write(fd, NULL, 0) != -1 || errno != EBADF || close(fd) != 0) return 19;
    int saved = dup(STDOUT_FILENO);
    fd = open("/tmp/probe", O_RDWR);
    if (saved != 3 || fd != 4 || dup2(fd, 1) != 1 || close(fd) != 0) return 20;
    if (write(1, "Rust C ABI", 10) != 10 || lseek(1, 0, SEEK_SET) != 0
            || read(1, text, 10) != 10 || !same(text, "Rust C ABI", 10)) return 21;
    if (dup2(-1, 1) != -1 || errno != EBADF || lseek(1, 0, SEEK_CUR) != 10) return 22;
    if (dup3(1, 1, O_CLOEXEC) != -1 || errno != EINVAL) return 23;
    if (dup3(1, 5, O_CLOFORK) != 5 || close(5) != 0) return 24;
    if (dup2(saved, 1) != 1 || close(saved) != 0) return 25;
    if (lseek(1, 0, SEEK_SET) != -1 || errno != ESPIPE) return 26;
    if (read(1, text, sizeof(text)) != -1 || errno != EBADF) return 27;
    if (read(-1, text, sizeof(text)) != -1 || errno != EBADF) return 28;
    if (write(1, NULL, 1) != -1 || errno != EFAULT) return 29;
    if (close(0) != 0 || open("motd", O_RDONLY) != 0 || read(0, text, 1) != 1 || text[0] != 's') return 30;
    if (close(0) != 0 || close(0) != -1 || errno != EBADF) return 31;
    int metadata_result = metadata();
    if (metadata_result) return metadata_result;
    int directory_result = directories();
    if (directory_result) return directory_result;
    int thread_result = threads();
    if (thread_result) return thread_result;
    int cancellation_result = cancellation();
    if (cancellation_result) return cancellation_result;
    int specific_result = specifics();
    if (specific_result) return specific_result;
    int once_result = once_initialization();
    if (once_result) return once_result;
    int mutex_result = mutexes();
    if (mutex_result) return mutex_result;
    int clock_result = clocks();
    if (clock_result) return clock_result;
    int sleep_result = sleeps();
    if (sleep_result) return sleep_result;
    int timed_result = timed_mutexes();
    if (timed_result) return timed_result;
    int allocation_result = allocations();
    if (allocation_result) return allocation_result;
    int collation_result = collation();
    if (collation_result) return collation_result;
    int signal_result = signals();
    if (signal_result) return signal_result;
    int scan_result = scans();
    if (scan_result) return scan_result;
    int credentials_result = credentials();
    if (credentials_result) return credentials_result;
    const char result[] = "posix-abi-probe: ok\n";
    if (write(1, result, sizeof(result) - 1) != (ssize_t)(sizeof(result) - 1)) return 32;
    return 0;
}
