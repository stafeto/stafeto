/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The first C program on relibc over the Rust POSIX layer: stdio with a
 * float, malloc, a file of the RAM file service through fopen and fread,
 * ENOENT, clock_gettime, and errno in the static TLS relibc built. */
#include <aio.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <complex.h>
#include <sys/select.h>
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
        int bit = 0;
        if (strcmp(entry->d_name, ".") == 0) { CHECK(entry->d_type == DT_DIR); bit = 1; }
        else if (strcmp(entry->d_name, "..") == 0) { CHECK(entry->d_type == DT_DIR); bit = 2; }
        else if (strcmp(entry->d_name, "motd") == 0) { CHECK(entry->d_type == DT_REG); bit = 4; }
        else if (strcmp(entry->d_name, "passwd") == 0) { CHECK(entry->d_type == DT_REG); bit = 8; }
        else if (strcmp(entry->d_name, "group") == 0) { CHECK(entry->d_type == DT_REG); bit = 16; }
        else CHECK(!"an entry /etc does not have");
        CHECK((seen & bit) == 0);
        seen |= bit;
    }
    CHECK(seen == 31);
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
    CHECK(getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur == 64);

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
    CHECK(dup2(file, 0) == 0 && (fcntl(0, F_GETFL) & (O_ACCMODE | O_APPEND)) == O_RDONLY);
    CHECK(fcntl(0, F_SETFL, fcntl(0, F_GETFL)) == 0);
    CHECK(fcntl(0, F_SETFL, O_NONBLOCK) == -1 && errno == EINVAL);
    CHECK(dup2(input, 0) == 0 && close(input) == 0 && close(file) == 0);
    /* F_GETFL gives the flags the file was opened with: the access mode and
     * O_APPEND, shared by a duplicate; mkostemp passes O_APPEND on. */
    int appended = open("/tmp/probe-flags", O_WRONLY | O_CREAT | O_APPEND, 0600);
    int readwrite = open("/tmp/probe-flags", O_RDWR);
    CHECK(appended >= 0 && readwrite >= 0);
    CHECK((fcntl(appended, F_GETFL) & (O_ACCMODE | O_APPEND)) == (O_WRONLY | O_APPEND));
    CHECK((fcntl(readwrite, F_GETFL) & (O_ACCMODE | O_APPEND)) == O_RDWR);
    int shared = dup(appended);
    CHECK(shared >= 0 && (fcntl(shared, F_GETFL) & (O_ACCMODE | O_APPEND)) == (O_WRONLY | O_APPEND));
    char temp[] = "/tmp/probe-XXXXXX";
    int made = mkostemp(temp, O_CLOEXEC | O_APPEND);
    CHECK(made >= 0 && (fcntl(made, F_GETFL) & (O_ACCMODE | O_APPEND)) == (O_RDWR | O_APPEND));
    CHECK(unlink(temp) == 0 && close(made) == 0 && close(shared) == 0);
    CHECK(close(appended) == 0 && close(readwrite) == 0 && unlink("/tmp/probe-flags") == 0);

    /* The table holds 64 descriptors: numbers up to 63 are taken by dup2,
     * dup3 and F_DUPFD, and 64 is EBADF (EINVAL for the minimum of F_DUPFD). */
    CHECK(dup2(2, 42) == 42 && (fcntl(42, F_GETFL) & O_ACCMODE) == O_WRONLY);
    CHECK(dup3(1, 63, O_CLOEXEC) == 63 && fcntl(63, F_GETFD) == FD_CLOEXEC);
    CHECK(dup2(2, 64) == -1 && errno == EBADF && dup3(1, 64, 0) == -1 && errno == EBADF);
    CHECK(fcntl(2, F_DUPFD, 64) == -1 && errno == EINVAL);
    int far = fcntl(2, F_DUPFD, 50);
    CHECK(far == 50 && close(far) == 0 && close(42) == 0 && close(63) == 0);

    /* writev keeps the bytes of the parts before one that fails; a count
     * of parts outside 1 to IOV_MAX is EINVAL. */
    int scratch = open("/tmp/probe", O_RDWR);
    struct iovec parts[2] = {{"ab", 2}, {NULL, 5}};
    CHECK(scratch >= 0 && writev(scratch, parts, 2) == 2);
    CHECK(writev(scratch, parts, 0) == -1 && errno == EINVAL && close(scratch) == 0);

    /* strtod converts a decimal constant whole, whatever its exponent: the
     * digits are not accumulated in floating point, the string past the
     * constant stays, no conversion leaves *endptr at the string, and the
     * range errors say ERANGE. */
    char *end;
    errno = 0;
    CHECK(strtod("1e308", &end) == 1e308 && *end == 0 && errno == 0);
    CHECK(strtod("1.7976931348623157e308x", &end) == 1.7976931348623157e308 && *end == 'x');
    CHECK(strtod("123456789012345678901234567890e-10", &end) == 123456789012345678901234567890e-10);
    CHECK(strtod("0.1", &end) == 0.1 && strtod("2.2250738585072014e-308", &end) == 2.2250738585072014e-308);
    CHECK(strtod("4.9e-324", &end) == 4.9e-324 && strtod("  -.5e1z", &end) == -5.0 && *end == 'z');
    CHECK(strtod("1e", &end) == 1.0 && *end == 'e' && strtod("1.e+", &end) == 1.0 && *end == 'e');
    CHECK(strtod("1e400", &end) > 1e308 && errno == ERANGE && *end == 0);
    errno = 0;
    CHECK(strtod("-1e400", &end) < -1e308 && errno == ERANGE);
    errno = 0;
    CHECK(strtod("1e-400", &end) == 0.0 && errno == ERANGE);
    errno = 0;
    CHECK(strtod("-abc", &end) == 0.0 && strcmp(end, "-abc") == 0 && errno == 0);
    CHECK(strtod("0x1p-1074", &end) == 4.9e-324 && *end == 0);
    CHECK(strtod("0x1.8p3", &end) == 12.0 && strtod("0x1p1000", &end) == 0x1p1000);
    CHECK(strtod("0xg", &end) == 0.0 && strcmp(end, "xg") == 0);
    CHECK(strtof("3.4028234e38", &end) == 3.4028234e38f && strtof("1.17549435e-38", &end) == 1.17549435e-38f);
    CHECK(strtof("16777217", &end) == 16777216.0f && strtof("0.1", &end) == 0.1f);
    /* clog near the unit circle: x*x + y*y - 1 is about 2^-70 here, and the
     * real part -0x1.16ea2fa2cp-72 needs it formed without cancelling (the
     * sum of logl(x) and log1pl(t*t)/2 gave -0x1.16ea2fa2bfcp-72). */
    double complex near_one = CMPLX(0.7071067257624838, 0.7071068366106069);
    CHECK(creal(clog(near_one)) == -0x1.16ea2fa2c0000p-72);
    /* select names more descriptors than a watch takes: a descriptor that is
     * none gives EBADF before EINVAL does. */
    fd_set many;
    FD_ZERO(&many);
    for (int i = 0; i < 41; i++) FD_SET(i, &many);
    struct timeval none = {0, 0};
    errno = 0;
    CHECK(select(41, &many, NULL, NULL, &none) == -1 && errno == EBADF);
    volatile double two = 2.0, ten = 10.0, zero = 0.0;
    CHECK(fabs(sqrt(two) - 1.41421356) < 1e-6 && pow(two, ten) == 1024.0 && sin(zero) == 0.0);
    printf("relibc-hello: directories, stat, descriptors, mmap, math\n");
    return 0;
}

/* Streams over memory: an fmemopen stream ends with its buffer (a write
 * past it is short with ENOSPC, a seek past it EINVAL), and the file behind
 * a memory stream does not outlive an exec. */
static int memory_streams(void) {
    char buffer[8];
    memset(buffer, 'x', sizeof buffer);
    FILE *fixed = fmemopen(buffer, sizeof buffer, "w");
    CHECK(fixed != NULL);
    errno = 0;
    CHECK(fwrite("0123456789ab", 1, 12, fixed) == 8 && ferror(fixed) && errno == ENOSPC);
    CHECK(fflush(fixed) == 0);
    CHECK(memcmp(buffer, "01234567", 8) == 0);
    CHECK(fclose(fixed) == 0);

    char update[8] = "abc";
    FILE *seekable = fmemopen(update, sizeof update, "r+");
    CHECK(seekable != NULL);
    errno = 0;
    CHECK(fseek(seekable, 9, SEEK_SET) == -1 && errno == EINVAL);
    CHECK(fseek(seekable, 8, SEEK_SET) == 0 && ftell(seekable) == 8);
    CHECK(fseek(seekable, 2, SEEK_SET) == 0 && fgetc(seekable) == 'c');
    CHECK(fclose(seekable) == 0);

    char *text = NULL;
    size_t length = 0;
    FILE *growing = open_memstream(&text, &length);
    CHECK(growing != NULL && fprintf(growing, "grown %d", 7) > 0 && fflush(growing) == 0);
    CHECK(length == 7 && strcmp(text, "grown 7") == 0);
    int behind = fileno(growing);
    CHECK(behind >= 0 && (fcntl(behind, F_GETFD) & FD_CLOEXEC) != 0);
    CHECK(fclose(growing) == 0);
    free(text);
    printf("relibc-hello: memory streams: short write ENOSPC, seek EINVAL, close-on-exec\n");
    return 0;
}

static volatile int aio_told;
static void aio_tell(union sigval value) { aio_told = (int)(intptr_t)value.sival_ptr; }

static int wait_aio(struct aiocb *cb) {
    for (int i = 0; i < 2000 && aio_error(cb) == EINPROGRESS; i++) {
        struct timespec nap = {0, 1000000};
        nanosleep(&nap, NULL);
    }
    return aio_error(cb);
}

/* Reads and writes of a file take all that is asked, whatever the size of
 * a message of the file service; O_SYNC opens; aio runs on threads. */
static int long_transfers_and_aio(void) {
    static unsigned char pattern[6000], back[6000];
    for (int i = 0; i < 6000; i++) pattern[i] = (unsigned char)(i * 7 + (i >> 8));
    int fd = open("/tmp-long", O_RDWR | O_CREAT | O_TRUNC | O_SYNC, 0600);
    CHECK(fd >= 0);
    CHECK(write(fd, pattern, 3000) == 3000);
    CHECK(pwrite(fd, pattern + 3000, 3000, 3000) == 3000);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    CHECK(read(fd, back, 6000) == 6000 && memcmp(back, pattern, 6000) == 0);
    memset(back, 0, sizeof back);
    CHECK(pread(fd, back, 5000, 500) == 5000 && memcmp(back, pattern + 500, 5000) == 0);
    CHECK(read(fd, back, 10) == 0);

#if !defined(_POSIX_ASYNCHRONOUS_IO) || _POSIX_ASYNCHRONOUS_IO < 200112L
    CHECK(!"_POSIX_ASYNCHRONOUS_IO is claimed");
#endif
    CHECK(sysconf(_SC_ASYNCHRONOUS_IO) == _POSIX_ASYNCHRONOUS_IO);
    CHECK(sysconf(_SC_AIO_MAX) == 128 && sysconf(_SC_AIO_LISTIO_MAX) == 128);

    struct aiocb fresh;
    memset(&fresh, 0, sizeof fresh);
    CHECK(aio_error(&fresh) == EINVAL);
    errno = 0;
    CHECK(aio_return(&fresh) == -1 && errno == EINVAL);

    struct aiocb cb;
    memset(&cb, 0, sizeof cb);
    cb.aio_fildes = fd;
    cb.aio_buf = pattern;
    cb.aio_nbytes = 2500;
    cb.aio_offset = 6000;
    cb.aio_sigevent.sigev_notify = SIGEV_THREAD;
    cb.aio_sigevent.sigev_notify_function = aio_tell;
    cb.aio_sigevent.sigev_value.sival_ptr = (void *)(intptr_t)42;
    CHECK(aio_write(&cb) == 0);
    CHECK(wait_aio(&cb) == 0);
    CHECK(aio_return(&cb) == 2500);
    errno = 0;
    CHECK(aio_return(&cb) == -1 && errno == EINVAL && aio_error(&cb) == EINVAL);
    for (int i = 0; i < 2000 && aio_told == 0; i++) {
        struct timespec nap = {0, 1000000};
        nanosleep(&nap, NULL);
    }
    CHECK(aio_told == 42);
    CHECK(aio_cancel(fd, &cb) == AIO_ALLDONE && aio_cancel(fd, NULL) == AIO_ALLDONE);

    memset(back, 0, sizeof back);
    struct aiocb rd;
    memset(&rd, 0, sizeof rd);
    rd.aio_fildes = fd;
    rd.aio_buf = back;
    rd.aio_nbytes = 2500;
    rd.aio_offset = 6000;
    CHECK(aio_read(&rd) == 0 && wait_aio(&rd) == 0 && aio_return(&rd) == 2500);
    CHECK(memcmp(back, pattern, 2500) == 0);

    /* A bad descriptor is the error of the request, not of the call. */
    struct aiocb bad;
    memset(&bad, 0, sizeof bad);
    bad.aio_fildes = -1;
    bad.aio_buf = back;
    bad.aio_nbytes = 1;
    CHECK(aio_read(&bad) == 0 && wait_aio(&bad) == EBADF && aio_return(&bad) == -1);
    CHECK(aio_fsync(O_SYNC, &bad) == -1 && errno == EBADF);

    /* A list that waits: a write then a read of the bytes, in order. */
    struct aiocb w2, r2;
    memset(&w2, 0, sizeof w2);
    memset(&r2, 0, sizeof r2);
    unsigned char out[16] = "list of two....", in[16] = {0};
    w2.aio_fildes = fd; w2.aio_buf = out; w2.aio_nbytes = 16; w2.aio_offset = 9000;
    w2.aio_lio_opcode = LIO_WRITE;
    r2.aio_fildes = fd; r2.aio_buf = in; r2.aio_nbytes = 16; r2.aio_offset = 9000;
    r2.aio_lio_opcode = LIO_READ;
    struct aiocb *list[2] = {&w2, &r2};
    CHECK(lio_listio(LIO_WAIT, list, 2, NULL) == 0);
    CHECK(aio_return(&w2) == 16 && aio_return(&r2) == 16 && memcmp(in, out, 16) == 0);

    /* Requests queued for one descriptor end with a result or ECANCELED. */
    struct aiocb many[8];
    for (int i = 0; i < 8; i++) {
        memset(&many[i], 0, sizeof many[i]);
        many[i].aio_fildes = fd; many[i].aio_buf = pattern; many[i].aio_nbytes = 2000;
        many[i].aio_offset = 10000 + 2000 * i;
        CHECK(aio_write(&many[i]) == 0);
    }
    int cancelled = aio_cancel(fd, NULL);
    CHECK(cancelled == AIO_CANCELED || cancelled == AIO_NOTCANCELED || cancelled == AIO_ALLDONE);
    for (int i = 0; i < 8; i++) {
        int err = wait_aio(&many[i]);
        CHECK(err == 0 || err == ECANCELED);
        CHECK(aio_return(&many[i]) == (err == 0 ? 2000 : -1));
    }
    /* A wait for a request ends when it does, and a wait that nothing ends
     * times out with EAGAIN. */
    CHECK(aio_write(&many[0]) == 0);
    const struct aiocb *wait_list[2] = {NULL, &many[0]};
    CHECK(aio_suspend(wait_list, 2, NULL) == 0 && aio_error(&many[0]) == 0);
    CHECK(aio_return(&many[0]) == 2000);
    struct aiocb idle;
    memset(&idle, 0, sizeof idle);
    const struct aiocb *idle_list[1] = {&idle};
    struct timespec shortly = {0, 20000000};
    errno = 0;
    CHECK(aio_suspend(idle_list, 1, &shortly) == -1 && errno == EAGAIN);
    CHECK(close(fd) == 0 && unlink("/tmp-long") == 0);
    printf("relibc-hello: long transfers, O_SYNC, aio on threads\n");
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

/* The constants of <unistd.h> and what sysconf answers, for every option of
 * POSIX.1-2024 that has an _SC_ name. The system claims a subprofile: the
 * version is 202405; a macro is defined only for an option that works, with
 * the value the standard allows (202405L, or any positive value for
 * JOB_CONTROL, REGEXP, SAVED_IDS and SHELL); sysconf then gives the macro's
 * value, and -1 with errno untouched for an option without a macro, except
 * the few that work at run time without a macro (runtime = 1). The XSI
 * option is not claimed. */
#ifndef _POSIX_SUBPROFILE
#error "unistd.h does not define _POSIX_SUBPROFILE"
#endif
#ifndef _POSIX_TIMERS
#error "unistd.h does not define _POSIX_TIMERS while the process service keeps timers"
#endif
#if defined(_XOPEN_UNIX) || defined(_XOPEN_VERSION) || defined(_XOPEN_SHM)
#error "unistd.h claims the XSI option"
#endif
_Static_assert(_POSIX_VERSION == 202405L, "_POSIX_VERSION is not POSIX.1-2024");

/* pthread.h after unistd.h: it must not define _POSIX_THREADS again. */
#include <pthread.h>
_Static_assert(_POSIX_THREADS == 202405L, "_POSIX_THREADS changed with the include order");

static int constants(void) {
    struct {
        const char *name;
        int key;
        long macro;
        char kind; /* V and O: 202405L when claimed (O is optional, V mandatory); P: positive */
        int runtime;
        int defined;
    } options[] = {
#ifdef _POSIX_ADVISORY_INFO
    {"_POSIX_ADVISORY_INFO", _SC_ADVISORY_INFO, _POSIX_ADVISORY_INFO, 'O', 0, 1},
#else
    {"_POSIX_ADVISORY_INFO", _SC_ADVISORY_INFO, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_ASYNCHRONOUS_IO
    {"_POSIX_ASYNCHRONOUS_IO", _SC_ASYNCHRONOUS_IO, _POSIX_ASYNCHRONOUS_IO, 'V', 0, 1},
#else
    {"_POSIX_ASYNCHRONOUS_IO", _SC_ASYNCHRONOUS_IO, -1, 'V', 0, 0},
#endif
#ifdef _POSIX_BARRIERS
    {"_POSIX_BARRIERS", _SC_BARRIERS, _POSIX_BARRIERS, 'V', 0, 1},
#else
    {"_POSIX_BARRIERS", _SC_BARRIERS, -1, 'V', 0, 0},
#endif
#ifdef _POSIX_CLOCK_SELECTION
    {"_POSIX_CLOCK_SELECTION", _SC_CLOCK_SELECTION, _POSIX_CLOCK_SELECTION, 'V', 1, 1},
#else
    {"_POSIX_CLOCK_SELECTION", _SC_CLOCK_SELECTION, -1, 'V', 1, 0},
#endif
#ifdef _POSIX_CPUTIME
    {"_POSIX_CPUTIME", _SC_CPUTIME, _POSIX_CPUTIME, 'O', 0, 1},
#else
    {"_POSIX_CPUTIME", _SC_CPUTIME, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_FSYNC
    {"_POSIX_FSYNC", _SC_FSYNC, _POSIX_FSYNC, 'O', 0, 1},
#else
    {"_POSIX_FSYNC", _SC_FSYNC, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_IPV6
    {"_POSIX_IPV6", _SC_IPV6, _POSIX_IPV6, 'O', 0, 1},
#else
    {"_POSIX_IPV6", _SC_IPV6, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_JOB_CONTROL
    {"_POSIX_JOB_CONTROL", _SC_JOB_CONTROL, _POSIX_JOB_CONTROL, 'P', 0, 1},
#else
    {"_POSIX_JOB_CONTROL", _SC_JOB_CONTROL, -1, 'P', 0, 0},
#endif
#ifdef _POSIX_MAPPED_FILES
    {"_POSIX_MAPPED_FILES", _SC_MAPPED_FILES, _POSIX_MAPPED_FILES, 'V', 0, 1},
#else
    {"_POSIX_MAPPED_FILES", _SC_MAPPED_FILES, -1, 'V', 0, 0},
#endif
#ifdef _POSIX_MEMLOCK
    {"_POSIX_MEMLOCK", _SC_MEMLOCK, _POSIX_MEMLOCK, 'O', 0, 1},
#else
    {"_POSIX_MEMLOCK", _SC_MEMLOCK, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_MEMLOCK_RANGE
    {"_POSIX_MEMLOCK_RANGE", _SC_MEMLOCK_RANGE, _POSIX_MEMLOCK_RANGE, 'O', 0, 1},
#else
    {"_POSIX_MEMLOCK_RANGE", _SC_MEMLOCK_RANGE, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_MEMORY_PROTECTION
    {"_POSIX_MEMORY_PROTECTION", _SC_MEMORY_PROTECTION, _POSIX_MEMORY_PROTECTION, 'V', 0, 1},
#else
    {"_POSIX_MEMORY_PROTECTION", _SC_MEMORY_PROTECTION, -1, 'V', 0, 0},
#endif
#ifdef _POSIX_MESSAGE_PASSING
    {"_POSIX_MESSAGE_PASSING", _SC_MESSAGE_PASSING, _POSIX_MESSAGE_PASSING, 'O', 0, 1},
#else
    {"_POSIX_MESSAGE_PASSING", _SC_MESSAGE_PASSING, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_MONOTONIC_CLOCK
    {"_POSIX_MONOTONIC_CLOCK", _SC_MONOTONIC_CLOCK, _POSIX_MONOTONIC_CLOCK, 'V', 0, 1},
#else
    {"_POSIX_MONOTONIC_CLOCK", _SC_MONOTONIC_CLOCK, -1, 'V', 0, 0},
#endif
#ifdef _POSIX_PRIORITIZED_IO
    {"_POSIX_PRIORITIZED_IO", _SC_PRIORITIZED_IO, _POSIX_PRIORITIZED_IO, 'O', 0, 1},
#else
    {"_POSIX_PRIORITIZED_IO", _SC_PRIORITIZED_IO, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_PRIORITY_SCHEDULING
    {"_POSIX_PRIORITY_SCHEDULING", _SC_PRIORITY_SCHEDULING, _POSIX_PRIORITY_SCHEDULING, 'O', 0, 1},
#else
    {"_POSIX_PRIORITY_SCHEDULING", _SC_PRIORITY_SCHEDULING, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_RAW_SOCKETS
    {"_POSIX_RAW_SOCKETS", _SC_RAW_SOCKETS, _POSIX_RAW_SOCKETS, 'O', 0, 1},
#else
    {"_POSIX_RAW_SOCKETS", _SC_RAW_SOCKETS, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_READER_WRITER_LOCKS
    {"_POSIX_READER_WRITER_LOCKS", _SC_READER_WRITER_LOCKS, _POSIX_READER_WRITER_LOCKS, 'V', 1, 1},
#else
    {"_POSIX_READER_WRITER_LOCKS", _SC_READER_WRITER_LOCKS, -1, 'V', 1, 0},
#endif
#ifdef _POSIX_REALTIME_SIGNALS
    {"_POSIX_REALTIME_SIGNALS", _SC_REALTIME_SIGNALS, _POSIX_REALTIME_SIGNALS, 'V', 0, 1},
#else
    {"_POSIX_REALTIME_SIGNALS", _SC_REALTIME_SIGNALS, -1, 'V', 0, 0},
#endif
#ifdef _POSIX_REGEXP
    {"_POSIX_REGEXP", _SC_REGEXP, _POSIX_REGEXP, 'P', 1, 1},
#else
    {"_POSIX_REGEXP", _SC_REGEXP, -1, 'P', 1, 0},
#endif
#ifdef _POSIX_SAVED_IDS
    {"_POSIX_SAVED_IDS", _SC_SAVED_IDS, _POSIX_SAVED_IDS, 'P', 0, 1},
#else
    {"_POSIX_SAVED_IDS", _SC_SAVED_IDS, -1, 'P', 0, 0},
#endif
#ifdef _POSIX_SEMAPHORES
    {"_POSIX_SEMAPHORES", _SC_SEMAPHORES, _POSIX_SEMAPHORES, 'V', 0, 1},
#else
    {"_POSIX_SEMAPHORES", _SC_SEMAPHORES, -1, 'V', 0, 0},
#endif
#ifdef _POSIX_SHARED_MEMORY_OBJECTS
    {"_POSIX_SHARED_MEMORY_OBJECTS", _SC_SHARED_MEMORY_OBJECTS, _POSIX_SHARED_MEMORY_OBJECTS, 'O', 0, 1},
#else
    {"_POSIX_SHARED_MEMORY_OBJECTS", _SC_SHARED_MEMORY_OBJECTS, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_SHELL
    {"_POSIX_SHELL", _SC_SHELL, _POSIX_SHELL, 'P', 0, 1},
#else
    {"_POSIX_SHELL", _SC_SHELL, -1, 'P', 0, 0},
#endif
#ifdef _POSIX_SPAWN
    {"_POSIX_SPAWN", _SC_SPAWN, _POSIX_SPAWN, 'O', 0, 1},
#else
    {"_POSIX_SPAWN", _SC_SPAWN, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_SPIN_LOCKS
    {"_POSIX_SPIN_LOCKS", _SC_SPIN_LOCKS, _POSIX_SPIN_LOCKS, 'V', 1, 1},
#else
    {"_POSIX_SPIN_LOCKS", _SC_SPIN_LOCKS, -1, 'V', 1, 0},
#endif
#ifdef _POSIX_SPORADIC_SERVER
    {"_POSIX_SPORADIC_SERVER", _SC_SPORADIC_SERVER, _POSIX_SPORADIC_SERVER, 'O', 0, 1},
#else
    {"_POSIX_SPORADIC_SERVER", _SC_SPORADIC_SERVER, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_SYNCHRONIZED_IO
    {"_POSIX_SYNCHRONIZED_IO", _SC_SYNCHRONIZED_IO, _POSIX_SYNCHRONIZED_IO, 'O', 0, 1},
#else
    {"_POSIX_SYNCHRONIZED_IO", _SC_SYNCHRONIZED_IO, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_THREAD_ATTR_STACKADDR
    {"_POSIX_THREAD_ATTR_STACKADDR", _SC_THREAD_ATTR_STACKADDR, _POSIX_THREAD_ATTR_STACKADDR, 'O', 0, 1},
#else
    {"_POSIX_THREAD_ATTR_STACKADDR", _SC_THREAD_ATTR_STACKADDR, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_THREAD_ATTR_STACKSIZE
    {"_POSIX_THREAD_ATTR_STACKSIZE", _SC_THREAD_ATTR_STACKSIZE, _POSIX_THREAD_ATTR_STACKSIZE, 'O', 0, 1},
#else
    {"_POSIX_THREAD_ATTR_STACKSIZE", _SC_THREAD_ATTR_STACKSIZE, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_THREAD_CPUTIME
    {"_POSIX_THREAD_CPUTIME", _SC_THREAD_CPUTIME, _POSIX_THREAD_CPUTIME, 'O', 0, 1},
#else
    {"_POSIX_THREAD_CPUTIME", _SC_THREAD_CPUTIME, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_THREAD_PRIO_INHERIT
    {"_POSIX_THREAD_PRIO_INHERIT", _SC_THREAD_PRIO_INHERIT, _POSIX_THREAD_PRIO_INHERIT, 'O', 0, 1},
#else
    {"_POSIX_THREAD_PRIO_INHERIT", _SC_THREAD_PRIO_INHERIT, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_THREAD_PRIO_PROTECT
    {"_POSIX_THREAD_PRIO_PROTECT", _SC_THREAD_PRIO_PROTECT, _POSIX_THREAD_PRIO_PROTECT, 'O', 0, 1},
#else
    {"_POSIX_THREAD_PRIO_PROTECT", _SC_THREAD_PRIO_PROTECT, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_THREAD_PRIORITY_SCHEDULING
    {"_POSIX_THREAD_PRIORITY_SCHEDULING", _SC_THREAD_PRIORITY_SCHEDULING, _POSIX_THREAD_PRIORITY_SCHEDULING, 'O', 0, 1},
#else
    {"_POSIX_THREAD_PRIORITY_SCHEDULING", _SC_THREAD_PRIORITY_SCHEDULING, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_THREAD_PROCESS_SHARED
    {"_POSIX_THREAD_PROCESS_SHARED", _SC_THREAD_PROCESS_SHARED, _POSIX_THREAD_PROCESS_SHARED, 'O', 0, 1},
#else
    {"_POSIX_THREAD_PROCESS_SHARED", _SC_THREAD_PROCESS_SHARED, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_THREAD_SAFE_FUNCTIONS
    {"_POSIX_THREAD_SAFE_FUNCTIONS", _SC_THREAD_SAFE_FUNCTIONS, _POSIX_THREAD_SAFE_FUNCTIONS, 'V', 1, 1},
#else
    {"_POSIX_THREAD_SAFE_FUNCTIONS", _SC_THREAD_SAFE_FUNCTIONS, -1, 'V', 1, 0},
#endif
#ifdef _POSIX_THREAD_SPORADIC_SERVER
    {"_POSIX_THREAD_SPORADIC_SERVER", _SC_THREAD_SPORADIC_SERVER, _POSIX_THREAD_SPORADIC_SERVER, 'O', 0, 1},
#else
    {"_POSIX_THREAD_SPORADIC_SERVER", _SC_THREAD_SPORADIC_SERVER, -1, 'O', 0, 0},
#endif
#ifdef _POSIX_THREADS
    {"_POSIX_THREADS", _SC_THREADS, _POSIX_THREADS, 'V', 0, 1},
#else
    {"_POSIX_THREADS", _SC_THREADS, -1, 'V', 0, 0},
#endif
#ifdef _POSIX_TIMEOUTS
    {"_POSIX_TIMEOUTS", _SC_TIMEOUTS, _POSIX_TIMEOUTS, 'V', 0, 1},
#else
    {"_POSIX_TIMEOUTS", _SC_TIMEOUTS, -1, 'V', 0, 0},
#endif
#ifdef _POSIX_TIMERS
    {"_POSIX_TIMERS", _SC_TIMERS, _POSIX_TIMERS, 'V', 0, 1},
#else
    {"_POSIX_TIMERS", _SC_TIMERS, -1, 'V', 0, 0},
#endif
#ifdef _POSIX_TYPED_MEMORY_OBJECTS
    {"_POSIX_TYPED_MEMORY_OBJECTS", _SC_TYPED_MEMORY_OBJECTS, _POSIX_TYPED_MEMORY_OBJECTS, 'O', 0, 1},
#else
    {"_POSIX_TYPED_MEMORY_OBJECTS", _SC_TYPED_MEMORY_OBJECTS, -1, 'O', 0, 0},
#endif
    };
    int claimed = 0;
    for (size_t i = 0; i < sizeof options / sizeof options[0]; i++) {
        long macro = options[i].macro;
        if (options[i].defined) {
            int fits = options[i].kind == 'P' ? macro > 0 : macro == 202405L;
            if (!fits) {
                printf("relibc-hello: %s is %ld, which the standard does not allow\n",
                       options[i].name, macro);
                return 21;
            }
            claimed++;
        }
        errno = 0;
        long got = sysconf(options[i].key);
        if (options[i].defined ? got != macro : (options[i].runtime
                                  ? (options[i].kind == 'P' ? got <= 0 : got != 202405L)
                                  : got != -1)) {
            printf("relibc-hello: sysconf(%s) is %ld, the header says %ld\n", options[i].name,
                   got, macro);
            return 22;
        }
        if (got == -1 && errno != 0) {
            printf("relibc-hello: sysconf(%s) set errno %d\n", options[i].name, errno);
            return 23;
        }
    }
    errno = 0;
    if (sysconf(_SC_XOPEN_UNIX) != -1 || sysconf(_SC_XOPEN_VERSION) != -1 ||
        sysconf(_SC_XOPEN_SHM) != -1 || sysconf(_SC_VERSION) != 202405L || errno != 0) {
        printf("relibc-hello: sysconf claims the XSI option or the wrong version\n");
        return 24;
    }
    /* The layer's descriptor table holds 64. */
    if (sysconf(_SC_OPEN_MAX) != 64 || errno != 0) {
        printf("relibc-hello: sysconf(_SC_OPEN_MAX) is %ld, expected 64\n", sysconf(_SC_OPEN_MAX));
        return 25;
    }
    printf("relibc-hello: constants: _POSIX_VERSION %ld, _POSIX_SUBPROFILE %ld, %d options claimed, timers %ld\n",
           sysconf(_SC_VERSION), (long)_POSIX_SUBPROFILE, claimed, sysconf(_SC_TIMERS));
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
    status = memory_streams();
    if (status) return status;
    status = long_transfers_and_aio();
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
