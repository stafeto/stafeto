/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <locale.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(pthread_t) == 8, "pthread ID ABI");
_Static_assert(sizeof(pthread_attr_t) == 32, "pthread attributes ABI");
_Static_assert(_Alignof(pthread_attr_t) == 8, "pthread attribute alignment");
_Static_assert(sizeof(void *) == 8, "pointer ABI");
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

static void *pressure[4096];
static int pressure_count, pressure_failed, select_count;

static int select_pressure(const struct dirent *entry) {
    (void)entry;
    if (++select_count == 2) {
        const size_t sizes[] = {1024, 144, 64, 1};
        for (int i = 0; i < 4; i++) {
            void *block;
            while ((block = malloc(sizes[i])) != NULL) {
                if (pressure_count == 4096) { free(block); pressure_failed = 1; return 1; }
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
struct thread_context { pthread_t parent, self; int fd; char byte; int failure; uint64_t floating; };

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
        .floating = fp_environment() };
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
    pthread_t children[31];
    for (size_t i = 0; i < 31; i++) {
        if (pthread_create(&children[i], &attr, thread_return, (void *)(uintptr_t)(i + 1))) return 214;
    }
    child = 987;
    if (pthread_create(&child, &attr, thread_return, NULL) != EAGAIN || child != 987 || errno != 123) return 215;
    for (size_t i = 0; i < 31; i++) {
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
    int allocation_result = allocations();
    if (allocation_result) return allocation_result;
    int collation_result = collation();
    if (collation_result) return collation_result;
    int scan_result = scans();
    if (scan_result) return scan_result;
    const char result[] = "posix-abi-probe: ok\n";
    if (write(1, result, sizeof(result) - 1) != (ssize_t)(sizeof(result) - 1)) return 32;
    return 0;
}
