/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PATH "/tmp/t6-runtime"
#define CHECK(x) do { if (!(x)) { \
    printf("t6-runtime: line %d %s failed errno %d\n", __LINE__, #x, errno); \
    return 1; } } while (0)
extern int t6_runtime_counts(uint32_t out[4]);
extern int t6_runtime_stage(int fd);

struct executable_header {
    unsigned char e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};
struct executable_part {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
};
_Static_assert(sizeof(struct executable_header) == 64, "ELF64 header size");
_Static_assert(offsetof(struct executable_header, e_phentsize) == 54, "ELF64 program entry size offset");
_Static_assert(sizeof(struct executable_part) == 56, "ELF64 program entry size");
_Static_assert(offsetof(struct executable_part, p_filesz) == 32, "ELF64 segment file size offset");


int files_loader_abort_sleep(void) {
    const struct timespec delay = {0, 10000000};
    return nanosleep(&delay, NULL);
}
static int byte(int fd, char value) { return write(fd, &value, 1) == 1; }
static int command(int fd, char wanted) {
    char value = 0;
    return read(fd, &value, 1) == 1 && value == wanted;
}
struct event { int32_t pid; char role; char reserved[3]; };
static int ready(int fd, char role) {
    const struct event event = {getpid(), role, {0, 0, 0}};
    return write(fd, &event, sizeof(event)) == (ssize_t)sizeof(event);
}
static int event(int fd, char role, pid_t *pid) {
    struct event event;
    CHECK(read(fd, &event, sizeof(event)) == (ssize_t)sizeof(event));
    CHECK(event.role == role && event.pid > 0 && !event.reserved[0] &&
          !event.reserved[1] && !event.reserved[2]);
    *pid = event.pid;
    return 0;
}
static int stopped(pid_t pid) {
    /* The three runtime descendants are killed individually, including orphans. */
    CHECK(kill(pid, SIGKILL) == 0);
    for (int i = 0; i < 200; ++i) {
        errno = 0;
        if (kill(pid, 0) == -1 && errno == ESRCH) return 0;
        CHECK(files_loader_abort_sleep() == 0);
    }
    CHECK(0);
}
static int counts(const uint32_t baseline[4], uint32_t images) {
    uint32_t actual[4];
    for (int i = 0; i < 200; ++i) {
        CHECK(t6_runtime_counts(actual) == 0);
        if (actual[0] == baseline[0] && actual[1] == baseline[1] &&
            actual[2] == baseline[2] && actual[3] == baseline[3] + images) {
            printf("t6-runtime: live images %u descriptions %u preparations %u\n",
                   images, actual[3], actual[1]);
            return 0;
        }
        CHECK(files_loader_abort_sleep() == 0);
    }
    printf("t6-runtime: counters %u/%u/%u/%u expected %u/%u/%u/%u\n",
           actual[0], actual[1], actual[2], actual[3],
           baseline[0], baseline[1], baseline[2], baseline[3] + images);
    CHECK(0);
}
static int access_time(int fd, int64_t out[2]) {
    struct stat info;
    CHECK(fstat(fd, &info) == 0);
    out[0] = info.st_atim.tv_sec;
    out[1] = info.st_atim.tv_nsec;
    return 0;
}
static int busy(void) {
    errno = 0;
    int fd = open(PATH, O_WRONLY);
    CHECK(fd == -1 && errno == ETXTBSY);
    return 0;
}
static int runtime(int parent_read, int child_read, int grand_read, int events) {
    CHECK(getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0);
    CHECK(ready(events, 'P'));
    CHECK(command(parent_read, 'F'));
    pid_t child = fork();
    if (child < 0) {
        printf("t6-runtime: runtime fork child returned -1 errno %d\n", errno);
        CHECK(ready(events, 'E'));
        return 1;
    }
    if (child == 0) {
        CHECK(getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0);
        CHECK(ready(events, 'C'));
        CHECK(command(child_read, 'F'));
        pid_t grandchild = fork();
        if (grandchild < 0) {
            printf("t6-runtime: runtime fork grandchild returned -1 errno %d\n", errno);
            CHECK(ready(events, 'E'));
            return 1;
        }
        if (grandchild == 0) {
            CHECK(getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0);
            CHECK(ready(events, 'G'));
            CHECK(command(grand_read, 'X'));
            _exit(0);
        }
        CHECK(command(child_read, 'X'));
        _exit(0);
    }
    CHECK(command(parent_read, 'X'));
    _exit(0);
}
static int copy_image(void) {
    int source = open("/bin/posix-files", O_RDONLY);
    CHECK(source >= 0);
    struct executable_header header;
    CHECK(pread(source, &header, sizeof(header), 0) == (ssize_t)sizeof(header));
    printf("t6-runtime: ELF header %02x%02x%02x%02x size %u phsize %u phnum %u\n",
           header.e_ident[0], header.e_ident[1], header.e_ident[2], header.e_ident[3],
           (unsigned)sizeof(header), header.e_phentsize, header.e_phnum);
    CHECK(memcmp(header.e_ident, "\177ELF", 4) == 0 &&
          header.e_phentsize == sizeof(struct executable_part) && header.e_phnum > 0 && header.e_phnum <= 16);
    uint64_t extent = header.e_phoff + header.e_phnum * sizeof(struct executable_part);
    unsigned loads = 0;
    for (unsigned i = 0; i < header.e_phnum; ++i) {
        struct executable_part part;
        CHECK(pread(source, &part, sizeof(part),
                    (off_t)(header.e_phoff + i * sizeof(part))) == (ssize_t)sizeof(part));
        if (part.p_type == PT_LOAD) {
            CHECK(part.p_offset <= UINT64_MAX - part.p_filesz);
            uint64_t end = part.p_offset + part.p_filesz;
            if (end > extent) extent = end;
            ++loads;
        }
    }
    CHECK(loads == 3 && extent > 4096 && extent <= 8 * 1024 * 1024);
    int output = open(PATH, O_CREAT | O_EXCL | O_WRONLY, 0755);
    CHECK(output >= 0);
    struct stat info;
    CHECK(fstat(output, &info) == 0 && S_ISREG(info.st_mode) &&
          (info.st_mode & 0777) == 0755);
    /* This buffer stays within the legacy Write frame as well as Data frames. */
    char buffer[512];
    ssize_t length;
    size_t copied = 0;
    /* The copied executable contains its headers and every PT_LOAD file byte. */
    while (copied < extent) {
        size_t requested = extent - copied;
        if (requested > sizeof(buffer)) requested = sizeof(buffer);
        length = read(source, buffer, requested);
        CHECK(length > 0);
        ssize_t offset = 0;
        while (offset < length) {
            ssize_t done = write(output, buffer + offset, (size_t)(length - offset));
            CHECK(done > 0);
            offset += done;
            copied += (size_t)done;
        }
    }
    CHECK(copied == extent && fstat(output, &info) == 0 && info.st_size == (off_t)extent);
    CHECK(close(source) == 0 && close(output) == 0);
    printf("t6-runtime: copied dynamic ELF %zu bytes\n", copied);
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 6 && strcmp(argv[1], "runtime") == 0)
        return runtime(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
    CHECK(argc == 1);
    CHECK(copy_image() == 0);
    int retained = open(PATH, O_RDONLY);
    CHECK(retained >= 0);
    CHECK(t6_runtime_stage(retained) == 0);
    char magic[4];
    CHECK(pread(retained, magic, sizeof(magic), 0) == (ssize_t)sizeof(magic) &&
          memcmp(magic, "\177ELF", sizeof(magic)) == 0);
    int64_t initial_atime[2];
    CHECK(access_time(retained, initial_atime) == 0);
    uint32_t baseline[4];
    CHECK(t6_runtime_counts(baseline) == 0);
    CHECK(baseline[0] == 0 && baseline[1] == 0 && baseline[2] == 0);
    int parent[2], child[2], grand[2], events[2];
    CHECK(pipe(parent) == 0 && pipe(child) == 0 && pipe(grand) == 0 && pipe(events) == 0);
    char a[16], b[16], c[16], d[16];
    CHECK(snprintf(a, sizeof(a), "%d", parent[0]) > 0);
    CHECK(snprintf(b, sizeof(b), "%d", child[0]) > 0);
    CHECK(snprintf(c, sizeof(c), "%d", grand[0]) > 0);
    CHECK(snprintf(d, sizeof(d), "%d", events[1]) > 0);
    char *args[] = {PATH, "runtime", a, b, c, d, NULL};
    char *env[] = {NULL};
    pid_t worker = -1;
    int launched = posix_spawn(&worker, PATH, NULL, NULL, args, env);
    printf("t6-runtime: dynamic parent spawn status %d pid %d\n", launched, worker);
    CHECK(launched == 0 && worker > 0);
    CHECK(close(parent[0]) == 0 && close(child[0]) == 0 && close(grand[0]) == 0);
    CHECK(close(events[1]) == 0);
    pid_t p, q, r;
    CHECK(event(events[0], 'P', &p) == 0 && p == worker);
    CHECK(counts(baseline, 1) == 0 && busy() == 0);
    int64_t atime[2], after[2];
    CHECK(access_time(retained, atime) == 0);
    CHECK(atime[0] > initial_atime[0] ||
          (atime[0] == initial_atime[0] && atime[1] > initial_atime[1]));
    CHECK(byte(parent[1], 'F'));
    CHECK(event(events[0], 'C', &q) == 0 && q != p);
    CHECK(counts(baseline, 2) == 0 && busy() == 0);
    CHECK(access_time(retained, after) == 0 && memcmp(after, atime, sizeof(after)) == 0);
    CHECK(byte(child[1], 'F'));
    CHECK(event(events[0], 'G', &r) == 0 && r != p && r != q);
    CHECK(counts(baseline, 3) == 0 && busy() == 0);
    CHECK(access_time(retained, after) == 0 && memcmp(after, atime, sizeof(after)) == 0);
    CHECK(kill(p, SIGKILL) == 0);
    int status = 0;
    CHECK(waitpid(worker, &status, 0) == worker && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    CHECK(counts(baseline, 2) == 0 && busy() == 0);
    CHECK(stopped(q) == 0);
    CHECK(counts(baseline, 1) == 0 && busy() == 0);
    CHECK(stopped(r) == 0);
    CHECK(counts(baseline, 0) == 0);
    int writable = open(PATH, O_WRONLY);
    CHECK(writable >= 0 && pwrite(writable, "\177", 1, 0) == 1 && close(writable) == 0);
    CHECK(counts(baseline, 0) == 0);
    CHECK(close(retained) == 0);
    CHECK(baseline[3] > 0);
    --baseline[3];
    CHECK(counts(baseline, 0) == 0);
    CHECK(close(parent[1]) == 0 && close(child[1]) == 0 && close(grand[1]) == 0);
    CHECK(close(events[0]) == 0);
    puts("t6-runtime: dynamic exec, two forks, End and ETXTBSY custody ok");
    return 0;
}
