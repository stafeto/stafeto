/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The program's mappings (Ф8): mmap, munmap and mprotect over the layer's
 * memory map, faults on pages that lost their access, and the limits of the
 * map. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096UL
static int failures;
static sigjmp_buf jump;
static volatile sig_atomic_t faults;

static void check(const char *what, int good) {
    if (!good) {
        printf("posix-map: %s failed (errno %d)\n", what, errno);
        failures++;
    }
}

static void on_fault(int signal) {
    (void)signal;
    faults++;
    siglongjmp(jump, 1);
}

/* 1 when reading the byte raises SIGSEGV, 0 when it reads. */
static int read_faults(volatile const char *at) {
    if (sigsetjmp(jump, 1)) return 1;
    (void)*at;
    return 0;
}

static int write_faults(volatile char *at) {
    if (sigsetjmp(jump, 1)) return 1;
    *at = 1;
    return 0;
}

static char *anon(size_t len, int prot) {
    char *p = mmap(NULL, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

/* mprotect on a whole mapping: read-only stops the write, none stops the
 * read, and the access comes back. */
static void protect_whole(size_t len, const char *who) {
    char text[96];
    char *p = anon(len, PROT_READ | PROT_WRITE);
    snprintf(text, sizeof text, "%s: mmap", who);
    check(text, p != NULL);
    if (!p) return;
    p[0] = 7;
    p[len - 1] = 9;
    snprintf(text, sizeof text, "%s: mprotect read", who);
    check(text, mprotect(p, len, PROT_READ) == 0);
    check("read after PROT_READ", !read_faults(p) && p[0] == 7);
    check("write after PROT_READ faults", write_faults(p + 8));
    check("mprotect none", mprotect(p, len, PROT_NONE) == 0);
    check("read after PROT_NONE faults", read_faults(p));
    check("mprotect back", mprotect(p, len, PROT_READ | PROT_WRITE) == 0);
    check("data kept", p[0] == 7 && p[len - 1] == 9);
    check("munmap", munmap(p, len) == 0);
    snprintf(text, sizeof text, "%s: read after munmap faults", who);
    check(text, read_faults(p));
}

/* The pages a munmap took fault, the edges stay, and a mapping of the same
 * size comes zeroed. */
static void unmap_part(size_t pages, const char *who) {
    char text[96];
    size_t len = pages * PAGE;
    char *p = anon(len, PROT_READ | PROT_WRITE);
    snprintf(text, sizeof text, "%s: mmap", who);
    check(text, p != NULL);
    if (!p) return;
    memset(p, 0x5a, len);
    size_t mid = pages / 2;
    check("munmap middle", munmap(p + mid * PAGE, PAGE) == 0);
    check("edge before reads", !read_faults(p) && p[0] == 0x5a);
    check("edge after reads", !read_faults(p + len - 1) && p[len - 1] == 0x5a);
    snprintf(text, sizeof text, "%s: middle faults", who);
    check(text, read_faults(p + mid * PAGE) && write_faults(p + mid * PAGE));
    check("munmap the rest", munmap(p, len) == 0);
    check("the whole faults", read_faults(p) && read_faults(p + len - 1));
    char *q = anon(len, PROT_READ | PROT_WRITE);
    check("mmap again", q != NULL);
    if (q) {
        int zero = 1;
        for (size_t i = 0; i < len; i += 61) zero &= q[i] == 0;
        check("a mapping again is zeros", zero);
        check("munmap again", munmap(q, len) == 0);
    }
}

/* One mprotect over several pieces of the map. */
static void protect_across(void) {
    char *p = anon(8 * PAGE, PROT_READ | PROT_WRITE);
    check("across: mmap", p != NULL);
    if (!p) return;
    memset(p, 1, 8 * PAGE);
    check("across: page 2 none", mprotect(p + 2 * PAGE, PAGE, PROT_NONE) == 0);
    check("across: page 5 read", mprotect(p + 5 * PAGE, PAGE, PROT_READ) == 0);
    check("across: all read", mprotect(p, 8 * PAGE, PROT_READ) == 0);
    int readable = 1, stopped = 1;
    for (int i = 0; i < 8; i++) {
        readable &= !read_faults(p + i * PAGE);
        stopped &= write_faults(p + i * PAGE);
    }
    check("across: every page reads", readable);
    check("across: every page refuses a write", stopped);
    check("across: all write", mprotect(p, 8 * PAGE, PROT_READ | PROT_WRITE) == 0);
    p[2 * PAGE] = 3;
    check("across: munmap across pieces", munmap(p + PAGE, 6 * PAGE) == 0);
    check("across: edges stay", !read_faults(p) && !read_faults(p + 7 * PAGE));
    check("across: inside faults", read_faults(p + PAGE) && read_faults(p + 6 * PAGE));
    check("across: munmap edges", munmap(p, PAGE) == 0 && munmap(p + 7 * PAGE, PAGE) == 0);
}

static void errors(void) {
    char *p = anon(2 * PAGE, PROT_READ | PROT_WRITE);
    check("errors: mmap", p != NULL);
    errno = 0;
    check("mprotect of an unmapped range is ENOMEM",
          mprotect((void *)0x70000000UL, PAGE, PROT_READ) == -1 && errno == ENOMEM);
    errno = 0;
    check("mprotect off a page is EINVAL", p && mprotect(p + 1, PAGE, PROT_READ) == -1 && errno == EINVAL);
    errno = 0;
    check("mprotect with PROT_EXEC is EACCES",
          p && mprotect(p, PAGE, PROT_READ | PROT_EXEC) == -1 && errno == EACCES);
    errno = 0;
    check("mprotect past the mapping is ENOMEM",
          p && mprotect(p, 64 * PAGE, PROT_READ) == -1 && errno == ENOMEM);
    check("the mapping is unchanged", p && !write_faults(p));
    errno = 0;
    check("mmap with PROT_EXEC is EACCES",
          mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == EACCES);
    errno = 0;
    check("mmap with no kind is EINVAL",
          mmap(NULL, PAGE, PROT_READ, MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == EINVAL);
    errno = 0;
    check("munmap off a page is EINVAL", p && munmap(p + 1, PAGE) == -1 && errno == EINVAL);
    check("munmap of nothing is fine", munmap((void *)0x70000000UL, PAGE) == 0);
    if (p) munmap(p, 2 * PAGE);
}

/* Every other page of a mapping cut off: the map fills, mprotect says
 * ENOMEM and changes nothing, munmap still succeeds. */
static void table_full(void) {
    size_t pages = 124;
    char *p = anon(pages * PAGE, PROT_READ | PROT_WRITE);
    check("full: mmap", p != NULL);
    if (!p) return;
    size_t cut = 0;
    int refused = 0;
    for (size_t i = 1; i < pages; i += 2) {
        if (mprotect(p + i * PAGE, PAGE, PROT_NONE) == 0) {
            cut++;
        } else {
            refused = errno == ENOMEM;
            break;
        }
    }
    check("full: the table fills with ENOMEM", refused && cut > 20 && cut < 128);
    int same = 1;
    for (size_t i = 0; i < pages && same; i += 2) same &= !write_faults(p + i * PAGE);
    check("full: the pages before stay writable", same);
    check("full: munmap still works", munmap(p, pages * PAGE) == 0);
    check("full: the room is back", ({
        char *q = anon(pages * PAGE, PROT_READ | PROT_WRITE);
        int good = q && !write_faults(q + (pages - 1) * PAGE);
        if (q) munmap(q, pages * PAGE);
        good;
    }));
}

/* A forked child has the parent's pages, the pages without access, and
 * its own copy. */
static void forked(void) {
    char *p = anon(4 * PAGE, PROT_READ | PROT_WRITE);
    check("fork: mmap", p != NULL);
    if (!p) return;
    p[0] = 11;
    p[PAGE] = 12;
    check("fork: protect", mprotect(p + PAGE, PAGE, PROT_NONE) == 0);
    check("fork: unmap", munmap(p + 2 * PAGE, PAGE) == 0);
    pid_t child = fork();
    if (child < 0) { printf("posix-map: fork failed with %d\n", errno); failures++; return; }
    if (child == 0) {
        int bad = 0;
        if (read_faults(p) || p[0] != 11) bad |= 1;
        if (!read_faults(p + PAGE)) bad |= 2;
        if (!read_faults(p + 2 * PAGE)) bad |= 4;
        if (read_faults(p + 3 * PAGE)) bad |= 8;
        p[0] = 99;
        if (mprotect(p + PAGE, PAGE, PROT_READ | PROT_WRITE) || read_faults(p + PAGE) || p[PAGE] != 12) bad |= 16;
        _exit(bad);
    }
    int status = 0;
    check("fork: waitpid", waitpid(child, &status, 0) == child);
    check("fork: the child saw the map", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (WIFEXITED(status) && WEXITSTATUS(status))
        printf("posix-map: fork child bits %d\n", WEXITSTATUS(status));
    check("fork: the child's write is its own", p[0] == 11);
    check("fork: the parent's page is still none", read_faults(p + PAGE));
    munmap(p, PAGE);
    munmap(p + 3 * PAGE, PAGE);
}

/* Many small mappings and unmappings reuse the pages and never run the
 * table out. */
static void churn(void) {
    int good = 1;
    for (int round = 0; round < 300 && good; round++) {
        char *a = anon((round % 7 + 1) * PAGE, PROT_READ | PROT_WRITE);
        char *b = anon(((round * 3) % 5 + 1) * PAGE, PROT_READ | PROT_WRITE);
        good = a && b;
        if (a) { a[0] = 1; munmap(a, PAGE); }
        if (b) { b[0] = 2; if (round % 2) mprotect(b, PAGE, PROT_READ); munmap(b, (((round * 3) % 5) + 1) * PAGE); }
        if (a && (round % 7) > 0) munmap(a + PAGE, (round % 7) * PAGE);
    }
    check("churn: 300 rounds of mmap and munmap", good);
}

/* MAP_SHARED anonymous memory is the same pages in a forked child. */
static void shared_anonymous(void) {
    char *p = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    check("shared: mmap", p != MAP_FAILED);
    if (p == MAP_FAILED) return;
    check("shared: zeros", p[0] == 0 && p[3 * PAGE - 1] == 0);
    p[0] = 1;
    pid_t child = fork();
    if (child < 0) { printf("posix-map: fork failed with %d\n", errno); failures++; return; }
    if (child == 0) {
        int bad = p[0] != 1;
        p[0] = 42;
        p[2 * PAGE] = 43;
        if (munmap(p + PAGE, PAGE)) bad |= 2;
        _exit(bad);
    }
    int status = 0;
    check("shared: waitpid", waitpid(child, &status, 0) == child);
    
    check("shared: the child saw the page", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check("shared: the parent sees the child's writes", p[0] == 42 && p[2 * PAGE] == 43);
    check("shared: the child's munmap is the child's", !read_faults(p + PAGE));
    check("shared: mprotect read", mprotect(p, 3 * PAGE, PROT_READ) == 0 && write_faults(p));
    check("shared: munmap", munmap(p, 3 * PAGE) == 0 && read_faults(p));
}

static const char *scratch = "/tmp/posix-map-file";

static int fill_file(size_t len) {
    int fd = open(scratch, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    for (size_t i = 0; i < len; i++) {
        char c = (char)('a' + i % 26);
        if (write(fd, &c, 1) != 1) return -1;
    }
    return fd;
}

static int file_byte(size_t at) {
    int fd = open(scratch, O_RDONLY);
    char c = 0;
    int got = fd >= 0 && pread(fd, &c, 1, (off_t)at) == 1;
    if (fd >= 0) close(fd);
    return got ? c : -1;
}

/* Mappings of a file: contents, offset, private copy, shared write back,
 * the descriptor closed meanwhile, a forked child. */
static void files(void) {
    int fd = fill_file(10000);
    check("file: create", fd >= 0);
    if (fd < 0) return;
    char *p = mmap(NULL, 10000, PROT_READ, MAP_PRIVATE, fd, 0);
    check("file: private mmap", p != MAP_FAILED);
    if (p != MAP_FAILED) {
        int same = 1;
        for (size_t i = 0; i < 10000; i += 7) same &= p[i] == 'a' + (int)(i % 26);
        check("file: contents", same);
        check("file: the tail of the last page is zeros", p[10000] == 0 && p[3 * PAGE - 1] == 0);
        check("file: private read-only refuses a write", write_faults(p));
        check("file: private mprotect", mprotect(p, 3 * PAGE, PROT_READ | PROT_WRITE) == 0);
        p[5] = '!';
        check("file: a private write stays", p[5] == '!' && file_byte(5) == 'f');
        munmap(p, 10000);
        check("file: a private write is not written back", file_byte(5) == 'f');
    }
    char *q = mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE, fd, PAGE);
    check("file: offset mapping", q != MAP_FAILED && q[0] == 'a' + (int)(PAGE % 26));
    if (q != MAP_FAILED) munmap(q, PAGE);
    char *s = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("file: shared mmap", s != MAP_FAILED);
    if (s == MAP_FAILED) return;
    check("file: close while mapped", close(fd) == 0);
    s[10] = 'X';
    check("file: msync", msync(s, 2 * PAGE, MS_SYNC) == 0);
    check("file: msync wrote the byte", file_byte(10) == 'X');
    s[20] = 'Y';
    check("file: msync asynchronous", msync(s, PAGE, MS_ASYNC) == 0 && file_byte(20) == 'Y');
    s[30] = 'Z';
    pid_t child = fork();
    if (child < 0) { printf("posix-map: fork failed with %d\n", errno); failures++; return; }
    if (child == 0) {
        int bad = s[30] != 'Z';
        s[40] = 'C';
        if (msync(s, PAGE, MS_SYNC)) bad |= 2;
        _exit(bad);
    }
    int status = 0;
    check("file: waitpid", waitpid(child, &status, 0) == child);
    check("file: the child's mapping is the same", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check("file: the parent sees the child's write", s[40] == 'C');
    check("file: the child wrote the file back", file_byte(40) == 'C');
    check("file: munmap writes back", munmap(s, 2 * PAGE) == 0 && file_byte(30) == 'Z');
    check("file: the mapping is gone", read_faults(s));
    /* The file's end: a mapping past it is zeros and is not written. */
    fd = open(scratch, O_RDWR);
    char *t = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("file: mapping past the end", t != MAP_FAILED);
    if (t != MAP_FAILED) {
        t[2 * PAGE + 5] = 9;
        check("file: unmap past the end", munmap(t, 3 * PAGE) == 0);
        struct stat st;
        check("file: the size is the same", fstat(fd, &st) == 0 && st.st_size == 10000);
    }
    errno = 0;
    check("file: offset off a page is EINVAL",
          mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, 100) == MAP_FAILED && errno == EINVAL);
    errno = 0;
    check("file: a bad descriptor is EBADF",
          mmap(NULL, PAGE, PROT_READ, MAP_SHARED, 99, 0) == MAP_FAILED && errno == EBADF);
    int dirfd = open("/tmp", O_RDONLY);
    errno = 0;
    check("file: a directory is ENODEV",
          dirfd >= 0 && mmap(NULL, PAGE, PROT_READ, MAP_SHARED, dirfd, 0) == MAP_FAILED && errno == ENODEV);
    if (dirfd >= 0) close(dirfd);
    close(fd);
    unlink(scratch);
}

/* shm_open: a name for a shared object, the pages the same in a child,
 * and the name gone with shm_unlink. */
static void shared_names(void) {
    const char *name = "/posix-map-shm";
    shm_unlink(name);
    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    check("shm: shm_open", fd >= 0);
    if (fd < 0) return;
    errno = 0;
    check("shm: O_EXCL on an existing name is EEXIST",
          shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600) == -1 && errno == EEXIST);
    check("shm: ftruncate", ftruncate(fd, 2 * PAGE) == 0);
    char *p = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("shm: mmap", p != MAP_FAILED);
    if (p != MAP_FAILED) {
        p[0] = 5;
        pid_t child = fork();
    if (child < 0) { printf("posix-map: fork failed with %d\n", errno); failures++; return; }
        if (child == 0) {
            int bad = p[0] != 5;
            p[1] = 6;
            _exit(bad);
        }
        int status = 0;
        check("shm: waitpid", waitpid(child, &status, 0) == child);
        check("shm: the child's write", WIFEXITED(status) && WEXITSTATUS(status) == 0 && p[1] == 6);
        munmap(p, 2 * PAGE);
    }
    close(fd);
    check("shm: shm_unlink", shm_unlink(name) == 0);
    errno = 0;
    check("shm: shm_unlink again is ENOENT", shm_unlink(name) == -1 && errno == ENOENT);
    errno = 0;
    check("shm: shm_open of the gone name is ENOENT", shm_open(name, O_RDWR, 0) == -1 && errno == ENOENT);
}

extern char **environ;

/* RLIMIT_DATA and RLIMIT_AS count the program's mappings; RLIMIT_STACK is
 * kept. */
static void limits(void) {
    struct rlimit old_data, old_as, stack, low;
    check("getrlimit DATA", getrlimit(RLIMIT_DATA, &old_data) == 0);
    check("getrlimit AS", getrlimit(RLIMIT_AS, &old_as) == 0);
    check("getrlimit STACK", getrlimit(RLIMIT_STACK, &stack) == 0 && stack.rlim_cur > 0);
    low = old_data;
    low.rlim_cur = PAGE;
    check("setrlimit DATA", setrlimit(RLIMIT_DATA, &low) == 0);
    errno = 0;
    check("DATA stops mmap", mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED
          && errno == ENOMEM);
    check("DATA is read back", getrlimit(RLIMIT_DATA, &low) == 0 && low.rlim_cur == PAGE);
    check("restore DATA", setrlimit(RLIMIT_DATA, &old_data) == 0);
    char *p = anon(2 * PAGE, PROT_READ | PROT_WRITE);
    check("DATA restored", p != NULL);
    if (p) munmap(p, 2 * PAGE);
    low = old_as;
    low.rlim_cur = PAGE;
    check("setrlimit AS", setrlimit(RLIMIT_AS, &low) == 0);
    errno = 0;
    check("AS stops a large mapping", mmap(NULL, 512 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED
          && errno == ENOMEM);
    errno = 0;
    check("AS stops a shared mapping", mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED
          && errno == ENOMEM);
    check("restore AS", setrlimit(RLIMIT_AS, &old_as) == 0);
    p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    check("AS restored", p != MAP_FAILED);
    if (p != MAP_FAILED) munmap(p, PAGE);
}

/* The time functions allocate through the same mappings. */
static void time_functions(void) {
    time_t t = 86400 * 365;
    struct tm *parts = localtime(&t);
    check("localtime", parts && parts->tm_year == 71);
    char buffer[64];
    check("strftime", parts && strftime(buffer, sizeof buffer, "%Y", parts) == 4);
}

/* A process of its own maps the shm object of the parent: the same pages,
 * not a copy of the file. */
static int peer(const char *name) {
    int fd = shm_open(name, O_RDWR, 0);
    if (fd < 0) return 1;
    char *p = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) return 2;
    if (p[0] != 7) return 3;
    p[1] = 9;
    if (munmap(p, 2 * PAGE)) return 4;
    return 0;
}

static void unrelated_processes(void) {
    const char *name = "/posix-map-peer";
    shm_unlink(name);
    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    check("peer: shm_open", fd >= 0);
    if (fd < 0) return;
    check("peer: ftruncate", ftruncate(fd, 2 * PAGE) == 0);
    char *p = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("peer: mmap", p != MAP_FAILED);
    if (p == MAP_FAILED) return;
    p[0] = 7;
    char *args[] = {"map", "peer", (char *)name, NULL};
    pid_t child;
    int error = posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, environ);
    check("peer: spawn", error == 0);
    int status = 0;
    if (!error) check("peer: waitpid", waitpid(child, &status, 0) == child);
    if (!error && WIFEXITED(status) && WEXITSTATUS(status))
        printf("posix-map: peer step %d\n", WEXITSTATUS(status));
    check("peer: the other process saw the pages", !error && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check("peer: and wrote them", p[1] == 9);
    check("peer: munmap", munmap(p, 2 * PAGE) == 0);
    /* No one maps the object now: a new mapping reads the file, which the
     * last munmap wrote. */
    char *q = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("peer: mmap again", q != MAP_FAILED);
    if (q != MAP_FAILED) {
        check("peer: the file has the pages", q[0] == 7 && q[1] == 9);
        munmap(q, 2 * PAGE);
    }
    close(fd);
    shm_unlink(name);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "peer") == 0) return peer(argv[2]);
    if (argc == 1) {
        /* fork needs a program the process service started. */
        char *args[] = {"map", "run", NULL};
        pid_t child;
        int error = posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, environ);
        if (error) {
            printf("posix-map: launcher failed %d\n", error);
            return 1;
        }
        int status = 0;
        return waitpid(child, &status, 0) == child && WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
    struct sigaction action = {.sa_handler = on_fault};
    sigaction(SIGSEGV, &action, NULL);
    time_functions();
    table_full();
    protect_whole(PAGE, "small");
    protect_whole(5 * PAGE, "five pages");
    protect_whole(32 * PAGE, "32 pages");
    unmap_part(4, "small");
    unmap_part(40, "large");
    protect_across();
    errors();
    forked();
    churn();
    shared_anonymous();
    files();
    shared_names();
    unrelated_processes();
    limits();
    if (failures) {
        printf("posix-map: %d failures\n", failures);
        return 1;
    }
    printf("posix-map: mprotect, munmap and faults ok\n");
    printf("posix-map: shared memory, files and shm ok\n");
    return 0;
}
