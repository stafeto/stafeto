/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The program's mappings: mmap, munmap and mprotect over the layer's
 * memory map, faults on pages that lost their access, and the limits of the
 * map. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
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
static const char *scratch = "/tmp/posix-map-file";
static int fill_file(size_t len);
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

/* What the handler with SA_SIGINFO saw of the last fault. */
static volatile int seen_signal, seen_code;
static void *volatile seen_addr;

static void on_fault_info(int signal, siginfo_t *info, void *context) {
    (void)context;
    seen_signal = signal;
    seen_code = info->si_code;
    seen_addr = info->si_addr;
    faults++;
    siglongjmp(jump, 1);
}

static int fault_seen(int code, const void *addr) {
    return seen_signal == SIGSEGV && seen_code == code && seen_addr == addr;
}

static void forget_fault(void) {
    seen_signal = seen_code = 0;
    seen_addr = NULL;
}

/* 1 when a jump to `at` raises SIGSEGV with SEGV_ACCERR and `at` itself as
 * the address (an instruction abort), 0 when it runs or says anything else. */
static int jump_faults(char *at) {
    void (*target)(void) = (void (*)(void))(void *)at;
    forget_fault();
    if (sigsetjmp(jump, 1)) return fault_seen(SEGV_ACCERR, at);
    target();
    return 0;
}

/* A page without access stops a read and a write with SIGSEGV, SEGV_ACCERR
 * and the faulting address; an unmapped page says SEGV_MAPERR. A jump to a
 * page of data is a fault too, whatever its access (a page is executable
 * only after mprotect to PROT_EXEC), at the address jumped to. */
static void none_page_faults(void) {
    struct sigaction info = {.sa_sigaction = on_fault_info, .sa_flags = SA_SIGINFO}, old;
    check("none: sigaction", sigaction(SIGSEGV, &info, &old) == 0);
    char *p = anon(3 * PAGE, PROT_READ | PROT_WRITE);
    check("none: mmap", p != NULL);
    if (!p) return;
    p[0] = 1;
    check("none: mprotect", mprotect(p + PAGE, PAGE, PROT_NONE) == 0);
    forget_fault();
    check("none: a read faults", read_faults(p + PAGE + 24));
    check("none: the read says ACCERR and its address", fault_seen(SEGV_ACCERR, p + PAGE + 24));
    forget_fault();
    check("none: a write faults", write_faults(p + PAGE + 40));
    check("none: the write says ACCERR and its address", fault_seen(SEGV_ACCERR, p + PAGE + 40));
    check("none: the neighbours are fine", !write_faults(p) && !write_faults(p + 2 * PAGE));
    check("none: munmap the page", munmap(p + PAGE, PAGE) == 0);
    forget_fault();
    check("none: an unmapped page of the map faults", read_faults(p + PAGE + 8));
    check("none: a page munmap gave back says MAPERR and its address",
          fault_seen(SEGV_MAPERR, p + PAGE + 8));
    /* An address the layer never gave out: the walk finds no descriptor. */
    forget_fault();
    char *never = (char *)0x70000000UL;
    check("none: a never mapped address faults", read_faults(never + 8));
    check("none: the never mapped address says MAPERR", fault_seen(SEGV_MAPERR, never + 8));
    /* A jump to a page of data, writable and read-only: the page is not
     * executable, whatever else it allows. */
    check("none: mprotect read", mprotect(p + 2 * PAGE, PAGE, PROT_READ) == 0);
    check("none: a jump to a read-only page says ACCERR at its address",
          jump_faults(p + 2 * PAGE + 16));
    check("none: mprotect write", mprotect(p + 2 * PAGE, PAGE, PROT_READ | PROT_WRITE) == 0);
    check("none: a jump to a writable page says ACCERR at its address",
          jump_faults(p + 2 * PAGE + 32));
    check("none: restore the handler", sigaction(SIGSEGV, &old, NULL) == 0);
    munmap(p, PAGE);
    munmap(p + 2 * PAGE, PAGE);
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
    check("mprotect with write and exec is ENOTSUP",
          p && mprotect(p, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1 && errno == ENOTSUP);
    errno = 0;
    check("mprotect past the mapping is ENOMEM",
          p && mprotect(p, 64 * PAGE, PROT_READ) == -1 && errno == ENOMEM);
    check("the mapping is unchanged", p && !write_faults(p));
    errno = 0;
    check("mmap with write and exec is ENOTSUP",
          mmap(NULL, PAGE, PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED
              && errno == ENOTSUP);
    errno = 0;
    check("mmap with no kind is EINVAL",
          mmap(NULL, PAGE, PROT_READ, MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == EINVAL);
    errno = 0;
    check("munmap off a page is EINVAL", p && munmap(p + 1, PAGE) == -1 && errno == EINVAL);
    check("munmap of nothing is fine", munmap((void *)0x70000000UL, PAGE) == 0);
    if (p) munmap(p, 2 * PAGE);
}

/* Executable memory (#384): code written through a writable page and run
 * after mprotect to PROT_READ | PROT_EXEC, the cycle again with other code,
 * code in a private mapping of a file, a forked child, the refusals
 * (ENOTSUP for write and exec, and for a shared mapping with exec), and a
 * write to an executable page. */
#define CODE_42 0x52800540u /* mov w0, #42 */
#define CODE_7 0x528000e0u  /* mov w0, #7 */
#define CODE_RET 0xd65f03c0u /* ret */

typedef int (*code_fn)(void);

static void put_code(char *at, uint32_t first) {
    uint32_t words[2] = {first, CODE_RET};
    memcpy(at, words, sizeof words);
}

static volatile int bus_signal, bus_code;
static void *volatile bus_addr;

static void on_bus(int signal, siginfo_t *info, void *context) {
    (void)context;
    bus_signal = signal;
    bus_code = info->si_code;
    bus_addr = info->si_addr;
    siglongjmp(jump, 1);
}

static void forget_bus(void) {
    bus_signal = bus_code = 0;
    bus_addr = NULL;
}

/* 1 when the read (or the write) of the byte raises SIGBUS with BUS_ADRERR
 * and `at` as the address. */
static int bus_faults(volatile char *at, int write) {
    forget_bus();
    if (sigsetjmp(jump, 1)) return bus_signal == SIGBUS && bus_code == BUS_ADRERR && bus_addr == (void *)at;
    if (write) *at = 1;
    else (void)*at;
    return 0;
}

static void exec_memory(void) {
    struct sigaction info = {.sa_sigaction = on_fault_info, .sa_flags = SA_SIGINFO}, old;
    check("exec: sigaction", sigaction(SIGSEGV, &info, &old) == 0);
    char *p = anon(2 * PAGE, PROT_READ | PROT_WRITE);
    check("exec: mmap", p != NULL);
    if (!p) return;
    put_code(p, CODE_42);
    check("exec: mprotect to read and exec", mprotect(p, PAGE, PROT_READ | PROT_EXEC) == 0);
    check("exec: the code runs", ((code_fn)(void *)p)() == 42);
    forget_fault();
    check("exec: a write to the code faults", write_faults(p + 64));
    check("exec: the write says ACCERR and its address", fault_seen(SEGV_ACCERR, p + 64));
    check("exec: the code can be read", !read_faults(p));
    /* Again: back to writable, other code, executable. */
    check("exec: mprotect to writable", mprotect(p, PAGE, PROT_READ | PROT_WRITE) == 0);
    put_code(p, CODE_7);
    check("exec: mprotect to exec again", mprotect(p, PAGE, PROT_EXEC) == 0);
    check("exec: the new code runs", ((code_fn)(void *)p)() == 7);
    /* A child runs the same code at the same address. */
    pid_t child = fork();
    if (child == 0) {
        int bad = 0;
        if (((code_fn)(void *)p)() != 7) bad |= 1;
        /* The copy of a code page is mapped without write: back to
         * writable is refused in a child (a deviation, posix-coverage.md). */
        if (mprotect(p, PAGE, PROT_READ | PROT_WRITE) != -1 || errno != EACCES) bad |= 2;
        _exit(bad);
    }
    int status = 0;
    check("exec: fork", child > 0 && waitpid(child, &status, 0) == child);
    check("exec: the child ran the code", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (WIFEXITED(status) && WEXITSTATUS(status))
        printf("posix-map: exec child bits %d\n", WEXITSTATUS(status));
    /* The refusals. */
    errno = 0;
    check("exec: write and exec to mprotect is ENOTSUP",
          mprotect(p + PAGE, PAGE, PROT_WRITE | PROT_EXEC) == -1 && errno == ENOTSUP);
    errno = 0;
    check("exec: read, write and exec to mprotect is ENOTSUP",
          mprotect(p + PAGE, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1 && errno == ENOTSUP);
    errno = 0;
    check("exec: write and exec to mmap is ENOTSUP",
          mmap(NULL, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED
              && errno == ENOTSUP);
    errno = 0;
    check("exec: a shared mapping with exec is ENOTSUP",
          mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED
              && errno == ENOTSUP);
    check("exec: the refusals changed nothing", ((code_fn)(void *)p)() == 7);
    /* Executable at once: success and readable (zeros are not code). */
    char *q = mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("exec: mmap read and exec at once", q != MAP_FAILED);
    if (q != MAP_FAILED) {
        check("exec: and it reads zeros", !read_faults(q) && q[0] == 0);
        munmap(q, PAGE);
    }
    check("exec: restore the handler", sigaction(SIGSEGV, &old, NULL) == 0);
    munmap(p, 2 * PAGE);

    /* A private mapping of a file (mode 0600, no x) with code in it. */
    int fd = open(scratch, O_RDWR | O_CREAT | O_TRUNC, 0600);
    check("exec: create the file", fd >= 0);
    if (fd < 0) return;
    char page[PAGE] = {0};
    put_code(page, CODE_42);
    check("exec: write the file", write(fd, page, PAGE) == (ssize_t)PAGE);
    char *f = mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    check("exec: mmap the file with exec", f != MAP_FAILED);
    if (f != MAP_FAILED) {
        check("exec: the code of the file runs", ((code_fn)(void *)f)() == 42);
        munmap(f, PAGE);
    }
    errno = 0;
    check("exec: a shared mapping of the file with exec is ENOTSUP",
          mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0) == MAP_FAILED && errno == ENOTSUP);
    close(fd);
    unlink(scratch);
}

/* A reference to a whole page past the end of a mapped file is SIGBUS with
 * BUS_ADRERR (XSH mmap); the tail of the last page reads zeros. */
static void past_end(void) {
    struct sigaction bus = {.sa_sigaction = on_bus, .sa_flags = SA_SIGINFO}, old;
    check("bus: sigaction", sigaction(SIGBUS, &bus, &old) == 0);
    int fd = fill_file(PAGE / 2);
    check("bus: create", fd >= 0);
    if (fd < 0) return;
    for (int kind = 0; kind < 2; kind++) {
        const char *what = kind ? "shared" : "private";
        char *f = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, kind ? MAP_SHARED : MAP_PRIVATE, fd, 0);
        check("bus: mmap", f != MAP_FAILED);
        if (f == MAP_FAILED) continue;
        char text[64];
        snprintf(text, sizeof text, "bus: %s: the file reads", what);
        check(text, f[0] == 'a' && f[PAGE / 2 - 1] == (char)('a' + (PAGE / 2 - 1) % 26));
        snprintf(text, sizeof text, "bus: %s: the tail of the page is zeros", what);
        check(text, f[PAGE / 2] == 0 && f[PAGE - 1] == 0);
        snprintf(text, sizeof text, "bus: %s: a read past the end is SIGBUS", what);
        check(text, bus_faults(f + PAGE + 8, 0));
        snprintf(text, sizeof text, "bus: %s: a write past the end is SIGBUS", what);
        check(text, bus_faults(f + PAGE + 16, 1));
        munmap(f, 2 * PAGE);
    }
    close(fd);
    unlink(scratch);
    check("bus: restore the handler", sigaction(SIGBUS, &old, NULL) == 0);
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

/* The child of a fork maps the parent's code and read-only data objects:
 * no copy of them, no write through the code object, the code runs in the
 * child, and in a grandchild that outlives its parent. */
extern char **environ;
extern int stafeto_probe_image(uintptr_t address, uint64_t *out);
extern uint64_t stafeto_probe_memory_quota(void);

static int image_answer(void) { return 4242; }

/* Read-only data of a few pages, an object of its own. */
static const unsigned char image_table[3 * PAGE] = {1, 2, 3};

static int image_state(const void *at, uint64_t *words) {
    return stafeto_probe_image((uintptr_t)at, words);
}

/* What the code and the read-only data show in a process that shares them
 * with a live parent: bits of what is wrong. `code_base` and `data_base` are
 * the mappings the parent's objects had before the fork. */
static int image_bits(uint64_t code_base, uint64_t data_base) {
    uint64_t code[5] = {0}, data[5] = {0};
    int bad = 0;
    if (image_state((const void *)&image_answer, code) != 1 ||
        image_state((const void *)image_table, data) != 1)
        return 1;
    if (code[0] < code_base + 1 || data[0] < data_base + 1) bad |= 1;
    if (code[2] != 0 || data[2] != 0 || code[4] != 1 || data[4] != 1) bad |= 4;
    uintptr_t page = (uintptr_t)&image_answer & ~(PAGE - 1);
    /* The segments lie outside the room mprotect works in; writing the
     * code is refused for good. */
    errno = 0;
    if (mprotect((void *)page, PAGE, PROT_READ | PROT_WRITE) == 0 || errno != EACCES) bad |= 8;
    int (*volatile call)(void) = image_answer;
    if (call() != 4242) bad |= 16;
    if (((const volatile unsigned char *)image_table)[2] != 3) bad |= 32;
    return bad;
}

static void image_shared(void) {
    uint64_t before[5] = {0}, rodata[5] = {0};
    check("image: the code is in the map", image_state((const void *)&image_answer, before) == 1);
    check("image: the layer marks the code", before[4] == 1);
    check("image: the code has no writable handle", before[2] == 0);
    check("image: one mapping before the fork", before[0] == 1);
    check("image: the read-only data is in the map", image_state((const void *)image_table, rodata) == 1);
    check("image: the read-only data is an image", rodata[4] == 1 && rodata[2] == 0);
    int fds[2];
    check("image: pipe", pipe(fds) == 0);
    uint64_t parent_quota = stafeto_probe_memory_quota();
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) { printf("posix-map: fork failed with %d\n", errno); failures++; return; }
    if (child == 0) {
        close(fds[0]);
        uint64_t mine[5] = {0};
        int bad = image_bits(before[0], rodata[0]);
        if (image_state((const void *)&image_answer, mine) != 1) _exit(1);
        /* The child did not pay for the code and the read-only data. */
        if (mine[1] + (mine[3] + rodata[3]) * PAGE > before[1]) bad |= 2;
        /* Nor was it given the quota for them. */
        if (stafeto_probe_memory_quota() + (before[3] + rodata[3]) * PAGE > parent_quota) bad |= 128;
        /* A grandchild outlives the child and still runs the shared code. */
        pid_t middle = getpid();
        pid_t grandchild = fork();
        if (grandchild < 0) _exit(bad | 64);
        if (grandchild == 0) {
            for (int i = 0; i < 2000 && getppid() == middle; i++) {
                const struct timespec ms = {0, 1000000};
                nanosleep(&ms, NULL);
            }
            int late = getppid() == middle ? 128 : image_bits(before[0], rodata[0]);
            unsigned char byte = (unsigned char)late;
            _exit(write(fds[1], &byte, 1) == 1 ? 0 : 1);
        }
        (void)parent;
        _exit(bad);
    }
    close(fds[1]);
    int status = 0;
    check("image: waitpid", waitpid(child, &status, 0) == child);
    check("image: the child saw the shared code", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (WIFEXITED(status) && WEXITSTATUS(status))
        printf("posix-map: image child bits %d\n", WEXITSTATUS(status));
    unsigned char late = 255;
    check("image: the grandchild answered", read(fds[0], &late, 1) == 1);
    check("image: the grandchild ran the shared code after its parent left", late == 0);
    if (late) printf("posix-map: image grandchild bits %d\n", late);
    close(fds[0]);
    /* The grandchild wrote its byte before its exit: its mapping goes when the
     * process service has torn its space down, a moment after the read here
     * returned (on several CPUs the other CPU is still at it). Wait for it. */
    uint64_t after[5] = {0};
    int found = image_state((const void *)&image_answer, after);
    for (int i = 0; i < 2000 && found == 1 && after[0] != 1; i++) {
        const struct timespec ms = {0, 1000000};
        nanosleep(&ms, NULL);
        found = image_state((const void *)&image_answer, after);
    }
    check("image: one mapping after the children", found == 1 && after[0] == 1);
}

/* Processes spawned from one file run the same code and read-only data
 * (the table of images); a file of another inode, though it holds the same
 * bytes, is another image. The role asks `expect` 1 for shared and 0 for
 * alone. */
static int image_role(int ready, int go, int done, int expect) {
    unsigned char byte = 1;
    if (write(ready, &byte, 1) != 1) return 1;
    if (read(go, &byte, 1) != 1) return 2;
    uint64_t code[5] = {0}, data[5] = {0};
    if (image_state((const void *)&image_answer, code) != 1 ||
        image_state((const void *)image_table, data) != 1)
        return 3;
    int bad = 0;
    if (expect) {
        if (code[0] < 2) bad |= 4;
        if (data[0] < 2) bad |= 8;
    } else {
        if (code[0] != 1) bad |= 16;
        if (data[0] != 1) bad |= 32;
    }
    if (code[2] != 0 || data[2] != 0) bad |= 64;
    int (*volatile call)(void) = image_answer;
    if (call() != 4242) bad |= 64;
    if (((const volatile unsigned char *)image_table)[2] != 3) bad |= 64;
    /* Every process keeps its image until all have looked at theirs. */
    byte = (unsigned char)bad;
    if (write(ready, &byte, 1) != 1) return 4;
    if (read(done, &byte, 1) != 1) return 5;
    return 0;
}

/* The `count` processes loaded wrote a byte each to `ready`; release them,
 * collect what each saw (bits of what is wrong, ORed) and let them go. */
static int image_look(int ready, int go, int done, int count, int *saw) {
    unsigned char bytes[4] = {0};
    int ok = write(go, "xxxx", (size_t)count) == count;
    *saw = 0;
    for (int i = 0; i < count; i++) {
        if (read(ready, bytes, 1) != 1) { ok = 0; continue; }
        *saw |= bytes[0];
    }
    return ok && write(done, "xxxx", (size_t)count) == count;
}

static int spawn_image(const char *path, int ready, int go, int done, int expect, pid_t *pid) {
    char r[16], g[16], d[16];
    snprintf(r, sizeof r, "%d", ready);
    snprintf(g, sizeof g, "%d", go);
    snprintf(d, sizeof d, "%d", done);
    char *args[] = {"map", "image", r, g, d, expect ? "1" : "0", NULL};
    return posix_spawn(pid, path, NULL, NULL, args, environ);
}

static int copy_file(const char *from, const char *to) {
    int in = open(from, O_RDONLY);
    int out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (in < 0 || out < 0) {
        if (in >= 0) close(in);
        if (out >= 0) close(out);
        return -1;
    }
    static char buffer[16384];
    ssize_t n;
    int ok = 1;
    while ((n = read(in, buffer, sizeof buffer)) > 0)
        if (write(out, buffer, (size_t)n) != n) { ok = 0; break; }
    if (n < 0) ok = 0;
    close(in);
    close(out);
    return ok ? 0 : -1;
}

static int image_exit(pid_t pid) {
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

/* Two threads spawn one file that no process runs yet, all at once (a parent
 * has two loads at most): one loader makes the objects and the other waits
 * for them, so both share. */
struct racer {
    const char *path;
    int ready, go, done;
    pid_t pid;
    int error;
};

static void *race_spawn(void *arg) {
    struct racer *racer = arg;
    racer->error = spawn_image(racer->path, racer->ready, racer->go, racer->done, 1, &racer->pid);
    return NULL;
}

static void image_race(void) {
    int ready[2], go[2], done[2];
    check("race image: pipes", pipe(ready) == 0 && pipe(go) == 0 && pipe(done) == 0);
    const char *copy = "/tmp/image-race";
    unlink(copy);
    check("race image: copy", copy_file("/bin/procs-child", copy) == 0);
    struct racer racers[2];
    pthread_t threads[2];
    for (int i = 0; i < 2; i++) {
        racers[i] = (struct racer){copy, ready[1], go[0], done[0], -1, -1};
        check("race image: thread", pthread_create(&threads[i], NULL, race_spawn, &racers[i]) == 0);
    }
    for (int i = 0; i < 2; i++) pthread_join(threads[i], NULL);
    unsigned char byte;
    int spawned = racers[0].error == 0 && racers[1].error == 0;
    check("race image: both spawned", spawned);
    if (!spawned) return;
    check("race image: both loaded", read(ready[0], &byte, 1) == 1 && read(ready[0], &byte, 1) == 1);
    int saw = -1;
    check("race image: look", image_look(ready[0], go[1], done[1], 2, &saw));
    check("race image: two spawns at once share one object", saw == 0);
    if (saw) printf("posix-map: race image bits %d\n", saw);
    check("race image: exit", image_exit(racers[0].pid) == 0 && image_exit(racers[1].pid) == 0);
    unlink(copy);
    close(ready[0]);
    close(ready[1]);
    close(go[0]);
    close(go[1]);
    close(done[0]);
    close(done[1]);
}

/* A process execs the file it runs (`exec sh` from `sh`): the entry of the
 * image stays registered to it, so the next process that runs the file
 * shares the object. The first one is spawned from a fresh copy, execs the
 * copy itself and then is the role `image`; the second is spawned after it
 * has loaded, and both have to see the code and the data mapped twice. */
static int exec_self(char **argv) {
    char *args[] = {"map", "image", argv[2], argv[3], argv[4], "1", NULL};
    execve(argv[5], args, environ);
    return 9;
}

static void image_exec_self(void) {
    int ready[2], go[2], done[2];
    check("exec image: pipes", pipe(ready) == 0 && pipe(go) == 0 && pipe(done) == 0);
    const char *copy = "/tmp/image-exec";
    unlink(copy);
    check("exec image: copy", copy_file("/bin/procs-child", copy) == 0);
    char r[16], g[16], d[16];
    snprintf(r, sizeof r, "%d", ready[1]);
    snprintf(g, sizeof g, "%d", go[0]);
    snprintf(d, sizeof d, "%d", done[0]);
    char *args[] = {"map", "execself", r, g, d, (char *)copy, NULL};
    pid_t a, b;
    check("exec image: spawn", posix_spawn(&a, copy, NULL, NULL, args, environ) == 0);
    unsigned char byte;
    check("exec image: the exec loaded", read(ready[0], &byte, 1) == 1);
    check("exec image: second spawn", spawn_image(copy, ready[1], go[0], done[0], 1, &b) == 0);
    check("exec image: second loaded", read(ready[0], &byte, 1) == 1);
    int saw = -1;
    check("exec image: look", image_look(ready[0], go[1], done[1], 2, &saw));
    check("exec image: a process that execs its own file keeps the image for the next one", saw == 0);
    if (saw) printf("posix-map: exec image bits %d\n", saw);
    check("exec image: exit", image_exit(a) == 0 && image_exit(b) == 0);
    unlink(copy);
    close(ready[0]);
    close(ready[1]);
    close(go[0]);
    close(go[1]);
    close(done[0]);
    close(done[1]);
}

static void image_spawned(void) {
    int ready[2], go[2], done[2];
    check("spawned image: pipes", pipe(ready) == 0 && pipe(go) == 0 && pipe(done) == 0);
    pid_t a, b;
    check("spawned image: first spawn", spawn_image("/bin/procs-child", ready[1], go[0], done[0], 1, &a) == 0);
    check("spawned image: second spawn", spawn_image("/bin/procs-child", ready[1], go[0], done[0], 1, &b) == 0);
    unsigned char byte;
    check("spawned image: both loaded", read(ready[0], &byte, 1) == 1 && read(ready[0], &byte, 1) == 1);
    int saw = -1;
    check("spawned image: look", image_look(ready[0], go[1], done[1], 2, &saw));
    check("spawned image: two spawns of one file share the code and the read-only data", saw == 0);
    if (saw) printf("posix-map: spawned image bits %d\n", saw);
    check("spawned image: exit", image_exit(a) == 0 && image_exit(b) == 0);
    /* The same bytes in a file of another inode are another image, though
     * the first one is still run. */
    const char *copy = "/tmp/image-copy";
    unlink(copy);
    check("spawned image: copy", copy_file("/bin/procs-child", copy) == 0);
    pid_t c1, c1b, c2;
    check("spawned image: copy spawn", spawn_image(copy, ready[1], go[0], done[0], 1, &c1) == 0);
    check("spawned image: copy spawn again", spawn_image(copy, ready[1], go[0], done[0], 1, &c1b) == 0);
    check("spawned image: copies loaded", read(ready[0], &byte, 1) == 1 && read(ready[0], &byte, 1) == 1);
    check("spawned image: replace", unlink(copy) == 0 && copy_file("/bin/procs-child", copy) == 0);
    check("spawned image: replaced spawn", spawn_image(copy, ready[1], go[0], done[0], 0, &c2) == 0);
    check("spawned image: replaced loaded", read(ready[0], &byte, 1) == 1);
    check("spawned image: look at the copies", image_look(ready[0], go[1], done[1], 3, &saw));
    check("spawned image: one inode shares, the replacement is alone", saw == 0);
    if (saw) printf("posix-map: spawned image copy bits %d\n", saw);
    check("spawned image: copies exit", image_exit(c1) == 0 && image_exit(c1b) == 0 && image_exit(c2) == 0);
    unlink(copy);
    close(ready[0]);
    close(ready[1]);
    close(go[0]);
    close(go[1]);
    close(done[0]);
    close(done[1]);
}

/* A fork of a map with 96 groups of regions that do not adjoin (the table of
 * pieces holds 128, the program's own take some 30 and the buffer of the
 * large reads of files one): four objects of 64 pages, of which every second
 * page is given back (the first object keeps 31 groups and gives back its
 * last two pages in one run, the last keeps one page and loses the rest in
 * one run). The child binds an object for each group (the loader joins
 * adjoining regions of one object), and the table of objects holds as many
 * as the table of pieces, 128: the fork has to succeed, and the child has the
 * map. Blocks of 64 pages keep the memory held small. */
#define BLOCKS 4
#define BLOCK_PAGES 64
/* The pages of a block that stay in groups: the first one up to page 61. */
static size_t block_limit(int b) { return b == BLOCKS - 1 ? 2 : b == 0 ? BLOCK_PAGES - 2 : BLOCK_PAGES; }
static void forked_many(void) {
    char *block[BLOCKS];
    size_t kept = 0;
    for (int b = 0; b < BLOCKS; b++) {
        block[b] = anon(BLOCK_PAGES * PAGE, PROT_READ | PROT_WRITE);
        check("many: mmap", block[b] != NULL);
        if (!block[b]) return;
        for (size_t i = 0; i < BLOCK_PAGES; i += 2) block[b][i * PAGE] = (char)(b * 40 + i / 2 + 1);
        size_t limit = block_limit(b);
        for (size_t i = 1; i < limit; i += 2) check("many: hole", munmap(block[b] + i * PAGE, PAGE) == 0);
        if (limit < BLOCK_PAGES)
            check("many: the run of holes", munmap(block[b] + limit * PAGE, (BLOCK_PAGES - limit) * PAGE) == 0);
        kept += limit / 2;
    }
    check("many: 96 groups", kept == 31 + 32 + 32 + 1);
    pid_t child = fork();
    if (child < 0) {
        printf("posix-map: many: fork gave errno %d\n", errno);
        failures++;
    } else if (child == 0) {
        int bad = 0;
        for (int b = 0; b < BLOCKS; b++) {
            size_t limit = block_limit(b);
            for (size_t i = 0; i < limit; i += 2)
                if (block[b][i * PAGE] != (char)(b * 40 + i / 2 + 1)) bad = 1;
            if (!read_faults(block[b] + PAGE)) bad |= 2;
        }
        _exit(bad);
    } else {
        int status = 0;
        check("many: waitpid", waitpid(child, &status, 0) == child);
        check("many: the child binds all the groups and exits 0",
              WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    for (int b = 0; b < BLOCKS; b++) {
        size_t limit = block_limit(b);
        for (size_t i = 0; i < limit; i += 2) munmap(block[b] + i * PAGE, PAGE);
    }
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

/* The maker of a shared object holds the entry reserved for a while
 * (stafeto_probe_fill_pause of the layer); the pause is in milliseconds. */
extern void stafeto_probe_fill_pause(unsigned milliseconds);
extern void stafeto_probe_grant_pause(unsigned milliseconds);

static const char *racing = "/tmp/posix-map-race";
#define RACE_PAGES 128

static int make_race_file(void) {
    int fd = open(racing, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    static char block[PAGE];
    for (size_t at = 0; at < RACE_PAGES * PAGE; at += PAGE) {
        for (size_t i = 0; i < PAGE; i++) block[i] = (char)('a' + (at / PAGE + i) % 26);
        if (pwrite(fd, block, PAGE, (off_t)at) != (ssize_t)PAGE) { close(fd); return -1; }
    }
    return fd;
}

/* The page `page` of the race file reads as its maker filled it. */
static int race_page_ok(const char *p, size_t page) {
    return p[page * PAGE + 3] == (char)('a' + (page + 3) % 26);
}

static void pause_ms(long ms) {
    struct timespec t = {ms / 1000, ms % 1000 * 1000000L};
    nanosleep(&t, NULL);
}

/* A process asks for the shared object of a file while another is making
 * it (the maker pauses 300 ms with the entry reserved): it waits for the
 * maker, whatever the levels of the two, and gets the same pages as the
 * maker. A write of either shows in the other. */
static void shared_while_made(void) {
    int ready[2], done[2], go[2];
    int fd = make_race_file();
    check("race: the file", fd >= 0);
    check("race: pipes", pipe(ready) == 0 && pipe(done) == 0 && pipe(go) == 0);
    if (fd < 0) return;
    pid_t maker = fork();
    if (maker < 0) { printf("posix-map: fork failed with %d\n", errno); failures++; return; }
    if (maker == 0) {
        int bad = 0;
        char c = 'r';
        stafeto_probe_fill_pause(300);
        if (write(ready[1], &c, 1) != 1) _exit(1);
        char *a = mmap(NULL, RACE_PAGES * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (a == MAP_FAILED) _exit(2);
        if (!race_page_ok(a, 100)) bad |= 4;
        a[1] = 'R';
        c = 'd';
        if (write(done[1], &c, 1) != 1) _exit(3);
        if (read(go[0], &c, 1) != 1) _exit(5);
        if (a[0] != 'Q') bad |= 8;
        _exit(bad);
    }
    char c = 0;
    check("race: the maker is on its way", read(ready[0], &c, 1) == 1);
    /* The maker has the entry reserved and sleeps. */
    pause_ms(100);
    char *p = mmap(NULL, RACE_PAGES * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("race: mmap while another makes the object", p != MAP_FAILED);
    if (p != MAP_FAILED) {
        check("race: the file is in the pages", race_page_ok(p, 100) && race_page_ok(p, 0));
        check("race: the maker is done", read(done[0], &c, 1) == 1);
        check("race: the maker's write shows", p[1] == 'R');
        p[0] = 'Q';
        check("race: tell the maker", write(go[1], &c, 1) == 1);
    } else {
        write(go[1], &c, 1);
    }
    int status = 0;
    check("race: waitpid", waitpid(maker, &status, 0) == maker);
    check("race: our write shows in the maker", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (WIFEXITED(status) && WEXITSTATUS(status))
        printf("posix-map: race: the maker ended with %d\n", WEXITSTATUS(status));
    if (p != MAP_FAILED) munmap(p, RACE_PAGES * PAGE);
    close(fd);
    unlink(racing);
    close(ready[0]); close(ready[1]); close(done[0]); close(done[1]); close(go[0]); close(go[1]);
}

/* Two threads of one process map one file at once: one object, so the
 * first thread's write shows in the second thread's mapping. */
static volatile int race_start;
static char *volatile race_maps[2];

static void *race_thread(void *arg) {
    long which = (long)arg;
    int fd = open(racing, O_RDWR);
    while (!race_start) sched_yield();
    char *p = mmap(NULL, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    race_maps[which] = p == MAP_FAILED ? NULL : p;
    close(fd);
    return NULL;
}

/* One round: the two threads ask together; the maker pauses `fill`
 * milliseconds with the entry reserved, and each thread `grant` between its
 * vouching and its ask, so that both vouchings come before the first
 * answer. */
static int two_threads_once(unsigned fill, unsigned grant) {
    stafeto_probe_fill_pause(fill);
    stafeto_probe_grant_pause(grant);
    pthread_t threads[2];
    race_start = 0;
    race_maps[0] = race_maps[1] = NULL;
    int made = 1;
    for (long i = 0; i < 2; i++) made &= pthread_create(&threads[i], NULL, race_thread, (void *)i) == 0;
    if (!made) return 0;
    race_start = 1;
    for (int i = 0; i < 2; i++) pthread_join(threads[i], NULL);
    char *a = race_maps[0], *b = race_maps[1];
    int good = a && b && race_page_ok(a, 2) && race_page_ok(b, 2);
    if (good) {
        a[7] = 'Z';
        good = b[7] == 'Z';
        b[9] = 'Y';
        good = good && a[9] == 'Y';
    }
    if (a) munmap(a, 4 * PAGE);
    if (b) munmap(b, 4 * PAGE);
    return good;
}

/* Two threads of one process map one file at once, 50 times, half of them
 * with the maker held (the object is made while the other waits) and half
 * with both vouchings before the first answer:
 * one object each time, so a write of one shows in the other. */
static void shared_by_two_threads(void) {
    int fd = make_race_file();
    check("threads: the file", fd >= 0);
    if (fd < 0) return;
    close(fd);
    int good = 1, round = 0;
    for (; round < 50 && good; round++) good = two_threads_once(round % 2 ? 20 : 0, round % 2 ? 0 : 10);
    if (!good) printf("posix-map: threads: round %d gave two objects\n", round);
    check("threads: 50 rounds of one object", good);
    stafeto_probe_fill_pause(0);
    stafeto_probe_grant_pause(0);
    unlink(racing);
}

/* The maker of a shared object ends while the entry is reserved (killed in
 * its pause): the asker that waits becomes the maker, maps the file, and
 * the next asker gets that object. */
static void shared_when_the_maker_goes(void) {
    int ready_m[2], ready_w[2], done_w[2], go_w[2];
    int fd = make_race_file();
    check("gone: the file", fd >= 0);
    check("gone: pipes", pipe(ready_m) == 0 && pipe(ready_w) == 0 && pipe(done_w) == 0 && pipe(go_w) == 0);
    if (fd < 0) return;
    pid_t maker = fork();
    if (maker < 0) { printf("posix-map: fork failed with %d\n", errno); failures++; return; }
    if (maker == 0) {
        char c = 'r';
        stafeto_probe_fill_pause(5000);
        if (write(ready_m[1], &c, 1) != 1) _exit(1);
        mmap(NULL, RACE_PAGES * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        _exit(2);
    }
    char c = 0;
    check("gone: the maker is on its way", read(ready_m[0], &c, 1) == 1);
    pause_ms(50);
    pid_t waiter = fork();
    if (waiter < 0) { printf("posix-map: fork failed with %d\n", errno); failures++; return; }
    if (waiter == 0) {
        int bad = 0;
        stafeto_probe_fill_pause(0);
        if (write(ready_w[1], &c, 1) != 1) _exit(1);
        char *a = mmap(NULL, RACE_PAGES * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (a == MAP_FAILED) _exit(2);
        if (!race_page_ok(a, 100)) bad |= 4;
        a[1] = 'R';
        if (write(done_w[1], &c, 1) != 1) _exit(3);
        if (read(go_w[0], &c, 1) != 1) _exit(5);
        if (a[0] != 'Q') bad |= 8;
        _exit(bad);
    }
    check("gone: the waiter is on its way", read(ready_w[0], &c, 1) == 1);
    pause_ms(100);
    /* The waiter waits in the service for the maker, who sleeps. */
    check("gone: kill the maker", kill(maker, SIGKILL) == 0);
    int status = 0;
    check("gone: the maker is gone", waitpid(maker, &status, 0) == maker && WIFSIGNALED(status));
    check("gone: the waiter made the object", read(done_w[0], &c, 1) == 1);
    char *p = mmap(NULL, RACE_PAGES * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("gone: the next asker maps", p != MAP_FAILED);
    if (p != MAP_FAILED) {
        check("gone: the waiter's write shows", p[1] == 'R');
        p[0] = 'Q';
        munmap(p, RACE_PAGES * PAGE);
    }
    check("gone: tell the waiter", write(go_w[1], &c, 1) == 1);
    check("gone: waitpid", waitpid(waiter, &status, 0) == waiter);
    check("gone: our write shows in the waiter", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(fd);
    unlink(racing);
    close(ready_m[0]); close(ready_m[1]); close(ready_w[0]); close(ready_w[1]);
    close(done_w[0]); close(done_w[1]); close(go_w[0]); close(go_w[1]);
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

/* Many cuts of the heap's pages: the table of the kernel stays short of
 * places, the free runs are joined, and a freed page still faults. */
static void fragmentation(void) {
    char *kept[40] = {0};
    int fine = 1;
    char *last = NULL;
    for (int round = 0; round < 600 && fine; round++) {
        char *a = anon(PAGE, PROT_READ | PROT_WRITE);
        char *b = anon(PAGE, PROT_READ | PROT_WRITE);
        if (!a || !b) { fine = 0; break; }
        a[0] = 1;
        b[0] = 2;
        munmap(a, PAGE);
        last = a;
        int slot = round % 40;
        if (kept[slot]) munmap(kept[slot], PAGE);
        kept[slot] = b;
    }
    check("fragmentation: 600 rounds", fine);
    check("fragmentation: a freed page still faults", last && read_faults(last));
    for (int i = 0; i < 40; i++) if (kept[i]) munmap(kept[i], PAGE);
    check("fragmentation: the freed pages fault", last && read_faults(last));
}

/* A process that maps a file, writes and leaves without msync: by exit, by
 * _exit or by exec. */
static int leaver(const char *how) {
    int fd = open(scratch, O_RDWR);
    if (fd < 0) return 1;
    char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) return 2;
    close(fd);
    p[3] = 'L';
    if (strcmp(how, "exit") == 0) exit(0);
    if (strcmp(how, "_exit") == 0) _exit(0);
    char *args[] = {"map", "peer", "/none", NULL};
    char *env[] = {NULL};
    execve("/bin/procs-child", args, env);
    return 3;
}

static void leaving(void) {
    const char *how[] = {"exit", "_exit", "exec"};
    for (int i = 0; i < 3; i++) {
        int fd = fill_file(PAGE);
        check("leave: create", fd >= 0);
        if (fd < 0) return;
        close(fd);
        char *args[] = {"map", "leave", (char *)how[i], NULL};
        pid_t child;
        int status = 0;
        int error = posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, environ);
        if (!error) waitpid(child, &status, 0);
        char what[64];
        snprintf(what, sizeof what, "leave: a write is kept by %s", how[i]);
        check(what, !error && WIFEXITED(status) && file_byte(3) == 'L');
        unlink(scratch);
    }
}

/* What the mapping may write back and where, and what the program may map. */
static void review(void) {
    int fd = fill_file(2 * PAGE);
    check("review: create", fd >= 0);
    if (fd < 0) return;
    /* A read-only shared mapping never writes the file: a pwrite after the
     * mmap stays. */
    char *r = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, 0);
    check("review: read-only mmap", r != MAP_FAILED);
    check("review: pwrite", pwrite(fd, "Z", 1, 0) == 1);
    if (r != MAP_FAILED) {
        check("review: msync of a read-only mapping", msync(r, PAGE, MS_SYNC) == 0);
        check("review: munmap of a read-only mapping", munmap(r, PAGE) == 0);
    }
    check("review: the pwrite is not overwritten", file_byte(0) == 'Z');
    /* A mapping that became writable does write. */
    r = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, 0);
    check("review: mprotect to write", r != MAP_FAILED && mprotect(r, PAGE, PROT_READ | PROT_WRITE) == 0);
    if (r != MAP_FAILED) {
        r[1] = 'W';
        munmap(r, PAGE);
        check("review: and is written back", file_byte(1) == 'W');
    }
    /* MS_INVALIDATE reads the file again. */
    char *w = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("review: mmap", w != MAP_FAILED);
    if (w != MAP_FAILED) {
        check("review: pwrite behind the mapping", pwrite(fd, "Q", 1, 2) == 1);
        check("review: invalidate", msync(w, PAGE, MS_SYNC | MS_INVALIDATE) == 0);
        check("review: the mapping shows the file", w[2] == 'Q');
        char *ro = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, 0);
        if (ro != MAP_FAILED) {
            pwrite(fd, "R", 1, 4);
            check("review: invalidate of a read-only mapping", msync(ro, PAGE, MS_SYNC | MS_INVALIDATE) == 0 && ro[4] == 'R');
            check("review: and it stays read-only", write_faults(ro) && mprotect(ro, PAGE, PROT_READ | PROT_WRITE) == 0);
            munmap(ro, PAGE);
        }
        /* The layer keeps no number for the mapping: another file put on any
         * free number, the high ones included, is not written to and not
         * closed, and the mapping still writes its own file. */
        int other = open("/tmp/posix-map-other", O_RDWR | O_CREAT | O_TRUNC, 0600);
        check("review: another file", other >= 0 && ftruncate(other, PAGE) == 0);
        int put = 0;
        if (other >= 0) {
            for (int n = 3; n < 64; n++) {
                if (n != fd && n != other && fcntl(n, F_GETFD) < 0 && dup2(other, n) == n) put++;
            }
        }
        check("review: every free number took another file", other >= 0 && put > 30);
        if (other >= 0) {
            w[5] = 'S';
            check("review: msync", msync(w, PAGE, MS_SYNC) == 0);
            char c = 0;
            check("review: msync does not write to the other file", pread(other, &c, 1, 5) == 1 && c == 0);
            c = 0;
            check("review: and the file is written", pread(fd, &c, 1, 5) == 1 && c == 'S');
            check("review: munmap", munmap(w, PAGE) == 0);
            w = MAP_FAILED;
            int alive = 0;
            for (int n = 3; n < 64; n++) {
                if (n != fd && n != other && fcntl(n, F_GETFD) >= 0) alive++;
            }
            check("review: munmap does not close the program's descriptors", alive == put);
            for (int n = 3; n < 64; n++) {
                if (n != fd && n != other) close(n);
            }
        }
        if (w != MAP_FAILED) munmap(w, PAGE);
        if (other >= 0) close(other);
        unlink("/tmp/posix-map-other");
    }
    /* The last munmap ends the object: the next mapping is the file's pages,
     * not the object the service kept. */
    {
        char *a = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        check("detach: mmap", a != MAP_FAILED);
        if (a != MAP_FAILED) {
            a[9] = 'A';
            munmap(a, PAGE);
            check("detach: pwrite behind the ended object", pwrite(fd, "B", 1, 9) == 1);
            char *b = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, 0);
            check("detach: the new mapping shows the file", b != MAP_FAILED && b[9] == 'B');
            if (b != MAP_FAILED) munmap(b, PAGE);
        }
    }
    close(fd);
    /* The mode of the descriptor. */
    fd = open(scratch, O_RDONLY);
    errno = 0;
    check("access: shared write on a read-only descriptor is EACCES",
          mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == MAP_FAILED && errno == EACCES);
    char *ro = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, 0);
    check("access: shared read on a read-only descriptor", ro != MAP_FAILED);
    errno = 0;
    check("access: and it does not become writable", ro != MAP_FAILED
          && mprotect(ro, PAGE, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
    if (ro != MAP_FAILED) munmap(ro, PAGE);
    char *pr = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    check("access: private write on a read-only descriptor", pr != MAP_FAILED);
    if (pr != MAP_FAILED) munmap(pr, PAGE);
    close(fd);
    fd = open(scratch, O_WRONLY);
    errno = 0;
    check("access: a write-only descriptor is EACCES",
          mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED && errno == EACCES);
    close(fd);
    fd = open(scratch, O_RDWR | O_APPEND);
    errno = 0;
    check("access: an append descriptor is EACCES for a shared write",
          mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == MAP_FAILED && errno == EACCES);
    close(fd);
    /* An error of the write back is the error of msync. */
    fd = open(scratch, O_RDWR);
    char *e = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (e != MAP_FAILED) {
        struct sigaction ignore = {.sa_handler = SIG_IGN}, old;
        sigaction(SIGXFSZ, &ignore, &old);
        struct rlimit saved, small;
        getrlimit(RLIMIT_FSIZE, &saved);
        small = saved;
        small.rlim_cur = 100;
        setrlimit(RLIMIT_FSIZE, &small);
        e[7] = 'E';
        errno = 0;
        check("access: msync reports a failed write", msync(e, PAGE, MS_SYNC) == -1 && errno != 0);
        setrlimit(RLIMIT_FSIZE, &saved);
        sigaction(SIGXFSZ, &old, NULL);
        munmap(e, PAGE);
    }
    close(fd);
    unlink(scratch);
}

#define PINS 16

static void pin_path(char *out, size_t size, int i) {
    snprintf(out, size, "/tmp/posix-map-pin-%d", i);
}

static int byte_at(const char *path, off_t at) {
    int fd = open(path, O_RDONLY);
    char c = 0;
    int got = fd >= 0 && pread(fd, &c, 1, at) == 1;
    if (fd >= 0) close(fd);
    return got ? c : -1;
}

/* Makes the file i of PAGE bytes of 'a' and maps it shared and writable;
 * the descriptor is closed at once, so the mapping alone keeps the file. */
static char *pin_map_prot(int i, int prot) {
    char path[48];
    pin_path(path, sizeof path, i);
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return NULL;
    char text[16];
    memset(text, 'a', sizeof text);
    for (size_t at = 0; at < PAGE; at += sizeof text) {
        if (write(fd, text, sizeof text) != (ssize_t)sizeof text) {
            close(fd);
            return NULL;
        }
    }
    char *p = mmap(NULL, PAGE, prot, MAP_SHARED, fd, 0);
    int saved = errno;
    close(fd);
    errno = saved;
    return p == MAP_FAILED ? NULL : p;
}

static char *pin_map(int i) {
    return pin_map_prot(i, PROT_READ | PROT_WRITE);
}

/* The numbers open now, 0 to 1 023. */
static int numbers_open(void) {
    int open_now = 0;
    for (int n = 0; n < 1024; n++) {
        if (fcntl(n, F_GETFD) >= 0) open_now++;
    }
    return open_now;
}

static void pin_unlink_all(void) {
    char path[48];
    for (int i = 0; i <= PINS; i++) {
        pin_path(path, sizeof path, i);
        unlink(path);
    }
}

/* The description of a shared mapping of a file has no number: the mapping
 * works after the program closed every descriptor, the program keeps all 64
 * numbers, a forked child keeps the mapping, and a process has 16 files
 * mapped shared at once. */
static void pins(void) {
    char *maps[PINS + 1] = {0};
    char path[48];
    pin_unlink_all();
    int before = numbers_open();
    for (int i = 0; i < PINS; i++) {
        maps[i] = pin_map(i);
        if (!maps[i]) printf("posix-map: pins: file %d: errno %d\n", i, errno);
    }
    int mapped = 0;
    for (int i = 0; i < PINS; i++) mapped += maps[i] != NULL;
    check("pins: 16 files mapped shared", mapped == PINS);
    if (mapped != PINS) goto out;
    check("pins: the mappings took no number", numbers_open() == before);
    /* Not a number is found by a search, and a close of every number from
     * 3 leaves the mappings alone. */
    for (int n = 3; n < 1024; n++) close(n);
    check("pins: the mappings survive the close of every number", numbers_open() == 3);
    for (int i = 0; i < PINS; i++) maps[i][i] = 'P';
    int written = 0;
    for (int i = 0; i < PINS; i++) written += msync(maps[i], PAGE, MS_SYNC) == 0;
    check("pins: msync of all", written == PINS);
    int stored = 0;
    for (int i = 0; i < PINS; i++) {
        pin_path(path, sizeof path, i);
        stored += byte_at(path, i) == 'P' && byte_at(path, PINS) == 'a';
    }
    check("pins: the writes are in the files", stored == PINS);
    /* A 17th file is refused with ENOMEM, and a free place takes it. */
    errno = 0;
    /* (read only: the process service keeps 16 objects of writable ones) */
    char *extra = pin_map_prot(PINS, PROT_READ);
    check("pins: the 17th file is ENOMEM", extra == NULL && errno == ENOMEM);
    pin_path(path, sizeof path, 0);
    int again_fd = open(path, O_RDWR);
    char *again = again_fd < 0 ? MAP_FAILED : mmap(NULL, PAGE, PROT_READ, MAP_SHARED, again_fd, 0);
    check("pins: another mapping of a mapped file needs no place", again != MAP_FAILED && again[0] == 'P');
    if (again != MAP_FAILED) munmap(again, PAGE);
    if (again_fd >= 0) close(again_fd);
    /* The program keeps all its numbers: a file and its copies fill the
     * table to the end while 16 mappings exist. */
    pin_path(path, sizeof path, 0);
    int fd = open(path, O_RDONLY);
    int copies = 0;
    while (fd >= 0 && dup(fd) >= 0) copies++;
    check("pins: all 1 024 numbers are free to use", fd >= 0 && fd + copies == 1023 && errno == EMFILE);
    check("pins: and the table is full", numbers_open() == 1024);
    for (int n = 3; n < 1024; n++) close(n);
    /* A forked child has the mappings and writes through them. */
    pid_t child = fork();
    if (child == 0) {
        int bad = 0;
        for (int i = 0; i < PINS; i++) {
            if (maps[i][i] != 'P') bad |= 1;
            maps[i][i + 100] = 'C';
            if (msync(maps[i], PAGE, MS_SYNC)) bad |= 2;
        }
        if (numbers_open() != 3) bad |= 4;
        _exit(bad);
    }
    int status = 0;
    check("pins: fork", child > 0 && waitpid(child, &status, 0) == child);
    check("pins: the child keeps the mappings", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    int kept = 0;
    for (int i = 0; i < PINS; i++) {
        pin_path(path, sizeof path, i);
        kept += byte_at(path, i + 100) == 'C';
    }
    check("pins: the child's msync wrote the files", kept == PINS);
    /* The last munmap gives the place back. */
    check("pins: munmap", munmap(maps[0], PAGE) == 0);
    maps[0] = NULL;
    extra = pin_map_prot(PINS, PROT_READ);
    check("pins: a place freed takes the 17th file", extra != NULL);
    maps[PINS] = extra;
out:
    for (int i = 0; i <= PINS; i++) {
        if (maps[i]) munmap(maps[i], PAGE);
    }
    /* All the descriptions went with the mappings: 32 files open at once. */
    pin_path(path, sizeof path, 1);
    int opened = 0;
    int fds[40];
    while (opened < 40 && (fds[opened] = open(path, O_RDONLY)) >= 0) opened++;
    check("pins: the descriptions are given back", opened >= 32);
    while (opened > 0) close(fds[--opened]);
    pin_unlink_all();
}

/* The places a new process has for files: what `pinsafter` opens. */
static int spawn_status(char **args) {
    pid_t child;
    int status = 0;
    int error = posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, environ);
    if (!error) waitpid(child, &status, 0);
    return !error && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* The pin of a shared mapping serves the writes of a description open for
 * writing only: a file mapped for reading from a read-only descriptor and
 * then for writing from another reaches the file, in both orders. */
static void pins_modes(void) {
    const char *path = "/tmp/posix-map-modes";
    for (int order = 0; order < 2; order++) {
        int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        char text[64];
        memset(text, 'm', sizeof text);
        check("modes: file", fd >= 0 && write(fd, text, sizeof text) == (ssize_t)sizeof text);
        close(fd);
        char *reader = NULL, *writer = NULL;
        for (int step = 0; step < 2; step++) {
            if ((step == 0) == (order == 0)) {
                int r = open(path, O_RDONLY);
                reader = r < 0 ? NULL : mmap(NULL, PAGE, PROT_READ, MAP_SHARED, r, 0);
                if (reader == MAP_FAILED) reader = NULL;
                if (r >= 0) close(r);
            } else {
                int w = open(path, O_RDWR);
                writer = w < 0 ? NULL : mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, w, 0);
                if (writer == MAP_FAILED) writer = NULL;
                if (w >= 0) close(w);
            }
        }
        check(order ? "modes: write then read: both mapped" : "modes: read then write: both mapped",
              reader && writer);
        if (reader && writer) {
            writer[5] = 'W';
            check("modes: msync of the writer", msync(writer, PAGE, MS_SYNC) == 0);
            check("modes: the byte is in the file", byte_at(path, 5) == 'W');
            writer[6] = 'V';
            check("modes: munmap of the writer", munmap(writer, PAGE) == 0);
            check("modes: and its last byte is in the file", byte_at(path, 6) == 'V');
            munmap(reader, PAGE);
        } else {
            if (reader) munmap(reader, PAGE);
            if (writer) munmap(writer, PAGE);
        }
        unlink(path);
    }
}

/* A shared mapping replaced by MAP_FIXED gives its place back at once: 16
 * files replaced, 16 others fit. */
static void pins_fixed(void) {
    char *first[PINS] = {0}, *second[PINS] = {0};
    char path[48];
    int mapped = 0, again = 0, replaced = 0;
    for (int i = 0; i < PINS; i++) {
        first[i] = pin_map(40 + i);
        mapped += first[i] != NULL;
    }
    check("fixed: 16 files mapped", mapped == PINS);
    for (int i = 0; i < PINS && first[i]; i++) {
        void *over = mmap(first[i], PAGE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        replaced += over == first[i];
    }
    check("fixed: 16 mappings replaced", replaced == mapped);
    for (int i = 0; i < PINS; i++) {
        second[i] = pin_map(60 + i);
        again += second[i] != NULL;
    }
    check("fixed: the places came back", again == PINS);
    for (int i = 0; i < PINS; i++) {
        if (first[i]) munmap(first[i], PAGE);
        if (second[i]) munmap(second[i], PAGE);
        pin_path(path, sizeof path, 40 + i);
        unlink(path);
        pin_path(path, sizeof path, 60 + i);
        unlink(path);
    }
}

/* Two threads map and unmap two files for a while: a place of the pins
 * that one thread gave back and the other took for its file never makes a
 * mapping read, write or give back the other's file. */
static volatile int pin_race_failed;
static const char *pin_race_path[2] = {"/tmp/posix-map-race-a", "/tmp/posix-map-race-b"};

static void *pin_race_thread(void *arg) {
    long which = (long)arg;
    const char *path = pin_race_path[which];
    char mine = which ? 'B' : 'A';
    for (int round = 0; round < 60 && !pin_race_failed; round++) {
        int fd = open(path, O_RDWR);
        char *p = fd < 0 ? MAP_FAILED : mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (fd >= 0) close(fd);
        if (p == MAP_FAILED) { pin_race_failed = 1; break; }
        if (p[100] != (which ? 'b' : 'a')) pin_race_failed = 2;
        p[round] = mine;
        /* Half of the rounds write back with msync, the others by munmap. */
        if (round % 2 && msync(p, PAGE, MS_SYNC)) pin_race_failed = 3;
        if (munmap(p, PAGE)) pin_race_failed = 4;
        if (byte_at(path, round) != mine) pin_race_failed = 5;
    }
    return NULL;
}

static void pins_race(void) {
    for (int i = 0; i < 2; i++) {
        int fd = open(pin_race_path[i], O_RDWR | O_CREAT | O_TRUNC, 0600);
        char text[256];
        memset(text, i ? 'b' : 'a', sizeof text);
        check("pin race: file", fd >= 0 && write(fd, text, sizeof text) == (ssize_t)sizeof text);
        if (fd >= 0) close(fd);
    }
    pin_race_failed = 0;
    /* The grant pause opens the window between the vouching and the ask. */
    stafeto_probe_grant_pause(2);
    pthread_t threads[2];
    int made = 1;
    for (long i = 0; i < 2; i++) made &= pthread_create(&threads[i], NULL, pin_race_thread, (void *)i) == 0;
    check("pin race: threads", made);
    if (made) for (int i = 0; i < 2; i++) pthread_join(threads[i], NULL);
    stafeto_probe_grant_pause(0);
    if (pin_race_failed) printf("posix-map: pin race: step %d\n", pin_race_failed);
    check("pin race: every mapping shows and writes its own file", !pin_race_failed);
    for (int i = 0; i < 2; i++) unlink(pin_race_path[i]);
}

/* A record lock goes with the close of the last number of a description
 * that a mapping pins, as with the close of any descriptor (POSIX); the
 * child's F_GETLK shows it. */
static int lock_get(const char *path) {
    int fd = open(path, O_RDWR);
    if (fd < 0) return 2;
    struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};
    int got = fcntl(fd, F_GETLK, &fl);
    return got == 0 && fl.l_type == F_UNLCK ? 0 : 1;
}

static void pins_lock(void) {
    const char *path = "/tmp/posix-map-lock";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    check("lock: file", fd >= 0 && ftruncate(fd, PAGE) == 0);
    if (fd < 0) return;
    char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};
    check("lock: mapped and locked", p != MAP_FAILED && fcntl(fd, F_SETLK, &fl) == 0);
    char *args[] = {"map", "lockget", (char *)path, NULL};
    check("lock: another process sees the lock", spawn_status(args) == 1);
    check("lock: close", close(fd) == 0);
    check("lock: the close of the last number released it", spawn_status(args) == 0);
    if (p != MAP_FAILED) {
        p[3] = 'K';
        check("lock: the mapping writes on", msync(p, PAGE, MS_SYNC) == 0 && byte_at(path, 3) == 'K');
        munmap(p, PAGE);
    }
    unlink(path);
}

/* A descriptor closed on fork does not carry the description to the child,
 * the pin does: the child writes through the mapping. */
static void pins_close_on_fork(void) {
    const char *path = "/tmp/posix-map-clofork";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    check("clofork: file", fd >= 0 && ftruncate(fd, PAGE) == 0);
    if (fd < 0) return;
    char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("clofork: mapped", p != MAP_FAILED);
    check("clofork: flag", fcntl(fd, F_SETFD, FD_CLOFORK) == 0);
    if (p == MAP_FAILED) { close(fd); return; }
    pid_t child = fork();
    if (child == 0) {
        int bad = fcntl(fd, F_GETFD) >= 0 ? 1 : 0;
        p[9] = 'F';
        if (msync(p, PAGE, MS_SYNC)) bad |= 2;
        _exit(bad);
    }
    int status = 0;
    check("clofork: fork", child > 0 && waitpid(child, &status, 0) == child);
    check("clofork: the number is closed in the child and the mapping writes",
          WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check("clofork: the file has the child's byte", byte_at(path, 9) == 'F');
    munmap(p, PAGE);
    close(fd);
    unlink(path);
}

/* A process maps 16 files shared, closes them and starts the program
 * `after`, which finds the places of its session free (every number
 * of the table). */
static int pins_exec(const char *how) {
    pin_unlink_all();
    for (int i = 0; i < PINS; i++) {
        if (!pin_map(i)) return 1;
    }
    char *args[] = {"map", "pinsafter", NULL};
    char *env[] = {NULL};
    if (strcmp(how, "exec") == 0) {
        execve("/bin/procs-child", args, env);
        return 2;
    }
    return 3;
}

static int pins_after(void) {
    char path[48];
    pin_path(path, sizeof path, 1);
    static int fds[1100];
    int opened = 0;
    while (opened < 1100 && (fds[opened] = open(path, O_RDWR | O_CREAT, 0600)) >= 0) opened++;
    int count = opened;
    while (opened > 0) close(fds[--opened]);
    pin_unlink_all();
    /* Every number of the layer's table is free, with the 16 places of the pins
     * of the service's session beside them. */
    return count >= 1000 ? 0 : 1;
}

static void pins_through_exec(void) {
    char *plain[] = {"map", "pinsafter", NULL};
    char *args[] = {"map", "pinexec", "exec", NULL};
    int free_places = spawn_status(plain);
    check("pins: a new process has all its places", free_places == 0);
    int after = spawn_status(args);
    check("pins: exec drops the pins", after == 0);
    pin_unlink_all();
}

unsigned long long stafeto_probe_share_key(unsigned long long device, unsigned long long inode);
int stafeto_probe_share_get(unsigned long long key);

/* A process that has not the file open asks the rendezvous for its memory:
 * refused, whatever it knows of the file's numbers. With the file open for
 * reading it asks, and gets no right to write. */
static int intruder(const char *name) {
    char path[96];
    snprintf(path, sizeof path, "/dev/shm%s", name);
    struct stat st;
    if (stat(path, &st) != 0) return 1;
    unsigned long long key = stafeto_probe_share_key(st.st_dev, st.st_ino);
    if (stafeto_probe_share_get(key) == 0) return 2;
    int fd = shm_open(name, O_RDONLY, 0);
    if (fd < 0) return 3;
    char *p = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) return 4;
    if (p[0] != 7) return 5;
    errno = 0;
    if (mprotect(p, PAGE, PROT_READ | PROT_WRITE) == 0) return 6;
    /* Closed again: the vouching is for this process alone. */
    munmap(p, PAGE);
    close(fd);
    return 0;
}

int stafeto_probe_share_grant(int fd);
int stafeto_probe_share_plant(int fd, unsigned long long key);
int stafeto_probe_share_map_write(int fd, unsigned long long key);

static unsigned long long key_of_fd(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return 0;
    return stafeto_probe_share_key(st.st_dev, st.st_ino);
}

/* The roles of the children below. */
static int role(const char *which, const char *name, int a, int b) {
    int fd;
    if (strcmp(which, "plant") == 0) {
        /* A reader hands the rendezvous an object of its own as the file's. */
        fd = shm_open(name, O_RDONLY, 0);
        if (fd < 0) return 1;
        char result = (char)stafeto_probe_share_plant(fd, key_of_fd(fd));
        if (write(b, &result, 1) != 1) return 2;
        char go;
        if (read(a, &go, 1) != 1) return 3;
        return 0;
    }
    if (strcmp(which, "readerhandle") == 0 || strcmp(which, "writerhandle") == 0) {
        int reader = which[0] == 'r';
        fd = shm_open(name, reader ? O_RDONLY : O_RDWR, 0);
        if (fd < 0) return 1;
        int got = stafeto_probe_share_map_write(fd, key_of_fd(fd));
        /* The reader's handle cannot map for writing; the writer's can. */
        return reader ? (got == 200 ? 0 : 2) : (got == 0 ? 0 : 3);
    }
    if (strcmp(which, "once") == 0) {
        fd = shm_open(name, O_RDONLY, 0);
        if (fd < 0) return 1;
        unsigned long long key = key_of_fd(fd);
        if (stafeto_probe_share_grant(fd) != 0) return 2;
        if (stafeto_probe_share_get(key) != 0) return 3;
        /* Used: a second ask, with the file still open, is refused. */
        return stafeto_probe_share_get(key) == 0 ? 4 : 0;
    }
    if (strcmp(which, "grants") == 0) {
        /* Three files, two grants a process: the third takes the oldest's
         * place and the oldest is gone. */
        char names[3][48];
        int fds[3];
        unsigned long long keys[3];
        for (int i = 0; i < 3; i++) {
            snprintf(names[i], sizeof names[i], "%s%d", name, i);
            fds[i] = shm_open(names[i], O_RDONLY, 0);
            if (fds[i] < 0) return 1;
            keys[i] = key_of_fd(fds[i]);
        }
        for (int i = 0; i < 3; i++)
            if (stafeto_probe_share_grant(fds[i]) != 0) return 2;
        if (stafeto_probe_share_get(keys[0]) == 0) return 3;
        if (stafeto_probe_share_get(keys[2]) != 0) return 4;
        return 0;
    }
    return 9;
}

static int spawn_role(const char *which, const char *name, int a, int b) {
    char x[16], y[16];
    snprintf(x, sizeof x, "%d", a);
    snprintf(y, sizeof y, "%d", b);
    char *args[] = {"map", "role", (char *)which, (char *)name, x, y, NULL};
    pid_t child;
    int status = 0;
    if (posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, environ) != 0) return -1;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return -2;
    return WEXITSTATUS(status);
}

/* What a process vouched for as a reader can and cannot do with the
 * rendezvous: the right of a writer is not in its hands. */
static void rights(void) {
    const char *name = "/posix-map-rights";
    shm_unlink(name);
    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    check("rights: shm_open", fd >= 0 && write(fd, "W", 1) == 1 && ftruncate(fd, PAGE) == 0);
    if (fd < 0) return;
    char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("rights: mmap", p != MAP_FAILED);
    if (p != MAP_FAILED) {
        int rc = spawn_role("readerhandle", name, 0, 0);
        if (rc) printf("posix-map: reader handle step %d\n", rc);
        check("rights: a reader's handle cannot map for writing", rc == 0);
        rc = spawn_role("writerhandle", name, 0, 0);
        if (rc) printf("posix-map: writer handle step %d\n", rc);
        check("rights: a writer's handle can", rc == 0);
        rc = spawn_role("once", name, 0, 0);
        if (rc) printf("posix-map: once step %d\n", rc);
        check("rights: a vouching serves one ask", rc == 0);
        munmap(p, PAGE);
    }
    close(fd);
    shm_unlink(name);
    /* Three files for the limit of the vouchings a process holds. */
    const char *base = "/posix-map-g";
    int ok = 1;
    for (int i = 0; i < 3; i++) {
        char n[48];
        snprintf(n, sizeof n, "%s%d", base, i);
        shm_unlink(n);
        int f = shm_open(n, O_RDWR | O_CREAT | O_EXCL, 0600);
        ok &= f >= 0;
        if (f >= 0) close(f);
    }
    check("rights: files", ok);
    int rc = spawn_role("grants", base, 0, 0);
    if (rc) printf("posix-map: grants step %d\n", rc);
    check("rights: a process holds two vouchings", rc == 0);
    for (int i = 0; i < 3; i++) {
        char n[48];
        snprintf(n, sizeof n, "%s%d", base, i);
        shm_unlink(n);
    }
    /* A reader's object is not planted in place of the writers'. */
    const char *sub = "/posix-map-sub";
    shm_unlink(sub);
    fd = shm_open(sub, O_RDWR | O_CREAT | O_EXCL, 0600);
    check("plant: shm_open", fd >= 0 && write(fd, "W", 1) == 1 && ftruncate(fd, PAGE) == 0);
    if (fd < 0) return;
    int up[2], down[2];
    check("plant: pipes", pipe(up) == 0 && pipe(down) == 0);
    char x[16], y[16];
    snprintf(x, sizeof x, "%d", down[0]);
    snprintf(y, sizeof y, "%d", up[1]);
    char *args[] = {"map", "role", "plant", (char *)sub, x, y, NULL};
    pid_t child;
    int started = posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, environ) == 0;
    check("plant: spawn", started);
    if (started) {
        char planted = 99;
        check("plant: the reader planted", read(up[0], &planted, 1) == 1);
        char *q = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        check("plant: mmap", q != MAP_FAILED);
        if (q != MAP_FAILED) {
            check("plant: a writer gets the file, not the reader's object", q[0] == 'W');
            munmap(q, PAGE);
        }
        char go = 1;
        write(down[1], &go, 1);
        int status = 0;
        waitpid(child, &status, 0);
    }
    close(fd);
    shm_unlink(sub);
}

static void foreign_processes(void) {
    const char *name = "/posix-map-guard";
    shm_unlink(name);
    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    check("guard: shm_open", fd >= 0 && ftruncate(fd, PAGE) == 0);
    if (fd < 0) return;
    char *p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check("guard: mmap", p != MAP_FAILED);
    if (p != MAP_FAILED) {
        p[0] = 7;
        char *args[] = {"map", "intruder", (char *)name, NULL};
        pid_t child;
        int status = 0;
        int error = posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, environ);
        if (!error) waitpid(child, &status, 0);
        if (!error && WIFEXITED(status) && WEXITSTATUS(status))
            printf("posix-map: intruder step %d\n", WEXITSTATUS(status));
        check("guard: no file, no memory; a reader reads only",
              !error && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        munmap(p, PAGE);
    }
    close(fd);
    shm_unlink(name);
}

int main(int argc, char **argv) {
    if (argc == 6 && strcmp(argv[1], "role") == 0)
        return role(argv[2], argv[3], atoi(argv[4]), atoi(argv[5]));
    if (argc == 3 && strcmp(argv[1], "intruder") == 0) return intruder(argv[2]);
    if (argc == 3 && strcmp(argv[1], "leave") == 0) return leaver(argv[2]);
    if (argc == 3 && strcmp(argv[1], "pinexec") == 0) return pins_exec(argv[2]);
    if (argc == 2 && strcmp(argv[1], "pinsafter") == 0) return pins_after();
    if (argc == 3 && strcmp(argv[1], "lockget") == 0) return lock_get(argv[2]);
    if (argc == 3 && strcmp(argv[1], "peer") == 0) return peer(argv[2]);
    if (argc == 6 && strcmp(argv[1], "execself") == 0) return exec_self(argv);
    if (argc == 6 && strcmp(argv[1], "image") == 0)
        return image_role(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
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
    none_page_faults();
    errors();
    exec_memory();
    past_end();
    forked();
    image_shared();
    image_spawned();
    image_exec_self();
    forked_many();
    churn();
    fragmentation();
    shared_anonymous();
    files();
    shared_names();
    shared_while_made();
    shared_by_two_threads();
    shared_when_the_maker_goes();
    review();
    pins();
    pins_modes();
    pins_fixed();
    pins_race();
    pins_lock();
    pins_close_on_fork();
    pins_through_exec();
    leaving();
    unrelated_processes();
    foreign_processes();
    rights();
    limits();
    image_race();
    if (failures) {
        printf("posix-map: %d failures\n", failures);
        return 1;
    }
    printf("posix-map: mprotect, munmap and faults ok\n");
    printf("posix-map: shared memory, files and shm ok\n");
    return 0;
}
