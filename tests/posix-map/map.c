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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
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
    size_t pages = 400;
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
    check("full: the table fills with ENOMEM", refused && cut > 40 && cut < 128);
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

int main(void) {
    struct sigaction action = {.sa_handler = on_fault};
    sigaction(SIGSEGV, &action, NULL);
    protect_whole(PAGE, "small");
    protect_whole(5 * PAGE, "five pages");
    protect_whole(32 * PAGE, "32 pages");
    unmap_part(4, "small");
    unmap_part(40, "large");
    protect_across();
    errors();
    forked();
    churn();
    table_full();
    if (failures) {
        printf("posix-map: %d failures\n", failures);
        return 1;
    }
    printf("posix-map: mprotect, munmap and faults ok\n");
    return 0;
}
