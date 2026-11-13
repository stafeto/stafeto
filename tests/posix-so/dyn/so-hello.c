/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* A dynamically linked program on libc.so (spec 2, 3.12.3). Without an
 * argument it checks what a program sees: arguments, the environment,
 * stdout, errno in two threads, the order of the constructors, a weak
 * undefined symbol. "wait" waits for a byte on its input; "fork" and "exec"
 * go through fork and execv of itself. The output is one line per mode. */
#include <stdint.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <sys/auxv.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
extern int so_absent __attribute__((weak));

/* The order the arrays ran in (volatile: otherwise the compiler runs the
 * constructors itself and the program has none): preinit 1, constructor with a priority 2,
 * constructor 3. */
static volatile int order[4];
static volatile int ran;

static void pre(void) { order[ran++ & 3] = 1; }
__attribute__((section(".preinit_array"), used)) static void (*const pre_entry)(void) = pre;
__attribute__((constructor(101))) static void first(void) { order[ran++ & 3] = 2; }
__attribute__((constructor)) static void second(void) { order[ran++ & 3] = 3; }

/* A destructor prints when the program ends through exit. */
__attribute__((destructor)) static void last(void) {
    printf("so-hello: destructor\n");
    fflush(stdout);
}

static void *errno_thread(void *arg) {
    int mine = 100 + (int)(long)arg;
    int bad = 0;
    for (int i = 0; i < 50; i++) {
        errno = mine;
        sched_yield();
        if (errno != mine) bad = 1;
    }
    return (void *)(long)bad;
}

static int hello(int argc, char **argv) {
    int bits = 0;
    if (argc < 1 || argv[0] == NULL || argv[argc] != NULL) bits |= 1;
    const char *probe = getenv("SO_PROBE");
    if (environ == NULL || environ[0] == NULL || probe == NULL || strcmp(probe, "1") != 0)
        bits |= 2;
    if (stdout == NULL || fileno(stdout) != 1) bits |= 4;
    errno = 7;
    pthread_t t[2];
    void *result[2] = {(void *)1, (void *)1};
    for (long i = 0; i < 2; i++)
        if (pthread_create(&t[i], NULL, errno_thread, (void *)i) != 0) bits |= 8;
    for (int i = 0; i < 2; i++)
        if (pthread_join(t[i], &result[i]) != 0 || result[i] != NULL) bits |= 8;
    if (errno != 7) bits |= 8;
    if (ran != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3) bits |= 16;
    if (&so_absent != NULL) bits |= 32;
    printf("so-hello: argc=%d order=%d%d%d bits=%d\n", argc, order[0], order[1], order[2], bits);
    fflush(stdout);
    return bits;
}

/* A symbol of the program that the link exports (--export-dynamic-symbol),
 * which dlsym finds in the program before it looks in libc.so. */
int so_exported(void) { return 42; }

struct walk {
    int modules;
    int bad;
    char names[2][32];
};

static int visit(struct dl_phdr_info *info, size_t size, void *data) {
    struct walk *w = data;
    int loads = 0;
    if (size < sizeof *info || info->dlpi_phdr == NULL || info->dlpi_phnum == 0) w->bad |= 1;
    for (int i = 0; i < info->dlpi_phnum && info->dlpi_phdr != NULL; i++)
        if (info->dlpi_phdr[i].p_type == PT_LOAD) loads++;
    if (loads != 3) w->bad |= 2;
    if (info->dlpi_addr != 0 || info->dlpi_adds != 2 || info->dlpi_subs != 0) w->bad |= 4;
    if (w->modules < 2) {
        strncpy(w->names[w->modules], info->dlpi_name, sizeof w->names[0] - 1);
    }
    w->modules++;
    return 0;
}

/* dlopen(NULL), dlsym of the global scope, dl_iterate_phdr (spec 2, 3.12.5). */
static int dl(void) {
    int bits = 0;
    void *global = dlopen(NULL, RTLD_NOW);
    if (global == NULL) return 1;
    if (dlsym(global, "printf") != (void *)printf) bits |= 2;
    if (dlsym(RTLD_DEFAULT, "printf") != (void *)printf) bits |= 4;
    if (dlsym(global, "so_exported") != (void *)so_exported) bits |= 8;
    if (dlsym(global, "so_exported_not") != NULL || dlerror() == NULL) bits |= 16;
    if (dlerror() != NULL) bits |= 32;
    if (dlopen("/lib/libx.so", RTLD_NOW) != NULL || dlerror() == NULL) bits |= 64;
    if (dlclose(global) != 0) bits |= 128;
    struct walk w = {0};
    int stopped = dl_iterate_phdr(visit, &w);
    if (stopped != 0 || w.modules != 2 || w.bad != 0) bits |= 256;
    if (w.names[0][0] != 0 || strcmp(w.names[1], "/lib/libc.so") != 0) bits |= 512;
    printf("so-hello: dl bits=%d modules=%d walk=%d\n", bits, w.modules, w.bad);
    fflush(stdout);
    return bits;
}

/* The canary of the stack protector is libc.so's __stack_chk_guard, which the program reaches
 * through its GOT (no copy relocation), so the value the start set is the one the program's
 * prologues and epilogues use: not zero, with a zero low byte. */
extern uintptr_t __stack_chk_guard;

/* A protected function (a local array gives it a canary) that writes past its buffer with a
 * length known only at run time; the return finds the canary changed and calls
 * __stack_chk_fail, which ends the program by SIGABRT. Without the protector it returns. */
__attribute__((noinline)) static void overflow(size_t length) {
    char buffer[16];
    memset(buffer, 'A', length);
    __asm__ volatile("" : : "r"(buffer) : "memory");
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "hello";
    if (strcmp(mode, "wait") == 0) {
        char byte;
        printf("so-hello: waiting\n");
        fflush(stdout);
        return read(0, &byte, 1) == 1 ? 0 : 1;
    }
    if (strcmp(mode, "dl") == 0) return dl();
    if (strcmp(mode, "guard") == 0)
        return __stack_chk_guard != 0 && (__stack_chk_guard & 0xff) == 0 ? 0 : 1;
    if (strcmp(mode, "smash") == 0) {
        volatile size_t length = 64;
        overflow(length);
        return 0;
    }
    if (strcmp(mode, "secure") == 0) {
        /* AT_SECURE as the program sees it, with the environment untouched:
         * the loader never reads LD_PRELOAD, whatever the mode. The exit
         * code is 40 + 2 * AT_SECURE + (LD_PRELOAD is set). */
        return 40 + 2 * (int)getauxval(23) + (getenv("LD_PRELOAD") != NULL);
    }
    if (strcmp(mode, "quick") == 0) {
        /* The counter at main, for the timing of the leader. */
        uint64_t at;
        __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(at)::"memory");
        return write(1, &at, sizeof at) == (ssize_t)sizeof at ? 0 : 1;
    }
    if (strcmp(mode, "fork") == 0) {
        fflush(stdout);
        pid_t pid = fork();
        if (pid < 0) return 2;
        if (pid == 0) {
            printf("so-hello: child ok\n");
            fflush(stdout);
            _exit(0);
        }
        int status = 0;
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            return 3;
        printf("so-hello: fork ok\n");
        return 0;
    }
    if (strcmp(mode, "exec") == 0) {
        char *args[] = {argv[0], (char *)"hello", NULL};
        fflush(stdout);
        execv(argv[0], args);
        return 4;
    }
    return hello(argc, argv);
}
