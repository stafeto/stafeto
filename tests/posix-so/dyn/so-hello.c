/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* A dynamically linked program on libc.so (spec 2, 3.12.3). Without an
 * argument it checks what a program sees: arguments, the environment,
 * stdout, errno in two threads, the order of the constructors, a weak
 * undefined symbol. "wait" waits for a byte on its input; "fork" and "exec"
 * go through fork and execv of itself. The output is one line per mode. */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
extern int so_absent __attribute__((weak));

/* The order the arrays ran in: preinit 1, constructor with a priority 2,
 * constructor 3. */
static int order[4];
static int ran;

static void pre(void) { order[ran++ & 3] = 1; }
__attribute__((section(".preinit_array"), used)) static void (*const pre_entry)(void) = pre;
__attribute__((constructor(101))) static void first(void) { order[ran++ & 3] = 2; }
__attribute__((constructor)) static void second(void) { order[ran++ & 3] = 3; }

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

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "hello";
    if (strcmp(mode, "wait") == 0) {
        char byte;
        printf("so-hello: waiting\n");
        fflush(stdout);
        return read(0, &byte, 1) == 1 ? 0 : 1;
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
