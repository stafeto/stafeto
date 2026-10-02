/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The first C program on relibc over the Rust POSIX layer: stdio with a
 * float, malloc, a file of the RAM file service through fopen and fread,
 * ENOENT, clock_gettime, and errno in the static TLS relibc built. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    printf("relibc-hello: ok\n");
    return 0;
}
