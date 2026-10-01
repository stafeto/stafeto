/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* libc probe (relibc, musl): stdio, malloc, fopen/fread on the RAM file service, time. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef PROBE
#define PROBE "relibc-probe"
#endif

int main(int argc, char **argv) {
    printf(PROBE ": hello from libc printf, argc=%d argv0=%s pi=%.3f\n",
           argc, argv[0], 3.14159);
    char *block = malloc(100000);
    if (!block) return 2;
    memset(block, 'x', 100000);
    char *small = malloc(24);
    if (!small) return 3;
    strcpy(small, "heap");
    printf(PROBE ": malloc %s %c\n", small, block[99999]);
    free(small);
    free(block);
    FILE *motd = fopen("/etc/motd", "r");
    if (!motd) {
        printf(PROBE ": fopen failed errno=%d\n", errno);
        return 4;
    }
    char text[128] = {0};
    size_t got = fread(text, 1, sizeof text - 1, motd);
    fclose(motd);
    printf(PROBE ": fread %zu bytes: %s", got, text);
    if (got == 0) return 5;
    if (fopen("/absent", "r") || errno != ENOENT) return 6;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 7;
    printf(PROBE ": monotonic %lld.%09ld\n", (long long)now.tv_sec, now.tv_nsec);
    printf(PROBE ": ok\n");
    return 0;
}
