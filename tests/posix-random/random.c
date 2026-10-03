/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The probe of the source of entropy on relibc (step 5e'). Built with
 * -fno-builtin; every result is compared, so no check folds away.
 *
 * Started by init: getentropy gives 256 bytes twice, which differ and are
 * not all zero; 257 bytes give EINVAL; getrandom with GRND_NONBLOCK gives
 * every byte, an unknown flag and GRND_RANDOM with GRND_INSECURE give
 * EINVAL, GRND_RANDOM gives 4096 bytes. Then it starts itself from its
 * file (/bin/posix-random fork), whose copy can fork.
 *
 * Role `fork`: the parent takes 16 bytes (its buffer now holds the rest of
 * a turn), forks; parent and child each take 32 bytes, the child sends its
 * bytes through a pipe, and the parent checks that they differ from its
 * own: the child forgot the parent's key and buffer.
 */

#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            printf("posix-random: check failed at line %d: %s (errno %d)\n", __LINE__, \
                   #cond, errno);                                                    \
            return 20;                                                               \
        }                                                                            \
    } while (0)

static int all_zero(const unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (bytes[i] != 0) return 0;
    return 1;
}

static unsigned long long head(const unsigned char *bytes) {
    unsigned long long word = 0;
    for (int i = 0; i < 8; i++) word = word << 8 | bytes[i];
    return word;
}

static int first(void) {
    static unsigned char a[256], b[256], big[4096];
    unsigned char c[257], d[64];
    CHECK(getentropy(a, sizeof a) == 0);
    CHECK(getentropy(b, sizeof b) == 0);
    CHECK(memcmp(a, b, sizeof a) != 0);
    CHECK(!all_zero(a, sizeof a) && !all_zero(b, sizeof b));
    printf("posix-random: getentropy gave 256 bytes twice, they differ (%016llx, %016llx)\n",
           head(a), head(b));
    errno = 0;
    CHECK(getentropy(c, sizeof c) == -1);
    CHECK(errno == EINVAL);
    printf("posix-random: getentropy of 257 bytes gave EINVAL\n");
    CHECK(getrandom(d, sizeof d, GRND_NONBLOCK) == (ssize_t)sizeof d);
    CHECK(!all_zero(d, sizeof d));
    errno = 0;
    CHECK(getrandom(d, 8, 8) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(getrandom(d, 8, GRND_RANDOM | GRND_INSECURE) == -1);
    CHECK(errno == EINVAL);
    CHECK(getrandom(big, sizeof big, GRND_RANDOM) == (ssize_t)sizeof big);
    CHECK(!all_zero(big, sizeof big));
    printf("posix-random: getrandom: GRND_NONBLOCK and GRND_RANDOM give every byte, "
           "bad flags EINVAL\n");
    pid_t pid = 0;
    char *argv[] = {"posix-random", "fork", NULL};
    CHECK(posix_spawn(&pid, "/bin/posix-random", NULL, NULL, argv, environ) == 0);
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

static int forked(void) {
    unsigned char warm[16], mine[32], theirs[32];
    int ends[2];
    CHECK(getentropy(warm, sizeof warm) == 0);
    CHECK(pipe(ends) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        unsigned char child[32];
        if (getentropy(child, sizeof child) != 0) _exit(3);
        if (write(ends[1], child, sizeof child) != (ssize_t)sizeof child) _exit(4);
        _exit(0);
    }
    CHECK(getentropy(mine, sizeof mine) == 0);
    CHECK(close(ends[1]) == 0);
    size_t got = 0;
    while (got < sizeof theirs) {
        ssize_t n = read(ends[0], theirs + got, sizeof theirs - got);
        CHECK(n > 0);
        got += (size_t)n;
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(memcmp(mine, theirs, sizeof mine) != 0);
    CHECK(!all_zero(theirs, sizeof theirs));
    printf("posix-random: after fork the child's bytes differ from the parent's "
           "(%016llx, %016llx)\n",
           head(mine), head(theirs));
    return 0;
}

int main(int argc, char **argv) {
    int status = argc > 1 && strcmp(argv[1], "fork") == 0 ? forked() : first();
    if (status == 0 && argc == 1) printf("posix-random: ok\n");
    return status;
}
