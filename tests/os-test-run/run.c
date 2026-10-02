/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The runner of os-test (cargo xtask os-test, tests/os-test): one boot runs
 * all the tests of an image, each a file of the RAM service started by
 * posix_spawn as misc/run.sh starts it: in the directory of its suite, as
 * "./name" with that as argv[0] (the tests that exec themselves and those
 * of basic/ name their program so). The list is the file /os-test/list, a
 * line a test: its name, its directory and its path from there, apart by
 * spaces; a line `limit MS` sets the time a test may take from then on.
 *
 * A test's output goes to the console as it writes it; the runner marks
 * each test on both sides, without a newline before the second mark, so
 * that xtask takes the output between the marks as it was:
 *
 *   @@os-test begin NAME
 *   (the test's output)
 *   @@os-test end NAME exit N | signal N | timeout | error WHAT
 *
 * A test that has not ended in the limit (10 s) gets SIGKILL from the
 * runner: there is no alarm yet, so the runner polls the child (WNOHANG)
 * between short naps and does the killing itself, and the run goes on with
 * the next test. At the end it prints `os-test-run: done`.
 *
 * The check of the runner (cargo xtask os-test, before the suites) starts
 * two files that are the runner itself: named `hang` it never ends, named
 * `quick` it exits with 7. */
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define LIMIT_MS 10000
#define NAP_MS 2

static long long limit_ms = LIMIT_MS;

static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void nap(void) {
    struct timespec t = {0, NAP_MS * 1000000L};
    nanosleep(&t, NULL);
}

/* Runs the test `name` of the file `rel` in the directory `dir`. */
static void run_one(const char *name, const char *dir, const char *rel) {
    printf("@@os-test begin %s\n", name);
    fflush(stdout);
    if (chdir(dir) != 0) {
        printf("@@os-test end %s error chdir %d\n", name, errno);
        return;
    }
    char path[512];
    snprintf(path, sizeof path, "./%s", rel);
    char *argv[] = {path, NULL};
    pid_t pid;
    int e = posix_spawn(&pid, path, NULL, NULL, argv, environ);
    if (e != 0) {
        printf("@@os-test end %s error spawn %d\n", name, e);
        return;
    }
    long long start = now_ms();
    int status = 0;
    for (;;) {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) break;
        if (got < 0 && errno != EINTR) {
            printf("@@os-test end %s error waitpid %d\n", name, errno);
            return;
        }
        if (now_ms() - start > limit_ms) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            printf("@@os-test end %s timeout\n", name);
            return;
        }
        nap();
    }
    if (WIFEXITED(status))
        printf("@@os-test end %s exit %d\n", name, WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("@@os-test end %s signal %d\n", name, WTERMSIG(status));
    else
        printf("@@os-test end %s error status %#x\n", name, status);
    fflush(stdout);
}

int main(int argc, char **argv) {
    /* The files of the runner's own check. */
    const char *self = argc > 0 ? strrchr(argv[0], '/') : NULL;
    self = self ? self + 1 : argc > 0 ? argv[0] : "";
    if (strcmp(self, "hang") == 0) {
        for (;;) pause();
    }
    if (strcmp(self, "quick") == 0) return 7;
    FILE *list = fopen("/os-test/list", "r");
    if (!list) {
        printf("os-test-run: no list: %s\n", strerror(errno));
        return 1;
    }
    char line[1100];
    while (fgets(line, sizeof line, list)) {
        char *name = strtok(line, " \n");
        if (name && strcmp(name, "limit") == 0) {
            char *ms = strtok(NULL, " \n");
            if (ms) limit_ms = atoll(ms);
            continue;
        }
        char *dir = strtok(NULL, " \n");
        char *rel = strtok(NULL, " \n");
        if (!name || !dir || !rel) continue;
        run_one(name, dir, rel);
    }
    fclose(list);
    printf("os-test-run: done\n");
    return 0;
}
