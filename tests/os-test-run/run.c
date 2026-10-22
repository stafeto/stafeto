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
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
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

/* The processes of group `group` that /proc lists (field 5 of
 * /proc/PID/stat), or -1 when /proc does not read. */
static int group_left(pid_t group) {
    DIR *proc = opendir("/proc");
    if (!proc) return -1;
    int left = 0;
    struct dirent *entry;
    while ((entry = readdir(proc))) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9') continue;
        char path[64];
        snprintf(path, sizeof path, "/proc/%s/stat", entry->d_name);
        FILE *stat = fopen(path, "r");
        if (!stat) continue;
        char line[512];
        if (fgets(line, sizeof line, stat)) {
            /* pid (comm) state ppid pgrp: the name may hold spaces, so
             * the fields count from its last parenthesis. */
            char *close = strrchr(line, ')');
            int ppid = 0, pgrp = 0;
            char state = 0;
            if (close && sscanf(close + 1, " %c %d %d", &state, &ppid, &pgrp) == 3 &&
                pgrp == group)
                left++;
        }
        fclose(stat);
    }
    closedir(proc);
    return left;
}

/* A test that forks and leaves its children behind (a stress test that forks
 * until the system is full, one that dies by a signal) leaves them to starve
 * the tests after it: each test runs in a process group of its own, and the
 * runner ends the group when the test is over and waits (3 s at most) until
 * it is empty. A group that is not empty by then gives -1 or the number of
 * its processes still there, which `report_group` prints after the test's
 * end mark (#342): the tests after it may lose to them. */
static int end_group(pid_t group) {
    kill(-group, SIGKILL);
    long long start = now_ms();
    while (kill(-group, 0) == 0 && now_ms() - start < 3000) nap();
    if (kill(-group, 0) != 0) return 0;
    int left = group_left(group);
    return left == 0 ? -1 : left;
}

/* The line of a group that `end_group` left behind, if any. */
static void report_group(const char *name, int left) {
    if (left > 0)
        printf("os-test-run: the group of %s is not empty after 3 s: %d processes left\n", name, left);
    else if (left < 0)
        printf("os-test-run: the group of %s is not empty after 3 s\n", name);
}

/* Runs the test `name` of the file `rel` in the directory `dir`. */
static void run_one(const char *name, const char *dir, const char *rel, const char *arg) {
    printf("@@os-test begin %s\n", name);
    fflush(stdout);
    if (chdir(dir) != 0) {
        printf("@@os-test end %s error chdir %d\n", name, errno);
        return;
    }
    char path[512];
    snprintf(path, sizeof path, "./%s", rel);
    char *argv[] = {path, (char *)arg, NULL};
    pid_t pid;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attr, 0);
    int e = posix_spawn(&pid, path, NULL, &attr, argv, environ);
    if (e == ENOEXEC) {
        /* A shell script of the suite: the shell of the image runs it, as
         * execvp does for a file that is no executable. */
        char *shell_argv[] = {"sh", path, (char *)arg, NULL};
        e = posix_spawn(&pid, "/bin/sh", NULL, &attr, shell_argv, environ);
    }
    posix_spawnattr_destroy(&attr);
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
            int left = end_group(pid);
            printf("@@os-test end %s timeout\n", name);
            report_group(name, left);
            return;
        }
        nap();
    }
    int left = end_group(pid);
    if (WIFEXITED(status))
        printf("@@os-test end %s exit %d\n", name, WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("@@os-test end %s signal %d\n", name, WTERMSIG(status));
    else
        printf("@@os-test end %s error status %#x\n", name, status);
    report_group(name, left);
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
        /* An argument for a test that wants one (the fourth word), else none. */
        char *arg = strtok(NULL, " \n");
        if (!name || !dir || !rel) continue;
        run_one(name, dir, rel, arg);
    }
    fclose(list);
    printf("os-test-run: done\n");
    /* The console may still hold the end of the last test's output when the
     * runner ends, and init's line about the runner's end overtakes it:
     * the log of the batch then stops in the middle of that test. Wait
     * until the output is out. */
    fflush(stdout);
    tcdrain(STDOUT_FILENO);
    return 0;
}
