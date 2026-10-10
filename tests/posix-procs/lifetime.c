/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* Actual Loaded, spawn, fork, credentials, exec and death transitions. */
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern int process_lifetime(int pid);
extern int ram_lifetime(int pid);
extern int ram_close_event(void);
extern int close_driver_receipts(void);
extern int close_driver_full_places(void);
extern void close_driver_jump_arm(int fd);
extern int close_driver_jump_recover(int fd);
static sigjmp_buf close_jump;
static volatile sig_atomic_t close_signal_seen;
static void close_signal(int number) {
    close_signal_seen = number;
    siglongjmp(close_jump, 1);
}
void close_probe_signal_jump(void) { raise(SIGUSR1); }

static int failures;
static void expect(const char *what, int actual, int wanted) {
    if (actual != wanted) {
        printf("PID lifetime: %s: got %d, expected %d\n", what, actual, wanted);
        failures++;
    }
}
static void expect_life(const char *what, pid_t pid, int wanted) {
    expect(what, process_lifetime(pid), wanted);
    expect("RAM observes exact PID lifetime", ram_lifetime(pid), wanted);
}
static void reap(pid_t child, int killed) {
    int status = 0;
    expect("wait", waitpid(child, &status, 0), child);
    expect("wait status", killed ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL
                                : WIFEXITED(status) && WEXITSTATUS(status) == 0, 1);
    expect_life("dead before wait returns", child, 0);
}
int main(int argc, char **argv) {
    expect_life("running full PID", getpid(), 1);
    if (argc > 1 && strcmp(argv[1], "sleep") == 0) {
        for (;;) pause();
    }
    if (argc > 1 && strcmp(argv[1], "exec") == 0) {
        /* Allow the old image's end notification to arrive before checking. */
        struct timespec delay = {0, 10000000};
        nanosleep(&delay, NULL);
        expect_life("same PID after old image ended", getpid(), 1);
        return failures != 0;
    }
    if (argc == 1) {
        /* Init's raw image has no loader segment map for fork. */
        char *run_argv[] = {"procs-child", "run", NULL};
        char *env[] = {NULL};
        pid_t run = -1;
        expect("spawn mapped supervisor", posix_spawn(&run, "/bin/procs-child", NULL,
                                                     NULL, run_argv, env), 0);
        if (run > 0) reap(run, 0);
        if (!failures) printf("posix-procs: PID lifetime page ok\n");
        return failures != 0;
    }
    expect("drop effective UID", seteuid(65534), 0);
    expect_life("PID lives with changed credentials", getpid(), 1);
    expect("restore effective UID", seteuid(0), 0);
    expect_life("PID lives with restored credentials", getpid(), 1);
    expect("native close receipt and 32-reference birth", ram_close_event(), 0);
    expect("public close receipts and helper reuse", close_driver_receipts(), 0);
    expect("public close with all independent places full", close_driver_full_places(), 0);
    struct sigaction close_action, close_previous;
    memset(&close_action, 0, sizeof close_action);
    close_action.sa_handler = close_signal;
    sigemptyset(&close_action.sa_mask);
    expect("install close signal", sigaction(SIGUSR1, &close_action, &close_previous), 0);
    int close_fd = open("/etc/motd", O_RDONLY);
    expect("open before close signal", close_fd >= 0, 1);
    close_signal_seen = 0;
    if (close_fd >= 0 && sigsetjmp(close_jump, 1) == 0) {
        close_driver_jump_arm(close_fd);
        close(close_fd);
        expect("close signal must leave through siglongjmp", 0, 1);
    }
    expect("genuine close signal", close_signal_seen, SIGUSR1);
    expect("recover physical close after siglongjmp", close_driver_jump_recover(close_fd), 0);
    expect("restore close signal", sigaction(SIGUSR1, &close_previous, NULL), 0);

    char *sleep_argv[] = {"procs-child", "sleep", NULL};
    char *environment[] = {NULL};
    pid_t child = -1;
    expect("spawn", posix_spawn(&child, "/bin/procs-child", NULL, NULL,
                               sleep_argv, environment), 0);
    if (child > 0) {
        expect_life("published at spawn commit", child, 1);
        expect("kill", kill(child, SIGKILL), 0);
        reap(child, 1);
    }
    child = fork();
    if (child < 0) printf("PID lifetime: fork failed errno %d\n", errno);
    if (child == 0) {
        expect_life("published at fork commit", getpid(), 1);
        _exit(failures != 0);
    }
    expect("fork", child > 0, 1);
    if (child > 0) reap(child, 0);
    child = fork();
    if (child < 0) printf("PID lifetime: fork failed errno %d\n", errno);
    if (child == 0) {
        char *exec_argv[] = {"procs-child", "exec", NULL};
        execve("/bin/procs-child", exec_argv, environment);
        _exit(2);
    }
    expect("fork for exec", child > 0, 1);
    if (child > 0) reap(child, 0);
    return failures != 0;
}
