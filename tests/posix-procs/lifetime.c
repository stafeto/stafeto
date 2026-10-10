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
extern int ram_lock_commands(int pid);
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
        printf("PID lifetime: %s: got %d, expected %d, errno %d\n", what, actual, wanted, errno);
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
static void public_lock_commands(void) {
    int fd = open("/tmp/public-lock-fields", O_CREAT | O_TRUNC | O_RDWR, 0666);
    expect("open public lock file", fd >= 0, 1);
    if (fd < 0) return;
    int alias = dup(fd);
    expect("alias public lock file", alias >= 0, 1);
    if (alias < 0) { close(fd); return; }
    expect("seek before accepted relative lock", lseek(fd, 16, SEEK_SET), 16);
    struct flock lock;
    memset(&lock, 0xa5, sizeof lock);
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_CUR;
    lock.l_start = 4; lock.l_len = 8; lock.l_pid = 123;
    struct flock original;
    memcpy(&original, &lock, sizeof lock);
    expect("public PID SET relative", fcntl(fd, F_SETLK, &lock), 0);
    expect("SET preserves all caller fields and padding", memcmp(&lock, &original, sizeof lock), 0);
    expect("accepted lock leaves cursor", lseek(fd, 0, SEEK_CUR), 16);
    memset(&lock, 0, sizeof lock);
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET; lock.l_len = 0;
    expect("public OFD GET sees PID blocker", fcntl(alias, 36, &lock), 0);
    expect("PID blocker type", lock.l_type, F_WRLCK);
    expect("PID blocker absolute origin", lock.l_whence, SEEK_SET);
    expect("PID blocker start", lock.l_start, 20);
    expect("PID blocker length", lock.l_len, 8);
    expect("PID blocker genuine identity", lock.l_pid, getpid());
    pid_t child = fork();
    if (child == 0) {
        struct flock query;
        memset(&query, 0, sizeof query);
        query.l_type = F_WRLCK; query.l_whence = SEEK_SET; query.l_len = 0;
        if (fcntl(fd, F_GETLK, &query) || query.l_pid != getppid() || query.l_start != 20)
            _exit(71);
        query.l_type = F_WRLCK; query.l_whence = SEEK_SET; query.l_start = 20;
        query.l_len = 8; query.l_pid = 0;
        struct flock before;
        memcpy(&before, &query, sizeof query);
        if (fcntl(fd, F_SETLK, &query) != -1 || errno != EAGAIN ||
            memcmp(&query, &before, sizeof query)) _exit(72);
        _exit(0);
    }
    expect("fork PID conflict child", child >= 0, 1);
    if (child > 0) {
        int status = 0;
        expect("wait PID conflict child", waitpid(child, &status, 0), child);
        expect("PID conflict child exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
        expect("PID conflict child is dead", process_lifetime(child), 0);
    }
    expect("close alias releases all PID locks", close(alias), 0);
    memset(&lock, 0xa5, sizeof lock);
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
    lock.l_start = 20; lock.l_len = 8; lock.l_pid = 0;
    memcpy(&original, &lock, sizeof lock);
    expect("public OFD GET after alias close", fcntl(fd, 36, &lock), 0);
    original.l_type = F_UNLCK;
    expect("unlocked GET changes only type", memcmp(&lock, &original, sizeof lock), 0);
    memset(&lock, 0, sizeof lock);
    lock.l_type = F_RDLCK; lock.l_whence = SEEK_SET; lock.l_start = 30; lock.l_len = 0;
    expect("public OFD SET", fcntl(fd, 37, &lock), 0);
    child = fork();
    if (child == 0) {
        struct flock query;
        memset(&query, 0, sizeof query);
        query.l_type = F_WRLCK; query.l_whence = SEEK_SET; query.l_len = 0;
        if (fcntl(fd, 36, &query) || query.l_type != F_UNLCK) _exit(73);
        query.l_type = F_WRLCK;
        if (fcntl(fd, F_GETLK, &query) || query.l_type != F_RDLCK ||
            query.l_start != 30 || query.l_len != 0 || query.l_pid != -1) _exit(74);
        if (close(fd)) _exit(75);
        _exit(0);
    }
    expect("fork OFD inheritance child", child >= 0, 1);
    if (child > 0) {
        int status = 0;
        expect("wait OFD inheritance child", waitpid(child, &status, 0), child);
        expect("OFD inheritance child exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
        expect("OFD inheritance child is dead", process_lifetime(child), 0);
    }
    memset(&lock, 0, sizeof lock);
    lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET; lock.l_len = 0;
    expect("parent OFD survives child close", fcntl(fd, F_GETLK, &lock), 0);
    expect("surviving OFD blocker", lock.l_pid, -1);
    expect("last OFD close", close(fd), 0);
    fd = open("/tmp/public-lock-fields", O_RDWR);
    expect("reopen after OFD retirement", fd >= 0, 1);
    if (fd >= 0) {
        memset(&lock, 0, sizeof lock);
        lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET; lock.l_len = 0;
        expect("last close clears OFD lock", fcntl(fd, F_GETLK, &lock), 0);
        expect("retired OFD is unlocked", lock.l_type, F_UNLCK);
        expect("close reopened file", close(fd), 0);
    }
    expect("invalid lock fd", fcntl(-1, F_GETLK, NULL), -1);
    expect("invalid lock fd errno", errno, EBADF);
    if (!failures) printf("posix-procs: public nonblocking locks, canonical fields, PID close and OFD fork ok\n");
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
    public_lock_commands();
    expect("native lock commands and exact custody", ram_lock_commands(getpid()), 0);
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
