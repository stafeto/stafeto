// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The first ash probe has one process, one root directory, and no job control.
// Unsupported operations fail explicitly until the corresponding service exists.

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static int unsupported(void) { errno = ENOSYS; return -1; }
extern int stafeto_tty_available(void);

uid_t getuid(void) { return 0; }
uid_t geteuid(void) { return 0; }
gid_t getgid(void) { return 0; }
gid_t getegid(void) { return 0; }
pid_t getppid(void) { return 1; }
int isatty(int fd) {
    if (fd >= 0 && fd <= 2 && stafeto_tty_available()) return 1;
    errno = ENOTTY;
    return 0;
}

char *getcwd(char *buf, size_t size) {
    if (buf == NULL) {
        buf = malloc(2);
        if (buf == NULL) return NULL;
        size = 2;
    }
    if (size < 2) { errno = ERANGE; return NULL; }
    memcpy(buf, "/", 2);
    return buf;
}

int chdir(const char *path) {
    if (strcmp(path, "/") == 0 || strcmp(path, ".") == 0) return 0;
    errno = ENOENT;
    return -1;
}

int stat(const char *path, struct stat *st) {
    if (strcmp(path, "/") == 0 || strcmp(path, ".") == 0) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFDIR | 0555;
        return 0;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int result = fstat(fd, st);
    close(fd);
    return result;
}

mode_t umask(mode_t mask) {
    static mode_t current = 022;
    mode_t previous = current;
    current = mask;
    return previous;
}

int fcntl(int fd, int command, ...) {
    if (fd >= 0 && fd <= 2 && (command == F_GETFD || command == F_GETFL)) {
        return command == F_GETFL ? (fd == 0 ? O_RDONLY : O_WRONLY) : 0;
    }
    return unsupported();
}

int fork(void) { return unsupported(); }
int execve(const char *path, char *const argv[], char *const envp[]) {
    (void)path; (void)argv; (void)envp;
    return unsupported();
}
pid_t waitpid(pid_t pid, int *status, int options) {
    (void)pid; (void)status; (void)options;
    return unsupported();
}
int pipe(int fds[2]) { (void)fds; return unsupported(); }
int dup2(int from, int to) { (void)from; (void)to; return unsupported(); }
int poll(struct pollfd *fds, nfds_t count, int timeout) {
    (void)fds; (void)count; (void)timeout;
    return unsupported();
}
int sigaction(int signum, const struct sigaction *action, struct sigaction *old) {
    (void)signum; (void)action; (void)old;
    return unsupported();
}
int sigsuspend(const sigset_t *mask) { (void)mask; return unsupported(); }
int tcgetattr(int fd, struct termios *termios) {
    (void)fd; (void)termios;
    errno = ENOTTY;
    return -1;
}
int tcsetattr(int fd, int action, const struct termios *termios) {
    (void)fd; (void)action; (void)termios;
    errno = ENOTTY;
    return -1;
}
int getrlimit(int resource, struct rlimit *limit) {
    (void)resource; (void)limit;
    return unsupported();
}
int setrlimit(int resource, const struct rlimit *limit) {
    (void)resource; (void)limit;
    return unsupported();
}
clock_t times(struct tms *times) { (void)times; return unsupported(); }
int gettimeofday(struct timeval *time, void *zone) {
    (void)time; (void)zone;
    return unsupported();
}
int glob(const char *pattern, int flags, int (*err)(const char *, int), glob_t *matches) {
    (void)pattern; (void)flags; (void)err; (void)matches;
    errno = ENOSYS;
    return GLOB_ABEND;
}
void globfree(glob_t *matches) { (void)matches; }
