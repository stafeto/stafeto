/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { \
    printf("posix-pty: line %d failed: %s (errno %d)\n", __LINE__, #test, errno); \
    return 1; } } while (0)
extern uint32_t stafeto_pty_description(uint32_t fd);
extern uint32_t stafeto_pty_query(uint32_t fd, uint32_t description);

struct pair { int master, slave; char name[32]; };
static int make_pair(struct pair *p) {
    p->master = posix_openpt(O_RDWR | O_NOCTTY);
    CHECK(p->master >= 0 && grantpt(p->master) == 0);
    const char *name = ptsname(p->master);
    CHECK(name && strlen(name) < sizeof p->name);
    strcpy(p->name, name);
    CHECK(unlockpt(p->master) == 0);
    p->slave = open(p->name, O_RDWR | O_NOCTTY);
    CHECK(p->slave >= 0 && isatty(p->slave) == 1);
    return 0;
}
static int raw_slave(int fd, int local) {
    struct termios t;
    CHECK(tcgetattr(fd, &t) == 0);
    t.c_iflag = 0; t.c_oflag = 0; t.c_lflag = 0;
    t.c_cflag = (t.c_cflag & ~CLOCAL) | (local ? CLOCAL : 0);
    t.c_cc[VMIN] = 1; t.c_cc[VTIME] = 0;
    CHECK(tcsetattr(fd, TCSANOW, &t) == 0);
    return 0;
}
static int close_pair(struct pair *p) {
    CHECK(close(p->slave) == 0 && close(p->master) == 0);
    return 0;
}
static int pause_ms(long ms) {
    struct timespec delay = {ms / 1000, ms % 1000 * 1000000};
    while (nanosleep(&delay, &delay) < 0) CHECK(errno == EINTR);
    return 0;
}
static int read_byte(int fd, char *byte) {
    ssize_t got;
    do { got = read(fd, byte, 1); } while (got < 0 && errno == EINTR);
    CHECK(got == 1);
    return 0;
}
static int wait_ok(pid_t pid) {
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

static int names_grants(void) {
    struct pair p;
    p.master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    CHECK(p.master >= 0 && (fcntl(p.master, F_GETFD) & FD_CLOEXEC));
    CHECK(grantpt(p.master) == 0);
    const char *name = ptsname(p.master);
    CHECK(name && strlen(name) < sizeof p.name); strcpy(p.name, name);
    errno = 0; CHECK(open(p.name, O_RDWR | O_NOCTTY) == -1);
    CHECK(unlockpt(p.master) == 0);
    p.slave = open(p.name, O_RDWR | O_NOCTTY); CHECK(p.slave >= 0);
    struct stat st;
    CHECK(fstat(p.slave, &st) == 0 && S_ISCHR(st.st_mode));
    CHECK(st.st_uid == getuid() && (st.st_mode & 0777) == 0620);
    CHECK(seteuid(1000) == 0 && getuid() == 0 && geteuid() == 1000);
    CHECK(grantpt(p.master) == 0);
    CHECK(seteuid(0) == 0 && fstat(p.slave, &st) == 0 && st.st_uid == 0);
    CHECK((st.st_mode & 0777) == 0620);
    errno = 0; CHECK(grantpt(-1) == -1 && errno == EBADF);
    int pipefd[2]; CHECK(pipe(pipefd) == 0);
    errno = 0; CHECK(grantpt(pipefd[0]) == -1 && errno == EINVAL);
    errno = 0; CHECK(grantpt(p.slave) == -1 && errno == EINVAL);
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    CHECK(close_pair(&p) == 0);
    printf("posix-pty: names, lock and real UID grant ok\n");
    return 0;
}

static int flags_refs(void) {
    struct pair p; CHECK(make_pair(&p) == 0 && raw_slave(p.slave, 1) == 0);
    int alias = dup(p.master); CHECK(alias >= 0);
    CHECK(fcntl(alias, F_SETFL, O_NONBLOCK) == 0);
    CHECK((fcntl(p.master, F_GETFL) & O_NONBLOCK) != 0);
    int sync[2], release[2]; CHECK(pipe(sync) == 0 && pipe(release) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        CHECK(close(sync[0]) == 0 && close(release[1]) == 0 && close(p.slave) == 0 && close(alias) == 0);
        CHECK((fcntl(p.master, F_GETFL) & O_NONBLOCK) != 0);
        CHECK(fcntl(p.master, F_SETFL, 0) == 0 && write(sync[1], "r", 1) == 1);
        char command; CHECK(read_byte(release[0], &command) == 0 && command == 'q');
        _exit(0); /* Gone releases this child's last master hold. */
    }
    CHECK(close(sync[1]) == 0 && close(release[0]) == 0);
    char c; CHECK(read(sync[0], &c, 1) == 1 && c == 'r');
    CHECK((fcntl(alias, F_GETFL) & O_NONBLOCK) == 0);
    CHECK(close(p.master) == 0 && close(alias) == 0);
    struct pollfd f = {p.slave, POLLIN | POLLOUT, 0};
    CHECK(poll(&f, 1, 0) == 1 && (f.revents & POLLHUP) == 0 && (f.revents & POLLOUT));
    CHECK(write(release[1], "q", 1) == 1 && wait_ok(child) == 0);
    f.events = POLLIN; f.revents = 0; CHECK(poll(&f, 1, 1000) == 1 && f.revents == (POLLIN | POLLERR | POLLHUP));
    CHECK(read(p.slave, &c, 1) == 0);
    errno = 0; CHECK(write(p.slave, "x", 1) == -1 && errno == EIO);
    f.events = 0; f.revents = 0;
    CHECK(poll(&f, 1, 0) == 1 && f.revents == (POLLERR | POLLHUP));
    CHECK(close(p.slave) == 0 && close(sync[0]) == 0 && close(release[1]) == 0);
    printf("posix-pty: shared flags, dup/fork and Gone disconnect ok\n");
    return 0;
}

static int discard_disconnect(void) {
    struct pair p; CHECK(make_pair(&p) == 0 && raw_slave(p.slave, 1) == 0);
    CHECK(write(p.master, "discard", 7) == 7);
    struct pollfd f = {p.slave, POLLIN, 0};
    CHECK(poll(&f, 1, 0) == 1 && f.revents == POLLIN);
    CHECK(close(p.master) == 0);
    char data[16]; CHECK(read(p.slave, data, sizeof data) == 0);
    f.events = POLLIN | POLLOUT; f.revents = 0;
    CHECK(poll(&f, 1, 0) == 1 && f.revents == (POLLIN | POLLERR | POLLHUP));
    CHECK(close(p.slave) == 0);
    printf("posix-pty: input discarded and no output readiness after disconnect\n");
    return 0;
}

struct waiting { int fd, read_call; int entered, done; ssize_t result; short ready; };
static void *waiter(void *data) {
    struct waiting *w = data;
    __atomic_store_n(&w->entered, 1, __ATOMIC_RELEASE);
    if (w->read_call) { char c; w->result = read(w->fd, &c, 1); }
    else { struct pollfd p = {w->fd, POLLIN, 0}; w->result = poll(&p, 1, 2000); w->ready = p.revents; }
    __atomic_store_n(&w->done, 1, __ATOMIC_RELEASE);
    return NULL;
}
static int armed_disconnect(void) {
    for (int read_call = 0; read_call < 2; read_call++) {
        struct pair p; CHECK(make_pair(&p) == 0 && raw_slave(p.slave, 1) == 0);
        struct waiting w = {.fd = p.slave, .read_call = read_call};
        pthread_t thread; CHECK(pthread_create(&thread, NULL, waiter, &w) == 0);
        while (!__atomic_load_n(&w.entered, __ATOMIC_ACQUIRE)) CHECK(pause_ms(1) == 0);
        CHECK(pause_ms(10) == 0 && __atomic_load_n(&w.done, __ATOMIC_ACQUIRE) == 0);
        CHECK(close(p.master) == 0 && pthread_join(thread, NULL) == 0);
        if (read_call) CHECK(w.result == 0);
        else CHECK(w.result == 1 && w.ready == (POLLIN | POLLERR | POLLHUP));
        CHECK(close(p.slave) == 0);
    }
    printf("posix-pty: waiting read and Watch complete on disconnect\n");
    return 0;
}

static int ring_and_input(void) {
    struct pair p; CHECK(make_pair(&p) == 0 && raw_slave(p.slave, 1) == 0);
    CHECK(fcntl(p.slave, F_SETFL, O_NONBLOCK) == 0);
    char output[8192], input[1024]; memset(output, 'q', sizeof output);
    ssize_t amount = write(p.slave, output, sizeof output);
    CHECK(amount > 0 && amount < (ssize_t)sizeof output);
    errno = 0; CHECK(write(p.slave, "z", 1) == -1 && errno == EAGAIN);
    struct pollfd ready = {p.master, POLLIN, 0};
    CHECK(poll(&ready, 1, 0) == 1 && (ready.revents & POLLIN));
    ssize_t total = 0;
    while (total < amount) {
        ssize_t n = read(p.master, input, sizeof input); CHECK(n > 0 && n <= amount - total);
        for (ssize_t i = 0; i < n; i++) CHECK(input[i] == 'q');
        total += n;
    }
    CHECK(tcdrain(p.slave) == 0);
    CHECK(write(p.master, "bytes", 5) == 5 && read(p.slave, input, sizeof input) == 5);
    CHECK(memcmp(input, "bytes", 5) == 0);
    CHECK(write(p.master, "discard", 7) == 7 && tcflush(p.slave, TCIFLUSH) == 0);
    errno = 0; CHECK(read(p.slave, input, 1) == -1 && errno == EAGAIN);
    CHECK(close_pair(&p) == 0);
    printf("posix-pty: bounded output, partial write, input and flush ok\n");
    return 0;
}

static volatile sig_atomic_t hup_count, cont_count;
static void caught(int signal) { if (signal == SIGHUP) hup_count++; if (signal == SIGCONT) cont_count++; }
static int install_signals(void) {
    struct sigaction a = {.sa_handler = caught}; sigemptyset(&a.sa_mask);
    CHECK(sigaction(SIGHUP, &a, NULL) == 0 && sigaction(SIGCONT, &a, NULL) == 0);
    hup_count = 0; cont_count = 0; return 0;
}
static int controller_disconnect(int local) {
    struct pair p; CHECK(make_pair(&p) == 0 && raw_slave(p.slave, local) == 0);
    int ready[2], command[2]; CHECK(pipe(ready) == 0 && pipe(command) == 0);
    pid_t controller = fork(); CHECK(controller >= 0);
    if (controller == 0) {
        CHECK(close(p.master) == 0 && close(ready[0]) == 0 && close(command[1]) == 0);
        CHECK(setsid() == getpid() && install_signals() == 0);
        CHECK(ioctl(p.slave, TIOCSCTTY, 0) == 0 && tcgetsid(p.slave) == getpid());
        int foreground_command[2]; CHECK(pipe(foreground_command) == 0);
        pid_t fg = fork(); CHECK(fg >= 0);
        if (fg == 0) {
            CHECK(setpgid(0, 0) == 0 && install_signals() == 0);
            CHECK(close(foreground_command[1]) == 0);
            char c; CHECK(read_byte(foreground_command[0], &c) == 0);
            CHECK(hup_count == 0 && cont_count == 0);
            _exit(0);
        }
        CHECK(close(foreground_command[0]) == 0 && setpgid(fg, fg) == 0);
        CHECK(tcsetpgrp(p.slave, fg) == 0 && tcgetpgrp(p.slave) == fg);
        CHECK(write(ready[1], "r", 1) == 1);
        char c; CHECK(read_byte(command[0], &c) == 0);
        CHECK(pause_ms(20) == 0 && hup_count == (local ? 0 : 1) && cont_count == 0);
        CHECK(write(foreground_command[1], "q", 1) == 1 && wait_ok(fg) == 0);
        errno = 0; CHECK(tcgetsid(p.slave) == -1 && errno == ENOTTY);
        _exit(0);
    }
    CHECK(close(ready[1]) == 0 && close(command[0]) == 0);
    char c; CHECK(read(ready[0], &c, 1) == 1 && c == 'r');
    CHECK(close(p.master) == 0 && write(command[1], "q", 1) == 1 && wait_ok(controller) == 0);
    CHECK(close(p.slave) == 0 && close(ready[0]) == 0 && close(command[1]) == 0);
    printf("posix-pty: CLOCAL=%d controller PID=SID HUP target ok\n", local);
    return 0;
}

static int limits_and_generation(void) {
    int masters[8];
    for (unsigned i = 0; i < 8; i++) { masters[i] = posix_openpt(O_RDWR | O_NOCTTY); CHECK(masters[i] >= 0); }
    errno = 0; CHECK(posix_openpt(O_RDWR | O_NOCTTY) == -1 && errno == EAGAIN);
    for (unsigned i = 0; i < 8; i++) CHECK(close(masters[i]) == 0);
    struct pair old; CHECK(make_pair(&old) == 0);
    uint32_t old_id = stafeto_pty_description((uint32_t)old.slave);
    CHECK(old_id != UINT32_MAX && stafeto_pty_query((uint32_t)old.slave, old_id) == 0);
    CHECK(close_pair(&old) == 0);
    struct pair fresh; CHECK(make_pair(&fresh) == 0);
    uint32_t new_id = stafeto_pty_description((uint32_t)fresh.slave);
    CHECK(new_id != old_id && (new_id & 255) == (old_id & 255));
    CHECK(stafeto_pty_query((uint32_t)fresh.slave, new_id) == 0);
    uint32_t stale = stafeto_pty_query((uint32_t)fresh.slave, old_id);
    CHECK(stale == 809);
    CHECK(tcgetattr(fresh.slave, &(struct termios){0}) == 0);
    CHECK(close_pair(&fresh) == 0);
    printf("posix-pty: eight instances, description reuse and stale status %u ok\n", stale);
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    /* The file-loaded image supplies the region map used by fork. */
    if (argc == 1) {
        char *next[] = {"posix-pty", "loaded", NULL}, *env[] = {NULL};
        execve("/bin/posix-pty", next, env); CHECK(0);
    }
    CHECK(names_grants() == 0 && flags_refs() == 0 && discard_disconnect() == 0 && armed_disconnect() == 0);
    CHECK(ring_and_input() == 0 && controller_disconnect(0) == 0 && controller_disconnect(1) == 0);
    CHECK(limits_and_generation() == 0);
    printf("posix-pty: ok\n");
    return 0;
}
