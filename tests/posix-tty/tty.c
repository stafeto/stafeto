/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The probe of the terminal (5f) from C on relibc: the termios functions
 * reach the terminal service through the layer.
 *
 * Identity: isatty is 1 on the standard descriptors and 0 on a pipe and on
 * /dev/null, with ENOTTY; ttyname gives "/dev/console" and the errors of
 * ttyname_r are their numbers. Settings: tcgetattr gives what tcsetattr
 * wrote, in every field including the two speeds. Raw input: with ICANON
 * and ECHO off and VMIN 1 each byte typed comes at once, with no echo;
 * the restored settings bring the canonical read back. Queues: tcflush and
 * TCSAFLUSH drop the input typed and not read. Output: tcflow stops and
 * starts it and sends STOP and START, tcflush drops what the driver did
 * not take, tcdrain waits for the output to go. Names: /dev/console and
 * /dev/tty name the terminal, which fork carries to a child; stat says a
 * character device; the terminal functions give EINVAL, ENOTTY and EBADF
 * where POSIX does. Sessions: a process of a session with no controlling
 * terminal gets ENOTTY from tcgetpgrp and ENXIO from /dev/tty; a leader's
 * open takes the console, a member's and one with O_NOCTTY do not;
 * tcsetpgrp takes a group of the session and refuses another session's.
 *
 * The program has three roles: the launcher that init starts, which spawns
 * /bin/posix-tty as "run" (init's own process has no code to fork; a
 * process of the loader does) and waits for it; "run", which does the
 * checks above, forks, and spawns /bin/posix-tty as "spawned" with the
 * terminal as an inherited descriptor and as one a file action opened;
 * and "spawned", which finds both its descriptors a terminal.
 *
 * Every check says its line on the console; xtask posix-tty types the
 * input the probe asks for and reads the lines. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* The numbers and structures relibc gives C are those of AArch64 Linux,
 * which the terminal service's proto_tty and the layer's posix-platform
 * hold with const assertions of their own. */
_Static_assert(sizeof(struct termios) == 60, "termios of Linux");
_Static_assert(offsetof(struct termios, c_cc) == 17, "c_cc");
_Static_assert(NCCS == 32, "NCCS");
_Static_assert(VINTR == 0 && VERASE == 2 && VEOF == 4 && VTIME == 5 && VMIN == 6, "c_cc");
_Static_assert(ICANON == 2 && ECHO == 010 && ISIG == 1 && ECHOCTL == 01000, "c_lflag");
_Static_assert(B9600 == 015 && B38400 == 017 && B115200 == 010002, "speeds");
_Static_assert(TCSANOW == 0 && TCSADRAIN == 1 && TCSAFLUSH == 2, "actions");
_Static_assert(TCIFLUSH == 0 && TCOFLUSH == 1 && TCIOFLUSH == 2, "queues");
_Static_assert(TCOOFF == 0 && TCOON == 1 && TCIOFF == 2 && TCION == 3, "flow");

static void say(const char *format, ...) {
    char line[160];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(line, sizeof line, format, args);
    va_end(args);
    if (n > 0) write(1, line, (size_t)n);
}

#define CHECK(cond) do { if (!(cond)) { \
    say("posix-tty: check failed at line %d: %s (errno %d)\n", __LINE__, #cond, errno); \
    return 20; } } while (0)

/* A write of the whole literal. */
#define PUT(fd, text) (write((fd), (text), sizeof(text) - 1) == (ssize_t)(sizeof(text) - 1))

/* The settings field by field: the struct's padding says nothing. */
static int same(const struct termios *a, const struct termios *b) {
    return a->c_iflag == b->c_iflag && a->c_oflag == b->c_oflag &&
           a->c_cflag == b->c_cflag && a->c_lflag == b->c_lflag &&
           memcmp(a->c_cc, b->c_cc, NCCS) == 0 &&
           cfgetispeed(a) == cfgetispeed(b) && cfgetospeed(a) == cfgetospeed(b);
}

static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void pause_ms(long ms) {
    struct timespec t = {0, ms * 1000000};
    nanosleep(&t, NULL);
}

/* Identity: isatty, ttyname, ttyname_r. */
static int identity(void) {
    int p[2];
    CHECK(pipe(p) == 0);
    CHECK(isatty(0) == 1 && isatty(1) == 1 && isatty(2) == 1);
    errno = 0;
    CHECK(isatty(p[0]) == 0 && errno == ENOTTY);
    errno = 0;
    CHECK(isatty(p[1]) == 0 && errno == ENOTTY);
    errno = 0;
    CHECK(isatty(99) == 0 && errno == EBADF);
    int null = open("/dev/null", O_RDWR);
    CHECK(null >= 0);
    errno = 0;
    CHECK(isatty(null) == 0 && errno == ENOTTY);
    CHECK(close(null) == 0);

    char *name = ttyname(0);
    CHECK(name != NULL && strcmp(name, "/dev/console") == 0);
    errno = 0;
    CHECK(ttyname(p[0]) == NULL && errno == ENOTTY);
    char buffer[16];
    CHECK(ttyname_r(1, buffer, sizeof buffer) == 0 && strcmp(buffer, "/dev/console") == 0);
    CHECK(ttyname_r(2, buffer, 13) == 0);
    CHECK(ttyname_r(0, buffer, 12) == ERANGE);
    CHECK(ttyname_r(0, buffer, 1) == ERANGE);
    CHECK(ttyname_r(p[0], buffer, sizeof buffer) == ENOTTY);
    CHECK(ttyname_r(99, buffer, sizeof buffer) == EBADF);
    CHECK(close(p[0]) == 0 && close(p[1]) == 0);
    say("posix-tty: identity ok\n");
    return 0;
}

/* The errors of the termios functions. */
static int errors(void) {
    struct termios t;
    int p[2];
    CHECK(pipe(p) == 0);
    CHECK(tcgetattr(0, &t) == 0);
    errno = 0;
    CHECK(tcgetattr(p[0], &t) == -1 && errno == ENOTTY);
    errno = 0;
    CHECK(tcgetattr(99, &t) == -1 && errno == EBADF);
    errno = 0;
    CHECK(tcsetattr(p[1], TCSANOW, &t) == -1 && errno == ENOTTY);
    errno = 0;
    CHECK(tcdrain(p[1]) == -1 && errno == ENOTTY);
    errno = 0;
    CHECK(tcflush(p[1], TCIFLUSH) == -1 && errno == ENOTTY);
    errno = 0;
    CHECK(tcflow(p[1], TCOON) == -1 && errno == ENOTTY);
    errno = 0;
    CHECK(tcsendbreak(p[1], 0) == -1 && errno == ENOTTY);
    errno = 0;
    CHECK(tcsetattr(0, 99, &t) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(tcflush(0, 7) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(tcflow(0, 9) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(cfsetispeed(&t, 0777777) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(cfsetospeed(&t, 0777777) == -1 && errno == EINVAL);
    CHECK(close(p[0]) == 0 && close(p[1]) == 0);
    say("posix-tty: errors ok\n");
    return 0;
}

/* The settings a terminal opens with, and the round trip of every field,
 * the speeds among them. */
static int settings(struct termios *saved) {
    CHECK(tcgetattr(0, saved) == 0);
    CHECK((saved->c_lflag & (ICANON | ECHO | ISIG)) == (ICANON | ECHO | ISIG));
    CHECK(saved->c_cc[VMIN] == 1 && saved->c_cc[VTIME] == 0);
    CHECK(saved->c_cc[VINTR] == 3 && saved->c_cc[VERASE] == 0x7f && saved->c_cc[VEOF] == 4);
    CHECK((saved->c_iflag & ICRNL) && (saved->c_oflag & (OPOST | ONLCR)) == (OPOST | ONLCR));
    CHECK((saved->c_cflag & CS8) == CS8 && cfgetispeed(saved) == B38400);

    struct termios t = *saved, back;
    CHECK(cfsetispeed(&t, B9600) == 0 && cfsetospeed(&t, B115200) == 0);
    t.c_cc[VEOF] = 0x05;
    t.c_cc[VMIN] = 7;
    t.c_cc[VTIME] = 3;
    CHECK(tcsetattr(0, TCSANOW, &t) == 0);
    memset(&back, 0, sizeof back);
    CHECK(tcgetattr(0, &back) == 0);
    CHECK(same(&back, &t));
    CHECK(cfgetispeed(&back) == B9600 && cfgetospeed(&back) == B115200);
    CHECK(cfsetspeed(&t, B38400) == 0 && cfgetispeed(&t) == B38400 && cfgetospeed(&t) == B38400);
    CHECK(tcsetattr(0, TCSADRAIN, saved) == 0);
    CHECK(tcgetattr(0, &back) == 0 && same(&back, saved));
    say("posix-tty: settings ok\n");
    return 0;
}

/* Raw input: single bytes with no echo and no wait for a line; then the
 * canonical read again after the settings are restored. */
static int raw_and_canonical(const struct termios *saved) {
    struct termios raw = *saved, back;
    raw.c_lflag &= ~(tcflag_t)(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    CHECK(tcsetattr(0, TCSANOW, &raw) == 0);
    CHECK(tcgetattr(0, &back) == 0 && same(&back, &raw));
    for (int i = 0; i < 3; i++) {
        say("posix-tty: raw read %d waits\n", i);
        unsigned char c = 0;
        CHECK(read(0, &c, 1) == 1);
        say("posix-tty: raw read %d gave 0x%02x\n", i, c);
    }
    CHECK(tcsetattr(0, TCSAFLUSH, saved) == 0);
    CHECK(tcgetattr(0, &back) == 0 && same(&back, saved));
    say("posix-tty: attributes restored\n");

    say("posix-tty: canonical read waits\n");
    char line[64];
    ssize_t n = read(0, line, sizeof line);
    CHECK(n == 3 && memcmp(line, "hi\n", 3) == 0);
    say("posix-tty: canonical read gave %d bytes\n", (int)n);
    return 0;
}

/* Input typed and not read goes with tcflush and with TCSAFLUSH. The bytes
 * wait in the line (canonical) or in the queue (VMIN 0 with VTIME 1 lets
 * a read give them): a read that gives none shows the flush. */
static int flushing(const struct termios *saved) {
    struct termios timed = *saved, back;
    timed.c_lflag &= ~(tcflag_t)ICANON;
    timed.c_cc[VMIN] = 0;
    timed.c_cc[VTIME] = 1;
    char c[16];

    say("posix-tty: type junk\n");
    pause_ms(300);
    CHECK(tcflush(0, TCIFLUSH) == 0);
    CHECK(tcsetattr(0, TCSANOW, &timed) == 0);
    CHECK(read(0, c, sizeof c) == 0);
    say("posix-tty: tcflush dropped the input\n");

    say("posix-tty: type more junk\n");
    pause_ms(300);
    CHECK(tcsetattr(0, TCSAFLUSH, &timed) == 0);
    CHECK(read(0, c, sizeof c) == 0);
    say("posix-tty: TCSAFLUSH dropped the input\n");

    /* Input typed after the flush is read. */
    struct termios waiting = timed;
    waiting.c_cc[VMIN] = 1;
    waiting.c_cc[VTIME] = 0;
    CHECK(tcsetattr(0, TCSANOW, &waiting) == 0);
    say("posix-tty: type k\n");
    CHECK(read(0, c, sizeof c) == 1 && c[0] == 'k');
    say("posix-tty: input after a flush is read\n");
    CHECK(tcsetattr(0, TCSANOW, saved) == 0);
    CHECK(tcgetattr(0, &back) == 0 && same(&back, saved));
    return 0;
}

/* tcflow(TCION) a moment after tcflow(TCOOFF), from a thread. */
static void *release(void *arg) {
    (void)arg;
    pause_ms(200);
    return (void *)(long)tcflow(1, TCOON);
}

static int output(void) {
    /* STOP and START go out as they are, between the bytes written. */
    CHECK(PUT(1, "<") && tcflow(1, TCIOFF) == 0 && PUT(1, ">"));
    CHECK(PUT(1, "(") && tcflow(1, TCION) == 0 && PUT(1, ")\n"));

    /* The output the driver did not take is dropped: stopped, written,
     * flushed, started. */
    CHECK(tcflow(1, TCOOFF) == 0);
    CHECK(PUT(1, "posix-tty: dropped by tcflush\n"));
    CHECK(tcflush(1, TCOFLUSH) == 0);
    CHECK(tcflow(1, TCOON) == 0);
    CHECK(tcdrain(1) == 0);
    say("posix-tty: output flushed\n");

    /* tcdrain waits while the output is stopped, and returns once it
     * went. */
    pthread_t releasing;
    CHECK(tcflow(1, TCOOFF) == 0);
    CHECK(PUT(1, "posix-tty: held by tcflow\n"));
    long long start = now_ms();
    CHECK(pthread_create(&releasing, NULL, release, NULL) == 0);
    CHECK(tcdrain(1) == 0);
    long long waited = now_ms() - start;
    void *result = (void *)1;
    CHECK(pthread_join(releasing, &result) == 0 && result == NULL);
    say("posix-tty: tcdrain waited %lld ms\n", waited);
    CHECK(waited >= 150);
    CHECK(tcsendbreak(0, 0) == 0);
    say("posix-tty: output ok\n");
    return 0;
}

/* The names of terminals: opened by the layer, the same terminal through
 * every descriptor, carried to a child by fork. */
static int names(const struct termios *saved) {
    struct stat info;
    CHECK(stat("/dev/console", &info) == 0 && S_ISCHR(info.st_mode));
    CHECK(stat("/dev/tty", &info) == 0 && S_ISCHR(info.st_mode));
    int fd = open("/dev/console", O_RDWR | O_NOCTTY);
    CHECK(fd > 2);
    CHECK(fstat(fd, &info) == 0 && S_ISCHR(info.st_mode));
    CHECK(isatty(fd) == 1);
    char *name = ttyname(fd);
    CHECK(name != NULL && strcmp(name, "/dev/console") == 0);
    struct termios t;
    CHECK(tcgetattr(fd, &t) == 0 && same(&t, saved));
    CHECK(PUT(fd, "posix-tty: written through /dev/console\n"));
    /* /dev/tty is the controlling terminal of the caller's session, and
     * this session has none: ENXIO (sessions() opens it with one). */
    errno = 0;
    CHECK(open("/dev/tty", O_RDWR) == -1 && errno == ENXIO);
    errno = 0;
    CHECK(open("/dev/console", O_RDONLY | O_DIRECTORY) == -1 && errno == ENOTDIR);
    errno = 0;
    CHECK(open("/dev/console/", O_RDWR) == -1 && errno == ENOTDIR);
    int copy = dup(fd);
    CHECK(copy > fd && isatty(copy) == 1 && close(copy) == 0);

    /* One terminal behind every name: the settings written through fd are
     * the ones fd 0 reads. */
    struct termios changed = *saved;
    changed.c_cc[VMIN] = 5;
    CHECK(tcsetattr(fd, TCSANOW, &changed) == 0);
    CHECK(tcgetattr(0, &t) == 0 && t.c_cc[VMIN] == 5);

    /* fork: the child's session with the service serves its copy of fd. */
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        struct termios in_child;
        if (tcgetattr(fd, &in_child) != 0 || in_child.c_cc[VMIN] != 5) _exit(31);
        in_child.c_cc[VMIN] = 9;
        if (tcsetattr(fd, TCSANOW, &in_child) != 0) _exit(32);
        if (!PUT(fd, "posix-tty: child wrote through /dev/console\n")) _exit(33);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(tcgetattr(0, &t) == 0 && t.c_cc[VMIN] == 9);

    /* posix_spawn: the descriptor opened without FD_CLOEXEC is inherited,
     * and a file action opens the name at 5; both are the terminal in the
     * child, whose session with the service the spawn gives it. */
    char inherited[16];
    snprintf(inherited, sizeof inherited, "%d", fd);
    int fd2 = open("/dev/console", O_RDWR);
    CHECK(fd2 > 2);
    CHECK(tcgetattr(fd2, &t) == 0);
    posix_spawn_file_actions_t actions;
    CHECK(posix_spawn_file_actions_init(&actions) == 0);
    CHECK(posix_spawn_file_actions_addopen(&actions, 5, "/dev/console", O_RDWR, 0) == 0);
    char *args[] = {"posix-tty", "spawned", inherited, "5", NULL};
    char *no_environment[] = {NULL};
    pid_t spawned;
    int spawn_error = posix_spawn(&spawned, "/bin/posix-tty", &actions, NULL, args, no_environment);
    if (spawn_error != 0) say("posix-tty: terminal spawn error %d\n", spawn_error);
    CHECK(spawn_error == 0);
    CHECK(waitpid(spawned, &status, 0) == spawned && WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(posix_spawn_file_actions_destroy(&actions) == 0);
    CHECK(close(fd2) == 0);
    CHECK(tcgetattr(0, &t) == 0 && t.c_cc[VMIN] == 11);
    CHECK(tcsetattr(fd, TCSANOW, saved) == 0);
    CHECK(close(fd) == 0);
    say("posix-tty: names ok\n");
    return 0;
}

/* TtySignal through the process's own session: the process service takes
 * it from the terminal service alone. */
extern int stafeto_probe_tty_signal(int pgid, int signal);
extern int stafeto_probe_trusted_terminal(int target, int newborn);
extern int stafeto_probe_terminal_edge(unsigned group);
static volatile sig_atomic_t winches;
static void winch(int number) { (void)number; ++winches; }
static int catch_winch(void) {
    struct sigaction action = {0};
    action.sa_handler = winch;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    return sigaction(SIGWINCH, &action, NULL);
}

/* Sixteen live members have distinct signal pages and routers. A walk
 * delivers to one member per step and scans at most sixteen empty slots. */
static int terminal_crowd(void) {
    enum { MEMBERS = 16 };
    int ready[2];
    if (pipe(ready) != 0) return 117;
    pid_t children[MEMBERS];
    for (int i = 0; i < MEMBERS; ++i) {
        children[i] = fork();
        if (children[i] < 0) return 118;
        if (children[i] == 0) {
            winches = 0;
            if (catch_winch() != 0 || write(ready[1], "r", 1) != 1) _exit(119);
            for (int waited = 0; winches == 0 && waited < 2000; ++waited) pause_ms(1);
            if (winches != 1) say("posix-tty: crowd handler count %d\n", (int)winches);
            _exit(winches == 1 ? 0 : 121);
        }
    }
    char byte;
    for (int i = 0; i < MEMBERS; ++i)
        if (read(ready[0], &byte, 1) != 1 || byte != 'r') return 122;
    if (stafeto_probe_trusted_terminal(getpgrp(), 0) != 0) return 123;
    for (int i = 0; i < MEMBERS; ++i) {
        int status = 0;
        if (waitpid(children[i], &status, 0) != children[i] ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            say("posix-tty: crowd child %d status %d\n", i, status);
            return 125;
        }
    }
    for (int i = 0; i < 2; ++i)
        if (close(ready[i]) != 0) return 126;
    say("posix-tty: terminal signal reached sixteen members\n");
    return 0;
}


static volatile sig_atomic_t hups;
static void on_hup(int signal) { if (signal == SIGHUP) ++hups; }

static int job_foreground(int fd, pid_t group) {
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGTTOU);
    if (sigprocmask(SIG_BLOCK, &block, &old) != 0) return -1;
    int result = tcsetpgrp(fd, group);
    if (sigprocmask(SIG_SETMASK, &old, NULL) != 0) return -1;
    return result;
}

/* An already armed read rechecks foreground on Take before consuming input. */
static int foreground_recheck(int fd) {
    int gate[2], ready[2], status;
    CHECK(pipe(gate) == 0 && pipe(ready) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        char byte, line[4];
        if (setpgid(0, 0) != 0 || write(ready[1], "r", 1) != 1
            || read(gate[0], &byte, 1) != 1) _exit(141);
        if (read(fd, line, sizeof line) != 2 || line[0] != 'r' || line[1] != '\n') _exit(142);
        _exit(0);
    }
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1);
    CHECK(job_foreground(fd, child) == 0 && write(gate[1], "g", 1) == 1);
    pause_ms(80);
    CHECK(job_foreground(fd, getpgrp()) == 0);
    say("posix-tty: foreground changed during read\n");
    CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status) && WSTOPSIG(status) == SIGTTIN);
    CHECK(job_foreground(fd, child) == 0 && kill(child, SIGCONT) == 0);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(job_foreground(fd, getpgrp()) == 0);
    CHECK(close(gate[0]) == 0 && close(gate[1]) == 0 && close(ready[0]) == 0 && close(ready[1]) == 0);
    return 0;
}

static int terminal_detach(int fd) {
    struct sigaction ignore = {0}, saved;
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    CHECK(sigaction(SIGHUP, &ignore, &saved) == 0);
    int ready[2], gate[2], status;
    CHECK(pipe(ready) == 0 && pipe(gate) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        char line[4];
        winches = 0;
        if (setpgid(0, 0) != 0 || catch_winch() != 0 || ioctl(fd, TIOCNOTTY, 0) != 0) _exit(143);
        errno = 0;
        if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO) _exit(144);
        errno = 0;
        if (tcgetsid(fd) != -1 || errno != ENOTTY || getpgrp() != getpid()) _exit(145);
        if (write(ready[1], "r", 1) != 1 || read(gate[0], line, 1) != 1 || winches != 1) _exit(146);
        if (read(fd, line, sizeof line) != 2 || line[0] != 'd' || line[1] != '\n') _exit(147);
        _exit(0);
    }
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && kill(-child, SIGWINCH) == 0 && write(gate[1], "g", 1) == 1);
    say("posix-tty: detached reader still uses open fd\n");
    CHECK(waitpid(child, &status, 0) == child);
    if (status != 0) say("posix-tty: detached child status %x\n", status);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (open("/dev/tty", O_RDWR) < 0 || write(ready[1], "r", 1) != 1 || read(gate[0], &byte, 1) != 1) _exit(148);
        errno = 0;
        if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO) _exit(149);
        errno = 0;
        if (tcgetsid(fd) != -1 || errno != ENOTTY) _exit(150);
        _exit(0);
    }
    CHECK(read(ready[0], &byte, 1) == 1);
    CHECK(ioctl(fd, TIOCNOTTY, 0) == 0);
    errno = 0;
    CHECK(open("/dev/tty", O_RDWR) == -1 && errno == ENXIO);
    CHECK(ioctl(fd, TIOCSCTTY, 0) == 0 && tcgetsid(fd) == getpid());
    CHECK(write(gate[1], "g", 1) == 1);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) _exit(open("/dev/tty", O_RDWR) >= 0 && tcgetsid(fd) == getsid(0) ? 0 : 151);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(ready[0]) == 0 && close(ready[1]) == 0 && close(gate[0]) == 0 && close(gate[1]) == 0);
    CHECK(sigaction(SIGHUP, &saved, NULL) == 0);
    say("posix-tty: personal detach and fresh attachment ok\n");
    return 0;
}

static int terminal_jobs(int fd) {
    struct termios saved, settings;
    CHECK(tcgetattr(fd, &saved) == 0);
    settings = saved;
    settings.c_lflag |= ICANON | ISIG;
    CHECK(tcsetattr(fd, TCSANOW, &settings) == 0);
    int recheck = foreground_recheck(fd);
    if (recheck) return recheck;
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (setpgid(0, 0) != 0) _exit(131);
        char bytes[4];
        if (read(fd, bytes, sizeof bytes) != 2 || bytes[0] != 'j' || bytes[1] != '\n') _exit(132);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status) && WSTOPSIG(status) == SIGTTIN);
    CHECK(job_foreground(fd, child) == 0);
    CHECK(kill(child, SIGCONT) == 0);
    /* The same pending terminal operation proceeds after the default stop. */
    CHECK(kill(child, SIGSTOP) == 0);
    CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    CHECK(kill(child, SIGCONT) == 0);
    say("posix-tty: stopped reader resumed\n");
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(job_foreground(fd, getpgrp()) == 0);

    settings.c_lflag |= TOSTOP;
    CHECK(tcsetattr(fd, TCSANOW, &settings) == 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        sigset_t block;
        sigemptyset(&block);
        sigaddset(&block, SIGTTIN);
        if (setpgid(0, 0) != 0 || sigprocmask(SIG_BLOCK, &block, NULL) != 0) _exit(158);
        char byte;
        errno = 0;
        if (read(fd, &byte, 1) != -1 || errno != EIO) _exit(159);
        /* TTOU was inherited blocked: TOSTOP permits this background write. */
        if (write(fd, "blocked-TTOU\n", 13) != 13) _exit(160);
        _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    for (int change = 0; change < 2; ++change) {
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            sigset_t block;
            sigemptyset(&block);
            sigaddset(&block, SIGTTOU);
            if (sigprocmask(SIG_UNBLOCK, &block, NULL) != 0 || setpgid(0, 0) != 0) _exit(133);
            int result = change ? tcsetattr(fd, TCSANOW, &settings) : (int)write(fd, "job-output\n", 11);
            _exit(result == (change ? 0 : 11) ? 0 : 134);
        }
        CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status) && WSTOPSIG(status) == SIGTTOU);
        CHECK(job_foreground(fd, child) == 0);
        CHECK(kill(child, SIGCONT) == 0);
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        CHECK(job_foreground(fd, getpgrp()) == 0);
    }
    CHECK(tcsetattr(fd, TCSANOW, &saved) == 0);
    say("posix-tty: job control ok\n");
    return 0;
}

/* The leader A of a new session, a child of "run" (XBD 11.1.3,
 * tcsetpgrp, tcgetpgrp, tcgetsid): a member of its session that opens the
 * console takes nothing; A's open with O_NOCTTY takes nothing either; its
 * open without takes the console, whose foreground group is A's; a group
 * of another session cannot be the foreground (EPERM), one of A's session
 * can. The exit code names the check that failed. */
static int leader(pid_t other_group) {
    if (setsid() != getpid()) return 51;
    errno = 0;
    if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO) return 52;
    /* A member that opens the console does not make it the session's. */
    pid_t member = fork();
    if (member < 0) return 53;
    if (member == 0) {
        int fd = open("/dev/console", O_RDWR);
        if (fd < 0) _exit(1);
        errno = 0;
        if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO) _exit(2);
        _exit(0);
    }
    int status = 0;
    if (waitpid(member, &status, 0) != member || !WIFEXITED(status)) return 54;
    if (WEXITSTATUS(status) != 0) return 60 + WEXITSTATUS(status);
    errno = 0;
    if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO) return 55;
    int quiet = open("/dev/console", O_RDWR | O_NOCTTY);
    if (quiet < 0) return 56;
    errno = 0;
    if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO) return 57;
    errno = 0;
    if (tcgetpgrp(quiet) != -1 || errno != ENOTTY) return 58;
    int early_gate[2];
    if (pipe(early_gate) != 0) return 152;
    pid_t early = fork();
    if (early < 0) return 153;
    if (early == 0) {
        char byte;
        if (read(early_gate[0], &byte, 1) != 1) _exit(154);
        errno = 0;
        if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO) _exit(155);
        _exit(0);
    }
    /* The leader's open takes the console. */
    int console = open("/dev/console", O_RDWR);
    if (console < 0) return 70;
    int tty = open("/dev/tty", O_RDWR);
    if (tty < 0) return 71;
    if (tcgetpgrp(tty) != getpgrp()) return 72;
    if (tcgetsid(tty) != getpid()) return 73;
    if (tcgetpgrp(0) != getpgrp()) return 74;
    if (write(early_gate[1], "g", 1) != 1 || waitpid(early, &status, 0) != early
        || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 156;
    if (close(early_gate[0]) != 0 || close(early_gate[1]) != 0) return 157;
    sigset_t quiet_background;
    sigemptyset(&quiet_background);
    sigaddset(&quiet_background, SIGTTOU);
    if (sigprocmask(SIG_BLOCK, &quiet_background, NULL) != 0) return 135;
    /* A process cannot send a signal as the terminal, not even to the
     * foreground group of its own terminal's session. */
    if (stafeto_probe_tty_signal(getpgrp(), SIGWINCH) != EPERM) return 59;
    errno = 0;
    if (tcsetpgrp(tty, other_group) != -1 || errno != EPERM) return 75;
    errno = 0;
    if (tcsetpgrp(tty, 0) != -1 || errno != EINVAL) return 76;
    /* The real TERMINAL notary refuses a group from another session. */
    if (stafeto_probe_trusted_terminal(other_group, 0) != EPERM) return 95;

    /* A group of the session: a child in a group of its own. */
    int ready[2], go[2];
    if (pipe(ready) != 0 || pipe(go) != 0) return 77;
    pid_t child = fork();
    if (child < 0) return 78;
    if (child == 0) {
        char c = 0;
        if (catch_winch() != 0) _exit(1);
        winches = 0;
        if (write(ready[1], "r", 1) != 1) _exit(2);
        if (read(go[0], &c, 1) != 1 || c != 'g') _exit(3);
        if (getpgrp() != getpid()) _exit(4);
        if (winches != 1) _exit(5);
        _exit(0);
    }
    char c = 0;
    if (read(ready[0], &c, 1) != 1 || c != 'r') return 79;
    /* Parent setpgid must publish both of the child's pages before reply. */
    if (setpgid(child, child) != 0) return 96;
    /* Real signal_newborn with the child's index behind a controlled
     * cursor. The special service also counts actual delivery calls. */
    if (stafeto_probe_trusted_terminal(child, 1) != 0) return 97;
    if (tcsetpgrp(tty, child) != 0) return 80;
    if (tcgetpgrp(tty) != child) return 81;
    if (tcsetpgrp(tty, getpgrp()) != 0) return 82;
    if (tcgetpgrp(tty) != getpgrp()) return 83;
    /* Successful last-slot lookup and an absent group use all 256 words.
     * Only the special process image supplies the synthetic final word. */
    const pid_t edge = 0x7ffffffe;
    if (stafeto_probe_terminal_edge(edge) != 0) return 98;
    if (tcsetpgrp(tty, edge) != 0 || tcgetpgrp(tty) != edge) return 99;
    if (stafeto_probe_terminal_edge(0) != 0) return 100;
    errno = 0;
    if (tcsetpgrp(tty, edge) != -1 || errno != EPERM) return 106;
    if (tcsetpgrp(tty, getpgrp()) != 0) return 107;
    if (stafeto_probe_trusted_terminal(getpgrp(), 0) != 0) return 108;

    if (write(go[1], "g", 1) != 1) return 84;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 85;
    if (WEXITSTATUS(status) != 0) return 90 + WEXITSTATUS(status);
    int job_error = terminal_jobs(tty);
    if (job_error != 0) return job_error;
    int detach_error = terminal_detach(tty);
    if (detach_error != 0) return detach_error;
    int crowd_error = terminal_crowd();
    if (crowd_error != 0) return crowd_error;
    return 0;
}

/* Sessions and the controlling terminal: "run" has none, its child A
 * (`leader`) makes a session and takes the console; a process cannot
 * send a signal as the terminal. */
static int sessions(void) {
    CHECK(catch_winch() == 0);
    winches = 0;
    CHECK(kill(getpid(), SIGWINCH) == 0);
    CHECK(winches == 1); /* Positive control of the foreign target. */
    winches = 0;
    CHECK(stafeto_probe_tty_signal(getpgrp(), SIGTERM) == EPERM);
    errno = 0;
    CHECK(tcgetpgrp(0) == -1 && errno == ENOTTY);
    errno = 0;
    CHECK(tcgetsid(0) == -1 && errno == ENOTTY);
    pid_t a = fork();
    CHECK(a >= 0);
    if (a == 0) _exit(leader(getpgrp()));
    int status = 0;
    CHECK(waitpid(a, &status, 0) == a && WIFEXITED(status));
    int code = WEXITSTATUS(status);
    if (code != 0) say("posix-tty: the leader failed with %d\n", code);
    CHECK(code == 0);
    CHECK(winches == 0);
    sigset_t pending;
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGWINCH) == 0);
    say("posix-tty: sessions ok\n");
    return 0;
}

/* Spawn terminal actions run with the child's attributes and identity.
 * Each child ends before the next acquires; the parent keeps no terminal. */
extern int stafeto_probe_terminal_full_exec(void);
static int terminal_child(int has_terminal, int descriptor, int again) {
    if (geteuid() != 0) return 109;
    if (getsid(0) != getpid()) return 101;
    errno = 0;
    int tty = open("/dev/tty", O_RDWR);
    if (!has_terminal) {
        if (tty != -1 || errno != ENXIO) return 102;
    } else {
        if (tty < 0 || tcgetsid(tty) != getpid()) return 103;
        if (close(tty) != 0) return 104;
    }
    if ((fcntl(5, F_GETFD) >= 0) != descriptor) return 105;
    if (again) {
        if (getuid() == 65534 && stafeto_probe_terminal_full_exec() != 0) return 116;
        execl("/bin/posix-tty", "posix-tty", "terminal-exec", has_terminal ? "1" : "0", descriptor ? "1" : "0", (char *)NULL);
        int error = errno;
        say("posix-tty: terminal exec error %d\n", error); tcdrain(1);
        return 110;
    }
    return 0;
}

extern int stafeto_probe_terminal_fake_start(void);
extern int stafeto_probe_terminal_fake_control(void);
extern unsigned stafeto_probe_terminal_fake_listen(void);
extern int stafeto_probe_terminal_fake_stop(void);
extern void stafeto_probe_terminal_fake_close(void);
static void *fake_terminal(void *unused) {
    (void)unused;
    return (void *)(size_t)stafeto_probe_terminal_fake_listen();
}

static int terminal_spawn_parent(void) {
    CHECK(setsid() == getpid());
    for (int test = 0; test < 8; ++test) {
        posix_spawn_file_actions_t actions;
        posix_spawnattr_t attr;
        CHECK(posix_spawn_file_actions_init(&actions) == 0);
        CHECK(posix_spawnattr_init(&attr) == 0);
        CHECK(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID) == 0); /* SETSID */
        int flags = O_RDWR;
        if (test == 2) flags |= O_NOCTTY;
        if (test == 4) flags |= O_CLOEXEC;
        const char *path = test == 0 ? "/dev/tty" : "/dev/../dev/console";
        if (test == 5) path = "/dev/console/";
        CHECK(posix_spawn_file_actions_addopen(&actions, 5, path, flags, 0) == 0);
        if (test == 1 || test == 7) CHECK(posix_spawn_file_actions_addopen(&actions, 6, "/dev/tty", O_RDWR, 0) == 0);
        if (test == 3) CHECK(posix_spawn_file_actions_addclose(&actions, 5) == 0);
        if (test == 6) for (int i = 0; i < 32; ++i)
            CHECK(posix_spawn_file_actions_addopen(&actions, 5, "/dev/console", O_RDWR, 0) == 0);
        char *args[] = {"posix-tty", "terminal-child", test == 2 ? "0" : "1",
            test == 3 || test == 4 ? "0" : "1", NULL};
        char *env[] = {NULL};
        pthread_t listener;
        if (test == 7) {
            CHECK(setuid(65534) == 0 && geteuid() == 65534);
            CHECK(stafeto_probe_terminal_fake_start() == 0);
            CHECK(pthread_create(&listener, NULL, fake_terminal, NULL) == 0);
            CHECK(stafeto_probe_terminal_fake_control() == 0); /* Positive control. */
        }
        pid_t child;
        int error = posix_spawn(&child, test == 7 ? "/bin/posix-tty-suid" : "/bin/posix-tty", &actions, &attr, args, env);
        if (test == 0) CHECK(error == ENXIO);
        else if (test == 5) CHECK(error == ENOTDIR);
        else if (test == 6) CHECK(error == EMFILE);
        else {
            CHECK(error == 0);
            int status;
            CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
            if (WEXITSTATUS(status)) say("posix-tty: terminal child failed %d\n", WEXITSTATUS(status));
            CHECK(WEXITSTATUS(status) == 0);
        }
        if (test == 7) {
            CHECK(stafeto_probe_terminal_fake_stop() == 0);
            void *received = NULL;
            CHECK(pthread_join(listener, &received) == 0);
            CHECK((size_t)received == 1); /* Only our positive control. */
            stafeto_probe_terminal_fake_close();
        }
        CHECK(posix_spawn_file_actions_destroy(&actions) == 0);
        CHECK(posix_spawnattr_destroy(&attr) == 0);
        errno = 0;
        CHECK(open("/dev/tty", O_RDWR) == -1 && errno == ENXIO);
        errno = 0;
        CHECK(tcgetsid(0) == -1 && errno == ENOTTY);
    }
    return 0;
}

static int spawn_terminal_actions(void) {
    pid_t parent = fork();
    CHECK(parent >= 0);
    if (parent == 0) _exit(terminal_spawn_parent());
    int status;
    CHECK(waitpid(parent, &status, 0) == parent && WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
    say("posix-tty: child terminal actions ok\n");
    return 0;
}

/* The survivor receives permission to inspect only after the outer
 * process has reaped the leader. Pipes establish both dependencies. */
static int departed_leader(void) {
    int ready[2], go[2], result[2];
    CHECK(pipe(ready) == 0 && pipe(go) == 0 && pipe(result) == 0);
    pid_t leader_pid = fork();
    CHECK(leader_pid >= 0);
    if (leader_pid == 0) {
        if (setsid() != getpid()) _exit(111);
        int fd = open("/dev/console", O_RDWR);
        if (fd < 0 || open("/dev/tty", O_RDWR) < 0) _exit(112);
        int installed[2];
        if (pipe(installed) != 0) _exit(136);
        pid_t survivor = fork();
        if (survivor < 0) _exit(113);
        if (survivor == 0) {
            hups = 0;
            if (signal(SIGHUP, on_hup) == SIG_ERR || write(installed[1], "i", 1) != 1) _exit(137);
            char byte;
            if (write(ready[1], "r", 1) != 1 || read(go[0], &byte, 1) != 1) _exit(114);
            errno = 0;
            int ok = open("/dev/tty", O_RDWR) == -1 && errno == ENXIO;
            errno = 0;
            ok &= tcgetsid(fd) == -1 && errno == ENOTTY;
            ok &= hups == 1;
            if (write(result[1], ok ? "y" : "n", 1) != 1) _exit(115);
            _exit(0);
        }
        char installed_byte;
        if (read(installed[0], &installed_byte, 1) != 1) _exit(138);
        _exit(0);
    }
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && byte == 'r');
    int status;
    CHECK(waitpid(leader_pid, &status, 0) == leader_pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(write(go[1], "g", 1) == 1);
    CHECK(read(result[0], &byte, 1) == 1 && byte == 'y');
    for (int i = 0; i < 2; ++i) {
        CHECK(close(ready[i]) == 0 && close(go[i]) == 0 && close(result[i]) == 0);
    }
    say("posix-tty: departed leader ok\n");
    return 0;
}

/* The role "spawned": `first` is the descriptor the parent left open,
 * `second` the one a file action opened; both are the terminal. */
static int spawned(int first, int second) {
    struct termios t;
    for (int fd = first; fd != -1; fd = fd == first ? second : -1) {
        if (isatty(fd) != 1) return 41;
        char *name = ttyname(fd);
        if (name == NULL || strcmp(name, "/dev/console") != 0) return 42;
        if (tcgetattr(fd, &t) != 0 || t.c_cc[VMIN] != 9) return 43;
    }
    t.c_cc[VMIN] = 11;
    if (tcsetattr(second, TCSANOW, &t) != 0) return 44;
    if (!PUT(first, "posix-tty: spawned child wrote through the inherited descriptor\n")) return 45;
    if (!PUT(second, "posix-tty: spawned child wrote through the descriptor of a file action\n")) return 46;
    return 0;
}

/* The role "run". */
static int run(void) {
    say("posix-tty: begin\n");
    struct termios saved;
    int status;
    if ((status = identity()) != 0) return status;
    if ((status = errors()) != 0) return status;
    if ((status = settings(&saved)) != 0) return status;
    if ((status = raw_and_canonical(&saved)) != 0) return status;
    if ((status = flushing(&saved)) != 0) return status;
    if ((status = output()) != 0) return status;
    if ((status = names(&saved)) != 0) return status;
    if ((status = spawn_terminal_actions()) != 0) return status;
    if ((status = sessions()) != 0) return status;
    if ((status = departed_leader()) != 0) return status;
    say("posix-tty: ok\n");
    return 0;
}

#ifdef STAFETO_QUIET_CONTROL
#include "quiet.c"
#endif

int main(int argc, char **argv) {
#ifdef STAFETO_QUIET_CONTROL
    if (argc == 2 && strcmp(argv[1], "quiet-run") == 0) return quiet_run();
    if (argc == 1) {
        char *args[] = {"posix-tty", "quiet-run", NULL};
        char *env[] = {NULL};
        pid_t pid;
        CHECK(posix_spawn(&pid, "/bin/posix-tty", NULL, NULL, args, env) == 0);
        int status;
        CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
        return WEXITSTATUS(status);
    }
#endif
    if (argc == 4 && strcmp(argv[1], "terminal-child") == 0) return terminal_child(atoi(argv[2]), atoi(argv[3]), 1);
    if (argc == 4 && strcmp(argv[1], "terminal-exec") == 0) return terminal_child(atoi(argv[2]), atoi(argv[3]), 0);
    if (argc == 4 && strcmp(argv[1], "spawned") == 0) return spawned(atoi(argv[2]), atoi(argv[3]));
    if (argc == 2 && strcmp(argv[1], "run") == 0) return run();
    char *args[] = {"posix-tty", "run", NULL};
    char *no_environment[] = {NULL};
    pid_t child;
    int error = posix_spawn(&child, "/bin/posix-tty", NULL, NULL, args, no_environment);
    if (error != 0) { say("posix-tty: launcher spawn error %d\n", error); tcdrain(1); return 10; }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 11;
    return WEXITSTATUS(status);
}
