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
 * /dev/tty open the terminal, which fork carries to a child; stat says a
 * character device; the terminal functions give EINVAL, ENOTTY and EBADF
 * where POSIX does.
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
#include <spawn.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
    int tty = open("/dev/tty", O_RDWR);
    CHECK(tty > 2 && isatty(tty) == 1 && close(tty) == 0);
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
    CHECK(posix_spawn(&spawned, "/bin/posix-tty", &actions, NULL, args, no_environment) == 0);
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
    say("posix-tty: ok\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "spawned") == 0) return spawned(atoi(argv[2]), atoi(argv[3]));
    if (argc == 2 && strcmp(argv[1], "run") == 0) return run();
    char *args[] = {"posix-tty", "run", NULL};
    char *no_environment[] = {NULL};
    pid_t child;
    if (posix_spawn(&child, "/bin/posix-tty", NULL, NULL, args, no_environment) != 0) return 10;
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 11;
    return WEXITSTATUS(status);
}
