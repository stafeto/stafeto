// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

/* Included after pty.c's ordinary pair helpers. The parent speaks only
 * through the real PTY master; the child shell owns the slave as ctty. */
struct pty_ash_dialog {
    int master;
    char output[8192];
    size_t length;
};
static const char pty_ash_prompt[] = "PTY-PROMPT> ";

static long long pty_ash_millis(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int pty_ash_line(const struct pty_ash_dialog *d, const char *expected) {
    const char *at = d->output, *end = d->output + d->length;
    size_t n = strlen(expected);
    while (at < end) {
        const char *newline = memchr(at, '\n', (size_t)(end - at));
        if (!newline) return 0;
        const char *last = newline;
        while (last > at && last[-1] == '\r') last--;
        if ((size_t)(last - at) == n && memcmp(at, expected, n) == 0) return 1;
        at = newline + 1;
    }
    return 0;
}

static int pty_ash_receive(struct pty_ash_dialog *d, const char *expected, int line) {
    long long began = pty_ash_millis();
    CHECK(began >= 0);
    for (;;) {
        if (line ? pty_ash_line(d, expected) : strstr(d->output, expected) != NULL) return 0;
        long long remaining = 5000 - (pty_ash_millis() - began);
        if (remaining <= 0) {
            printf("posix-pty: ash expected [%s], received [%s]\n", expected, d->output);
            return 1;
        }
        struct pollfd wait = {d->master, POLLIN, 0};
        int ready = poll(&wait, 1, (int)remaining);
        if (ready < 0 && errno == EINTR) continue;
        CHECK(ready > 0 && !(wait.revents & (POLLERR | POLLHUP | POLLNVAL)));
        CHECK(d->length + 1 < sizeof d->output);
        ssize_t n = read(d->master, d->output + d->length, sizeof d->output - d->length - 1);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        CHECK(n > 0);
        d->length += (size_t)n;
        d->output[d->length] = 0;
    }
}

static int pty_ash_send(struct pty_ash_dialog *d, const char *text) {
    d->length = 0;
    d->output[0] = 0;
    size_t size = strlen(text), sent = 0;
    long long began = pty_ash_millis();
    CHECK(began >= 0);
    while (sent < size) {
        ssize_t n = write(d->master, text + sent, size - sent);
        if (n > 0) { sent += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        CHECK(n < 0 && errno == EAGAIN);
        long long remaining = 5000 - (pty_ash_millis() - began);
        CHECK(remaining > 0);
        struct pollfd wait = {d->master, POLLOUT, 0};
        int ready = poll(&wait, 1, (int)remaining);
        CHECK(ready > 0 && (wait.revents & POLLOUT));
    }
    return 0;
}

static int pty_ash_command(struct pty_ash_dialog *d, const char *command, const char *line) {
    CHECK(pty_ash_send(d, command) == 0);
    CHECK(pty_ash_receive(d, pty_ash_prompt, 0) == 0);
    if (line) CHECK(pty_ash_line(d, line));
    return 0;
}

/* The shell starts this external role by exec. Its ready line confirms
 * that the final executable has entered main before Stop/Ctrl-C. */
static int pty_ash_worker(void) {
    const char ready[] = "PTY-CHILD\n";
    size_t sent = 0;
    while (sent < sizeof ready - 1) {
        ssize_t n = write(STDOUT_FILENO, ready + sent, sizeof ready - 1 - sent);
        if (n < 0 && errno == EINTR) continue;
        CHECK(n > 0);
        sent += (size_t)n;
    }
    for (;;) pause();
}

static int pty_ash_link(void) {
    sigset_t mask;
    CHECK(sigprocmask(SIG_SETMASK, NULL, &mask) == 0);
    printf("PTY-LINK pid %d parent %d sid %d tty-sid %d foreground %d group %d parent-group %d HUP-blocked %d\n", getpid(), getppid(), getsid(0), tcgetsid(0), tcgetpgrp(0), getpgrp(), getpgid(getppid()), sigismember(&mask, SIGHUP));
    return 0;
}

static int pty_ash_dialog(int direct_hup) {
    struct pair p;
    CHECK(make_pair(&p) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (close(p.master) != 0 || close(p.slave) != 0 || setsid() < 0) _exit(60);
        int slave = open(p.name, O_RDWR);
        if (slave < 0 || tcgetsid(slave) != getsid(0)) _exit(61);
        for (int fd = 0; fd <= 2; fd++) if (dup2(slave, fd) != fd) _exit(62);
        if (slave > 2 && close(slave) != 0) _exit(63);
        if (setenv("PATH", "/bin", 1) != 0 || setenv("PS1", pty_ash_prompt, 1) != 0) _exit(64);
        execl("/bin/ash", "ash", "-i", (char *)NULL);
        _exit(65);
    }
    CHECK(close(p.slave) == 0);
    CHECK(fcntl(p.master, F_SETFL, fcntl(p.master, F_GETFL) | O_NONBLOCK) == 0);
    struct pty_ash_dialog d = {.master = p.master, .length = 0};
    CHECK(pty_ash_receive(&d, pty_ash_prompt, 0) == 0);
    CHECK(pty_ash_command(&d, "printf '%s\\n' \"$((6*7))\"\n", "42") == 0);
    CHECK(pty_ash_command(&d, "test 3 -gt 2 && printf 'PTY-TEST\\n'\n", "PTY-TEST") == 0);

    /* This marker comes from the external executable's own main. */
    const char *sleeping = "/bin/posix-pty ash-worker\n";
    CHECK(pty_ash_send(&d, sleeping) == 0);
    CHECK(pty_ash_receive(&d, "PTY-CHILD", 1) == 0);
    CHECK(pty_ash_send(&d, "\003") == 0);
    CHECK(pty_ash_receive(&d, pty_ash_prompt, 0) == 0);
    CHECK(pty_ash_command(&d, "echo $?\n", "130") == 0);

    CHECK(pty_ash_send(&d, sleeping) == 0);
    CHECK(pty_ash_receive(&d, "PTY-CHILD", 1) == 0);
    CHECK(pty_ash_send(&d, "\032") == 0);
    CHECK(pty_ash_receive(&d, pty_ash_prompt, 0) == 0);
    CHECK(strstr(d.output, "Stopped") != NULL);
    CHECK(pty_ash_command(&d, "jobs\n", NULL) == 0);
    CHECK(strstr(d.output, "Stopped") != NULL);
    CHECK(pty_ash_command(&d, "bg\n", NULL) == 0);
    CHECK(pty_ash_command(&d, "jobs\n", NULL) == 0);
    CHECK(strstr(d.output, "Running") != NULL && strstr(d.output, "Stopped") == NULL);
    CHECK(pty_ash_send(&d, "fg\n") == 0);
    CHECK(pty_ash_receive(&d, "ash-worker", 0) == 0);
    CHECK(pause_ms(20) == 0);
    CHECK(pty_ash_send(&d, "\003") == 0);
    CHECK(pty_ash_receive(&d, pty_ash_prompt, 0) == 0);
    CHECK(pty_ash_command(&d, "echo $?\n", "130") == 0);
    CHECK(pty_ash_command(&d, "trap 'exit 79' HUP; echo PTY-HUP-ARMED\n", "PTY-HUP-ARMED") == 0);
    CHECK(pty_ash_command(&d, "echo PTY-SHELL-PID=$$; /bin/posix-pty ash-link\n", NULL) == 0);
    printf("posix-pty: shell link [%s]\n", d.output);
    CHECK(pty_ash_command(&d, "trap\n", NULL) == 0);
    printf("posix-pty: installed shell traps [%s]\n", d.output);
    CHECK(strstr(d.output, "exit 79") != NULL && strstr(d.output, "HUP") != NULL);
    struct termios attributes;
    CHECK(tcgetattr(p.master, &attributes) == 0);
    printf("posix-pty: ash CLOCAL %d, cflag 0x%x\n", !!(attributes.c_cflag & CLOCAL), (unsigned)attributes.c_cflag);
    CHECK(!(attributes.c_cflag & CLOCAL));
    if (direct_hup) CHECK(kill(child, SIGHUP) == 0);
    else CHECK(close(p.master) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    printf("posix-pty: ash disconnect status %d, exited %d code %d signal %d\n", status, WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1, WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 79);
    if (direct_hup) CHECK(close(p.master) == 0);
    printf("posix-pty: ash master Ctrl-C/Ctrl-Z/jobs/bg/fg/HUP via %s ok\n", direct_hup ? "kill" : "master close");
    return 0;
}
