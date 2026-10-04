/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

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
