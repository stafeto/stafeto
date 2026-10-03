/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

int stafeto_watch_start(const uint32_t *, const uint32_t *, uint32_t, uint64_t *, uint32_t *);
int stafeto_watch_keyed(uint32_t, uint64_t, uint32_t, uint32_t, uint32_t *, uint32_t);
int stafeto_watch_bit(uint64_t);
int stafeto_watch_full_pipe(uint32_t, uint32_t);
int stafeto_watch_full_tty(uint32_t, uint32_t);
void stafeto_watch_close_channel(void);
int stafeto_watch_stats(uint32_t, uint32_t);
#define CHECK(c) do { if (!(c)) { printf("posix-poll: line %d: %s errno %d\n", __LINE__, #c, errno); fflush(stdout); return 20; } } while (0)
#define IN 1u
#define OUT 4u
#define HUP 16u

static int service_watches(void) {
    int first[2], second[2];
    CHECK(pipe(first) == 0 && pipe(second) == 0);
    uint32_t fds[32], events[32], ready[32];
    uint64_t key, keys[8];
    for (unsigned i = 0; i < 32; i++) { fds[i] = first[0]; events[i] = i % 2 ? 0 : IN; }
    CHECK(stafeto_watch_start(fds, events, 32, &key, ready) == 1 && key != 0);
    CHECK(stafeto_watch_keyed(first[0], key, 0, 1, ready, 32) == 1);
    CHECK(write(first[1], "x", 1) == 1);
    CHECK(stafeto_watch_bit(key) == 0);
    CHECK(stafeto_watch_keyed(first[0], key, 0, 0, ready, 32) == 0);
    for (unsigned i = 0; i < 32; i++) CHECK(ready[i] == (i % 2 ? 0 : IN));
    CHECK(close(first[1]) == 0);
    CHECK(stafeto_watch_keyed(first[0], key, 1, 0, ready, 32) == 0);
    for (unsigned i = 0; i < 32; i++) CHECK(ready[i] == (i % 2 ? HUP : IN | HUP));
    CHECK(stafeto_watch_keyed(first[0], key, 1, 0, ready, 32) < 0);
    char byte;
    CHECK(read(first[0], &byte, 1) == 1 && byte == 'x');
    CHECK(close(first[0]) == 0);

    fds[0] = second[0]; events[0] = IN;
    for (unsigned i = 0; i < 8; i++) CHECK(stafeto_watch_start(fds, events, 1, &keys[i], ready) == 1);
    CHECK(stafeto_watch_start(fds, events, 1, &key, ready) == -EAGAIN);
    CHECK(pipe(first) == 0);
    fds[0] = first[0]; fds[1] = second[0]; events[1] = IN;
    CHECK(stafeto_watch_start(fds, events, 2, &key, ready) == -EAGAIN);
    fds[0] = first[0];
    uint64_t rollback[8];
    for (unsigned i = 0; i < 8; i++) CHECK(stafeto_watch_start(fds, events, 1, &rollback[i], ready) == 1);
    CHECK(stafeto_watch_start(fds, events, 1, &key, ready) == -EAGAIN);
    for (unsigned i = 0; i < 8; i++) {
        CHECK(stafeto_watch_keyed(first[0], rollback[i], 1, 0, ready, 1) == 0);
        CHECK(ready[0] == 0);
        CHECK(stafeto_watch_keyed(second[0], keys[i], 1, 0, ready, 1) == 0);
    }
    CHECK(stafeto_watch_full_pipe(first[0], 0) == 0);
    CHECK(stafeto_watch_full_pipe(first[0], 1) == 0);
    CHECK(close(first[0]) == 0 && close(first[1]) == 0);
    CHECK(close(second[0]) == 0 && close(second[1]) == 0);

    int tty = open("/dev/console", O_RDWR | O_NOCTTY);
    CHECK(tty >= 0);
    struct termios old, raw;
    CHECK(tcgetattr(tty, &old) == 0);
    raw = old; raw.c_lflag &= ~ICANON; raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 1;
    CHECK(tcsetattr(tty, TCSANOW, &raw) == 0);
    for (unsigned i = 0; i < 32; i++) { fds[i] = tty; events[i] = IN; }
    CHECK(stafeto_watch_start(fds, events, 32, &key, ready) == 1);
    CHECK(stafeto_watch_keyed(tty, key, 0, 1, ready, 32) == 1);
    raw.c_cc[VTIME] = 0;
    CHECK(tcsetattr(tty, TCSANOW, &raw) == 0);
    CHECK(stafeto_watch_bit(key) == 0);
    CHECK(stafeto_watch_keyed(tty, key, 0, 0, ready, 32) == 0);
    CHECK(stafeto_watch_keyed(tty, key, 1, 0, ready, 32) == 0);
    for (unsigned i = 0; i < 32; i++) CHECK(ready[i] == IN);
    CHECK(stafeto_watch_full_tty(tty, 0) == 0);
    CHECK(stafeto_watch_full_tty(tty, 1) == 0);
    CHECK(tcsetattr(tty, TCSANOW, &old) == 0);
    CHECK(close(tty) == 0);
    return 0;
}

int main(void) {
    int result = service_watches();
    if (result != 0) return result;
    int ends[2], tty = open("/dev/console", O_RDWR | O_NOCTTY);
    CHECK(tty >= 0 && pipe(ends) == 0);
    CHECK(stafeto_watch_stats(ends[0], tty) == 0);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0 && close(tty) == 0);
    stafeto_watch_close_channel();
    printf("posix-poll: ok\n");
    fflush(stdout);
    return 0;
}
