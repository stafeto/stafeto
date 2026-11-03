/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The probe of the screen and the keys of libc.so (sub-project 3, part 3b;
 * <stafeto/display.h>), a dynamic program that tests/display-run starts. The
 * role is argv[1]:
 *
 *   main    open (the refusals before it, the description, the same
 *           description again, a cleared buffer), a pattern and a
 *           rectangle shown (xtask compares QEMU's screenshots with the
 *           CRC-32 printed here), the keys xtask sends through the monitor,
 *           the refusals of flush, a forked child (EBUSY, and SIGSEGV at the
 *           parent's buffer), then exec of the second role;
 *   second  the screen after exec: opens at once (the image that exec took
 *           the screen from is gone), a cleared buffer; ends with the screen
 *           open, which the end of the process gives back;
 *   third   opens again (the exit gave it back), closes (the buffer is gone,
 *           the calls say EBADF), opens again, spawns the program that kills
 *           the display service, and finds every call refused: flush and
 *           keys ENODEV, close fine, open ENODEV;
 *   nogpu   an image without a display service: ENODEV from open, EBADF from
 *           the rest.
 *
 * Built with -fno-builtin; every result is compared.
 */
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <stafeto/display.h>

extern char **environ;

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            printf("display-probe: check failed at line %d: %s (errno %d)\n", __LINE__, \
                   #cond, errno);                                                    \
            return 20;                                                               \
        }                                                                            \
    } while (0)

#define FAILS(call, code) (((call) == -1) && errno == (code))

enum { WIDTH = 640, HEIGHT = 400, STRIDE = 2560, KEY_A = 30, KEY_B = 48 };

static void pause_10ms(void) {
    struct timespec t = {0, 10000000};
    nanosleep(&t, NULL);
}

static uint32_t crc_table[256];

static void crc_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_table[i] = c;
    }
}

/* The CRC-32 of the red, green and blue bytes of the points in order, as
 * xtask takes it from a screenshot. */
static uint32_t screen_crc(const volatile uint32_t *p) {
    uint32_t crc = 0xFFFFFFFFu;
    for (int i = 0; i < WIDTH * HEIGHT; i++) {
        uint32_t v = p[i];
        uint8_t rgb[3] = {(uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
        for (int k = 0; k < 3; k++) crc = crc_table[(crc ^ rgb[k]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

static int all_zero(const volatile uint32_t *p) {
    for (int i = 0; i < STRIDE / 4 * HEIGHT; i++)
        if (p[i] != 0) return 0;
    return 1;
}

/* The keys: up to `want` events within 30 s, one call asking for `max`
 * at the most. */
static int read_keys(struct stafeto_key *out, int want, int max) {
    int have = 0;
    for (int waited = 0; have < want && waited < 3000; waited++) {
        int n = stafeto_input_read(out + have, have + max > want ? want - have : max);
        if (n < 0) return -1;
        have += n;
        if (n == 0) pause_10ms();
    }
    return have;
}

static int is_key(const struct stafeto_key *k, int code, int value) {
    return k->type == 1 && k->code == code && k->value == value;
}

static int description(const struct stafeto_display *d) {
    return d->width == WIDTH && d->height == HEIGHT && d->stride == STRIDE &&
           d->format == STAFETO_FORMAT_XRGB8888 && d->pixels != NULL &&
           ((uintptr_t)d->pixels & 4095) == 0;
}

static int run_role(const char *role, int *status) {
    char *argv[] = {"display-probe", (char *)role, NULL};
    pid_t pid = 0;
    if (posix_spawn(&pid, "/bin/display-probe", NULL, NULL, argv, environ) != 0) return -1;
    if (waitpid(pid, status, 0) != pid) return -1;
    return 0;
}

static int main_role(void) {
    struct stafeto_display d, again;
    struct stafeto_key keys[8];
    crc_init();
    /* Before the open: nothing is open, and the arguments are checked. */
    errno = 0;
    CHECK(FAILS(stafeto_display_flush(0, 0, 1, 1), EBADF));
    errno = 0;
    CHECK(FAILS(stafeto_input_read(keys, 8), EBADF));
    errno = 0;
    CHECK(FAILS(stafeto_display_close(), EBADF));
    errno = 0;
    CHECK(FAILS(stafeto_display_open(NULL), EINVAL));
    printf("display-probe: before the open the calls are EBADF, a null description EINVAL\n");

    CHECK(stafeto_display_open(&d) == 0);
    CHECK(description(&d));
    volatile uint32_t *p = d.pixels;
    CHECK(all_zero(p));
    memset(&again, 0xAA, sizeof again);
    CHECK(stafeto_display_open(&again) == 0);
    CHECK(memcmp(&d, &again, sizeof d) == 0);
    printf("display-probe: the screen is 640x400, XRGB8888, a cleared buffer; a second open gives the same\n");

    errno = 0;
    CHECK(FAILS(stafeto_input_read(NULL, 8), EINVAL));
    errno = 0;
    CHECK(FAILS(stafeto_input_read(keys, 0), EINVAL));
    CHECK(stafeto_input_read(keys, 8) == 0);
    printf("display-probe: with no key pressed a read gives 0\n");

    /* The pattern, shown whole. */
    for (int y = 0; y < HEIGHT; y++)
        for (int x = 0; x < WIDTH; x++)
            p[y * (STRIDE / 4) + x] = (uint32_t)((x * 255 / (WIDTH - 1)) << 16 |
                                                 (y * 255 / (HEIGHT - 1)) << 8 | ((x ^ y) & 0xFF));
    CHECK(stafeto_display_flush(0, 0, WIDTH, HEIGHT) == 0);
    printf("display-probe: pattern crc %08x\n", screen_crc(p));
    /* xtask photographs the screen and presses a. */
    CHECK(read_keys(keys, 2, 8) == 2);
    CHECK(is_key(&keys[0], KEY_A, 1) && is_key(&keys[1], KEY_A, 0));
    printf("display-probe: the keys a down and a up came\n");

    /* A rectangle in another colour, shown alone. */
    for (int y = 50; y < 150; y++)
        for (int x = 100; x < 300; x++) p[y * (STRIDE / 4) + x] = 0x00FF8000u;
    CHECK(stafeto_display_flush(100, 50, 200, 100) == 0);
    printf("display-probe: partial crc %08x\n", screen_crc(p));
    /* xtask photographs it and presses b; the read asks for one key a call. */
    CHECK(read_keys(keys, 2, 1) == 2);
    CHECK(is_key(&keys[0], KEY_B, 1) && is_key(&keys[1], KEY_B, 0));
    printf("display-probe: the keys b down and b up came one by one\n");

    errno = 0;
    CHECK(FAILS(stafeto_display_flush(0, 0, 0, 1), EINVAL));
    errno = 0;
    CHECK(FAILS(stafeto_display_flush(0, 0, 1, 0), EINVAL));
    errno = 0;
    CHECK(FAILS(stafeto_display_flush(639, 0, 2, 1), EINVAL));
    errno = 0;
    CHECK(FAILS(stafeto_display_flush(0, 399, 1, 2), EINVAL));
    errno = 0;
    CHECK(FAILS(stafeto_display_flush(-1, 0, 1, 1), EINVAL));
    errno = 0;
    CHECK(FAILS(stafeto_display_flush(2, 0, INT_MAX, 1), EINVAL));
    errno = 0;
    CHECK(FAILS(stafeto_display_flush(0, 0, WIDTH + 1, HEIGHT), EINVAL));
    CHECK(stafeto_display_flush(WIDTH - 1, HEIGHT - 1, 1, 1) == 0);
    printf("display-probe: rectangles outside the screen are EINVAL\n");

    /* A forked child: no screen, no buffer. */
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        struct stafeto_display c;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        errno = 0;
        if (!FAILS(stafeto_display_open(&c), EBUSY)) _exit(30);
        /* BUSY is answered at once: only CLEARING is asked again, 10 ms
         * apart. */
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if ((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 > 200) _exit(34);
        errno = 0;
        if (!FAILS(stafeto_display_flush(0, 0, 1, 1), EBADF)) _exit(31);
        errno = 0;
        if (!FAILS(stafeto_input_read(keys, 1), EBADF)) _exit(32);
        /* The parent's buffer is a hole in the child. */
        (void)*(volatile uint32_t *)d.pixels;
        _exit(33);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
    CHECK(p[60 * (STRIDE / 4) + 120] == 0x00FF8000u);
    printf("display-probe: a forked child gets EBUSY at once and SIGSEGV at the parent's buffer\n");

    /* exec takes the screen back: the second role opens it at once. */
    fflush(stdout);
    execl("/bin/display-probe", "display-probe", "second", (char *)NULL);
    printf("display-probe: check failed: exec (errno %d)\n", errno);
    return 21;
}

static int second_role(void) {
    struct stafeto_display d;
    CHECK(stafeto_display_open(&d) == 0);
    CHECK(description(&d));
    CHECK(all_zero(d.pixels));
    printf("display-probe: after exec the screen opens at once and its buffer is cleared\n");
    /* No close: the end of the process gives the screen back. */
    return 0;
}

static int third_role(void) {
    struct stafeto_display d;
    struct stafeto_key key;
    int status = 0;
    CHECK(stafeto_display_open(&d) == 0);
    CHECK(description(&d));
    CHECK(all_zero(d.pixels));
    printf("display-probe: after the exit of its owner the screen opens, a cleared buffer\n");

    CHECK(stafeto_display_close() == 0);
    errno = 0;
    CHECK(FAILS(stafeto_display_flush(0, 0, 1, 1), EBADF));
    errno = 0;
    CHECK(FAILS(stafeto_input_read(&key, 1), EBADF));
    errno = 0;
    CHECK(FAILS(stafeto_display_close(), EBADF));
    CHECK(stafeto_display_open(&d) == 0);
    CHECK(description(&d));
    CHECK(all_zero(d.pixels));
    printf("display-probe: close takes the buffer away and the screen opens again\n");

    /* The display service ends: every call that goes to it is refused. */
    char *argv[] = {"display-run", "crash", NULL};
    pid_t pid = 0;
    CHECK(posix_spawn(&pid, "/bin/display-run", NULL, NULL, argv, environ) == 0);
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    errno = 0;
    CHECK(FAILS(stafeto_display_flush(0, 0, 1, 1), ENODEV));
    /* The input service takes the focus back when the display service's
     * session with it closes: its own step, a little later. */
    int refused = 0;
    for (int i = 0; i < 300 && !refused; i++) {
        errno = 0;
        if (stafeto_input_read(&key, 1) == -1 && errno == ENODEV) refused = 1;
        else pause_10ms();
    }
    CHECK(refused);
    printf("display-probe: after the display service ended flush and the keys are ENODEV\n");
    CHECK(stafeto_display_close() == 0);
    errno = 0;
    CHECK(FAILS(stafeto_display_open(&d), ENODEV));
    printf("display-probe: close still works and a new open is ENODEV\n");
    return 0;
}

static int nogpu_role(void) {
    struct stafeto_display d;
    struct stafeto_key key;
    errno = 0;
    CHECK(FAILS(stafeto_display_open(&d), ENODEV));
    errno = 0;
    CHECK(FAILS(stafeto_display_flush(0, 0, 1, 1), EBADF));
    errno = 0;
    CHECK(FAILS(stafeto_input_read(&key, 1), EBADF));
    errno = 0;
    CHECK(FAILS(stafeto_display_close(), EBADF));
    printf("display-probe: without a display service open is ENODEV and the rest EBADF\n");
    return 0;
}

int main(int argc, char **argv) {
    const char *role = argc > 1 ? argv[1] : "main";
    int status = 0;
    /* The console is no terminal to relibc: a line goes out when it ends,
     * or xtask would wait for it. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (strcmp(role, "run") == 0) {
        /* The whole probe: the roles one after another, each a process. */
        static const char *const roles[] = {"main", "third"};
        for (unsigned i = 0; i < sizeof roles / sizeof roles[0]; i++) {
            if (run_role(roles[i], &status) != 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                printf("display-probe: failed: the role %s ended with status %#x\n", roles[i], status);
                return 1;
            }
        }
        printf("display-probe: ok\n");
        return 0;
    }
    int rc = 22;
    if (strcmp(role, "main") == 0) rc = main_role();
    else if (strcmp(role, "second") == 0) rc = second_role();
    else if (strcmp(role, "third") == 0) rc = third_role();
    else if (strcmp(role, "nogpu") == 0) {
        rc = nogpu_role();
        if (rc == 0) printf("display-probe: nogpu ok\n");
    }
    return rc;
}
