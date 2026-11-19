/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The probe of the window library (<stafeto/window.h>) against the
 * composition service, in a static program. Built with -fno-builtin; every
 * result is compared.
 *
 * Started by init, the program starts its own file once (/bin/posix-window
 * run), the copy that can fork. That copy describes the screen, makes a
 * window of 200 by 100 points with two buffers at (100, 50), draws a
 * pattern, posts it, waits for the frame, and prints the CRC-32 of the
 * screen it should show (the host compares it with QEMU's screenshot). It
 * posts the second buffer with one rectangle changed (CRC again), then the
 * first with five rectangles that merge into their bounding box and bring
 * the first picture back (the same CRC as the first). The bit of each
 * replaced buffer frees it, the events are the focus events, a forked child
 * has no window, a signal ends a wait with EINTR, close ends the window and
 * a new one can be made.
 */

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <stafeto/window.h>

extern char **environ;

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            printf("posix-window: check failed at line %d: %s (errno %d)\n", __LINE__, \
                   #cond, errno);                                                    \
            return 20;                                                               \
        }                                                                            \
    } while (0)

#define SCREEN_W 640
#define SCREEN_H 400
#define WIN_X 100
#define WIN_Y 50
#define WIN_W 200
#define WIN_H 100
#define MARK 0x00FF8000u
#define SECOND 1000000000ull
#define WITHIN (60 * SECOND)

/* The marked rectangle of the second buffer, in window coordinates. */
static const struct stafeto_rect CHANGED = {20, 10, 40, 30};

static uint32_t crc_table[256];

static void crc_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_table[i] = c;
    }
}

static uint32_t crc_byte(uint32_t crc, uint8_t b) {
    return crc_table[(crc ^ b) & 0xFF] ^ (crc >> 8);
}

/* The pattern of the window's points. */
static uint32_t pattern(int x, int y) {
    uint32_t r = (uint32_t)(x * 255 / (WIN_W - 1));
    uint32_t g = (uint32_t)(y * 255 / (WIN_H - 1));
    uint32_t b = (uint32_t)((x ^ y) & 0xFF);
    return r << 16 | g << 8 | b;
}

static int in_changed(int x, int y) {
    return x >= CHANGED.x && x < CHANGED.x + CHANGED.w && y >= CHANGED.y &&
           y < CHANGED.y + CHANGED.h;
}

static uint32_t point_of(int marked, int x, int y) {
    return marked && in_changed(x, y) ? MARK : pattern(x, y);
}

/* The CRC-32 of the colours of the screen with the window (marked or not)
 * over black, as the host takes it from a screenshot: R, G, B of each
 * point, by rows. */
static uint32_t screen_crc(int marked) {
    uint32_t crc = 0xFFFFFFFFu;
    for (int y = 0; y < SCREEN_H; y++) {
        for (int x = 0; x < SCREEN_W; x++) {
            uint32_t p = 0;
            if (x >= WIN_X && x < WIN_X + WIN_W && y >= WIN_Y && y < WIN_Y + WIN_H)
                p = point_of(marked, x - WIN_X, y - WIN_Y);
            crc = crc_byte(crc, (uint8_t)(p >> 16));
            crc = crc_byte(crc, (uint8_t)(p >> 8));
            crc = crc_byte(crc, (uint8_t)p);
        }
    }
    return ~crc;
}

/* The line the host compares with its screenshot, and the pause it takes
 * the shot in. */
static void snapshot(const char *what, uint32_t crc) {
    struct timespec pause = {2, 500000000};
    printf("posix-window: %s crc %08x\n", what, crc);
    fflush(stdout);
    nanosleep(&pause, NULL);
}

/* The first buffer's points carry 0xFF in their top byte, which XRGB8888
 * ignores: the CRC above takes R, G and B alone, as the host does over the
 * screenshot, so the screen of the first buffer and of the second (top byte
 * 0) must agree wherever they hold the same colours. */
static void draw(const struct stafeto_window *w, unsigned k, int marked) {
    uint32_t *p = (uint32_t *)w->pixels[k];
    uint32_t words = w->stride / 4;
    uint32_t top = k == 0 ? 0xFF000000u : 0;
    for (int y = 0; y < WIN_H; y++)
        for (int x = 0; x < WIN_W; x++)
            p[(uint32_t)y * words + (uint32_t)x] = top | point_of(marked, x, y);
}

/* Waits until every buffer of `mask` is free by the library's account,
 * collecting the bits that came. The wait is made first, with no time to
 * wait: a post that returned already took the bits that waited on the
 * channel (the frame can end before the post returns), and it keeps them
 * for the next wait, which is where the program sees them. The mask alone
 * would say "free" and leave those bits uncollected. */
static int wait_free(uint32_t mask, uint32_t *all) {
    uint32_t bits = 0;
    if (stafeto_window_wait(0, 0, &bits) == 0) {
        if (all) *all |= bits;
    } else if (errno != ETIMEDOUT) {
        return -1;
    }
    for (int i = 0; i < 600; i++) {
        if ((stafeto_window_free_buffers(0) & mask) == mask) return 0;
        bits = 0;
        if (stafeto_window_wait(0, SECOND / 10, &bits) == 0) {
            if (all) *all |= bits;
        } else if (errno != ETIMEDOUT) {
            return -1;
        }
    }
    return -1;
}

static volatile sig_atomic_t usr1;
static void on_usr1(int sig) {
    (void)sig;
    usr1 = 1;
}

/* A forked child: no window, whatever the parent has. */
static int child_without_window(void) {
    struct stafeto_window_event e[2];
    uint32_t bits = 0;
    errno = 0;
    if (stafeto_window_post(0, 0, NULL, 0) != -1 || errno != EBADF) return 40;
    if (stafeto_window_free_buffers(0) != 0) return 41;
    errno = 0;
    if (stafeto_window_wait(0, 0, &bits) != -1 || errno != EBADF) return 42;
    errno = 0;
    if (stafeto_window_events(0, e, 2, NULL) != -1 || errno != EBADF) return 43;
    errno = 0;
    if (stafeto_window_close(0) != -1 || errno != EBADF) return 44;
    /* The parent's signal comes while it waits: sent again every 200 ms
     * (the parent kills this child once a wait ended with EINTR), at most 150
     * times. */
    for (int i = 0; i < 150; i++) {
        struct timespec later = {0, 200000000};
        nanosleep(&later, NULL);
        if (kill(getppid(), SIGUSR1) != 0) return 45;
    }
    return 0;
}

static int setup_and_refusals(struct stafeto_window *w) {
    struct stafeto_screen s;
    memset(&s, 0xAA, sizeof s);
    CHECK(stafeto_screen_describe(&s) == 0);
    CHECK(s.width == SCREEN_W && s.height == SCREEN_H && s.format == STAFETO_WINDOW_XRGB8888);
    CHECK(s.flags == 0 && s.reserved[0] == 0 && s.reserved[3] == 0);
    errno = 0;
    CHECK(stafeto_screen_describe(NULL) == -1 && errno == EINVAL);
    /* No window yet. */
    errno = 0;
    CHECK(stafeto_window_post(0, 0, NULL, 0) == -1 && errno == EBADF);
    CHECK(stafeto_window_free_buffers(0) == 0);
    errno = 0;
    CHECK(stafeto_window_close(0) == -1 && errno == EBADF);
    /* Bad arguments leave nothing behind. */
    errno = 0;
    CHECK(stafeto_window_open(0, 0, 10, 10, 1, 2, 0, NULL) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_window_open(0, 0, 10, 10, 1, 0, 0, w) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_window_open(0, 0, 10, 10, 1, 4, 0, w) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_window_open(0, 0, 10, 10, 2, 2, 0, w) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_window_open(0, 0, 10, 10, 1, 2, 1, w) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_window_open(500, 0, 200, 10, 1, 2, 0, w) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_window_open(0, 0, 0, 10, 1, 2, 0, w) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_window_open(-1, 0, 10, 10, 1, 2, 0, w) == -1 && errno == EINVAL);
    CHECK(stafeto_window_free_buffers(0) == 0);
    printf("posix-window: the screen is described, no window yet, and bad arguments leave nothing\n");

    memset(w, 0xAA, sizeof *w);
    CHECK(stafeto_window_open(WIN_X, WIN_Y, WIN_W, WIN_H, STAFETO_WINDOW_XRGB8888, 2, 0, w) == 0);
    CHECK(w->width == WIN_W && w->height == WIN_H && w->stride == WIN_W * 4);
    CHECK(w->format == STAFETO_WINDOW_XRGB8888 && w->buffers == 2 && w->reserved == 0);
    CHECK(w->pixels[0] != NULL && w->pixels[1] != NULL && w->pixels[0] != w->pixels[1]);
    CHECK(w->pixels[2] == NULL);
    CHECK(stafeto_window_free_buffers(0) == (STAFETO_WINDOW_BUFFER(0) | STAFETO_WINDOW_BUFFER(1)));
    for (unsigned k = 0; k < 2; k++) {
        const uint32_t *p = (const uint32_t *)w->pixels[k];
        CHECK(p[0] == 0 && p[(WIN_H * WIN_W) - 1] == 0);
    }
    errno = 0;
    CHECK(stafeto_window_open(WIN_X, WIN_Y, 10, 10, 1, 1, 0, w) == -1 && errno == EBUSY);
    printf("posix-window: a window of 200 by 100 with two zeroed buffers, a second open is EBUSY\n");

    /* Post refusals: nothing goes to the service. */
    errno = 0;
    CHECK(stafeto_window_post(0, 2, NULL, 0) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_window_post(1, 0, NULL, 0) == -1 && errno == EBADF);
    {
        struct stafeto_rect wide = {0, 0, WIN_W + 1, 1};
        struct stafeto_rect empty = {0, 0, 0, 5};
        errno = 0;
        CHECK(stafeto_window_post(0, 0, &wide, 1) == -1 && errno == EINVAL);
        errno = 0;
        CHECK(stafeto_window_post(0, 0, &empty, 1) == -1 && errno == EINVAL);
        errno = 0;
        CHECK(stafeto_window_post(0, 0, NULL, 1) == -1 && errno == EINVAL);
    }
    CHECK(stafeto_window_free_buffers(0) == 3);
    return 0;
}

static int run_role(void) {
    struct stafeto_window w;
    struct stafeto_window_event ev[STAFETO_WINDOW_EVENTS_MAX];
    uint32_t bits = 0, all = 0, flags = 99;
    int n;

    crc_init();
    CHECK(setup_and_refusals(&w) == 0);

    /* The first picture. */
    draw(&w, 0, 0);
    draw(&w, 1, 1);
    CHECK(stafeto_window_post(0, 0, NULL, 0) == 0);
    CHECK(stafeto_window_free_buffers(0) == STAFETO_WINDOW_BUFFER(1));
    errno = 0;
    CHECK(stafeto_window_post(0, 0, NULL, 0) == -1 && errno == EBUSY);
    printf("posix-window: post refuses a wrong buffer, window or rectangle, and a buffer that is out\n");
    CHECK(stafeto_window_shown(0, WITHIN) == 0);
    snapshot("window", screen_crc(0));

    /* The second buffer with one rectangle: the frame frees the first. */
    CHECK(stafeto_window_post(0, 1, &CHANGED, 1) == 0);
    CHECK(stafeto_window_shown(0, WITHIN) == 0);
    CHECK(wait_free(STAFETO_WINDOW_BUFFER(0), &all) == 0);
    if (!(all & STAFETO_WINDOW_BUFFER(0)))
        printf("posix-window: the bits that came: %x, the free buffers: %x\n", (unsigned)all,
               (unsigned)stafeto_window_free_buffers(0));
    CHECK(all & STAFETO_WINDOW_BUFFER(0));
    CHECK(stafeto_window_free_buffers(0) == STAFETO_WINDOW_BUFFER(0));
    printf("posix-window: the frame is shown and its bit frees the replaced buffer\n");
    snapshot("partial", screen_crc(1));

    /* Five rectangles merge into their bounding box, which is the marked
     * place: the first picture comes back. */
    {
        struct stafeto_rect five[5] = {
            {20, 10, 10, 30}, {30, 10, 10, 30}, {40, 10, 10, 30}, {50, 10, 10, 30}, {20, 10, 40, 30},
        };
        CHECK(stafeto_window_post(0, 0, five, 5) == 0);
    }
    CHECK(stafeto_window_shown(0, WITHIN) == 0);
    CHECK(wait_free(STAFETO_WINDOW_BUFFER(1), NULL) == 0);
    printf("posix-window: five rectangles merge into their bounding box\n");
    snapshot("merged", screen_crc(0));

    /* The events: the focus the window got, then none. */
    errno = 0;
    CHECK(stafeto_window_events(0, NULL, 4, &flags) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_window_events(0, ev, 0, &flags) == -1 && errno == EINVAL);
    n = stafeto_window_events(0, ev, 1000, &flags);
    CHECK(n >= 0 && n <= STAFETO_WINDOW_EVENTS_MAX);
    CHECK(flags == 0);
    for (int i = 0; i < n; i++)
        CHECK(ev[i].kind == STAFETO_WINDOW_EVENT_FOCUS_IN || ev[i].kind == STAFETO_WINDOW_EVENT_FOCUS_OUT);
    n = stafeto_window_events(0, ev, STAFETO_WINDOW_EVENTS_MAX, &flags);
    CHECK(n == 0 && flags == 0);
    printf("posix-window: the events are the focus events only and the ring is empty after\n");

    /* Nothing waits on the channel now. */
    for (int i = 0; i < 20; i++) {
        if (stafeto_window_wait(0, 0, &bits) == -1 && errno == ETIMEDOUT) break;
    }
    errno = 0;
    CHECK(stafeto_window_wait(0, 0, &bits) == -1 && errno == ETIMEDOUT);

    /* A forked child has no window; its signal ends the parent's wait. */
    {
        struct sigaction act;
        int status = 0, ended = 0;
        pid_t pid;
        /* The buffer on the screen (the merged post's) is the service's until
         * a later post replaces it: only the other one is free, and no fork or
         * signal changes that. */
        const uint32_t before = stafeto_window_free_buffers(0);
        CHECK(before == STAFETO_WINDOW_BUFFER(1));
        memset(&act, 0, sizeof act);
        act.sa_handler = on_usr1;
        /* SA_RESTART: a wait ends with EINTR whatever it says. */
        act.sa_flags = SA_RESTART;
        sigemptyset(&act.sa_mask);
        CHECK(sigaction(SIGUSR1, &act, NULL) == 0);
        pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) _exit(child_without_window());
        /* At most 10 waits of 3 s: a child that failed its checks exits at once
         * and sends nothing, and the loop ends. */
        for (int i = 0; i < 10 && !ended; i++) {
            errno = 0;
            if (stafeto_window_wait(0, 3 * SECOND, &bits) == -1 && errno == EINTR) ended = 1;
            if (waitpid(pid, &status, WNOHANG) == pid) {
                pid = 0;
                break;
            }
        }
        if (pid != 0) {
            /* Still looping its signals: it passed its checks. */
            CHECK(kill(pid, SIGKILL) == 0);
            CHECK(waitpid(pid, &status, 0) == pid);
            CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        } else {
            /* It exited by itself: its code says which check failed. */
            printf("posix-window: the child ended by itself, status %d\n",
                   WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            return 21;
        }
        CHECK(ended && usr1 == 1);
        CHECK(stafeto_window_free_buffers(0) == before);
    }
    printf("posix-window: a forked child has no window, and a signal ends a wait with EINTR\n");

    /* Close ends the window; a new one opens, so nothing of the first remains. */
    CHECK(stafeto_window_close(0) == 0);
    errno = 0;
    CHECK(stafeto_window_close(0) == -1 && errno == EBADF);
    errno = 0;
    CHECK(stafeto_window_post(0, 0, NULL, 0) == -1 && errno == EBADF);
    CHECK(stafeto_window_free_buffers(0) == 0);
    CHECK(stafeto_window_open(0, 0, 50, 40, STAFETO_WINDOW_XRGB8888, 1, 0, &w) == 0);
    CHECK(w.buffers == 1 && w.stride == 200 && w.pixels[1] == NULL);
    CHECK(stafeto_window_close(0) == 0);
    printf("posix-window: close ends the window, and a new one opens\n");
    return 0;
}

static int first(void) {
    char *argv[] = {"posix-window", "run", NULL};
    pid_t pid = 0;
    int status = 0;
    CHECK(posix_spawn(&pid, "/bin/posix-window", NULL, NULL, argv, environ) == 0);
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "run") == 0) return run_role();
    int status = first();
    if (status == 0) printf("posix-window: ok\n");
    return status;
}
