/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The probe of the manager's calls (<stafeto/manager.h>) against the
 * composition service, in a static program built with -fno-builtin. Every
 * result is compared.
 *
 * Init starts the program as the record `desk`, a process of POSIX that has
 * the manager's mark. It subscribes, starts its own file as the client (the
 * role `client`, a child that holds a clone of the manager's session, which
 * has no mark), and drives the client's window:
 *
 *  - the manager hears the client's window (CREATE) and gives it the focus,
 *    reads its title and the kind of its program (TITLE, INFO);
 *  - a window of the manager's own is the client's frame: LINK ties it, MOVE
 *    moves the pair and the list shows both at the same offset; a move that
 *    would put the frame off the screen is refused and nothing moves;
 *  - the host presses a key and moves and clicks a tablet (QEMU's monitor and
 *    QMP) at a point the manager prints, and the client, which has the focus,
 *    says it got them by changing its title;
 *  - CONFIGURE asks for a size, the client answers (SIZE, POST), the manager
 *    hears RESIZED and resizes the frame;
 *  - CLOSE asks the client to close, its window goes (CLOSE) and the frame is
 *    hidden.
 *
 * The client also checks that the clone of the manager's session is refused
 * with EPERM.
 */

#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <stafeto/manager.h>
#include <stafeto/window.h>

extern char **environ;

#define CHECK(cond)                                                                   \
    do {                                                                              \
        if (!(cond)) {                                                                \
            printf("posix-manager: check failed at line %d: %s (errno %d)\n", __LINE__, \
                   #cond, errno);                                                     \
            return 20;                                                                \
        }                                                                             \
    } while (0)

#define MS 1000000ull
#define SECOND (1000 * MS)
#define WITHIN (60 * SECOND)

/* The client's window: at (100, 60), 200 by 100 points, resizable. The frame
 * is 4 points wider on each side and below, and 24 above (a bar). */
#define CLIENT_X 100
#define CLIENT_Y 60
#define CLIENT_W 200
#define CLIENT_H 100
#define BORDER 4
#define BAR 24
/* Where the client goes, and the size the manager asks for. */
#define MOVED_X 150
#define MOVED_Y 80
#define ASKED_W 300
#define ASKED_H 150

#define KEY_A 30
#define BTN_LEFT 0x110

#define CLIENT_TITLE "probe client"
#define CLIENT_APP "posix-manager-client"
#define INPUT_TITLE "input ok"

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void fill(const struct stafeto_window *w, unsigned k, uint32_t width, uint32_t height,
                 uint32_t colour) {
    uint32_t *p = (uint32_t *)w->pixels[k];
    uint32_t words = w->stride / 4;
    for (uint32_t y = 0; y < height; y++)
        for (uint32_t x = 0; x < width; x++) p[y * words + x] = colour;
}

/* ------------------------------------------------------------------ the client */

/* Posts the window in the given size, in a buffer other than the last. */
static int repost(int win, unsigned *current, uint32_t width, uint32_t height, uint32_t colour) {
    struct stafeto_window w;
    unsigned next = 1 - *current;
    uint32_t free_mask = 0;
    CHECK(stafeto_window_info(win, &w) == 0);
    CHECK(stafeto_window_wait_free(win, 1u << next, WITHIN, &free_mask) == 0);
    fill(&w, next, width, height, colour);
    CHECK(stafeto_window_post(win, next, NULL, 0) == 0);
    *current = next;
    return 0;
}

static int inside(int x, int y, int w, int h) { return x >= 0 && y >= 0 && x < w && y < h; }

static int client_role(void) {
    struct stafeto_window w;
    struct stafeto_manager_window list[STAFETO_MANAGER_WINDOWS_MAX];
    unsigned current = 0;
    uint32_t width = CLIENT_W, height = CLIENT_H;
    int key_down = 0, key_up = 0, moved = 0, button_down = 0, button_up = 0, input_said = 0;
    long end = now_ms() + 100000;

    /* The clone of the manager's session is no manager's. */
    errno = 0;
    CHECK(stafeto_manager_subscribe() == -1 && errno == EPERM);
    errno = 0;
    CHECK(stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX) == -1 && errno == EBADF);
    printf("posix-manager: a child of the manager is refused with EPERM\n");

    CHECK(stafeto_window_open(CLIENT_X, CLIENT_Y, CLIENT_W, CLIENT_H, STAFETO_WINDOW_XRGB8888, 2,
                              STAFETO_WINDOW_RESIZABLE, &w) == 0);
    CHECK(stafeto_window_set_title(0, CLIENT_TITLE) == 0);
    CHECK(stafeto_window_set_app_id(0, CLIENT_APP) == 0);
    fill(&w, 0, width, height, 0x00C04040u);
    CHECK(stafeto_window_post(0, 0, NULL, 0) == 0);

    while (now_ms() < end) {
        struct stafeto_window_event e[STAFETO_WINDOW_EVENTS_MAX];
        uint32_t bits = 0;
        int n;
        if (stafeto_window_wait(0, 200 * MS, &bits) != 0 && errno != ETIMEDOUT) {
            printf("posix-manager: check failed: the client's wait (errno %d)\n", errno);
            return 21;
        }
        n = stafeto_window_events(0, e, STAFETO_WINDOW_EVENTS_MAX, NULL);
        CHECK(n >= 0);
        for (int i = 0; i < n; i++) {
            switch (e[i].kind) {
            case STAFETO_WINDOW_EVENT_KEY:
                if (e[i].code == KEY_A && e[i].value == 1) key_down = 1;
                if (e[i].code == KEY_A && e[i].value == 0 && key_down) key_up = 1;
                break;
            case STAFETO_WINDOW_EVENT_MOVE:
                /* The tablet is at (200, 119 or 120) of the screen, the window at
                 * (MOVED_X, MOVED_Y). */
                if (inside(e[i].x, e[i].y, (int)width, (int)height) &&
                    e[i].x >= 200 - MOVED_X - 2 && e[i].x <= 200 - MOVED_X + 2 &&
                    e[i].y >= 120 - MOVED_Y - 3 && e[i].y <= 120 - MOVED_Y + 1)
                    moved = 1;
                break;
            case STAFETO_WINDOW_EVENT_BUTTON:
                if (e[i].code == BTN_LEFT && moved &&
                    inside(e[i].x, e[i].y, (int)width, (int)height)) {
                    if (e[i].value == 1) button_down = 1;
                    if (e[i].value == 0 && button_down) button_up = 1;
                }
                break;
            case STAFETO_WINDOW_EVENT_CONFIGURE:
                /* The manager asks; the client answers with the size inside its
                 * capacity, and shows it with the next post. */
                CHECK(e[i].x > 0 && e[i].y > 0);
                width = (uint32_t)e[i].x;
                height = (uint32_t)e[i].y;
                CHECK(stafeto_window_resize(0, width, height, (uint32_t)e[i].value) == 0);
                if (repost(0, &current, width, height, 0x0040C040u) != 0) return 20;
                break;
            case STAFETO_WINDOW_EVENT_CLOSE_REQUEST:
                CHECK(stafeto_window_close(0) == 0);
                printf("posix-manager: client ok\n");
                return 0;
            default:
                break;
            }
        }
        if (!input_said && key_down && key_up && moved && button_down && button_up) {
            CHECK(stafeto_window_set_title(0, INPUT_TITLE) == 0);
            input_said = 1;
        }
    }
    printf("posix-manager: check failed: the client was never asked to close\n");
    return 22;
}

/* ----------------------------------------------------------------- the manager */

#define LOG_MAX 256
static struct stafeto_window_event ring_log[LOG_MAX];
static unsigned char taken[LOG_MAX];
static int ring_count;

static void drain_ring(void) {
    for (;;) {
        struct stafeto_window_event e[STAFETO_WINDOW_EVENTS_MAX];
        int n = stafeto_manager_events(e, STAFETO_WINDOW_EVENTS_MAX, NULL);
        if (n <= 0) return;
        for (int i = 0; i < n && ring_count < LOG_MAX; i++) {
            taken[ring_count] = 0;
            ring_log[ring_count++] = e[i];
        }
        if (n < STAFETO_WINDOW_EVENTS_MAX) return;
    }
}

/* Waits for an event of `kind` whose value is `value` (any when it is -1) and
 * whose x is `x` (any when -2); the event is used up. The events of other
 * kinds stay in the log. 0 or -1. */
static int wait_event(uint16_t kind, int value, int x, struct stafeto_window_event *out) {
    long end = now_ms() + (long)(WITHIN / MS);
    for (;;) {
        uint32_t bits[STAFETO_WINDOWS_MAX];
        for (int i = 0; i < ring_count; i++) {
            if (taken[i] || ring_log[i].kind != kind) continue;
            if (value != -1 && ring_log[i].value != value) continue;
            if (x != -2 && ring_log[i].x != x) continue;
            taken[i] = 1;
            if (out) *out = ring_log[i];
            return 0;
        }
        if (now_ms() > end) return -1;
        {
            int mask = stafeto_windows_wait(100 * MS, bits);
            if (mask > 0 && (mask & STAFETO_MANAGER_EVENTS)) drain_ring();
            else if (mask == -1 && errno != ETIMEDOUT) return -1;
        }
        drain_ring();
    }
}

static const struct stafeto_manager_window *find(const struct stafeto_manager_window *list, int n,
                                                 uint32_t id) {
    for (int i = 0; i < n; i++)
        if (list[i].id == id) return &list[i];
    return NULL;
}

/* Waits for the frame's buffer `k` and posts it, in a size. */
static int post_frame(int win, unsigned *current, uint32_t width, uint32_t height) {
    struct stafeto_window w;
    unsigned next = 1 - *current;
    uint32_t free_mask = 0;
    CHECK(stafeto_window_info(win, &w) == 0);
    CHECK(stafeto_window_wait_free(win, 1u << next, WITHIN, &free_mask) == 0);
    fill(&w, next, width, height, 0x00406080u);
    CHECK(stafeto_window_post(win, next, NULL, 0) == 0);
    *current = next;
    return 0;
}

static int manager_role(void) {
    struct stafeto_manager_window list[STAFETO_MANAGER_WINDOWS_MAX];
    struct stafeto_manager_info info;
    struct stafeto_window frame;
    struct stafeto_window_event e;
    char *argv[] = {"posix-manager", "client", NULL};
    pid_t pid = 0;
    int status = 0, n, win;
    uint32_t client = 0, frame_id = 0;
    unsigned current = 0;
    const struct stafeto_manager_window *c, *f;

    /* Before the subscription every call but the subscription says so. */
    errno = 0;
    CHECK(stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX) == -1 && errno == EBADF);
    errno = 0;
    CHECK(stafeto_manager_events(&e, 1, NULL) == -1 && errno == EBADF);
    errno = 0;
    CHECK(stafeto_manager_focus(1) == -1 && errno == EBADF);
    CHECK(stafeto_manager_subscribe() == 0);
    errno = 0;
    CHECK(stafeto_manager_subscribe() == -1 && errno == EBUSY);
    errno = 0;
    CHECK(stafeto_manager_list(NULL, 4) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_manager_info(0x7ffffff0u, &info) == -1 && errno == EINVAL);
    CHECK(stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX) == 0);
    printf("posix-manager: a call before the subscription is EBADF, a second subscription EBUSY, "
           "an id that names no window EINVAL\n");

    /* The session with the manager's mark would move to the new image, so exec
     * is refused while the process is a manager. */
    errno = 0;
    CHECK(execv("/bin/posix-manager", argv) == -1 && errno == EPERM);
    printf("posix-manager: exec is refused with EPERM while the process is a manager\n");

    CHECK(posix_spawn(&pid, "/bin/posix-manager", NULL, NULL, argv, environ) == 0);

    /* The manager's ring tells a wait across the windows (the manager has none
     * of its own yet) with the bit of its own, and no other bit. */
    {
        uint32_t bits[STAFETO_WINDOWS_MAX];
        int mask;
        long end = now_ms() + (long)(WITHIN / MS);
        do {
            mask = stafeto_windows_wait(100 * MS, bits);
        } while (mask == -1 && errno == ETIMEDOUT && now_ms() < end);
        CHECK(mask == (int)STAFETO_MANAGER_EVENTS);
        for (int k = 0; k < STAFETO_WINDOWS_MAX; k++) CHECK(bits[k] == 0);
    }

    /* The client's window: the manager gives it the focus and the top place. */
    CHECK(wait_event(STAFETO_MANAGER_EVENT_CREATE, -1, -2, &e) == 0);
    client = (uint32_t)e.value;
    CHECK(stafeto_manager_focus(client) == 0);
    printf("posix-manager: the client's window is created and the manager gives it the focus\n");

    /* Its title and the kind of its program come by INFO. */
    CHECK(wait_event(STAFETO_MANAGER_EVENT_TITLE, (int)client, STAFETO_MANAGER_TITLE, NULL) == 0);
    CHECK(wait_event(STAFETO_MANAGER_EVENT_TITLE, (int)client, STAFETO_MANAGER_APP_ID, NULL) == 0);
    memset(&info, 0xAA, sizeof info);
    CHECK(stafeto_manager_info(client, &info) == 0);
    CHECK(strcmp(info.title, CLIENT_TITLE) == 0);
    CHECK(strcmp(info.app_id, CLIENT_APP) == 0);
    CHECK(info.cap_w == 640 && info.cap_h == 400);
    CHECK((info.flags & (STAFETO_MANAGER_INFO_LEGACY | STAFETO_MANAGER_INFO_OWN)) == 0);
    printf("posix-manager: the title and the kind of the program come by INFO\n");

    /* The frame: a window of the manager's own, tied to the client's. */
    CHECK(stafeto_window_open(CLIENT_X - BORDER, CLIENT_Y - BAR, CLIENT_W + 2 * BORDER,
                              CLIENT_H + BAR + BORDER, STAFETO_WINDOW_XRGB8888, 2,
                              STAFETO_WINDOW_RESIZABLE, &frame) == 0);
    win = 0;
    CHECK(stafeto_window_id(win, &frame_id) == 0 && frame_id != 0 && frame_id != client);
    errno = 0;
    CHECK(stafeto_window_id(5, &frame_id) == -1 && errno == EBADF);
    CHECK(stafeto_window_id(win, &frame_id) == 0);
    fill(&frame, 0, CLIENT_W + 2 * BORDER, CLIENT_H + BAR + BORDER, 0x00406080u);
    CHECK(stafeto_window_post(win, 0, NULL, 0) == 0);
    /* The service tells of the manager's own window too, and it is the one
     * stafeto_window_id names. */
    CHECK(wait_event(STAFETO_MANAGER_EVENT_CREATE, (int)frame_id, -2, NULL) == 0);
    CHECK(stafeto_manager_info(frame_id, &info) == 0);
    CHECK(info.flags & STAFETO_MANAGER_INFO_OWN);
    /* Only a window of the manager's own is a frame. */
    errno = 0;
    CHECK(stafeto_manager_link(client, client) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_manager_link(frame_id, client) == -1 && errno == EINVAL);
    CHECK(stafeto_manager_link(client, frame_id) == 0);
    CHECK(stafeto_manager_info(client, &info) == 0 && (info.flags & STAFETO_MANAGER_INFO_LEADER));
    CHECK(stafeto_manager_info(frame_id, &info) == 0 &&
          (info.flags & STAFETO_MANAGER_INFO_FOLLOWER));
    n = stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX);
    CHECK(n == 2);
    c = find(list, n, client);
    f = find(list, n, frame_id);
    CHECK(c && f);
    CHECK(c->x == CLIENT_X && c->y == CLIENT_Y && c->w == CLIENT_W && c->h == CLIENT_H);
    CHECK(f->x == CLIENT_X - BORDER && f->y == CLIENT_Y - BAR);
    CHECK(f->depth + 1 == c->depth);
    CHECK(c->flags & STAFETO_MANAGER_FOCUSED);
    CHECK(!(f->flags & STAFETO_MANAGER_FOCUSED));

    /* The pair moves as one. */
    CHECK(stafeto_manager_move(client, MOVED_X, MOVED_Y) == 0);
    n = stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX);
    CHECK(n == 2);
    c = find(list, n, client);
    f = find(list, n, frame_id);
    CHECK(c && f);
    CHECK(c->x == MOVED_X && c->y == MOVED_Y);
    CHECK(f->x == MOVED_X - BORDER && f->y == MOVED_Y - BAR);
    CHECK(f->depth + 1 == c->depth);
    printf("posix-manager: a frame of the manager's own is linked, and the pair moves as one\n");

    /* A move that would put the frame off the screen moves nothing. */
    errno = 0;
    CHECK(stafeto_manager_move(client, 2, 10) == -1 && errno == EINVAL);
    n = stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX);
    c = find(list, n, client);
    f = find(list, n, frame_id);
    CHECK(n == 2 && c && f);
    CHECK(c->x == MOVED_X && c->y == MOVED_Y);
    CHECK(f->x == MOVED_X - BORDER && f->y == MOVED_Y - BAR);
    printf("posix-manager: a move that would put the frame off the screen is refused and "
           "nothing moves\n");

    /* The key and the pointer: the host sends them at this point of the screen. */
    printf("posix-manager: input at 200 120\n");
    fflush(stdout);
    CHECK(wait_event(STAFETO_MANAGER_EVENT_TITLE, (int)client, STAFETO_MANAGER_TITLE, NULL) == 0);
    CHECK(stafeto_manager_info(client, &info) == 0);
    CHECK(strcmp(info.title, INPUT_TITLE) == 0);
    printf("posix-manager: the key and the pointer reached the window with the focus\n");

    /* CONFIGURE: the client answers, the manager hears the size and follows it. */
    CHECK(stafeto_manager_configure(client, ASKED_W, ASKED_H, 0) == 0);
    CHECK(wait_event(STAFETO_MANAGER_EVENT_RESIZED, (int)client, ASKED_W, &e) == 0);
    CHECK(e.y == ASKED_H);
    CHECK(stafeto_window_resize(win, ASKED_W + 2 * BORDER, ASKED_H + BAR + BORDER, 0) == 0);
    CHECK(post_frame(win, &current, ASKED_W + 2 * BORDER, ASKED_H + BAR + BORDER) == 0);
    CHECK(wait_event(STAFETO_MANAGER_EVENT_RESIZED, (int)frame_id, ASKED_W + 2 * BORDER, &e) == 0);
    CHECK(e.y == ASKED_H + BAR + BORDER);
    n = stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX);
    c = find(list, n, client);
    f = find(list, n, frame_id);
    CHECK(n == 2 && c && f);
    CHECK(c->w == ASKED_W && c->h == ASKED_H);
    CHECK(f->w == ASKED_W + 2 * BORDER && f->h == ASKED_H + BAR + BORDER);
    CHECK(c->x == MOVED_X && f->x == MOVED_X - BORDER);
    /* A size past the screen, half of a size and an unknown state are refused. */
    errno = 0;
    CHECK(stafeto_manager_configure(client, 641, 400, 0) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_manager_configure(client, 0, 150, 0) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(stafeto_manager_configure(client, ASKED_W, ASKED_H, 0x80) == -1 && errno == EINVAL);
    printf("posix-manager: CONFIGURE got RESIZED and the frame follows the size\n");

    /* Hide and show: the frame goes with its window. */
    CHECK(stafeto_manager_visible(client, 0) == 0);
    n = stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX);
    c = find(list, n, client);
    f = find(list, n, frame_id);
    CHECK(c && f && !(c->flags & STAFETO_MANAGER_SHOWN) && !(f->flags & STAFETO_MANAGER_SHOWN));
    CHECK(stafeto_manager_visible(client, 1) == 0);
    n = stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX);
    c = find(list, n, client);
    f = find(list, n, frame_id);
    CHECK(c && f && (c->flags & STAFETO_MANAGER_SHOWN) && (f->flags & STAFETO_MANAGER_SHOWN));
    CHECK(stafeto_manager_raise(client) == 0);
    printf("posix-manager: the frame is hidden and shown with its window\n");

    /* CLOSE: the client is asked, its window goes, the frame is hidden. */
    CHECK(stafeto_manager_close(client) == 0);
    CHECK(wait_event(STAFETO_MANAGER_EVENT_CLOSE, (int)client, -2, NULL) == 0);
    n = stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX);
    f = find(list, n, frame_id);
    CHECK(n == 1 && f && !find(list, n, client));
    CHECK(!(f->flags & STAFETO_MANAGER_SHOWN));
    CHECK(stafeto_manager_info(frame_id, &info) == 0 &&
          !(info.flags & STAFETO_MANAGER_INFO_FOLLOWER));
    errno = 0;
    CHECK(stafeto_manager_info(client, &info) == -1 && errno == EINVAL);
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(stafeto_window_close(win) == 0);
    printf("posix-manager: close asks the client, whose window goes, and the frame is hidden\n");
    printf("posix-manager: ok\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "client") == 0) return client_role();
    return manager_role();
}
