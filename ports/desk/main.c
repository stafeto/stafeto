/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The window manager `desk`: a process of POSIX with the manager's mark that
 * puts a frame of its own around the windows of the programs and a panel at
 * the top of the screen (<stafeto/manager.h>, LVGL for the drawing).
 *
 *   desk [--trace] [--spawn APPID,PATH[,ARG...]]...
 *
 * The manager subscribes, lists the windows (those already open get a frame
 * as the new ones do), and then decides on what comes: the events of its ring
 * (a window made or gone, a title, the keys under Super), the pointer on the
 * frames and the panel (events of the windows it made for them), and the time.
 * The decisions are those of policy.c, which has no call to the service; this
 * file carries them out. A frame is a window of the manager's own tied to the
 * client's window by stafeto_manager_link, so the service moves, raises and
 * hides the two as one in a frame of its own.
 *
 * Each --spawn starts a program once, when the manager finds no window of
 * a client at its start (a manager that restarts finds the windows of the
 * first run and starts nothing): APPID is the application id the program gives
 * its window, which names the process for SIGTERM, PATH the file, and the
 * rest the arguments. The next program starts when the one before has a window.
 *
 * With --trace the manager prints a line for each change of what the service
 * lists: the windows from the lowest, each with its place, size and flags
 * (s shown, f focus), the probe reads them. */
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "lvgl.h"

#include <stafeto/manager.h>
#include <stafeto/window.h>

#include "desk_io.h"
#include "draw.h"
#include "policy.h"
#include "launch.h"

extern char **environ;

/* The memory of the layer's heap, from the Rust side of the program. */
extern unsigned long desk_heap_bytes(void);
extern unsigned long desk_own_pages(void);

#define FONT_PATH "/usr/share/fonts/LiberationSans-Regular.ttf"
#define FONT_PX 14
/* The longest the manager sleeps without looking at the list: it learns of a
 * click on a window with no frame (the focus moves) only from the list. */
#define POLL_MS 500
#define SPAWN_MAX 8
#define SPAWN_WAIT_MS 15000
/* The address space a program the manager starts may have, in bytes: its own
 * quota (a child gets the manager's quota, which holds the manager's windows;
 * the limit is set in the manager for the spawn and put back). */
#define SPAWN_LIMIT_BYTES (6ull << 20)
#define MS 1000000ull

static desk_policy policy;
static desk_surface surfaces[STAFETO_WINDOWS_MAX];
static int trace_on;
static int running = 1;
static lv_font_t *font;
static int32_t screen_w, screen_h;

/* The programs the manager started: the process of a window is the first one
 * whose application id is the window's that no window has claimed. */
struct child {
    pid_t pid;
    char app_id[DESK_TEXT_MAX + 1];
    uint32_t window;   /* DESK_NO_WINDOW until a window claims it */
};
static struct child children[SPAWN_MAX];

static desk_spawn specs[SPAWN_MAX];
static unsigned spec_count, spawned;
static long spawned_at_ms;

static long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("desk: ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    fflush(stdout);
}

/* ---- the surfaces ---- */

static desk_surface *surface_of_window(uint32_t id)
{
    for (int i = 0; i < STAFETO_WINDOWS_MAX; i++) {
        if (surfaces[i].kind != DESK_SURFACE_NONE && surfaces[i].id == id) {
            return &surfaces[i];
        }
    }
    return NULL;
}

static desk_surface *frame_of(uint32_t client)
{
    for (int i = 0; i < STAFETO_WINDOWS_MAX; i++) {
        if (surfaces[i].kind == DESK_SURFACE_FRAME && surfaces[i].client == client) {
            return &surfaces[i];
        }
    }
    return NULL;
}

static desk_surface *panel(void)
{
    for (int i = 0; i < STAFETO_WINDOWS_MAX; i++) {
        if (surfaces[i].kind == DESK_SURFACE_PANEL) {
            return &surfaces[i];
        }
    }
    return NULL;
}

static const char *title_of(const desk_win *w)
{
    return w->title[0] ? w->title : w->app_id[0] ? w->app_id : "?";
}

/* The frame of the client window `id` gets the title and the focus. */
static void set_frame_view(desk_surface *f)
{
    const desk_win *w = desk_find(&policy, f->client);
    if (w) {
        desk_frame_view_set(&f->frame, f->display, title_of(w), policy.focus == f->client);
    }
}

static void make_frame(uint32_t client)
{
    const desk_win *w = desk_find(&policy, client);
    if (!w || frame_of(client)) {
        return;
    }
    int32_t fx, fy, fw, fh;
    desk_frame_rect(w->x, w->y, w->w, w->h, &fx, &fy, &fw, &fh);
    desk_surface s;
    if (desk_surface_open(&s, DESK_SURFACE_FRAME, fx, fy, fw, fh) != 0) {
        say("no frame for a window: errno %d", errno);
        desk_frame_failed(&policy, client);
        return;
    }
    s.client = client;
    /* Linked first: the frame is under its window from the start, and drawn
     * (shown) only after that. */
    if (stafeto_manager_link(client, s.id) != 0) {
        say("no link for a frame: errno %d", errno);
        desk_surface_close(&s);
        desk_frame_failed(&policy, client);
        return;
    }
    desk_frame_view_init(&s.frame, s.display, font, fw, fh);
    set_frame_view(&s);
    desk_surface_refresh(&s);
    surfaces[s.win] = s;
    /* The display keeps a pointer to the surface that was on the stack. */
    lv_display_set_user_data(s.display, &surfaces[s.win]);
    if (trace_on) {
        say("memory heap-bytes %lu own-pages %lu", desk_heap_bytes(), desk_own_pages());
    }
}

static void drop_frame(uint32_t client)
{
    desk_surface *f = frame_of(client);
    if (f) {
        desk_surface_close(f);
    }
}

static void draw_dirty(void)
{
    for (int i = 0; i < STAFETO_WINDOWS_MAX; i++) {
        desk_surface *s = &surfaces[i];
        if (s->kind == DESK_SURFACE_NONE || !s->dirty) {
            continue;
        }
        s->dirty = 0;
        if (s->kind == DESK_SURFACE_FRAME) {
            set_frame_view(s);
        } else {
            desk_panel_view_set(&s->panel, &policy);
        }
        desk_surface_refresh(s);
    }
}

/* ---- the programs ---- */

static void claim_child(uint32_t window, const char *app_id)
{
    for (unsigned i = 0; i < SPAWN_MAX; i++) {
        struct child *c = &children[i];
        if (c->pid && c->window == DESK_NO_WINDOW && strcmp(c->app_id, app_id) == 0) {
            c->window = window;
            return;
        }
    }
}

static void reap(void)
{
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        for (unsigned i = 0; i < SPAWN_MAX; i++) {
            if (children[i].pid == pid) {
                memset(&children[i], 0, sizeof children[i]);
            }
        }
    }
}

static void spawn_next(void)
{
    desk_spawn *sp = &specs[spawned];
    for (unsigned i = 0; i < SPAWN_MAX; i++) {
        if (children[i].pid == 0) {
            pid_t pid = 0;
            struct rlimit before, limited;
            int have = getrlimit(RLIMIT_AS, &before) == 0;
            if (have) {
                limited = before;
                if (limited.rlim_cur > SPAWN_LIMIT_BYTES) {
                    limited.rlim_cur = SPAWN_LIMIT_BYTES;
                }
                setrlimit(RLIMIT_AS, &limited);
            }
            int err = posix_spawn(&pid, sp->path, NULL, NULL, sp->argv, environ);
            if (have) {
                setrlimit(RLIMIT_AS, &before);
            }
            if (err != 0) {
                say("cannot start %s: errno %d", sp->path, err);
            } else {
                children[i].pid = pid;
                children[i].window = DESK_NO_WINDOW;
                snprintf(children[i].app_id, sizeof children[i].app_id, "%s", sp->app_id);
                say("started %s", sp->app_id);
            }
            break;
        }
    }
    spawned++;
    spawned_at_ms = now_ms();
}

/* ---- the windows ---- */

static void learn_text(uint32_t id, int which, const char *text)
{
    desk_text(&policy, id, which, text);
    if (which == STAFETO_MANAGER_APP_ID) {
        claim_child(id, text);
    }
}

/* A window of a client the policy does not know yet. */
static void adopt(const struct stafeto_manager_window *l)
{
    struct stafeto_manager_info info;
    if (stafeto_manager_info(l->id, &info) != 0) {
        return;   /* gone already */
    }
    if (info.flags & STAFETO_MANAGER_INFO_OWN) {
        return;
    }
    int legacy = (info.flags & STAFETO_MANAGER_INFO_LEGACY) != 0;
    if (desk_created(&policy, l->id, (int32_t)l->x, (int32_t)l->y, (int32_t)l->w, (int32_t)l->h,
                     legacy) != 0) {
        say("no room for another window");
        return;
    }
    if (info.title[0]) {
        learn_text(l->id, STAFETO_MANAGER_TITLE, info.title);
    }
    if (info.app_id[0]) {
        learn_text(l->id, STAFETO_MANAGER_APP_ID, info.app_id);
    }
}

/* The service's list against the policy's windows: the new ones are adopted,
 * the ones that went are dropped, and the place and the focus of the others are
 * taken from the list. */
static int sync_list(struct stafeto_manager_window *list)
{
    int n = stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX);
    if (n < 0) {
        return -1;
    }
    for (int i = 0; i < n; i++) {
        if (surface_of_window(list[i].id)) {
            continue;
        }
        if (desk_find(&policy, list[i].id)) {
            desk_sync(&policy, list[i].id, (int32_t)list[i].x, (int32_t)list[i].y,
                      (int32_t)list[i].w, (int32_t)list[i].h,
                      (list[i].flags & STAFETO_MANAGER_FOCUSED) != 0);
        } else {
            adopt(&list[i]);
        }
    }
    for (unsigned i = 0; i < desk_cells(&policy);) {
        uint32_t id = desk_cell(&policy, i)->id;
        int there = 0;
        for (int k = 0; k < n; k++) {
            there |= list[k].id == id;
        }
        if (there) {
            i++;
        } else {
            desk_gone(&policy, id);
        }
    }
    return n;
}

/* ---- the events ---- */

static void ring_event(const struct stafeto_window_event *e)
{
    struct stafeto_manager_info info;
    switch (e->kind) {
    case STAFETO_MANAGER_EVENT_TITLE:
        if (stafeto_manager_info((uint32_t)e->value, &info) == 0 && desk_find(&policy, (uint32_t)e->value)) {
            if (e->x == STAFETO_MANAGER_TITLE) {
                learn_text((uint32_t)e->value, STAFETO_MANAGER_TITLE, info.title);
            } else if (e->x == STAFETO_MANAGER_APP_ID) {
                learn_text((uint32_t)e->value, STAFETO_MANAGER_APP_ID, info.app_id);
            }
        }
        break;
    case STAFETO_MANAGER_EVENT_CLOSE:
        desk_gone(&policy, (uint32_t)e->value);
        break;
    case STAFETO_WINDOW_EVENT_KEY:
        desk_key(&policy, e->code, e->value);
        break;
    default:
        /* CREATE comes with the list; the other kinds are for later steps. */
        break;
    }
}

/* The events of a window of the manager's own: the pointer on a frame or on the
 * panel. The moves of one batch are one: the last (the policy moves the
 * window by the pointer's distance from where the press was, so the moves
 * between add nothing). */
static void surface_events(desk_surface *s)
{
    struct stafeto_window_event e[STAFETO_WINDOW_EVENTS_MAX];
    int pending = 0;
    int32_t mx = 0, my = 0;
    for (;;) {
        int n = stafeto_window_events(s->win, e, STAFETO_WINDOW_EVENTS_MAX, NULL);
        if (n < 0) {
            if (errno == ENODEV) {
                s->gone = 1;
            }
            return;
        }
        for (int i = 0; i < n; i++) {
            if (e[i].kind == STAFETO_WINDOW_EVENT_MOVE) {
                pending = 1;
                mx = e[i].x;
                my = e[i].y;
            } else if (e[i].kind == STAFETO_WINDOW_EVENT_BUTTON && e[i].code == 0x110) {
                if (pending && s->kind == DESK_SURFACE_FRAME) {
                    desk_frame_move(&policy, s->client, mx, my);
                }
                pending = 0;
                if (s->kind == DESK_SURFACE_FRAME) {
                    desk_frame_button(&policy, s->client, e[i].value != 0, e[i].x, e[i].y);
                } else {
                    desk_panel_button(&policy, e[i].value != 0, e[i].x, e[i].y);
                }
            }
        }
        if (n < STAFETO_WINDOW_EVENTS_MAX) {
            break;
        }
    }
    if (pending && s->kind == DESK_SURFACE_FRAME) {
        desk_frame_move(&policy, s->client, mx, my);
    }
}

/* ---- the actions ---- */

static void term(uint32_t id)
{
    for (unsigned i = 0; i < SPAWN_MAX; i++) {
        if (children[i].pid && children[i].window == id) {
            const desk_win *w = desk_find(&policy, id);
            say("SIGTERM to %s after %u ms", w ? title_of(w) : "?",
                w ? (unsigned)(policy.now_ms - w->close_at_ms) : 0u);
            kill(children[i].pid, SIGTERM);
            return;
        }
    }
    say("no process of ours has the window that did not close");
}

static unsigned run_actions(void)
{
    desk_action a;
    unsigned count = 0;
    while (desk_next(&policy, &a)) {
        count++;
        desk_surface *s;
        switch (a.kind) {
        case DESK_ACT_FOCUS:
            stafeto_manager_focus(a.id);
            break;
        case DESK_ACT_MOVE:
            stafeto_manager_move(a.id, (uint32_t)a.a, (uint32_t)a.b);
            break;
        case DESK_ACT_CLOSE: {
            const desk_win *w = desk_find(&policy, a.id);
            if (stafeto_manager_close(a.id) == 0) {
                say("closing %s", w ? title_of(w) : "?");
            }
            break;
        }
        case DESK_ACT_TERM:
            term(a.id);
            break;
        case DESK_ACT_FRAME:
            make_frame(a.id);
            break;
        case DESK_ACT_UNFRAME:
            drop_frame(a.id);
            break;
        case DESK_ACT_DRAW_FRAME:
            s = frame_of(a.id);
            if (s) {
                s->dirty = 1;
            }
            break;
        case DESK_ACT_DRAW_PANEL:
            s = panel();
            if (s) {
                s->dirty = 1;
            }
            break;
        case DESK_ACT_PANEL_SHOWN:
            s = panel();
            if (s) {
                stafeto_manager_visible(s->id, a.a);
            }
            break;
        case DESK_ACT_QUIT:
            running = 0;
            break;
        default:
            break;
        }
    }
    return count;
}

/* ---- the trace ---- */

static void trace(const struct stafeto_manager_window *list, int n)
{
    static char last[2048];
    char line[2048];
    size_t at = 0;
    line[0] = 0;
    for (int i = 0; i < n; i++) {
        const desk_surface *s = surface_of_window(list[i].id);
        char name[2 * DESK_TEXT_MAX + 16];
        if (s && s->kind == DESK_SURFACE_PANEL) {
            snprintf(name, sizeof name, "panel");
        } else if (s) {
            const desk_win *w = desk_find(&policy, s->client);
            snprintf(name, sizeof name, "frame(%s)", w ? title_of(w) : "?");
        } else {
            const desk_win *w = desk_find(&policy, list[i].id);
            snprintf(name, sizeof name, "%s", w ? title_of(w) : "?");
        }
        int wrote = snprintf(line + at, sizeof line - at, "%s%s@%u,%u/%ux%u/%s%s", i ? "; " : "",
                             name, list[i].x, list[i].y, list[i].w, list[i].h,
                             list[i].flags & STAFETO_MANAGER_SHOWN ? "s" : "",
                             list[i].flags & STAFETO_MANAGER_FOCUSED ? "f" : "");
        if (wrote < 0 || (size_t)wrote >= sizeof line - at) {
            break;
        }
        at += (size_t)wrote;
    }
    if (strcmp(line, last) != 0) {
        snprintf(last, sizeof last, "%s", line);
        say("state %s", n ? line : "(no windows)");
    }
}

/* ---- the start ---- */

static int parse_spawn(const char *text)
{
    if (spec_count >= SPAWN_MAX || desk_spawn_parse(&specs[spec_count], text) != 0) {
        return -1;
    }
    spec_count++;
    return 0;
}

static int subscribe(void)
{
    /* A manager that restarts gets EBUSY until the service has seen the old
     * session go. */
    long end = now_ms() + 30000;
    for (;;) {
        if (stafeto_manager_subscribe() == 0) {
            return 0;
        }
        if (errno != EBUSY || now_ms() > end) {
            say("cannot subscribe: errno %d", errno);
            return -1;
        }
        struct timespec t = {0, 100 * 1000000};
        nanosleep(&t, NULL);
    }
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--trace") == 0) {
            trace_on = 1;
        } else if (strcmp(argv[i], "--spawn") == 0 && i + 1 < argc) {
            if (parse_spawn(argv[++i]) != 0) {
                say("bad --spawn %s", argv[i]);
                return 2;
            }
        } else {
            fprintf(stderr, "usage: desk [--trace] [--spawn APPID,PATH[,ARG...]]...\n");
            return 2;
        }
    }
    struct stafeto_screen screen;
    if (stafeto_screen_describe(&screen) != 0) {
        say("no screen: errno %d", errno);
        return 1;
    }
    screen_w = (int32_t)screen.width;
    screen_h = (int32_t)screen.height;
    if (subscribe() != 0) {
        return 1;
    }
    desk_io_init();
    lv_init();
    font = lv_freetype_font_create(FONT_PATH, LV_FREETYPE_FONT_RENDER_MODE_BITMAP, FONT_PX,
                                   LV_FREETYPE_FONT_STYLE_NORMAL);
    if (!font) {
        say("no font %s: the built-in one is used", FONT_PATH);
        font = (lv_font_t *)&lv_font_montserrat_16;
    } else {
        font->fallback = &lv_font_montserrat_16;
    }
    desk_init(&policy, screen_w, screen_h);
    for (unsigned i = 0; i < SPAWN_MAX; i++) {
        children[i].window = DESK_NO_WINDOW;
    }

    /* The windows of clients that are open now (a manager that restarts) are
     * framed like the new ones; with none, the programs of the list start. */
    struct stafeto_manager_window list[STAFETO_MANAGER_WINDOWS_MAX];
    int existing = stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX);
    if (existing < 0) {
        say("cannot list: errno %d", errno);
        return 1;
    }
    unsigned start_spawn = existing == 0 ? 0 : spec_count;
    spawned = start_spawn;

    desk_surface *pn = &surfaces[0];
    if (desk_surface_open(pn, DESK_SURFACE_PANEL, 0, 0, screen_w, DESK_PANEL_H) != 0) {
        say("no panel: errno %d", errno);
        return 1;
    }
    /* The first window of the process is the library's window 0, the slot of the
     * table that holds it (a frame is held at the slot of its number too). */
    if (pn->win != 0) {
        say("the panel is window %d", pn->win);
        return 1;
    }
    desk_panel_view_init(&pn->panel, pn->display, font, screen_w);
    desk_panel_view_set(&pn->panel, &policy);
    desk_surface_refresh(pn);
    say("ready %ux%u", (unsigned)screen_w, (unsigned)screen_h);
    say("memory heap-bytes %lu own-pages %lu", desk_heap_bytes(), desk_own_pages());

    while (running) {
        /* The programs of the list, one after the other. */
        if (spawned < spec_count &&
            (spawned == start_spawn || desk_cells(&policy) >= spawned - start_spawn ||
             now_ms() - spawned_at_ms > SPAWN_WAIT_MS)) {
            spawn_next();
        }
        desk_time(&policy, (uint32_t)now_ms());
        int wait_ms = POLL_MS;
        int deadline = desk_next_deadline(&policy);
        if (deadline >= 0 && deadline < wait_ms) {
            wait_ms = deadline + 1;
        }
        if (spawned < spec_count && wait_ms > 100) {
            wait_ms = 100;
        }
        uint32_t bits[STAFETO_WINDOWS_MAX] = {0};
        int mask = stafeto_windows_wait((uint64_t)wait_ms * MS, bits);
        if (mask == -1) {
            if (errno == ETIMEDOUT || errno == EINTR) {
                mask = 0;
            } else {
                say("the wait ended: errno %d", errno);
                return 1;
            }
        }
        desk_time(&policy, (uint32_t)now_ms());
        reap();
        int n = sync_list(list);
        if (n < 0) {
            say("the service ended: errno %d", errno);
            return 1;
        }
        /* The ring: the keys, the titles, the windows that went. */
        unsigned work = 0;
        for (;;) {
            struct stafeto_window_event e[STAFETO_WINDOW_EVENTS_MAX];
            int got = stafeto_manager_events(e, STAFETO_WINDOW_EVENTS_MAX, NULL);
            if (got < 0) {
                say("the ring ended: errno %d", errno);
                return 1;
            }
            for (int i = 0; i < got; i++) {
                ring_event(&e[i]);
            }
            work += (unsigned)got;
            if (got < STAFETO_WINDOW_EVENTS_MAX) {
                break;
            }
        }
        for (int i = 0; i < STAFETO_WINDOWS_MAX; i++) {
            if (surfaces[i].kind == DESK_SURFACE_NONE) {
                continue;
            }
            if (bits[i] & STAFETO_WINDOW_GONE) {
                surfaces[i].gone = 1;
            }
            if (mask > 0 && (mask & (1 << i))) {
                surface_events(&surfaces[i]);
                work++;
            }
        }
        desk_tick(&policy);
        work += run_actions();
        draw_dirty();
        if (trace_on) {
            /* The list of the start of the turn is still the service's when nothing
             * happened since (a wait that ran out): one call to the service a turn. */
            if (work != 0) {
                n = stafeto_manager_list(list, STAFETO_MANAGER_WINDOWS_MAX);
            }
            if (n >= 0) {
                trace(list, n);
            }
        }
    }
    say("memory heap-bytes %lu own-pages %lu", desk_heap_bytes(), desk_own_pages());
    say("quit");
    return 0;
}
