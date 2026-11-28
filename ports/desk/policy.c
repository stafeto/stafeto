/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include "policy.h"

#include <string.h>

void desk_init(desk_policy *p, int32_t screen_w, int32_t screen_h)
{
    memset(p, 0, sizeof *p);
    p->screen_w = screen_w;
    p->screen_h = screen_h;
    p->focus = DESK_NO_WINDOW;
    p->panel_shown = 1;
    p->drag.id = DESK_NO_WINDOW;
    p->press.id = DESK_NO_WINDOW;
}

void desk_time(desk_policy *p, uint32_t now_ms)
{
    p->now_ms = now_ms;
}

/* ---- the queue ---- */

static void act(desk_policy *p, int kind, uint32_t id, int32_t a, int32_t b)
{
    if (p->queued - p->taken >= DESK_ACTIONS_MAX) {
        return;   /* the program takes the actions after each event; this does not happen */
    }
    if (p->queued == DESK_ACTIONS_MAX) {
        /* Compact: the taken ones go. */
        memmove(p->queue, p->queue + p->taken, (p->queued - p->taken) * sizeof p->queue[0]);
        p->queued -= p->taken;
        p->taken = 0;
    }
    p->queue[p->queued++] = (desk_action){kind, id, a, b};
}

int desk_next(desk_policy *p, desk_action *out)
{
    if (p->taken == p->queued) {
        p->taken = p->queued = 0;
        return 0;
    }
    *out = p->queue[p->taken++];
    return 1;
}

/* ---- the windows ---- */

static desk_win *find(desk_policy *p, uint32_t id)
{
    for (int i = 0; i < DESK_MAX_WINDOWS; i++) {
        if (p->win[i].used && p->win[i].id == id) {
            return &p->win[i];
        }
    }
    return NULL;
}

const desk_win *desk_find(const desk_policy *p, uint32_t id)
{
    return find((desk_policy *)p, id);
}

int desk_frameable(const desk_policy *p, int legacy, int32_t w, int32_t h)
{
    return !legacy && w > 0 && h > 0 && w + 2 * DESK_BORDER <= p->screen_w &&
           h + DESK_BAR + DESK_BORDER <= p->screen_h - DESK_PANEL_H;
}

void desk_frame_rect(int32_t x, int32_t y, int32_t w, int32_t h, int32_t *fx, int32_t *fy,
                     int32_t *fw, int32_t *fh)
{
    *fx = x - DESK_BORDER;
    *fy = y - DESK_BAR;
    *fw = w + 2 * DESK_BORDER;
    *fh = h + DESK_BAR + DESK_BORDER;
}

int desk_zone(int32_t fw, int32_t x, int32_t y)
{
    if (x < 0 || y < 0 || x >= fw || y >= DESK_BAR) {
        return DESK_ZONE_NONE;
    }
    return x >= fw - DESK_CLOSE_W ? DESK_ZONE_CLOSE : DESK_ZONE_TITLE;
}

static int32_t clamp(int32_t v, int32_t lo, int32_t hi)
{
    if (hi < lo) {
        hi = lo;
    }
    return v < lo ? lo : v > hi ? hi : v;
}

/* The place nearest to (x, y) where the frame of a w by h window is inside the
 * screen and below the panel. */
static void keep_frame_inside(const desk_policy *p, int32_t w, int32_t h, int32_t *x, int32_t *y)
{
    *x = clamp(*x, DESK_BORDER, p->screen_w - w - DESK_BORDER);
    *y = clamp(*y, DESK_PANEL_H + DESK_BAR, p->screen_h - h - DESK_BORDER);
}

/* Whether the panel is shown with the focus where it is: it is hidden while a
 * window with no frame has the focus and covers the screen or is of the first
 * revision. */
static void panel_check(desk_policy *p)
{
    const desk_win *f = p->focus == DESK_NO_WINDOW ? NULL : find(p, p->focus);
    int hide = f && !f->framed && (f->legacy || (f->w >= p->screen_w && f->h >= p->screen_h));
    int want = !hide;
    if (want != p->panel_shown) {
        p->panel_shown = want;
        act(p, DESK_ACT_PANEL_SHOWN, 0, want, 0);
    }
}

static void draw_frame(desk_policy *p, const desk_win *w)
{
    if (w && w->framed) {
        act(p, DESK_ACT_DRAW_FRAME, w->id, 0, 0);
    }
}

/* The window has the focus from now on (the service has given it, or the
 * action FOCUS follows). */
static void focus_to(desk_policy *p, desk_win *w, int give)
{
    if (p->focus != w->id) {
        draw_frame(p, p->focus == DESK_NO_WINDOW ? NULL : find(p, p->focus));
        p->focus = w->id;
        w->stamp = ++p->stamp;
        draw_frame(p, w);
        act(p, DESK_ACT_DRAW_PANEL, 0, 0, 0);
        panel_check(p);
    }
    if (give) {
        act(p, DESK_ACT_FOCUS, w->id, 0, 0);
    }
}

int desk_created(desk_policy *p, uint32_t id, int32_t x, int32_t y, int32_t w, int32_t h,
                 int legacy)
{
    if (find(p, id)) {
        return 0;
    }
    /* The windows are kept in the order they were made, with no hole. */
    unsigned count = desk_cells(p);
    if (count >= DESK_MAX_WINDOWS) {
        return -1;
    }
    desk_win *n = &p->win[count];
    memset(n, 0, sizeof *n);
    n->used = 1;
    n->id = id;
    n->x = x;
    n->y = y;
    n->w = w;
    n->h = h;
    n->legacy = legacy;
    int frame = desk_frameable(p, legacy, w, h);
    if (frame) {
        int32_t nx = x, ny = y;
        keep_frame_inside(p, w, h, &nx, &ny);
        if (nx != x || ny != y) {
            act(p, DESK_ACT_MOVE, id, nx, ny);
            n->x = nx;
            n->y = ny;
        }
    }
    /* The focus first, while the window has no frame to draw yet: the frame is
     * drawn when it is made, with the focus it has by then. */
    focus_to(p, n, 0);
    if (frame) {
        n->framed = 1;
        act(p, DESK_ACT_FRAME, id, 0, 0);
    }
    act(p, DESK_ACT_FOCUS, id, 0, 0);
    return 0;
}

void desk_frame_failed(desk_policy *p, uint32_t id)
{
    desk_win *w = find(p, id);
    if (w && w->framed) {
        w->framed = 0;
        act(p, DESK_ACT_DRAW_PANEL, 0, 0, 0);
        panel_check(p);
    }
}

void desk_gone(desk_policy *p, uint32_t id)
{
    desk_win *w = find(p, id);
    if (!w) {
        return;
    }
    if (w->framed) {
        act(p, DESK_ACT_UNFRAME, id, 0, 0);
    }
    if (p->drag.active && p->drag.id == id) {
        p->drag.active = 0;
        p->drag.id = DESK_NO_WINDOW;
    }
    if (p->press.id == id) {
        p->press.id = DESK_NO_WINDOW;
    }
    int had_focus = p->focus == id;
    int at = (int)(w - p->win);
    memmove(&p->win[at], &p->win[at + 1], (size_t)(DESK_MAX_WINDOWS - at - 1) * sizeof p->win[0]);
    memset(&p->win[DESK_MAX_WINDOWS - 1], 0, sizeof p->win[0]);
    if (had_focus) {
        p->focus = DESK_NO_WINDOW;
        desk_win *next = NULL;
        for (int i = 0; i < DESK_MAX_WINDOWS; i++) {
            desk_win *c = &p->win[i];
            if (c->used && !c->hidden && (!next || c->stamp >= next->stamp)) {
                next = c;
            }
        }
        if (next) {
            focus_to(p, next, 1);
        }
    }
    act(p, DESK_ACT_DRAW_PANEL, 0, 0, 0);
    panel_check(p);
}

void desk_text(desk_policy *p, uint32_t id, int which, const char *text)
{
    desk_win *w = find(p, id);
    if (!w) {
        return;
    }
    char *to = which == 1 ? w->title : which == 2 ? w->app_id : NULL;
    if (!to) {
        return;
    }
    size_t n = strlen(text);
    if (n > DESK_TEXT_MAX) {
        n = DESK_TEXT_MAX;
    }
    if (strlen(to) == n && memcmp(to, text, n) == 0) {
        return;
    }
    memcpy(to, text, n);
    to[n] = 0;
    if (which == 1) {
        draw_frame(p, w);
        act(p, DESK_ACT_DRAW_PANEL, 0, 0, 0);
    }
}

void desk_sync(desk_policy *p, uint32_t id, int32_t x, int32_t y, int32_t w, int32_t h,
               int focused)
{
    desk_win *c = find(p, id);
    if (!c) {
        return;
    }
    c->x = x;
    c->y = y;
    c->w = w;
    c->h = h;
    if (focused && p->focus != id) {
        focus_to(p, c, 0);
    }
}

void desk_set_hidden(desk_policy *p, uint32_t id, int hidden)
{
    desk_win *w = find(p, id);
    if (w && w->hidden != !!hidden) {
        w->hidden = !!hidden;
        act(p, DESK_ACT_DRAW_PANEL, 0, 0, 0);
    }
}

/* ---- closing ---- */

static void request_close(desk_policy *p, desk_win *w)
{
    if (!w->close_asked) {
        w->close_asked = 1;
        w->close_at_ms = p->now_ms;
    }
    act(p, DESK_ACT_CLOSE, w->id, 0, 0);
}

void desk_tick(desk_policy *p)
{
    for (int i = 0; i < DESK_MAX_WINDOWS; i++) {
        desk_win *w = &p->win[i];
        if (w->used && w->close_asked && !w->termed &&
            (uint32_t)(p->now_ms - w->close_at_ms) >= DESK_CLOSE_MS) {
            w->termed = 1;
            act(p, DESK_ACT_TERM, w->id, 0, 0);
        }
    }
}

int desk_next_deadline(const desk_policy *p)
{
    int best = -1;
    for (int i = 0; i < DESK_MAX_WINDOWS; i++) {
        const desk_win *w = &p->win[i];
        if (!w->used || !w->close_asked || w->termed) {
            continue;
        }
        uint32_t spent = p->now_ms - w->close_at_ms;
        int left = spent >= DESK_CLOSE_MS ? 0 : (int)(DESK_CLOSE_MS - spent);
        if (best < 0 || left < best) {
            best = left;
        }
    }
    return best;
}

/* ---- the keys ---- */

/* Super and Tab: the window after the one with the focus in the order the
 * windows were made (before it with Shift), the hidden ones skipped. */
static void cycle(desk_policy *p, int backwards)
{
    int start = -1;
    for (int i = 0; i < DESK_MAX_WINDOWS; i++) {
        if (p->win[i].used && p->win[i].id == p->focus) {
            start = i;
        }
    }
    int step = backwards ? DESK_MAX_WINDOWS - 1 : 1;
    int at = start;
    if (start < 0) {
        /* No window has the focus: the first, or the last going back. */
        at = backwards ? 0 : DESK_MAX_WINDOWS - 1;
    }
    for (int tried = 0; tried < DESK_MAX_WINDOWS; tried++) {
        at = (at + step) % DESK_MAX_WINDOWS;
        desk_win *w = &p->win[at];
        if (w->used && !w->hidden) {
            if (w->id != p->focus) {
                focus_to(p, w, 1);
            }
            return;
        }
    }
}

void desk_key(desk_policy *p, uint16_t code, int32_t value)
{
    unsigned *mask = NULL;
    unsigned bit = 0;
    switch (code) {
    case DESK_KEY_LEFTMETA: mask = &p->super_keys; bit = 1; break;
    case DESK_KEY_RIGHTMETA: mask = &p->super_keys; bit = 2; break;
    case DESK_KEY_LEFTSHIFT: mask = &p->shift_keys; bit = 1; break;
    case DESK_KEY_RIGHTSHIFT: mask = &p->shift_keys; bit = 2; break;
    default: break;
    }
    if (mask) {
        if (value) {
            *mask |= bit;
        } else {
            *mask &= ~bit;
        }
        return;
    }
    if (value != 1 || !p->super_keys) {
        return;
    }
    switch (code) {
    case DESK_KEY_TAB:
        cycle(p, p->shift_keys != 0);
        break;
    case DESK_KEY_Q: {
        desk_win *w = p->focus == DESK_NO_WINDOW ? NULL : find(p, p->focus);
        if (w) {
            request_close(p, w);
        }
        break;
    }
    case DESK_KEY_ESC:
        act(p, DESK_ACT_QUIT, 0, 0, 0);
        break;
    default:
        break;
    }
}

/* ---- the pointer ---- */

void desk_frame_button(desk_policy *p, uint32_t id, int down, int32_t x, int32_t y)
{
    desk_win *w = find(p, id);
    if (!w || !w->framed) {
        return;
    }
    int zone = desk_zone(w->w + 2 * DESK_BORDER, x, y);
    if (down) {
        p->press.id = id;
        p->press.zone = zone;
        if (zone == DESK_ZONE_TITLE) {
            p->drag.active = 1;
            p->drag.id = id;
            p->drag.grab_x = x;
            p->drag.grab_y = y;
        }
        /* The press gave the window the focus (the service did, with the top place). */
        focus_to(p, w, 0);
        return;
    }
    if (p->press.id == id && p->press.zone == DESK_ZONE_CLOSE && zone == DESK_ZONE_CLOSE) {
        request_close(p, w);
    }
    p->press.id = DESK_NO_WINDOW;
    if (p->drag.active && p->drag.id == id) {
        p->drag.active = 0;
        p->drag.id = DESK_NO_WINDOW;
    }
}

void desk_frame_move(desk_policy *p, uint32_t id, int32_t x, int32_t y)
{
    if (!p->drag.active || p->drag.id != id) {
        return;
    }
    desk_win *w = find(p, id);
    if (!w) {
        return;
    }
    int32_t nx = w->x + (x - p->drag.grab_x);
    int32_t ny = w->y + (y - p->drag.grab_y);
    keep_frame_inside(p, w->w, w->h, &nx, &ny);
    if (nx != w->x || ny != w->y) {
        w->x = nx;
        w->y = ny;
        act(p, DESK_ACT_MOVE, id, nx, ny);
    }
}

/* ---- the panel ---- */

unsigned desk_cells(const desk_policy *p)
{
    unsigned n = 0;
    for (int i = 0; i < DESK_MAX_WINDOWS; i++) {
        n += p->win[i].used != 0;
    }
    return n;
}

int32_t desk_cell_width(const desk_policy *p)
{
    unsigned n = desk_cells(p);
    int32_t w = n ? p->screen_w / (int32_t)n : DESK_CELL_MAX;
    return w < DESK_CELL_MAX ? w : DESK_CELL_MAX;
}

const desk_win *desk_cell(const desk_policy *p, unsigned i)
{
    return i < DESK_MAX_WINDOWS && p->win[i].used ? &p->win[i] : NULL;
}

void desk_panel_button(desk_policy *p, int down, int32_t x, int32_t y)
{
    if (!down || y < 0 || y >= DESK_PANEL_H || x < 0) {
        return;
    }
    /* The press gave the focus to the panel's window; a cell names the window
     * to give it to, and anywhere else on the panel it goes back. */
    int32_t cell = desk_cell_width(p);
    const desk_win *w = x / cell < (int32_t)desk_cells(p) ? desk_cell(p, (unsigned)(x / cell)) : NULL;
    if (!w && p->focus != DESK_NO_WINDOW) {
        w = find(p, p->focus);
    }
    if (w) {
        focus_to(p, (desk_win *)w, 0);
        act(p, DESK_ACT_FOCUS, w->id, 0, 0);
    }
}
