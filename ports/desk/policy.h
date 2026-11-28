/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The policy of the window manager `desk`: what the manager does when a
 * window is made or goes, when a title changes, when a key or the pointer
 * comes. It is a model of the windows with no call to the composition
 * service: each function takes an event and queues the actions the program
 * (main.c) carries out with the manager's calls, in order. The host tests
 * (policy_test.c) run it with events and compare the actions; the geometry of
 * the frames and of the panel lives here too, so that the drawing (draw.c) and
 * the hit tests agree.
 *
 * A window with a frame is a window of a client that is not of the first
 * revision and fits the screen with its frame below the panel. The frame is a
 * window of the manager's own, linked under the client's: DESK_BORDER points
 * wider on each side and below, and DESK_BAR points above, with the title and
 * the close button in the bar. A window of the first revision, a window too big
 * to carry a frame (the whole screen, say) and a window the program could not
 * make a frame for have none. The panel is a strip of DESK_PANEL_H points at
 * the top of the screen with a cell for each window, and it is hidden while
 * the window with the focus has no frame and covers the screen or is of the
 * first revision. */
#ifndef DESK_POLICY_H
#define DESK_POLICY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DESK_MAX_WINDOWS 16
#define DESK_TEXT_MAX 64
#define DESK_NO_WINDOW 0xFFFFFFFFu

#define DESK_PANEL_H 24
#define DESK_BORDER 4
#define DESK_BAR 24
#define DESK_CLOSE_W 24
#define DESK_CELL_MAX 160
/* How long a window may take to close after it was asked to before its
 * process gets SIGTERM. */
#define DESK_CLOSE_MS 5000

/* Linux's key codes the policy reads. */
#define DESK_KEY_ESC 1
#define DESK_KEY_Q 16
#define DESK_KEY_TAB 15
#define DESK_KEY_LEFTSHIFT 42
#define DESK_KEY_RIGHTSHIFT 54
#define DESK_KEY_LEFTMETA 125
#define DESK_KEY_RIGHTMETA 126

enum desk_action_kind {
    DESK_ACT_FOCUS = 1,    /* give window id the focus (and the top place) */
    DESK_ACT_MOVE,         /* move window id so that its top left point is (a, b) */
    DESK_ACT_CLOSE,        /* ask window id to close */
    DESK_ACT_TERM,         /* the process of window id did not close: SIGTERM */
    DESK_ACT_FRAME,        /* make a frame for window id */
    DESK_ACT_UNFRAME,      /* the frame of window id goes */
    DESK_ACT_DRAW_FRAME,   /* draw the frame of window id again */
    DESK_ACT_DRAW_PANEL,   /* draw the panel again */
    DESK_ACT_PANEL_SHOWN,  /* show the panel (a is 1) or hide it (a is 0) */
    DESK_ACT_QUIT,         /* the manager ends */
};

typedef struct desk_action {
    int kind;
    uint32_t id;
    int32_t a, b;
} desk_action;

/* The most actions an event queues (a window made queues five), and the room of
 * the queue: the program takes the actions after each event. */
#define DESK_ACTIONS_MAX 64

typedef struct desk_win {
    int used;
    uint32_t id;
    int32_t x, y, w, h;    /* the client's window, in points of the screen */
    int legacy;            /* a window of the first revision */
    int framed;            /* a frame was asked for and has not failed */
    int hidden;            /* hidden by the manager: Super and Tab skip it */
    uint32_t stamp;        /* when it last had the focus (higher is later) */
    int close_asked;
    int termed;
    uint32_t close_at_ms;
    char title[DESK_TEXT_MAX + 1];
    char app_id[DESK_TEXT_MAX + 1];
} desk_win;

typedef struct desk_policy {
    int32_t screen_w, screen_h;
    desk_win win[DESK_MAX_WINDOWS];   /* in the order the windows were made */
    uint32_t focus;                   /* an id, or DESK_NO_WINDOW */
    uint32_t stamp;
    uint32_t now_ms;
    unsigned super_keys;              /* the Super keys held, one bit each (left, right) */
    unsigned shift_keys;              /* the Shift keys held */
    int panel_shown;
    struct {
        int active;
        uint32_t id;
        int32_t grab_x, grab_y;       /* the point of the bar the press was at */
    } drag;
    struct {
        uint32_t id;
        int zone;                     /* DESK_ZONE_*, of the press */
    } press;
    desk_action queue[DESK_ACTIONS_MAX];
    unsigned queued, taken;
} desk_policy;

/* The parts of a frame a point can be in. */
enum { DESK_ZONE_NONE = 0, DESK_ZONE_TITLE, DESK_ZONE_CLOSE };

void desk_init(desk_policy *p, int32_t screen_w, int32_t screen_h);

/* The time of the events that follow, in milliseconds on a monotonic clock. */
void desk_time(desk_policy *p, uint32_t now_ms);

/* The next queued action, in the order the events made them: 1 and *out set,
 * or 0 when none is left. */
int desk_next(desk_policy *p, desk_action *out);

/* Whether a window of this place and size gets a frame, and the frame's place
 * and size for a window at (x, y), w by h. */
int desk_frameable(const desk_policy *p, int legacy, int32_t w, int32_t h);
void desk_frame_rect(int32_t x, int32_t y, int32_t w, int32_t h, int32_t *fx, int32_t *fy,
                     int32_t *fw, int32_t *fh);

/* The part of a frame of width fw a point (x, y) of the frame is in. */
int desk_zone(int32_t fw, int32_t x, int32_t y);

/* A window of a client was made: id, its place and size, and whether it is of
 * the first revision. It is moved if its frame would not fit where it is, it
 * gets a frame when it can have one, and it gets the focus. 0, or -1 when the
 * manager has no room for another window (it is left alone). */
int desk_created(desk_policy *p, uint32_t id, int32_t x, int32_t y, int32_t w, int32_t h,
                 int legacy);

/* The program could not make the frame of window id: it stays without one. */
void desk_frame_failed(desk_policy *p, uint32_t id);

/* A window went. Its frame goes with it, and the focus goes to the window that
 * had it last. */
void desk_gone(desk_policy *p, uint32_t id);

/* A text of a window changed: which is 1 for the title and 2 for the kind of
 * the program. */
void desk_text(desk_policy *p, uint32_t id, int which, const char *text);

/* The service's list says window id is at (x, y), w by h, and has the focus
 * when `focused`. The program calls it for each window of the list before
 * the events of a round. */
void desk_sync(desk_policy *p, uint32_t id, int32_t x, int32_t y, int32_t w, int32_t h,
               int focused);

/* A hidden or shown window (the program's own decision): hidden windows are
 * skipped by Super and Tab. */
void desk_set_hidden(desk_policy *p, uint32_t id, int hidden);

/* A key of the manager's ring: value 1 down, 0 up. */
void desk_key(desk_policy *p, uint16_t code, int32_t value);

/* The pointer on the frame of window id: a MOVE with the point of the frame, and
 * a button (down 1, up 0) with the point of the frame. */
void desk_frame_move(desk_policy *p, uint32_t id, int32_t x, int32_t y);
void desk_frame_button(desk_policy *p, uint32_t id, int down, int32_t x, int32_t y);

/* The button on the panel, with the point of the panel. */
void desk_panel_button(desk_policy *p, int down, int32_t x, int32_t y);

/* The time has come to look at the windows that were asked to close. */
void desk_tick(desk_policy *p);

/* The milliseconds until the first overdue close, or -1 when none waits. */
int desk_next_deadline(const desk_policy *p);

/* The panel's cells: the count, the width of one, and the window of cell i (an
 * index of desk_win). */
unsigned desk_cells(const desk_policy *p);
int32_t desk_cell_width(const desk_policy *p);
const desk_win *desk_cell(const desk_policy *p, unsigned i);

/* The window with the id, or null. */
const desk_win *desk_find(const desk_policy *p, uint32_t id);

#ifdef __cplusplus
}
#endif

#endif
