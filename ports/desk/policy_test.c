/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The host test of policy.c (tools/test_desk_port.py): every event of the
 * policy and every key, with the actions it queues compared as text. Prints
 * the number of checks that passed, or the line of the first that failed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "policy.h"

static unsigned checks;

#define EXPECT(cond)                                                               \
    do {                                                                           \
        checks++;                                                                  \
        if (!(cond)) {                                                             \
            printf("policy_test: check failed at line %d: %s\n", __LINE__, #cond); \
            exit(1);                                                               \
        }                                                                          \
    } while (0)

/* The queued actions as one line: "KIND id a b;" with the fields the kind uses. */
static const char *drain(desk_policy *p)
{
    static char line[1024];
    char one[64];
    line[0] = 0;
    desk_action a;
    while (desk_next(p, &a)) {
        switch (a.kind) {
        case DESK_ACT_FOCUS: snprintf(one, sizeof one, "FOCUS %u;", a.id); break;
        case DESK_ACT_MOVE: snprintf(one, sizeof one, "MOVE %u %d %d;", a.id, a.a, a.b); break;
        case DESK_ACT_CLOSE: snprintf(one, sizeof one, "CLOSE %u;", a.id); break;
        case DESK_ACT_TERM: snprintf(one, sizeof one, "TERM %u;", a.id); break;
        case DESK_ACT_FRAME: snprintf(one, sizeof one, "FRAME %u;", a.id); break;
        case DESK_ACT_UNFRAME: snprintf(one, sizeof one, "UNFRAME %u;", a.id); break;
        case DESK_ACT_DRAW_FRAME: snprintf(one, sizeof one, "DRAWF %u;", a.id); break;
        case DESK_ACT_DRAW_PANEL: snprintf(one, sizeof one, "DRAWP;"); break;
        case DESK_ACT_PANEL_SHOWN: snprintf(one, sizeof one, "PANEL %d;", a.a); break;
        case DESK_ACT_QUIT: snprintf(one, sizeof one, "QUIT;"); break;
        default: snprintf(one, sizeof one, "?%d;", a.kind); break;
        }
        strcat(line, one);
    }
    return line;
}

static void actions_are(desk_policy *p, const char *want, int line)
{
    const char *got = drain(p);
    checks++;
    if (strcmp(got, want) != 0) {
        printf("policy_test: check failed at line %d: actions\n  got  %s\n  want %s\n", line, got, want);
#ifndef SOFT
        exit(1);
#endif
    }
}

#define ACTIONS(p, text) actions_are(p, text, __LINE__)

static void fresh(desk_policy *p)
{
    desk_init(p, 640, 400);
    desk_time(p, 1000);
}

/* A framed window of 200 by 120 at (60, 80), the id the number. */
static void make(desk_policy *p, uint32_t id, int32_t x, int32_t y)
{
    EXPECT(desk_created(p, id, x, y, 200, 120, 0) == 0);
    (void)drain(p);
}

static void key(desk_policy *p, uint16_t code, int32_t value)
{
    desk_key(p, code, value);
}

static void chord(desk_policy *p, uint16_t code)
{
    key(p, DESK_KEY_LEFTMETA, 1);
    key(p, code, 1);
    key(p, code, 0);
    key(p, DESK_KEY_LEFTMETA, 0);
}

static void geometry(void)
{
    int32_t fx, fy, fw, fh;
    desk_frame_rect(60, 80, 200, 120, &fx, &fy, &fw, &fh);
    EXPECT(fx == 56 && fy == 56 && fw == 208 && fh == 148);
    EXPECT(desk_zone(208, 10, 10) == DESK_ZONE_TITLE);
    EXPECT(desk_zone(208, 183, 10) == DESK_ZONE_TITLE);
    EXPECT(desk_zone(208, 184, 0) == DESK_ZONE_CLOSE);
    EXPECT(desk_zone(208, 207, 23) == DESK_ZONE_CLOSE);
    EXPECT(desk_zone(208, 207, 24) == DESK_ZONE_NONE);
    EXPECT(desk_zone(208, 208, 10) == DESK_ZONE_NONE);
    EXPECT(desk_zone(208, -1, 10) == DESK_ZONE_NONE);
    desk_policy p;
    fresh(&p);
    /* The frame must fit below the panel: 632 by 372 is the biggest width and a
     * little less than the biggest height. */
    EXPECT(desk_frameable(&p, 0, 632, 348));
    EXPECT(!desk_frameable(&p, 0, 633, 100));
    EXPECT(!desk_frameable(&p, 0, 100, 349));
    EXPECT(!desk_frameable(&p, 1, 100, 100));
    EXPECT(!desk_frameable(&p, 0, 640, 400));
    EXPECT(!desk_frameable(&p, 0, 0, 100));
}

static void a_window_is_framed_and_gets_the_focus(void)
{
    desk_policy p;
    fresh(&p);
    EXPECT(desk_created(&p, 7, 60, 80, 200, 120, 0) == 0);
    ACTIONS(&p, "DRAWP;FRAME 7;FOCUS 7;");
    EXPECT(p.focus == 7 && desk_cells(&p) == 1);
    /* The second window: the first stops being the focus (its frame is drawn
     * again), the second is framed and takes it. */
    EXPECT(desk_created(&p, 9, 300, 105, 220, 140, 0) == 0);
    ACTIONS(&p, "DRAWF 7;DRAWP;FRAME 9;FOCUS 9;");
    EXPECT(p.focus == 9 && desk_cells(&p) == 2);
    /* The same window told twice is no new window. */
    EXPECT(desk_created(&p, 9, 300, 105, 220, 140, 0) == 0);
    ACTIONS(&p, "");
    EXPECT(desk_cells(&p) == 2);
}

static void a_window_whose_frame_would_not_fit_is_moved(void)
{
    desk_policy p;
    fresh(&p);
    /* At (0, 0) the frame would lie off the screen and under the panel. */
    EXPECT(desk_created(&p, 1, 0, 0, 200, 120, 0) == 0);
    ACTIONS(&p, "MOVE 1 4 48;DRAWP;FRAME 1;FOCUS 1;");
    EXPECT(desk_find(&p, 1)->x == 4 && desk_find(&p, 1)->y == 48);
    /* Too far right and down. */
    EXPECT(desk_created(&p, 2, 600, 390, 200, 120, 0) == 0);
    ACTIONS(&p, "MOVE 2 436 276;DRAWF 1;DRAWP;FRAME 2;FOCUS 2;");
}

static void windows_with_no_frame_and_the_panel(void)
{
    desk_policy p;
    fresh(&p);
    /* A window of the screen's size has no frame and hides the panel. */
    EXPECT(desk_created(&p, 1, 0, 0, 640, 400, 0) == 0);
    ACTIONS(&p, "DRAWP;PANEL 0;FOCUS 1;");
    EXPECT(!p.panel_shown);
    /* A framed window with the focus shows it again. */
    EXPECT(desk_created(&p, 2, 60, 80, 200, 120, 0) == 0);
    ACTIONS(&p, "DRAWP;PANEL 1;FRAME 2;FOCUS 2;");
    EXPECT(p.panel_shown);
    /* Going back to the big one (Super and Tab) hides it. */
    chord(&p, DESK_KEY_TAB);
    ACTIONS(&p, "DRAWF 2;DRAWP;PANEL 0;FOCUS 1;");
    /* A window of the first revision has no frame either and hides the panel
     * with the focus, however small. */
    desk_policy q;
    fresh(&q);
    EXPECT(desk_created(&q, 3, 100, 100, 100, 100, 1) == 0);
    ACTIONS(&q, "DRAWP;PANEL 0;FOCUS 3;");
    EXPECT(!desk_find(&q, 3)->framed);
    /* A window almost the screen's size but with a frame that does not fit has
     * none, and the panel stays (the window does not cover the screen). */
    desk_policy r;
    fresh(&r);
    EXPECT(desk_created(&r, 4, 4, 30, 632, 366, 0) == 0);
    ACTIONS(&r, "DRAWP;FOCUS 4;");
    EXPECT(r.panel_shown && !desk_find(&r, 4)->framed);
    /* A frame the program could not make: the window stays without one. */
    desk_policy s;
    fresh(&s);
    make(&s, 5, 60, 80);
    desk_frame_failed(&s, 5);
    ACTIONS(&s, "DRAWP;");
    EXPECT(!desk_find(&s, 5)->framed);
    /* No pointer event of a frame the window does not have. */
    desk_frame_button(&s, 5, 1, 10, 10);
    ACTIONS(&s, "");
}

static void there_is_room_for_sixteen_windows(void)
{
    desk_policy p;
    fresh(&p);
    for (uint32_t i = 1; i <= DESK_MAX_WINDOWS; i++) {
        EXPECT(desk_created(&p, i, 60, 80, 100, 100, 0) == 0);
    }
    (void)drain(&p);
    EXPECT(desk_created(&p, 99, 60, 80, 100, 100, 0) == -1);
    ACTIONS(&p, "");
    EXPECT(desk_cells(&p) == DESK_MAX_WINDOWS && desk_find(&p, 99) == NULL);
    desk_gone(&p, 3);
    (void)drain(&p);
    EXPECT(desk_created(&p, 99, 60, 80, 100, 100, 0) == 0);
}

static void a_title_redraws_the_frame_and_the_panel(void)
{
    desk_policy p;
    fresh(&p);
    make(&p, 1, 60, 80);
    make(&p, 2, 300, 105);
    desk_text(&p, 1, 1, "alpha");
    ACTIONS(&p, "DRAWF 1;DRAWP;");
    EXPECT(strcmp(desk_find(&p, 1)->title, "alpha") == 0);
    /* The same text again, the kind of the program (no title), a window that
     * is none and a text that is too long. */
    desk_text(&p, 1, 1, "alpha");
    desk_text(&p, 1, 2, "alpha-app");
    desk_text(&p, 77, 1, "x");
    desk_text(&p, 1, 3, "x");
    ACTIONS(&p, "");
    EXPECT(strcmp(desk_find(&p, 1)->app_id, "alpha-app") == 0);
    char big[200];
    memset(big, 'x', sizeof big - 1);
    big[sizeof big - 1] = 0;
    desk_text(&p, 2, 1, big);
    EXPECT(strlen(desk_find(&p, 2)->title) == DESK_TEXT_MAX);
}

static void the_focus_goes_to_the_window_that_had_it_last(void)
{
    desk_policy p;
    fresh(&p);
    make(&p, 1, 60, 80);
    make(&p, 2, 300, 105);
    make(&p, 3, 100, 230);
    /* Window 1 is clicked (the service gave it the focus), then 3 is: 3 had it
     * last, then 1. */
    desk_frame_button(&p, 1, 1, 50, 50);
    desk_frame_button(&p, 1, 0, 50, 50);
    (void)drain(&p);
    desk_gone(&p, 1);
    ACTIONS(&p, "UNFRAME 1;DRAWF 3;DRAWP;FOCUS 3;DRAWP;");
    EXPECT(p.focus == 3);
    /* A window that is not the focus goes: nothing is asked of the service. */
    desk_gone(&p, 2);
    ACTIONS(&p, "UNFRAME 2;DRAWP;");
    EXPECT(p.focus == 3);
    desk_gone(&p, 3);
    ACTIONS(&p, "UNFRAME 3;DRAWP;");
    EXPECT(p.focus == DESK_NO_WINDOW && desk_cells(&p) == 0);
    desk_gone(&p, 3);
    ACTIONS(&p, "");
}

static void super_and_tab_go_round(void)
{
    desk_policy p;
    fresh(&p);
    make(&p, 1, 60, 80);
    make(&p, 2, 300, 105);
    make(&p, 3, 100, 230);
    EXPECT(p.focus == 3);
    /* Forward, in the order the windows were made, round the end. */
    chord(&p, DESK_KEY_TAB);
    ACTIONS(&p, "DRAWF 3;DRAWF 1;DRAWP;FOCUS 1;");
    EXPECT(p.focus == 1);
    chord(&p, DESK_KEY_TAB);
    ACTIONS(&p, "DRAWF 1;DRAWF 2;DRAWP;FOCUS 2;");
    chord(&p, DESK_KEY_TAB);
    ACTIONS(&p, "DRAWF 2;DRAWF 3;DRAWP;FOCUS 3;");
    /* Backwards with Shift (pressed after Super, as the service has it). */
    key(&p, DESK_KEY_LEFTMETA, 1);
    key(&p, DESK_KEY_LEFTSHIFT, 1);
    key(&p, DESK_KEY_TAB, 1);
    key(&p, DESK_KEY_TAB, 0);
    key(&p, DESK_KEY_LEFTSHIFT, 0);
    key(&p, DESK_KEY_LEFTMETA, 0);
    ACTIONS(&p, "DRAWF 3;DRAWF 2;DRAWP;FOCUS 2;");
    /* The right Super and the right Shift too. */
    key(&p, DESK_KEY_RIGHTMETA, 1);
    key(&p, DESK_KEY_RIGHTSHIFT, 1);
    key(&p, DESK_KEY_TAB, 1);
    ACTIONS(&p, "DRAWF 2;DRAWF 1;DRAWP;FOCUS 1;");
    /* With Shift let go it goes forward again, with Super still held. */
    key(&p, DESK_KEY_RIGHTSHIFT, 0);
    key(&p, DESK_KEY_TAB, 1);
    ACTIONS(&p, "DRAWF 1;DRAWF 2;DRAWP;FOCUS 2;");
    key(&p, DESK_KEY_RIGHTMETA, 0);
    /* Backwards round the beginning. */
    key(&p, DESK_KEY_LEFTMETA, 1);
    key(&p, DESK_KEY_LEFTSHIFT, 1);
    key(&p, DESK_KEY_TAB, 1);
    (void)drain(&p);
    key(&p, DESK_KEY_TAB, 1);
    ACTIONS(&p, "DRAWF 1;DRAWF 3;DRAWP;FOCUS 3;");
    key(&p, DESK_KEY_LEFTSHIFT, 0);
    key(&p, DESK_KEY_LEFTMETA, 0);
    /* Tab with no Super is the window's: nothing here. Super alone too. */
    key(&p, DESK_KEY_TAB, 1);
    key(&p, DESK_KEY_LEFTMETA, 1);
    key(&p, DESK_KEY_LEFTMETA, 0);
    ACTIONS(&p, "");
    /* A release of Tab is no cycle. */
    key(&p, DESK_KEY_LEFTMETA, 1);
    key(&p, DESK_KEY_TAB, 0);
    key(&p, DESK_KEY_LEFTMETA, 0);
    ACTIONS(&p, "");
}

static void super_and_tab_skip_a_hidden_window(void)
{
    desk_policy p;
    fresh(&p);
    make(&p, 1, 60, 80);
    make(&p, 2, 300, 105);
    make(&p, 3, 100, 230);
    desk_set_hidden(&p, 1, 1);
    ACTIONS(&p, "DRAWP;");
    /* From 3 forward: 1 is hidden, so 2. */
    chord(&p, DESK_KEY_TAB);
    ACTIONS(&p, "DRAWF 3;DRAWF 2;DRAWP;FOCUS 2;");
    /* Backward from 2: 1 is hidden, so 3. */
    key(&p, DESK_KEY_LEFTMETA, 1);
    key(&p, DESK_KEY_LEFTSHIFT, 1);
    key(&p, DESK_KEY_TAB, 1);
    ACTIONS(&p, "DRAWF 2;DRAWF 3;DRAWP;FOCUS 3;");
    key(&p, DESK_KEY_LEFTSHIFT, 0);
    key(&p, DESK_KEY_LEFTMETA, 0);
    desk_set_hidden(&p, 1, 0);
    (void)drain(&p);
    chord(&p, DESK_KEY_TAB);
    ACTIONS(&p, "DRAWF 3;DRAWF 1;DRAWP;FOCUS 1;");
    /* One window with the focus and the rest hidden: nothing to go to. */
    desk_set_hidden(&p, 2, 1);
    desk_set_hidden(&p, 3, 1);
    (void)drain(&p);
    chord(&p, DESK_KEY_TAB);
    ACTIONS(&p, "");
    /* A hidden window does not take the focus when the focused one goes. */
    desk_gone(&p, 1);
    ACTIONS(&p, "UNFRAME 1;DRAWP;");
    EXPECT(p.focus == DESK_NO_WINDOW);
}

static void one_window_and_none_have_nowhere_to_go(void)
{
    desk_policy p;
    fresh(&p);
    chord(&p, DESK_KEY_TAB);
    ACTIONS(&p, "");
    make(&p, 1, 60, 80);
    chord(&p, DESK_KEY_TAB);
    ACTIONS(&p, "");
    /* No window has the focus (the panel's click went nowhere): Tab takes the
     * first, Shift and Tab the last. */
    desk_policy q;
    fresh(&q);
    make(&q, 1, 60, 80);
    make(&q, 2, 300, 105);
    desk_gone(&q, 2);
    desk_gone(&q, 1);
    (void)drain(&q);
    EXPECT(q.focus == DESK_NO_WINDOW);
}

static void super_and_q_ask_the_focused_window_to_close(void)
{
    desk_policy p;
    fresh(&p);
    make(&p, 1, 60, 80);
    make(&p, 2, 300, 105);
    chord(&p, DESK_KEY_Q);
    ACTIONS(&p, "CLOSE 2;");
    /* Q alone is the window's. */
    key(&p, DESK_KEY_Q, 1);
    ACTIONS(&p, "");
    /* With no window nothing happens. */
    desk_policy q;
    fresh(&q);
    chord(&q, DESK_KEY_Q);
    ACTIONS(&q, "");
}

static void a_window_that_does_not_close_gets_sigterm_after_five_seconds(void)
{
    desk_policy p;
    fresh(&p);
    make(&p, 1, 60, 80);
    make(&p, 2, 300, 105);
    EXPECT(desk_next_deadline(&p) == -1);
    desk_time(&p, 2000);
    chord(&p, DESK_KEY_Q);
    ACTIONS(&p, "CLOSE 2;");
    EXPECT(desk_next_deadline(&p) == DESK_CLOSE_MS);
    desk_time(&p, 2000 + 4999);
    desk_tick(&p);
    ACTIONS(&p, "");
    EXPECT(desk_next_deadline(&p) == 1);
    /* Asking again does not start the five seconds over. */
    chord(&p, DESK_KEY_Q);
    ACTIONS(&p, "CLOSE 2;");
    EXPECT(desk_next_deadline(&p) == 1);
    desk_time(&p, 2000 + 5000);
    desk_tick(&p);
    ACTIONS(&p, "TERM 2;");
    EXPECT(desk_next_deadline(&p) == -1);
    /* SIGTERM is sent once. */
    desk_time(&p, 2000 + 9000);
    desk_tick(&p);
    ACTIONS(&p, "");
    /* A window that closes in time is not sent one: it is gone. */
    desk_policy q;
    fresh(&q);
    make(&q, 1, 60, 80);
    desk_time(&q, 5000);
    chord(&q, DESK_KEY_Q);
    (void)drain(&q);
    desk_gone(&q, 1);
    (void)drain(&q);
    desk_time(&q, 20000);
    desk_tick(&q);
    ACTIONS(&q, "");
    EXPECT(desk_next_deadline(&q) == -1);
    /* The clock may wrap: the time since the ask is the unsigned difference. */
    desk_policy r;
    fresh(&r);
    make(&r, 1, 60, 80);
    desk_time(&r, 0xFFFFFFF0u);
    chord(&r, DESK_KEY_Q);
    (void)drain(&r);
    desk_time(&r, 4974u);   /* 4990 ms after the ask, the clock having wrapped */
    desk_tick(&r);
    ACTIONS(&r, "");
    desk_time(&r, 4984u);
    desk_tick(&r);
    ACTIONS(&r, "TERM 1;");
}

static void super_and_escape_end_the_manager(void)
{
    desk_policy p;
    fresh(&p);
    chord(&p, DESK_KEY_ESC);
    ACTIONS(&p, "QUIT;");
    key(&p, DESK_KEY_ESC, 1);
    ACTIONS(&p, "");
}

static void the_close_button_asks_when_pressed_and_let_go_on_it(void)
{
    desk_policy p;
    fresh(&p);
    make(&p, 1, 60, 80);       /* the frame is 208 wide: the button is x 184 to 207 */
    desk_frame_button(&p, 1, 1, 190, 10);
    desk_frame_button(&p, 1, 0, 190, 10);
    ACTIONS(&p, "CLOSE 1;");
    /* Pressed on it and let go elsewhere on the frame: no close. */
    desk_policy q;
    fresh(&q);
    make(&q, 1, 60, 80);
    desk_frame_button(&q, 1, 1, 190, 10);
    desk_frame_button(&q, 1, 0, 100, 10);
    ACTIONS(&q, "");
    /* Pressed on the bar and let go on the button: no close. */
    desk_frame_button(&q, 1, 1, 100, 10);
    desk_frame_button(&q, 1, 0, 190, 10);
    ACTIONS(&q, "");
    /* The edges of the button. */
    desk_frame_button(&q, 1, 1, 184, 0);
    desk_frame_button(&q, 1, 0, 207, 23);
    ACTIONS(&q, "CLOSE 1;");
    desk_frame_button(&q, 1, 1, 183, 0);
    desk_frame_button(&q, 1, 0, 183, 0);
    ACTIONS(&q, "");
    /* A release that was never pressed. */
    desk_frame_button(&q, 1, 0, 190, 10);
    ACTIONS(&q, "");
}

static void the_title_bar_drags_the_window(void)
{
    desk_policy p;
    fresh(&p);
    make(&p, 1, 60, 80);       /* the frame at (56, 56) */
    make(&p, 2, 300, 105);
    desk_frame_button(&p, 1, 1, 94, 19);   /* the press on the bar of 1: it has the focus */
    ACTIONS(&p, "DRAWF 2;DRAWF 1;DRAWP;");
    EXPECT(p.focus == 1 && p.drag.active);
    /* The pointer moves by (+50, +50) of the screen: the frame has not moved yet. */
    desk_frame_move(&p, 1, 144, 69);
    ACTIONS(&p, "MOVE 1 110 130;");
    EXPECT(desk_find(&p, 1)->x == 110 && desk_find(&p, 1)->y == 130);
    /* The frame is at its new place: the point of the pointer in it is the
     * grab point, so no move. */
    desk_frame_move(&p, 1, 94, 19);
    ACTIONS(&p, "");
    /* Past the left edge and the top: the frame stays inside, below the panel. */
    desk_frame_move(&p, 1, -500, -500);
    ACTIONS(&p, "MOVE 1 4 48;");
    /* Past the right edge and the bottom: x is 640 - 200 - 4, y is 400 - 120 - 4. */
    desk_frame_move(&p, 1, 900, 900);
    ACTIONS(&p, "MOVE 1 436 276;");
    desk_frame_button(&p, 1, 0, 94, 19);
    ACTIONS(&p, "");
    EXPECT(!p.drag.active);
    /* After the release a move drags nothing. */
    desk_frame_move(&p, 1, 0, 0);
    ACTIONS(&p, "");
    /* A press on the body of the frame (or its edge) drags nothing. */
    desk_frame_button(&p, 1, 1, 100, 60);
    EXPECT(!p.drag.active);
    desk_frame_button(&p, 1, 0, 100, 60);
    (void)drain(&p);
    /* A move of another window's frame is no drag of this one. */
    desk_frame_button(&p, 2, 1, 50, 10);
    (void)drain(&p);
    desk_frame_move(&p, 1, 0, 0);
    ACTIONS(&p, "");
    /* The window going ends the drag. */
    desk_gone(&p, 2);
    (void)drain(&p);
    EXPECT(!p.drag.active);
}

static void the_panel_gives_the_focus_to_the_cell_clicked(void)
{
    desk_policy p;
    fresh(&p);
    make(&p, 1, 60, 80);
    make(&p, 2, 300, 105);
    make(&p, 3, 100, 230);
    EXPECT(desk_cells(&p) == 3 && desk_cell_width(&p) == 160);
    EXPECT(desk_cell(&p, 0)->id == 1 && desk_cell(&p, 2)->id == 3 && desk_cell(&p, 3) == NULL);
    desk_panel_button(&p, 1, 10, 10);
    ACTIONS(&p, "DRAWF 3;DRAWF 1;DRAWP;FOCUS 1;");
    /* The same window again: the service gave the focus to the panel, so it
     * is given back. */
    desk_panel_button(&p, 1, 150, 12);
    ACTIONS(&p, "FOCUS 1;");
    desk_panel_button(&p, 1, 160, 0);
    ACTIONS(&p, "DRAWF 1;DRAWF 2;DRAWP;FOCUS 2;");
    desk_panel_button(&p, 1, 479, 23);
    ACTIONS(&p, "DRAWF 2;DRAWF 3;DRAWP;FOCUS 3;");
    /* Past the cells, the focus goes back to the window that had it. */
    desk_panel_button(&p, 1, 480, 10);
    ACTIONS(&p, "FOCUS 3;");
    /* The release, a point below the panel and a point off it are nothing. */
    desk_panel_button(&p, 0, 10, 10);
    desk_panel_button(&p, 1, 10, 24);
    desk_panel_button(&p, 1, -1, 10);
    ACTIONS(&p, "");
    /* The cells narrow with many windows and stay 160 wide with few. */
    desk_policy q;
    fresh(&q);
    for (uint32_t i = 1; i <= 5; i++) {
        make(&q, i, 60, 80);
    }
    EXPECT(desk_cell_width(&q) == 128);
    desk_panel_button(&q, 1, 128 * 3 + 1, 5);
    ACTIONS(&q, "DRAWF 5;DRAWF 4;DRAWP;FOCUS 4;");
    desk_policy r;
    fresh(&r);
    make(&r, 1, 60, 80);
    EXPECT(desk_cell_width(&r) == 160);
    desk_policy s;
    fresh(&s);
    EXPECT(desk_cells(&s) == 0 && desk_cell_width(&s) == DESK_CELL_MAX);
    desk_panel_button(&s, 1, 10, 10);
    ACTIONS(&s, "");
}

static void the_list_of_the_service_moves_the_model(void)
{
    desk_policy p;
    fresh(&p);
    make(&p, 1, 60, 80);
    make(&p, 2, 300, 105);
    desk_sync(&p, 1, 70, 90, 200, 120, 1);
    ACTIONS(&p, "DRAWF 2;DRAWF 1;DRAWP;");
    EXPECT(p.focus == 1 && desk_find(&p, 1)->x == 70 && desk_find(&p, 1)->y == 90);
    /* A window with no focus flag changes nothing of the focus (the panel
     * holds it for a moment after a click). */
    desk_sync(&p, 2, 300, 105, 220, 140, 0);
    ACTIONS(&p, "");
    EXPECT(p.focus == 1);
    desk_sync(&p, 99, 0, 0, 1, 1, 1);
    ACTIONS(&p, "");
}

int main(void)
{
    geometry();
    a_window_is_framed_and_gets_the_focus();
    a_window_whose_frame_would_not_fit_is_moved();
    windows_with_no_frame_and_the_panel();
    there_is_room_for_sixteen_windows();
    a_title_redraws_the_frame_and_the_panel();
    the_focus_goes_to_the_window_that_had_it_last();
    super_and_tab_go_round();
    super_and_tab_skip_a_hidden_window();
    one_window_and_none_have_nowhere_to_go();
    super_and_q_ask_the_focused_window_to_close();
    a_window_that_does_not_close_gets_sigterm_after_five_seconds();
    super_and_escape_end_the_manager();
    the_close_button_asks_when_pressed_and_let_go_on_it();
    the_title_bar_drags_the_window();
    the_panel_gives_the_focus_to_the_cell_clicked();
    the_list_of_the_service_moves_the_model();
    printf("policy_test: %u checks passed\n", checks);
    return 0;
}
