/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The one source of the demo's screen and of its scenario: the demo, the
 * reference program on the host and the program that injects the events read
 * it. The places and sizes are constants, so a frame does not depend on a
 * layout pass. */
#ifndef STAFETO_SCENE_H
#define STAFETO_SCENE_H

#define DEMO_WIDTH 640
#define DEMO_HEIGHT 400
#define DEMO_STRIDE (DEMO_WIDTH * 4)
#define DEMO_BUFFER_BYTES (DEMO_STRIDE * DEMO_HEIGHT)

/* The font file of the guest image; the reference program takes its path from
 * the command line. */
#define DEMO_FONT_PATH "/usr/share/fonts/LiberationSans-Regular.ttf"

#define SCENE_TITLE "stafeto: LVGL 9.6 and FreeType 2.14"
#define SCENE_TITLE_X 20
#define SCENE_TITLE_Y 16
#define SCENE_TITLE_PX 22

#define SCENE_BODY_TEXT \
    "LVGL lays out the widgets, and FreeType draws every glyph.\n" \
    "Kerning pairs such as AV, To and Wa show in this line."
#define SCENE_BODY_X 20
#define SCENE_BODY_Y 56
#define SCENE_BODY_W 600
#define SCENE_TEXT_PX 16

#define SCENE_BUTTON_X 20
#define SCENE_BUTTON_Y 120
#define SCENE_BUTTON_W 140
#define SCENE_BUTTON_H 44
#define SCENE_BUTTON_TEXT "Press"
#define SCENE_COUNT_X 180
#define SCENE_COUNT_Y 132

#define SCENE_CHECK_X 20
#define SCENE_CHECK_Y 190
#define SCENE_CHECK_TEXT "Option"

#define SCENE_SWITCH_X 200
#define SCENE_SWITCH_Y 186
#define SCENE_SWITCH_W 60
#define SCENE_SWITCH_H 30

#define SCENE_SLIDER_X 20
#define SCENE_SLIDER_Y 250
#define SCENE_SLIDER_W 400
#define SCENE_SLIDER_H 20
#define SCENE_SLIDER_START 20
#define SCENE_VALUE_X 440
#define SCENE_VALUE_Y 244

#define SCENE_AREA_X 20
#define SCENE_AREA_Y 300
#define SCENE_AREA_W 400
#define SCENE_AREA_H 44
#define SCENE_AREA_HINT "Type here"

/* The scenario: 22 events, of which 16 are changes (a button or a key going
 * down or up; a MOVE only moves the point). The layout of a row is that of
 * struct demo_event: kind, code, value, x, y (kind 2 MOVE, 3 BUTTON with the
 * left button 0x110, 1 KEY with the Linux codes of h and i). */
#define SCENE_EVENTS 22
#define SCENE_CHANGES 16
#define SCENE_EVENT_ROWS \
    /* the button, twice */ \
    {2, 0, 0, 90, 142}, {3, 0x110, 1, 90, 142}, {3, 0x110, 0, 90, 142}, \
    {2, 0, 0, 90, 142}, {3, 0x110, 1, 90, 142}, {3, 0x110, 0, 90, 142}, \
    /* the check box */ \
    {2, 0, 0, 30, 200}, {3, 0x110, 1, 30, 200}, {3, 0x110, 0, 30, 200}, \
    /* the switch */ \
    {2, 0, 0, 230, 201}, {3, 0x110, 1, 230, 201}, {3, 0x110, 0, 230, 201}, \
    /* the slider, to three quarters */ \
    {2, 0, 0, 320, 260}, {3, 0x110, 1, 320, 260}, {3, 0x110, 0, 320, 260}, \
    /* the text area */ \
    {2, 0, 0, 220, 322}, {3, 0x110, 1, 220, 322}, {3, 0x110, 0, 220, 322}, \
    /* h and i */ \
    {1, 35, 1, 0, 0}, {1, 35, 0, 0, 0}, {1, 23, 1, 0, 0}, {1, 23, 0, 0, 0}

/* The state line the probe prints after the scenario. */
#define SCENE_STATE_FORMAT "presses %d option %d switch %d slider %d text %s"

#endif
