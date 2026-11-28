/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The drawing of the desk: the frame of a window and the panel, in LVGL
 * objects on the screen of a display that the caller made over a window's
 * buffers. The functions know nothing of windows or of the service; the
 * reference program on the host (tools/desk-ref) draws the same objects over
 * memory buffers, so the pixels are one code's. The shapes are flat
 * rectangles and clipped text: no radius, shadow or opacity, so a frame is
 * cheap to draw and does not depend on a layer buffer. */
#ifndef DESK_DRAW_H
#define DESK_DRAW_H

#include <stdint.h>

#include "lvgl.h"

#include "policy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The colours (0xRRGGBB). */
#define DESK_COLOR_FOCUS 0x3A6EA5
#define DESK_COLOR_IDLE 0x7A7A7A
#define DESK_COLOR_TEXT 0xFFFFFF
#define DESK_COLOR_CLOSE 0xB04040
#define DESK_COLOR_CLIENT 0x202020
#define DESK_COLOR_PANEL 0x1E1E1E
#define DESK_COLOR_CELL 0x444444
#define DESK_COLOR_DIM 0x9A9A9A

typedef struct desk_frame_view {
    lv_obj_t *title;
    int32_t w, h;
} desk_frame_view;

/* Builds the frame, w by h points, on the active screen of `disp`: the bar
 * with the title, the close button and the dark inside that the client's
 * window covers. */
void desk_frame_view_init(desk_frame_view *v, lv_display_t *disp, const lv_font_t *font,
                          int32_t w, int32_t h);

/* Sets what changes: the title and whether the window has the focus. */
void desk_frame_view_set(desk_frame_view *v, lv_display_t *disp, const char *title, int focused);

typedef struct desk_panel_view {
    lv_obj_t *cell[DESK_MAX_WINDOWS];
    lv_obj_t *label[DESK_MAX_WINDOWS];
} desk_panel_view;

/* Builds the panel, w points wide and DESK_PANEL_H high, on the active screen
 * of `disp`. */
void desk_panel_view_init(desk_panel_view *v, lv_display_t *disp, const lv_font_t *font,
                          int32_t w);

/* Shows a cell for each window of the policy (the title, the kind of the
 * program when there is no title), the window with the focus in the colour of
 * the focus and a hidden window dimmed. */
void desk_panel_view_set(desk_panel_view *v, const desk_policy *p);

#ifdef __cplusplus
}
#endif

#endif
