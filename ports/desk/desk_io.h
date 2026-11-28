/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The glue between LVGL and the window library: a surface is a window of the
 * manager's own with an LVGL display over its two buffers. A frame and the
 * panel are surfaces. LVGL draws into the buffer of the window that is free,
 * the post of a finished frame is a POST with the rectangles LVGL redrew, and
 * the wait for the next buffer is the wait for the service's bit for it
 * (stafeto_window_wait_free, which leaves the other bits of the process's
 * channel to stafeto_windows_wait). */
#ifndef DESK_IO_H
#define DESK_IO_H

#include <stdint.h>

#include "lvgl.h"

#include <stafeto/manager.h>
#include <stafeto/window.h>

#include "draw.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The most areas a frame of LVGL posts (the library merges more than four
 * of them, and the service takes the box). */
#define DESK_IO_RECTS 16
/* How long a wait for a free buffer lasts before it looks again. */
#define DESK_IO_WAIT_NS 1000000000ull

enum desk_surface_kind { DESK_SURFACE_NONE = 0, DESK_SURFACE_PANEL, DESK_SURFACE_FRAME };

typedef struct desk_surface {
    int kind;
    int win;                  /* the library's number of the window */
    uint32_t id;              /* the service's id of the window */
    uint32_t client;          /* for a frame: the id of the window it frames */
    struct stafeto_window window;
    lv_display_t *display;
    int dirty;                /* the view changed: draw it */
    int gone;                 /* the service ended or took the window away */
    desk_frame_view frame;
    desk_panel_view panel;
    struct stafeto_rect rects[DESK_IO_RECTS];
    unsigned rect_count;
    unsigned posts;
} desk_surface;

/* The clock of LVGL, in milliseconds. */
void desk_io_init(void);

/* Opens a window of w by h points at (x, y), two XRGB8888 buffers, and an LVGL
 * display over it. 0, or -1 with errno of the window's open. */
int desk_surface_open(desk_surface *s, int kind, int x, int y, int w, int h);

/* Draws what changed (the display's invalid areas) and posts it. */
void desk_surface_refresh(desk_surface *s);

/* Deletes the display and closes the window. */
void desk_surface_close(desk_surface *s);

#ifdef __cplusplus
}
#endif

#endif
