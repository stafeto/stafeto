/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The demo of stage G4: a screen of LVGL widgets with FreeType text, and the
 * contract it keeps with whoever shows it (the display and input contract of
 * section 3.2 of the plan). The demo draws into two buffers of the screen's
 * size and knows nothing of windows: the host program supplies the buffers,
 * posts a finished frame, waits for a buffer to be free, hands in input
 * events and tells the time. The reference program on the host
 * (tools/lvgl-ref) supplies memory buffers, the guest program supplies the
 * window.
 *
 * One input change at a time is handed to LVGL (schedule.h): in probe mode
 * the next change waits until the frame has settled, so the pixels of a run
 * do not depend on when the events arrived or on the speed of the machine. */
#ifndef STAFETO_DEMO_H
#define STAFETO_DEMO_H

#include <stddef.h>
#include <stdint.h>

#include "scene.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A rectangle of the frame that changed (the layout of struct stafeto_rect). */
typedef struct demo_rect {
    int32_t x, y, w, h;
} demo_rect;

/* An input event (the layout of a window event of the compositor). */
typedef struct demo_event {
    uint16_t kind;  /* DEMO_EVENT_* */
    uint16_t code;  /* KEY: Linux key code; BUTTON: Linux button code */
    int32_t value;  /* KEY and BUTTON: 1 down, 0 up, 2 repeat */
    int32_t x, y;   /* MOVE and BUTTON: the point, in the window */
} demo_event;

enum {
    DEMO_EVENT_KEY = 1,
    DEMO_EVENT_MOVE = 2,
    DEMO_EVENT_BUTTON = 3,
    DEMO_EVENT_FOCUS_IN = 4,
    DEMO_EVENT_FOCUS_OUT = 5,
};

#define DEMO_BTN_LEFT 0x110

/* What the host supplies. A callback that is NULL is skipped. */
typedef struct demo_host {
    void *user;
    /* Two buffers of DEMO_WIDTH x DEMO_HEIGHT points, XRGB8888 (the word
     * 0xXXRRGGBB, low byte first), rows of DEMO_STRIDE bytes. */
    uint8_t *buffer[2];
    /* A finished frame is in `buffer`; `rects` (at most DEMO_MAX_RECTS) are the
     * areas that changed. The demo does not draw into the buffer again until
     * wait_free for it has returned. 0, or -1 when the display has ended (the
     * demo stops). */
    int (*post)(void *user, unsigned buffer, const demo_rect *rects, unsigned count);
    /* Return when the buffer may be drawn into: 0, or -1 when the display is
     * gone (the demo stops). */
    int (*wait_free)(void *user, unsigned buffer);
    /* Hand in up to `max` events that arrived; the number handed in. The demo
     * calls again while a call returns as many as it asked for. */
    unsigned (*events)(void *user, demo_event *out, unsigned max);
    /* The time in milliseconds on a monotonic clock: the clock of LVGL in
     * normal mode, and in probe mode the real-time deadline of the wait for
     * the events of the scenario (the clock of LVGL is the virtual one). */
    uint32_t (*now_ms)(void *user);
    /* Sleep until an event may have arrived or `ms` have passed. Normal mode
     * calls it between turns; probe mode calls it while it waits for the
     * events of the scenario, with no turn of the clock in between. */
    void (*idle)(void *user, uint32_t ms);
    /* Probe stages: 0 the last posted frame is on the screen, 1 the snapshot
     * of the first frame may be taken (the host waits for it). 0, or -1 when
     * the display has ended (the probe fails). */
    int (*pause)(void *user, int stage);
    /* One line of text for the log (no newline). */
    void (*log)(void *user, const char *line);
} demo_host;

#define DEMO_MAX_RECTS 16

typedef struct demo demo;

/* Create the demo: LVGL, the display, the two input devices, the fonts (the
 * Liberation Sans file at `font_path`) and the screen of scene.h. `probe` 1
 * selects the virtual clock and the one-change-at-a-time hand-out. NULL when
 * LVGL or FreeType does not start or the font is missing. */
demo *demo_open(const demo_host *host, const char *font_path, int probe);

/* Rows in a band of the frame CRCs the evidence prints, and the bands. */
#define DEMO_BAND_ROWS 16
#define DEMO_BANDS (DEMO_HEIGHT / DEMO_BAND_ROWS)

typedef struct demo_result {
    uint32_t first_crc;   /* CRC-32 of the R, G, B bytes of the first settled frame */
    uint32_t after_crc;   /* the same after the scenario */
    uint32_t first_bands[DEMO_BANDS];   /* the same for each band of 16 rows */
    uint32_t after_bands[DEMO_BANDS];
    unsigned long mem_max_used;         /* the most LVGL's pool held, in bytes */
    char status[160];     /* "presses 2 option 1 switch 1 slider 75 text hi" */
    unsigned turns;       /* turns of the loop */
    unsigned frames;      /* frames posted */
} demo_result;

/* Probe mode: settle the first frame, take its CRC, then collect all the input
 * events of the scenario of scene.h with no turn of the clock (waiting
 * through the host's idle, against a real-time deadline: a late key-up would
 * otherwise become a long press), hand them in one change at a time, settle,
 * take the CRC and the state. 0, or -1 when the frame does not settle or the
 * events do not come (the log says how many came). The wait ends when every
 * change of the scenario (SCENE_CHANGES keys and buttons going down or up) has
 * come: the compositor does not deliver a move to the place the pointer is
 * already at, so the number of events is no end condition. When the deadline
 * passes, the log lists the events that did come, in order. */
int demo_probe(demo *d, demo_result *result);

/* The CRC of each band of 16 rows of the two frames of `result`, as lines of
 * the log (behind the evidence flag of the program: a probe that finds the
 * CRCs differ names the bands). */
void demo_bands(const demo_host *host, const demo_result *result);

/* Normal mode: run until the host's wait_free fails. */
void demo_run(demo *d);

/* The determinism evidence of the glyph path (lines to the host's log): for
 * each of `a g W 0` at 16 pixels, the number of points and the CRC-32 of the
 * hinted outline after FT_Load_Glyph with no rendering, the bitmap's width,
 * rows, pitch, left, top and advance with the CRC-32 of its buffer, then
 * FT_HAS_MULTIPLE_MASTERS and FT_Get_Kerning for the pair AV. 0, or -1. */
int demo_evidence(const demo_host *host, const char *font_path);

/* Free what demo_open made. */
void demo_close(demo *d);

#ifdef __cplusplus
}
#endif

#endif
