/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The glue between the demo (demo.h) and the window library
 * (<stafeto/window.h>): the state the display driver (stafeto_display.c) and
 * the input driver (stafeto_input.c) share, and the functions of the demo's
 * contract they implement. main.c puts them in a demo_host. */
#ifndef STAFETO_IO_H
#define STAFETO_IO_H

#include <stdint.h>

#include <stafeto/window.h>

#include "demo.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The longest a wait for a free buffer or for an event lasts before it looks
 * again (the library asks for a finite time: a wait does not learn of the
 * service's end by itself). */
#define STAFETO_IO_WAIT_NS 1000000000ull

struct stafeto_io {
    struct stafeto_window window;
    int id;                    /* the window's number */
    int events_pending;        /* the bit for events came and they are not all taken */
    unsigned events_lost;      /* events the ring dropped */
    unsigned seen[6];          /* events taken, by kind (1 key, 2 move, 3 button, 4 focus in, 5 focus out) */
    int gone;                  /* the service ended or took the window away */
    unsigned posts;            /* frames posted */
    uint32_t bits_since_post;  /* the bits the waits returned since the last post */
    void (*log)(const char *line);
};

/* Open the window: the whole screen, two XRGB8888 buffers. 0, or -1 with the
 * reason logged. */
int stafeto_display_open(struct stafeto_io *io);

/* The display's side of the contract of demo.h. `user` is a struct
 * stafeto_io. */
int stafeto_display_post(void *user, unsigned buffer, const demo_rect *rects, unsigned count);
int stafeto_display_wait_free(void *user, unsigned buffer);

/* Take the bits of the window's channel: wait at most `timeout_ns` (0 looks
 * without waiting). Notes the bit for events in `events_pending` and the bits
 * in `bits_since_post`. Returns 0 when a bit came, 1 when the time ran out
 * (or a signal ended the wait) with none, and -1 when the service has gone
 * (logged). */
int stafeto_display_take_bits(struct stafeto_io *io, uint64_t timeout_ns);

/* The input side. */
unsigned stafeto_input_events(void *user, demo_event *out, unsigned max);

/* The clock and the pause of the loop. */
uint32_t stafeto_now_ms(void *user);
void stafeto_idle(void *user, uint32_t ms);

#ifdef __cplusplus
}
#endif

#endif
