/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The display driver of the demo: its two buffers are those of a window of
 * the composition service, the post of a finished frame is a POST with the
 * rectangles LVGL redrew, and the wait for a free buffer is the wait for the
 * service's bit (section 3.2 of the plan of stage G4). */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "stafeto_io.h"

_Static_assert(sizeof(demo_rect) == sizeof(struct stafeto_rect), "the rectangles are the library's");
_Static_assert(sizeof(demo_event) == sizeof(struct stafeto_window_event), "the events are the library's");

static void say(struct stafeto_io *io, const char *what, int err)
{
    char line[160];
    snprintf(line, sizeof line, "%s: errno %d", what, err);
    io->log(line);
}

int stafeto_display_open(struct stafeto_io *io)
{
    io->id = stafeto_window_open(0, 0, DEMO_WIDTH, DEMO_HEIGHT, STAFETO_WINDOW_XRGB8888, 2, 0,
                                 &io->window);
    if (io->id < 0) {
        say(io, "cannot open the window", errno);
        return -1;
    }
    if (io->window.stride != DEMO_STRIDE || io->window.buffers != 2) {
        io->log("the window is not 640 x 400 with two buffers of 2560-byte lines");
        return -1;
    }
    return 0;
}

int stafeto_display_take_bits(struct stafeto_io *io, uint64_t timeout_ns)
{
    uint32_t bits = 0;
    if (stafeto_window_wait(io->id, timeout_ns, &bits) == 0) {
        if (bits & STAFETO_WINDOW_EVENTS) {
            io->events_pending = 1;
        }
        return 0;
    }
    if (errno == ETIMEDOUT || errno == EINTR) {
        return 0;
    }
    if (!io->gone) {
        say(io, "the display is gone (wait)", errno);
    }
    io->gone = 1;
    return -1;
}

int stafeto_display_post(void *user, unsigned buffer, const demo_rect *rects, unsigned count)
{
    struct stafeto_io *io = user;
    if (io->gone) {
        return -1;
    }
    if (stafeto_window_post(io->id, buffer, (const struct stafeto_rect *)rects, count) != 0) {
        say(io, "cannot post the frame", errno);
        io->gone = 1;
        return -1;
    }
    io->posts++;
    return 0;
}

int stafeto_display_wait_free(void *user, unsigned buffer)
{
    struct stafeto_io *io = user;
    while (!io->gone) {
        uint32_t mask = stafeto_window_free_buffers(io->id);
        if (mask & STAFETO_WINDOW_BUFFER(buffer)) {
            return 0;
        }
        if (stafeto_display_take_bits(io, STAFETO_IO_WAIT_NS) != 0) {
            break;
        }
        if (stafeto_window_free_buffers(io->id) == mask) {
            io->log("still waiting for a free buffer");
        }
    }
    return -1;
}

uint32_t stafeto_now_ms(void *user)
{
    (void)user;
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint32_t)((uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u);
}

void stafeto_idle(void *user, uint32_t ms)
{
    struct stafeto_io *io = user;
    if (stafeto_display_take_bits(io, (uint64_t)(ms ? ms : 1) * 1000000u) != 0) {
        /* The display is gone: nothing more to show. */
        io->log("the display service ended; the demo ends");
        stafeto_window_close(io->id);
        _Exit(1);
    }
}
