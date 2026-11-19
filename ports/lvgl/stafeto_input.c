/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The input driver of the demo: the events of the window's ring, taken
 * without waiting, in the layout demo.h hands to the schedule (section 3.3 of
 * the plan of stage G4). */
#include <errno.h>
#include <stdio.h>

#include "stafeto_io.h"

unsigned stafeto_input_events(void *user, demo_event *out, unsigned max)
{
    struct stafeto_io *io = user;
    if (io->gone) {
        return 0;
    }
    /* A look at the channel without waiting: the bits are returned only by
     * stafeto_window_wait, so the bit for events is learned here when no
     * wait for a buffer has met it. */
    if (stafeto_display_take_bits(io, 0) != 0) {
        return 0;
    }
    if (!io->events_pending) {
        return 0;
    }
    unsigned total = 0;
    while (total < max) {
        int want = (int)(max - total);
        if (want > STAFETO_WINDOW_EVENTS_MAX) {
            want = STAFETO_WINDOW_EVENTS_MAX;
        }
        uint32_t flags = 0;
        int n = stafeto_window_events(io->id, (struct stafeto_window_event *)&out[total], want, &flags);
        if (n < 0) {
            char line[96];
            snprintf(line, sizeof line, "cannot take events: errno %d", errno);
            io->log(line);
            io->gone = 1;
            return total;
        }
        if (flags & STAFETO_WINDOW_EVENTS_LOST) {
            io->events_lost++;
            io->log("LOST: the ring of events dropped some");
        }
        total += (unsigned)n;
        if (n < want) {
            /* Fewer than asked: the ring is empty. */
            io->events_pending = 0;
            break;
        }
    }
    return total;
}
