/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The program lvgl-demo: the demo of demo.h on a window of the composition
 * service (sections 3.2 to 3.4 and 5.4 of the plan of stage G4).
 *
 *   lvgl-demo [--probe [--quick]] [--evidence] [--font PATH]
 *
 * Without --probe it runs until the display ends: the clock is the monotonic
 * clock, the input is handed to LVGL as it comes, and between turns the
 * program sleeps in the wait for the service's bits. --probe runs the
 * scenario of scene.h on the virtual clock, one input change at a time, and
 * prints the lines the probe of the guest reads (first crc, after crc, state,
 * memory, frames); --quick skips the two seconds the probe leaves for the
 * snapshot of QEMU. --evidence prints the lines of the determinism evidence of
 * the glyph path, the same lines the reference program on the host prints. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "demo.h"
#include "stafeto_io.h"

/* The memory of the layer's heap, from the Rust side of the program. */
extern unsigned long lvgl_demo_heap_bytes(void);
extern unsigned long lvgl_demo_own_pages(void);

/* The seconds the probe leaves for QEMU's snapshot. */
#define SNAPSHOT_NS 2000000000ull
/* How long the probe waits for the frame to be on the screen. */
#define SHOWN_NS 10000000000ull

static struct stafeto_io io;
static int quick;
/* Per-frame time: the turns of the loop in which a frame was posted. */
static uint64_t last_turn_us;
static unsigned last_posts;
static uint64_t frame_total_us, frame_longest_us;
static unsigned frame_count;

static void say(const char *line)
{
    printf("lvgl-demo: %s\n", line);
    fflush(stdout);
}

static void host_log(void *user, const char *line)
{
    (void)user;
    say(line);
}

static uint64_t now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000u + (uint64_t)t.tv_nsec / 1000u;
}

static void sleep_ns(uint64_t ns)
{
    struct timespec t = {(time_t)(ns / 1000000000u), (long)(ns % 1000000000u)};
    while (nanosleep(&t, &t) != 0) {
        /* a signal: the rest of the time */
    }
}

/* The input driver, with the clock of the frames: the calls come once in a
 * turn of the loop, so the time between two of them is a turn. */
static unsigned timed_events(void *user, demo_event *out, unsigned max)
{
    uint64_t now = now_us();
    if (last_turn_us && io.posts > last_posts) {
        uint64_t took = now - last_turn_us;
        frame_total_us += took;
        frame_count++;
        if (took > frame_longest_us) {
            frame_longest_us = took;
        }
    }
    last_turn_us = now;
    last_posts = io.posts;
    return stafeto_input_events(user, out, max);
}

static void pause_cb(void *user, int stage)
{
    (void)user;
    if (stage == 0) {
        if (stafeto_window_shown(io.id, SHOWN_NS) != 0) {
            say("the frame did not reach the screen");
        }
    } else if (!quick) {
        sleep_ns(SNAPSHOT_NS);
    }
}

int main(int argc, char **argv)
{
    int probe = 0, evidence = 0;
    const char *font = DEMO_FONT_PATH;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--probe")) {
            probe = 1;
        } else if (!strcmp(argv[i], "--quick")) {
            quick = 1;
        } else if (!strcmp(argv[i], "--evidence")) {
            evidence = 1;
        } else if (!strcmp(argv[i], "--font") && i + 1 < argc) {
            font = argv[++i];
        } else {
            fprintf(stderr, "usage: lvgl-demo [--probe [--quick]] [--evidence] [--font PATH]\n");
            return 2;
        }
    }
    io.log = say;
    if (stafeto_display_open(&io) != 0) {
        return 1;
    }
    demo_host host = {
        .user = &io,
        .buffer = {io.window.pixels[0], io.window.pixels[1]},
        .post = stafeto_display_post,
        .wait_free = stafeto_display_wait_free,
        .events = timed_events,
        .now_ms = stafeto_now_ms,
        .idle = stafeto_idle,
        .pause = pause_cb,
        .log = host_log,
    };
    if (evidence && demo_evidence(&host, font) != 0) {
        say("the evidence failed");
        return 1;
    }
    demo *d = demo_open(&host, font, probe);
    if (!d) {
        return 1;
    }
    int status = 0;
    if (probe) {
        demo_result result;
        if (demo_probe(d, &result) != 0) {
            status = 1;
        } else {
            char line[240];
            snprintf(line, sizeof line, "state %s", result.status);
            say(line);
            snprintf(line, sizeof line, "memory heap-bytes %lu own-pages %lu", lvgl_demo_heap_bytes(),
                     lvgl_demo_own_pages());
            say(line);
            snprintf(line, sizeof line, "frames %u longest-us %llu mean-us %llu", frame_count,
                     (unsigned long long)frame_longest_us,
                     (unsigned long long)(frame_count ? frame_total_us / frame_count : 0));
            say(line);
            if (io.events_lost) {
                say("LOST: events were dropped");
                status = 1;
            }
            if (!quick) {
                sleep_ns(SNAPSHOT_NS);
            }
        }
    } else {
        demo_run(d);
        status = io.gone ? 1 : 0;
    }
    demo_close(d);
    stafeto_window_close(io.id);
    return status;
}
