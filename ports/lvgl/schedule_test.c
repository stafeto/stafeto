/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The host test of schedule.c (tools/test_lvgl_port.py): the scenario of
 * scene.h run through the schedule with a model of LVGL's loop. After each
 * change handed out the model draws frames and runs an animation for BUSY
 * turns. In mode `batch` all the events are queued at the start; in mode
 * `single` the next events (up to and including the next change) are queued
 * only when the schedule is idle. Each change handed out is printed with the
 * turn it was handed out in:
 *   P TURN X Y PRESSED     the pointer
 *   K TURN KEY PRESSED     the keyboard
 * and, at the end, "changes N lost L". */
#include <stdio.h>
#include <string.h>

#include "schedule.h"

#define BUSY 10

static const demo_event scenario[SCENE_EVENTS] = {SCENE_EVENT_ROWS};

static int is_change(const demo_event *e)
{
    return e->kind == DEMO_EVENT_BUTTON || e->kind == DEMO_EVENT_KEY;
}

int main(int argc, char **argv)
{
    int batch = argc > 1 && !strcmp(argv[1], "batch");
    static sched s;
    sched_init(&s, 1);
    unsigned next = 0;
    if (batch) {
        for (; next < SCENE_EVENTS; next++) {
            sched_push(&s, &scenario[next]);
        }
    }
    unsigned busy = 0;
    unsigned seen = 0;
    for (unsigned turn = 1; turn < 2000; turn++) {
        if (!batch && sched_idle(&s)) {
            while (next < SCENE_EVENTS) {
                int change = is_change(&scenario[next]);
                sched_push(&s, &scenario[next++]);
                if (change) {
                    break;
                }
            }
        }
        /* LVGL reads both devices in each turn of this model. */
        int32_t x, y;
        int pressed;
        uint32_t key;
        int key_pressed;
        sched_pointer(&s, &x, &y, &pressed);
        if (s.changes != seen) {
            printf("P %u %d %d %d\n", turn, (int)x, (int)y, pressed);
            seen = s.changes;
            busy = BUSY;
        }
        sched_keypad(&s, &key, &key_pressed);
        if (s.changes != seen) {
            printf("K %u %u %d\n", turn, (unsigned)key, key_pressed);
            seen = s.changes;
            busy = BUSY;
        }
        int drew = busy > 0;
        unsigned animations = busy > 2 ? 1 : 0;
        if (busy > 0) {
            busy--;
        }
        sched_end_turn(&s, drew, animations);
        if (next == SCENE_EVENTS && sched_idle(&s) && busy == 0) {
            break;
        }
    }
    printf("changes %u lost %u\n", s.changes, s.lost);
    return 0;
}
