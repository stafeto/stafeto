/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include "schedule.h"

enum { HOLD_NONE = 0, HOLD_POINTER = 1, HOLD_KEYBOARD = 2 };

void sched_init(sched *s, int strict)
{
    s->head = 0;
    s->count = 0;
    s->lost = 0;
    s->x = 0;
    s->y = 0;
    s->pressed = 0;
    keys_init(&s->keymap);
    s->key = 0;
    s->key_pressed = 0;
    s->strict = strict;
    s->hold = HOLD_NONE;
    s->polls = 0;
    s->changes = 0;
}

int sched_push(sched *s, const demo_event *e)
{
    if (s->count == SCHED_QUEUE) {
        s->lost++;
        return -1;
    }
    s->queue[(s->head + s->count) % SCHED_QUEUE] = *e;
    s->count++;
    return 0;
}

static const demo_event *front(const sched *s)
{
    return s->count ? &s->queue[s->head] : 0;
}

static void drop(sched *s)
{
    s->head = (s->head + 1) % SCHED_QUEUE;
    s->count--;
}

/* The change a device just had handed out. */
static void changed(sched *s, int device)
{
    s->changes++;
    if (s->strict) {
        s->hold = device;
        s->polls = 0;
    }
}

int sched_pointer(sched *s, int32_t *x, int32_t *y, int *pressed)
{
    int again = 0;
    if (s->hold == HOLD_POINTER) {
        s->polls++;
    }
    if (s->hold == HOLD_NONE) {
        const demo_event *e;
        while ((e = front(s)) != 0) {
            if (e->kind == DEMO_EVENT_MOVE) {
                s->x = e->x;
                s->y = e->y;
                drop(s);
            } else if (e->kind == DEMO_EVENT_BUTTON && e->code == DEMO_BTN_LEFT) {
                s->x = e->x;
                s->y = e->y;
                s->pressed = e->value != 0;
                drop(s);
                changed(s, HOLD_POINTER);
                again = !s->strict && s->count > 0;
                break;
            } else if (e->kind == DEMO_EVENT_FOCUS_IN || e->kind == DEMO_EVENT_FOCUS_OUT
                       || (e->kind == DEMO_EVENT_BUTTON)) {
                drop(s);
            } else {
                break;
            }
        }
    }
    *x = s->x;
    *y = s->y;
    *pressed = s->pressed;
    return again;
}

int sched_keypad(sched *s, uint32_t *key, int *pressed)
{
    int again = 0;
    if (s->hold == HOLD_KEYBOARD) {
        s->polls++;
    }
    if (s->hold == HOLD_NONE) {
        const demo_event *e;
        while ((e = front(s)) != 0) {
            if (e->kind == DEMO_EVENT_KEY) {
                uint32_t k;
                int down;
                int handed = keys_feed(&s->keymap, e->code, e->value, &k, &down);
                drop(s);
                if (handed) {
                    s->key = k;
                    s->key_pressed = down;
                    changed(s, HOLD_KEYBOARD);
                    again = !s->strict && s->count > 0;
                    break;
                }
            } else if (e->kind == DEMO_EVENT_FOCUS_IN || e->kind == DEMO_EVENT_FOCUS_OUT) {
                drop(s);
            } else {
                break;
            }
        }
    }
    *key = s->key;
    *pressed = s->key_pressed;
    return again;
}

int sched_end_turn(sched *s, int drew, unsigned animations)
{
    int settled = !drew && animations == 0 && (s->hold == HOLD_NONE || s->polls >= 1);
    if (settled) {
        s->hold = HOLD_NONE;
    }
    return settled;
}

int sched_idle(const sched *s)
{
    return s->count == 0 && s->hold == HOLD_NONE;
}
