/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The order in which input reaches LVGL (section 5.3 of the plan). Events
 * wait in a queue of the program. LVGL reads the pointer and the keyboard
 * through two functions that each hand out one change: a MOVE moves the
 * point and counts for nothing else, while a button or key going down or up is
 * a change. In strict
 * mode (the probe) the next change waits until the frame has settled: a turn
 * of the loop with no frame drawn and no animation running, after at least one
 * more read of the same device since the change was handed out. The pixels of
 * a run then do not depend on when the events arrived. Pure logic, tested on
 * the host with a model of LVGL's loop. */
#ifndef STAFETO_SCHEDULE_H
#define STAFETO_SCHEDULE_H

#include <stdint.h>

#include "demo.h"
#include "keys.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCHED_QUEUE 256

typedef struct sched {
    demo_event queue[SCHED_QUEUE];
    unsigned head;
    unsigned count;
    unsigned lost;          /* events dropped because the queue was full */
    int32_t x, y;           /* the pointer as last handed out */
    int pressed;
    keys keymap;
    uint32_t key;           /* the keyboard as last handed out */
    int key_pressed;
    int strict;             /* 1: one change at a time, each after a settled frame */
    int hold;               /* a change is out and the frame has not settled: 0, 1 pointer, 2 keyboard */
    unsigned polls;         /* reads of that device since the change */
    unsigned changes;       /* changes handed out */
} sched;

void sched_init(sched *s, int strict);

/* Queue an event; 0, or -1 when the queue is full (counted in `lost`). */
int sched_push(sched *s, const demo_event *e);

/* The read function of the pointer: the point and state to give LVGL.
 * Returns 1 when LVGL should read again at once. */
int sched_pointer(sched *s, int32_t *x, int32_t *y, int *pressed);

/* The read function of the keyboard. */
int sched_keypad(sched *s, uint32_t *key, int *pressed);

/* End of a turn of the loop: whether a frame was drawn in it and how many
 * animations run. Returns 1 when the frame has settled; a held change is
 * released then. */
int sched_end_turn(sched *s, int drew, unsigned animations);

/* Whether every event handed in has been handed out. */
int sched_idle(const sched *s);

#ifdef __cplusplus
}
#endif

#endif
