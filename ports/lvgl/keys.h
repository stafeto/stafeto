/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The translation of Linux key codes (the codes of the compositor's KEY
 * events) into the characters and control keys the text area takes: the US
 * layout, with Shift. Pure functions, tested on the host. */
#ifndef STAFETO_KEYS_H
#define STAFETO_KEYS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Control keys, the values of LV_KEY_* (demo.c checks them). */
#define KEYS_UP 17
#define KEYS_DOWN 18
#define KEYS_RIGHT 19
#define KEYS_LEFT 20
#define KEYS_ESC 27
#define KEYS_DEL 127
#define KEYS_BACKSPACE 8
#define KEYS_ENTER 10
#define KEYS_NEXT 9
#define KEYS_HOME 2
#define KEYS_END 3

typedef struct keys {
    int shift;            /* the count of Shift keys held */
    uint32_t held[256];   /* the key handed out when a code went down */
} keys;

void keys_init(keys *k);

/* Feed one KEY event (value 1 down, 0 up, 2 repeat). Returns 1 when there is
 * a key for LVGL: `*key` is its value and `*pressed` 1 for down and repeat, 0
 * for up (the key of an up is the one its down gave). Returns 0 for Shift
 * itself and for a code with no translation. */
int keys_feed(keys *k, uint16_t code, int32_t value, uint32_t *key, int *pressed);

#ifdef __cplusplus
}
#endif

#endif
