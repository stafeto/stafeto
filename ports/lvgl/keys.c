/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include "keys.h"

#define KEY_LEFTSHIFT 42
#define KEY_RIGHTSHIFT 54

/* Linux key codes 0 to 57 on a US keyboard: the plain and the shifted
 * character, 0 for a key with none. */
static const char plain[58] =
    "\0\033" "1234567890-=" "\b" "\t" "qwertyuiop[]" "\n" "\0" "asdfghjkl;'`" "\0" "\\"
    "zxcvbnm,./" "\0" "*" "\0" " ";
static const char shifted[58] =
    "\0\033" "!@#$%^&*()_+" "\b" "\t" "QWERTYUIOP{}" "\n" "\0" "ASDFGHJKL:\"~" "\0" "|"
    "ZXCVBNM<>?" "\0" "*" "\0" " ";

static uint32_t translate(const keys *k, uint16_t code)
{
    if (code < sizeof plain) {
        char c = k->shift ? shifted[code] : plain[code];
        if (c == '\t') {
            return KEYS_NEXT;
        }
        return (uint32_t)(uint8_t)c;
    }
    switch (code) {
    case 102: return KEYS_HOME;
    case 103: return KEYS_UP;
    case 105: return KEYS_LEFT;
    case 106: return KEYS_RIGHT;
    case 107: return KEYS_END;
    case 108: return KEYS_DOWN;
    case 111: return KEYS_DEL;
    default: return 0;
    }
}

void keys_init(keys *k)
{
    k->shift = 0;
    for (unsigned i = 0; i < 256; i++) {
        k->held[i] = 0;
    }
}

int keys_feed(keys *k, uint16_t code, int32_t value, uint32_t *key, int *pressed)
{
    if (code == KEY_LEFTSHIFT || code == KEY_RIGHTSHIFT) {
        if (value == 1) {
            k->shift++;
        } else if (value == 0 && k->shift > 0) {
            k->shift--;
        }
        return 0;
    }
    if (code >= 256) {
        return 0;
    }
    if (value == 0) {
        if (k->held[code] == 0) {
            return 0;
        }
        *key = k->held[code];
        *pressed = 0;
        k->held[code] = 0;
        return 1;
    }
    uint32_t t = translate(k, code);
    if (t == 0) {
        return 0;
    }
    k->held[code] = t;
    *key = t;
    *pressed = 1;
    return 1;
}
