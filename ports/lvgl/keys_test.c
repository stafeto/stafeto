/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The host test of keys.c (tools/test_lvgl_port.py). Reads lines "CODE VALUE"
 * on standard input and prints "KEY PRESSED" for each that gives a key and "-"
 * for each that gives none. */
#include <stdio.h>

#include "keys.h"

int main(void)
{
    keys k;
    keys_init(&k);
    unsigned code;
    int value;
    while (scanf("%u %d", &code, &value) == 2) {
        uint32_t key = 0;
        int pressed = 0;
        if (keys_feed(&k, (uint16_t)code, value, &key, &pressed)) {
            printf("%u %d\n", (unsigned)key, pressed);
        } else {
            printf("-\n");
        }
    }
    return 0;
}
