/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The host test of crc.c (tools/test_lvgl_port.py). Reads bytes on standard
 * input and prints, in capitals, the CRC-32 of them as one block and as the
 * running form fed in pieces of 3 bytes; with the arguments `xrgb W H` it
 * prints the CRC of the R, G, B bytes of the XRGB8888 frame on standard
 * input. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crc.h"

int main(int argc, char **argv)
{
    static uint8_t data[1 << 22];
    size_t n = fread(data, 1, sizeof data, stdin);
    if (argc == 4 && !strcmp(argv[1], "xrgb")) {
        unsigned w = (unsigned)atoi(argv[2]), h = (unsigned)atoi(argv[3]);
        printf("%08X\n", (unsigned)crc32_xrgb(data, w, h, w * 4));
        return 0;
    }
    uint32_t state = crc32_start();
    for (size_t i = 0; i < n; i += 3) {
        state = crc32_feed(state, data + i, n - i < 3 ? n - i : 3);
    }
    printf("%08X %08X\n", (unsigned)crc32_bytes(data, n), (unsigned)crc32_finish(state));
    return 0;
}
