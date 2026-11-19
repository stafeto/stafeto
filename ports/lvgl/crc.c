/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include "crc.h"

static uint32_t table[256];
static int ready;

static void make_table(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) {
            c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        }
        table[i] = c;
    }
    ready = 1;
}

uint32_t crc32_start(void)
{
    if (!ready) {
        make_table();
    }
    return 0xFFFFFFFFu;
}

uint32_t crc32_feed(uint32_t state, const void *data, size_t len)
{
    const uint8_t *p = data;
    if (!ready) {
        make_table();
    }
    for (size_t i = 0; i < len; i++) {
        state = table[(state ^ p[i]) & 0xFF] ^ (state >> 8);
    }
    return state;
}

uint32_t crc32_finish(uint32_t state)
{
    return ~state;
}

uint32_t crc32_bytes(const void *data, size_t len)
{
    return crc32_finish(crc32_feed(crc32_start(), data, len));
}

uint32_t crc32_xrgb(const uint8_t *pixels, unsigned width, unsigned height, unsigned stride)
{
    uint32_t state = crc32_start();
    for (unsigned y = 0; y < height; y++) {
        const uint8_t *row = pixels + (size_t)y * stride;
        for (unsigned x = 0; x < width; x++) {
            /* Bytes of a point: B, G, R, X; the CRC takes R, G, B. */
            uint8_t rgb[3] = {row[x * 4 + 2], row[x * 4 + 1], row[x * 4]};
            state = crc32_feed(state, rgb, 3);
        }
    }
    return crc32_finish(state);
}
