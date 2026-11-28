/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include "pattern.h"

#define BORDER 3

void pattern_fill(uint32_t *px, uint32_t stride_words, uint32_t w, uint32_t h, uint32_t colour)
{
    uint32_t dark = (colour >> 1) & 0x007F7F7Fu;
    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x++) {
            uint32_t c = colour;
            if (x < BORDER || y < BORDER || x + BORDER >= w || y + BORDER >= h) {
                c = 0x00FFFFFFu;
            } else if (x * h / (w ? w : 1) == y || (w - 1 - x) * h / (w ? w : 1) == y) {
                c = dark;
            }
            px[y * stride_words + x] = c;
        }
    }
}
