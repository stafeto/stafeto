/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The pattern a client of the desk draws: its colour over the whole window, a
 * border of 3 points in white, and a cross of the diagonals in a darker shade,
 * so the size and the place of the window show on a screenshot. A pure
 * function of the size and the colour (tools/desk-ref draws it too). */
#ifndef DESK_CLIENT_PATTERN_H
#define DESK_CLIENT_PATTERN_H

#include <stdint.h>

/* Fills w by h points of `px` (rows of `stride_words` words, XRGB8888). */
void pattern_fill(uint32_t *px, uint32_t stride_words, uint32_t w, uint32_t h, uint32_t colour);

#endif
