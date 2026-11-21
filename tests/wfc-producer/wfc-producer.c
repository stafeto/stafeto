/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The producer of the probe of OpenWF Composition (apps/wfc-demo). Started by
 * the demo with a role: "a" makes a window of 100 by 200 points and draws the
 * first pattern in it, "b" one of 160 by 100 with the second. The window has
 * one buffer, drawn once and posted whole; the demo takes its number from the
 * scene's ring (wfcNextStreamSTAFETO) and shows it through an element. The
 * patterns are the numbers of tools/wfc-ref (pattern_a, pattern_b), which draws
 * the host's expected frames. The producer then waits (the demo ends it).
 * Built with -fno-builtin; every result is compared.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <stafeto/window.h>

#define CHECK(cond)                                                                    \
    do {                                                                               \
        if (!(cond)) {                                                                 \
            printf("wfc-producer: check failed at line %d: %s (errno %d)\n", __LINE__, \
                   #cond, errno);                                                      \
            return 20;                                                                 \
        }                                                                              \
    } while (0)

static uint32_t pattern_a(uint32_t x, uint32_t y) {
    uint32_t r = x * 255 / 99, g = y * 255 / 199, b = (x * 3 + y * 5) & 0xFF;
    return r << 16 | g << 8 | b;
}

static uint32_t pattern_b(uint32_t x, uint32_t y) {
    uint32_t r = ((x / 8 + y / 8) & 1) ? 240 : 16, g = x * 255 / 159, b = y * 255 / 99;
    return r << 16 | g << 8 | b;
}

int main(int argc, char **argv) {
    struct stafeto_window w;
    int is_a;
    uint32_t width, height;
    struct stafeto_rect whole;
    if (argc < 2 || (strcmp(argv[1], "a") != 0 && strcmp(argv[1], "b") != 0)) {
        printf("wfc-producer: the role is a or b\n");
        return 2;
    }
    is_a = strcmp(argv[1], "a") == 0;
    width = is_a ? 100 : 160;
    height = is_a ? 200 : 100;
    CHECK(stafeto_window_open(0, 0, (int)width, (int)height, STAFETO_WINDOW_XRGB8888, 1, 0, &w) == 0);
    CHECK(w.width == width && w.height == height && w.pixels[0] != NULL);
    for (uint32_t y = 0; y < height; y++) {
        uint32_t *row = (uint32_t *)((char *)w.pixels[0] + (size_t)y * w.stride);
        for (uint32_t x = 0; x < width; x++) row[x] = is_a ? pattern_a(x, y) : pattern_b(x, y);
    }
    whole.x = 0;
    whole.y = 0;
    whole.w = (int)width;
    whole.h = (int)height;
    CHECK(stafeto_window_post(0, 0, &whole, 1) == 0);
    printf("wfc-producer: %s posted its pattern\n", argv[1]);
    fflush(stdout);
    for (int i = 0; i < 600; i++) {
        struct timespec t = {1, 0};
        nanosleep(&t, NULL);
    }
    return 0;
}
