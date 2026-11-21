/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The producer of the probe of OpenWF Composition (apps/wfc-demo). Started by
 * the demo with a role: "a" makes a window of 100 by 200 points and draws the
 * first pattern in it, "b" one of 160 by 100 with the second, "s" opens the
 * screen of the first revision (a window of the whole screen) and draws a
 * gradient in it. The window has
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

/* The screen of the first revision, from src/main.rs. */
int wp_screen_open(void **pixels);
int wp_screen_flush(unsigned rows);

/* The picture of the first revision's window: the gradient of frame 0 of
 * wfd-demo (xtask's `wfd::pattern_crc(0)` is its CRC). */
static uint32_t pattern_s(uint32_t x, uint32_t y) {
    if (y >= 8 && y < 24 && x < 6) return 0x00FFFFFFu;
    return (x * 255 / 639) << 16 | (y * 255 / 399) << 8 | ((x ^ y) & 0xFF);
}

static int screen_role(void) {
    void *px = NULL;
    CHECK(wp_screen_open(&px) == 0 && px != NULL);
    uint32_t *points = px;
    for (uint32_t y = 0; y < 400; y++)
        for (uint32_t x = 0; x < 640; x++) points[y * 640 + x] = pattern_s(x, y);
    CHECK(wp_screen_flush(400) == 0);
    printf("wfc-producer: s drew the screen of the first revision\n");
    fflush(stdout);
    for (int i = 0; i < 600; i++) {
        struct timespec t = {1, 0};
        nanosleep(&t, NULL);
    }
    return 0;
}

int main(int argc, char **argv) {
    struct stafeto_window w;
    int is_a;
    uint32_t width, height;
    struct stafeto_rect whole;
    if (argc >= 2 && strcmp(argv[1], "s") == 0) return screen_role();
    if (argc < 2 || (strcmp(argv[1], "a") != 0 && strcmp(argv[1], "b") != 0)) {
        printf("wfc-producer: the role is a, b or s\n");
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
