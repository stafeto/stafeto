/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The reference program of the LVGL demo on the host: the same demo, LVGL and
 * FreeType code as the guest's, compiled for the host (tools/build-lvgl.py
 * --host), drawing into two memory buffers. It runs the probe scenario of
 * scene.h and prints the CRC-32 of the first settled frame and of the frame
 * after the scenario, and the state line. The guest's probe prints the same
 * lines and the expected values are these.
 *
 *   lvgl-ref [--feed batch|single] [--evidence] [--out DIR] FONT
 *
 * --feed batch hands in all the events of the scenario at once; single hands
 * in one event at each turn of the loop. The result is the same.
 * --evidence also prints the determinism evidence of the glyph path.
 * --out DIR writes ref.txt (the two CRCs and the state line) and the two
 * frames as PPM files for the eye. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_MODULE_H

#include "demo.h"

struct ref {
    uint8_t *buffer[2];
    int single;                 /* one event per call */
    unsigned fed;               /* events of the scenario handed in */
    int released;               /* the scenario may start (after the first frame) */
    uint8_t *copy;              /* the frame at the last pause 0 */
    uint8_t *first, *after;     /* the frames at the two CRCs */
    unsigned last;
    int stage;                  /* pauses of stage 0 seen */
};

static const demo_event scenario[SCENE_EVENTS] = {SCENE_EVENT_ROWS};

static void post(void *user, unsigned buffer, const demo_rect *rects, unsigned count)
{
    struct ref *r = user;
    (void)rects;
    (void)count;
    r->last = buffer;
}

static int wait_free(void *user, unsigned buffer)
{
    (void)user;
    (void)buffer;
    return 0;
}

static unsigned events(void *user, demo_event *out, unsigned max)
{
    struct ref *r = user;
    unsigned n = 0;
    unsigned limit = r->single ? 1 : max;
    while (n < limit && n < max && r->fed < SCENE_EVENTS) {
        out[n++] = scenario[r->fed++];
    }
    return n;
}

static void pause_cb(void *user, int stage)
{
    struct ref *r = user;
    if (stage != 0) {
        return;
    }
    uint8_t *into = r->stage == 0 ? r->first : r->after;
    memcpy(into, r->buffer[r->last], DEMO_BUFFER_BYTES);
    r->stage++;
}

static void say(void *user, const char *line)
{
    (void)user;
    printf("lvgl-ref: %s\n", line);
}

static void write_ppm(const char *dir, const char *name, const uint8_t *px)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) {
        return;
    }
    fprintf(f, "P6\n%d %d\n255\n", DEMO_WIDTH, DEMO_HEIGHT);
    for (int i = 0; i < DEMO_WIDTH * DEMO_HEIGHT; i++) {
        uint8_t rgb[3] = {px[i * 4 + 2], px[i * 4 + 1], px[i * 4]};
        fwrite(rgb, 1, 3, f);
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    struct ref r;
    memset(&r, 0, sizeof r);
    const char *font = NULL, *out = NULL;
    int evidence = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--feed") && i + 1 < argc) {
            r.single = !strcmp(argv[++i], "single");
        } else if (!strcmp(argv[i], "--evidence")) {
            evidence = 1;
        } else if (!strcmp(argv[i], "--out") && i + 1 < argc) {
            out = argv[++i];
        } else {
            font = argv[i];
        }
    }
    if (!font) {
        fprintf(stderr, "usage: lvgl-ref [--feed batch|single] [--evidence] [--out DIR] FONT\n");
        return 2;
    }
    for (int i = 0; i < 2; i++) {
        r.buffer[i] = calloc(1, DEMO_BUFFER_BYTES);
    }
    r.first = calloc(1, DEMO_BUFFER_BYTES);
    r.after = calloc(1, DEMO_BUFFER_BYTES);
    demo_host host = {
        .user = &r,
        .buffer = {r.buffer[0], r.buffer[1]},
        .post = post,
        .wait_free = wait_free,
        .events = events,
        .pause = pause_cb,
        .log = say,
    };
    if (evidence) {
        if (demo_evidence(&host, font) != 0) {
            fprintf(stderr, "lvgl-ref: the evidence failed\n");
            return 1;
        }
        /* The mode of the TrueType interpreter, read from the library (this
         * program only; the demo code never touches properties). */
        FT_Library library;
        FT_UInt version = 0;
        FT_Init_FreeType(&library);
        FT_Property_Get(library, "truetype", "interpreter-version", &version);
        printf("lvgl-ref: evidence truetype interpreter-version %u\n", version);
        FT_Done_FreeType(library);
    }
    demo *d = demo_open(&host, font, 1);
    if (!d) {
        return 1;
    }
    demo_result result;
    if (demo_probe(d, &result) != 0) {
        return 1;
    }
    printf("lvgl-ref: state %s\n", result.status);
    printf("lvgl-ref: turns %u frames %u\n", result.turns, result.frames);
    if (out) {
        char path[512];
        snprintf(path, sizeof path, "%s/ref.txt", out);
        FILE *f = fopen(path, "w");
        if (f) {
            fprintf(f, "first crc %08X\nafter crc %08X\nstate %s\n", (unsigned)result.first_crc,
                    (unsigned)result.after_crc, result.status);
            fclose(f);
        }
        write_ppm(out, "first.ppm", r.first);
        write_ppm(out, "after.ppm", r.after);
    }
    demo_close(d);
    return 0;
}
