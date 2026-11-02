// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The platform of Doomgeneric for stafeto: the functions the engine asks of
// its host (doomgeneric.h) and `main`.
//
// The screen and the keyboard come from libc.so (<stafeto/display.h>). The
// screen is 640 by 400 points, XRGB8888, the size of the engine's frame
// (DOOMGENERIC_RESX by RESY, the engine scales its 320 by 200 by two), so
// DG_ScreenBuffer points at the buffer of the screen and a frame is shown
// without a copy. Where the screen does not open (an image without a
// display service, a screen that another process holds), the frames go
// nowhere and no key is ever pressed; that is all `-timedemo -nodraw` needs.
//
// Two lines on stderr let a probe follow the game: `doom: title crc32 X`
// at the first frame of the title screen and `doom: level E M` at the first
// frame of a level the player plays (the demos that follow the title run
// levels too). The CRC-32 is taken over the red, green and blue bytes
// of the frame, as the probe takes it over the screen QEMU photographs.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <stafeto/display.h>

#include "doomgeneric.h"
#include "doomkeys.h"
#include "doomstat.h"
#include "keys.h"

// The values of keys.h are the engine's.
_Static_assert(SK_UPARROW == KEY_UPARROW && SK_DOWNARROW == KEY_DOWNARROW,
               "arrows");
_Static_assert(SK_LEFTARROW == KEY_LEFTARROW && SK_RIGHTARROW == KEY_RIGHTARROW,
               "arrows");
_Static_assert(SK_ESCAPE == KEY_ESCAPE && SK_ENTER == KEY_ENTER, "esc, enter");
_Static_assert(SK_TAB == KEY_TAB && SK_BACKSPACE == KEY_BACKSPACE, "tab");
_Static_assert(SK_PAUSE == KEY_PAUSE && SK_CAPSLOCK == KEY_CAPSLOCK, "pause");
_Static_assert(SK_RSHIFT == KEY_RSHIFT && SK_RCTRL == KEY_RCTRL, "shift, ctrl");
_Static_assert(SK_RALT == KEY_RALT, "alt");
_Static_assert(SK_F1 == KEY_F1 && SK_F10 == KEY_F10 && SK_F11 == KEY_F11 &&
                   SK_F12 == KEY_F12 && SK_F1 + 9 == SK_F10,
               "function keys");
_Static_assert(SK_HOME == KEY_HOME && SK_END == KEY_END && SK_PGUP == KEY_PGUP &&
                   SK_PGDN == KEY_PGDN && SK_INS == KEY_INS &&
                   SK_DEL == KEY_DEL,
               "navigation keys");

// The most key events one read gives (the service's reply holds 120).
#define KEYS_PER_READ 120

static int have_display;
static struct stafeto_key pending[KEYS_PER_READ];
static int pending_at, pending_count;

void DG_Init(void)
{
    struct stafeto_display d;

    if (stafeto_display_open(&d) != 0) {
        fprintf(stderr, "doom: no display (%s), frames are dropped\n",
                strerror(errno));
        return;
    }
    if (d.width != DOOMGENERIC_RESX || d.height != DOOMGENERIC_RESY ||
        d.stride != DOOMGENERIC_RESX * 4 ||
        d.format != STAFETO_FORMAT_XRGB8888) {
        fprintf(stderr, "doom: the screen is %ux%u, format %u: frames are dropped\n",
                d.width, d.height, d.format);
        stafeto_display_close();
        return;
    }
    free(DG_ScreenBuffer);
    DG_ScreenBuffer = d.pixels;
    have_display = 1;
}

static uint32_t crc32_of_frame(const pixel_t *frame)
{
    uint32_t crc = 0xffffffffu;

    for (size_t i = 0; i < (size_t)DOOMGENERIC_RESX * DOOMGENERIC_RESY; i++) {
        for (int shift = 16; shift >= 0; shift -= 8) {
            crc ^= (frame[i] >> shift) & 0xffu;
            for (int bit = 0; bit < 8; bit++)
                crc = (crc >> 1) ^ (0xedb88320u & -(crc & 1u));
        }
    }
    return ~crc;
}

void DG_DrawFrame(void)
{
    static int title_said, level_said;

    if (!have_display)
        return;
    stafeto_display_flush(0, 0, DOOMGENERIC_RESX, DOOMGENERIC_RESY);
    // The lines follow the flush: the screen shows the frame they name.
    if (gamestate == GS_DEMOSCREEN && !title_said) {
        title_said = 1;
        fprintf(stderr, "doom: title crc32 %08x\n", crc32_of_frame(DG_ScreenBuffer));
    } else if (gamestate == GS_LEVEL && !demoplayback && !level_said) {
        level_said = 1;
        fprintf(stderr, "doom: level %d %d\n", gameepisode, gamemap);
    }
}

void DG_SleepMs(uint32_t ms)
{
    usleep(ms * 1000u);
}

uint32_t DG_GetTicksMs(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint32_t)(now.tv_sec * 1000u + now.tv_nsec / 1000000u);
}

int DG_GetKey(int *pressed, unsigned char *key)
{
    for (;;) {
        while (pending_at < pending_count) {
            const struct stafeto_key *k = &pending[pending_at++];
            int doom_key;

            if (!stafeto_key_event_wanted(k->type, k->value))
                continue;
            doom_key = stafeto_doom_key(k->code);
            if (doom_key == 0)
                continue;
            *pressed = k->value;
            *key = (unsigned char)doom_key;
            return 1;
        }
        pending_at = pending_count = 0;
        if (!have_display)
            return 0;
        // Without waiting; an error reads as no keys.
        pending_count = stafeto_input_read(pending, KEYS_PER_READ);
        if (pending_count <= 0) {
            pending_count = 0;
            return 0;
        }
    }
}

void DG_SetWindowTitle(const char *title)
{
    (void)title;
}

int main(int argc, char **argv)
{
    doomgeneric_Create(argc, argv);
    for (;;)
        doomgeneric_Tick();
}
