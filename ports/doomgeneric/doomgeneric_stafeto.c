// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The platform of Doomgeneric for stafeto: the functions the engine asks of
// its host (doomgeneric.h) and `main`.
//
// This version runs without a screen. The display and the keyboard come
// from libc.so (stafeto_display_open, stafeto_input_read) once the services
// behind them exist; until then the stub below answers that no display is
// there (ENODEV), the frames go nowhere and no key is ever pressed. That is
// all `-timedemo` needs: the engine plays the demo, counts the game tics and
// reports them.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "doomgeneric.h"

// The call libc.so will have for the display. Until then the display is not
// there.
static int stafeto_display_open(void)
{
    errno = ENODEV;
    return -1;
}

static int have_display;

void DG_Init(void)
{
    have_display = stafeto_display_open() == 0;
    if (!have_display)
        fprintf(stderr, "doom: no display (%s), frames are dropped\n", "ENODEV");
}

void DG_DrawFrame(void)
{
    // No display: the frame in DG_ScreenBuffer is dropped.
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
    (void)pressed;
    (void)key;
    return 0;
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
