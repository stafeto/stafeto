/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * A client of the desk (the probe of the manager `desk`): one window with a
 * title and an application id, a pattern of its colour, and the answers a
 * client gives the manager.
 *
 *   desk-client NAME X Y W H RRGGBB [stubborn] [resizable]
 *
 * NAME is the window's title and application id, (X, Y) its place, W by H its
 * size and RRGGBB its colour in hexadecimal. A CLOSE_REQUEST closes the window
 * and ends the program with code 0; with `stubborn` the request is ignored,
 * so the manager's SIGTERM ends the program. With `resizable` the window has
 * buffers for the whole screen and answers a CONFIGURE with the size asked.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stafeto/window.h>

#include "pattern.h"

#define MS 1000000ull
#define SECOND (1000 * MS)

static int draw(int win, unsigned *current, uint32_t w, uint32_t h, uint32_t colour)
{
    struct stafeto_window info;
    unsigned next = 1 - *current;
    uint32_t free_mask = 0;
    if (stafeto_window_info(win, &info) != 0) {
        return -1;
    }
    if (stafeto_window_wait_free(win, 1u << next, 60 * SECOND, &free_mask) != 0) {
        return -1;
    }
    pattern_fill((uint32_t *)info.pixels[next], info.stride / 4, w, h, colour);
    if (stafeto_window_post(win, next, NULL, 0) != 0) {
        return -1;
    }
    *current = next;
    return 0;
}

int main(int argc, char **argv)
{
    int stubborn = 0, resizable = 0;
    if (argc < 7) {
        fprintf(stderr, "usage: desk-client NAME X Y W H RRGGBB [stubborn] [resizable]\n");
        return 2;
    }
    for (int i = 7; i < argc; i++) {
        stubborn |= strcmp(argv[i], "stubborn") == 0;
        resizable |= strcmp(argv[i], "resizable") == 0;
    }
    const char *name = argv[1];
    int x = atoi(argv[2]), y = atoi(argv[3]);
    uint32_t w = (uint32_t)atoi(argv[4]), h = (uint32_t)atoi(argv[5]);
    uint32_t colour = (uint32_t)strtoul(argv[6], NULL, 16);
    struct stafeto_window win;
    int number = stafeto_window_open(x, y, (int)w, (int)h, STAFETO_WINDOW_XRGB8888, 2,
                                     resizable ? STAFETO_WINDOW_RESIZABLE : 0, &win);
    if (number < 0) {
        printf("desk-client %s: cannot open the window: errno %d\n", name, errno);
        return 1;
    }
    unsigned current = 1;
    if (stafeto_window_set_title(number, name) != 0 || stafeto_window_set_app_id(number, name) != 0 ||
        draw(number, &current, w, h, colour) != 0) {
        printf("desk-client %s: cannot set up the window: errno %d\n", name, errno);
        return 1;
    }
    printf("desk-client %s: up\n", name);
    fflush(stdout);
    for (;;) {
        struct stafeto_window_event e[STAFETO_WINDOW_EVENTS_MAX];
        uint32_t bits = 0;
        if (stafeto_window_wait(number, 500 * MS, &bits) != 0 && errno != ETIMEDOUT &&
            errno != EINTR) {
            printf("desk-client %s: the display ended: errno %d\n", name, errno);
            return 1;
        }
        int n = stafeto_window_events(number, e, STAFETO_WINDOW_EVENTS_MAX, NULL);
        for (int i = 0; i < n; i++) {
            switch (e[i].kind) {
            case STAFETO_WINDOW_EVENT_CLOSE_REQUEST:
                if (stubborn) {
                    printf("desk-client %s: close request ignored\n", name);
                    fflush(stdout);
                    break;
                }
                stafeto_window_close(number);
                printf("desk-client %s: closed\n", name);
                fflush(stdout);
                return 0;
            case STAFETO_WINDOW_EVENT_CONFIGURE:
                if (resizable && e[i].x > 0 && e[i].y > 0) {
                    w = (uint32_t)e[i].x;
                    h = (uint32_t)e[i].y;
                    if (stafeto_window_resize(number, w, h, (uint32_t)e[i].value) == 0) {
                        draw(number, &current, w, h, colour);
                    }
                }
                break;
            default:
                break;
            }
        }
    }
}
