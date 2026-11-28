/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include "desk_io.h"

#include <errno.h>
#include <string.h>
#include <time.h>

static uint32_t tick_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint32_t)((uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u);
}

void desk_io_init(void)
{
    lv_tick_set_cb(tick_ms);
}

static void flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map)
{
    desk_surface *s = lv_display_get_user_data(disp);
    struct stafeto_rect r = {area->x1, area->y1, area->x2 - area->x1 + 1, area->y2 - area->y1 + 1};
    if (s->rect_count < DESK_IO_RECTS) {
        s->rects[s->rect_count++] = r;
    } else {
        /* More areas than the list holds: the last grows to cover them. */
        struct stafeto_rect *l = &s->rects[DESK_IO_RECTS - 1];
        int32_t x2 = l->x + l->w > r.x + r.w ? l->x + l->w : r.x + r.w;
        int32_t y2 = l->y + l->h > r.y + r.h ? l->y + l->h : r.y + r.h;
        l->x = l->x < r.x ? l->x : r.x;
        l->y = l->y < r.y ? l->y : r.y;
        l->w = x2 - l->x;
        l->h = y2 - l->y;
    }
    if (lv_display_flush_is_last(disp)) {
        unsigned buffer = px_map == (uint8_t *)s->window.pixels[1] ? 1 : 0;
        if (!s->gone && stafeto_window_post(s->win, buffer, s->rects, s->rect_count) != 0) {
            s->gone = 1;
        }
        s->posts++;
        s->rect_count = 0;
    }
    /* No lv_display_flush_ready: LVGL clears the flag itself when the wait
     * function returns. */
}

/* LVGL asks before it draws into the buffer it is about to use. */
static void flush_wait_cb(lv_display_t *disp)
{
    desk_surface *s = lv_display_get_user_data(disp);
    lv_draw_buf_t *active = lv_display_get_buf_active(disp);
    unsigned buffer = (active && active->data == s->window.pixels[1]) ? 1 : 0;
    while (!s->gone) {
        uint32_t free_mask = 0;
        if (stafeto_window_wait_free(s->win, STAFETO_WINDOW_BUFFER(buffer), DESK_IO_WAIT_NS,
                                     &free_mask) == 0) {
            return;
        }
        if (errno != ETIMEDOUT && errno != EINTR) {
            s->gone = 1;
        }
    }
}

int desk_surface_open(desk_surface *s, int kind, int x, int y, int w, int h)
{
    memset(s, 0, sizeof *s);
    s->win = stafeto_window_open(x, y, w, h, STAFETO_WINDOW_XRGB8888, 2, 0, &s->window);
    if (s->win < 0) {
        return -1;
    }
    if (stafeto_window_id(s->win, &s->id) != 0) {
        int saved = errno;
        stafeto_window_close(s->win);
        errno = saved;
        return -1;
    }
    s->kind = kind;
    s->display = lv_display_create(w, h);
    lv_display_set_color_format(s->display, LV_COLOR_FORMAT_XRGB8888);
    lv_display_set_buffers_with_stride(s->display, s->window.pixels[0], s->window.pixels[1],
                                       s->window.stride * (uint32_t)h, s->window.stride,
                                       LV_DISPLAY_RENDER_MODE_DIRECT);
    lv_display_set_user_data(s->display, s);
    lv_display_set_flush_cb(s->display, flush_cb);
    lv_display_set_flush_wait_cb(s->display, flush_wait_cb);
    return 0;
}

void desk_surface_refresh(desk_surface *s)
{
    if (s->kind != DESK_SURFACE_NONE && !s->gone) {
        lv_refr_now(s->display);
    }
}

void desk_surface_close(desk_surface *s)
{
    if (s->display) {
        lv_display_delete(s->display);
    }
    if (s->kind != DESK_SURFACE_NONE) {
        stafeto_window_close(s->win);
    }
    memset(s, 0, sizeof *s);
}
