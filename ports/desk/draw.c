/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include "draw.h"

#include <string.h>

static lv_color_t rgb(uint32_t c)
{
    return lv_color_hex(c);
}

/* A rectangle with no style but its colour. */
static lv_obj_t *rect(lv_obj_t *parent, int32_t x, int32_t y, int32_t w, int32_t h, uint32_t c)
{
    lv_obj_t *o = lv_obj_create(parent);
    lv_obj_remove_style_all(o);
    lv_obj_set_pos(o, x, y);
    lv_obj_set_size(o, w, h);
    lv_obj_set_style_bg_color(o, rgb(c), 0);
    lv_obj_set_style_bg_opa(o, LV_OPA_COVER, 0);
    lv_obj_set_scrollable(o, false);
    lv_obj_set_clickable(o, false);
    return o;
}

/* A one-line label that clips what does not fit its width. */
static lv_obj_t *text(lv_obj_t *parent, const lv_font_t *font, int32_t x, int32_t y, int32_t w,
                      uint32_t c)
{
    lv_obj_t *l = lv_label_create(parent);
    lv_obj_set_style_text_font(l, font, 0);
    lv_obj_set_style_text_color(l, rgb(c), 0);
    lv_label_set_long_mode(l, LV_LABEL_LONG_MODE_CLIP);
    lv_obj_set_width(l, w);
    lv_obj_set_pos(l, x, y);
    lv_label_set_text_static(l, "");
    return l;
}

static void screen_style(lv_obj_t *screen, uint32_t c)
{
    lv_obj_remove_style_all(screen);
    lv_obj_set_style_bg_color(screen, rgb(c), 0);
    lv_obj_set_style_bg_opa(screen, LV_OPA_COVER, 0);
    lv_obj_set_scrollable(screen, false);
}

static void set_text(lv_obj_t *label, const char *s)
{
    if (strcmp(lv_label_get_text(label), s) != 0) {
        lv_label_set_text(label, s);
    }
}

void desk_frame_view_init(desk_frame_view *v, lv_display_t *disp, const lv_font_t *font,
                          int32_t w, int32_t h)
{
    lv_obj_t *screen = lv_display_get_screen_active(disp);
    v->w = w;
    v->h = h;
    screen_style(screen, DESK_COLOR_IDLE);
    rect(screen, DESK_BORDER, DESK_BAR, w - 2 * DESK_BORDER, h - DESK_BAR - DESK_BORDER,
         DESK_COLOR_CLIENT);
    int32_t font_h = lv_font_get_line_height(font);
    v->title = text(screen, font, 8, (DESK_BAR - font_h) / 2, w - DESK_CLOSE_W - 12,
                    DESK_COLOR_TEXT);
    lv_obj_t *close = rect(screen, w - DESK_CLOSE_W, 0, DESK_CLOSE_W, DESK_BAR, DESK_COLOR_CLOSE);
    lv_obj_t *x = lv_label_create(close);
    lv_obj_set_style_text_font(x, font, 0);
    lv_obj_set_style_text_color(x, rgb(DESK_COLOR_TEXT), 0);
    lv_label_set_text_static(x, "x");
    lv_obj_center(x);
}

void desk_frame_view_set(desk_frame_view *v, lv_display_t *disp, const char *title, int focused)
{
    lv_obj_t *screen = lv_display_get_screen_active(disp);
    lv_obj_set_style_bg_color(screen, rgb(focused ? DESK_COLOR_FOCUS : DESK_COLOR_IDLE), 0);
    set_text(v->title, title);
}

void desk_panel_view_init(desk_panel_view *v, lv_display_t *disp, const lv_font_t *font,
                          int32_t w)
{
    (void)w;
    lv_obj_t *screen = lv_display_get_screen_active(disp);
    screen_style(screen, DESK_COLOR_PANEL);
    int32_t font_h = lv_font_get_line_height(font);
    for (int i = 0; i < DESK_MAX_WINDOWS; i++) {
        v->cell[i] = rect(screen, 0, 1, DESK_CELL_MAX - 2, DESK_PANEL_H - 2, DESK_COLOR_CELL);
        lv_obj_set_hidden(v->cell[i], true);
        v->label[i] = text(v->cell[i], font, 6, (DESK_PANEL_H - 2 - font_h) / 2, DESK_CELL_MAX - 14,
                           DESK_COLOR_TEXT);
    }
}

void desk_panel_view_set(desk_panel_view *v, const desk_policy *p)
{
    unsigned n = desk_cells(p);
    int32_t cw = desk_cell_width(p);
    for (unsigned i = 0; i < DESK_MAX_WINDOWS; i++) {
        const desk_win *w = i < n ? desk_cell(p, i) : NULL;
        if (!w) {
            lv_obj_set_hidden(v->cell[i], true);
            continue;
        }
        lv_obj_set_hidden(v->cell[i], false);
        lv_obj_set_x(v->cell[i], (int32_t)i * cw);
        lv_obj_set_width(v->cell[i], cw - 2);
        lv_obj_set_width(v->label[i], cw - 14);
        lv_obj_set_style_bg_color(
            v->cell[i], rgb(w->id == p->focus ? DESK_COLOR_FOCUS : DESK_COLOR_CELL), 0);
        lv_obj_set_style_text_color(v->label[i], rgb(w->hidden ? DESK_COLOR_DIM : DESK_COLOR_TEXT),
                                    0);
        set_text(v->label[i], w->title[0] ? w->title : w->app_id[0] ? w->app_id : "?");
    }
}
