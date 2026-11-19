/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include "demo.h"

#include <stdio.h>
#include <string.h>

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_OUTLINE_H

#include "lvgl.h"

#include "crc.h"
#include "keys.h"
#include "schedule.h"

/* keys.h repeats the values of LV_KEY_*. */
_Static_assert(KEYS_UP == LV_KEY_UP && KEYS_DOWN == LV_KEY_DOWN, "key values");
_Static_assert(KEYS_LEFT == LV_KEY_LEFT && KEYS_RIGHT == LV_KEY_RIGHT, "key values");
_Static_assert(KEYS_ESC == LV_KEY_ESC && KEYS_DEL == LV_KEY_DEL, "key values");
_Static_assert(KEYS_BACKSPACE == LV_KEY_BACKSPACE && KEYS_ENTER == LV_KEY_ENTER, "key values");
_Static_assert(KEYS_NEXT == LV_KEY_NEXT && KEYS_HOME == LV_KEY_HOME && KEYS_END == LV_KEY_END,
               "key values");

/* The milliseconds the virtual clock of the probe advances in a turn. */
#define TURN_MS 16
/* The turns the probe waits for a frame to settle before it gives up. */
#define SETTLE_TURNS 4000

struct demo {
    demo_host host;
    int probe;
    int stopped;
    uint32_t vnow;              /* the virtual clock, in milliseconds */
    sched sched;
    lv_display_t *display;
    lv_indev_t *pointer;
    lv_indev_t *keypad;
    lv_font_t *font16;
    lv_font_t *font22;
    lv_obj_t *count_label;
    lv_obj_t *check;
    lv_obj_t *toggle;
    lv_obj_t *slider;
    lv_obj_t *value_label;
    lv_obj_t *area;
    int presses;
    demo_rect rects[DEMO_MAX_RECTS];
    unsigned rect_count;
    unsigned flushes;           /* flush calls in the current turn */
    unsigned posted;            /* frames posted */
    unsigned last_posted;       /* the buffer of the last post */
    unsigned turns;
};

/* The callbacks of LVGL carry no argument of ours: one demo at a time. */
static demo *current;

static void say(demo *d, const char *fmt, const char *text)
{
    char line[200];
    snprintf(line, sizeof line, fmt, text);
    if (d->host.log) {
        d->host.log(d->host.user, line);
    }
}

/* ---- the display ---- */

static unsigned buffer_of(const demo *d, const uint8_t *px)
{
    return px == d->host.buffer[1] ? 1 : 0;
}

static void flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map)
{
    demo *d = current;
    d->flushes++;
    demo_rect r = {area->x1, area->y1, area->x2 - area->x1 + 1, area->y2 - area->y1 + 1};
    if (d->rect_count < DEMO_MAX_RECTS) {
        d->rects[d->rect_count++] = r;
    } else {
        /* More areas than the list holds: the last entry grows to cover them. */
        demo_rect *l = &d->rects[DEMO_MAX_RECTS - 1];
        int32_t x2 = l->x + l->w > r.x + r.w ? l->x + l->w : r.x + r.w;
        int32_t y2 = l->y + l->h > r.y + r.h ? l->y + l->h : r.y + r.h;
        l->x = l->x < r.x ? l->x : r.x;
        l->y = l->y < r.y ? l->y : r.y;
        l->w = x2 - l->x;
        l->h = y2 - l->y;
    }
    if (lv_display_flush_is_last(disp)) {
        unsigned b = buffer_of(d, px_map);
        if (d->host.post && d->host.post(d->host.user, b, d->rects, d->rect_count) != 0) {
            d->stopped = 1;
        }
        d->posted++;
        d->last_posted = b;
        d->rect_count = 0;
    }
    /* No lv_display_flush_ready: LVGL clears the flag itself when the wait
     * function returns. */
}

/* LVGL asks before it draws into the buffer it is about to use. */
static void flush_wait_cb(lv_display_t *disp)
{
    demo *d = current;
    lv_draw_buf_t *active = lv_display_get_buf_active(disp);
    unsigned b = (active && active->data == d->host.buffer[1]) ? 1 : 0;
    if (d->host.wait_free && d->host.wait_free(d->host.user, b) != 0) {
        d->stopped = 1;
    }
}

/* ---- the input devices ---- */

static void pointer_read(lv_indev_t *indev, lv_indev_data_t *data)
{
    (void)indev;
    int32_t x, y;
    int pressed;
    data->continue_reading = sched_pointer(&current->sched, &x, &y, &pressed) != 0;
    data->point.x = x;
    data->point.y = y;
    data->state = pressed ? LV_INDEV_STATE_PRESSED : LV_INDEV_STATE_RELEASED;
}

static void keypad_read(lv_indev_t *indev, lv_indev_data_t *data)
{
    (void)indev;
    uint32_t key;
    int pressed;
    data->continue_reading = sched_keypad(&current->sched, &key, &pressed) != 0;
    data->key = key;
    data->state = pressed ? LV_INDEV_STATE_PRESSED : LV_INDEV_STATE_RELEASED;
}

/* ---- time and log ---- */

static uint32_t tick_cb(void)
{
    demo *d = current;
    if (d->probe || !d->host.now_ms) {
        return d->vnow;
    }
    return d->host.now_ms(d->host.user);
}

static void log_cb(lv_log_level_t level, const char *text)
{
    (void)level;
    demo *d = current;
    char line[240];
    size_t n = strlen(text);
    while (n > 0 && (text[n - 1] == '\n' || text[n - 1] == '\r')) {
        n--;
    }
    snprintf(line, sizeof line, "lvgl: %.*s", (int)n, text);
    if (d->host.log) {
        d->host.log(d->host.user, line);
    }
}

/* ---- the screen ---- */

static void button_clicked(lv_event_t *e)
{
    (void)e;
    demo *d = current;
    d->presses++;
    lv_label_set_text_fmt(d->count_label, "Pressed %d times", d->presses);
}

static void slider_changed(lv_event_t *e)
{
    (void)e;
    demo *d = current;
    lv_label_set_text_fmt(d->value_label, "%d", (int)lv_slider_get_value(d->slider));
}

static void place(lv_obj_t *obj, int x, int y)
{
    lv_obj_set_pos(obj, x, y);
}

static void build_screen(demo *d)
{
    lv_obj_t *screen = lv_screen_active();
    lv_obj_set_style_pad_all(screen, 0, 0);
    lv_obj_set_scrollable(screen, false);

    lv_obj_t *title = lv_label_create(screen);
    lv_obj_set_style_text_font(title, d->font22, 0);
    lv_label_set_text(title, SCENE_TITLE);
    place(title, SCENE_TITLE_X, SCENE_TITLE_Y);

    lv_obj_t *body = lv_label_create(screen);
    lv_label_set_long_mode(body, LV_LABEL_LONG_MODE_WRAP);
    lv_obj_set_width(body, SCENE_BODY_W);
    lv_label_set_text(body, SCENE_BODY_TEXT);
    place(body, SCENE_BODY_X, SCENE_BODY_Y);

    lv_obj_t *button = lv_button_create(screen);
    lv_obj_set_size(button, SCENE_BUTTON_W, SCENE_BUTTON_H);
    place(button, SCENE_BUTTON_X, SCENE_BUTTON_Y);
    lv_obj_t *caption = lv_label_create(button);
    lv_label_set_text(caption, SCENE_BUTTON_TEXT);
    lv_obj_center(caption);
    lv_obj_add_event_cb(button, button_clicked, LV_EVENT_CLICKED, NULL);

    d->count_label = lv_label_create(screen);
    lv_label_set_text(d->count_label, "Pressed 0 times");
    place(d->count_label, SCENE_COUNT_X, SCENE_COUNT_Y);

    d->check = lv_checkbox_create(screen);
    lv_checkbox_set_text_static(d->check, SCENE_CHECK_TEXT);
    place(d->check, SCENE_CHECK_X, SCENE_CHECK_Y);

    d->toggle = lv_switch_create(screen);
    lv_obj_set_size(d->toggle, SCENE_SWITCH_W, SCENE_SWITCH_H);
    place(d->toggle, SCENE_SWITCH_X, SCENE_SWITCH_Y);

    d->slider = lv_slider_create(screen);
    lv_obj_set_size(d->slider, SCENE_SLIDER_W, SCENE_SLIDER_H);
    lv_slider_set_range(d->slider, 0, 100);
    lv_slider_set_value(d->slider, SCENE_SLIDER_START, LV_ANIM_OFF);
    place(d->slider, SCENE_SLIDER_X, SCENE_SLIDER_Y);
    d->value_label = lv_label_create(screen);
    lv_label_set_text_fmt(d->value_label, "%d", SCENE_SLIDER_START);
    place(d->value_label, SCENE_VALUE_X, SCENE_VALUE_Y);
    lv_obj_add_event_cb(d->slider, slider_changed, LV_EVENT_VALUE_CHANGED, NULL);

    d->area = lv_textarea_create(screen);
    lv_obj_set_size(d->area, SCENE_AREA_W, SCENE_AREA_H);
    place(d->area, SCENE_AREA_X, SCENE_AREA_Y);
    lv_textarea_set_one_line(d->area, true);
    lv_textarea_set_placeholder_text(d->area, SCENE_AREA_HINT);
    /* The cursor does not blink: the frame does not change by itself. */
    lv_obj_set_style_anim_duration(d->area, 0, LV_PART_CURSOR);
    /* The theme sets the blink time on the cursor in the focused state, which
     * outranks the style above in that state. */
    lv_obj_set_style_anim_duration(d->area, 0, LV_PART_CURSOR | LV_STATE_FOCUSED);

    /* The text area is the one member of the keyboard's group, in focus. */
    lv_group_t *group = lv_group_create();
    lv_group_add_obj(group, d->area);
    lv_group_focus_obj(d->area);
    lv_indev_set_group(d->keypad, group);
}

/* ---- opening and the loop ---- */

demo *demo_open(const demo_host *host, const char *font_path, int probe)
{
    static demo instance;
    demo *d = &instance;
    memset(d, 0, sizeof *d);
    d->host = *host;
    d->probe = probe;
    current = d;
    sched_init(&d->sched, probe);

    lv_init();
    lv_tick_set_cb(tick_cb);
    lv_log_register_print_cb(log_cb);
    /* lv_init has started FreeType, with LV_FREETYPE_CACHE_FT_GLYPH_CNT glyphs. */
    d->font16 = lv_freetype_font_create(font_path, LV_FREETYPE_FONT_RENDER_MODE_BITMAP,
                                        SCENE_TEXT_PX, LV_FREETYPE_FONT_STYLE_NORMAL);
    d->font22 = lv_freetype_font_create(font_path, LV_FREETYPE_FONT_RENDER_MODE_BITMAP,
                                        SCENE_TITLE_PX, LV_FREETYPE_FONT_STYLE_NORMAL);
    if (!d->font16 || !d->font22) {
        say(d, "demo: cannot open the font %s", font_path);
        return NULL;
    }
    /* The symbols (LV_SYMBOL_*) are not in Liberation Sans. */
    d->font16->fallback = &lv_font_montserrat_16;
    d->font22->fallback = &lv_font_montserrat_16;

    d->display = lv_display_create(DEMO_WIDTH, DEMO_HEIGHT);
    lv_display_set_color_format(d->display, LV_COLOR_FORMAT_XRGB8888);
    lv_display_set_buffers(d->display, d->host.buffer[0], d->host.buffer[1],
                           DEMO_BUFFER_BYTES, LV_DISPLAY_RENDER_MODE_DIRECT);
    lv_display_set_flush_cb(d->display, flush_cb);
    lv_display_set_flush_wait_cb(d->display, flush_wait_cb);

    lv_theme_t *theme = lv_theme_default_init(d->display, lv_palette_main(LV_PALETTE_BLUE),
                                              lv_palette_main(LV_PALETTE_RED), false, d->font16);
    lv_display_set_theme(d->display, theme);

    d->pointer = lv_indev_create();
    lv_indev_set_type(d->pointer, LV_INDEV_TYPE_POINTER);
    lv_indev_set_read_cb(d->pointer, pointer_read);
    d->keypad = lv_indev_create();
    lv_indev_set_type(d->keypad, LV_INDEV_TYPE_KEYPAD);
    lv_indev_set_read_cb(d->keypad, keypad_read);

    build_screen(d);
    return d;
}

void demo_close(demo *d)
{
    if (d->font16) {
        lv_freetype_font_delete(d->font16);
    }
    if (d->font22) {
        lv_freetype_font_delete(d->font22);
    }
    lv_deinit();
    current = NULL;
}

/* Hand the events that arrived to the queue, as long as a call returns as many
 * as it was asked for. The input events (not the focus) among them are added
 * to `*inputs`. */
static void pull_events(demo *d, unsigned *inputs)
{
    if (!d->host.events) {
        return;
    }
    demo_event batch[32];
    for (;;) {
        unsigned room = SCHED_QUEUE - d->sched.count;
        if (room > 32) {
            room = 32;
        }
        if (room == 0) {
            return;
        }
        unsigned n = d->host.events(d->host.user, batch, room);
        for (unsigned i = 0; i < n; i++) {
            if (batch[i].kind == DEMO_EVENT_KEY || batch[i].kind == DEMO_EVENT_MOVE
                || batch[i].kind == DEMO_EVENT_BUTTON) {
                if (inputs) {
                    (*inputs)++;
                }
            }
            sched_push(&d->sched, &batch[i]);
        }
        if (n < room) {
            return;
        }
    }
}

/* The real-time wait of the probe for the events of the scenario: the longest
 * it waits, and how often it looks. */
#define COLLECT_MS 30000
#define COLLECT_LOOKS 2000

/* Collect all the input events of the scenario before the clock of LVGL
 * runs again: the clock does not move while the program waits, so the time an
 * event takes to arrive cannot show in the pixels. */
static int collect_inputs(demo *d)
{
    unsigned inputs = 0;
    uint32_t start = d->host.now_ms ? d->host.now_ms(d->host.user) : 0;
    for (unsigned looks = 0;; looks++) {
        pull_events(d, &inputs);
        if (inputs >= SCENE_EVENTS) {
            return 0;
        }
        int late = d->host.now_ms ? d->host.now_ms(d->host.user) - start > COLLECT_MS
                                  : looks > COLLECT_LOOKS;
        if (late || d->stopped) {
            char line[120];
            snprintf(line, sizeof line, "only %u of %d input events came", inputs, SCENE_EVENTS);
            say(d, "demo: %s", line);
            return -1;
        }
        if (d->host.idle) {
            d->host.idle(d->host.user, TURN_MS);
        }
    }
}

/* One turn of the probe loop: the clock moves a fixed step, LVGL runs its
 * timers once, and the schedule learns whether the frame settled. */
static int probe_turn(demo *d, int pull)
{
    d->vnow += TURN_MS;
    d->turns++;
    if (pull) {
        pull_events(d, NULL);
    }
    d->flushes = 0;
    lv_timer_handler();
    /* A frame is not settled while a redraw is pending: the last step of an
     * animation can invalidate after a turn that drew nothing. */
    int drew = d->flushes != 0 || !lv_timer_get_paused(lv_display_get_refr_timer(d->display));
    return sched_end_turn(&d->sched, drew, lv_anim_count_running());
}

static int settle(demo *d, int pull, int (*done)(const demo *))
{
    for (unsigned i = 0; i < SETTLE_TURNS; i++) {
        int settled = probe_turn(d, pull);
        if (d->stopped) {
            return -1;
        }
        if (settled && done(d)) {
            return 0;
        }
    }
    return -1;
}

static int first_frame_done(const demo *d)
{
    return d->posted > 0;
}

static int scenario_done(const demo *d)
{
    return d->sched.changes >= SCENE_CHANGES && sched_idle(&d->sched);
}

static uint32_t posted_crc(demo *d, uint32_t *bands)
{
    const uint8_t *frame = d->host.buffer[d->last_posted];
    for (unsigned band = 0; band < DEMO_BANDS; band++) {
        bands[band] = crc32_xrgb(frame + (size_t)band * DEMO_BAND_ROWS * DEMO_STRIDE, DEMO_WIDTH,
                                 DEMO_BAND_ROWS, DEMO_STRIDE);
    }
    return crc32_xrgb(frame, DEMO_WIDTH, DEMO_HEIGHT, DEMO_STRIDE);
}

/* The frame is on the screen: false when the host says the display ended. */
static int shown(demo *d)
{
    if (d->host.pause && d->host.pause(d->host.user, 0) != 0) {
        say(d, "demo: %s", "the display ended before the frame was shown");
        return 0;
    }
    return 1;
}

int demo_probe(demo *d, demo_result *r)
{
    char line[200];
    memset(r, 0, sizeof *r);
    if (settle(d, 0, first_frame_done) != 0) {
        say(d, "demo: %s", "the first frame did not settle");
        return -1;
    }
    if (!shown(d)) {
        return -1;
    }
    r->first_crc = posted_crc(d, r->first_bands);
    snprintf(line, sizeof line, "first crc %08X", (unsigned)r->first_crc);
    if (d->host.log) {
        d->host.log(d->host.user, line);
    }
    if (d->host.pause && d->host.pause(d->host.user, 1) != 0) {
        say(d, "demo: %s", "the display ended before the snapshot");
        return -1;
    }
    /* All the events first, with no turn of the clock; then the scenario with
     * no further pulls. */
    if (collect_inputs(d) != 0) {
        return -1;
    }
    if (settle(d, 0, scenario_done) != 0) {
        snprintf(line, sizeof line, "the scenario did not finish: %u changes of %d, %u lost",
                 d->sched.changes, SCENE_CHANGES, d->sched.lost);
        say(d, "demo: %s", line);
        return -1;
    }
    if (!shown(d)) {
        return -1;
    }
    r->after_crc = posted_crc(d, r->after_bands);
    snprintf(line, sizeof line, "after crc %08X", (unsigned)r->after_crc);
    if (d->host.log) {
        d->host.log(d->host.user, line);
    }
    snprintf(r->status, sizeof r->status, SCENE_STATE_FORMAT, d->presses,
             lv_obj_has_state(d->check, LV_STATE_CHECKED) ? 1 : 0,
             lv_obj_has_state(d->toggle, LV_STATE_CHECKED) ? 1 : 0,
             (int)lv_slider_get_value(d->slider), lv_textarea_get_text(d->area));
    lv_mem_monitor_t monitor;
    lv_mem_monitor(&monitor);
    r->mem_max_used = (unsigned long)monitor.max_used;
    r->turns = d->turns;
    r->frames = d->posted;
    return 0;
}

void demo_bands(const demo_host *host, const demo_result *r)
{
    char line[DEMO_BANDS * 9 + 32];
    for (int which = 0; which < 2; which++) {
        const uint32_t *bands = which ? r->after_bands : r->first_bands;
        size_t at = (size_t)snprintf(line, sizeof line, "evidence bands %s", which ? "after" : "first");
        for (unsigned i = 0; i < DEMO_BANDS; i++) {
            at += (size_t)snprintf(line + at, sizeof line - at, " %08X", (unsigned)bands[i]);
        }
        host->log(host->user, line);
    }
}

void demo_run(demo *d)
{
    while (!d->stopped) {
        uint32_t wait = lv_timer_handler();
        pull_events(d, NULL);
        if (d->stopped) {
            break;
        }
        if (d->host.idle) {
            d->host.idle(d->host.user, wait < TURN_MS ? wait : TURN_MS);
        }
    }
}

/* ---- the evidence of the glyph path ---- */

static uint32_t crc_points(const FT_Outline *o)
{
    uint32_t state = crc32_start();
    for (int i = 0; i < o->n_points; i++) {
        int32_t xy[2] = {(int32_t)o->points[i].x, (int32_t)o->points[i].y};
        uint8_t bytes[8];
        for (int k = 0; k < 2; k++) {
            for (int b = 0; b < 4; b++) {
                bytes[k * 4 + b] = (uint8_t)((uint32_t)xy[k] >> (8 * b));
            }
        }
        state = crc32_feed(state, bytes, 8);
    }
    return crc32_finish(state);
}

int demo_evidence(const demo_host *host, const char *font_path)
{
    char line[200];
    FT_Library library;
    FT_Face face;
    if (FT_Init_FreeType(&library) != 0) {
        return -1;
    }
    if (FT_New_Face(library, font_path, 0, &face) != 0) {
        FT_Done_FreeType(library);
        return -1;
    }
    if (FT_Set_Pixel_Sizes(face, 0, SCENE_TEXT_PX) != 0) {
        FT_Done_Face(face);
        FT_Done_FreeType(library);
        return -1;
    }
    /* The flags of LVGL's glyph path (lv_freetype_glyph.c, lv_freetype_image.c). */
    const FT_Int32 hinted = FT_LOAD_NO_AUTOHINT | FT_LOAD_TARGET_NORMAL;
    for (const char *p = "agW0"; *p; p++) {
        FT_UInt index = FT_Get_Char_Index(face, (FT_ULong)(unsigned char)*p);
        if (FT_Load_Glyph(face, index, hinted) != 0) {
            FT_Done_Face(face);
            FT_Done_FreeType(library);
            return -1;
        }
        snprintf(line, sizeof line, "evidence glyph %c outline points %d contours %d crc %08X", *p,
                 face->glyph->outline.n_points, face->glyph->outline.n_contours,
                 (unsigned)crc_points(&face->glyph->outline));
        host->log(host->user, line);
        if (FT_Load_Glyph(face, index, hinted | FT_LOAD_RENDER) != 0) {
            FT_Done_Face(face);
            FT_Done_FreeType(library);
            return -1;
        }
        const FT_GlyphSlot slot = face->glyph;
        int pitch = slot->bitmap.pitch < 0 ? -slot->bitmap.pitch : slot->bitmap.pitch;
        snprintf(line, sizeof line,
                 "evidence glyph %c bitmap width %u rows %u pitch %d left %d top %d advance %ld crc %08X",
                 *p, slot->bitmap.width, slot->bitmap.rows, slot->bitmap.pitch, slot->bitmap_left,
                 slot->bitmap_top, (long)slot->advance.x,
                 (unsigned)crc32_bytes(slot->bitmap.buffer, (size_t)pitch * slot->bitmap.rows));
        host->log(host->user, line);
    }
    snprintf(line, sizeof line, "evidence multiple-masters %d", FT_HAS_MULTIPLE_MASTERS(face) ? 1 : 0);
    host->log(host->user, line);
    FT_Vector kerning = {0, 0};
    FT_Get_Kerning(face, FT_Get_Char_Index(face, 'A'), FT_Get_Char_Index(face, 'V'),
                   FT_KERNING_DEFAULT, &kerning);
    snprintf(line, sizeof line, "evidence kerning AV x %ld y %ld", (long)kerning.x, (long)kerning.y);
    host->log(host->user, line);
    FT_Done_Face(face);
    FT_Done_FreeType(library);
    return 0;
}
