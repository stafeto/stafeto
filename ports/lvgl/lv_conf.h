/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The configuration of LVGL 9.6.0 for stafeto (tools/build-lvgl.py finds it
 * as "lv_conf.h" on the include path). LVGL supplies a default for every
 * name this file leaves out, so the build script checks the settings that
 * matter on the macros the compiler ends up with, and
 * tools/test_build_lvgl.py checks this file.
 *
 * The program is one thread. The drawing is integer arithmetic into the two
 * XRGB8888 buffers of a window of 640 x 400, with the text drawn by FreeType
 * (ports/freetype), so the same sources give the same pixels on every run. */
#ifndef LV_CONF_H
#define LV_CONF_H

/* ---- memory and the C library ---- */

/* LVGL's own allocator over a pool in .bss: its size is known at build time. */
#define LV_USE_STDLIB_MALLOC LV_STDLIB_BUILTIN
#define LV_MEM_SIZE (512 * 1024)
#define LV_USE_STDLIB_STRING LV_STDLIB_CLIB
#define LV_USE_STDLIB_SPRINTF LV_STDLIB_BUILTIN
#define LV_STDINT_INCLUDE <stdint.h>

/* ---- one thread, no operating system layer ---- */

#define LV_USE_OS LV_OS_NONE

/* ---- display and drawing ---- */

#define LV_COLOR_FORMAT_DEFAULT LV_COLOR_FORMAT_XRGB8888
#define LV_DEF_REFR_PERIOD 16
#define LV_USE_DRAW_SW 1
#define LV_DRAW_SW_DRAW_UNIT_CNT 1
#define LV_DRAW_SW_COMPLEX 1
#define LV_USE_DRAW_SW_ASM LV_DRAW_SW_ASM_NONE
#define LV_DRAW_SW_SUPPORT_RGB565 0
#define LV_DRAW_SW_SUPPORT_RGB565_SWAPPED 0
#define LV_DRAW_SW_SUPPORT_RGB565A8 0
#define LV_DRAW_SW_SUPPORT_RGB888 0
#define LV_DRAW_SW_SUPPORT_XRGB8888 1
#define LV_DRAW_SW_SUPPORT_ARGB8888 1
#define LV_DRAW_SW_SUPPORT_ARGB8888_PREMULTIPLIED 0
#define LV_DRAW_SW_SUPPORT_L8 1
#define LV_DRAW_SW_SUPPORT_AL88 0
#define LV_DRAW_SW_SUPPORT_A8 1
#define LV_DRAW_SW_SUPPORT_I1 0
#define LV_USE_FLOAT 0
#define LV_USE_MATRIX 0
#define LV_DRAW_TRANSFORM_USE_MATRIX 0
#define LV_USE_VECTOR_GRAPHIC 0
#define LV_USE_THORVG 0
#define LV_USE_SNAPSHOT 0
#define LV_USE_OBSERVER 0
#define LV_USE_FLEX 0
#define LV_USE_GRID 0

/* ---- themes and fonts ---- */

#define LV_USE_THEME_DEFAULT 1
#define LV_THEME_DEFAULT_DARK 0
#define LV_THEME_DEFAULT_GROW 1
#define LV_THEME_DEFAULT_TRANSITION_TIME 80
#define LV_USE_THEME_SIMPLE 0
#define LV_USE_THEME_MONO 0

/* Montserrat 16 stays as the font of the LV_SYMBOL_* signs, which the
 * Liberation Sans of the demo lacks. */
#define LV_FONT_MONTSERRAT_14 0
#define LV_FONT_MONTSERRAT_16 1
#define LV_FONT_DEFAULT LV_FONT_DEFAULT_MONTSERRAT_16
#define LV_USE_FONT_PLACEHOLDER 1

/* FreeType (src/font/freetype) over the library of ports/freetype, with
 * FreeType's own allocator and file reads. */
#define LV_USE_FREETYPE 1
#define LV_FREETYPE_USE_LVGL_PORT 0
#define LV_FREETYPE_CACHE_FT_GLYPH_CNT 256
#define LV_FREETYPE_CACHE_FT_GLYPH_L1 1
#define LV_USE_TINY_TTF 0
#define LV_USE_IMGFONT 0
#define LV_USE_FONT_MANAGER 0
#define LV_USE_BIDI 0

/* ---- widgets: the ones the demo draws ---- */

#define LV_USE_LABEL 1
#define LV_USE_BUTTON 1
#define LV_USE_CHECKBOX 1
#define LV_USE_SWITCH 1
#define LV_USE_SLIDER 1
#define LV_USE_BAR 1
#define LV_USE_TEXTAREA 1
#define LV_USE_IMAGE 1

#define LV_USE_ANIMIMG 0
#define LV_USE_ARC 0
#define LV_USE_ARCLABEL 0
#define LV_USE_BARCODE 0
#define LV_USE_BUTTONMATRIX 0
#define LV_USE_CALENDAR 0
#define LV_USE_CANVAS 0
#define LV_USE_CHART 0
#define LV_USE_DROPDOWN 0
#define LV_USE_GIF 0
#define LV_USE_IMAGEBUTTON 0
#define LV_USE_KEYBOARD 0
#define LV_USE_LED 0
#define LV_USE_LINE 0
#define LV_USE_LIST 0
#define LV_USE_MENU 0
#define LV_USE_MSGBOX 0
#define LV_USE_QRCODE 0
#define LV_USE_ROLLER 0
#define LV_USE_SCALE 0
#define LV_USE_SPAN 0
#define LV_USE_SPINBOX 0
#define LV_USE_SPINNER 0
#define LV_USE_TABLE 0
#define LV_USE_TABVIEW 0
#define LV_USE_TILEVIEW 0
#define LV_USE_WIN 0
#define LV_USE_GRIDNAV 0
#define LV_USE_FRAGMENT 0
#define LV_USE_FILE_EXPLORER 0
#define LV_USE_IME_PINYIN 0
#define LV_USE_LOTTIE 0
#define LV_USE_3DTEXTURE 0

/* ---- images, file systems and drivers: none ---- */

#define LV_USE_LODEPNG 0
#define LV_USE_LIBPNG 0
#define LV_USE_BMP 0
#define LV_USE_TJPGD 0
#define LV_USE_LIBJPEG_TURBO 0
#define LV_USE_LIBWEBP 0
#define LV_USE_SVG 0
#define LV_USE_FFMPEG 0
#define LV_USE_RLE 0
#define LV_USE_LZ4 0

#define LV_USE_FS_STDIO 0
#define LV_USE_FS_POSIX 0
#define LV_USE_FS_WIN32 0
#define LV_USE_FS_FATFS 0
#define LV_USE_FS_LITTLEFS 0
#define LV_USE_FS_ARDUINO_ESP_LITTLEFS 0
#define LV_USE_FS_ARDUINO_SD 0
#define LV_USE_FS_UEFI 0
#define LV_USE_FS_FROGFS 0
#define LV_USE_FS_MEMFS 0

#define LV_USE_LINUX_DRM 0
#define LV_USE_LINUX_FBDEV 0
#define LV_USE_EVDEV 0
#define LV_USE_LIBINPUT 0
#define LV_USE_SDL 0
#define LV_USE_X11 0
#define LV_USE_WAYLAND 0
#define LV_USE_OPENGLES 0
#define LV_USE_GLFW 0
#define LV_USE_NUTTX 0
#define LV_USE_UEFI 0
#define LV_USE_WINDOWS 0

/* ---- no monitors, profilers or tests: nothing on the screen changes by itself ---- */

#define LV_USE_SYSMON 0
#define LV_USE_PERF_MONITOR 0
#define LV_USE_MEM_MONITOR 0
#define LV_USE_PROFILER 0
#define LV_USE_TEST 0
#define LV_USE_MONKEY 0
#define LV_USE_REFR_DEBUG 0
#define LV_USE_LAYER_DEBUG 0
#define LV_USE_PARALLEL_DRAW_DEBUG 0
#define LV_BUILD_EXAMPLES 0
#define LV_BUILD_DEMOS 0

/* ---- log and assertions ---- */

/* The log goes to the callback the program registers with
 * lv_log_register_print_cb (to standard error); no time stamps, so the text
 * of a run does not depend on the clock. */
#define LV_USE_LOG 1
#define LV_LOG_LEVEL LV_LOG_LEVEL_WARN
#define LV_LOG_PRINTF 0
#define LV_LOG_USE_TIMESTAMP 0
#define LV_LOG_USE_FILE_LINE 1

#define LV_USE_ASSERT_NULL 1
#define LV_USE_ASSERT_MALLOC 1
/* A failed assertion ends the program (lv_assert_handler.h defines the handler). */
#define LV_ASSERT_USE_CUSTOM_INCLUDE 1
#define LV_ASSERT_CUSTOM_INCLUDE "lv_assert_handler.h"

#endif
