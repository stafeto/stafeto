// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The configuration of FreeType 2.14.3 for stafeto (the file its build reads
// through FT_CONFIG_OPTIONS_H, tools/build-freetype.py). The glyph path is
// integer arithmetic on one thread: the outline of a TrueType glyph, the
// scale by FT_MulFix in 64-bit integers, the hinting by the byte-code
// interpreter (version 40 rules), the coverage of the smooth rasterizer in
// 8 bits. The same sources with this file give the same pixels on every run.
// tools/test_build_freetype.py checks that the macros listed below as left
// undefined are absent from this file.
#ifndef STAFETO_FTOPTION_H_
#define STAFETO_FTOPTION_H_

#include <ft2build.h>

// No 32-bit assembler fragments: FT_MulFix is plain 64-bit C.
#define FT_CONFIG_OPTION_NO_ASSEMBLER
#define FT_CONFIG_OPTION_INLINE_MULFIX

// The memory the smooth rasterizer renders a glyph in, and the table of modules.
#define FT_RENDER_POOL_SIZE 16384L
#define FT_MAX_MODULES 32

// TrueType: the hinting interpreter with the rules of version 40 (they have
// no relation to the LCD filter) and the tables the driver reads.
#define TT_CONFIG_OPTION_BYTECODE_INTERPRETER
#define TT_CONFIG_OPTION_SUBPIXEL_HINTING
#define TT_CONFIG_OPTION_EMBEDDED_BITMAPS
#define TT_CONFIG_CMAP_FORMAT_0
#define TT_CONFIG_CMAP_FORMAT_2
#define TT_CONFIG_CMAP_FORMAT_4
#define TT_CONFIG_CMAP_FORMAT_6
#define TT_CONFIG_CMAP_FORMAT_8
#define TT_CONFIG_CMAP_FORMAT_10
#define TT_CONFIG_CMAP_FORMAT_12
#define TT_CONFIG_CMAP_FORMAT_13
#define TT_CONFIG_CMAP_FORMAT_14
#ifndef TT_CONFIG_OPTION_MAX_RUNNABLE_OPCODES
#define TT_CONFIG_OPTION_MAX_RUNNABLE_OPCODES 1000000L
#endif

// Sizes of the structures psaux.h declares (the header comes in with
// ftobjs.h; no Type 1 or CFF driver is built).
#define T1_MAX_DICT_DEPTH 5
#define T1_MAX_SUBRS_CALLS 16
#define T1_MAX_CHARSTRINGS_OPERANDS 256

// The two macros FreeType's own file derives from the options above.
#ifdef TT_CONFIG_OPTION_BYTECODE_INTERPRETER
#define TT_USE_BYTECODE_INTERPRETER
#ifdef TT_CONFIG_OPTION_SUBPIXEL_HINTING
#define TT_SUPPORT_SUBPIXEL_HINTING_MINIMAL
#endif
#endif

// Left undefined on purpose (the build script and its test check the list):
// FT_CONFIG_OPTION_ENVIRONMENT_PROPERTIES (no read of the environment, no
// FT_Property_Set), FT_CONFIG_OPTION_USE_ZLIB, _USE_BZIP2, _USE_LZW,
// _USE_PNG, _USE_HARFBUZZ, _USE_BROTLI, FT_CONFIG_OPTION_SVG,
// FT_CONFIG_OPTION_SUBPIXEL_RENDERING (no LCD filter),
// FT_DEBUG_LEVEL_ERROR, FT_DEBUG_LEVEL_TRACE, FT_DEBUG_MEMORY,
// FT_CONFIG_OPTION_ERROR_STRINGS, TT_CONFIG_OPTION_GX_VAR_SUPPORT (no
// variable fonts: FT_Get_MM_Var answers with an error).

#endif
