// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The modules FreeType registers at FT_Init_FreeType (the file its build
// reads through FT_CONFIG_MODULES_H, tools/build-freetype.py): the TrueType
// driver, the container it reads (sfnt) and the anti-aliasing renderer. The
// automatic hinter, the other font formats, the other renderers and the
// SVG hooks are not built.
FT_USE_MODULE( FT_Driver_ClassRec, tt_driver_class )
FT_USE_MODULE( FT_Module_Class, sfnt_module_class )
FT_USE_MODULE( FT_Renderer_Class, ft_smooth_renderer_class )
