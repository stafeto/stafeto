#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The checks of tools/build-freetype.py that need no compiler: the
configuration file of ports/freetype (the macros that keep the glyph path
integer and free of run-time properties are as the plan of stage G4 says),
the list of undefined names the build accepts, and the names no object may
carry, each on samples of `llvm-nm` output and on a configuration with a
planted fault.

One real run of the planted fault (the file ftoption.h copied with
FT_CONFIG_OPTION_ENVIRONMENT_PROPERTIES defined, the build pointed at the copy
with STAFETO_FREETYPE_PORT_DIR) ended with exit status 1 and the findings
FREETYPE_PROPERTIES (the text is in ftinit.o), getenv (the objects must not
name it), getenv (a name the library never calls) and strtol (not in the list
of the C library's functions it may call)."""

import importlib.util
from pathlib import Path
import re
import sys
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("build_freetype", HERE / "build-freetype.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

DEFINED = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
REQUIRED = {
    "TT_CONFIG_OPTION_BYTECODE_INTERPRETER", "TT_CONFIG_OPTION_SUBPIXEL_HINTING",
    "TT_CONFIG_OPTION_EMBEDDED_BITMAPS", "FT_CONFIG_OPTION_NO_ASSEMBLER",
    "FT_RENDER_POOL_SIZE",
    *(f"TT_CONFIG_CMAP_FORMAT_{n}" for n in (0, 2, 4, 6, 8, 10, 12, 13, 14)),
}
FORBIDDEN = {
    "FT_CONFIG_OPTION_ENVIRONMENT_PROPERTIES", "FT_CONFIG_OPTION_USE_ZLIB",
    "FT_CONFIG_OPTION_USE_BZIP2", "FT_CONFIG_OPTION_USE_PNG",
    "FT_CONFIG_OPTION_USE_HARFBUZZ", "FT_CONFIG_OPTION_USE_BROTLI",
    "FT_CONFIG_OPTION_USE_LZW", "FT_CONFIG_OPTION_SVG",
    "FT_CONFIG_OPTION_SUBPIXEL_RENDERING", "FT_DEBUG_LEVEL_ERROR",
    "FT_DEBUG_LEVEL_TRACE", "FT_DEBUG_MEMORY", "FT_CONFIG_OPTION_ERROR_STRINGS",
    "TT_CONFIG_OPTION_GX_VAR_SUPPORT",
}


def defined(text: str) -> set[str]:
    """The macros a header defines (comments of `//` and `/* */` dropped)."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return set(DEFINED.findall(text))


def problems(text: str) -> list[str]:
    """What is wrong with a configuration: a forbidden macro defined or a
    required one missing."""
    names = defined(text)
    return ([f"{n} is defined" for n in sorted(names & FORBIDDEN)]
            + [f"{n} is not defined" for n in sorted(REQUIRED - names)])


OPTION = (ROOT / "ports" / "freetype" / "ftoption.h").read_text()
# What `llvm-nm -u --format=just-symbols` prints for the joined objects.
GOOD_NM = "fclose\nfopen\nfread\nfree\nfseek\nftell\nlongjmp\nmalloc\nmemcpy\nmemset\nqsort\nsetjmp\nstrcmp\nstrlen\n"


class ConfigurationTests(unittest.TestCase):
    def test_the_configuration_is_as_planned(self):
        self.assertEqual(problems(OPTION), [])

    def test_a_property_reading_configuration_is_refused(self):
        planted = OPTION.replace(
            "#define FT_CONFIG_OPTION_NO_ASSEMBLER",
            "#define FT_CONFIG_OPTION_ENVIRONMENT_PROPERTIES\n#define FT_CONFIG_OPTION_NO_ASSEMBLER")
        self.assertEqual(problems(planted),
                         ["FT_CONFIG_OPTION_ENVIRONMENT_PROPERTIES is defined"])

    def test_comments_do_not_define_anything(self):
        self.assertEqual(defined("// #define A\n/* #define B */\n#define C 1\n"), {"C"})

    def test_a_missing_interpreter_is_refused(self):
        planted = OPTION.replace("#define TT_CONFIG_OPTION_BYTECODE_INTERPRETER\n", "")
        self.assertIn("TT_CONFIG_OPTION_BYTECODE_INTERPRETER is not defined", problems(planted))

    def test_the_modules_are_the_three_planned(self):
        text = (ROOT / "ports" / "freetype" / "ftmodule.h").read_text()
        modules = re.findall(r"^FT_USE_MODULE\(\s*\w+,\s*(\w+)\s*\)", text, re.M)
        self.assertEqual(modules, ["tt_driver_class", "sfnt_module_class",
                                   "ft_smooth_renderer_class"])


class NamesTests(unittest.TestCase):
    def test_the_symbols_are_read_one_to_a_line(self):
        self.assertEqual(builder.symbol_names("a\n\nb\nlib.a(x.o):\n"), ["a", "b"])

    def test_the_planned_names_pass(self):
        self.assertEqual(builder.undefined_violations(builder.symbol_names(GOOD_NM)), [])

    def test_getenv_fails_the_list(self):
        bad = builder.undefined_violations(builder.symbol_names(GOOD_NM + "getenv\n"))
        self.assertEqual(len(bad), 1)
        self.assertIn("getenv", bad[0])

    def test_threads_the_loader_and_the_mapper_fail(self):
        for name in ("pthread_mutex_lock", "dlopen", "mmap", "munmap"):
            self.assertEqual(len(builder.undefined_violations([name])), 1, name)

    def test_floating_point_functions_fail(self):
        for name in ("sqrt", "floor", "pow", "atan2f"):
            self.assertEqual(len(builder.undefined_violations([name])), 1, name)

    def test_a_name_off_the_list_fails(self):
        bad = builder.undefined_violations(["printf"])
        self.assertIn("printf", bad[0])

    def test_the_names_of_the_property_and_debug_paths_are_refused(self):
        for name in ("strtol", "strtod", "strtof", "calloc", "snprintf", "memchr", "strncmp"):
            self.assertEqual(len(builder.undefined_violations([name])), 1, name)

    def test_the_underscore_of_an_elf_name_stays(self):
        self.assertEqual(builder.symbol_names("__stack_chk_fail\n"), ["__stack_chk_fail"])

    def test_getenv_in_an_object_is_found_defined_or_not(self):
        self.assertEqual(len(builder.absent_violations(["FT_Init_FreeType", "getenv"])), 1)
        self.assertEqual(builder.absent_violations(["FT_Init_FreeType"]), [])

    def test_a_call_of_the_property_setter_from_another_object_is_found(self):
        self.assertEqual(len(builder.called_violations(["malloc", "FT_Property_Set"])), 1)
        self.assertEqual(builder.called_violations(["malloc"]), [])

    def test_a_name_the_library_lacks_is_found(self):
        provided = {"malloc", "free"}
        self.assertEqual(builder.unresolved(["malloc", "free"], provided), [])
        found = builder.unresolved(["malloc", "qsort"], provided)
        self.assertEqual(len(found), 1)
        self.assertIn("qsort", found[0])


class DescriptionTests(unittest.TestCase):
    def test_the_package_description_is_the_planned_one(self):
        package = builder.PACKAGE
        self.assertEqual(package["version"], "2.14.3")
        self.assertEqual(package["license"], "FTL")
        self.assertEqual(package["license_file"], "docs/FTL.TXT")
        self.assertEqual(package["files"], [])
        self.assertEqual(len(package["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
