#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The checks of tools/build-lvgl.py that need no compiler: the configuration
file of ports/lvgl (the parts the plan of stage G4 turns off are off, the ones
it turns on are on), the check of the macros the compiler sees, and the list
of undefined names the build accepts, each on samples and on a configuration
with a planted fault.

One real run of the planted fault (ports/lvgl copied with `LV_USE_OS` set to
`LV_OS_PTHREAD` and a drawing-thread stack of 32 KiB, which LVGL asks for with
the OS layer on; the build pointed at the copy with STAFETO_LVGL_PORT_DIR) ended
with exit status 1 and the findings `LV_USE_OS is LV_OS_PTHREAD, expected
LV_OS_NONE`, sixteen `pthread_*` names (create, join, the mutex, condition and
attribute functions) and `usleep`."""

import importlib.util
from pathlib import Path
import re
import sys
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("build_lvgl", HERE / "build-lvgl.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

DEFINE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)[ \t]*([^\n]*)$", re.M)
CONF = (ROOT / "ports" / "lvgl" / "lv_conf.h").read_text()


def settings(text: str) -> dict[str, str]:
    """The macros a header defines, name to value (comments dropped)."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return {name: value.strip() for name, value in DEFINE.findall(text)}


class ConfigurationTests(unittest.TestCase):
    def test_the_file_is_parsed(self):
        values = settings(CONF)
        self.assertEqual(values["LV_USE_OS"], "LV_OS_NONE")
        self.assertEqual(values["LV_DEF_REFR_PERIOD"], "16")
        self.assertEqual(values["LV_MEM_SIZE"], "(512 * 1024)")

    def test_the_forbidden_parts_are_off(self):
        values = settings(CONF)
        for name in ("LV_USE_SYSMON", "LV_USE_PERF_MONITOR", "LV_USE_MEM_MONITOR",
                     "LV_USE_PROFILER", "LV_USE_SNAPSHOT", "LV_USE_FLEX", "LV_USE_GRID",
                     "LV_USE_FLOAT", "LV_USE_MATRIX", "LV_USE_THORVG", "LV_USE_TINY_TTF",
                     "LV_BUILD_EXAMPLES", "LV_BUILD_DEMOS", "LV_USE_FS_STDIO",
                     "LV_USE_FS_POSIX", "LV_USE_FS_MEMFS", "LV_USE_LINUX_FBDEV",
                     "LV_USE_LINUX_DRM", "LV_USE_SDL", "LV_USE_X11", "LV_USE_WAYLAND",
                     "LV_FREETYPE_USE_LVGL_PORT"):
            self.assertEqual(values[name], "0", name)
        self.assertEqual(values["LV_USE_DRAW_SW_ASM"], "LV_DRAW_SW_ASM_NONE")

    def test_the_demo_parts_are_on(self):
        values = settings(CONF)
        for name in ("LV_USE_LABEL", "LV_USE_BUTTON", "LV_USE_CHECKBOX", "LV_USE_SWITCH",
                     "LV_USE_SLIDER", "LV_USE_BAR", "LV_USE_TEXTAREA", "LV_USE_IMAGE",
                     "LV_USE_THEME_DEFAULT", "LV_USE_FREETYPE", "LV_USE_LOG",
                     "LV_FONT_MONTSERRAT_16"):
            self.assertEqual(values[name], "1", name)

    def test_the_expected_table_agrees_with_the_file(self):
        values = settings(CONF)
        for name, value in builder.EXPECTED.items():
            self.assertEqual(values.get(name), value, name)

    def test_every_forbidden_family_the_file_names_is_off(self):
        for name, value in settings(CONF).items():
            if name.startswith(builder.OFF_PREFIXES) or name in builder.OFF_NAMES:
                self.assertEqual(value, "0", name)


def effective(overrides: dict[str, str]) -> dict[str, str]:
    """The macros a compiler would see: the expected ones, with changes."""
    macros = dict(builder.EXPECTED)
    macros.update(overrides)
    return macros


class MacroTests(unittest.TestCase):
    def test_the_macros_of_a_listing_are_read(self):
        listing = "#define A 1\n#define B(x) x\n#define C\n#define D LV_OS_NONE\n"
        self.assertEqual(builder.parse_macros(listing), {"A": "1", "C": "", "D": "LV_OS_NONE"})

    def test_the_planned_settings_pass(self):
        self.assertEqual(builder.configuration_problems(effective({})), [])

    def test_a_thread_layer_is_found(self):
        found = builder.configuration_problems(effective({"LV_USE_OS": "LV_OS_PTHREAD"}))
        self.assertEqual(found, ["LV_USE_OS is LV_OS_PTHREAD, expected LV_OS_NONE"])

    def test_a_default_that_turns_a_part_on_is_found(self):
        self.assertEqual(len(builder.configuration_problems(effective({"LV_USE_FLEX": "1"}))), 1)
        self.assertEqual(len(builder.configuration_problems(effective({"LV_USE_FS_POSIX": "1"}))), 1)
        self.assertEqual(len(builder.configuration_problems(effective({"LV_USE_SYSMON": "1"}))), 1)
        self.assertEqual(len(builder.configuration_problems(effective({"LV_USE_DRAW_SW_ASM": "LV_DRAW_SW_ASM_NEON"}))), 1)

    def test_a_missing_setting_is_found(self):
        macros = effective({})
        del macros["LV_USE_FREETYPE"]
        self.assertIn("LV_USE_FREETYPE is undefined, expected 1",
                      builder.configuration_problems(macros))


FT = {"FT_Init_FreeType", "FT_New_Face", "FT_Property_Set", "FT_Set_Default_Properties"}
GOOD = ["FT_Init_FreeType", "FT_New_Face", "abort", "memcpy", "strlen", "__stack_chk_fail"]


class NamesTests(unittest.TestCase):
    def test_the_planned_names_pass(self):
        self.assertEqual(builder.undefined_violations(GOOD, FT), [])

    def test_threads_fail(self):
        names = ["pthread_create", "pthread_mutex_lock", "usleep"]
        found = builder.undefined_violations(GOOD + names, FT)
        self.assertEqual(len(found), 3)
        self.assertIn("pthread_create", found[0])

    def test_floating_point_functions_fail(self):
        for name in ("sqrt", "floor", "pow", "atan2f", "sinf"):
            self.assertEqual(len(builder.undefined_violations([name], FT)), 1, name)

    def test_the_property_and_environment_names_fail_even_if_freetype_defines_them(self):
        for name in ("FT_Property_Set", "FT_Set_Default_Properties", "getenv",
                     "FT_Library_SetLcdFilter"):
            found = builder.undefined_violations([name], FT | {name})
            self.assertEqual(len(found), 1, name)
            self.assertIn("never calls", found[0])

    def test_conversion_and_output_functions_fail(self):
        for name in ("strtol", "strtod", "snprintf", "printf", "fopen", "calloc", "malloc"):
            self.assertEqual(len(builder.undefined_violations([name], FT)), 1, name)

    def test_a_library_name_off_the_list_of_freetype_fails(self):
        found = builder.undefined_violations(["FT_Stream_Open"], FT)
        self.assertIn("FT_Stream_Open", found[0])


class DescriptionTests(unittest.TestCase):
    def test_the_package_description_is_the_planned_one(self):
        package = builder.PACKAGE
        self.assertEqual(package["version"], "9.6.0")
        self.assertEqual(package["license"], "MIT AND OFL-1.1")
        self.assertEqual(package["license_file"], "LICENCE.txt")
        self.assertEqual(package["build_depends"], ["freetype"])
        self.assertEqual(len(package["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
