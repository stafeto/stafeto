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


# Every LV_USE_* name the port's lv_conf.h sets: the parts it turns on or off
# on purpose. A name that is not here (a driver or a board of the template, say)
# was pasted in from the template and is not the port's own.
OWN_SWITCHES = set("""
LV_USE_3DTEXTURE LV_USE_ANIMIMG LV_USE_ARC LV_USE_ARCLABEL LV_USE_ASSERT_MALLOC LV_USE_ASSERT_NULL
LV_USE_BAR LV_USE_BARCODE LV_USE_BIDI LV_USE_BMP LV_USE_BUTTON LV_USE_BUTTONMATRIX LV_USE_CALENDAR
LV_USE_CANVAS LV_USE_CHART LV_USE_CHECKBOX LV_USE_DRAW_SW LV_USE_DRAW_SW_ASM LV_USE_DROPDOWN
LV_USE_EVDEV LV_USE_FFMPEG LV_USE_FILE_EXPLORER LV_USE_FLEX LV_USE_FLOAT LV_USE_FONT_MANAGER
LV_USE_FONT_PLACEHOLDER LV_USE_FRAGMENT LV_USE_FREETYPE LV_USE_FS_ARDUINO_ESP_LITTLEFS
LV_USE_FS_ARDUINO_SD LV_USE_FS_FATFS LV_USE_FS_FROGFS LV_USE_FS_LITTLEFS LV_USE_FS_MEMFS
LV_USE_FS_POSIX LV_USE_FS_STDIO LV_USE_FS_UEFI LV_USE_FS_WIN32 LV_USE_GIF LV_USE_GLFW LV_USE_GRID
LV_USE_GRIDNAV LV_USE_IMAGE LV_USE_IMAGEBUTTON LV_USE_IME_PINYIN LV_USE_IMGFONT LV_USE_KEYBOARD
LV_USE_LABEL LV_USE_LAYER_DEBUG LV_USE_LED LV_USE_LIBINPUT LV_USE_LIBJPEG_TURBO LV_USE_LIBPNG
LV_USE_LIBWEBP LV_USE_LINE LV_USE_LINUX_DRM LV_USE_LINUX_FBDEV LV_USE_LIST LV_USE_LODEPNG
LV_USE_LOG LV_USE_LOTTIE LV_USE_LZ4 LV_USE_MATRIX LV_USE_MEM_MONITOR LV_USE_MENU LV_USE_MONKEY
LV_USE_MSGBOX LV_USE_NUTTX LV_USE_OBSERVER LV_USE_OPENGLES LV_USE_OS LV_USE_PARALLEL_DRAW_DEBUG
LV_USE_PERF_MONITOR LV_USE_PROFILER LV_USE_QRCODE LV_USE_REFR_DEBUG LV_USE_RLE LV_USE_ROLLER
LV_USE_SCALE LV_USE_SDL LV_USE_SLIDER LV_USE_SNAPSHOT LV_USE_SPAN LV_USE_SPINBOX LV_USE_SPINNER
LV_USE_STDLIB_MALLOC LV_USE_STDLIB_SPRINTF LV_USE_STDLIB_STRING LV_USE_SVG LV_USE_SWITCH
LV_USE_SYSMON LV_USE_TABLE LV_USE_TABVIEW LV_USE_TEST LV_USE_TEXTAREA LV_USE_THEME_DEFAULT
LV_USE_THEME_MONO LV_USE_THEME_SIMPLE LV_USE_THORVG LV_USE_TILEVIEW LV_USE_TINY_TTF LV_USE_TJPGD
LV_USE_UEFI LV_USE_VECTOR_GRAPHIC LV_USE_WAYLAND LV_USE_WIN LV_USE_WINDOWS LV_USE_X11
""".split())


def foreign_switches(text: str) -> list[str]:
    """The LV_USE_* switches `text` sets that the port does not list as its own."""
    return sorted(name for name in settings(text) if name.startswith("LV_USE_")
                  and name not in OWN_SWITCHES)


class OwnSwitchesTests(unittest.TestCase):
    def test_the_file_sets_only_switches_the_port_lists(self):
        self.assertEqual(foreign_switches(CONF), [])

    def test_a_switch_pasted_from_the_template_is_found(self):
        pasted = CONF + "\n#define LV_USE_SOME_BOARD_DRIVER 0\n"
        self.assertEqual(foreign_switches(pasted), ["LV_USE_SOME_BOARD_DRIVER"])

    def test_every_listed_switch_is_in_the_file_or_is_a_driver_left_off(self):
        # The list does not grow past the file: a name the file dropped is
        # taken off the list too.
        self.assertEqual(sorted(OWN_SWITCHES - set(settings(CONF))), [])


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
