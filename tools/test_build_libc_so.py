#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The host test of the names tools/build-libc-so.py keeps out of libc.so: the
functions of the window library, and of OpenWF Display and Composition. In the
open series 0.6 `cargo xtask abi --check` only prints a change of the libc
part, so a feature of a static library that leaked into the build `shared`
would pass without this check. A planted fault: with the pattern of OpenWF
removed from `leaked_names`, `wfdCreateDevice` is no longer found and the test
of the OpenWF names fails."""

import importlib.util
from pathlib import Path
import unittest


def load():
    path = Path(__file__).resolve().parent / "build-libc-so.py"
    spec = importlib.util.spec_from_file_location("build_libc_so", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULE = load()


class LeakedNames(unittest.TestCase):
    def test_the_window_library_is_found(self):
        self.assertEqual(
            MODULE.leaked_names({"stafeto_window_open", "stafeto_screen_describe", "malloc"}),
            ["stafeto_screen_describe", "stafeto_window_open"])

    def test_the_wait_across_windows_is_found(self):
        self.assertEqual(
            MODULE.leaked_names({"stafeto_windows_wait", "stafeto_window_resize", "malloc"}),
            ["stafeto_window_resize", "stafeto_windows_wait"])

    def test_the_functions_of_openwf_are_found(self):
        names = {"wfdCreateDevice", "wfdStafetoStream", "wfcCreateContext", "wfcCompose", "write"}
        self.assertEqual(
            MODULE.leaked_names(names),
            ["wfcCompose", "wfcCreateContext", "wfdCreateDevice", "wfdStafetoStream"])

    def test_the_functions_of_egl_and_opengl_es_are_found(self):
        names = {"eglSwapBuffers", "eglGetDisplay", "glDrawElements", "glClear", "glob", "write"}
        self.assertEqual(
            MODULE.leaked_names(names),
            ["eglGetDisplay", "eglSwapBuffers", "glClear", "glDrawElements"])

    def test_names_of_libc_are_not_taken_for_them(self):
        names = {"wfdlike", "wfc", "wf", "stafeto_display_open", "stafeto_input_read", "wcscpy",
                 "glob", "globfree", "glibc_version", "eglobal", "gl", "egl"}
        self.assertEqual(MODULE.leaked_names(names), [])


if __name__ == "__main__":
    unittest.main()
