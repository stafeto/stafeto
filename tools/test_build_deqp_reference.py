#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The checks of tools/build-deqp-reference.py that need no compiler and no
source tree: the words of the command line, the options of Mesa for the two
variants (the same as the build for stafeto where Linux allows), and the
options of CMake for a target."""

import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("build_deqp_reference", HERE / "build-deqp-reference.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class Arguments(unittest.TestCase):
    def test_a_word_is_a_target_and_its_modules(self):
        wanted = builder.parse_arguments(["surfaceless:gles2,gles3", "nullws:egl", "nullws:gles31,egl"])
        self.assertEqual(wanted, {"surfaceless": ["gles2", "gles3"], "nullws": ["egl", "gles31"]})

    def test_deqp_egl_needs_a_platform_with_eglu(self):
        with self.assertRaises(SystemExit):
            builder.parse_arguments(["surfaceless:egl"])

    def test_the_x11_target_builds_deqp_egl_only(self):
        self.assertEqual(builder.parse_arguments(["x11_egl:egl"]), {"x11_egl": ["egl"]})
        with self.assertRaises(SystemExit):
            builder.parse_arguments(["x11_egl:gles2"])

    def test_unknown_names_are_refused(self):
        for word in ["wayland:egl", "nullws:gles9", "nullws:", "nullws"]:
            with self.assertRaises(SystemExit, msg=word):
                builder.parse_arguments([word])


class Options(unittest.TestCase):
    def test_mesa_keeps_the_options_of_the_stafeto_build(self):
        options = builder.mesa_options("surfaceless", Path("/p"))
        for wanted in ["-Dgallium-drivers=softpipe", "-Dllvm=disabled", "-Dopengl=false",
                       "-Dshader-cache=disabled", "-Dgles2=enabled", "-Degl-native-platform=surfaceless",
                       "-Dplatforms=", "--prefix=/p"]:
            self.assertIn(wanted, options)
        # A cross build for static archives makes no sense here.
        for omitted in ["-Ddefault_library=static", "-Dplatform-stafeto=true"]:
            self.assertNotIn(omitted, options)

    def test_the_x11_variant_adds_the_platform_of_x11_and_nothing_else(self):
        plain = builder.mesa_options("surfaceless", Path("/p"))
        x11 = builder.mesa_options("x11", Path("/p"))
        self.assertIn("-Dplatforms=x11", x11)
        self.assertEqual(sorted(set(x11) - set(plain)), ["-Dplatforms=x11"])

    def test_the_variant_of_a_target(self):
        self.assertEqual(builder.mesa_variant("x11_egl"), "x11")
        self.assertEqual(builder.mesa_variant("nullws"), "surfaceless")
        self.assertEqual(builder.mesa_variant("surfaceless"), "surfaceless")

    def test_cmake_builds_the_modules_of_the_target_in_release(self):
        options = builder.cmake_options("nullws", ["egl", "gles31"], "clang", "clang++")
        self.assertIn("-DDEQP_TARGET=nullws", options)
        self.assertIn("-DSELECTED_BUILD_TARGETS=deqp-egl deqp-gles31", options)
        self.assertIn("-DCMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG", options)

    def test_the_commit_is_the_one_of_the_guest_build(self):
        text = (HERE / "build-deqp.py").read_text()
        self.assertIn(builder.bd.COMMIT, text)
        self.assertEqual(builder.bd.TAG, "opengl-es-cts-3.2.14.1")


if __name__ == "__main__":
    unittest.main()
