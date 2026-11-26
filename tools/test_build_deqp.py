#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The checks of tools/build-deqp.py that need no source tree and no
compiler: the pinned release and commit, the toolchain file (the flags of
the other objects of stafeto, the search of libraries kept inside the
sysroot), the options of CMake (direct link, the CPU, the selected modules),
the revisions fetch_sources.py pins as the script reads them, the lists of
the objects and archives of a link line, the stamp, and the files of the
platform the build copies into the tree."""

import importlib.util
from pathlib import Path
import sys
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("build_deqp", HERE / "build-deqp.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

FETCH = '''
PACKAGES = [
    SourcePackage("https://x/zlib.tar.gz", "ab", "zlib"),
    GitRepo(
        "https://github.com/KhronosGroup/SPIRV-Tools.git",
        "git@github.com:KhronosGroup/SPIRV-Tools.git",
        "65b2ace21293057714b7fa1e87bd764d3dcef305",
        "spirv-tools"),
    GitRepo(
        "https://github.com/KhronosGroup/glslang.git",
        "git@github.com:KhronosGroup/glslang.git",
        "7881226269b1596feb604515743f528f02041375",
        "glslang",
        removeTags = ["main-tot"]),
    GitRepo(
        "https://github.com/KhronosGroup/Vulkan-Video-Samples.git",
        "git@github.com:KhronosGroup/Vulkan-Video-Samples.git",
        "v0.3.9",
        "vulkan-video-samples"),
]
'''


class Pinned(unittest.TestCase):
    def test_the_release_and_its_commit(self):
        self.assertEqual(builder.TAG, "opengl-es-cts-3.2.14.1")
        self.assertEqual(builder.COMMIT, "067e8832315e79817ede1c4863804e440f5d1c80")
        self.assertEqual(len(builder.COMMIT), 40)

    def test_the_modules(self):
        self.assertEqual(builder.MODULES,
                         ["deqp-egl", "deqp-gles2", "deqp-gles3", "deqp-gles31"])

    def test_the_revisions_of_the_script_of_the_tree(self):
        pinned = builder.pinned_revisions(FETCH)
        self.assertEqual(pinned["glslang"], "7881226269b1596feb604515743f528f02041375")
        self.assertEqual(pinned["spirv-tools"], "65b2ace21293057714b7fa1e87bd764d3dcef305")
        self.assertEqual(pinned["vulkan-video-samples"], "v0.3.9")
        self.assertNotIn("zlib", pinned)


class Toolchain(unittest.TestCase):
    def setUp(self):
        self.text = builder.toolchain_file(Path("/b/clang"), Path("/b/clang++"), Path("/b/ar"),
                                           Path("/b/ranlib"), Path("/s"), Path("/c"), Path("/p"))

    def test_the_target_and_the_headers(self):
        self.assertIn("--target=aarch64-linux-gnu", self.text)
        self.assertIn("-mfix-cortex-a53-835769", self.text)
        self.assertIn("-D__stafeto__=1", self.text)
        self.assertIn("-isystem /s/include", self.text)
        self.assertIn("-isystem /c/include/c++/v1", self.text)
        self.assertIn("-isystem /p/include", self.text)
        self.assertIn("-nostdinc++", self.text)

    def test_nothing_links_and_the_search_stays_in_the_sysroot(self):
        self.assertIn("CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY", self.text)
        self.assertIn('CMAKE_FIND_ROOT_PATH "/s"', self.text)
        for kind in ("LIBRARY", "INCLUDE", "PACKAGE"):
            self.assertIn(f"CMAKE_FIND_ROOT_PATH_MODE_{kind} ONLY", self.text)


class Options(unittest.TestCase):
    def test_direct_link_cpu_and_modules(self):
        options = builder.cmake_options(Path("/t.cmake"), ["deqp-egl", "deqp-gles2"])
        self.assertIn("-DGLES_ALLOW_DIRECT_LINK=ON", options)
        self.assertIn("-DDE_CPU=DE_CPU_ARM_64", options)
        self.assertIn("-DDEQP_TARGET=stafeto", options)
        self.assertIn("-DSELECTED_BUILD_TARGETS=deqp-egl deqp-gles2", options)
        self.assertIn("-DCMAKE_TOOLCHAIN_FILE=/t.cmake", options)


class Link(unittest.TestCase):
    def test_the_inputs_of_a_link_line(self):
        command = ("/b/clang++ -O2 -o modules/egl/deqp-egl "
                   "a/tcuMain.cpp.o modules/egl/e.cpp.o m/libx.a /abs/libmesa.a -lpthread")
        objects, archives = builder.link_inputs(command, Path("/build"))
        self.assertEqual([str(o) for o in objects],
                         ["/build/a/tcuMain.cpp.o", "/build/modules/egl/e.cpp.o"])
        self.assertEqual([str(a) for a in archives], ["/build/m/libx.a", "/abs/libmesa.a"])


class Stamp(unittest.TestCase):
    def test_a_change_of_an_input_changes_the_stamp(self):
        base = builder.stamp_text(b"s", b"p", "r", "c", "m", ["deqp-egl"])
        self.assertIn(builder.COMMIT, base)
        for changed in (builder.stamp_text(b"s2", b"p", "r", "c", "m", ["deqp-egl"]),
                        builder.stamp_text(b"s", b"p2", "r", "c", "m", ["deqp-egl"]),
                        builder.stamp_text(b"s", b"p", "r2", "c", "m", ["deqp-egl"]),
                        builder.stamp_text(b"s", b"p", "r", "c2", "m", ["deqp-egl"]),
                        builder.stamp_text(b"s", b"p", "r", "c", "m2", ["deqp-egl"]),
                        builder.stamp_text(b"s", b"p", "r", "c", "m", ["deqp-egl", "deqp-gles2"])):
            self.assertNotEqual(base, changed)


class Port(unittest.TestCase):
    def test_the_platform_files_are_there(self):
        for name in ("tcuStafetoPlatform.cpp", "tcuStafetoPlatform.hpp", "tcuStafetoMain.cpp"):
            self.assertTrue((builder.PORT / "platform" / name).is_file(), name)
        target = (builder.PORT / "targets" / "stafeto" / "stafeto.cmake").read_text()
        for name in ("tcuStafetoMain.cpp", "tcuStafetoPlatform.cpp"):
            self.assertIn(f"stafeto/{name}", target)
        # The platform reads the window library the program links.
        self.assertIn("stafeto/window.h",
                      (builder.PORT / "platform" / "tcuStafetoPlatform.cpp").read_text())


if __name__ == "__main__":
    unittest.main()
