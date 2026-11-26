#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The checks of tools/build-mesa.py that need no compiler and no network:
the package record (version, licences, pinned archive), the options of the
build (with the planted fault of dropping `opengl=false`), the cross file of
meson, the stub of the C library's names, the patches (their names, their
files and, when the pinned archive is in the cache, that they apply to it),
the stamp that makes a change of the script or the port build again, the
merge script of the archive, the check for names defined twice and for names
left undefined (on samples of `llvm-nm` output with faults planted), and the
licence texts of the notices."""

import contextlib
import importlib.util
import io
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("build_mesa", HERE / "build-mesa.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

CROSS = builder.cross_file(
    Path("/llvm/bin/clang"), Path("/llvm/bin/clang++"), Path("/llvm/bin/llvm-ar"),
    Path("/llvm/bin/llvm-nm"), Path("/llvm/bin/llvm-strip"), Path("/llvm/bin/llvm-ranlib"),
    Path("/work/stub/libstub.a"), sysroot=Path("/sysroot"), libcxx=Path("/libcxx"),
    port=Path("/port"))


class PackageTests(unittest.TestCase):
    def test_the_record_pins_the_archive_of_the_release(self):
        package = builder.PACKAGE
        self.assertEqual(package["version"], "26.3.1")
        self.assertEqual(
            package["sha256"], "4e4e438eac7b840a9383988cbb7c08dad8041da544b9319fc26d319fa7348961")
        self.assertEqual(package["url"], "https://archive.mesa3d.org/mesa-26.3.1.tar.xz")
        self.assertEqual(package["files"], [])
        self.assertEqual(package["build_depends"], ["libcxx"])

    def test_the_licences_are_those_of_the_files_the_archive_holds(self):
        licence = builder.PACKAGE["license"].split(" AND ")
        for name in ("MIT", "Apache-2.0", "BSL-1.0", "BSD-2-Clause", "BSD-3-Clause",
                     "HPND-sell-variant", "LicenseRef-public-domain"):
            self.assertIn(name, licence)
        # The GPL files of Mesa's tree belong to code the build leaves out.
        self.assertFalse([n for n in licence if "GPL" in n])
        self.assertEqual(builder.LICENCE_TEXTS, ["MIT", "Apache-2.0", "BSL-1.0"])

    def test_libdrm_is_the_release_the_wrap_of_mesa_names(self):
        self.assertEqual(builder.LIBDRM_VERSION, "2.4.133")
        self.assertEqual(
            builder.LIBDRM_SHA256,
            "fc68f9d0ba2ea63c9432a299e14fea09fad7a8a66e8039fcd7802ca59f77b4f5")
        self.assertTrue(builder.LIBDRM_URL.endswith("libdrm-2.4.133.tar.xz"))
        self.assertTrue(builder.LIBDRM_URL.startswith("https://"))


class OptionTests(unittest.TestCase):
    def test_the_build_is_softpipe_without_desktop_opengl(self):
        options = builder.OPTIONS
        self.assertEqual(options["opengl"], "false")
        self.assertEqual(options["gles2"], "enabled")
        self.assertEqual(options["egl"], "enabled")
        self.assertEqual(options["gallium-drivers"], "softpipe")
        self.assertEqual(options["vulkan-drivers"], "")
        self.assertEqual(options["llvm"], "disabled")
        self.assertEqual(options["shader-cache"], "disabled")
        self.assertEqual(options["platforms"], "")
        self.assertEqual(options["egl-native-platform"], "surfaceless")
        self.assertEqual(options["cpp_eh"], "none")
        self.assertEqual(options["cpp_rtti"], "false")
        self.assertEqual(options["default_library"], "static")
        self.assertEqual(options["wrap_mode"], "nodownload")
        self.assertEqual(options["allow-fallback-for"], "libdrm")
        self.assertEqual(options["b_staticpic"], "false")

    def test_the_arguments_of_meson_are_one_option_each(self):
        args = builder.meson_options()
        self.assertIn("-Dopengl=false", args)
        self.assertIn("-Dplatforms=", args)
        self.assertIn("-Dlibdrm:auto_features=disabled", args)
        self.assertEqual(len(args), len(set(args)))
        self.assertTrue(all(a.startswith("-D") for a in args))

    def test_the_options_the_archive_depends_on_pass_the_check(self):
        builder.check_options(builder.OPTIONS)

    def test_dropping_opengl_false_is_refused(self):
        # The planted fault: with desktop OpenGL on the tree also builds
        # libglapi_bridge.a, which defines the 357 names libGLESv2.a defines.
        options = {k: v for k, v in builder.OPTIONS.items() if k != "opengl"}
        with self.assertRaises(SystemExit) as caught:
            builder.check_options(options)
        self.assertIn("opengl", str(caught.exception))
        with self.assertRaises(SystemExit):
            builder.check_options({**builder.OPTIONS, "opengl": "true"})

    def test_dropping_the_shader_cache_option_is_refused(self):
        options = {k: v for k, v in builder.OPTIONS.items() if k != "shader-cache"}
        with self.assertRaises(SystemExit) as caught:
            builder.check_options(options)
        self.assertIn("shader-cache", str(caught.exception))


class CrossFileTests(unittest.TestCase):
    def test_the_system_is_linux_and_stafeto_is_a_macro(self):
        self.assertIn("system = 'linux'", CROSS)
        self.assertIn("cpu_family = 'aarch64'", CROSS)
        self.assertIn("needs_exe_wrapper = true", CROSS)
        self.assertIn("'-D__stafeto__=1'", CROSS)
        self.assertNotIn("system = 'stafeto'", CROSS)

    def test_alloca_is_included_in_every_file(self):
        self.assertRegex(CROSS, r"c_args = \[[^\]]*'-include', 'alloca.h'")
        self.assertRegex(CROSS, r"cpp_args = \[[^\]]*'-include', 'alloca.h'")

    def test_the_headers_are_those_of_relibc_libcxx_and_the_port(self):
        self.assertIn("'/sysroot/include'", CROSS)
        self.assertIn("'/libcxx/include/c++/v1'", CROSS)
        self.assertIn("-I/port/include", CROSS)
        self.assertIn("'--target=aarch64-linux-gnu'", CROSS)
        self.assertIn("'-nostdinc++'", CROSS)

    def test_probes_link_statically_against_the_stub(self):
        self.assertRegex(CROSS, r"c_link_args = \[[^\]]*'-static'[^\]]*'/work/stub/libstub.a'")
        self.assertIn("'-nostdlib'", CROSS)

    def test_the_code_is_for_the_a53_without_outlined_atomics(self):
        self.assertIn("'-mfix-cortex-a53-835769'", CROSS)
        self.assertIn("'-mno-outline-atomics'", CROSS)
        self.assertIn("'-fno-pic'", CROSS)


class StubTests(unittest.TestCase):
    def test_every_name_is_defined_once_as_a_function(self):
        text = builder.stub_source({"memcpy", "malloc", "malloc"})
        self.assertEqual(text.count(".globl malloc\n"), 1)
        self.assertEqual(text.count("malloc:\n"), 1)
        self.assertIn(".type memcpy,%function", text)
        self.assertLess(text.index("malloc:"), text.index("memcpy:"))


class PatchTests(unittest.TestCase):
    PATCHES = sorted((ROOT / "ports" / "mesa" / "patches").glob("*.patch"))

    def test_the_patches_are_numbered_and_listed_in_order(self):
        names = [p.name for p in builder.patches()]
        self.assertEqual(names, sorted(names))
        self.assertEqual(
            names,
            ["0001-detect-os-stafeto.patch", "0002-static-targets.patch",
             "0003-c11-threads-from-the-c-library.patch",
             "0004-softpipe-texture-caches-on-first-use.patch"])
        for name in names:
            self.assertRegex(name, r"^\d{4}-[a-z0-9-]+\.patch$")

    def test_each_patch_has_a_description_and_a_licence_line(self):
        for patch in self.PATCHES:
            text = patch.read_text()
            head = text.split("diff --git", 1)[0]
            self.assertIn("SPDX-License-Identifier: MIT", head, patch.name)
            self.assertIn("Sergey Subbotin", head, patch.name)
            self.assertGreater(len(head.strip().splitlines()), 4, patch.name)

    def test_the_patches_touch_the_files_the_build_needs(self):
        touched = {p.name: re.findall(r"^diff --git a/(\S+)", p.read_text(), re.M)
                   for p in self.PATCHES}
        self.assertEqual(
            touched["0001-detect-os-stafeto.patch"],
            ["src/util/detect_os.h", "src/util/futex.h", "src/util/os_misc.c", "src/util/u_process.c",
             "src/util/u_queue.c"])
        self.assertEqual(
            touched["0002-static-targets.patch"],
            ["src/egl/meson.build", "src/gallium/targets/dri/meson.build",
             "src/mesa/glapi/es2api/meson.build"])
        self.assertEqual(touched["0003-c11-threads-from-the-c-library.patch"], ["meson.build"])
        self.assertEqual(
            touched["0004-softpipe-texture-caches-on-first-use.patch"],
            ["src/gallium/drivers/softpipe/sp_context.c",
             "src/gallium/drivers/softpipe/sp_state_sampler.c",
             "src/gallium/drivers/softpipe/sp_tex_tile_cache.c"])

    def test_the_detect_os_patch_puts_stafeto_before_linux(self):
        text = (ROOT / "ports/mesa/patches/0001-detect-os-stafeto.patch").read_text()
        self.assertIn("+#if defined(__stafeto__)\n+#define DETECT_OS_STAFETO 1\n", text)
        self.assertIn("+#define DETECT_OS_POSIX 1\n+#elif defined(__linux__)\n", text)
        self.assertIn("-#if defined(__linux__)\n+/*\n", text)

    def test_the_threads_come_from_the_c_library_under_the_stafeto_macro(self):
        text = (ROOT / "ports/mesa/patches/0003-c11-threads-from-the-c-library.patch").read_text()
        self.assertIn("cc.get_define('__stafeto__') == '1'", text)
        self.assertIn("with_c11_threads = true", text)

    def test_the_three_targets_become_static_libraries(self):
        text = (ROOT / "ports/mesa/patches/0002-static-targets.patch").read_text()
        for old in ("libegl = shared_library(", "libgles2 = shared_library(",
                    "libgallium_dri = shared_library("):
            self.assertIn("-" + old, text)
        self.assertEqual(text.count("static_library("), 3)

    def test_the_kernel_header_stubs_are_the_two_files_the_drm_headers_need(self):
        include = ROOT / "ports" / "mesa" / "include"
        types = (include / "linux" / "types.h").read_text()
        for name in ("__u8", "__u16", "__u32", "__u64", "__s64", "__kernel_size_t"):
            self.assertIn(name, types)
        ioctl = (include / "asm" / "ioctl.h").read_text()
        for name in ("_IOC(", "_IOWR(", "_IOR(", "_IOW(", "_IOC_SIZE("):
            self.assertIn(name, ioctl)
        # The layout of AArch64: 8, 8, 14 and 2 bits.
        self.assertIn("#define _IOC_DIRSHIFT (_IOC_SIZESHIFT + _IOC_SIZEBITS)", ioctl)
        self.assertEqual(sorted(p.name for p in include.rglob("*.h")), ["ioctl.h", "types.h"])

    ARCHIVE = builder.CACHE / f"mesa-{builder.VERSION}.tar.xz"

    @unittest.skipUnless(ARCHIVE.exists(), "the Mesa archive is not in the cache yet")
    def test_the_patches_apply_to_the_pinned_archive(self):
        import hashlib
        import subprocess
        if hashlib.sha256(self.ARCHIVE.read_bytes()).hexdigest() != builder.SHA256:
            self.skipTest("the cached archive has another digest")
        with tempfile.TemporaryDirectory() as work:
            top = builder.unpack(self.ARCHIVE, Path(work))
            log = Path(work) / "patch.log"
            log.write_text("")
            builder.apply_patches(top, log)
            detect = (top / "src/util/detect_os.h").read_text()
            self.assertLess(detect.index("DETECT_OS_STAFETO 1"), detect.index("DETECT_OS_LINUX 1"))
            self.assertIn("with_c11_threads = true", (top / "meson.build").read_text())
            self.assertIn("static_library(", (top / "src/egl/meson.build").read_text())
            sampler = (top / "src/gallium/drivers/softpipe/sp_state_sampler.c").read_text()
            self.assertIn("sp_create_tex_tile_cache", sampler)
            # The files named in NOTICE_FILES exist in the tree.
            for _, path in builder.NOTICE_FILES:
                if not path.startswith("libdrm/"):
                    self.assertTrue((top / path).exists(), path)
            for name in builder.LICENCE_TEXTS:
                self.assertTrue((top / "licenses" / name).exists(), name)
            # A second application finds the changes already there and fails.
            with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()):
                builder.apply_patches(top, log)
            self.assertTrue(subprocess.run(["patch", "--version"], capture_output=True).returncode == 0)


class StampTests(unittest.TestCase):
    def test_each_input_changes_the_stamp(self):
        base = builder.stamp_text(b"script", b"port", "relibc-a", "libcxx-a")
        self.assertEqual(base, builder.stamp_text(b"script", b"port", "relibc-a", "libcxx-a"))
        for other in (("script2", "port", "relibc-a", "libcxx-a"),
                      ("script", "port2", "relibc-a", "libcxx-a"),
                      ("script", "port", "relibc-b", "libcxx-a"),
                      ("script", "port", "relibc-a", "libcxx-b")):
            self.assertNotEqual(
                base, builder.stamp_text(*(x.encode() if i < 2 else x for i, x in enumerate(other))))
        self.assertTrue(base.startswith(f"{builder.VERSION} {builder.SHA256} 2.4.133 "))

    def test_the_port_bytes_cover_the_patches_and_the_headers(self):
        self.assertTrue(builder.port_bytes())
        with tempfile.TemporaryDirectory() as work:
            port = Path(work)
            (port / "patches").mkdir()
            (port / "patches" / "0001-a.patch").write_text("a")
            first = builder.port_bytes(port)
            (port / "patches" / "0001-a.patch").write_text("b")
            self.assertNotEqual(first, builder.port_bytes(port))


class MergeTests(unittest.TestCase):
    def test_the_archives_are_whole_and_without_repeats(self):
        names = builder.ARCHIVES
        self.assertEqual(len(names), len(set(names)))
        for needed in ("src/egl/libEGL.a", "src/mesa/glapi/es2api/libGLESv2.a",
                       "src/gallium/drivers/softpipe/libsoftpipe.a", "src/mesa/libmesa.a",
                       "src/compiler/nir/libnir.a", "src/compiler/glsl/libglsl.a",
                       "subprojects/libdrm-2.4.133/libdrm.a"):
            self.assertIn(needed, names)
        # libgallium holds the objects of libdri (link_whole); both would define every name twice.
        self.assertNotIn("src/gallium/frontends/dri/libdri.a", names)
        # The entry points of desktop OpenGL define the names of libGLESv2.a.
        self.assertFalse([n for n in names if "glapi_bridge" in n])

    def test_the_merge_script_adds_each_library_to_one_archive(self):
        text = builder.mri_script(Path("/out/libmesa.a"), [Path("/b/a.a"), Path("/b/c.a")])
        self.assertEqual(text, "CREATE /out/libmesa.a\nADDLIB /b/a.a\nADDLIB /b/c.a\nSAVE\nEND\n")

    def test_a_library_the_build_did_not_make_is_refused(self):
        with tempfile.TemporaryDirectory() as work:
            build = Path(work)
            log = build / "log"
            log.write_text("")
            with self.assertRaises(SystemExit) as caught:
                builder.merge_archives(Path("/llvm/bin/llvm-ar"), build, build / "out.a", log)
            self.assertIn("libEGL.a", str(caught.exception))


# The shape of `llvm-nm --format=posix -A --defined-only --extern-only` of the
# merged archive when libglapi_bridge.a (desktop OpenGL) is in it.
DUPLICATES = """libmesa.a[libGLESv2.a.p/libgles2_public.c.o]: glClear T 0 8
libmesa.a[libGLESv2.a.p/libgles2_public.c.o]: glActiveTexture T 8 8
libmesa.a[libglapi_bridge.a.p/libgl_public.c.o]: glClear T 0 8
libmesa.a[libglapi_bridge.a.p/libgl_public.c.o]: glActiveTexture T 8 8
libmesa.a[libglsl.a.p/a.cpp.o]: _ZSt28__throw_bad_array_new_lengthB9nin230106v W 0 20
libmesa.a[libmesa_util.a.p/b.c.o]: _ZSt28__throw_bad_array_new_lengthB9nin230106v W 0 20
libmesa.a[libnir.a.p/c.c.o]: nir_shader_create T 0 40
"""
NM = """libEGL.a.p/main_eglapi.c.o:
eglGetDisplay T 0 f8
malloc U
strtold_l U
__cxa_atexit U
_ZTH23_mesa_glapi_tls_Context w
_ZN3foo3barEv U
"""


class SymbolTests(unittest.TestCase):
    def test_a_name_defined_by_two_members_is_reported(self):
        twice = builder.strong_duplicates(DUPLICATES)
        self.assertEqual(sorted(twice), ["glActiveTexture", "glClear"])
        self.assertEqual(
            twice["glClear"],
            ["libGLESv2.a.p/libgles2_public.c.o", "libglapi_bridge.a.p/libgl_public.c.o"])

    def test_weak_definitions_in_many_members_are_allowed(self):
        self.assertNotIn("_ZSt28__throw_bad_array_new_lengthB9nin230106v",
                         builder.strong_duplicates(DUPLICATES))
        self.assertEqual(builder.strong_duplicates(DUPLICATES.split("\n", 4)[4]), {})

    def test_the_listing_is_split_into_defined_and_undefined_without_weak_references(self):
        defined, undefined = builder.parse_nm(NM)
        self.assertEqual(defined, {"eglGetDisplay"})
        self.assertEqual(undefined, {"malloc", "strtold_l", "__cxa_atexit", "_ZN3foo3barEv"})

    def test_a_name_nothing_defines_is_reported(self):
        _, undefined = builder.parse_nm(NM)
        known = {"malloc", "strtold_l", "__cxa_atexit", "_ZN3foo3barEv"}
        self.assertEqual(builder.strays(undefined, known), [])
        # The planted fault: a library of Mesa missing from the archive.
        self.assertEqual(builder.strays(undefined, known - {"_ZN3foo3barEv"}), ["_ZN3foo3barEv"])
        self.assertEqual(builder.strays(undefined, known - {"strtold_l"}), ["strtold_l"])


BUILDOPTIONS = [
    {"name": "opengl", "value": False},
    {"name": "gles2", "value": "enabled"},
    {"name": "platforms", "value": []},
    {"name": "gallium-drivers", "value": ["softpipe"]},
    {"name": "opengl", "value": True, "subproject": "libdrm"},
]


class ConfiguredTests(unittest.TestCase):
    REQUIRED = {"opengl": "false", "gles2": "enabled", "platforms": "", "gallium-drivers": "softpipe"}

    def test_the_options_as_meson_holds_them_are_compared(self):
        self.assertEqual(builder.configured_differences(BUILDOPTIONS, self.REQUIRED), [])

    def test_opengl_on_in_the_configured_tree_is_reported_whatever_the_script_passed(self):
        # The planted fault: the guard of the script bypassed, opengl left on.
        on = [{**o, "value": True} if o["name"] == "opengl" and "subproject" not in o else o
              for o in BUILDOPTIONS]
        found = builder.configured_differences(on, self.REQUIRED)
        self.assertEqual(len(found), 1)
        self.assertIn("opengl='true'", found[0])

    def test_an_option_meson_does_not_know_is_reported(self):
        self.assertEqual(len(builder.configured_differences(BUILDOPTIONS[:1], self.REQUIRED)), 3)

    def test_the_values_are_those_of_the_command_line(self):
        self.assertEqual(builder.meson_value(True), "true")
        self.assertEqual(builder.meson_value([]), "")
        self.assertEqual(builder.meson_value(["a", "b"]), "a,b")


class UnlistedTests(unittest.TestCase):
    TREE = list(builder.ARCHIVES) + ["src/gallium/frontends/dri/libdri.a",
                                     "src/mesa/glapi/glapi/libglapi_bridge.a"]

    def test_the_listed_and_the_excluded_libraries_are_accounted_for(self):
        self.assertEqual(builder.unlisted_archives(self.TREE), [])

    def test_another_library_is_reported(self):
        self.assertEqual(builder.unlisted_archives(self.TREE + ["src/mesa/libglx_extra.a"]),
                         ["src/mesa/libglx_extra.a"])

    def test_the_excluded_are_the_two_the_archive_leaves_out_on_purpose(self):
        self.assertEqual(builder.EXCLUDED, {"libdri.a", "libglapi_bridge.a"})


class SharedNameTests(unittest.TestCase):
    MESA = """libmesa.a[a.o]:
mtx_init T 0 8
eglGetDisplay T 8 8
inline_fn W 0 4
"""
    LIBC = """x.o:
mtx_init T 0 8
malloc T 8 8
inline_fn W 0 4
"""

    def test_strong_names_leave_out_the_weak_and_the_undefined(self):
        self.assertEqual(builder.strong_names(self.MESA + "free U\n"), {"mtx_init", "eglGetDisplay"})

    def test_a_name_both_define_is_found(self):
        # The planted fault: patch 0003 dropped, Mesa's threads_posix.c in the archive.
        both = builder.strong_names(self.MESA) & builder.strong_names(self.LIBC)
        self.assertEqual(both, {"mtx_init"})

    def test_the_patch_that_prevents_it_is_in_the_list(self):
        self.assertIn("0003-c11-threads-from-the-c-library.patch",
                      [p.name for p in builder.patches()])


class RequirementsTests(unittest.TestCase):
    def read(self, path):
        return path.read_text()

    def test_every_package_is_pinned_with_hashes(self):
        text = self.read(builder.REQUIREMENTS)
        for name, version in (("mako", "1.4.3"), ("markupsafe", "3.0.4"), ("pyyaml", "6.0.4"),
                              ("packaging", "26.3")):
            self.assertRegex(text, rf"(?m)^{name}=={re.escape(version)} \\$")
        for line in text.splitlines():
            if line.startswith("    --hash="):
                self.assertRegex(line, r"^    --hash=sha256:[0-9a-f]{64}( \\)?$")
        pins = re.findall(r"(?m)^\w+==", text)
        self.assertEqual(len(pins), 4)

    def test_the_platform_wheels_cover_the_hosts(self):
        # MarkupSafe and PyYAML: macOS arm64 and Linux aarch64 wheels of CPython 3.12 and 3.15.
        text = self.read(builder.REQUIREMENTS)
        self.assertGreater(text.count("--hash=sha256:"), 30)

    def test_meson_is_pinned_apart(self):
        text = self.read(builder.REQUIREMENTS_MESON)
        self.assertRegex(text, r"(?m)^meson==1\.12\.1 \\$")
        self.assertEqual(text.count("--hash=sha256:"), 1)

    def test_the_stamp_holds_the_digest_of_the_files(self):
        self.assertRegex(builder.requirements_digest(), r"^[0-9a-f]{64}$")
        a = builder.stamp_text(b"s", b"p", "r", "l", "one")
        self.assertNotEqual(a, builder.stamp_text(b"s", b"p", "r", "l", "two"))


class NoticeTests(unittest.TestCase):
    def test_the_leading_comment_is_the_first_block(self):
        self.assertEqual(builder.leading_comment("/* a\n * b */\nint x;\n/* c */"), "/* a\n * b */")
        self.assertEqual(
            builder.leading_comment("#ifndef X\n#define X\n/*\n** MIT\n*/\nint y;"), "/*\n** MIT\n*/")
        self.assertEqual(builder.leading_comment("// one\n// two\nint z;"), "// one\n// two")
        self.assertEqual(builder.leading_comment("README text, no comment"), "README text, no comment")

    def test_the_files_with_their_own_terms_are_named(self):
        paths = [p for _, p in builder.NOTICE_FILES]
        self.assertEqual(len(paths), len(set(paths)))
        for needed in ("src/util/softfloat.c", "src/util/xxhash.h", "src/loader/loader_dri_helper.c",
                       "src/util/blake3/README", "src/c11/threads.h", "include/EGL/egl.h",
                       "libdrm/xf86drm.c"):
            self.assertIn(needed, paths)

    def test_the_notices_carry_the_texts_and_the_headings(self):
        with tempfile.TemporaryDirectory() as work:
            source = Path(work) / "mesa"
            libdrm = Path(work) / "libdrm"
            (source / "docs").mkdir(parents=True)
            (source / "docs" / "license.rst").write_text("License and Copyright")
            (source / "licenses").mkdir()
            for name in builder.LICENCE_TEXTS:
                (source / "licenses" / name).write_text(f"text of {name}")
            for _, path in builder.NOTICE_FILES:
                base = libdrm if path.startswith("libdrm/") else source
                file = base / path.removeprefix("libdrm/")
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(f"/* licence heading of {path} */\nint x;\n")
            for _, path, start in builder.PUBLIC_DOMAIN:
                file = source / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(f"int y;\n{start}\n * belongs to the public domain.\n */\nint z;\n")
            text = builder.notices(source, libdrm)
        self.assertIn("License and Copyright", text)
        self.assertIn("text of Apache-2.0", text)
        self.assertIn("licence heading of src/util/softfloat.c", text)
        self.assertIn("licence heading of libdrm/xf86drm.c", text)
        self.assertNotIn("int x;", text)
        self.assertIn("belongs to the public domain.", text)
        self.assertIn("rand_xorshift128plus of Sebastiano Vigna", text)
        self.assertNotIn("int z;", text)


class ArchiveTests(unittest.TestCase):
    def test_an_archive_with_a_wrong_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as work:
            cache = Path(work)
            old = builder.CACHE
            builder.CACHE = cache
            try:
                (cache / "x.tar.xz").write_bytes(b"not the archive")
                # A file in the cache with the wrong digest is fetched again;
                # with no network the fetch of a local URL stands for it.
                source = Path(work) / "source.bin"
                source.write_bytes(b"other bytes")
                with self.assertRaises(SystemExit) as caught:
                    builder.fetch(source.as_uri(), "0" * 64, "x.tar.xz")
                self.assertIn("unexpected SHA-256", str(caught.exception))
                self.assertFalse((cache / "x.tar.xz.part").exists())
            finally:
                builder.CACHE = old

    def test_an_archive_unpacks_under_its_top_directory(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / "t" / "mesa-1").mkdir(parents=True)
            (root / "t" / "mesa-1" / "meson.build").write_text("project()")
            archive = root / "a.tar.xz"
            with tarfile.open(archive, "w:xz") as out:
                out.add(root / "t" / "mesa-1", arcname="mesa-1")
            top = builder.unpack(archive, root / "out")
            self.assertEqual(top.name, "mesa-1")
            self.assertTrue((top / "meson.build").exists())


spec_reference = importlib.util.spec_from_file_location(
    "build_mesa_reference", HERE / "build-mesa-reference.py")
reference = importlib.util.module_from_spec(spec_reference)
spec_reference.loader.exec_module(reference)

RUN = "".join(
    f"gles-cube: frame {k} crc {0x1000 + k:08x} sum {900 + k}\ngles-cube: time frame {k} 24 ms\n"
    for k in range(10)) + "gles-cube: ok\n"


class ReferenceTests(unittest.TestCase):
    def test_the_reference_builds_with_the_options_of_the_guest_less_the_static_ones(self):
        args = reference.native_options()
        self.assertIn("-Dopengl=false", args)
        self.assertIn("-Dgallium-drivers=softpipe", args)
        self.assertIn("-Dplatforms=", args)
        self.assertIn("-Degl-native-platform=surfaceless", args)
        self.assertFalse([a for a in args if a.startswith("-Ddefault_library")])
        self.assertFalse([a for a in args if a.startswith("-Db_staticpic")])
        self.assertTrue([a for a in args if a.startswith("--prefix=")])

    def test_the_crcs_the_guest_is_expected_to_print_are_read_from_xtask(self):
        crcs = reference.expected_crcs(reference.XTASK.read_text())
        self.assertEqual(len(crcs), 10)
        self.assertEqual(len(set(crcs)), 10)
        self.assertEqual(reference.expected_crcs("pub const EXPECTED_CRCS: Option<[u32; FRAMES]> = None;"), [])

    def test_the_frame_lines_are_read_and_the_others_left(self):
        seen = reference.frames(RUN)
        self.assertEqual(len(seen), 10)
        self.assertEqual(seen[3], (3, 0x1003, 903))

    def test_equal_frames_agree_and_one_changed_bit_does_not(self):
        expected = [0x1000 + k for k in range(10)]
        table, same = reference.comparison(expected, reference.frames(RUN))
        self.assertTrue(same)
        self.assertNotIn("NO", table)
        expected[6] ^= 1
        table, same = reference.comparison(expected, reference.frames(RUN))
        self.assertFalse(same)
        self.assertEqual(table.count("NO"), 1)
        table, same = reference.comparison(expected[:9], reference.frames(RUN))
        self.assertFalse(same)
        self.assertIn("10 frames seen, 9 expected", table)

    def test_the_workflow_runs_the_script_on_an_arm64_runner_by_hand(self):
        text = (ROOT / ".github" / "workflows" / "mesa-reference.yml").read_text()
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("runs-on: ubuntu-24.04-arm", text)
        self.assertIn("python3 tools/build-mesa-reference.py", text)
        self.assertNotIn("pull_request", text)


class VersionTests(unittest.TestCase):
    def test_the_minimum_of_meson_is_the_one_of_mesa(self):
        self.assertEqual(builder.MESON_MINIMUM, (1, 5, 0))
        self.assertLess(builder.version_tuple("1.4.2"), builder.MESON_MINIMUM)
        self.assertGreaterEqual(builder.version_tuple("1.12.1\n"), builder.MESON_MINIMUM)


if __name__ == "__main__":
    unittest.main()
