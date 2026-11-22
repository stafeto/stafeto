#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The checks of tools/build-libcxx.py that need no compiler and no archive:
the package record (version, licence, pinned archive), the file of the site
configuration filled from its template, the patch of libunwind, the choice
of the directories unpacked from the archive, the stamp that makes a change
of the script, the port or the relibc sysroot build again, the lists of
files, the header of the futex operations, and the check of the names the
libraries leave undefined (on samples of `llvm-nm` output, with a fault
planted: a conversion function the C library lacks)."""

import importlib.util
from pathlib import Path
import re
import sys
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("build_libcxx", HERE / "build-libcxx.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

# The shape of libcxx/include/__config_site.in, shortened.
TEMPLATE = """#ifndef _LIBCPP___CONFIG_SITE
#define _LIBCPP___CONFIG_SITE
#cmakedefine _LIBCPP_ABI_VERSION @_LIBCPP_ABI_VERSION@
#cmakedefine01 _LIBCPP_HAS_THREADS
#cmakedefine01 _LIBCPP_HAS_MUSL_LIBC
#cmakedefine _LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS
#cmakedefine _LIBCPP_HARDENING_MODE_DEFAULT @_LIBCPP_HARDENING_MODE_DEFAULT@
@_LIBCPP_ABI_DEFINES@
@_LIBCPP_EXTRA_SITE_DEFINES@
#endif
"""
UNWIND = """#include <mach-o/dyld.h>
#if defined(_LIBUNWIND_TARGET_LINUX) &&                                        \\
    (defined(_LIBUNWIND_TARGET_AARCH64))
#include <errno.h>
#define _LIBUNWIND_CHECK_LINUX_SIGRETURN 1
#endif
"""


class PackageTests(unittest.TestCase):
    def test_the_record_pins_the_archive_of_the_release(self):
        package = builder.PACKAGE
        self.assertEqual(package["version"], "23.1.6")
        self.assertEqual(package["license"], "Apache-2.0 WITH LLVM-exception OR MIT OR NCSA")
        self.assertRegex(package["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            package["url"],
            "https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.6/"
            "llvm-project-23.1.6.src.tar.xz")
        self.assertEqual(package["files"], [])

    def test_the_licence_is_one_the_exception_of_which_is_known_to_the_checks(self):
        text = (ROOT / "tools" / "check-licenses.py").read_text()
        self.assertIn("Apache-2.0 WITH LLVM-exception", text)


class SiteFileTests(unittest.TestCase):
    def test_every_option_of_the_template_is_filled(self):
        text = builder.site_file(TEMPLATE)
        self.assertNotIn("@", text)
        self.assertNotIn("#cmake", text)
        self.assertIn("#define _LIBCPP_ABI_VERSION 1", text)
        self.assertIn("#define _LIBCPP_HAS_THREADS 1", text)
        self.assertIn("#define _LIBCPP_HAS_MUSL_LIBC 0", text)
        self.assertIn("/* #undef _LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS */", text)
        self.assertIn("#define _LIBCPP_HARDENING_MODE_DEFAULT _LIBCPP_HARDENING_MODE_NONE", text)

    def test_libcxx_takes_its_own_table_of_character_classes(self):
        # relibc does not define __GLIBC__: without this line <__locale>
        # stops with "unknown rune table for this platform".
        text = builder.site_file(TEMPLATE)
        self.assertIn("#define _LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE", text)
        self.assertEqual(builder.SITE["_LIBCPP_HAS_MUSL_LIBC"], 0)

    def test_the_configuration_is_threads_localization_and_files_without_time_zones(self):
        site = builder.SITE
        self.assertEqual(site["_LIBCPP_HAS_THREADS"], 1)
        self.assertEqual(site["_LIBCPP_HAS_THREAD_API_PTHREAD"], 1)
        self.assertEqual(site["_LIBCPP_HAS_LOCALIZATION"], 1)
        self.assertEqual(site["_LIBCPP_HAS_FILESYSTEM"], 1)
        self.assertEqual(site["_LIBCPP_HAS_TIME_ZONE_DATABASE"], 0)

    def test_an_option_the_table_does_not_hold_is_filled_as_off(self):
        text = builder.site_file(TEMPLATE + "#cmakedefine01 _LIBCPP_NEW_OPTION\n")
        self.assertIn("#define _LIBCPP_NEW_OPTION 0", text)


class PatchTests(unittest.TestCase):
    def test_the_check_of_the_linux_return_trampoline_is_off_for_stafeto(self):
        patched = builder.patch_unwind(UNWIND)
        self.assertIn("#if !defined(__stafeto__) && defined(_LIBUNWIND_TARGET_LINUX) &&", patched)
        self.assertEqual(patched.count("__stafeto__"), 1)
        self.assertEqual(patched.replace("!defined(__stafeto__) && ", ""), UNWIND)

    def test_a_source_without_the_line_or_with_it_twice_is_refused(self):
        with self.assertRaises(SystemExit):
            builder.patch_unwind("#include <errno.h>\n")
        with self.assertRaises(SystemExit):
            builder.patch_unwind(UNWIND + UNWIND)


class SelectionTests(unittest.TestCase):
    def test_the_directories_the_build_needs_are_unpacked(self):
        for name in ("libcxx/src/atomic.cpp", "libcxx/include/__config_site.in",
                     "libcxx/vendor/llvm/default_assertion_handler.in",
                     "libcxxabi/src/cxa_guard.cpp", "libunwind/src/UnwindCursor.hpp",
                     "libc/shared/fp_bits.h", "libc/src/__support/str_to_float.h",
                     "libcxx/LICENSE.TXT", "libc/hdr/errno_macros.h"):
            self.assertTrue(builder.wanted(name), name)

    def test_tests_documents_and_the_rest_of_libc_are_left_in_the_archive(self):
        for name in ("libcxx/test/std/atomic.pass.cpp", "libcxx/docs/index.rst",
                     "libcxx/benchmarks/a.cpp", "libc/test/src/a.cpp", "libc/src/string/a.cpp",
                     "libcxxabi/test/a.cpp", "llvm/lib/a.cpp", "libcxxsrc/other"):
            self.assertFalse(builder.wanted(name), name)

    def test_the_lists_of_files_are_whole_and_without_repeats(self):
        for names in (builder.LIBCXX, builder.LIBCXXABI):
            self.assertEqual(len(names), len(set(names)))
        # charconv takes its parser from the header library of LLVM libc.
        self.assertIn("charconv", builder.LIBCXX)
        self.assertIn("atomic", builder.LIBCXX)
        self.assertIn("cxa_personality", builder.LIBCXXABI)
        self.assertIn("cxa_thread_atexit", builder.LIBCXXABI)
        self.assertFalse([n for n in builder.LIBCXX if "experimental" in n or "tzdb" in n])
        self.assertIn("libc/shared", builder.TAKE)
        self.assertIn("libc/src/__support", builder.TAKE)


class StampTests(unittest.TestCase):
    def test_each_input_changes_the_stamp(self):
        base = builder.stamp_text(b"script", b"port", "relibc-a")
        self.assertEqual(base, builder.stamp_text(b"script", b"port", "relibc-a"))
        self.assertNotEqual(base, builder.stamp_text(b"script2", b"port", "relibc-a"))
        self.assertNotEqual(base, builder.stamp_text(b"script", b"port2", "relibc-a"))
        self.assertNotEqual(base, builder.stamp_text(b"script", b"port", "relibc-b"))
        self.assertTrue(base.startswith(f"{builder.VERSION} {builder.SHA256} "))

    def test_the_port_is_the_futex_header(self):
        header = (ROOT / "ports" / "libcxx" / "include" / "linux" / "futex.h").read_text()
        self.assertEqual(re.findall(r"#define (FUTEX_\w+) (\d+)", header),
                         [("FUTEX_WAIT_PRIVATE", "128"), ("FUTEX_WAKE_PRIVATE", "129")])
        self.assertIn("#define SYS_futex 98", header)
        self.assertTrue(builder.port_bytes())


NM = """algorithm.o:
_ZNSt3__16random T 0 0
strtold_l U
strtod_l U
__cxa_atexit U
malloc U
_ZNSt3__16random2 U
"""


class UndefinedNameTests(unittest.TestCase):
    def test_the_listing_is_split_into_defined_and_undefined(self):
        defined, undefined = builder.parse_nm(NM)
        self.assertEqual(defined, {"_ZNSt3__16random"})
        self.assertEqual(undefined, {"strtold_l", "strtod_l", "__cxa_atexit", "malloc",
                                     "_ZNSt3__16random2"})

    def test_a_name_the_c_library_lacks_is_reported(self):
        _, undefined = builder.parse_nm(NM)
        libc = {"strtold_l", "strtod_l", "__cxa_atexit", "malloc", "_ZNSt3__16random2"}
        self.assertEqual(builder.strays(undefined, libc), [])
        # The planted fault: a relibc without strtold_l.
        self.assertEqual(builder.strays(undefined, libc - {"strtold_l"}), ["strtold_l"])


if __name__ == "__main__":
    unittest.main()
