#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The choice of tests and the diagnostics of tools/build-open-posix.py on a
fixture tree, as scripts/locate-test of the suite would choose them."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
import unittest.mock

spec = importlib.util.spec_from_file_location(
    "open_posix_build", Path(__file__).with_name("build-open-posix.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class InventoryTests(unittest.TestCase):
    def test_tests_are_picked_as_locate_test_picks_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            files = [
                "conformance/interfaces/fork/1-1.c",
                "conformance/interfaces/fork/1-1-buildonly.c",
                "conformance/interfaces/fork/assertions.xml",
                "conformance/interfaces/fork/2-1.sh",
                "conformance/interfaces/fork/cln.sh",
                "conformance/interfaces/testfrmw/testfrmw.c",
                "conformance/interfaces/testfrmw/threads_scenarii.c",
                "conformance/definitions/time_h/1-1-buildonly.c",
                "functional/threads/schedule/1-1.c",
                "functional/threads/helper.c",
                "stress/mqueues/a_1.c",
                "stress/mqueues/a_1.args",
            ]
            for name in files:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("")
            with unittest.mock.patch.object(builder, "SOURCE", source):
                rows = builder.inventory()
        self.assertEqual(rows and [(n, k) for n, k, _ in rows], [
            ("conformance/definitions/time_h/1-1-buildonly", "BUILDONLY"),
            ("conformance/interfaces/fork/1-1", "RUN"),
            ("conformance/interfaces/fork/1-1-buildonly", "BUILDONLY"),
            ("conformance/interfaces/fork/2-1", "SCRIPT"),
            ("functional/threads/helper", "RUN"),
            ("functional/threads/schedule/1-1", "RUN"),
            ("stress/mqueues/a_1", "ARGS"),
        ])

    def test_first_error_is_one_line_without_the_source_path(self):
        with unittest.mock.patch.object(builder, "SOURCE", Path("/s")):
            text = "x\n/s/a/b.c:3:1: error: call to undeclared function 'f'\n\tmore\n"
            self.assertEqual(builder.first_error(text),
                             "a/b.c:3:1: error: call to undeclared function 'f'")

    def test_the_archive_is_pinned_by_sha256(self):
        self.assertRegex(builder.SHA256, r"^[0-9a-f]{64}$")
        self.assertIn(builder.RELEASE, builder.URL)


if __name__ == "__main__":
    unittest.main()
