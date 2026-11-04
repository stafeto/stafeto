#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The answers to nginx's run-probes (tools/nginx/autotest-answer.py): a size
comes from the compiler for the target, a known probe from the table, and an
unknown one is written down and answered "not found"."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ANSWER = Path(__file__).with_name("nginx") / "autotest-answer.py"


def clang() -> str:
    for path in ("/opt/homebrew/opt/llvm/bin/clang", shutil.which("clang")):
        if path and Path(path).exists():
            return path
    raise unittest.SkipTest("no clang")


class AnswerTests(unittest.TestCase):
    def ask(self, name: str, source: str = "int main(void) { return 0; }\n"):
        """The exit status and the output of the answer to the probe `name`
        whose source is `source`, and what went to the files of unknown
        probes and of answers."""
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            probe = work / "autotest"
            probe.with_name("autotest.c").write_text(source)
            unknown, log = work / "unknown.txt", work / "answers.txt"
            env = dict(os.environ, NGX_AUTOTEST_NAME=name,
                       NGX_AUTOTEST_CC=f"{clang()} --target=aarch64-linux-gnu -nostdinc",
                       NGX_AUTOTEST_UNKNOWN=str(unknown), NGX_AUTOTEST_LOG=str(log))
            result = subprocess.run([sys.executable, "-I", str(ANSWER), str(probe)],
                                    env=env, capture_output=True, text=True)
            read = lambda path: path.read_text() if path.exists() else ""
            return result.returncode, result.stdout, read(unknown), read(log)

    def test_a_size_comes_from_the_compiler_for_the_target(self):
        status, out, unknown, log = self.ask("sizeof long")
        self.assertEqual((status, out, unknown), (0, "8", ""))
        self.assertIn("sizeof long: 0 (8 bytes", log)
        self.assertEqual(self.ask("sizeof int")[:2], (0, "4"))
        self.assertEqual(self.ask("sizeof void *")[:2], (0, "8"))

    def test_a_size_sees_the_includes_of_the_probe(self):
        source = "typedef struct { char a[24]; } wide_t;\nint main(void) { return 0; }\n"
        self.assertEqual(self.ask("sizeof wide_t", source)[:2], (1, ""))
        source = "typedef struct { char a[16]; } wide_t;\nint main(void) { return 0; }\n"
        self.assertEqual(self.ask("sizeof wide_t", source)[:2], (0, "16"))

    def test_the_target_is_little_endian(self):
        self.assertEqual(self.ask("byte ordering")[0], 0)

    def test_a_known_probe_has_its_answer_and_reason(self):
        status, _, unknown, log = self.ask("epoll")
        self.assertEqual((status, unknown), (0, ""))
        self.assertIn("epoll: 0 (", log)
        self.assertEqual(self.ask("sendfile()")[0], 1)

    def test_an_unknown_probe_is_written_down_and_not_found(self):
        status, _, unknown, _ = self.ask("kqueue")
        self.assertEqual((status, unknown), (1, "kqueue\n"))


if __name__ == "__main__":
    unittest.main()
