#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Real Git/Clang fixtures for complete extraction and failed-test continuation."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "os_test_build", Path(__file__).with_name("build-os-test.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class FullBasicTests(unittest.TestCase):
    def test_git_only_inventory_continues_after_failure_and_keeps_relative_includes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            files = {
                "LICENSE": "fixture license\n",
                "misc/errors.h": "#define ERROR_VALUE 4\n",
                "basic/basic.h": '#include "../misc/errors.h"\n',
                "basic/alpha/broken.c": '#include <missing_fixture_header.h>\n',
                "basic/math/sin.c": "double sin(double);\n"
                "int main(void) { return sin(0.0) != 0.0; }\n",
                "basic/sys_select/select.c": "int dependency(void) { return ERROR_VALUE; }\n",
                "basic/other/later.c": '#include "../basic.h"\n'
                '#include "../sys_select/select.c"\n'
                "int main(void) { return dependency() == 4 ? 0 : 1; }\n",
            }
            for name, text in files.items():
                path = repository / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(["git", "-c", "user.name=Fixture", "-c",
                            "user.email=fixture@example.invalid", "commit", "-qm", "fixture"],
                           cwd=repository, check=True)
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                             cwd=repository, text=True).strip()
            # Nothing in the checkout may supply or omit a test.
            shutil.rmtree(repository / "basic")
            (repository / "stamp").write_text("default stamp untouched\n")
            with patch.object(builder, "COMMIT", commit):
                paths = builder.git_inventory(repository, "basic")
                self.assertEqual(len([p for p in paths if p.endswith(".c")]), 4)
                work = root / "full"
                builder.compile_full_basic(repository, work, builder.clang(), expected=4)
                rows = (work / "tests.txt").read_text().splitlines()
                self.assertEqual(len(rows), 4)
                self.assertEqual(rows[0], "basic/alpha/broken !missing_header")
                later = next(row for row in rows if row.startswith("basic/other/later "))
                self.assertNotIn("!", later)
                self.assertTrue(Path(later.split(" ", 1)[1]).is_file())
                math = next(row for row in rows if row.startswith("basic/math/sin "))
                nm = Path(builder.clang()).with_name("llvm-nm")
                symbols = subprocess.check_output(
                    [str(nm), "--undefined-only", math.split(" ", 1)[1]], text=True)
                self.assertIn(" sin\n", symbols)
                sources = (work / "sources.txt").read_text().splitlines()
                self.assertEqual(len(sources), 4)
                self.assertEqual(len({row.split("\t")[1] for row in sources}), 4)
                self.assertTrue(all(Path(row.split("\t")[1]).exists() for row in sources))
                self.assertEqual(len((work / "compile.tsv").read_text().splitlines()), 4)
                with self.assertRaisesRegex(RuntimeError, "expected 5"):
                    builder.compile_full_basic(repository, work, builder.clang(), expected=5)
            self.assertEqual((repository / "stamp").read_text(), "default stamp untouched\n")


if __name__ == "__main__":
    unittest.main()
