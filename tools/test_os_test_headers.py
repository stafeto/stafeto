#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Exercise the header census with real Git blobs, compilers and target links."""

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("headers", HERE / "check-os-test-headers.py")
headers = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = headers
spec.loader.exec_module(headers)


def tool(name):
    brew = Path("/opt/homebrew/opt/llvm/bin") / name
    return str(brew) if brew.exists() else shutil.which(name)


class CensusTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="header-census-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.sysroot = self.work / "sysroot"
        (self.sysroot / "include").mkdir(parents=True)
        self.compiler = headers.builder.clang()
        self.flags = headers.target_flags(self.sysroot)

    def repository(self, files):
        repo = self.work / "git"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", repo], check=True)
        for number, (name, contents) in enumerate(files.items()):
            # Git's index preserves case-sensitive paths even on APFS.
            raw = self.work / f"blob-{number}"
            raw.write_text(contents)
            oid = subprocess.check_output(["git", "hash-object", "-w", raw], cwd=repo,
                                          text=True).strip()
            subprocess.run(["git", "update-index", "--add", "--cacheinfo", "100644", oid, name],
                           cwd=repo, check=True)
        tree = subprocess.check_output(["git", "write-tree"], cwd=repo, text=True).strip()
        return repo, tree

    def plan(self):
        directory = self.work / "plan"
        directory.mkdir()
        for name, binary in (("lld", "ld.lld"), ("ar", "llvm-ar"), ("nm", "llvm-nm")):
            path = tool(binary)
            self.assertIsNotNone(path, f"missing {binary}")
            (directory / name).write_text(path)
        args = ["-flavor", "gnu", "-e", "main", "--gc-sections", "-L", "{ARCHIVE_DIR}",
                "-lostest", "-o", "{OUTPUT}"]
        (directory / "args.nul").write_bytes(b"\0".join(arg.encode() for arg in args) + b"\0")
        return headers.LinkPlan(directory)

    def test_git_case_pairs_keep_both_genuine_compiler_outcomes(self):
        (self.sysroot / "include/inttypes.h").write_text("#define PRIX16 \"X\"\n")
        files = {
            "include/inttypes/PRIX16.c": '#include <inttypes.h>\n#ifndef PRIX16\n#error upper missing\n#endif\nint main(void){return 0;}\n',
            "include/inttypes/PRIx16.c": '#include <inttypes.h>\n#ifndef PRIx16\n#error lower missing\n#endif\nint main(void){return 0;}\n',
        }
        repo, tree = self.repository(files)
        names, _, _ = headers.inventory(repo, tree, pinned=False)
        self.assertEqual(len(headers.collisions(names)), 1)
        extracted = headers.extract(repo, tree, names, self.work / "extracted")
        self.assertEqual(len(extracted), 2)
        self.assertNotEqual(extracted[0][1], extracted[1][1])
        plan = self.plan()
        rows = []
        for name, path in extracted:
            self.assertEqual(path.read_text(), files[name])
            rows.append(headers.check_include((name, path), self.compiler, self.flags, plan))
        self.assertEqual([row.outcome for row in rows], ["good", "compile_error"])
        headers.write_rows(self.work / "results.tsv", rows, names)
        with self.assertRaises(ValueError):
            headers.write_rows(self.work / "incomplete.tsv", rows[:1], names)

    def test_cross_headers_ignore_poisoned_host_include_environment(self):
        target = self.sysroot / "include/target_only.h"
        target.write_text("#define TARGET_ONLY 1\n")
        poison = self.work / "host-include"
        poison.mkdir()
        (poison / "host_only.h").write_text("#define HOST_ONLY 1\n")
        source = self.work / "target.c"
        source.write_text('#include <target_only.h>\n#ifndef __aarch64__\n#error wrong target\n#endif\n#ifndef TARGET_ONLY\n#error wrong headers\n#endif\nint main(void){return 0;}\n')
        with patch.dict(os.environ, {"CPATH": str(poison), "C_INCLUDE_PATH": str(poison)}):
            result = headers.run([self.compiler, *self.flags, "-c", source, "-o", self.work / "target.o"],
                                 env=headers.cross_env())
            self.assertEqual(result.returncode, 0, result.stderr)
            source.write_text('#include <host_only.h>\nint main(void){return 0;}\n')
            result = headers.run([self.compiler, *self.flags, "-c", source, "-o", self.work / "host.o"],
                                 env=headers.cross_env())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("host_only.h", result.stderr)
            source.write_text('#include <stddef.h>\nint main(void){return 0;}\n')
            result = headers.run([self.compiler, *self.flags, "-c", source, "-o", self.work / "default.o"],
                                 env=headers.cross_env())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("stddef.h", result.stderr)

    def test_global_pointer_requires_symbol_and_failure_keeps_next_row(self):
        plan = self.plan()
        inputs = []
        for name, contents in (
                ("bad-declaration", "#include <missing_header.h>\nint main(void){return 0;}\n"),
                ("missing-symbol", "extern int missing(int);\nint (*foo)(int)=missing;\nint main(void){return 0;}\n"),
                ("present-symbol", "int present(int x){return x;}\nint (*foo)(int)=present;\nint main(void){return 0;}\n")):
            source = self.work / f"{name}.c"
            source.write_text(contents)
            inputs.append(("include/" + name + ".c", source))
        rows = [headers.check_include(item, self.compiler, self.flags, plan) for item in inputs]
        self.assertEqual([row.outcome for row in rows], ["missing_header", "undefined", "good"])
        self.assertIn("missing", rows[1].diagnostic)
        self.assertEqual(rows[1].stage, "link")
        headers.write_rows(self.work / "rows.tsv", rows, [name for name, _ in inputs])
        self.assertEqual(len((self.work / "rows.tsv").read_text().splitlines()), 5)
        self.assertFalse(list(self.work.glob("include-*")))

    def test_upstream_profile_fallback_keeps_its_category(self):
        source = self.work / "previous.c"
        source.write_text('#if _POSIX_C_SOURCE != 200809L\n#error requires previous POSIX\n#endif\nint main(void){return 0;}\n')
        row = headers.check_include(("include/previous.c", source), self.compiler, self.flags, self.plan())
        self.assertEqual((row.outcome, row.profile), ("previous_posix", "posix200809"))

    def test_other_target_link_rejection_keeps_its_phase_and_continues(self):
        plan = self.plan()
        source = self.work / "supported.c"
        source.write_text("int main(void){return 0;}\n")
        # A genuine target-format rejection must retain its own LINK row.
        original_args = plan.args[:]
        plan.args += ["-m", "elf_x86_64"]
        bad = headers.check_include(("include/incompatible.c", source), self.compiler,
                                    self.flags, plan)
        plan.args = original_args
        good = headers.check_include(("include/supported.c", source), self.compiler,
                                     self.flags, plan)
        self.assertEqual((bad.outcome, bad.stage), ("link_error", "link"), bad.diagnostic)
        self.assertIn("incompatible", bad.diagnostic)
        self.assertEqual(good.outcome, "good")
        headers.write_rows(self.work / "link-errors.tsv", [bad, good], [bad.name, good.name])

    def test_native_upstream_parser_reads_cross_declarations(self):
        upstream = headers.ROOT / "target/os-test/source"
        if not upstream.is_dir():
            self.skipTest("pinned upstream source is fetched by os-test-headers")
        parser = headers.namespace_parser(upstream, headers.COMMIT, self.work,
                                           shutil.which("cc") or self.compiler)
        api = self.work / "api"
        api.mkdir()
        (api / "probe.api").write_text("function allowed: int allowed(int);\n")
        header = self.sysroot / "include/probe.h"
        source = self.work / "probe.c"
        source.write_text("#include <probe.h>\n")
        header.write_text("int allowed(int);\n")
        row = headers.check_namespace(("namespace/probe.c", source), self.compiler,
                                       self.flags, parser, api)
        self.assertEqual(row.outcome, "good", row.diagnostic)
        header.write_text("int allowed(int);\nint unexpected(int);\n")
        row = headers.check_namespace(("namespace/probe.c", source), self.compiler,
                                       self.flags, parser, api)
        self.assertEqual(row.outcome, "pollution", row.diagnostic)
        self.assertIn("unexpected", row.diagnostic)


if __name__ == "__main__":
    unittest.main()
