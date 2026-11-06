#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Tests of tools/pkg-source.py on small packages made here: no network, no
build outputs."""

import hashlib
import importlib.util
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("pkg_source", HERE / "pkg-source.py")
pkg_source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg_source)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class World:
    """Two descriptions: `lib` (GPL-2.0-only) and `app` (MIT) that links it,
    and `plain` (MIT) that links nothing."""

    def __init__(self, base: Path):
        self.base = base
        self.cache = base / "cache"
        self.cache.mkdir()
        self.tree = base / "tree"
        (self.tree / "tools").mkdir(parents=True)
        (self.tree / "tools" / "build-app.py").write_text("print('build')\n")
        self.blobs = {"lib": b"library source", "app": b"application source", "plain": b"plain source"}
        self.descriptions = {
            "lib": self.describe_one("lib", "GPL-2.0-only", []),
            "app": self.describe_one("app", "MIT", ["lib"]),
            "plain": self.describe_one("plain", "MIT", []),
        }
        for name, blob in self.blobs.items():
            (self.cache / f"{name}-1.0.tar").write_bytes(blob)
        self.inputs = base / "inputs"
        self.inputs.write_text("file tools/build-app.py abc\nstray line\n")

    def describe_one(self, name, license, build_depends):
        return {"name": name, "version": "1.0", "release": "1", "license": license,
                "url": f"https://example.org/{name}-1.0.tar", "sha256": sha(self.blobs[name]),
                "build_depends": build_depends}

    def describe(self, name):
        return self.descriptions[name]

    def fetch(self, description, cache):
        return cache / f"{description['name']}-1.0.tar"

    def build(self, name, out):
        pkg_source.build(name, out, self.inputs, "c" * 40, "r" * 40, self.cache,
                         self.describe, self.fetch, self.tree)


class PkgSource(unittest.TestCase):
    def test_the_archive_holds_the_sources_the_tree_files_and_a_readme(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = World(Path(tmp))
            out = Path(tmp) / "app.tar.xz"
            w.build("app", out)
            with tarfile.open(out) as tar:
                names = sorted(m.name for m in tar if m.isfile())
            self.assertEqual(names, ["app-1.0-1-src/README", "app-1.0-1-src/sources/app-1.0.tar",
                                     "app-1.0-1-src/sources/lib-1.0.tar",
                                     "app-1.0-1-src/tree/tools/build-app.py"])
            w.build("app", Path(tmp) / "again.tar.xz")
            self.assertEqual(out.read_bytes(), (Path(tmp) / "again.tar.xz").read_bytes())

    def test_a_gpl_package_or_one_that_links_gpl_needs_a_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = World(Path(tmp))
            self.assertTrue(pkg_source.needs_source("lib", w.describe))
            self.assertTrue(pkg_source.needs_source("app", w.describe))
            self.assertFalse(pkg_source.needs_source("plain", w.describe))

    def repo(self, w, entries):
        repo = Path(w.base) / "repo"
        (repo / "src").mkdir(parents=True)
        text = "format 1\n\n" + "\n\n".join(
            "\n".join(f"{k} {v}" for k, v in e.items()) for e in entries) + "\n"
        (repo / "INDEX").write_text(text)
        return repo

    def test_check_accepts_a_whole_repository_and_names_what_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = World(Path(tmp))
            repo = self.repo(w, [
                {"name": "app", "source": "src/app-1.0-1-src.tar.xz"},
                {"name": "plain"},
            ])
            w.build("app", repo / "src" / "app-1.0-1-src.tar.xz")
            self.assertEqual(pkg_source.check(repo, w.describe), 1)
            # A GPL entry with no source field.
            bare = self.repo_again(w, [{"name": "app"}])
            with self.assertRaisesRegex(SystemExit, "has no source"):
                pkg_source.check(bare, w.describe)
            # A source field, but no file.
            gone = self.repo_again(w, [{"name": "app", "source": "src/none.tar.xz"}])
            with self.assertRaisesRegex(SystemExit, "is missing"):
                pkg_source.check(gone, w.describe)

    def repo_again(self, w, entries):
        import shutil
        shutil.rmtree(Path(w.base) / "repo", ignore_errors=True)
        return self.repo(w, entries)

    def test_check_refuses_an_archive_with_another_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = World(Path(tmp))
            (w.cache / "lib-1.0.tar").write_bytes(b"another library")
            repo = self.repo(w, [{"name": "app", "source": "src/app-1.0-1-src.tar.xz"}])
            w.build("app", repo / "src" / "app-1.0-1-src.tar.xz")
            with self.assertRaisesRegex(SystemExit, "is not the archive of SHA-256"):
                pkg_source.check(repo, w.describe)

    def test_a_damaged_gzip_archive_is_a_mismatch_not_a_crash(self):
        import gzip
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.tar.gz"
            data = bytearray(gzip.compress(b"x" * 5000))
            data[len(data) // 2] ^= 1
            path.write_bytes(bytes(data))
            self.assertFalse(pkg_source.same(path, "0" * 64))

    def test_scan_finds_names_and_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = World(Path(tmp))
            out = Path(tmp) / "app.tar.xz"
            w.build("app", out)
            self.assertEqual(pkg_source.scan(out, ["library source"], ["f-stack"]),
                             [f"app.tar.xz: member app-1.0-1-src/sources/lib-1.0.tar holds 'library source'"])
            self.assertEqual(len(pkg_source.scan(out, [], ["tree"])), 3)
            self.assertEqual(pkg_source.scan(out, ["absent"], ["absent"]), [])

    def test_scan_leaves_the_members_it_is_told_to_allow(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = World(Path(tmp))
            out = Path(tmp) / "app.tar.xz"
            w.build("app", out)
            self.assertEqual(len(pkg_source.scan(out, ["library source"], [])), 1)
            self.assertEqual(pkg_source.scan(out, ["library source"], [], ["/lib-1.0.tar"]), [])

    def test_an_entry_with_an_address_for_a_source_is_checked_in_src_or_left_to_the_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = World(Path(tmp))
            address = "https://github.com/stafeto/packages/releases/download/v1-aarch64/app-1.0-1-src.tar.xz"
            repo = self.repo(w, [{"name": "app", "source": address}])
            # The archive was published before (a carried package): nothing to look at here.
            self.assertEqual(pkg_source.check(repo, w.describe), 0)
            # This build made it: it is looked at.
            w.build("app", repo / "src" / "app-1.0-1-src.tar.xz")
            self.assertEqual(pkg_source.check(repo, w.describe), 1)


if __name__ == "__main__":
    unittest.main()
