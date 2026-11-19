#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Tests of tools/dist.py (`stage`, `pack`) and of tools/dist/run.sh. The
test that run.sh and xtask build the same QEMU command is a test of xtask
(`cargo test -p xtask dist_run`)."""

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dist  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PACKAGE = b"signed package bytes"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_script(directory: Path, flavour: str, *args: str) -> subprocess.CompletedProcess:
    image, memory, _ = dist.FLAVOURS[flavour]
    path = directory / f"run-{flavour}.sh"
    path.write_text(dist.fill((HERE / "dist" / "run.sh").read_text(), image=image, memory=memory))
    return subprocess.run(["sh", str(path), *args], capture_output=True, text=True)


def option(lines: list[str], flag: str) -> list[str]:
    return [lines[i + 1] for i, line in enumerate(lines) if line == flag]


class RunScript(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def lines(self, flavour: str, *args: str) -> list[str]:
        done = run_script(self.dir, flavour, "--print", *args)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.splitlines()

    def test_both_archives_have_a_screen_a_keyboard_and_the_disk(self):
        for flavour in ("base", "full"):
            lines = self.lines(flavour)
            devices = " ".join(option(lines, "-device"))
            self.assertIn("virtio-gpu-device", devices, flavour)
            self.assertIn("virtio-keyboard-device", devices, flavour)
            self.assertIn("virtio-blk-pci", devices, flavour)
            self.assertIn("-serial", lines)
            self.assertNotIn("-nographic", lines)

    def test_memory_and_image_follow_the_archive(self):
        base, full = self.lines("base"), self.lines("full")
        self.assertEqual(option(base, "-m"), ["512M"])
        self.assertEqual(option(full, "-m"), ["1024M"])
        self.assertTrue(option(base, "-initrd")[0].endswith("/boot-base.img"))
        self.assertTrue(option(full, "-initrd")[0].endswith("/boot-full.img"))

    def test_the_full_image_refuses_less_than_1024m(self):
        done = run_script(self.dir, "full", "--print", "--memory", "512M")
        self.assertEqual(done.returncode, 2)
        self.assertIn("1024M", done.stderr)
        self.assertEqual(option(self.lines("full", "--memory", "2G"), "-m"), ["2G"])
        self.assertEqual(option(self.lines("base", "--memory", "256M"), "-m"), ["256M"])

    def test_the_keys(self):
        lines = self.lines("base", "--cpus", "4", "--hvf", "--nographic", "--", "-d", "guest_errors")
        self.assertEqual(option(lines, "-smp"), ["4"])
        self.assertEqual(option(lines, "-cpu"), ["host"])
        self.assertIn("-nographic", lines)
        self.assertNotIn("-serial", lines)
        self.assertEqual(lines[-2:], ["-d", "guest_errors"])
        self.assertEqual(run_script(self.dir, "base", "--cpus", "9").returncode, 2)
        self.assertEqual(run_script(self.dir, "base", "--bogus").returncode, 2)

    def test_print_makes_no_disk(self):
        self.lines("base")
        self.assertEqual(list(self.dir.glob("store.img")), [])


class Pack(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.staged = self.dir / "stage"
        for flavour in ("base", "full"):
            (self.staged / flavour / "LICENSES").mkdir(parents=True)
            (self.staged / flavour / "LICENSES" / "INDEX.txt").write_text(f"{flavour}\n")
        (self.staged / "sources.txt").write_text("busybox\n")
        for name in ("kernel", "gpl-sources"):
            part = self.dir / f"stafeto-1.2.3-{name}"
            part.mkdir()
            (part / "file").write_bytes(name.encode())
            dist.write_tar_xz(self.staged / f"{part.name}.tar.xz", part)
        for name in ("Image", "base.img", "full.img", "INDEX.sig"):
            (self.dir / name).write_bytes(name.encode())
        self.packages = self.dir / "pkg"
        self.packages.mkdir()
        (self.packages / "busybox-1-1.stpkg").write_bytes(PACKAGE)
        self.index = self.dir / "INDEX"
        self.index.write_text(
            "format 1\nrepository stafeto\n\nname busybox\nversion 1-1\n"
            f"size {len(PACKAGE)}\nsha256 {digest(PACKAGE)}\nfile https://example.org/x/busybox-1-1.stpkg\n"
            "summary s\n")
        self.out = self.dir / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def pack(self):
        args = [
            "pack", "--version", "1.2.3", "--stage", str(self.staged), "--image", str(self.dir / "Image"),
            "--base-image", str(self.dir / "base.img"), "--full-image", str(self.dir / "full.img"),
            "--packages", str(self.packages), "--index", str(self.index),
            "--index-sig", str(self.dir / "INDEX.sig"), "--out", str(self.out)]
        old = sys.argv
        sys.argv = ["dist.py", *args]
        try:
            dist.main()
        finally:
            sys.argv = old

    def test_the_files_of_the_release(self):
        self.pack()
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), [
            "SHA256SUMS",
            "stafeto-1.2.3-INDEX",
            "stafeto-1.2.3-INDEX.sig",
            "stafeto-1.2.3-aarch64-virt-base.tar.xz",
            "stafeto-1.2.3-aarch64-virt-full.tar.xz",
            "stafeto-1.2.3-gpl-sources.tar.xz",
            "stafeto-1.2.3-kernel.tar.xz",
            "stafeto-1.2.3-sbom.spdx.json",
        ])
        sums = (self.out / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(sums), 7)
        for line in sums:
            value, name = line.split("  ")
            self.assertEqual(value, digest((self.out / name).read_bytes()))

    def test_the_release_notes_table_names_the_files_that_are_packed(self):
        self.pack()
        spec = importlib.util.spec_from_file_location("release_notes", HERE / "release-notes.py")
        notes = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(notes)
        text = notes.notes("1.2.3", "v1.2.3", "v1.2.2")
        table = [line for line in text.splitlines() if line.startswith("| `")]
        listed = [name for line in table for name in re.findall(r"`([^`]+)`", line.split(" | ")[0])]
        packed = sorted(p.name for p in self.out.iterdir())
        self.assertEqual(sorted(listed), packed)
        self.assertEqual(listed, [name for names, _ in dist.release_files("1.2.3") for name in names])
        self.assertNotIn("stafeto-1.2.3-aarch64-virt.tar.xz", text)
        self.assertIn("`stafeto-1.2.3-INDEX`, `stafeto-1.2.3-INDEX.sig`", text)

    def release_notes(self):
        spec = importlib.util.spec_from_file_location("release_notes", HERE / "release-notes.py")
        notes = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(notes)
        return notes

    def test_the_release_notes_carry_the_freetype_credit(self):
        notes = self.release_notes()
        credit = ("Portions of this software are copyright \u00a9 2026 The FreeType Project "
                  "(https://freetype.org). All rights reserved.")
        self.assertEqual(notes.credits(), [credit])
        text = notes.notes("1.2.3", "v1.2.3", None)
        self.assertIn("## Credits\n\n" + credit + "\n", text)
        # The credit comes from the file the package's record names.
        self.assertEqual(credit + "\n", (ROOT / "ports/freetype/CREDIT.txt").read_text())

    def test_the_credit_is_there_only_when_a_package_under_ftl_is(self):
        notes = self.release_notes()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "packages").mkdir()
            (root / "ports").mkdir()
            (root / "ports/credit.txt").write_text("Credit line.\n")
            record = 'name = "{n}"\nlicense = "{l}"\n{extra}'
            (root / "packages/a.toml").write_text(
                record.format(n="a", l="MIT", extra='notices = ["CREDIT = tree:ports/credit.txt"]\n'))
            self.assertEqual(notes.credits(root), [])
            (root / "packages/b.toml").write_text(
                record.format(n="b", l="FTL", extra='notices = ["CREDIT = tree:ports/credit.txt"]\n'))
            self.assertEqual(notes.credits(root), ["Credit line."])
            # Two packages with the same line give it once; an FTL package with
            # no credit file named gives nothing.
            (root / "packages/c.toml").write_text(
                record.format(n="c", l="MIT AND FTL", extra='notices = ["CREDIT = tree:ports/credit.txt"]\n'))
            (root / "packages/d.toml").write_text(record.format(n="d", l="FTL", extra=""))
            self.assertEqual(notes.credits(root), ["Credit line."])

    def test_the_archives_that_run(self):
        self.pack()
        for flavour, image, memory in (("base", "boot-base.img", "512M"), ("full", "boot-full.img", "1024M")):
            with tarfile.open(self.out / f"stafeto-1.2.3-aarch64-virt-{flavour}.tar.xz") as tar:
                top = f"stafeto-1.2.3-aarch64-virt-{flavour}"
                self.assertEqual(sorted(m.name for m in tar if m.isfile()), sorted(
                    f"{top}/{n}" for n in ("Image", image, "README.md", "run.sh", "LICENSES/INDEX.txt")))
                script = tar.extractfile(f"{top}/run.sh").read().decode()
                self.assertIn(f"image={image}\n", script)
                self.assertIn(f"memory={memory}\n", script)
                self.assertEqual(tar.getmember(f"{top}/run.sh").mode & 0o111, 0o111)
                self.assertEqual(tar.extractfile(f"{top}/LICENSES/INDEX.txt").read().decode(), f"{flavour}\n")

    def test_the_readme_tells_a_pre_release_from_a_release(self):
        self.assertIn("may not exist yet", dist.release_words("0.3.0-pre.1")[1])
        self.assertNotIn("pre-release", " ".join(dist.release_words("0.3.0")))
        self.assertIn("packages/0.3/aarch64", dist.release_words("0.3.0")[1])
        self.pack()
        with tarfile.open(self.out / "stafeto-1.2.3-aarch64-virt-base.tar.xz") as tar:
            text = tar.extractfile("stafeto-1.2.3-aarch64-virt-base/README.md").read().decode()
        self.assertIn("Series 1.2:", text)

    def test_the_sbom_pins_the_signed_package(self):
        self.pack()
        sbom = json.loads((self.out / "stafeto-1.2.3-sbom.spdx.json").read_text())
        busybox = next(p for p in sbom["packages"] if p["name"] == "busybox")
        sums = [c["checksumValue"] for c in busybox["checksums"]]
        self.assertEqual(len(sums), 2)
        self.assertEqual(sums[1], digest(PACKAGE))
        self.assertIn("busybox-1-1.stpkg", busybox["comment"])

    def test_a_package_that_differs_from_the_index_stops_the_release(self):
        (self.packages / "busybox-1-1.stpkg").write_bytes(b"another file")
        with self.assertRaises(SystemExit) as stopped:
            self.pack()
        self.assertIn("the index says", str(stopped.exception))

    def test_a_file_of_the_linux_guest_stops_the_release(self):
        (self.staged / "base" / "LICENSES" / "initramfs.cpio").write_bytes(b"x")
        with self.assertRaises(SystemExit) as stopped:
            self.pack()
        self.assertIn("Linux guest", str(stopped.exception))

    def test_the_shell_archive_is_gone(self):
        self.pack()
        self.assertEqual([p.name for p in self.out.iterdir() if p.name.endswith("aarch64-virt.tar.xz")], [])


class Stage(unittest.TestCase):
    def test_the_stage_holds_the_kernel_the_sources_and_the_notices_of_both_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            for name in ("Image", "kernel.elf"):
                (tmp / name).write_bytes(name.encode())
            seen = []
            for flavour in ("base", "full"):
                licenses = tmp / f"licenses-{flavour}"
                licenses.mkdir()
                (licenses / "packages.txt").write_text(f"busybox\t1-1\tGPL-2.0-only\n")
                (licenses / "sources.txt").write_text("busybox\n" if flavour == "base" else "busybox\nnano\n")
            real = (dist.stage_licenses, dist.stage_sources)
            dist.stage_licenses = lambda stage, version, licenses: (
                seen.append(licenses.name), (stage / "LICENSES").mkdir())
            dist.stage_sources = lambda stage, version, cache, names: (
                stage.mkdir(parents=True), (stage / "README").write_text(" ".join(names)))
            try:
                old = sys.argv
                sys.argv = ["dist.py", "stage", "--version", "9", "--image", str(tmp / "Image"),
                            "--elf", str(tmp / "kernel.elf"), "--licenses-base", str(tmp / "licenses-base"),
                            "--licenses-full", str(tmp / "licenses-full"), "--out", str(tmp / "stage")]
                dist.main()
            finally:
                sys.argv = old
                dist.stage_licenses, dist.stage_sources = real
            self.assertEqual(seen, ["licenses-base", "licenses-full"])
            self.assertEqual((tmp / "stage" / "sources.txt").read_text(), "busybox\nnano\n")
            self.assertTrue((tmp / "stage" / "base" / "LICENSES").is_dir())
            with tarfile.open(tmp / "stage" / "stafeto-9-gpl-sources.tar.xz") as tar:
                self.assertEqual(tar.extractfile("stafeto-9-gpl-sources/README").read().decode(), "busybox nano")
            with tarfile.open(tmp / "stage" / "stafeto-9-kernel.tar.xz") as tar:
                self.assertEqual(sorted(m.name for m in tar if m.isfile()),
                                 ["stafeto-9-kernel/Image", "stafeto-9-kernel/kernel.elf"])


class PackagesOnly(unittest.TestCase):
    """The files of a packages-only update (`pack-packages`) and its notes."""

    OLD = b"the signed package before"
    NEW = b"the signed package after"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.packages = self.dir / "pkg"
        self.packages.mkdir()
        self.busybox = dist.pkgdesc.load("busybox")["version"]
        self.nano = dist.pkgdesc.load("nano")["version"]
        # busybox is carried from the storage of 0.5.1; nano is built for the update.
        (self.packages / f"busybox-{self.busybox}-1.stpkg").write_bytes(PACKAGE)
        (self.packages / f"nano-{self.nano}-2.stpkg").write_bytes(self.NEW)
        storage = "https://github.com/stafeto/packages/releases/download"
        self.index = self.dir / "INDEX"
        self.index.write_text(
            "format 1\nrepository stafeto\nseries 0.5\nserial 3\n"
            f"\nname busybox\nversion {self.busybox}-1\nsize {len(PACKAGE)}\nsha256 {digest(PACKAGE)}\n"
            f"file {storage}/v0.5.1-aarch64/busybox-{self.busybox}-1.stpkg\nsummary s\n"
            f"\nname nano\nversion {self.nano}-2\nsize {len(self.NEW)}\nsha256 {digest(self.NEW)}\n"
            f"file {storage}/v0.5-pkgs.1-aarch64/nano-{self.nano}-2.stpkg\nsummary s\n")
        self.previous = self.dir / "OLD"
        self.previous.write_text(
            "format 1\nrepository stafeto\nseries 0.5\nserial 2\n"
            f"\nname busybox\nversion {self.busybox}-1\nsize {len(PACKAGE)}\nsha256 {digest(PACKAGE)}\n"
            f"file {storage}/v0.5.1-aarch64/busybox-{self.busybox}-1.stpkg\nsummary s\n"
            f"\nname nano\nversion {self.nano}-1\nsize {len(self.OLD)}\nsha256 {digest(self.OLD)}\n"
            f"file {storage}/v0.5.1-aarch64/nano-{self.nano}-1.stpkg\nsummary s\n")
        (self.dir / "INDEX.sig").write_bytes(b"sig")
        self.out = self.dir / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def pack(self):
        old = sys.argv
        sys.argv = ["dist.py", "pack-packages", "--name", "0.5-pkgs.1", "--packages", str(self.packages),
                    "--index", str(self.index), "--index-sig", str(self.dir / "INDEX.sig"), "--out", str(self.out)]
        try:
            dist.main()
        finally:
            sys.argv = old

    def notes(self):
        spec = importlib.util.spec_from_file_location("release_notes", HERE / "release-notes.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_the_files_of_the_update_are_the_index_the_sbom_and_the_sums(self):
        self.pack()
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), [
            "SHA256SUMS", "stafeto-0.5-pkgs.1-INDEX", "stafeto-0.5-pkgs.1-INDEX.sig",
            "stafeto-0.5-pkgs.1-sbom.spdx.json"])
        for line in (self.out / "SHA256SUMS").read_text().splitlines():
            value, name = line.split("  ")
            self.assertEqual(value, digest((self.out / name).read_bytes()))
        self.assertEqual(sorted(n for names, _ in dist.packages_release_files("0.5-pkgs.1") for n in names),
                         sorted(p.name for p in self.out.iterdir()))

    def test_the_sbom_of_an_update_holds_every_package_of_the_index_with_the_sha256_of_its_file(self):
        self.pack()
        sbom = json.loads((self.out / "stafeto-0.5-pkgs.1-sbom.spdx.json").read_text())
        found = {p["name"]: p for p in sbom["packages"]}
        for name, data in (("busybox", PACKAGE), ("nano", self.NEW)):
            self.assertEqual(found[name]["checksums"][1]["checksumValue"], digest(data))
        self.assertEqual(found["busybox"]["versionInfo"], self.busybox)
        self.assertEqual(sbom["name"], "stafeto-0.5-pkgs.1")

    def test_a_package_file_that_is_missing_or_changed_stops_the_update(self):
        (self.packages / f"busybox-{self.busybox}-1.stpkg").unlink()
        with self.assertRaises(SystemExit) as stopped:
            self.pack()
        self.assertIn("busybox", str(stopped.exception))
        (self.packages / f"busybox-{self.busybox}-1.stpkg").write_bytes(b"another file")
        with self.assertRaises(SystemExit) as stopped:
            self.pack()
        self.assertIn("the index says", str(stopped.exception))

    def test_a_tree_that_has_moved_on_from_the_index_stops_the_update(self):
        self.index.write_text(self.index.read_text().replace(f"version {self.nano}-2", "version 0.0.1-2"))
        with self.assertRaises(SystemExit) as stopped:
            self.pack()
        self.assertIn("packages/nano.toml", str(stopped.exception))

    def test_the_notes_list_the_changed_packages_from_two_indexes(self):
        text = self.notes().packages_notes("0.5-pkgs.1", "v0.5-pkgs.1", "v0.5.1", self.index, self.previous)
        table = [line for line in text.splitlines() if line.startswith("| `")]
        self.assertEqual(table[0], f"| `nano` | {self.nano}-1 | {self.nano}-2 | `v0.5-pkgs.1-aarch64` |")
        self.assertFalse(any(line.startswith("| `busybox`") for line in table))
        self.assertIn("compare/v0.5.1...v0.5-pkgs.1", text)
        self.assertIn("`stafeto-0.5-pkgs.1-INDEX`, `stafeto-0.5-pkgs.1-INDEX.sig`", text)
        self.assertIn("An update of the packages of the series 0.5", text)

    def test_a_package_added_or_removed_has_its_row(self):
        notes = self.notes()
        gone = "\nname gone\nversion 1-1\nsize 1\nsha256 " + "0" * 64 + "\nfile https://example.org/v0.5.1-aarch64/gone-1-1.stpkg\nsummary s\n"
        self.previous.write_text(self.previous.read_text() + gone)
        rows = notes.changed_table(self.index, self.previous)
        self.assertIn("| `gone` | 1-1 | - | - |", rows)
        self.assertIn(f"| `nano` | {self.nano}-1 | {self.nano}-2 | `v0.5-pkgs.1-aarch64` |", rows)
        # Read the other way round, the package that was removed is new.
        added = notes.changed_table(self.previous, self.index)
        self.assertIn("| `gone` | - | 1-1 | `v0.5.1-aarch64` |", added)


if __name__ == "__main__":
    unittest.main()
