#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The checks of tools/build-linux-guest.py on synthetic files (the build in
ci downloads no Alpine package): the SHA-256 pins, the unpacking of the EFI
zboot kernel, the closure of the shared libraries, the archive of the
initramfs, the read of an apk, and the refusal of tools/dist.py to ship the
Linux guest."""

import gzip
import hashlib
import importlib.util
import io
import struct
import sys
import tarfile
import tempfile
import unittest
import zlib
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("build_linux_guest", HERE / "build-linux-guest.py")
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)
spec = importlib.util.spec_from_file_location("dist", HERE / "dist.py")
dist = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dist)

LOCK = """
mirror = "https://example.invalid/alpine"
branch = "v3.24"
repository = "main"
arch = "aarch64"

[[package]]
name = "nginx"
version = "1.30.6-r0"
sha256 = "%s"
license = "BSD-2-Clause"
"""


def image(size: int = 0x100) -> bytes:
    """A stand-in for an arm64 Image: the magic ARMd at offset 0x38."""
    data = bytearray(size)
    data[0:2] = b"MZ"
    data[0x38:0x3c] = b"ARMd"
    struct.pack_into("<Q", data, 0x10, size + 0x1000)
    return bytes(data)


def zboot(payload: bytes, compression: bytes = b"gzip", marker: bytes = b"zimg") -> bytes:
    """An EFI zboot file as Alpine ships vmlinuz: a PE header with zimg at 4,
    the start and the length of the payload at 8 and 12, the name of the
    compression at 0x18, the compressed payload after the header."""
    packed = gzip.compress(payload)
    head = bytearray(0x40)
    head[0:2] = b"MZ"
    head[4:8] = marker
    struct.pack_into("<II", head, 8, len(head), len(packed))
    head[0x18:0x18 + len(compression)] = compression
    return bytes(head) + packed


def elf(needed, interp=None, dynamic=True) -> bytes:
    """A 64-bit little-endian ELF file with the given DT_NEEDED names: one
    PT_LOAD for the whole file at address 0, a PT_DYNAMIC, and an optional
    PT_INTERP."""
    strtab = b"\0" + b"".join(n.encode() + b"\0" for n in needed)
    offsets, at = [], 1
    for n in needed:
        offsets.append(at)
        at += len(n) + 1
    interp_bytes = (interp.encode() + b"\0") if interp else b""
    phnum = 1 + (1 if dynamic else 0) + (1 if interp else 0)
    header_end = 64 + 56 * phnum
    interp_at = header_end
    strtab_at = interp_at + len(interp_bytes)
    dynamic_at = strtab_at + len(strtab)
    dynamic_at += -dynamic_at % 8
    entries = b"".join(struct.pack("<qQ", 1, o) for o in offsets)
    entries += struct.pack("<qQ", 5, strtab_at) + struct.pack("<qQ", 0, 0)
    total = dynamic_at + len(entries)
    out = bytearray(total)
    out[0:4] = b"\x7fELF"
    out[4], out[5] = 2, 1
    struct.pack_into("<Q", out, 32, 64)
    struct.pack_into("<HH", out, 54, 56, phnum)
    at_header = 64

    def phdr(kind, offset, size):
        nonlocal at_header
        struct.pack_into("<IIQQQQQQ", out, at_header, kind, 5, offset, offset, offset, size, size, 8)
        at_header += 56

    phdr(1, 0, total)
    if dynamic:
        phdr(2, dynamic_at, len(entries))
    if interp:
        phdr(3, interp_at, len(interp_bytes))
    out[interp_at:interp_at + len(interp_bytes)] = interp_bytes
    out[strtab_at:strtab_at + len(strtab)] = strtab
    out[dynamic_at:dynamic_at + len(entries)] = entries
    return bytes(out)


def apk(members, control: str = "") -> bytes:
    """An apk: gzip streams one after the other, each with a tar inside
    that has no end of archive, the first stream the signature, the second
    the control file and the third the files."""
    def stream(items):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for name, content in items:
                info = tarfile.TarInfo(name)
                if content is None:
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    tar.addfile(info)
                else:
                    info.size = len(content)
                    info.mode = 0o644
                    tar.addfile(info, io.BytesIO(content))
        return gzip.compress(buffer.getvalue()[:-1024])

    return stream([(".SIGN.RSA.x", b"sig")]) + stream([(".PKGINFO", control.encode())]) + stream(members)


def pkginfo(name="nginx", version="1.30.6-r0", license="BSD-2-Clause") -> str:
    return f"pkgname = {name}\npkgver = {version}\nlicense = {license}\n"


class LockTests(unittest.TestCase):
    def test_a_lock_is_read(self):
        lock = guest.parse_lock(LOCK % ("a" * 64))
        self.assertEqual(lock["branch"], "v3.24")
        self.assertEqual(lock["package"][0]["name"], "nginx")

    def test_a_pin_that_is_no_sha256_is_refused(self):
        with self.assertRaises(SystemExit):
            guest.parse_lock(LOCK % "abc")
        with self.assertRaises(SystemExit):
            guest.parse_lock(LOCK % ("G" * 64))

    def test_the_shipped_lock_pins_nginx_and_openssl_of_stafeto(self):
        lock = guest.parse_lock((HERE / "linux-guest" / "alpine.lock").read_text())
        versions = {p["name"]: p["version"] for p in lock["package"]}
        self.assertEqual(versions["nginx"], "1.30.6-r0")
        self.assertEqual(versions["libssl3"], "3.5.9-r0")
        self.assertEqual(versions["libcrypto3"], "3.5.9-r0")
        self.assertIn("linux-virt", versions)

    def test_a_package_that_is_not_the_pinned_one_is_refused(self):
        # Breakage 9: a package replaced, or gone from the branch.
        package = {"name": "nginx", "version": "1.30.6-r0", "sha256": hashlib.sha256(b"good").hexdigest()}
        guest.check_bytes(package, b"good")
        with self.assertRaises(SystemExit) as raised:
            guest.check_bytes(package, b"spoiled")
        self.assertIn("SHA-256", str(raised.exception))

    def test_a_spoiled_file_in_the_cache_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            package = {"name": "nginx", "version": "1.30.6-r0", "sha256": hashlib.sha256(b"good").hexdigest(),
                       "license": "x"}
            lock = {"mirror": "https://example.invalid", "branch": "v3.24", "repository": "main", "arch": "aarch64"}
            (cache / f"{package['sha256']}.apk").write_bytes(b"good")
            self.assertEqual(guest.fetch(lock, package, cache), b"good")
            (cache / f"{package['sha256']}.apk").write_bytes(b"spoiled")
            with self.assertRaises(SystemExit):
                guest.fetch(lock, package, cache)

    def test_a_package_of_another_version_or_licence_is_refused(self):
        # Breakage 3 at the level of the package: 1.28.3 of Alpine 3.23.
        package = {"name": "nginx", "version": "1.30.6-r0", "license": "BSD-2-Clause"}
        good = guest.read_apk(apk([("usr/sbin/nginx", b"x")], pkginfo()))
        guest.check_package(package, good)
        old = guest.read_apk(apk([("usr/sbin/nginx", b"x")], pkginfo(version="1.28.3-r0")))
        with self.assertRaises(SystemExit):
            guest.check_package(package, old)
        other = guest.read_apk(apk([("usr/sbin/nginx", b"x")], pkginfo(license="GPL-2.0-only")))
        with self.assertRaises(SystemExit):
            guest.check_package(package, other)


class ApkTests(unittest.TestCase):
    def test_the_streams_of_an_apk_are_read_in_order(self):
        members = guest.read_apk(apk([("usr", None), ("usr/sbin/nginx", b"binary")], pkginfo()))
        names = [m[0] for m in members]
        self.assertEqual(names, [".SIGN.RSA.x", ".PKGINFO", "usr", "usr/sbin/nginx"])
        self.assertEqual(dict((m[0], m[2]) for m in members)["usr/sbin/nginx"], b"binary")

    def test_a_name_outside_the_tree_is_refused(self):
        with self.assertRaises(SystemExit):
            guest.read_apk(apk([("../escape", b"x")], pkginfo()))

    def test_the_files_of_a_package_go_into_the_tree_without_its_documents(self):
        tree = {}
        members = guest.read_apk(apk([
            ("usr/sbin/nginx", b"binary"),
            ("usr/share/doc/nginx/README", b"text"),
            ("etc/logrotate.d/nginx", b"rotate"),
        ], pkginfo()))
        guest.add_package(tree, {"name": "nginx"}, members)
        self.assertEqual(sorted(tree), ["usr/sbin/nginx"])

    def test_the_kernel_package_gives_its_image_and_the_modules_it_has_only(self):
        tree = {}
        members = guest.read_apk(apk([
            ("boot/vmlinuz-virt", b"zboot"),
            ("boot/System.map-virt", b"map"),
            ("lib/modules/6.18/kernel/drivers/net/virtio_net.ko.gz", gzip.compress(b"module")),
            ("lib/modules/6.18/kernel/fs/ext4/ext4.ko.gz", gzip.compress(b"other")),
        ], pkginfo("linux-virt", "6.18.60-r0", "GPL-2.0-only")))
        kernel = guest.add_package(tree, {"name": "linux-virt"}, members)
        self.assertEqual(kernel, b"zboot")
        self.assertEqual(sorted(tree), ["lib/modules/virtio_net.ko"])
        self.assertEqual(tree["lib/modules/virtio_net.ko"].data, b"module")


class KernelTests(unittest.TestCase):
    def test_a_zboot_kernel_gives_its_image(self):
        self.assertEqual(guest.unzboot(zboot(image())), image())

    def test_a_pe_file_without_zimg_is_refused(self):
        # Breakage 10: a kernel that VZ cannot boot.
        with self.assertRaises(SystemExit):
            guest.unzboot(zboot(image(), marker=b"nope"))
        with self.assertRaises(SystemExit):
            guest.unzboot(b"")

    def test_another_compression_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            guest.unzboot(zboot(image(), compression=b"zstd22"))
        self.assertIn("zstd", str(raised.exception))

    def test_an_image_without_armd_is_refused(self):
        bad = bytearray(image())
        bad[0x38:0x3c] = b"\0\0\0\0"
        with self.assertRaises(SystemExit):
            guest.unzboot(zboot(bytes(bad)))

    def test_a_payload_that_is_no_gzip_is_refused(self):
        data = bytearray(zboot(image()))
        data[0x40:0x44] = b"\0\0\0\0"
        with self.assertRaises(SystemExit):
            guest.unzboot(bytes(data))


class KernelEndTests(unittest.TestCase):
    def test_a_cut_payload_is_refused(self):
        # The start of the stream is whole and the end is gone.
        packed = gzip.compress(image(0x4000))
        cut = packed[: len(packed) - 12]
        head = bytearray(0x40)
        head[0:2] = b"MZ"
        head[4:8] = b"zimg"
        struct.pack_into("<II", head, 8, len(head), len(cut))
        head[0x18:0x1c] = b"gzip"
        with self.assertRaises(SystemExit):
            guest.unzboot(bytes(head) + cut)

    def test_bytes_after_the_stream_are_refused(self):
        data = zboot(image())
        head = bytearray(data[:0x40])
        packed = data[0x40:] + b"junk"
        struct.pack_into("<II", head, 8, len(head), len(packed))
        with self.assertRaises(SystemExit):
            guest.unzboot(bytes(head) + packed)

    def test_an_image_size_below_the_image_is_refused(self):
        small = bytearray(image())
        struct.pack_into("<Q", small, 0x10, 0x10)
        with self.assertRaises(SystemExit):
            guest.unzboot(zboot(bytes(small)))


class ModuleTests(unittest.TestCase):
    def test_a_missing_module_stops_the_build(self):
        # Breakage: the guest would boot with no network.
        with tempfile.TemporaryDirectory() as directory:
            lock = {"mirror": "m", "branch": "b", "repository": "r", "arch": "a",
                    "package": [{"name": "linux-virt", "version": "1-r0", "sha256": "0" * 64,
                                 "license": "GPL-2.0-only"}]}
            members = apk([("boot/vmlinuz-virt", b"zboot"),
                           ("lib/modules/6/kernel/net/failover.ko.gz", gzip.compress(b"m"))],
                          pkginfo("linux-virt", "1-r0", "GPL-2.0-only"))
            lock["package"][0]["sha256"] = hashlib.sha256(members).hexdigest()
            cache = Path(directory)
            (cache / f"{lock['package'][0]['sha256']}.apk").write_bytes(members)
            init = cache / "init"
            init.write_bytes(b"#!/bin/sh\n")
            overlay = cache / "overlay"
            overlay.mkdir()
            with self.assertRaises(SystemExit) as raised:
                guest.make_tree(lock, cache, overlay, init)
            self.assertIn("virtio_net", str(raised.exception))


class ClosureTests(unittest.TestCase):
    def tree(self, program_needs, libraries):
        tree = {"bin/prog": guest.Entry("file", 0o755, elf(program_needs, "/lib/ld-musl-aarch64.so.1")),
                "lib/ld-musl-aarch64.so.1": guest.Entry("file", 0o755, elf([]))}
        for name in libraries:
            tree[f"usr/lib/{name}"] = guest.Entry("file", 0o755, elf([]))
        return tree

    def test_the_needed_names_of_an_elf_file_are_read(self):
        self.assertEqual(guest.elf_needed(elf(["libssl.so.3", "libc.musl-aarch64.so.1"], "/lib/ld")),
                         ("/lib/ld", ["libssl.so.3", "libc.musl-aarch64.so.1"]))
        self.assertEqual(guest.elf_needed(elf([], dynamic=False)), (None, []))
        self.assertIsNone(guest.elf_needed(b"#!/bin/sh\n"))

    def test_a_closed_tree_passes(self):
        guest.check_closure(self.tree(["libz.so.1"], ["libz.so.1"]))

    def test_a_library_that_is_missing_stops_the_build(self):
        # Breakage 11.
        with self.assertRaises(SystemExit) as raised:
            guest.check_closure(self.tree(["libz.so.1", "libssl.so.3"], ["libz.so.1"]))
        self.assertIn("libssl.so.3", str(raised.exception))

    def test_a_link_to_the_library_counts(self):
        tree = self.tree(["libz.so.1"], ["libz.so.1.3.2"])
        tree["usr/lib/libz.so.1"] = guest.Entry("symlink", 0o777, b"libz.so.1.3.2")
        guest.check_closure(tree)

    def test_a_missing_interpreter_stops_the_build(self):
        tree = self.tree([], [])
        del tree["lib/ld-musl-aarch64.so.1"]
        with self.assertRaises(SystemExit):
            guest.check_closure(tree)


class ArchiveTests(unittest.TestCase):
    def read(self, data):
        """The (name, mode, content) of a newc archive."""
        entries, at = [], 0
        while True:
            self.assertEqual(data[at:at + 6], b"070701")
            fields = [int(data[at + 6 + 8 * n: at + 14 + 8 * n], 16) for n in range(13)]
            size, namesize = fields[6], fields[11]
            name = data[at + 110: at + 110 + namesize - 1].decode()
            at += 110 + namesize
            at += -at % 4
            content = data[at:at + size]
            at += size
            at += -at % 4
            if name == "TRAILER!!!":
                return entries
            entries.append((name, fields[1], content))

    def tree(self):
        return {"etc": guest.Entry("dir", 0o755),
                "etc/passwd": guest.Entry("file", 0o644, b"root\n"),
                "bin": guest.Entry("dir", 0o755),
                "bin/sh": guest.Entry("symlink", 0o777, b"/bin/busybox"),
                "dev/console": guest.Entry("device", 0o20600, rdev=(5, 1)),
                "dev": guest.Entry("dir", 0o755)}

    def test_the_archive_is_sorted_and_reads_back(self):
        entries = self.read(guest.cpio_newc(self.tree()))
        self.assertEqual([e[0] for e in entries], ["bin", "bin/sh", "dev", "dev/console", "etc", "etc/passwd"])
        by_name = {e[0]: e for e in entries}
        self.assertEqual(by_name["etc/passwd"][1], 0o100644)
        self.assertEqual(by_name["etc/passwd"][2], b"root\n")
        self.assertEqual(by_name["bin/sh"][1], 0o120777)
        self.assertEqual(by_name["bin/sh"][2], b"/bin/busybox")
        self.assertEqual(by_name["dev/console"][1], 0o20600)
        self.assertEqual(by_name["etc"][1], 0o40755)

    def test_the_same_tree_gives_the_same_bytes(self):
        a = guest.gzip_bytes(guest.cpio_newc(self.tree()))
        b = guest.gzip_bytes(guest.cpio_newc(dict(reversed(list(self.tree().items())))))
        self.assertEqual(a, b)
        self.assertEqual(zlib.decompress(a, 31), guest.cpio_newc(self.tree()))

    def test_the_overlay_goes_over_the_tree_and_makes_its_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            overlay = Path(directory)
            (overlay / "www").mkdir()
            (overlay / "www" / "1k.bin").write_bytes(b"x" * 1024)
            tree = {"www": guest.Entry("dir", 0o755)}
            guest.add_overlay(tree, overlay)
            self.assertEqual(sorted(tree), ["www", "www/1k.bin"])
            (overlay / "link").symlink_to("www")
            with self.assertRaises(SystemExit):
                guest.add_overlay({}, overlay)


class DistTests(unittest.TestCase):
    def archive(self, directory, name, members):
        with tarfile.open(directory / name, "w:xz") as tar:
            for member, content in members:
                info = tarfile.TarInfo(member)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))

    def test_a_release_without_the_guest_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.archive(out, "stafeto-1-gpl-sources.tar.xz", [
                ("stafeto-1/tools/build-linux-guest.py", b"script"),
                ("stafeto-1/tools/linux-guest/alpine.lock", b"lock")])
            self.archive(out, "stafeto-1-aarch64-virt.tar.xz", [("stafeto-1-aarch64-virt/Image", b"kernel")])
            dist.refuse_linux_guest(out, out / "no-guest")

    def test_a_release_with_a_file_of_the_guest_is_refused(self):
        # The names of the guest's files, and the guest's bytes under any name.
        for name in ("target/linux-guest/Image", "stafeto/initramfs.cpio.gz", "boot/vmlinuz-virt",
                     "pkg/nginx-1.30.6-r0.apk"):
            with tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                self.archive(out, "release.tar.xz", [(name, b"x")])
                with self.assertRaises(SystemExit, msg=name):
                    dist.refuse_linux_guest(out, out / "no-guest")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            guest_dir = out / "guest"
            guest_dir.mkdir()
            (guest_dir / "Image").write_bytes(b"the guest's kernel")
            self.archive(out, "release.tar.xz", [("stafeto/Image", b"the guest's kernel")])
            with self.assertRaises(SystemExit) as raised:
                dist.refuse_linux_guest(out, guest_dir)
            self.assertIn("Linux guest", str(raised.exception))

    def test_a_renamed_file_of_the_guest_next_to_the_archives_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            guest_dir = out / "guest"
            guest_dir.mkdir()
            (guest_dir / "Image").write_bytes(b"the guest's kernel")
            (out / "kernel-copy").write_bytes(b"the guest's kernel")
            with self.assertRaises(SystemExit):
                dist.refuse_linux_guest(out, guest_dir)

    def test_a_loose_file_of_the_guest_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / "alpine-nginx.apk").write_bytes(b"x")
            with self.assertRaises(SystemExit):
                dist.refuse_linux_guest(out, out / "no-guest")


if __name__ == "__main__":
    unittest.main()
