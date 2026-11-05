#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build the Linux guest of the measurement of the network (stage P7): an
Alpine Linux aarch64 kernel and user space from the packages that
tools/linux-guest/alpine.lock pins by SHA-256, as the files
target/linux-guest/Image (the kernel VZ boots), initramfs.cpio.gz and
MANIFEST.

The guest runs on the Mac that builds it and is never shipped: it stays in
target/linux-guest and no release archive takes it (tools/dist.py refuses
one that holds it). The packages are downloaded into a cache outside the
clone (~/.cache/stafeto/alpine/<sha256>.apk), checked against the lock, and
read in memory: no member of an archive is written to disk under the name
the archive gives it, and no program of the archives runs on the Mac.

    build-linux-guest.py --overlay DIR [--out DIR] [--lock FILE] [--init FILE]

DIR holds the files of the guest that stafeto's image carries too (the
settings of nginx and the files under /www), made by `cargo xtask
linux-guest build` from the same sources as stafeto's image. The same lock
and the same overlay give the same bytes."""

import argparse
import gzip
import hashlib
import io
import os
import struct
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
import zlib
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
LOCK = HERE / "linux-guest" / "alpine.lock"
INIT = HERE / "linux-guest" / "init"
OUT = ROOT / "target" / "linux-guest"

# The kernel image of arm64 carries the magic "ARM\x64" at offset 0x38.
IMAGE_MAGIC = b"ARMd"
# The modules the guest needs, in the order /init loads them: virtio-net with
# its dependencies, and the packet sockets udhcpc sends DHCP through.
MODULES = ("failover", "net_failover", "virtio_net", "af_packet")
# What the kernel package contributes besides the modules.
KERNEL_FILE = "boot/vmlinuz-virt"
# The directories the guest needs that no package makes.
DIRECTORIES = ("proc", "sys", "dev", "run", "tmp", "root", "var", "var/log", "var/log/nginx", "lib/modules")
SYMLINKS = {"var/run": "/run", "var/tmp": "/tmp", "bin/sh": "/bin/busybox"}
# Packages' trees that the guest does not carry.
SKIPPED = ("usr/share/doc/", "usr/share/man/", "usr/share/bash-completion/", "usr/share/licenses/",
           "etc/logrotate.d/", "etc/network/", "usr/share/nginx/", "var/www/", "var/lib/nginx/html/",
           "etc/busybox-paths.d/", "etc/securetty", "etc/shadow", "etc/inittab",
           "etc/fstab", "etc/profile", "etc/modules", "etc/sysctl.conf", "etc/shells")
DEVICES = {"dev/console": (0o20600, 5, 1), "dev/null": (0o20666, 1, 3)}


class Entry:
    """A file, a directory, a symbolic link or a device of the guest."""

    def __init__(self, kind, mode, data=b"", rdev=(0, 0)):
        self.kind, self.mode, self.data, self.rdev = kind, mode, data, rdev


def die(message):
    raise SystemExit(f"linux-guest: {message}")


# The lock ------------------------------------------------------------------

def parse_lock(text):
    """The pins of a lock: the mirror, the branch, the repository, the
    architecture and the packages (name, version, sha256)."""
    lock = tomllib.loads(text)
    for key in ("mirror", "branch", "repository", "arch"):
        if not isinstance(lock.get(key), str):
            die(f"the lock has no {key}")
    packages = lock.get("package", [])
    if not packages:
        die("the lock has no package")
    names = set()
    for p in packages:
        for key in ("name", "version", "sha256", "license"):
            if not isinstance(p.get(key), str) or not p[key]:
                die(f"a package of the lock has no {key}: {p}")
        if len(p["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in p["sha256"]):
            die(f"{p['name']}: the SHA-256 in the lock is no 64 hex digits")
        if p["name"] in names:
            die(f"{p['name']} twice in the lock")
        names.add(p["name"])
    return lock


def apk_name(package):
    return f"{package['name']}-{package['version']}.apk"


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def check_bytes(package, data):
    """Refuses the bytes of a package that are not the ones the lock pins."""
    got = sha256_hex(data)
    if got != package["sha256"]:
        die(f"{apk_name(package)}: SHA-256 {got}, the lock pins {package['sha256']}")


def fetch(lock, package, cache):
    """The bytes of the package, from the cache or from the mirror, checked
    against the lock."""
    cached = cache / f"{package['sha256']}.apk"
    if cached.is_file():
        data = cached.read_bytes()
        check_bytes(package, data)
        return data
    url = f"{lock['mirror']}/{lock['branch']}/{lock['repository']}/{lock['arch']}/{apk_name(package)}"
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            die(f"the package {package['name']} {package['version']} left the branch "
                f"{lock['branch']}: update tools/linux-guest/alpine.lock ({url})")
        die(f"{url}: {error}")
    except OSError as error:
        die(f"{url}: {error}")
    check_bytes(package, data)
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=cache, delete=False) as file:
        file.write(data)
    os.replace(file.name, cached)
    return data


# The packages ----------------------------------------------------------------

def safe_name(name):
    """The name of a member as a relative path without dots, or None."""
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def read_apk(data):
    """The members of an apk (gzip streams one after the other, each with a
    tar inside that has no end of archive): (name, TarInfo, content) for
    the files, directories and links; the control files (.PKGINFO, the
    signature, the scripts) come as names that start with a dot."""
    members = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz", ignore_zeros=True) as tar:
        for info in tar:
            name = safe_name(info.name)
            if name is None:
                die(f"a member of a package has the name {info.name!r}")
            if info.isfile():
                members.append((name, info, tar.extractfile(info).read()))
            elif info.isdir() or info.issym() or info.islnk():
                members.append((name, info, b""))
            else:
                die(f"{name}: a member of a package that is no file, directory or link")
    return members


def pkginfo(members):
    """The fields of .PKGINFO as a dict (a field that repeats keeps the
    first)."""
    for name, _, content in members:
        if name == ".PKGINFO":
            fields = {}
            for line in content.decode().splitlines():
                if line.startswith("#") or " = " not in line:
                    continue
                key, value = line.split(" = ", 1)
                fields.setdefault(key, value)
            return fields
    die("a package has no .PKGINFO")


def check_package(package, members):
    """The package is the one the lock names: its .PKGINFO says the same
    name and version and a licence the lock lists."""
    info = pkginfo(members)
    if info.get("pkgname") != package["name"] or info.get("pkgver") != package["version"]:
        die(f"{apk_name(package)} holds {info.get('pkgname')} {info.get('pkgver')}")
    if info.get("license") != package["license"]:
        die(f"{package['name']}: the licence is {info.get('license')!r}, the lock says "
            f"{package['license']!r}")


def add_package(tree, package, members):
    """Puts the files of a package into the tree. The kernel package gives
    only its image and the modules; the rest of the packages give all they
    carry except the trees in SKIPPED. Gives the kernel's file for the kernel
    package."""
    kernel = None
    for name, info, content in members:
        if name.startswith("."):
            continue
        if package["name"].startswith("linux-"):
            if name == KERNEL_FILE:
                kernel = content
            elif name.startswith("lib/modules/") and name.endswith(".ko.gz"):
                module = name.rsplit("/", 1)[1][: -len(".ko.gz")]
                if module in MODULES:
                    tree[f"lib/modules/{module}.ko"] = Entry("file", 0o644, gzip.decompress(content))
            continue
        if any(name.startswith(prefix) or name + "/" == prefix for prefix in SKIPPED):
            continue
        mode = info.mode & 0o7777
        if info.isdir():
            tree.setdefault(name, Entry("dir", 0o755))
        elif info.issym():
            tree[name] = Entry("symlink", 0o777, info.linkname.encode())
        elif info.islnk():
            target = safe_name(info.linkname)
            if target is None or target not in tree:
                die(f"{name}: a hard link to {info.linkname}")
            tree[name] = tree[target]
        else:
            tree[name] = Entry("file", mode, content)
    return kernel


def busybox_links(members):
    """The paths of the applets (etc/busybox-paths.d/busybox)."""
    for name, _, content in members:
        if name == "etc/busybox-paths.d/busybox":
            return [p for p in content.decode().split() if safe_name(p) == p]
    die("the busybox package has no etc/busybox-paths.d/busybox")


# The kernel --------------------------------------------------------------------

def unzboot(data):
    """The Image in an EFI zboot file (what Alpine ships as vmlinuz): a PE
    file with "zimg" at offset 4, the start and the length of the payload
    at 8 and 12, the name of the compression at 0x18. Only gzip is read; the
    result must carry "ARMd" at offset 0x38. VZ boots an Image; a zboot file
    fails to boot."""
    if len(data) < 0x20 or data[:2] != b"MZ" or data[4:8] != b"zimg":
        die("the kernel is no EFI zboot file (no MZ and zimg)")
    start, length = struct.unpack_from("<II", data, 8)
    compression = data[0x18:0x20].split(b"\0")[0]
    if compression != b"gzip":
        die(f"the kernel's payload is compressed with {compression!r}; only gzip is read")
    if start + length > len(data) or length == 0:
        die("the payload of the kernel lies outside the file")
    stream = zlib.decompressobj(31)
    try:
        image = stream.decompress(data[start:start + length])
    except zlib.error as error:
        die(f"the payload of the kernel does not unpack: {error}")
    if not stream.eof or stream.unused_data:
        die("the payload of the kernel is cut short or has bytes after its gzip stream")
    if len(image) < 0x40 or image[0x38:0x3c] != IMAGE_MAGIC:
        die("the unpacked kernel has no ARMd at offset 0x38: no arm64 Image")
    if struct.unpack_from("<Q", image, 0x10)[0] < len(image):
        die("image_size in the header of the kernel is smaller than the Image")
    return image


# The closure of the shared libraries ----------------------------------------------

PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB = 0, 1, 5


def elf_needed(data):
    """(interpreter, [DT_NEEDED names]) of a 64-bit little-endian ELF file;
    None for a file that is no ELF; (None, []) for a static one."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    if data[4] != 2 or data[5] != 1:
        die("an ELF file that is no 64-bit little-endian one")
    phoff, = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    loads, dynamic, interp = [], None, None
    for n in range(phnum):
        at = phoff + n * phentsize
        kind, _, offset, vaddr, _, filesz, _, _ = struct.unpack_from("<IIQQQQQQ", data, at)
        if kind == PT_LOAD:
            loads.append((vaddr, offset, filesz))
        elif kind == PT_DYNAMIC:
            dynamic = (offset, filesz)
        elif kind == PT_INTERP:
            interp = data[offset:offset + filesz].split(b"\0")[0].decode()
    if dynamic is None:
        return interp, []

    def file_offset(address):
        for vaddr, offset, size in loads:
            if vaddr <= address < vaddr + size:
                return offset + address - vaddr
        die("a dynamic address outside every segment")

    needed, strtab = [], None
    offset, size = dynamic
    for at in range(offset, offset + size, 16):
        tag, value = struct.unpack_from("<qQ", data, at)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            needed.append(value)
        elif tag == DT_STRTAB:
            strtab = file_offset(value)
    if needed and strtab is None:
        die("a dynamic section with DT_NEEDED and no DT_STRTAB")
    names = []
    for value in needed:
        end = data.index(b"\0", strtab + value)
        names.append(data[strtab + value:end].decode())
    return interp, names


def resolve(tree, path, depth=0):
    """The entry at `path` (no leading slash) with the links followed."""
    if depth > 8:
        return None
    entry = tree.get(path)
    if entry is not None and entry.kind == "symlink":
        target = entry.data.decode()
        if not target.startswith("/"):
            target = os.path.normpath(os.path.join(os.path.dirname(path), target))
        return resolve(tree, target.lstrip("/"), depth + 1)
    return entry


def check_closure(tree):
    """Every ELF program and library in the tree finds its interpreter and
    each DT_NEEDED in /lib or /usr/lib of the tree; the first that does not
    stops the build before the guest boots."""
    missing = []
    for path, entry in sorted(tree.items()):
        if entry.kind != "file" or path.endswith(".ko"):
            continue
        found = elf_needed(entry.data)
        if found is None:
            continue
        interp, needed = found
        if interp and resolve(tree, interp.lstrip("/")) is None:
            missing.append(f"{path}: the interpreter {interp}")
        for name in needed:
            if not any(resolve(tree, f"{d}/{name}") for d in ("lib", "usr/lib")):
                missing.append(f"{path}: {name}")
    if missing:
        die("a library is missing from the initramfs:\n  " + "\n  ".join(missing))


# The initramfs ------------------------------------------------------------------------

def cpio_newc(tree):
    """The archive in the format `newc`: sorted by name, so that a directory
    comes before its files, with the time 0 and the owner root, the same
    bytes for the same tree."""
    out = bytearray()
    names = sorted(tree)
    for number, name in enumerate(names, start=1):
        entry = tree[name]
        mode = {"dir": 0o040000, "file": 0o100000, "symlink": 0o120000}.get(entry.kind, 0)
        if entry.kind == "device":
            kind_mode = entry.mode & 0o170000
            mode = kind_mode
        data = entry.data if entry.kind in ("file", "symlink") else b""
        perm = entry.mode & 0o7777
        raw_name = name.encode() + b"\0"
        header = "070701" + "".join(f"{value:08x}" for value in (
            number, mode | perm, 0, 0, 2 if entry.kind == "dir" else 1, 0, len(data), 0, 0,
            entry.rdev[0], entry.rdev[1], len(raw_name), 0))
        out += header.encode() + raw_name
        out += b"\0" * (-len(out) % 4)
        out += data
        out += b"\0" * (-len(out) % 4)
    trailer = b"TRAILER!!!\0"
    out += ("070701" + "".join(f"{value:08x}" for value in (
        0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(trailer), 0))).encode() + trailer
    out += b"\0" * (-len(out) % 4)
    return bytes(out)


def gzip_bytes(data):
    """gzip with no name and the time 0: the same bytes for the same data."""
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=0) as file:
        file.write(data)
    return buffer.getvalue()


# The overlay and the tree ---------------------------------------------------------------------

def add_overlay(tree, overlay):
    """The files of the overlay directory over the tree: regular files and
    directories only; the owner root, the mode 0644 and 0755."""
    for path in sorted(overlay.rglob("*")):
        relative = path.relative_to(overlay).as_posix()
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            die(f"the overlay holds {relative}, which is no file or directory")
        if safe_name(relative) != relative:
            die(f"the overlay holds the name {relative}")
        if path.is_dir():
            tree.setdefault(relative, Entry("dir", 0o755))
        else:
            tree[relative] = Entry("file", 0o644, path.read_bytes())
            parent = relative.rsplit("/", 1)[0] if "/" in relative else None
            while parent:
                tree.setdefault(parent, Entry("dir", 0o755))
                parent = parent.rsplit("/", 1)[0] if "/" in parent else None


def make_tree(lock, cache, overlay, init):
    """The tree of the guest from the lock, the overlay and /init; gives it
    with the kernel's zboot file and the licence of each package."""
    tree = {}
    kernel = None
    for package in lock["package"]:
        data = fetch(lock, package, cache)
        members = read_apk(data)
        check_package(package, members)
        found = add_package(tree, package, members)
        if package["name"] == "busybox":
            for path in busybox_links(members):
                tree.setdefault(path, Entry("symlink", 0o777, b"/bin/busybox"))
        if found is not None:
            kernel = found
    if kernel is None:
        die("the lock has no kernel package with " + KERNEL_FILE)
    absent = [m for m in MODULES if f"lib/modules/{m}.ko" not in tree]
    if absent:
        die(f"the kernel package has no module {', '.join(absent)}: the guest would boot without its network")
    for name in DIRECTORIES:
        tree.setdefault(name, Entry("dir", 0o755 if name != "tmp" else 0o1777))
    for name, target in SYMLINKS.items():
        tree.setdefault(name, Entry("symlink", 0o777, target.encode()))
    for name, (mode, major, minor) in DEVICES.items():
        tree[name] = Entry("device", mode, rdev=(major, minor))
    tree["init"] = Entry("file", 0o755, init.read_bytes())
    add_overlay(tree, overlay)
    for name in [n for n in tree if "/" in n]:
        parent = name.rsplit("/", 1)[0]
        while parent:
            tree.setdefault(parent, Entry("dir", 0o755))
            parent = parent.rsplit("/", 1)[0] if "/" in parent else ""
    check_closure(tree)
    return tree, kernel


def manifest(lock, image, initramfs, overlay_sha256):
    lines = [f"alpine {lock['branch']} {lock['repository']} {lock['arch']}"]
    for p in lock["package"]:
        lines.append(f"package {p['name']} {p['version']} sha256:{p['sha256']} license:{p['license']}")
    lines.append(f"overlay sha256:{overlay_sha256}")
    lines.append(f"Image sha256:{sha256_hex(image)} {len(image)} bytes")
    lines.append(f"initramfs.cpio.gz sha256:{sha256_hex(initramfs)} {len(initramfs)} bytes")
    return "\n".join(lines) + "\n"


def overlay_digest(overlay):
    digest = hashlib.sha256()
    for path in sorted(overlay.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(overlay).as_posix().encode() + b"\0")
            digest.update(sha256_hex(path.read_bytes()).encode() + b"\n")
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--overlay", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=OUT)
    parser.add_argument("--lock", type=Path, default=LOCK)
    parser.add_argument("--init", type=Path, default=INIT)
    parser.add_argument("--cache", type=Path,
                        default=Path(os.environ.get("HOME", "~")) / ".cache" / "stafeto" / "alpine")
    args = parser.parse_args()
    lock = parse_lock(args.lock.read_text())
    tree, zboot = make_tree(lock, args.cache, args.overlay, args.init)
    image = unzboot(zboot)
    initramfs = gzip_bytes(cpio_newc(tree))
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "Image").write_bytes(image)
    (args.out / "initramfs.cpio.gz").write_bytes(initramfs)
    text = manifest(lock, image, initramfs, overlay_digest(args.overlay))
    (args.out / "MANIFEST").write_text(text)
    print(text, end="")
    print(f"linux-guest: {args.out}")


if __name__ == "__main__":
    main()
