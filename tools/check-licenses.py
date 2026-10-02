#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The licences of what programs link (spec 2, 5): the POSIX system layer
under GPL-3.0-or-later with the GCC Runtime Library Exception 3.1, relibc
and its dependencies under licences GPL-2.0-only takes, the GPL-2.0-only
BusyBox apart from bare GPLv3 code, and the crates of the drivers. Runs in
`cargo xtask ci` right after `cargo xtask relibc`, whose fork it reads
(target/relibc/source). Writes target/relibc/THIRD-PARTY-NOTICES from the
licence files of relibc's closure."""

import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RELIBC = ROOT / "target" / "relibc" / "source"
NOTICES = ROOT / "target" / "relibc" / "THIRD-PARTY-NOTICES"
TOOLCHAIN = "nightly-2026-05-24"

GPL = "GPL-3.0-or-later"
EXCEPTION = "GPL-3.0-or-later WITH GCC-exception-3.1"
# The programs link these and all they take (item 1).
LINK_ROOTS = ("posix-crt", "posix-platform")
# The exception's text from the SPDX licence list (spec 2, 5), unchanged.
EXCEPTION_FILE = ROOT / "LICENSE-GCC-exception-3.1"
EXCEPTION_SHA256 = "7103d4f7f7e2f8ce10d282a05e0689637f8d6d9ef7b399d808d1da313e69b960"

# Licences GPL-2.0-only takes (items 5 and 6). Apache-2.0 alone does not;
# with the LLVM exception it does, the exception says so for GPLv2. SunPro
# is FDLIBM's notice: use with the notice kept, nothing more.
GPL2_COMPATIBLE = {"MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "Unlicense",
                   "Unicode-3.0", "LicenseRef-public-domain", "SunPro",
                   "Apache-2.0 WITH LLVM-exception"}

# relibc's packages without a `license` field: the file that grants their
# licence, its SHA-256, and the licence (item 6).
UNLABELLED = {
    "relibc": ("LICENSE", "MIT"),
    "generic-rt": ("LICENSE", "MIT"),
    "redox-rings": ("vendor/redox-rings-0.1.0/LICENCE", "MIT"),
}
UNLABELLED_SHA256 = {
    "LICENSE": "1bc13112bee203de03bb45dfebc20e5338a20349a5935c16b7222c87fd0c7609",
    "vendor/redox-rings-0.1.0/LICENCE":
        "ceee4630ce05fd02513c2df17e89e82ba92a70cf54618fe3f641f0867e1c9970",
}
# openlibm, of which relibc takes the headers alone: LICENSE.md names the
# BSD, ISC and MIT licences, FDLIBM's notice (SunPro) and public domain for
# the code; the LGPL files are the tests in test/, which nothing builds.
OPENLIBM = ("openlibm/LICENSE.md",
            "b1843fbf5b03f519a5f0a44fce751bdd1022ae7148614923f9d6293e17a18b17",
            "BSD-2-Clause AND ISC AND MIT AND SunPro AND LicenseRef-public-domain")

# Licences a GPL-3.0-or-later program may link from crates.io (drivers).
PERMISSIVE = {"MIT", "Apache-2.0", "MIT OR Apache-2.0", "Apache-2.0 OR MIT",
              "Zlib OR Apache-2.0 OR MIT", "BSD-2-Clause OR Apache-2.0 OR MIT"}


def fail(message: str) -> None:
    raise SystemExit(f"check-licenses: {message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tokens(expression: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", expression.replace("/", " OR "))


def allowed(expression: str) -> bool:
    """Whether GPL-2.0-only takes the SPDX `expression`: an OR needs one
    side, an AND both; a WITH is one licence with its exception."""
    items = tokens(expression)
    position = 0

    def primary() -> bool:
        nonlocal position
        if position >= len(items):
            fail(f"incomplete licence expression {expression!r}")
        item = items[position]
        position += 1
        if item == "(":
            value = either()
            if position >= len(items) or items[position] != ")":
                fail(f"unbalanced licence expression {expression!r}")
            position += 1
            return value
        if position + 1 < len(items) and items[position] == "WITH":
            item = f"{item} WITH {items[position + 1]}"
            position += 2
        return item in GPL2_COMPATIBLE

    def both() -> bool:
        nonlocal position
        value = primary()
        while position < len(items) and items[position] == "AND":
            position += 1
            value = primary() and value
        return value

    def either() -> bool:
        nonlocal position
        value = both()
        while position < len(items) and items[position] == "OR":
            position += 1
            value = both() or value
        return value

    value = either()
    if position != len(items):
        fail(f"unexpected {items[position]!r} in licence expression {expression!r}")
    return value


def metadata(cwd: Path, *extra: str, toolchain: str | None = None) -> dict:
    command = ["cargo"] + ([f"+{toolchain}"] if toolchain else [])
    command += ["metadata", "--format-version", "1", "--locked", *extra]
    return json.loads(subprocess.check_output(command, cwd=cwd))


def closure(metadata_: dict, roots) -> set:
    """What `roots` link: normal dependencies, without procedural macros
    (they run in the compiler) and build scripts' dependencies."""
    packages = {package["id"]: package for package in metadata_["packages"]}
    nodes = {node["id"]: node for node in metadata_["resolve"]["nodes"]}
    pending, seen = list(roots), set()
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        if any("proc-macro" in target["kind"] for target in packages[package_id]["targets"]):
            continue
        seen.add(package_id)
        for dep in nodes[package_id]["deps"]:
            if any(kind["kind"] is None for kind in dep["dep_kinds"]):
                pending.append(dep["pkg"])
    return seen


def workspace() -> None:
    """Items 1 to 5 on the workspace."""
    data = metadata(ROOT, "--all-features", "--filter-platform", "aarch64-unknown-none")
    packages = {package["id"]: package for package in data["packages"]}
    named = {package["name"]: package for package in data["packages"]}
    members = set(data["workspace_members"])
    linked = closure(data, [named[name]["id"] for name in LINK_ROOTS])
    # 1: the closure of the link roots.
    for package_id in sorted(linked, key=lambda i: packages[i]["name"]):
        package = packages[package_id]
        license_name = package["license"] or ""
        if package_id in members:
            if license_name not in ("MIT", EXCEPTION):
                fail(f"{package['name']} is linked into programs under {license_name!r},"
                     f" not MIT or {EXCEPTION}")
        elif "GPL" in license_name:
            fail(f"programs link {package['name']} under {license_name}")
    # 2: the exception goes to the closure alone; the rest of POSIX and
    # the services stay GPL-3.0-or-later.
    for package_id in members - linked:
        package = packages[package_id]
        manifest = Path(package["manifest_path"]).relative_to(ROOT)
        if package["license"] == EXCEPTION:
            fail(f"{package['name']} has the exception but no program links it")
        # The bridge of Picolibc programs is MIT until relibc replaces it.
        if package["name"] == "posix-bridge":
            continue
        if (package["name"].startswith("posix-") or manifest.parts[0] == "services") \
                and package["license"] != GPL:
            fail(f"{package['name']} must be {GPL}")
    # 3: every source file says its package's licence first.
    roots = sorted(((Path(packages[i]["manifest_path"]).parent, packages[i]["license"])
                    for i in members), key=lambda root: len(root[0].parts), reverse=True)
    for directory, license_name in roots:
        for source in sorted(directory.rglob("*")):
            if source.suffix not in (".rs", ".c", ".h") or "target" in source.parts:
                continue
            owner = next(lic for d, lic in roots if source.is_relative_to(d))
            if owner != license_name:
                continue
            expected = [f"// SPDX-License-Identifier: {license_name}"]
            if source.suffix != ".rs":
                expected.append(f"/* SPDX-License-Identifier: {license_name} */")
            lines = source.read_text().splitlines()
            if not lines or lines[0] not in expected:
                fail(f"{source.relative_to(ROOT)} must start with {expected[0]!r}")
    # 4: the exception's text.
    if not EXCEPTION_FILE.exists() or sha256(EXCEPTION_FILE) != EXCEPTION_SHA256:
        fail(f"{EXCEPTION_FILE.name} is missing or not the SPDX text")
    layer = sorted(packages[i]["name"] for i in linked if packages[i]["license"] == EXCEPTION)
    print(f"the layer programs link is {EXCEPTION}: {', '.join(layer)}")
    print(f"programs link {len(linked & members)} workspace crates, MIT or with the exception;"
          f" the other POSIX crates and the services are {GPL}")
    # 5: the GPL-2.0-only BusyBox links no bare GPLv3 code.
    busybox = named["busybox-probe"]["id"]
    for package_id in closure(data, [busybox]) - {busybox}:
        license_name = packages[package_id]["license"] or ""
        if license_name != EXCEPTION and not allowed(license_name):
            fail(f"BusyBox links {packages[package_id]['name']} under {license_name!r}")
    print("BusyBox links MIT, GPL-2.0-only compatible and exception crates alone")
    drivers(data, packages, named)


def drivers(data: dict, packages: dict, named: dict) -> None:
    """The kernel links no crate from outside the workspace; the Virtio
    console's driver links virtio-drivers (MIT) and crates under licences
    the GPL takes."""
    for package_id in closure(data, [named["kernel"]["id"]]):
        if packages[package_id]["source"] is not None:
            fail(f"the kernel links {packages[package_id]['name']}")
    outside = []
    for package_id in closure(data, [named["virtio-console"]["id"]]):
        package = packages[package_id]
        if package["source"] is None:
            continue
        if package["license"] not in PERMISSIVE:
            fail(f"virtio-console links {package['name']} under {package['license']}")
        outside.append(package["name"])
    if "virtio-drivers" not in outside:
        fail("virtio-console no longer links virtio-drivers")
    print("kernel links no outside crate; virtio-console links "
          + ", ".join(sorted(outside)) + " under permissive licences")


def licence_files(directory: Path) -> list[Path]:
    return sorted(path for path in directory.iterdir() if path.is_file() and re.match(
        r"(LICEN[CS]E|COPYING|UNLICENSE|NOTICE|COPYRIGHT)", path.name, re.I))


def relibc() -> None:
    """Item 6: relibc's closure on the target, the crates -Z build-std
    builds, openlibm's headers."""
    if not (RELIBC / "Cargo.lock").exists():
        fail(f"no relibc at {RELIBC}; run cargo xtask relibc first")
    data = metadata(RELIBC, "--offline", "--filter-platform", "aarch64-unknown-linux-gnu",
                    toolchain=TOOLCHAIN)
    packages = {package["id"]: package for package in data["packages"]}
    root = next(p["id"] for p in data["packages"] if p["name"] == "relibc")
    linked = closure(data, [root])
    notices = []
    for package_id in sorted(linked, key=lambda i: packages[i]["name"]):
        package = packages[package_id]
        name, license_name = package["name"], package["license"]
        directory = Path(package["manifest_path"]).parent
        files = licence_files(directory)
        if license_name is None:
            if name not in UNLABELLED:
                fail(f"relibc links {name}, which names no licence")
            path, license_name = UNLABELLED[name]
            if sha256(RELIBC / path) != UNLABELLED_SHA256[path]:
                fail(f"{path}, the licence of {name}, changed")
            files = [RELIBC / path]
        if not allowed(license_name):
            fail(f"relibc links {name} under {license_name!r}")
        notices.append((f"{name} {package['version']}", license_name, files))
    # The crates of the standard library relibc builds with -Z build-std.
    sysroot = subprocess.check_output(["rustup", "run", TOOLCHAIN, "rustc", "--print",
                                       "sysroot"], text=True).strip()
    library = Path(sysroot) / "lib/rustlib/src/rust/library"
    for manifest in ("core", "alloc", "compiler-builtins/compiler-builtins"):
        package = tomllib.loads((library / manifest / "Cargo.toml").read_text())["package"]
        license_name = package["license"]
        if not allowed(license_name):
            fail(f"relibc links {package['name']} under {license_name!r}")
        files = licence_files(library / manifest.split("/")[0])
        notices.append((f"{package['name']} ({TOOLCHAIN})", license_name, files))
    path, digest, license_name = OPENLIBM
    if sha256(RELIBC / path) != digest:
        fail(f"{path} changed: read it again")
    for header in [*(RELIBC / "openlibm/include").glob("*.h"),
                   *(RELIBC / "openlibm/src").glob("*.h")]:
        if "General Public License" in header.read_text(errors="replace"):
            fail(f"openlibm header {header.name} is under a GNU licence")
    notices.append(("openlibm (headers)", license_name, [RELIBC / path]))
    write_notices(notices)
    print(f"relibc links {len(linked)} crates and {len(notices) - len(linked)} more parts,"
          " all under licences GPL-2.0-only takes")


def write_notices(notices) -> None:
    """The licence files of each part; a text met before is named, not
    repeated. A part without files (core, alloc) points to its source."""
    parts = ["Third-party notices: relibc and what it links into stafeto programs.\n"]
    seen = {}
    for title, license_name, files in notices:
        parts.append(f"\n{'=' * 72}\n{title}: {license_name}\n{'=' * 72}\n")
        if not files:
            parts.append("\nThe licence texts are in https://github.com/rust-lang/rust"
                         " (LICENSE-MIT, LICENSE-APACHE).\n")
        for path in files:
            text = path.read_text(errors="replace").rstrip()
            digest = hashlib.sha256(text.encode()).hexdigest()
            if digest in seen:
                parts.append(f"\n--- {path.name}: the same text as for {seen[digest]}\n")
                continue
            seen[digest] = title
            parts.append(f"\n--- {path.name}\n\n{text}\n")
    NOTICES.write_text("".join(parts))


def main() -> None:
    workspace()
    relibc()


if __name__ == "__main__":
    main()
