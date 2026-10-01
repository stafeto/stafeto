#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Keep the GPLv3 Rust POSIX code outside the GPLv2-only BusyBox binary,
and the crates of the drivers under licences the GPL takes."""

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked",
         "--filter-platform", "aarch64-unknown-none"], cwd=ROOT))
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    named = {package["name"]: package for package in metadata["packages"]}
    for package_id in metadata["workspace_members"]:
        package = packages[package_id]
        if package["name"].startswith("posix-") and package["name"] != "posix-bridge":
            if package["license"] != "GPL-3.0-or-later":
                raise SystemExit(f"{package['name']} must be GPL-3.0-or-later")
            package_root = Path(package["manifest_path"]).parent
            sources = set(package_root.rglob("*.rs"))
            sources.update(package_root.rglob("*.h"))
            for source in sorted(sources):
                lines = source.read_text().splitlines()
                expected = ("/* SPDX-License-Identifier: GPL-3.0-or-later */"
                            if source.suffix == ".h" else
                            "// SPDX-License-Identifier: GPL-3.0-or-later")
                if not lines or lines[0] != expected:
                    raise SystemExit(f"{source} needs its GPL-3.0-or-later SPDX header")
    if named["posix-bridge"]["license"] != "MIT":
        raise SystemExit("the temporary BusyBox POSIX bridge must remain MIT")
    pending = [named["busybox-probe"]["id"]]
    seen = set()
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        if package_id != named["busybox-probe"]["id"]:
            license_name = packages[package_id]["license"] or ""
            if "GPL-3.0" in license_name:
                raise SystemExit(
                    f"BusyBox links GPLv3 dependency {packages[package_id]['name']}")
        pending.extend(nodes[package_id]["dependencies"])
    print("Rust POSIX GPL-3.0-or-later; BusyBox dependency graph remains GPLv3-free")
    check_drivers(packages, nodes, named)


# Licences a GPL-3.0-or-later program may link from crates.io.
PERMISSIVE = {"MIT", "Apache-2.0", "MIT OR Apache-2.0", "Apache-2.0 OR MIT",
              "Zlib OR Apache-2.0 OR MIT", "BSD-2-Clause OR Apache-2.0 OR MIT"}


def closure(nodes, root, packages=None):
    """The packages `root` links: with `packages`, procedural macros and
    what they take run in the compiler and are left out."""
    pending, seen = [root], set()
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        if packages is not None and any(
                "proc-macro" in t["kind"] for t in packages[package_id]["targets"]):
            continue
        seen.add(package_id)
        pending.extend(nodes[package_id]["dependencies"])
    return seen


def check_drivers(packages, nodes, named) -> None:
    """The kernel links no crate from outside the workspace; the Virtio
    console's driver links virtio-drivers (MIT) and crates under licences
    the GPL takes."""
    for package_id in closure(nodes, named["kernel"]["id"]):
        if packages[package_id]["source"] is not None:
            raise SystemExit(f"the kernel links {packages[package_id]['name']}")
    outside = []
    for package_id in closure(nodes, named["virtio-console"]["id"], packages):
        package = packages[package_id]
        if package["source"] is None:
            continue
        if package["license"] not in PERMISSIVE:
            raise SystemExit(
                f"virtio-console links {package['name']} under {package['license']}")
        outside.append(package["name"])
    if "virtio-drivers" not in outside:
        raise SystemExit("virtio-console no longer links virtio-drivers")
    print("kernel links no outside crate; virtio-console links "
          + ", ".join(sorted(outside)) + " under permissive licences")


if __name__ == "__main__":
    main()
