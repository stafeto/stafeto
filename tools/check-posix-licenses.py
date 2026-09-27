#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Keep the GPLv3 Rust POSIX code outside the GPLv2-only BusyBox binary."""

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
            for target in package["targets"]:
                source = Path(target["src_path"])
                if source.read_text().splitlines()[0] != (
                    "// SPDX-License-Identifier: GPL-3.0-or-later"
                ):
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


if __name__ == "__main__":
    main()
