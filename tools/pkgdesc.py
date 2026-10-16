# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The package descriptions of packages/ (docs/packages.md): the one place
that holds the version, source URL and SHA-256 of each third-party program.
The build scripts of tools/ read them here."""

from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def load(name: str) -> dict:
    """The description of the package `name`."""
    with (ROOT / "packages" / f"{name}.toml").open("rb") as file:
        description = tomllib.load(file)
    if description["name"] != name:
        raise SystemExit(f"packages/{name}.toml describes {description['name']}")
    return description
