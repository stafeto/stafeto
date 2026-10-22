#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The release files of a version (`cargo xtask dist`, docs/release.md):
the archive to run in QEMU, the kernel with its symbols, the sources of the
GPL packages with our build scripts, the SBOM and SHA256SUMS, in the output
directory. xtask builds the kernel and the boot image and passes them here;
the sources of the packages come from packages/*.toml at their SHA-256."""

import argparse
import gzip
import hashlib
import json
import lzma
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pkgdesc  # noqa: E402

ROOT = pkgdesc.ROOT
HERE = Path(__file__).resolve().parent
RELIBC_REPOSITORY = "https://github.com/stafeto/relibc"
# What a source tree names its licence text.
LICENSE_NAMES = re.compile(r"^(COPYING|COPYING\.[A-Za-z0-9]+|LICENSE|LICENSE\.[a-z]+|LICENCE|UNLICENSE|COPYRIGHT)$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def matches(path: Path, expected: str) -> bool:
    """Whether the archive has the SHA-256 of its description. The archives
    that GitHub generates change their gzip bytes from time to time, and
    their descriptions pin the tar inside (tools/build-ready-utils.py)."""
    if sha256_file(path) == expected:
        return True
    name = path.name.removesuffix(".part")
    opener = gzip.open if name.endswith((".gz", ".tgz")) else lzma.open if name.endswith(".xz") else None
    if opener is not None:
        with opener(path) as file:
            digest = hashlib.sha256()
            for block in iter(lambda: file.read(1 << 20), b""):
                digest.update(block)
        return digest.hexdigest() == expected
    return False


def package_names() -> list[str]:
    return sorted(path.stem for path in (ROOT / "packages").glob("*.toml"))


def is_gpl(expression: str) -> bool:
    """Whether the licence expression names a GPL family licence."""
    return re.search(r"GPL", expression) is not None


def relibc_commit() -> str:
    text = (ROOT / "tools" / "build-relibc.py").read_text()
    return re.search(r'^COMMIT = "([0-9a-f]{40})"', text, re.M).group(1)


def fetch(description: dict, cache: Path) -> Path:
    """The source archive of a package in `cache`, checked against its SHA-256."""
    url = description["url"]
    path = cache / cache_name(description)
    if path.exists() and matches(path, description["sha256"]):
        return path
    cache.mkdir(parents=True, exist_ok=True)
    part = path.with_suffix(path.suffix + ".part")
    with urllib.request.urlopen(url) as reply, part.open("wb") as file:
        shutil.copyfileobj(reply, file)
    if not matches(part, description["sha256"]):
        got = sha256_file(part)
        part.unlink()
        raise SystemExit(f"dist: {url} has SHA-256 {got}, packages/{description['name']}.toml says {description['sha256']}")
    part.rename(path)
    return path


def license_texts(archive: Path, wanted: str = "") -> dict[str, bytes]:
    """The licence files in the top two directories of a source archive, and
    the file `wanted` (a path below the top directory) the description names."""
    found = {}
    with tarfile.open(archive) as tar:
        for member in tar:
            parts = member.name.split("/")
            if member.isfile() and (
                    len(parts) <= 2 and LICENSE_NAMES.match(parts[-1])
                    or wanted and "/".join(parts[1:]) == wanted):
                found[parts[-1]] = tar.extractfile(member).read()
    return found


def git_archive(directory: Path, prefix: str, destination: Path, revision: str = "HEAD") -> None:
    with destination.open("wb") as file:
        subprocess.run(["git", "archive", "--format=tar", f"--prefix={prefix}/", revision],
                       cwd=directory, stdout=file, check=True)


def write_tar_xz(destination: Path, directory: Path) -> None:
    """`directory` as <name>/... in a tar.xz, with fixed owners and times."""
    def normal(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0
        return info
    with tarfile.open(destination, "w:xz", preset=6) as tar:
        for path in sorted(directory.rglob("*")):
            tar.add(path, arcname=str(Path(directory.name) / path.relative_to(directory)),
                    recursive=False, filter=normal)


def stage_licenses(stage: Path, version: str, cache: Path) -> None:
    out = stage / "LICENSES"
    out.mkdir()
    for name in ("LICENSE", "LICENSE-MIT", "LICENSE-GCC-exception-3.1"):
        shutil.copy(ROOT / name, out / name)
    notices = ROOT / "target" / "relibc" / "THIRD-PARTY-NOTICES"
    if notices.exists():
        shutil.copy(notices, out / "relibc-THIRD-PARTY-NOTICES")
    shutil.copytree(ROOT / "docs" / "licenses", out / "crates")
    index = [f"stafeto {version}: kernel, services, tools GPL-3.0-or-later; "
             "libraries that programs link MIT; POSIX system layer "
             "GPL-3.0-or-later WITH GCC-exception-3.1",
             f"relibc (pin {relibc_commit()[:8]}): see relibc-THIRD-PARTY-NOTICES"]
    for name in package_names():
        description = pkgdesc.load(name)
        index.append(f"{name} {description['version']}: {description['license']}")
        wanted = description.get("license_file", "")
        texts = license_texts(fetch(description, cache), wanted)
        if wanted:
            texts = {k: v for k, v in texts.items() if k == Path(wanted).name} or texts
        target = out / "packages" / name
        target.mkdir(parents=True)
        for file_name, data in texts.items():
            (target / file_name).write_bytes(data)
        # A description with an empty `license_file` (paxmirabilis) names a
        # source whose files state the terms in their headers; the image
        # carries them in UTILITIES-LICENSE.
        if not texts and description.get("license_file") != "":
            raise SystemExit(f"dist: no licence text found in the source of {name}")
    (out / "INDEX.txt").write_text("\n".join(index) + "\n")


def sbom(version: str, commit: str, cache: Path) -> dict:
    packages = [{
        "SPDXID": "SPDXRef-stafeto", "name": "stafeto", "versionInfo": version,
        "downloadLocation": "https://github.com/stafeto/stafeto",
        "licenseDeclared": "GPL-3.0-or-later", "licenseConcluded": "NOASSERTION",
        "copyrightText": "Copyright (C) 2026 Sergey Subbotin", "filesAnalyzed": False,
    }, {
        "SPDXID": "SPDXRef-relibc", "name": "relibc", "versionInfo": f"pin-{commit[:8]}",
        "downloadLocation": f"git+{RELIBC_REPOSITORY}.git@{commit}",
        "licenseDeclared": "MIT", "licenseConcluded": "NOASSERTION",
        "copyrightText": "NOASSERTION", "filesAnalyzed": False,
    }]
    for name in package_names():
        d = pkgdesc.load(name)
        packages.append({
            "SPDXID": f"SPDXRef-{name}", "name": name, "versionInfo": d["version"],
            "downloadLocation": d["url"],
            "checksums": [{"algorithm": "SHA256", "checksumValue": d["sha256"]}],
            "licenseDeclared": d["license"], "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION", "filesAnalyzed": False,
        })
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"stafeto-{version}",
        "documentNamespace": f"https://github.com/stafeto/stafeto/releases/sbom/{version}",
        "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: stafeto-dist"]},
        "packages": packages,
        "relationships": [{"spdxElementId": "SPDXRef-stafeto", "relationshipType": "CONTAINS",
                           "relatedSpdxElement": p["SPDXID"]} for p in packages[1:]],
    }


def stage_sources(stage: Path, version: str, cache: Path) -> None:
    packages = stage / "packages"
    packages.mkdir(parents=True)
    gpl = []
    for name in package_names():
        d = pkgdesc.load(name)
        if is_gpl(d["license"]):
            shutil.copy(fetch(d, cache), packages / cache_name(d))
            gpl.append(f"{name} {d['version']} {d['license']} {d['url']} sha256:{d['sha256']}")
    commit = relibc_commit()
    relibc = ROOT / "target" / "relibc" / "source"
    if not (relibc / ".git").exists():
        raise SystemExit("dist: target/relibc/source is missing; run `cargo xtask relibc`")
    git_archive(relibc, f"relibc-pin-{commit[:8]}", stage / f"relibc-pin-{commit[:8]}.tar", commit)
    git_archive(ROOT, f"stafeto-{version}", stage / f"stafeto-{version}.tar")
    (stage / "README").write_text(
        f"Corresponding source of stafeto {version}.\n\n"
        f"stafeto-{version}.tar   the stafeto tree of the release commit: the kernel, services,\n"
        "                        tools/build-*.py, the patches and compat headers under tools/,\n"
        "                        packages/*.toml (the pinned versions and SHA-256 sums)\n"
        f"relibc-pin-{commit[:8]}.tar  the relibc fork at the commit {commit} (the tag pin-{commit[:8]}),\n"
        "                        with its stafeto platform\n"
        "packages/               the original source archives of the GPL packages, as the SHA-256\n"
        "                        sums of packages/*.toml pin them:\n\n"
        + "\n".join(f"  {line}" for line in gpl) + "\n\n"
        "Build: unpack stafeto-<version>.tar and run `cargo xtask dist`; the build scripts\n"
        "fetch the archives above by their URLs and check the same SHA-256 sums.\n")


def cache_name(description: dict) -> str:
    """The file name of a source archive: its own when it names the package,
    else prefixed with the package and version (GitHub's `v5.0.tar.gz`)."""
    base = description["url"].rsplit("/", 1)[-1]
    if base.startswith(description["name"]):
        return base
    return f"{description['name']}-{description['version']}-{base}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--boot", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    version, out = args.version, args.out
    cache = out.parent / "dist-cache"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    work = out.parent / "dist-work"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()

    run = work / f"stafeto-{version}-aarch64-virt"
    run.mkdir()
    shutil.copy(args.image, run / "Image")
    shutil.copy(args.boot, run / "boot.img")
    shutil.copy(HERE / "dist" / "run.sh", run / "run.sh")
    (run / "run.sh").chmod(0o755)
    (run / "README.md").write_text((HERE / "dist" / "README.md").read_text().replace("@VERSION@", version))
    stage_licenses(run, version, cache)
    write_tar_xz(out / f"{run.name}.tar.xz", run)

    kernel = work / f"stafeto-{version}-kernel"
    kernel.mkdir()
    shutil.copy(args.image, kernel / "Image")
    shutil.copy(args.elf, kernel / "kernel.elf")
    write_tar_xz(out / f"{kernel.name}.tar.xz", kernel)

    sources = work / f"stafeto-{version}-gpl-sources"
    stage_sources(sources, version, cache)
    write_tar_xz(out / f"{sources.name}.tar.xz", sources)

    (out / f"stafeto-{version}-sbom.spdx.json").write_text(
        json.dumps(sbom(version, relibc_commit(), cache), indent=2) + "\n")
    lines = [f"{sha256_file(p)}  {p.name}" for p in sorted(out.iterdir())]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    shutil.rmtree(work)
    for p in sorted(out.iterdir()):
        print(f"{p.stat().st_size:>10}  {p}")


if __name__ == "__main__":
    main()
