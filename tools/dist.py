#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The release files of a version (`cargo xtask dist`, docs/release.md), in
two steps. `stage` runs where the code of the packages is built: the archive
of the kernel, the archive of the GPL sources and the notices of the base
image and of the full image. `pack` runs after the packages are signed: the
archives of the base image and of the full image with the signed boot images,
the SBOM, the copy of the signed index and SHA256SUMS. xtask builds the kernel
and the images and passes them here; the sources of the packages come from
packages/*.toml at their SHA-256."""

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


def archive_packages(licenses: Path) -> list[tuple[str, str, str]]:
    """The packages of the archive: name, version-release and SPDX licence,
    from `packages.txt` of the directory of notices."""
    rows = []
    for line in (licenses / "packages.txt").read_text().splitlines():
        name, version, license_name = line.split("\t")
        rows.append((name, version, license_name))
    return rows


def source_names(licenses: Path) -> list[str]:
    """The packages whose sources and records the archive owes: those it
    holds and the packages linked into them."""
    return sorted((licenses / "sources.txt").read_text().split())


def stage_licenses(stage: Path, version: str, licenses: Path) -> None:
    out = stage / "LICENSES"
    out.mkdir()
    for name in ("LICENSE", "LICENSE-MIT", "LICENSE-GCC-exception-3.1"):
        shutil.copy(ROOT / name, out / name)
    # The notices of relibc and of every crate from outside the workspace
    # that the kernel, the services and the programs link; the check fails
    # when the file misses one of them.
    subprocess.run([sys.executable, str(HERE / "check-licenses.py"), "--verify"], check=True)
    notices = ROOT / "target" / "relibc" / "THIRD-PARTY-NOTICES"
    shutil.copy(notices, out / "relibc-THIRD-PARTY-NOTICES")
    shutil.copytree(ROOT / "docs" / "licenses", out / "crates")
    index = [f"stafeto {version}: kernel, services, tools GPL-3.0-or-later; "
             "libraries that programs link MIT; POSIX system layer "
             "GPL-3.0-or-later WITH GCC-exception-3.1",
             f"relibc (pin {relibc_commit()[:8]}): see relibc-THIRD-PARTY-NOTICES",
             "crates from crates.io that the services and programs link"
             " (virtio-drivers, smoltcp and theirs): see relibc-THIRD-PARTY-NOTICES"]
    # The notices of each package the image holds, as the package carries
    # them in /usr/share/licenses/<name>/ (xtask extracted them).
    for name, package_version, license_name in archive_packages(licenses):
        index.append(f"{name} {package_version}: {license_name}")
        shutil.copytree(licenses / name, out / "packages" / name)
    (out / "INDEX.txt").write_text("\n".join(index) + "\n")


def sbom(version: str, commit: str, names: list[str], digests: dict[str, tuple[str, str]]) -> dict:
    """SPDX 2.3 of the release. `digests` maps a package to the file name and
    SHA-256 of its signed .stpkg, which is a second checksum of the package."""
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
    for name in names:
        d = pkgdesc.load(name)
        entry = {
            "SPDXID": f"SPDXRef-{name}", "name": name, "versionInfo": d["version"],
            "downloadLocation": d["url"],
            "checksums": [{"algorithm": "SHA256", "checksumValue": d["sha256"]}],
            "licenseDeclared": d["license"], "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION", "filesAnalyzed": False,
        }
        if name in digests:
            file_name, digest = digests[name]
            entry["checksums"].append({"algorithm": "SHA256", "checksumValue": digest})
            entry["comment"] = f"The first checksum is that of the source archive; the second is that of {file_name}."
        packages.append(entry)
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"stafeto-{version}",
        "documentNamespace": f"https://github.com/stafeto/stafeto/releases/sbom/{version}",
        "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: stafeto-dist"]},
        "packages": packages,
        "relationships": [{"spdxElementId": "SPDXRef-stafeto", "relationshipType": "CONTAINS",
                           "relatedSpdxElement": p["SPDXID"]} for p in packages[1:]],
    }


def stage_sources(stage: Path, version: str, cache: Path, names: list[str]) -> None:
    packages = stage / "packages"
    packages.mkdir(parents=True)
    gpl = []
    for name in names:
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


# What of the Linux guest of the measurement (tools/build-linux-guest.py) a
# release must not hold: the Alpine packages, the unpacked kernel and the
# initramfs. The guest is built on the owner's Mac for the measurement and is
# never shipped (its kernel and BusyBox are GPL-2.0-only, and shipping them
# would owe their sources). Our build script, the lock and the init are source
# files of the repository and ship with it.
GUEST_NAMES = re.compile(r"(^|/)(target/linux-guest(/|$)|initramfs\.cpio|vmlinuz)|\.apk$")


def refuse_linux_guest(out: Path, guest: Path) -> None:
    """Stops the release if a file of it is a file of the Linux guest: by the
    name of a member of an archive, or by the SHA-256 of its bytes against
    the Image and the initramfs of `guest` (target/linux-guest) if built."""
    secret = {}
    for name in ("Image", "initramfs.cpio.gz"):
        if (guest / name).is_file():
            secret[sha256_file(guest / name)] = name
    for path in sorted(out.iterdir()):
        if GUEST_NAMES.search(path.name):
            raise SystemExit(f"dist: {path.name} is a file of the Linux guest")
        if secret and path.is_file() and sha256_file(path) in secret:
            raise SystemExit(f"dist: {path.name} is the {secret[sha256_file(path)]} of the Linux guest")
        if not path.name.endswith((".tar.xz", ".tar")):
            continue
        with tarfile.open(path) as tar:
            for member in tar:
                if GUEST_NAMES.search(member.name):
                    raise SystemExit(f"dist: {path.name} holds {member.name}, a file of the Linux guest")
                if member.isfile() and secret:
                    digest = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
                    if digest in secret:
                        raise SystemExit(f"dist: {path.name} holds {member.name}, which is the {secret[digest]} of the Linux guest")


def fill(template: str, **values: str) -> str:
    """The template with each `@NAME@` replaced; a mark left over is an error."""
    for name, value in values.items():
        template = template.replace(f"@{name.upper()}@", value)
    left = re.search(r"@[A-Z]+@", template)
    if left:
        raise SystemExit(f"dist: the template keeps {left.group(0)}")
    return template


# The two archives that run: the file of the boot image, the memory run.sh
# starts with and what the README says of the image.
FLAVOURS = {
    "base": ("boot-base.img", "512M",
             "The base image: the shell, the network, the screen and the keyboard, and the base "
             "packages (BusyBox, GNU bash, the package tool, the libraries and the small utilities). "
             "Everything else installs with `pkg install <name>`."),
    "full": ("boot-full.img", "1024M",
             "The full image: every package of the series is in it already (Doom, nano, htop, ncdu, "
             "nginx and the rest), and it starts with 1024M, because its container of 54 MB leaves "
             "init too few free pages on 512M."),
}


def release_words(version: str) -> tuple[str, str]:
    """What the README says of the release: a version with a suffix is a
    pre-release, whose series may have no repository of packages yet."""
    series = ".".join(version.split(".")[:2])
    if "-" in version:
        return (f"A pre-release of stafeto {version}.",
                f"A pre-release: the interfaces and the image layout can change, and the repository of the "
                f"series {series} (https://stafeto.github.io/packages/{series}/aarch64) may not exist yet, "
                "so `pkg install` can say that it cannot reach it.")
    return (f"stafeto {version}.",
            f"Series {series}: the packages of the series run on every system of the series, and `pkg` "
            f"takes them from https://stafeto.github.io/packages/{series}/aarch64.")


def index_entries(index: Path) -> dict[str, tuple[str, str]]:
    """The entries of an INDEX text: package name to the last part of its
    `file` and its `sha256`."""
    found: dict[str, tuple[str, str]] = {}
    for block in index.read_text().split("\n\n")[1:]:
        fields = dict(line.partition(" ")[::2] for line in block.splitlines())
        if {"name", "file", "sha256"} <= fields.keys():
            found[fields["name"]] = (fields["file"].rsplit("/", 1)[-1], fields["sha256"])
    return found


def package_digests(index: Path, packages: Path) -> dict[str, tuple[str, str]]:
    """The file name and SHA-256 of each package file of `packages` that the
    index lists, checked against the index (they are the files it signs)."""
    out = {}
    for name, (file_name, expected) in index_entries(index).items():
        path = packages / file_name
        if not path.is_file():
            continue
        digest = sha256_file(path)
        if digest != expected:
            raise SystemExit(f"dist: {file_name} has SHA-256 {digest}, the index says {expected}")
        out[name] = (file_name, digest)
    return out


def stage(args: argparse.Namespace) -> None:
    out, version = args.out, args.version
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    work = out.parent / "dist-work"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    names: set[str] = set()
    for flavour, licenses in (("base", args.licenses_base), ("full", args.licenses_full)):
        directory = out / flavour
        directory.mkdir()
        stage_licenses(directory, version, licenses)
        shutil.copy(licenses / "packages.txt", directory / "packages.txt")
        names.update(source_names(licenses))
    (out / "sources.txt").write_text("\n".join(sorted(names)) + "\n")

    kernel = work / f"stafeto-{version}-kernel"
    kernel.mkdir()
    shutil.copy(args.image, kernel / "Image")
    shutil.copy(args.elf, kernel / "kernel.elf")
    write_tar_xz(out / f"{kernel.name}.tar.xz", kernel)

    sources = work / f"stafeto-{version}-gpl-sources"
    stage_sources(sources, version, args.cache, sorted(names))
    write_tar_xz(out / f"{sources.name}.tar.xz", sources)
    shutil.rmtree(work)


def pack(args: argparse.Namespace) -> None:
    version, out, staged = args.version, args.out, args.stage
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    work = out.parent / "dist-work"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    images = {"base": args.base_image, "full": args.full_image}
    release = release_words(version)
    for flavour, (image_name, memory, about) in FLAVOURS.items():
        run = work / f"stafeto-{version}-aarch64-virt-{flavour}"
        run.mkdir()
        shutil.copy(args.image, run / "Image")
        shutil.copy(images[flavour], run / image_name)
        script = fill((HERE / "dist" / "run.sh").read_text(), image=image_name, memory=memory)
        (run / "run.sh").write_text(script)
        (run / "run.sh").chmod(0o755)
        (run / "README.md").write_text(fill(
            (HERE / "dist" / "README.md").read_text(), version=version, flavour=flavour,
            image=image_name, memory=memory, about=about, release=release[0], limit=release[1]))
        shutil.copytree(staged / flavour / "LICENSES", run / "LICENSES")
        write_tar_xz(out / f"{run.name}.tar.xz", run)
    for name in (f"stafeto-{version}-kernel.tar.xz", f"stafeto-{version}-gpl-sources.tar.xz"):
        shutil.copy(staged / name, out / name)
    shutil.copy(args.index, out / f"stafeto-{version}-INDEX")
    shutil.copy(args.index_sig, out / f"stafeto-{version}-INDEX.sig")
    names = (staged / "sources.txt").read_text().split()
    digests = package_digests(args.index, args.packages)
    (out / f"stafeto-{version}-sbom.spdx.json").write_text(
        json.dumps(sbom(version, relibc_commit(), names, digests), indent=2) + "\n")
    refuse_linux_guest(out, ROOT / "target" / "linux-guest")
    lines = [f"{sha256_file(p)}  {p.name}" for p in sorted(out.iterdir())]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    shutil.rmtree(work)
    for p in sorted(out.iterdir()):
        print(f"{p.stat().st_size:>10}  {p}")


def main() -> None:
    parser = argparse.ArgumentParser()
    steps = parser.add_subparsers(dest="step", required=True)
    one = steps.add_parser("stage", help="the archives of the kernel and the sources, the notices")
    one.add_argument("--version", required=True)
    one.add_argument("--image", type=Path, required=True)
    one.add_argument("--elf", type=Path, required=True)
    one.add_argument("--licenses-base", type=Path, required=True,
                     help="the notices of the packages of the base image")
    one.add_argument("--licenses-full", type=Path, required=True,
                     help="the notices of the packages of the full image")
    one.add_argument("--cache", type=Path, default=ROOT / "target" / "dist-cache")
    one.add_argument("--out", type=Path, required=True)
    two = steps.add_parser("pack", help="the archives that run, the SBOM and SHA256SUMS")
    two.add_argument("--version", required=True)
    two.add_argument("--stage", type=Path, required=True)
    two.add_argument("--image", type=Path, required=True)
    two.add_argument("--base-image", type=Path, required=True)
    two.add_argument("--full-image", type=Path, required=True)
    two.add_argument("--packages", type=Path, required=True,
                     help="the signed package files the index lists")
    two.add_argument("--index", type=Path, required=True)
    two.add_argument("--index-sig", type=Path, required=True)
    two.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    {"stage": stage, "pack": pack}[args.step](args)


if __name__ == "__main__":
    main()
