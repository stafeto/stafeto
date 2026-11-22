#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build Mesa's EGL and OpenGL ES 2.0/3.x over its softpipe driver for
programs written in C (`cargo xtask mesa`): one static archive for
aarch64-linux-gnu against the sysroot of relibc (target/relibc/sysroot,
`cargo xtask relibc`) and the C++ runtime of tools/build-libcxx.py
(target/libcxx), from the pinned source archive of the release.

The archive is the source of packages/mesa.toml (Mesa 26.3.1); libdrm, which
Mesa's EGL includes unconditionally, is the release the wrap of Mesa names
(subprojects/libdrm.wrap, 2.4.133). Both are fetched into target/mesa-src/ with
their SHA-256 checked, libdrm is handed to meson through its package cache, and
meson is told never to download anything itself. The Mesa tree is unpacked to
target/mesa/src, the patches of ports/mesa/patches are applied in order, and
meson and ninja build it.
meson, ninja, flex and bison come from the host (Homebrew), and the Python
that runs Mesa's generators needs Mako, MarkupSafe and PyYAML: the Python of
the host when it has them, otherwise a venv in target/mesa/venv with the
pinned versions below.

What the build is (the decisions that belong to stafeto, plan G8 section 4):

  - the cross file says `system = 'linux'`: the programs are built for
    aarch64-linux-gnu and relibc's headers test `__linux__`, and meson's own
    list of systems that have KMS and DRM, which Mesa's EGL requires, knows
    no other name. `-D__stafeto__=1` is what tells Mesa the system: the patch
    of src/util/detect_os.h makes it a POSIX system that is no Linux, and the
    others replace the direct tests of `__linux__` of the files the build
    compiles by DETECT_OS_LINUX;
  - Mesa takes its C11 threads from relibc (`with_c11_threads`), and its
    futex path is off because the sysroot has no <linux/futex.h>;
  - the drivers: softpipe only, no LLVM, no desktop OpenGL (`opengl=false`:
    with it on, libGL and libGLESv2 hold the same names and the link of a
    program fails with duplicates), no GLX, no GBM, no platforms (the platform
    of EGL is surfaceless, the one without a window; the program asks for the
    software path with LIBGL_ALWAYS_SOFTWARE=1);
  - C++ in Mesa (the GLSL compiler) is built without exceptions and run-time
    type information, so the runtime it needs is the libc++ of the program;
  - the targets of meson are static libraries and are merged into one
    archive, `lib/libmesa.a`; the headers of Khronos are copied from the
    tree into `include/`, unchanged.

meson probes the C library by linking small programs; the sysroot's libc.a
needs the layer under it, so those probes link a stub archive generated here
from the names of libc.a and libm.a (what the probes find is what relibc
exports).

The result is target/mesa/: include/ (EGL, GLES2, GLES3, KHR), lib/libmesa.a,
NOTICES (the licence texts of the files the library holds and the headers of
Khronos) and LICENSE (the licence text of the package). `--check` prints the
stamp the build would write and exits; `--cross-file PATH` writes the cross
file of meson and exits."""

from hashlib import sha256
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
from urllib.request import urlopen

import pkgdesc


PACKAGE = pkgdesc.load("mesa")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
LIBDRM_VERSION = "2.4.133"
LIBDRM_SHA256 = "fc68f9d0ba2ea63c9432a299e14fea09fad7a8a66e8039fcd7802ca59f77b4f5"
LIBDRM_URL = f"https://dri.freedesktop.org/libdrm/libdrm-{LIBDRM_VERSION}.tar.xz"
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "mesa"
CACHE = ROOT / "target" / "mesa-src"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
LIBCXX = ROOT / "target" / "libcxx"
PORT = ROOT / "ports" / "mesa"
# Python packages the generators of Mesa import, with the versions the build
# was made with.
PYTHON_PACKAGES = ["Mako==1.4.3", "MarkupSafe==3.0.4", "PyYAML==6.0.4", "packaging==26.3"]
MESON_MINIMUM = (1, 5, 0)
MESON_VERSION = "1.12.1"
# The options of the build, in the form meson takes them (meson.options of
# Mesa 26.3.1).
OPTIONS = {
    "buildtype": "release",
    "b_ndebug": "true",
    "b_lto": "false",
    "default_library": "static",
    "b_staticpic": "false",
    "wrap_mode": "nodownload",
    "cpp_eh": "none",
    "cpp_rtti": "false",
    "c_std": "gnu11",
    "gallium-drivers": "softpipe",
    "vulkan-drivers": "",
    "platforms": "",
    "egl-native-platform": "surfaceless",
    "egl": "enabled",
    "gles1": "disabled",
    "gles2": "enabled",
    "opengl": "false",
    "glx": "disabled",
    "gbm": "disabled",
    "glvnd": "disabled",
    "llvm": "disabled",
    "shader-cache": "disabled",
    "expat": "disabled",
    "zlib": "disabled",
    "zstd": "disabled",
    "xmlconfig": "disabled",
    "valgrind": "disabled",
    "libunwind": "disabled",
    "lmsensors": "disabled",
    "gallium-va": "disabled",
    "gallium-rusticl": "false",
    "video-codecs": "",
    "tools": "",
    "build-tests": "false",
    "allow-fallback-for": "libdrm",
}
# The options the archive depends on (check_options).
REQUIRED = {
    "opengl": "false",
    "gles2": "enabled",
    "egl": "enabled",
    "gallium-drivers": "softpipe",
    "llvm": "disabled",
    "shader-cache": "disabled",
    "glvnd": "disabled",
    "platforms": "",
    "egl-native-platform": "surfaceless",
    "default_library": "static",
    "cpp_eh": "none",
    "cpp_rtti": "false",
}
# What the options of libdrm leave on: nothing but its core.
LIBDRM_OPTIONS = {"auto_features": "disabled", "tests": "false", "install-test-programs": "false"}
# Cortex-A53 erratum 835769 (the PinePhone's A64), as the other objects; no
# outlined atomics (libgcc's helpers are not in the sysroot).
TARGET_FLAGS = ["-mfix-cortex-a53-835769", "-mno-outline-atomics", "-fno-pic",
                "-fasynchronous-unwind-tables"]
# The static libraries of the build tree that make the archive: what meson
# links into libgallium (the driver, the state tracker, the GLSL compiler,
# NIR, the winsys, the utilities), the two libraries of the API (libEGL.a,
# libGLESv2.a) and libdrm's core. libdri.a is not listed: libgallium holds its
# objects (link_whole), and the same objects twice would define every name
# twice. A library missing from this list shows as a name left undefined at
# the end of the build.
ARCHIVES = [
    "src/egl/libEGL.a",
    "src/mesa/glapi/es2api/libGLESv2.a",
    "src/gallium/targets/dri/libgallium-26.3.1.a",
    "src/c11/impl/libmesa_util_c11.a",
    "src/compiler/glsl/glcpp/libglcpp.a",
    "src/compiler/glsl/libglsl.a",
    "src/compiler/libcompiler.a",
    "src/compiler/nir/libnir.a",
    "src/compiler/spirv/libvtn.a",
    "src/gallium/auxiliary/libgallium.a",
    "src/gallium/auxiliary/libgalliumvl.a",
    "src/gallium/auxiliary/pipe-loader/libpipe_loader_static.a",
    "src/gallium/drivers/softpipe/libsoftpipe.a",
    "src/gallium/winsys/sw/dri/libswdri.a",
    "src/gallium/winsys/sw/kms-dri/libswkmsdri.a",
    "src/gallium/winsys/sw/null/libws_null.a",
    "src/gallium/winsys/sw/wrapper/libwsw.a",
    "src/loader/libloader.a",
    "src/mesa/glapi/shared-glapi/libglapi.a",
    "src/mesa/libmesa.a",
    "src/util/blake3/libblake3.a",
    "src/util/libmesa_util.a",
    "src/util/libmesa_util_simd.a",
    "src/util/libxmlconfig.a",
    f"subprojects/libdrm-{LIBDRM_VERSION}/libdrm.a",
]
# What of the tree is copied to `include/`.
HEADER_DIRS = ["EGL", "GLES2", "GLES3", "KHR"]
# The licence texts of Mesa's tree that the library holds (licenses/): the
# other files of the tree (GPL, SGI Free B) belong to code the build leaves out.
LICENCE_TEXTS = ["MIT", "Apache-2.0", "BSL-1.0"]
# Files of the library whose terms are not the MIT text of the rest, with the
# licence of each; the build copies the licence heading of each into NOTICES.
NOTICE_FILES = [
    ("Berkeley SoftFloat, BSD-3-Clause", "src/util/softfloat.c"),
    ("xxHash, BSD-2-Clause", "src/util/xxhash.h"),
    ("loader helper of Keith Packard and others, HPND-sell-variant", "src/loader/loader_dri_helper.c"),
    ("BLAKE3, CC0-1.0 OR Apache-2.0 (taken as Apache-2.0)", "src/util/blake3/README"),
    ("C11 threads header, BSL-1.0", "src/c11/threads.h"),
    ("SPIR-V header of Khronos, MIT", "src/compiler/spirv/spirv.h"),
    ("EGL header of Khronos, Apache-2.0", "include/EGL/egl.h"),
    ("EGL platform header of Khronos, Apache-2.0", "include/EGL/eglplatform.h"),
    ("EGL extensions header of Khronos, Apache-2.0", "include/EGL/eglext.h"),
    ("EGL extensions of Mesa, MIT", "include/EGL/eglmesaext.h"),
    ("OpenGL ES 2.0 header of Khronos, MIT", "include/GLES2/gl2.h"),
    ("OpenGL ES 2.0 platform header of Khronos, Apache-2.0", "include/GLES2/gl2platform.h"),
    ("OpenGL ES 3.0 platform header of Khronos, Apache-2.0", "include/GLES3/gl3platform.h"),
    ("Khronos platform header, MIT", "include/KHR/khrplatform.h"),
    ("libdrm, MIT", "libdrm/xf86drm.c"),
]
# Names the library may leave undefined besides the C library's and the C++
# runtime's: none.
UNDEFINED_OK: set[str] = set()


def tool(name: str, brew_formula: str | None = None) -> Path:
    override = os.environ.get("STAFETO_C_TOOL_DIR")
    if override and (Path(override) / name).exists():
        return Path(override) / name
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install it (Homebrew: {brew_formula or name})")
    return Path(found).absolute()


def run(log: Path, *args, cwd: Path | None = None, env: dict | None = None) -> None:
    with log.open("a") as out:
        out.write("$ " + " ".join(map(str, args)) + "\n")
        out.flush()
        result = subprocess.run([str(a) for a in args], cwd=cwd, env=env, stdout=out,
                                stderr=subprocess.STDOUT)
    if result.returncode:
        print("\n".join(log.read_text(errors="replace").splitlines()[-80:]))
        raise SystemExit(f"command failed: {' '.join(map(str, args))}")


def version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text)[:3])


def meson_options(options: dict = OPTIONS, libdrm: dict = LIBDRM_OPTIONS) -> list[str]:
    """The `-D` arguments of `meson setup`."""
    args = [f"-D{key}={value}" for key, value in options.items()]
    args += [f"-Dlibdrm:{key}={value}" for key, value in libdrm.items()]
    return args


def quote(items: list[str]) -> str:
    return "[" + ", ".join("'" + item.replace("'", "\\'") + "'" for item in items) + "]"


def cross_file(clang: Path, clangxx: Path, ar: Path, nm: Path, strip: Path, ranlib: Path,
               stub: Path, sysroot: Path = RELIBC, libcxx: Path = LIBCXX, port: Path = PORT) -> str:
    """The cross file of meson. The compilers target aarch64-linux-gnu with
    the headers of relibc and, for C++, of libc++; `__stafeto__` is defined
    for both (detect_os.h of Mesa); alloca.h is included in every C file
    because relibc declares `alloca` only there; the link arguments hold the
    stub archive of the C library's names."""
    target = ["--target=aarch64-linux-gnu", *TARGET_FLAGS]
    common = ["-D__stafeto__=1", "-include", "alloca.h", f"-I{port / 'include'}", "-nostdlibinc",
              "-isystem", str(sysroot / "include")]
    cpp = ["-D__stafeto__=1", "-include", "alloca.h", f"-I{port / 'include'}", "-nostdlibinc",
           "-nostdinc++", "-isystem", str(libcxx / "include" / "c++" / "v1"),
           "-isystem", str(sysroot / "include")]
    link = ["-fuse-ld=lld", "-static", "-nostdlib", "-nostartfiles", str(stub),
            "-Wl,--entry=main", "-Wl,--no-gc-sections"]
    return f"""[binaries]
c = {quote([str(clang), *target])}
cpp = {quote([str(clangxx), *target])}
ar = '{ar}'
nm = '{nm}'
strip = '{strip}'
ranlib = '{ranlib}'
pkg-config = 'false'

[built-in options]
c_args = {quote(common)}
cpp_args = {quote(cpp)}
c_link_args = {quote(link)}
cpp_link_args = {quote(link)}

[host_machine]
system = 'linux'
cpu_family = 'aarch64'
cpu = 'cortex-a53'
endian = 'little'

[properties]
needs_exe_wrapper = true
"""


def stub_source(names: set[str]) -> str:
    """Assembly for a stub that defines every name once, as a function: the
    link probes of meson then find what the C library exports."""
    lines = [".text"]
    for name in sorted(names):
        lines += [f".globl {name}", f".type {name},%function", f"{name}:", "    ret"]
    return "\n".join(lines) + "\n"


def archive_names(nm: Path, library: Path) -> set[str]:
    out = subprocess.run([str(nm), "--defined-only", "--extern-only", "--format=just-symbols",
                          str(library)], capture_output=True, text=True, check=True).stdout
    return {line for line in out.splitlines() if line and not line.endswith(":")}


def parse_nm(listing: str) -> tuple[set[str], set[str]]:
    """The names defined and the names left undefined in the output of
    `llvm-nm --format=posix` (one line per symbol: name, type, ...); a weak
    undefined name is no requirement and is left out."""
    defined: set[str] = set()
    undefined: set[str] = set()
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) < 2 or line.endswith(":"):
            continue
        if fields[1] in ("w", "v"):
            continue
        (undefined if fields[1] == "U" else defined).add(fields[0])
    return defined, undefined


def strong_duplicates(listing: str) -> dict[str, list[str]]:
    """The names that more than one member of the archive defines with a
    strong symbol, from `llvm-nm --format=posix -A --defined-only
    --extern-only` (one line per symbol: `archive[member]: name type ...`).
    The weak symbols of inline functions and templates are allowed in many
    members; two strong ones make a program's link fail."""
    members: dict[str, list[str]] = {}
    for line in listing.splitlines():
        match = re.match(r"^.*\[(.*)\]: (\S+) (\w) ", line)
        if match is None or match[3] in "WVwvUu":
            continue
        members.setdefault(match[2], []).append(match[1])
    return {name: found for name, found in members.items() if len(found) > 1}


def check_options(options: dict = OPTIONS) -> None:
    """The settings the archive depends on: with desktop OpenGL on, the tree
    also builds libglapi_bridge.a (the entry points of libGL), which defines
    the 358 names libGLESv2.a defines; a shader cache and a driver table
    make Mesa open files and modules this system has none for."""
    for key, value in REQUIRED.items():
        if options.get(key) != value:
            raise SystemExit(f"the option {key} must be {value!r}, it is {options.get(key)!r}")


def strays(undefined: set[str], known: set[str]) -> list[str]:
    """The undefined names that neither the C library, the C++ runtime nor
    UNDEFINED_OK account for."""
    return sorted(undefined - known - UNDEFINED_OK)


def stamp_text(script: bytes, port: bytes, relibc_stamp: str, libcxx_stamp: str) -> str:
    return (f"{VERSION} {SHA256} {LIBDRM_VERSION} {LIBDRM_SHA256} {sha256(script).hexdigest()} "
            f"{sha256(port).hexdigest()} {relibc_stamp} {libcxx_stamp}\n")


def port_bytes(port: Path = PORT) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(port.rglob("*")) if p.is_file())


def stamp_of(path: Path, what: str, hint: str) -> str:
    if not path.exists():
        raise SystemExit(f"build {what} first: {hint}")
    return sha256(path.read_bytes()).hexdigest()


def fetch(url: str, digest: str, name: str) -> Path:
    """The archive in the cache, with its SHA-256 checked."""
    CACHE.mkdir(parents=True, exist_ok=True)
    archive = CACHE / name
    if not archive.exists() or sha256(archive.read_bytes()).hexdigest() != digest:
        part = archive.with_suffix(archive.suffix + ".part")
        with urlopen(url) as response, part.open("wb") as out:
            shutil.copyfileobj(response, out)
        if sha256(part.read_bytes()).hexdigest() != digest:
            part.unlink()
            raise SystemExit(f"{name} has an unexpected SHA-256")
        part.replace(archive)
    return archive


def unpack(archive: Path, destination: Path) -> Path:
    """The archive under `destination`; returns its top directory."""
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:xz") as members:
        top = members.getnames()[0].split("/", 1)[0]
        members.extractall(destination, filter="data")
    return destination / top


def patches(port: Path = PORT) -> list[Path]:
    """The patch files, in the order they are applied (their names start
    with a number)."""
    return sorted((port / "patches").glob("*.patch"))


def apply_patches(source: Path, log: Path, port: Path = PORT) -> None:
    for patch in patches(port):
        run(log, "patch", "-p1", "-N", "--no-backup-if-mismatch", "-s", "-i", patch, cwd=source)


def ensure_venv(packages: list[str], log: Path) -> Path:
    """The bin directory of the venv in target/mesa/venv with exactly these
    packages (made again when the list differs from the one it was made for)."""
    venv = WORK / "venv"
    record = venv / "packages.txt"
    wanted = "\n".join(packages) + "\n"
    if not record.exists() or record.read_text() != wanted:
        shutil.rmtree(venv, ignore_errors=True)
        run(log, sys.executable, "-m", "venv", venv)
        run(log, venv / "bin" / "python3", "-m", "pip", "install", "--quiet",
            "--only-binary", ":all:", *packages)
        record.write_text(wanted)
    return venv / "bin"


def host_tools(log: Path) -> tuple[Path, list[Path]]:
    """The meson to run and the directories for the front of the PATH. The
    host's meson serves when it is new enough, and the host's Python when it
    imports what the generators need; otherwise a venv holds the pinned
    versions (meson.build wants meson 1.5, and Ubuntu 24.04 has 1.3)."""
    found = shutil.which("meson")
    meson_ok = False
    if found:
        text = subprocess.run([found, "--version"], capture_output=True, text=True).stdout
        meson_ok = version_tuple(text) >= MESON_MINIMUM
    python = shutil.which("python3")
    python_ok = bool(python) and subprocess.run(
        [python, "-c", "import mako, yaml, markupsafe, packaging"],
        capture_output=True).returncode == 0
    if meson_ok and python_ok:
        return Path(found), [Path(python).parent]
    packages = PYTHON_PACKAGES + ([] if meson_ok else [f"meson=={MESON_VERSION}"])
    venv = ensure_venv(packages, log)
    return (Path(found) if meson_ok else venv / "meson"), [venv]


def mri_script(output: Path, libraries: list[Path]) -> str:
    """The script `llvm-ar -M` reads to make one archive of several: the
    members of each, under their own names."""
    lines = [f"CREATE {output}"] + [f"ADDLIB {library}" for library in libraries]
    return "\n".join(lines + ["SAVE", "END"]) + "\n"


def merge_archives(ar: Path, build: Path, output: Path, log: Path) -> None:
    """One archive of the static libraries of ARCHIVES."""
    libraries = [build / name for name in ARCHIVES]
    missing = [str(p) for p in libraries if not p.exists()]
    if missing:
        raise SystemExit("the build made no " + ", ".join(missing))
    output.unlink(missing_ok=True)
    with log.open("a") as out:
        result = subprocess.run([str(ar), "-M"], input=mri_script(output, libraries),
                                text=True, stdout=out, stderr=subprocess.STDOUT)
    if result.returncode:
        raise SystemExit("llvm-ar could not merge the libraries of Mesa")


def leading_comment(text: str) -> str:
    """The first comment block of a file (`/* ... */`, or the run of `//`
    lines), where its licence is; the include guards a header may open with
    are skipped. A file with no comment in its first 1500 characters is
    returned whole (a README)."""
    start = text.find("/*", 0, 1500)
    if start >= 0:
        return text[start: text.index("*/", start) + 2]
    if text.startswith("//"):
        lines = []
        for line in text.splitlines():
            if not line.startswith("//"):
                break
            lines.append(line)
        return "\n".join(lines)
    return text


def notices(source: Path, libdrm: Path) -> str:
    """The licence texts the package carries: Mesa's licence file and the
    texts of the licences in its tree that the library holds (MIT, Apache-2.0,
    BSL-1.0), then the licence heading of each file whose terms differ from
    MIT, the headers of Khronos and libdrm's."""
    parts = [("Mesa (docs/license.rst)", (source / "docs" / "license.rst").read_text())]
    for name in LICENCE_TEXTS:
        parts.append((f"licenses/{name}", (source / "licenses" / name).read_text(errors="replace")))
    for title, path in NOTICE_FILES:
        base = libdrm if path.startswith("libdrm/") else source
        file = base / path.removeprefix("libdrm/")
        parts.append((f"{title} ({path})", leading_comment(file.read_text(errors="replace"))))
    return "\n\n".join(f"==== {title} ====\n\n{text}\n" for title, text in parts)


def main() -> None:
    script = Path(__file__).read_bytes()
    relibc_stamp = stamp_of(ROOT / "target" / "relibc" / "stamp", "relibc", "cargo xtask relibc")
    libcxx_stamp = stamp_of(LIBCXX / "stamp", "libc++", "cargo xtask libcxx")
    text = stamp_text(script, port_bytes(), relibc_stamp, libcxx_stamp)
    arguments = sys.argv[1:]
    if "--check" in arguments:
        print(text, end="")
        return
    clang, clangxx = tool("clang", "llvm"), tool("clang++", "llvm")
    ar, nm = tool("llvm-ar", "llvm"), tool("llvm-nm", "llvm")
    strip, ranlib = tool("llvm-strip", "llvm"), tool("llvm-ranlib", "llvm")
    if "--cross-file" in arguments:
        out = Path(arguments[arguments.index("--cross-file") + 1])
        out.write_text(cross_file(clang, clangxx, ar, nm, strip, ranlib,
                                  WORK / "stub" / "libstub.a"))
        return
    stamp = WORK / "stamp"
    library = WORK / "lib" / "libmesa.a"
    if stamp.exists() and stamp.read_text() == text and library.exists():
        print(f"mesa ready: {WORK}")
        return
    started = time.time()
    keep = WORK / "venv"
    shutil.rmtree(WORK / "src", ignore_errors=True)
    for child in WORK.glob("*") if WORK.exists() else []:
        if child != keep:
            shutil.rmtree(child, ignore_errors=True) if child.is_dir() else child.unlink()
    WORK.mkdir(parents=True, exist_ok=True)
    log = WORK / "build.log"
    log.write_text("")
    check_options()
    ninja = tool("ninja", "ninja")
    tool("flex", "flex")
    bison = tool("bison", "bison")
    meson, front = host_tools(log)
    path = [*map(str, front), str(bison.parent), str(ninja.parent), os.environ.get("PATH", "")]
    env = {**os.environ, "PATH": os.pathsep.join(path), "SOURCE_DATE_EPOCH": "1"}
    source = unpack(fetch(URL, SHA256, f"mesa-{VERSION}.tar.xz"), WORK / "src")
    libdrm_archive = fetch(LIBDRM_URL, LIBDRM_SHA256, f"libdrm-{LIBDRM_VERSION}.tar.xz")
    wrap = (source / "subprojects" / "libdrm.wrap").read_text()
    if LIBDRM_SHA256 not in wrap:
        raise SystemExit("subprojects/libdrm.wrap names another libdrm than the pinned one")
    cache = source / "subprojects" / "packagecache"
    cache.mkdir(exist_ok=True)
    shutil.copy(libdrm_archive, cache / libdrm_archive.name)
    apply_patches(source, log)
    # The stub of the C library's names, for meson's link probes.
    names = (archive_names(nm, RELIBC / "lib" / "libc.a")
             | archive_names(nm, RELIBC / "lib" / "libm.a"))
    stub_dir = WORK / "stub"
    stub_dir.mkdir()
    (stub_dir / "stub.s").write_text(stub_source(names))
    run(log, clang, "--target=aarch64-linux-gnu", "-c", stub_dir / "stub.s", "-o",
        stub_dir / "stub.o")
    run(log, ar, "rcs", stub_dir / "libstub.a", stub_dir / "stub.o")
    cross = WORK / "cross.ini"
    cross.write_text(cross_file(clang, clangxx, ar, nm, strip, ranlib, stub_dir / "libstub.a"))
    build = WORK / "build"
    run(log, meson, "setup", build, source, "--cross-file", cross, *meson_options(),
        cwd=WORK, env=env)
    run(log, ninja, "-C", build, *ARCHIVES, cwd=WORK, env=env)
    (WORK / "lib").mkdir()
    merge_archives(ar, build, library, log)
    include = WORK / "include"
    for directory in HEADER_DIRS:
        shutil.copytree(source / "include" / directory, include / directory)
    (WORK / "NOTICES").write_text(notices(source, source / "subprojects" / f"libdrm-{LIBDRM_VERSION}"))
    (WORK / "LICENSE").write_text((source / "docs" / "license.rst").read_text())
    # No name is defined twice, and the names the library leaves undefined
    # must be the C library's or the C++ runtime's.
    listing = subprocess.run([str(nm), "--format=posix", "-A", "--defined-only", "--extern-only",
                              str(library)], capture_output=True, text=True, check=True).stdout
    twice = strong_duplicates(listing)
    if twice:
        raise SystemExit("names the archive defines more than once: "
                         + " ".join(f"{n} ({len(m)})" for n, m in sorted(twice.items())[:20]))
    listing = subprocess.run([str(nm), "--format=posix", str(library)], capture_output=True,
                             text=True, check=True).stdout
    defined, undefined = parse_nm(listing)
    known = set(names)
    for lib in ("libc++.a", "libc++abi.a", "libunwind.a"):
        known |= archive_names(nm, LIBCXX / "lib" / lib)
    stray = strays(undefined - defined, known)
    if stray:
        (WORK / "undefined.txt").write_text("\n".join(stray) + "\n")
        raise SystemExit(f"names the library needs and nothing defines ({len(stray)}): "
                         + " ".join(stray[:40]))
    shutil.rmtree(build)
    shutil.rmtree(WORK / "src")
    stamp.write_text(text)
    size = library.stat().st_size
    print(f"mesa ready: {WORK} ({size} bytes of libmesa.a, built in {time.time() - started:.0f} s)")


if __name__ == "__main__":
    main()
