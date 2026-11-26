#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build the test framework dEQP of VK-GL-CTS for stafeto (`cargo xtask
deqp`): the modules deqp-egl, deqp-gles2, deqp-gles3 and deqp-gles31 as
static archives for aarch64-linux-gnu, against the sysroot of relibc
(target/relibc/sysroot), the C++ runtime of tools/build-libcxx.py
(target/libcxx) and the Mesa of tools/build-mesa.py (target/mesa). A Rust
start crate (tests/deqp, the program deqp-egl) links them: the CMake build
makes no executable.

The source is VK-GL-CTS, tag opengl-es-cts-3.2.14.1, the commit COMMIT below
(the release the CI of Mesa 26.3.1 takes for these modules). It is fetched by
that commit hash from GitHub into target/deqp-src/cts and the hash of the
checkout is compared. The tree needs the directories of its external sources
(the top CMakeLists.txt adds spirv-tools, glslang, amber and jsoncpp and
requires spirv-headers, all excluded from the build), so the script of the
tree, `external/fetch_sources.py`, runs whole with python3 -I in that fresh
directory outside the tree of stafeto, with the revisions it pins; the
checkouts of the five repositories the CMake files need are compared with the
revisions in the script. The Vulkan Validation Layers are not fetched
(`--include-vvl` off): CMakeLists.txt:129 adds the directory on ARM_64, but its
CMake file builds the layers only when `external/vulkan-validationlayers/
external` exists, and no target of ours needs them.

The target of stafeto (tests/deqp/targets/stafeto/stafeto.cmake) and its
platform (tests/deqp/platform) are copied into the tree. The build is
`GLES_ALLOW_DIRECT_LINK=ON`: the framework links the entry points of EGL and
OpenGL ES from libmesa.a, where it would dlopen("libEGL.so"). CMake is the
generator only: the script builds with ninja the objects and archives that the
link line of each module names (`ninja -t commands`), and puts them in
target/deqp/lib; target/deqp/<module>.link lists the archives of a module's
link in order, and lib<module>-main.a holds its own objects (tcuMain and the
entry of the package).

CMake (3.20 or later; Homebrew `cmake`, apt `cmake`), ninja and git come from
the host. `--check` prints the stamp the build would write and exits;
`--modules a,b` builds a subset."""

from hashlib import sha256
from pathlib import Path
import os
import re
import shlex
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "deqp"
CACHE = ROOT / "target" / "deqp-src"
SOURCE = CACHE / "cts"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
LIBCXX = ROOT / "target" / "libcxx"
MESA = ROOT / "target" / "mesa"
PORT = ROOT / "tests" / "deqp"
WINDOW_INCLUDE = ROOT / "lib" / "posix-crt" / "window"
URL = "https://github.com/KhronosGroup/VK-GL-CTS.git"
TAG = "opengl-es-cts-3.2.14.1"
COMMIT = "067e8832315e79817ede1c4863804e440f5d1c80"
MODULES = ["deqp-egl", "deqp-gles2", "deqp-gles3", "deqp-gles31"]
# The repositories of the external sources the CMake files need, and the
# directories fetch_sources.py puts them in (external/<name>/src).
REQUIRED_EXTERNALS = ["spirv-tools", "glslang", "spirv-headers", "amber", "jsoncpp"]
CMAKE_MINIMUM = (3, 20, 0)
# As the other objects of stafeto (tools/build-libcxx.py): Cortex-A53 erratum
# 835769, no outlined atomics (libgcc's helpers are not in the sysroot), the
# unwind rows the exceptions need, and no machine outlining, which drops them.
TARGET_FLAGS = ["--target=aarch64-linux-gnu", "-mfix-cortex-a53-835769", "-mno-outline-atomics",
                "-fno-pic", "-fasynchronous-unwind-tables", "-mllvm",
                "-enable-machine-outliner=never"]
# The file names of the license texts that go into NOTICES (the tree's own and
# the sources the programs link: zlib and libpng; the other externals are
# never built).
NOTICE_FILES = [
    ("VK-GL-CTS", "Apache-2.0", "LICENSE"),
    ("VK-GL-CTS (NOTICE)", "Apache-2.0", "NOTICE"),
    ("zlib 1.2.13", "Zlib", "external/zlib/src/README"),
    ("libpng 1.6.50", "libpng-2.0", "external/libpng/src/LICENSE"),
    # The archives of the Vulkan part of the tree (tcutil-platform links vkutil,
    # which links these); a program takes what it references only.
    ("glslang", "BSD-3-Clause AND BSD-2-Clause AND MIT AND Apache-2.0 AND GPL-3.0-or-later "
     "WITH Bison-exception-2.2", "external/glslang/src/LICENSE.txt"),
    ("SPIRV-Tools", "Apache-2.0", "external/spirv-tools/src/LICENSE"),
    ("SPIRV-Headers", "MIT", "external/spirv-headers/src/LICENSE"),
]


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
        raise SystemExit(f"missing {name}; install it (Homebrew or apt: {brew_formula or name})")
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


def output(*args, cwd: Path | None = None) -> str:
    return subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True, text=True,
                          check=True).stdout


def version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text)[:3])


def toolchain_file(clang: Path, clangxx: Path, ar: Path, ranlib: Path, sysroot: Path = RELIBC,
                   libcxx: Path = LIBCXX, port: Path = PORT) -> str:
    """The CMake toolchain file: clang for aarch64-linux-gnu against the
    headers of relibc and libc++; `__stafeto__` is defined as for Mesa. The
    probes of CMake build static libraries only (nothing links here), and
    the search for libraries and packages stays inside the sysroot, so that
    no library of the host is found."""
    common = " ".join(TARGET_FLAGS + ["-D__stafeto__=1", "-nostdlibinc", f"-isystem {port / 'include'}"])
    return f"""set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER "{clang}")
set(CMAKE_CXX_COMPILER "{clangxx}")
set(CMAKE_AR "{ar}")
set(CMAKE_RANLIB "{ranlib}")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_C_FLAGS_INIT "{common} -isystem {sysroot / 'include'}")
set(CMAKE_CXX_FLAGS_INIT "{common} -nostdinc++ -isystem {libcxx / 'include' / 'c++' / 'v1'} -isystem {sysroot / 'include'}")
set(CMAKE_FIND_ROOT_PATH "{sysroot}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
"""


def cmake_options(toolchain: Path, modules: list[str]) -> list[str]:
    """The `-D` arguments of the CMake configuration."""
    return [
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG",
        "-DCMAKE_CXX_FLAGS_RELEASE=-O2 -DNDEBUG",
        # zlib 1.2.13 asks for CMake 2.4, which CMake 4 refuses.
        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
        "-DDEQP_TARGET=stafeto",
        "-DDE_CPU=DE_CPU_ARM_64",
        "-DGLES_ALLOW_DIRECT_LINK=ON",
        f"-DSELECTED_BUILD_TARGETS={' '.join(modules)}",
        f"-DSTAFETO_MESA_DIR={MESA}",
        f"-DSTAFETO_WINDOW_INCLUDE={WINDOW_INCLUDE}",
    ]


def port_bytes(port: Path = PORT) -> bytes:
    files = [p for p in sorted(port.rglob("*")) if p.is_file()]
    return b"".join(p.read_bytes() for p in files)


def stamp_of(path: Path, what: str, hint: str) -> str:
    if not path.exists():
        raise SystemExit(f"build {what} first: {hint}")
    return sha256(path.read_bytes()).hexdigest()


def stamp_text(script: bytes, port: bytes, relibc: str, libcxx: str, mesa: str,
               modules: list[str]) -> str:
    return (f"{TAG} {COMMIT} {sha256(script).hexdigest()} {sha256(port).hexdigest()} "
            f"{relibc} {libcxx} {mesa} {','.join(modules)}\n")


def fetch_source(log: Path) -> None:
    """The checkout of COMMIT in SOURCE, with its hash compared."""
    if not (SOURCE / ".git").exists():
        SOURCE.mkdir(parents=True, exist_ok=True)
        run(log, "git", "init", "-q", SOURCE)
        run(log, "git", "remote", "add", "origin", URL, cwd=SOURCE)
    have = subprocess.run(["git", "rev-parse", "-q", "--verify", "HEAD"], cwd=SOURCE,
                          capture_output=True, text=True).stdout.strip()
    if have != COMMIT:
        run(log, "git", "fetch", "-q", "--depth", "1", "origin", COMMIT, cwd=SOURCE)
        run(log, "git", "checkout", "-q", "--force", "FETCH_HEAD", cwd=SOURCE)
    head = output("git", "rev-parse", "HEAD", cwd=SOURCE).strip()
    if head != COMMIT:
        raise SystemExit(f"the checkout is at {head}, {COMMIT} ({TAG}) expected")


def pinned_revisions(script: str) -> dict[str, str]:
    """The revisions of the git repositories fetch_sources.py pins, by the
    directory of external/ they go to: the entries `GitRepo(https, ssh,
    revision, baseDir`."""
    found = {}
    for match in re.finditer(r'GitRepo\(\s*"[^"]*",\s*"[^"]*",\s*"([^"]+)",\s*"([^"]+)"', script):
        found[match.group(2)] = match.group(1)
    return found


def fetch_externals(log: Path) -> None:
    """external/fetch_sources.py of the tree, whole, in the fresh directory
    of the checkout; then the five checkouts the build needs against the
    revisions it pins."""
    marker = SOURCE / "external" / ".fetched"
    if marker.exists() and marker.read_text() == COMMIT:
        return
    run(log, sys.executable, "-I", SOURCE / "external" / "fetch_sources.py", cwd=SOURCE)
    pinned = pinned_revisions((SOURCE / "external" / "fetch_sources.py").read_text())
    for name in REQUIRED_EXTERNALS:
        want = pinned.get(name)
        head = output("git", "rev-parse", "HEAD", cwd=SOURCE / "external" / name / "src").strip()
        if want is None or head != want:
            raise SystemExit(f"external/{name} is at {head}, the script pins {want}")
    marker.write_text(COMMIT)


def copy_overlay(source: Path = SOURCE, port: Path = PORT) -> None:
    """The target of stafeto and its platform into the tree."""
    target = source / "targets" / "stafeto"
    target.mkdir(parents=True, exist_ok=True)
    shutil.copy(port / "targets" / "stafeto" / "stafeto.cmake", target / "stafeto.cmake")
    platform = source / "framework" / "platform" / "stafeto"
    shutil.rmtree(platform, ignore_errors=True)
    shutil.copytree(port / "platform", platform)


def link_inputs(command: str, build: Path) -> tuple[list[Path], list[Path]]:
    """The objects and the archives of a link command of ninja, in order, as
    paths in the build directory."""
    objects, archives = [], []
    for word in shlex.split(command):
        if word.endswith(".o"):
            objects.append(build / word)
        elif word.endswith(".a"):
            archives.append(Path(word) if word.startswith("/") else build / word)
    return objects, archives


def notices(source: Path = SOURCE) -> str:
    parts = [f"VK-GL-CTS {TAG} ({COMMIT}) and the sources its build links.\n"
             "The test framework is under the Apache License 2.0; zlib and libpng are\n"
             "built from the sources external/fetch_sources.py fetches, and so are\n"
             "glslang and SPIRV-Tools, whose archives the Vulkan part of the tree\n"
             "adds to the link. The other external sources it fetches (Amber, jsoncpp,\n"
             "Vulkan-Docs, Vulkan-Video-Samples, video_generator) are not built.\n"]
    for name, spdx, path in NOTICE_FILES:
        parts.append(f"\n{'=' * 72}\n{name} ({spdx}): {path}\n{'=' * 72}\n")
        parts.append((source / path).read_text(errors="replace"))
    return "".join(parts)


def main() -> None:
    arguments = sys.argv[1:]
    modules = MODULES
    if "--modules" in arguments:
        modules = arguments[arguments.index("--modules") + 1].split(",")
        unknown = [m for m in modules if m not in MODULES]
        if unknown:
            raise SystemExit(f"unknown modules: {' '.join(unknown)}")
    text = stamp_text(Path(__file__).read_bytes(), port_bytes(),
                      stamp_of(ROOT / "target" / "relibc" / "stamp", "relibc", "cargo xtask relibc"),
                      stamp_of(LIBCXX / "stamp", "libc++", "cargo xtask libcxx"),
                      stamp_of(MESA / "stamp", "Mesa", "cargo xtask mesa"), modules)
    if "--check" in arguments:
        print(text, end="")
        return
    stamp = WORK / "stamp"
    if stamp.exists() and stamp.read_text() == text and all(
            (WORK / f"{m}.link").exists() for m in modules):
        print(f"deqp ready: {WORK}")
        return
    started = time.time()
    clang, clangxx = tool("clang", "llvm"), tool("clang++", "llvm")
    ar, ranlib = tool("llvm-ar", "llvm"), tool("llvm-ranlib", "llvm")
    objcopy = tool("llvm-objcopy", "llvm")
    cmake, ninja, git = tool("cmake", "cmake"), tool("ninja", "ninja"), tool("git")
    found = version_tuple(output(cmake, "--version").splitlines()[0])
    if found < CMAKE_MINIMUM:
        raise SystemExit(f"cmake {'.'.join(map(str, found))} is older than "
                         f"{'.'.join(map(str, CMAKE_MINIMUM))}")
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text(f"cmake {'.'.join(map(str, found))}\n")
    env = {**os.environ, "PATH": os.pathsep.join(
        [str(git.parent), str(ninja.parent), os.environ.get("PATH", "")]),
        "SOURCE_DATE_EPOCH": "1"}
    fetch_source(log)
    fetch_externals(log)
    copy_overlay()
    toolchain = WORK / "toolchain.cmake"
    toolchain.write_text(toolchain_file(clang, clangxx, ar, ranlib))
    build = WORK / "build"
    run(log, cmake, "-G", "Ninja", "-S", SOURCE, "-B", build, *cmake_options(toolchain, modules),
        env=env)
    lib = WORK / "lib"
    lib.mkdir()
    for module in modules:
        commands = output(ninja, "-C", build, "-t", "commands", module).splitlines()
        objects, archives = link_inputs(commands[-1], build)
        if not objects or not archives:
            raise SystemExit(f"the link line of {module} names no objects or no archives")
        run(log, ninja, "-C", build, *[str(p.relative_to(build)) for p in objects if
                                       not p.is_absolute() or p.is_relative_to(build)],
            *[str(p.relative_to(build)) for p in archives if p.is_relative_to(build)], env=env)
        # The main of the framework gives its name to the main of stafeto
        # (tests/deqp/platform/tcuStafetoMain.cpp, in tcutil-platform).
        renamed = []
        for obj in objects:
            if obj.name == "tcuMain.cpp.o":
                copy = lib / f"{module}-{obj.name}"
                run(log, objcopy, "--redefine-sym", "main=deqp_main", obj, copy)
                obj = copy
            renamed.append(obj)
        main_archive = lib / f"lib{module}-main.a"
        run(log, ar, "crs", main_archive, *renamed)
        for obj in renamed:
            if obj.parent == lib:
                obj.unlink()
        names = [main_archive.name]
        for archive in archives:
            if archive.is_relative_to(MESA):
                continue
            if not (lib / archive.name).exists():
                shutil.copy(archive, lib / archive.name)
            names.append(archive.name)
        (WORK / f"{module}.link").write_text("\n".join(names) + "\n")
    (WORK / "NOTICES").write_text(notices())
    shutil.copy(SOURCE / "LICENSE", WORK / "LICENSE")
    stamp.write_text(text)
    size = sum(p.stat().st_size for p in lib.glob("*.a"))
    print(f"deqp ready: {WORK} ({size} bytes of archives, built in {time.time() - started:.0f} s)")


if __name__ == "__main__":
    main()
