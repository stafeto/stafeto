#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The Linux side of the dEQP baseline (`cargo xtask deqp-reference`, plan G8,
7.3): the same Mesa and the same VK-GL-CTS as the guest has, built for the
machine it runs on.

    build-deqp-reference.py TARGET:MODULE[,MODULE]...

TARGET is the platform of dEQP the baseline is made on (`surfaceless`,
`nullws` or `x11_egl`), MODULE a module of the suite (`egl`, `gles2`, `gles3`,
`gles31`). For each target the script builds

- Mesa (packages/mesa.toml, the archive and SHA-256 of tools/build-mesa.py)
  with the options of the build for stafeto (softpipe, no LLVM, no desktop
  OpenGL) as shared libraries into target/deqp-reference/mesa-<variant>/prefix:
  the variant `surfaceless` serves the targets `surfaceless` and `nullws`, the
  variant `x11` has the EGL platform of X11 on top (the target `x11_egl`);
- the modules of VK-GL-CTS (tools/build-deqp.py's commit and checkout) with
  that target of its CMake, into target/deqp-reference/cts-<target>.

Its output is the binaries `cts-<target>/modules/<module>/deqp-<module>` and
`versions.txt` (what the header of a baseline file cites). The compiler is
CC and CXX of the environment, clang and clang++ when they are not set."""

from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bm = load("build_mesa", "build-mesa.py")
mr = load("build_mesa_reference", "build-mesa-reference.py")
bd = load("build_deqp", "build-deqp.py")

ROOT = bm.ROOT
WORK = ROOT / "target" / "deqp-reference"
TARGETS = ["surfaceless", "nullws", "x11_egl"]
MODULES = ["egl", "gles2", "gles3", "gles31"]


def mesa_variant(target: str) -> str:
    return "x11" if target == "x11_egl" else "surfaceless"


def mesa_options(variant: str, prefix: Path) -> list[str]:
    """The options of the build for stafeto less the ones that make static
    targets for a cross build (build-mesa-reference.py), and the platform of X11
    for the variant that runs on an X server. The default platform of EGL stays
    the surfaceless one; a run picks X11 with EGL_PLATFORM."""
    options = {k: v for k, v in bm.OPTIONS.items() if k not in mr.OMITTED}
    options["egl-native-platform"] = "surfaceless"
    if variant == "x11":
        options["platforms"] = "x11"
    return bm.meson_options(options, bm.LIBDRM_OPTIONS) + [f"--prefix={prefix}"]


def parse_arguments(words: list[str]) -> dict[str, list[str]]:
    """`TARGET:MODULE,MODULE` words as {target: [module, ...]}."""
    wanted: dict[str, list[str]] = {}
    for word in words:
        target, _, modules = word.partition(":")
        if target not in TARGETS:
            raise SystemExit(f"unknown target {target!r}; the targets are {' '.join(TARGETS)}")
        names = [m for m in modules.split(",") if m]
        if not names:
            raise SystemExit(f"no module in {word!r}")
        for module in names:
            if module not in MODULES:
                raise SystemExit(f"unknown module {module!r}; the modules are {' '.join(MODULES)}")
            if module == "egl" and target == "surfaceless":
                raise SystemExit("deqp-egl needs eglu::Platform, which the target surfaceless has not "
                                 "(plan 7.3): use nullws or x11_egl")
            if module != "egl" and target == "x11_egl":
                raise SystemExit("the GLES modules take the target surfaceless or nullws")
            if module not in wanted.setdefault(target, []):
                wanted[target].append(module)
    return wanted


def cmake_options(target: str, modules: list[str], cc: str, cxx: str) -> list[str]:
    """The `-D` arguments of the configuration of VK-GL-CTS for a target."""
    return [
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG",
        "-DCMAKE_CXX_FLAGS_RELEASE=-O2 -DNDEBUG",
        f"-DCMAKE_C_COMPILER={cc}",
        f"-DCMAKE_CXX_COMPILER={cxx}",
        # zlib 1.2.13 asks for CMake 2.4, which CMake 4 refuses.
        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
        f"-DDEQP_TARGET={target}",
        f"-DSELECTED_BUILD_TARGETS={' '.join('deqp-' + m for m in modules)}",
    ]


def mesa_libdir(prefix: Path) -> Path:
    """The directory of libEGL.so under an install prefix of Mesa (`lib` or
    `lib/<triplet>`)."""
    for found in sorted((prefix / "lib").glob("**/libEGL.so*")):
        return found.parent
    raise SystemExit(f"no libEGL.so under {prefix}")


def build_mesa(variant: str, log: Path, env: dict) -> Path:
    """Mesa for this machine, installed; the prefix. Built once: the stamp
    holds the options."""
    work = WORK / f"mesa-{variant}"
    prefix = work / "prefix"
    options = mesa_options(variant, prefix)
    stamp = work / "stamp"
    if stamp.exists() and stamp.read_text() == "\n".join(options):
        print(f"Mesa ({variant}) ready: {prefix}")
        return prefix
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    bm.WORK = work
    bm.check_options()
    ninja = bm.tool("ninja", "ninja")
    bm.tool("flex", "flex")
    bison = bm.tool("bison", "bison")
    meson, front = bm.host_tools(log)
    mesa_env = {**env, "SOURCE_DATE_EPOCH": "1",
                "PATH": os.pathsep.join([*map(str, front), str(bison.parent), str(ninja.parent),
                                         env.get("PATH", "")])}
    source = bm.unpack(bm.fetch(bm.URL, bm.SHA256, f"mesa-{bm.VERSION}.tar.xz"), work / "src")
    libdrm = bm.fetch(bm.LIBDRM_URL, bm.LIBDRM_SHA256, f"libdrm-{bm.LIBDRM_VERSION}.tar.xz")
    cache = source / "subprojects" / "packagecache"
    cache.mkdir(exist_ok=True)
    shutil.copy(libdrm, cache / libdrm.name)
    build = work / "build"
    bm.run(log, meson, "setup", build, source, *options, cwd=work, env=mesa_env)
    bm.run(log, ninja, "-C", build, cwd=work, env=mesa_env)
    bm.run(log, meson, "install", "-C", build, cwd=work, env=mesa_env)
    stamp.write_text("\n".join(options))
    print(f"Mesa ({variant}) built: {prefix}")
    return prefix


def build_cts(target: str, modules: list[str], prefix: Path, log: Path, env: dict) -> None:
    """The modules of VK-GL-CTS for a target of its CMake, against Mesa's
    prefix (headers and libraries come from it through the search paths of CMake)."""
    bd.fetch_source(log)
    bd.fetch_externals(log)
    cmake, ninja = bd.tool("cmake", "cmake"), bd.tool("ninja", "ninja")
    build = WORK / f"cts-{target}"
    cc, cxx = env["CC"], env["CXX"]
    cenv = {**env, "PATH": os.pathsep.join([str(ninja.parent), env.get("PATH", "")]),
            "PKG_CONFIG_PATH": os.pathsep.join(
                str(p) for p in sorted((prefix / "lib").glob("**/pkgconfig"))),
            "CMAKE_PREFIX_PATH": str(prefix)}
    libdir = mesa_libdir(prefix)
    # The targets find the libraries by name; the directory of Mesa's goes to the
    # linker and, as an rpath, to the programs.
    link = f"-L{libdir} -Wl,-rpath,{libdir}"
    bd.run(log, cmake, "-G", "Ninja", "-S", bd.SOURCE, "-B", build,
           *cmake_options(target, modules, cc, cxx), f"-DCMAKE_PREFIX_PATH={prefix}",
           f"-DCMAKE_EXE_LINKER_FLAGS={link}", env=cenv)
    bd.run(log, ninja, "-C", build, *["deqp-" + m for m in modules], env=cenv)
    for module in modules:
        binary = build / "modules" / module / f"deqp-{module}"
        if not binary.exists():
            raise SystemExit(f"{binary} was not built")
        print(f"built {binary}")


def main() -> None:
    words = [w for w in sys.argv[1:] if not w.startswith("--")]
    wanted = parse_arguments(words)
    if not wanted:
        raise SystemExit(__doc__)
    WORK.mkdir(parents=True, exist_ok=True)
    log = WORK / "build.log"
    log.touch()
    env = dict(os.environ)
    env.setdefault("CC", "clang")
    env.setdefault("CXX", "clang++")
    for target, modules in wanted.items():
        prefix = build_mesa(mesa_variant(target), log, env)
        build_cts(target, modules, prefix, log, env)
    versions = [f"VK-GL-CTS {bd.TAG} ({bd.COMMIT})", f"Mesa {bm.VERSION} softpipe, shared libraries, "
                f"{env['CC']}"]
    (WORK / "versions.txt").write_text("\n".join(versions) + "\n")


if __name__ == "__main__":
    main()
