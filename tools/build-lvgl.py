#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build LVGL for programs that draw a window (the demo of stage G4) from its
pinned source archive, unchanged, as one static library.

The archive is the release tag's (about 111 MB, mostly documents and demos).
It is fetched once into target/lvgl-src/ with its SHA-256 checked, and only
`src`, `include`, `lvgl.h`, `lv_version.h` and `LICENCE.txt` are unpacked (the
two files of the font, `src/libs/freetype/LiberationSans-Regular.ttf` and its
licence text, come with `src`). Every `src/**/*.c` is compiled with the
`lv_conf.h` of ports/lvgl, against relibc's headers and the Linux AArch64 C
ABI they describe: the parts the configuration turns off compile to nothing,
as LVGL's own `lvgl.mk` relies on. The C++ files and the assembly files of the
tree (ThorVG, the NEON blend) are not compiled.

The result is target/lvgl/liblvgl.a; the headers a program includes are in
target/lvgl/lvgl-<version> (with `-I` for it, ports/lvgl and
target/freetype/include); the font and the licences are copied to
target/lvgl/ (LiberationSans-Regular.ttf, LiberationSans-LICENSE.txt,
LICENCE.txt). `--host` builds the same files with the compiler of the host
(`-funsigned-char`, as the char of AArch64 Linux, which the guest build has too)
into target/lvgl-host/ and then the reference program target/lvgl-host/lvgl-ref
(tools/lvgl-ref/main.c with the demo of ports/lvgl), whose CRCs the probe of the
guest compares with.

FreeType (tools/build-freetype.py, run first) is what the library's font
module links; its library and headers are those of target/freetype.

Checks after the build, each stopping it with what it found:
  - the archive's SHA-256 is the one of packages/lvgl.toml;
  - no object holds the build directory's path (the sources are built with
    -fmacro-prefix-map);
  - the settings that fix what is drawn (one thread, no floating point in the
    drawing, no assembler, no file system, no monitors, only the widgets of
    the demo) are what the compiler sees, defaults of LVGL included;
  - the names the objects leave undefined are the functions of relibc the
    library calls (the exact list below, each defined in relibc's libc.a) and the
    functions of libfreetype.a, and none is a thread, loader, mapper or
    floating-point function of libm."""

from hashlib import sha256
import importlib.util
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tarfile
from urllib.request import urlopen

import pkgdesc

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("build_freetype", HERE / "build-freetype.py")
freetype = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(freetype)

PACKAGE = pkgdesc.load("lvgl")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = HERE.parent
HOST = freetype.HOST
WORK = ROOT / "target" / "lvgl"
BUILD = ROOT / "target" / "lvgl-host" if HOST else WORK
# The directory of lv_conf.h; the test of the planted faults points it at a
# changed copy.
PORT_DIR = Path(os.environ.get("STAFETO_LVGL_PORT_DIR", ROOT / "ports" / "lvgl"))
CACHE = ROOT / "target" / "lvgl-src"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
FREETYPE_DIR = ROOT / "target" / ("freetype-host" if HOST else "freetype")
OUTPUT = BUILD / "liblvgl.a"
SOURCE_DIR = f"lvgl-{VERSION}"
# What of the archive is unpacked: the first path component of the archive
# is dropped.
UNPACKED = ("src", "include")
UNPACKED_FILES = ("lvgl.h", "lv_version.h", "LICENCE.txt")
FONT = "src/libs/freetype/LiberationSans-Regular.ttf"
FONT_LICENCE = "src/libs/freetype/LiberationSans-LICENSE.txt"
# Cortex-A53 erratum 835769 (the PinePhone's A64), as the other objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")

# The functions of the C library the objects may leave undefined (the exact
# set of this configuration, and the two helpers of the stack protector): a
# name that is not here, formatted-output and floating-point conversion among
# them, stops the build.
ALLOWED = {
    "abort", "memcmp", "memcpy", "memmove", "memset", "strcat", "strchr",
    "strcmp", "strcpy", "strlen", "strncat", "strncmp", "strncpy", "strnlen",
    "__stack_chk_fail", "__stack_chk_guard",
}
# FreeType functions the library must not call although libfreetype.a defines
# some of them: the properties, which can change what a glyph looks like, and
# the LCD filter.
FREETYPE_REFUSED = {
    "FT_Property_Set", "FT_Property_Get", "FT_Set_Default_Properties",
    "FT_Face_Properties", "FT_Library_SetLcdFilter", "FT_Library_SetLcdFilterWeights",
    "FT_Library_SetLcdGeometry", "getenv",
}
# Files of src that are not compiled: the C++ and assembly files by their
# suffix, and src/osal/lv_linux.c, whose one use is the load figure of the
# system monitor (off) and which reads /proc/stat through stdio.
EXCLUDED = ("osal/lv_linux.c",)

# The macros the compiler must see with these values (the configuration of
# ports/lvgl and the defaults of LVGL it does not name). A value is the text
# of the definition; "0" for a part that is off.
EXPECTED = {
    "LV_USE_OS": "LV_OS_NONE",
    "LV_USE_FLOAT": "0",
    "LV_USE_MATRIX": "0",
    "LV_USE_DRAW_SW_ASM": "LV_DRAW_SW_ASM_NONE",
    "LV_USE_SYSMON": "0",
    "LV_USE_PERF_MONITOR": "0",
    "LV_USE_MEM_MONITOR": "0",
    "LV_USE_PROFILER": "0",
    "LV_USE_SNAPSHOT": "0",
    "LV_USE_FLEX": "0",
    "LV_USE_GRID": "0",
    "LV_USE_THORVG": "0",
    "LV_USE_VECTOR_GRAPHIC": "0",
    "LV_USE_TINY_TTF": "0",
    "LV_USE_OBSERVER": "0",
    "LV_BUILD_EXAMPLES": "0",
    "LV_BUILD_DEMOS": "0",
    "LV_USE_FREETYPE": "1",
    "LV_FREETYPE_USE_LVGL_PORT": "0",
    "LV_USE_DRAW_SW": "1",
    "LV_DRAW_SW_DRAW_UNIT_CNT": "1",
    "LV_DEF_REFR_PERIOD": "16",
    "LV_USE_LABEL": "1",
    "LV_USE_BUTTON": "1",
    "LV_USE_CHECKBOX": "1",
    "LV_USE_SWITCH": "1",
    "LV_USE_SLIDER": "1",
    "LV_USE_BAR": "1",
    "LV_USE_TEXTAREA": "1",
    "LV_USE_IMAGE": "1",
    "LV_USE_THEME_DEFAULT": "1",
    "LV_USE_THEME_SIMPLE": "0",
    "LV_USE_THEME_MONO": "0",
}
# Every one of these, a family of parts the demo has no use for, is off.
OFF_PREFIXES = ("LV_USE_FS_", "LV_USE_LINUX_")
OFF_NAMES = (
    "LV_USE_SDL", "LV_USE_X11", "LV_USE_WAYLAND", "LV_USE_OPENGLES", "LV_USE_LODEPNG",
    "LV_USE_LIBPNG", "LV_USE_BMP", "LV_USE_TJPGD", "LV_USE_LIBJPEG_TURBO",
    "LV_USE_LIBWEBP", "LV_USE_SVG", "LV_USE_GIF", "LV_USE_FFMPEG", "LV_USE_QRCODE",
    "LV_USE_CHART", "LV_USE_CANVAS", "LV_USE_ARC", "LV_USE_DROPDOWN",
    "LV_USE_KEYBOARD", "LV_USE_LIST", "LV_USE_MENU", "LV_USE_MSGBOX", "LV_USE_TABLE",
)


# The files of the port the library is built from.
LIBRARY_PORT = ("lv_conf.h", "lv_assert_handler.h")
# The reference program of the host (tools/lvgl-ref): the demo, its schedule,
# key table and CRC, with the host's LVGL and FreeType.
HOST_DIR = ROOT / "target" / "lvgl-host"
REFERENCE = HOST_DIR / "lvgl-ref"
REFERENCE_SOURCES = ("demo.c", "schedule.c", "keys.c", "crc.c")


def reference_flags(port_dir: Path) -> list[str]:
    """The flags of the host build of the library and the reference: the char
    of AArch64 Linux, wrapping overflow, no fused multiply-add."""
    return ["-std=gnu11", "-O2", "-funsigned-char", "-fwrapv", f"-fmacro-prefix-map={ROOT}/=",
            "-ffp-contract=off",
            f"-I{port_dir}", f"-I{HOST_DIR / SOURCE_DIR}",
            f"-I{ROOT / 'target' / 'freetype-host' / 'include'}"]


def build_reference(port_dir: Path = PORT_DIR, output: Path = REFERENCE,
                    main: Path = ROOT / "tools" / "lvgl-ref" / "main.c") -> Path:
    """Build the reference program from the sources of `port_dir` and the
    host's libraries (built by `build-lvgl.py --host`); the path of the
    program. Rebuilt only when a source, the compiler flags or a library
    changed."""
    library = HOST_DIR / "liblvgl.a"
    ft = ROOT / "target" / "freetype-host" / "libfreetype.a"
    if not library.exists() or not ft.exists():
        raise SystemExit("build the libraries first: tools/build-lvgl.py --host")
    sources = [port_dir / name for name in REFERENCE_SOURCES] + [main]
    headers = sorted(port_dir.glob("*.h"))
    text = sha256(b"".join(p.read_bytes() for p in sources + headers + [library, ft, Path(__file__)])
                  ).hexdigest() + "\n"
    stamp = output.with_suffix(".stamp")
    if output.exists() and stamp.exists() and stamp.read_text() == text:
        print(f"lvgl-ref ready: {output}")
        return output
    clang = freetype.tool("clang", "llvm")
    log = output.with_suffix(".log")
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("")
    run(log, clang, *reference_flags(port_dir), *sources, library, ft, "-o", output)
    stamp.write_text(text)
    print(f"lvgl-ref ready: {output}")
    return output


def run(log: Path, *args, cwd: Path | None = None) -> None:
    freetype.run(log, *args, cwd=cwd)


def configuration_problems(macros: dict[str, str]) -> list[str]:
    """What is wrong with the macros the compiler sees: a setting that is not
    what the demo needs, a part that is on and should be off."""
    bad = [f"{name} is {macros.get(name, 'undefined')}, expected {value}"
           for name, value in EXPECTED.items() if macros.get(name) != value]
    for name, value in sorted(macros.items()):
        if (name.startswith(OFF_PREFIXES) or name in OFF_NAMES) and value != "0":
            bad.append(f"{name} is {value}, expected 0")
    return bad


def parse_macros(listing: str) -> dict[str, str]:
    """The object-like macros of a `clang -dM -E` listing, name to text."""
    macros = {}
    for line in listing.splitlines():
        parts = line.split(" ", 2)
        if len(parts) >= 2 and parts[0] == "#define" and "(" not in parts[1]:
            macros[parts[1]] = parts[2] if len(parts) > 2 else ""
    return macros


def undefined_violations(names: list[str], freetype_names: set[str]) -> list[str]:
    """The undefined names that may not stay so: the library's own functions
    pass, the C library's listed ones pass, a thread, loader, mapper or
    libm name is refused by name, anything else is off the lists."""
    bad = []
    for name in sorted(set(names)):
        if name in FREETYPE_REFUSED:
            bad.append(f"{name} (a name the library never calls)")
        elif name in freetype_names:
            continue
        elif (name in freetype.FORBIDDEN or name in freetype.FORBIDDEN_MATH
                or name.startswith(freetype.FORBIDDEN_PREFIXES)):
            bad.append(f"{name} (a name the library never calls)")
        elif name in ALLOWED:
            continue
        else:
            bad.append(f"{name} (not in the lists of what it may call)")
    return bad


def fetch() -> Path:
    """The source archive, from the cache or the network, with its SHA-256 checked."""
    CACHE.mkdir(parents=True, exist_ok=True)
    archive = CACHE / f"lvgl-{VERSION}.tar.gz"
    if not archive.exists() or sha256(archive.read_bytes()).hexdigest() != SHA256:
        try:
            with urlopen(URL) as response:
                archive.write_bytes(response.read())
        except OSError as error:
            raise SystemExit(f"cannot fetch the LVGL source archive {URL} (SHA-256 {SHA256}): {error}")
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        archive.unlink()
        raise SystemExit(f"the LVGL source archive {URL} has an unexpected SHA-256 (expected {SHA256})")
    return archive


def unpack(archive: Path, into: Path) -> Path:
    """Unpack the parts of the archive the build uses, without its first path
    component, into `into`/lvgl-<version>."""
    root = into / SOURCE_DIR
    with tarfile.open(archive) as members:
        keep = []
        for member in members:
            parts = member.name.split("/", 1)
            if len(parts) < 2:
                continue
            rest = parts[1]
            if rest.split("/", 1)[0] in UNPACKED or rest in UNPACKED_FILES:
                member.name = f"{SOURCE_DIR}/{rest}"
                keep.append(member)
        members.extractall(into, members=keep, filter="data")
    return root


def sources(root: Path) -> list[Path]:
    """Every C file of src but the excluded ones (the C++ and assembly files
    have other suffixes)."""
    return sorted(p for p in (root / "src").rglob("*.c")
                  if str(p.relative_to(root / "src")) not in EXCLUDED)


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    # The library depends on its configuration files only; the sources of the
    # demo (the rest of ports/lvgl) are the reference program's business.
    port = sha256(b"".join((PORT_DIR / name).read_bytes() for name in LIBRARY_PORT)).hexdigest()
    libc = RELIBC / "lib" / "libc.a"
    if not HOST and (not (RELIBC / "include" / "stdio.h").exists() or not libc.exists()):
        raise SystemExit("build relibc with cargo xtask relibc first")
    # FreeType first: its headers and library are what this build uses.
    subprocess.run([sys.executable, str(HERE / "build-freetype.py"), *(["--host"] if HOST else [])],
                   check=True)
    ft_lib = FREETYPE_DIR / "libfreetype.a"
    stamp = BUILD / "stamp"
    text = f"{VERSION} {SHA256} {script} {port} {sha256(ft_lib.read_bytes()).hexdigest()}"
    if not HOST:
        text += f" {sha256(libc.read_bytes()).hexdigest()}"
    text += "\n"
    if stamp.exists() and stamp.read_text() == text and OUTPUT.exists():
        print(f"lvgl ready: {OUTPUT}")
        if HOST:
            build_reference()
        return
    archive = fetch()
    shutil.rmtree(BUILD, ignore_errors=True)
    BUILD.mkdir(parents=True)
    log = BUILD / "build.log"
    log.write_text("")
    root = unpack(archive, BUILD)
    clang, ar = freetype.tool("clang", "llvm"), freetype.tool("llvm-ar", "llvm")
    nm_tool, lld = freetype.tool("llvm-nm", "llvm"), freetype.tool("ld.lld", "lld")
    # -funsigned-char: the char of AArch64 Linux, on the host sample too;
    # -fwrapv: signed overflow wraps.
    # -fmacro-prefix-map: the build machine's directory is in no object.
    flags = ["-std=gnu11", "-O2", "-funsigned-char", "-fwrapv", f"-fmacro-prefix-map={ROOT}/=", "-ffunction-sections", "-fdata-sections",
             "-ffp-contract=off", f"-I{PORT_DIR}", f"-I{root}",
             f"-I{FREETYPE_DIR / 'include'}"]
    if HOST:
        cc = (str(clang), "-fPIC", *flags)
    else:
        cc = (str(clang), "--target=aarch64-linux-gnu", "-nostdinc",
              "-isystem", str(RELIBC / "include"), "-mno-outline-atomics",
              "-fstack-protector-strong", A53_ERRATA, "-fPIC", *UNWIND_CFLAGS, *flags)
    # The settings the compiler ends up with.
    probe = BUILD / "probe.c"
    probe.write_text('#include "lvgl.h"\n')
    listing = subprocess.run([*cc, "-dM", "-E", str(probe)], capture_output=True, text=True)
    if listing.returncode:
        print(listing.stderr[-3000:])
        raise SystemExit("lvgl: the headers do not compile with ports/lvgl/lv_conf.h")
    # Reported with the findings of the names below: a changed setting often
    # shows in both.
    found = configuration_problems(parse_macros(listing.stdout))
    objects = []
    (BUILD / "obj").mkdir()
    for path in sources(root):
        obj = BUILD / "obj" / (str(path.relative_to(root / "src")).replace("/", "__")[:-2] + ".o")
        run(log, *cc, "-c", path, "-o", obj)
        objects.append(obj)
        found += freetype.build_path_violations(obj, ROOT)
    if not HOST:
        joined = BUILD / "joined.o"
        run(log, lld, "-r", "-o", joined, *objects)
        undefined = freetype.symbol_names(freetype.nm(nm_tool, "-u", joined))
        joined.unlink()
        ft_names = set(freetype.symbol_names(
            freetype.nm(nm_tool, "-g", "--defined-only", ft_lib)))
        provided = set(freetype.symbol_names(
            freetype.nm(nm_tool, "-g", "--defined-only", libc)))
        found += undefined_violations(undefined, ft_names)
        found += freetype.unresolved([n for n in undefined if n not in ft_names], provided)
        print("lvgl: undefined names: " + " ".join(sorted(set(undefined))))
    if found:
        raise SystemExit("lvgl: " + "; ".join(found))
    OUTPUT.unlink(missing_ok=True)
    run(log, ar, "rcs", OUTPUT, *objects)
    shutil.copy(root / FONT, BUILD / "LiberationSans-Regular.ttf")
    shutil.copy(root / FONT_LICENCE, BUILD / "LiberationSans-LICENSE.txt")
    shutil.copy(root / "LICENCE.txt", BUILD / "LICENCE.txt")
    stamp.write_text(text)
    print(f"lvgl ready: {OUTPUT}")
    if HOST:
        build_reference()


if __name__ == "__main__":
    main()
