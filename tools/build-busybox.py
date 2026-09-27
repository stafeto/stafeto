#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build the pinned BusyBox echo/cat objects for the stafeto guest probe."""

from hashlib import sha256
from pathlib import Path
import shutil
import subprocess
from urllib.request import urlopen


VERSION = "1.37.0"
SHA256 = "3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4"
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "busybox"
SOURCE = WORK / "source"
ARCHIVE = WORK / f"busybox-{VERSION}.tar.bz2"
COMPAT = ROOT / "tools" / "busybox" / "compat"
LOG = WORK / "build.log"
STAMP = WORK / "config"
CONFIG = f"{VERSION} {SHA256} echo cat picolibc-v1\n"
OBJECTS = (
    "appletlib.o", "xfuncs_printf.o", "xfuncs.o", "full_write.o",
    "process_escape_sequence.o", "ptr_to_globals.o", "messages.o",
    "verror_msg.o", "compare_string_array.o", "xfunc_die.o",
    "perror_msg.o", "safe_write.o", "default_error_retval.o",
    "bb_cat.o", "copyfd.o", "getopt32.o", "wfopen_input.o",
    "read.o", "safe_strncpy.o", "llist.o", "xatonum.o",
    "get_last_path_component.o",
)


def run(*args: str, cwd: Path | None = None) -> None:
    with LOG.open("a") as log:
        result = subprocess.run(args, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        print("\n".join(LOG.read_text(errors="replace").splitlines()[-70:]))
        raise SystemExit(f"command failed: {' '.join(args)}")


def replace(path: Path, old: str, new: str) -> None:
    content = path.read_text()
    if content.count(old) != 1:
        raise SystemExit(f"expected one occurrence of {old!r} in {path}")
    path.write_text(content.replace(old, new))


def tool(name: str, brew_formula: str | None = None) -> Path:
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM, lld and GNU Make")
    return Path(found).resolve()


def main() -> None:
    if (STAMP.exists() and STAMP.read_text() == CONFIG
            and (SOURCE / "libbb/lib.a").exists()
            and (SOURCE / "coreutils/lib.a").exists()):
        print(f"BusyBox objects ready: {SOURCE}")
        return
    WORK.mkdir(parents=True, exist_ok=True)
    LOG.write_text("")
    if not ARCHIVE.exists():
        with urlopen(f"https://busybox.net/downloads/busybox-{VERSION}.tar.bz2") as response:
            ARCHIVE.write_bytes(response.read())
    if sha256(ARCHIVE.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("BusyBox source archive has an unexpected SHA-256")
    if SOURCE.exists():
        shutil.rmtree(SOURCE)
    run("tar", "-xjf", str(ARCHIVE), "-C", str(WORK))
    (WORK / f"busybox-{VERSION}").rename(SOURCE)
    replace(SOURCE / "include/platform.h",
            " || defined _NEWLIB_VERSION\n# include <features.h>",
            "\n# include <features.h>")
    replace(SOURCE / "include/libbb.h", '#include "platform.h"',
            '#include "platform.h"\n#ifdef _NEWLIB_VERSION\n'
            '#undef HAVE_UNLOCKED_STDIO\n#undef HAVE_UNLOCKED_LINE_OPS\n#endif')
    replace(SOURCE / "include/libbb.h", "#include <stdlib.h>",
            "#include <stdlib.h>\n#define utoa bb_utoa\n#define itoa bb_itoa")
    kbuild = SOURCE / "libbb/Kbuild.src"
    lines = [line for line in kbuild.read_text().splitlines()
             if not line.startswith("lib-y +=")]
    lines.append("lib-y += " + " ".join(OBJECTS))
    kbuild.write_text("\n".join(lines) + "\n")
    for source in (SOURCE / "libbb").glob("*.c"):
        content = source.read_text()
        if "//kbuild:lib-y +=" in content:
            source.write_text(content.replace("//kbuild:lib-y +=", "//disabled-kbuild:lib-y +="))
    run("make", "allnoconfig", cwd=SOURCE)
    config = SOURCE / ".config"
    replace(config, "# CONFIG_ECHO is not set", "CONFIG_ECHO=y")
    replace(config, "# CONFIG_CAT is not set", "CONFIG_CAT=y")
    replace(config, "# CONFIG_STATIC is not set", "CONFIG_STATIC=y")
    replace(config, "CONFIG_SH_IS_ASH=y", "# CONFIG_SH_IS_ASH is not set")
    replace(config, "# CONFIG_SH_IS_NONE is not set", "CONFIG_SH_IS_NONE=y")
    clang = tool("clang", "llvm")
    lld = tool("ld.lld", "lld")
    ar = tool("llvm-ar", "llvm")
    include = ROOT / "target/picolibc/root/usr/include"
    if not include.exists():
        raise SystemExit("build Picolibc with tools/build-picolibc.py first")
    run("make", "-j4", "libbb", "coreutils", f"CC={clang}", f"LD={lld}",
        f"AR={ar}", "HOSTCC=cc",
        "EXTRA_CFLAGS=" + " ".join(("--target=aarch64-none-elf", f"-I{COMPAT}",
            f"-I{include}", "-ffreestanding", "-fno-stack-protector",
            "-ffunction-sections", "-fdata-sections")), cwd=SOURCE)
    for archive in [SOURCE / "libbb/lib.a", SOURCE / "coreutils/lib.a"]:
        if not archive.exists():
            raise SystemExit(f"BusyBox did not produce {archive}")
    STAMP.write_text(CONFIG)
    print(f"BusyBox objects ready: {SOURCE}")


if __name__ == "__main__":
    main()
