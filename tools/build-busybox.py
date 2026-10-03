#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build pinned BusyBox objects for the stafeto guest probes, with
relibc's headers (target/relibc/sysroot, cargo xtask relibc) and the Linux
AArch64 C ABI they describe."""

from hashlib import sha256
import importlib.util
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
RELIBC = ROOT / "target" / "relibc" / "sysroot"
# Headers BusyBox includes on Linux that relibc lacks; searched after
# relibc's own (-idirafter).
COMPAT = ROOT / "tools" / "busybox" / "compat"
LOG = WORK / "build.log"
STAMP = WORK / "config"
# Cortex-A53 erratum 835769 (the PinePhone's A64): a nop between a memory
# access and a 64-bit multiply-accumulate. The objects go into a Rust
# program, whose aarch64-unknown-none link passes --fix-cortex-a53-843419.
A53_ERRATA = "-mfix-cortex-a53-835769"
# BusyBox's main becomes busybox_main: the probe's own C main, which relibc
# calls, chooses the applet and its arguments.
PATCH = "echo cat wc sleep ash ls-nofork relibc main-renamed a53-835769"


def relibc_commit() -> str:
    """The relibc commit tools/build-relibc.py pins, for the stamp."""
    spec = importlib.util.spec_from_file_location(
        "build_relibc", ROOT / "tools" / "build-relibc.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.COMMIT
OBJECTS = (
    "appletlib.o", "xfuncs_printf.o", "xfuncs.o", "full_write.o",
    "process_escape_sequence.o", "ptr_to_globals.o", "messages.o",
    "verror_msg.o", "compare_string_array.o", "xfunc_die.o",
    "perror_msg.o", "safe_write.o", "default_error_retval.o",
    "bb_cat.o", "copyfd.o", "getopt32.o", "wfopen_input.o",
    "read.o", "safe_strncpy.o", "llist.o", "xatonum.o",
    "get_last_path_component.o",
    "const_hack.o", "endofname.o", "bb_strtonum.o", "sysconf.o",
    "parse_mode.o", "time.o", "signals.o", "read_printf.o",
    "u_signal_names.o",
    "safe_poll.o", "single_argv.o",
    "common_bufsiz.o", "concat_path_file.o", "printable_string.o",
    "xreadlink.o", "mode_string.o",
    "last_char_is.o", "auto_string.o",
    "vfork_daemon_rexec.o",
    "wfopen.o", "fclose_nonstdin.o", "fflush_stdout_and_exit.o",
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
    headers = sorted(COMPAT.rglob("*.h"))
    compatibility = sha256(b"".join(path.read_bytes() for path in headers)).hexdigest()
    config_stamp = f"{VERSION} {SHA256} {PATCH} {sha256(" ".join(OBJECTS).encode()).hexdigest()} {compatibility} relibc {relibc_commit()}\n"
    if (STAMP.exists() and STAMP.read_text() == config_stamp
            and (SOURCE / "libbb/lib.a").exists()
            and (SOURCE / "coreutils/lib.a").exists()
            and (SOURCE / "shell/lib.a").exists()):
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
    replace(SOURCE / "coreutils/ls.c",
            "APPLET_NOEXEC(ls, ls, BB_DIR_BIN, BB_SUID_DROP, ls)",
            "APPLET_NOFORK(ls, ls, BB_DIR_BIN, BB_SUID_DROP, ls)")
    # relibc next to the other C libraries of platform.h: the glibc
    # extensions it lacks, alloca from its own header, and the declaration
    # of settimeofday, which libbb's xsettimeofday names and no probe calls.
    replace(SOURCE / "include/platform.h",
            "#if defined(ANDROID) || defined(__ANDROID__)\n# if __ANDROID_API__ < 8",
            "#if defined(__RELIBC__)\n# include <alloca.h>\n# undef HAVE_CLEARENV\n"
            "# undef HAVE_MEMPCPY\n# undef HAVE_STRVERSCMP\n# undef HAVE_UNLOCKED_STDIO\n"
            "# undef HAVE_UNLOCKED_LINE_OPS\nstruct timeval;\nstruct timezone;\n"
            "int settimeofday(const struct timeval *, const struct timezone *);\n#endif\n\n"
            "#if defined(ANDROID) || defined(__ANDROID__)\n# if __ANDROID_API__ < 8")
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
    replace(config, "# CONFIG_LS is not set", "CONFIG_LS=y")
    replace(config, "# CONFIG_WC is not set", "CONFIG_WC=y")
    replace(config, "# CONFIG_SLEEP is not set", "CONFIG_SLEEP=y")
    replace(config, "# CONFIG_SHOW_USAGE is not set", "CONFIG_SHOW_USAGE=y")
    replace(config, "# CONFIG_FEATURE_VERBOSE_USAGE is not set",
            "CONFIG_FEATURE_VERBOSE_USAGE=y")
    replace(config, "# CONFIG_FEATURE_CLEAN_UP is not set", "CONFIG_FEATURE_CLEAN_UP=y")
    replace(config, "# CONFIG_ASH is not set", "CONFIG_ASH=y")
    replace(config, "# CONFIG_ASH_ECHO is not set", "CONFIG_ASH_ECHO=y")
    replace(config, "# CONFIG_FEATURE_SH_STANDALONE is not set",
            "CONFIG_FEATURE_SH_STANDALONE=y")
    replace(config, "# CONFIG_FEATURE_SH_NOFORK is not set",
            "CONFIG_FEATURE_SH_NOFORK=y")
    replace(config, "# CONFIG_STATIC is not set", "CONFIG_STATIC=y")
    replace(config, "CONFIG_SH_IS_ASH=y", "# CONFIG_SH_IS_ASH is not set")
    replace(config, "# CONFIG_SH_IS_NONE is not set", "CONFIG_SH_IS_NONE=y")
    clang = tool("clang", "llvm")
    lld = tool("ld.lld", "lld")
    ar = tool("llvm-ar", "llvm")
    include = RELIBC / "include"
    if not (include / "stdio.h").exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    run("make", "-j4", "libbb", "coreutils", "shell", f"CC={clang}", f"LD={lld}",
        f"AR={ar}", "HOSTCC=cc",
        "EXTRA_CFLAGS=" + " ".join(("--target=aarch64-linux-gnu", "-nostdinc",
            f"-isystem {include}", f"-idirafter {COMPAT}", "-mno-outline-atomics", "-fno-stack-protector",
            "-ffunction-sections", "-fdata-sections", "-Dmain=busybox_main",
            A53_ERRATA)), cwd=SOURCE)
    for archive in [SOURCE / "libbb/lib.a", SOURCE / "coreutils/lib.a",
                    SOURCE / "shell/lib.a"]:
        if not archive.exists():
            raise SystemExit(f"BusyBox did not produce {archive}")
    STAMP.write_text(config_stamp)
    print(f"BusyBox objects ready: {SOURCE}")


if __name__ == "__main__":
    main()
