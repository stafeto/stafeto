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

import pkgdesc


PACKAGE = pkgdesc.load("busybox")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
ROOT = Path(__file__).resolve().parents[1]
# Two builds of the same source: the one the probes use (the applets they
# run) and the one of the shell image of the utilities (the applets of XCU),
# which is much bigger: it carries the time zone data of relibc that date and
# the others pull in.
WORK = ROOT / "target" / "busybox"
WORK_UTILITIES = ROOT / "target" / "busybox-utils"
# The ready-made utilities BusyBox lacks (tools/build-ready-utils.py), built
# from their own sources apart from BusyBox's and linked with its second build.
WORK_READY = ROOT / "target" / "ready-utils"
SOURCE = WORK / "source"
ARCHIVE = WORK / f"busybox-{VERSION}.tar.bz2"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
# Headers BusyBox includes on Linux that relibc lacks; searched after
# relibc's own (-idirafter).
COMPAT = ROOT / "tools" / "busybox" / "compat"
# BusyBox sources of our own, copied into the tree by directory: the
# applet login-probe, which the tests of getlogin and utmpx run.
OWN = ROOT / "tools" / "busybox" / "stafeto"
LOG = WORK / "build.log"
STAMP = WORK / "config"
# Cortex-A53 erratum 835769 (the PinePhone's A64): a nop between a memory
# access and a 64-bit multiply-accumulate. The objects go into a Rust
# program, whose aarch64-unknown-none link passes --fix-cortex-a53-843419.
A53_ERRATA = "-mfix-cortex-a53-835769"
# Keep compiler-generated async rows for C frames; outlining is reserved
# for the native Rust policy, whose helper rows the linker validates.
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")
# BusyBox's main becomes applets_main: the probe's own C main, which relibc
# calls, chooses the applet and its arguments.
PATCH = "utilities echo cat wc sleep head-c mktemp ash-random ash-job-control ash-builtins ash-interruptible-traps names-nofork-cat math test printf getopts alias command kill ash ls-nofork relibc main-renamed a53-835769 sockets nc timeout"


def relibc_commit() -> str:
    """The relibc commit tools/build-relibc.py pins, for the stamp."""
    spec = importlib.util.spec_from_file_location(
        "build_relibc", ROOT / "tools" / "build-relibc.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.COMMIT
# libbb keeps BusyBox's own list of objects (alloc_affinity.o, the one that
# reads the mask of sched_getaffinity, is among them: nproc and taskset
# use it); objects a program does not name stay out of the link.
# Nothing of BusyBox's own is written here: an applet BusyBox lacks is not
# provided (login-probe, the guest test of the C library, is the exception).
EXCLUDED_OBJECTS = ()
# The small build keeps the objects of libbb it always had: the others pull
# in more of relibc (syslog, and with it the time zone data) than the probes
# have room for.
BASE_OBJECTS = (
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
    "safe_poll.o", "single_argv.o", "skip_whitespace.o", "bb_getgroups.o",
    "common_bufsiz.o", "concat_path_file.o", "printable_string.o",
    "xreadlink.o", "mode_string.o",
    "last_char_is.o", "auto_string.o",
    "vfork_daemon_rexec.o",
    "wfopen.o", "fclose_nonstdin.o", "fflush_stdout_and_exit.o",
    "perror_nomsg_and_die.o", "get_line_from_file.o",
    # The applets on names (mv, rm, mkdir, ln, readlink).
    "ask_confirmation.o", "make_directory.o", "copy_file.o", "inode_hash.o",
    "concat_subpath_file.o", "isdirectory.o", "recursive_action.o", "xgetcwd.o",
    "remove_file.o",
    # nc: connections over the loopback of the socket service.
    "xconnect.o", "inet_common.o", "executable.o", "bb_do_delay.o",
)

# The directories BusyBox's archives come from; build.rs links each.
DIRECTORIES = ("libbb", "coreutils", "coreutils/libcoreutils", "shell", "procps",
               "networking", "archival", "archival/libarchive", "editors",
               "findutils", "miscutils", "util-linux", "sysklogd", "libpwdgrp",
               "console-tools")


# The CONFIG names of the XCU utilities BusyBox has and the shell does not
# hold, those of our own applets, and the features their pages ask for.
OWN_CONFIGS = tuple(sorted(
    line.rsplit(" ", 1)[-1].strip()
    for source in (ROOT / "tools" / "busybox" / "stafeto").rglob("*.c")
    for line in source.read_text().splitlines()
    if line.startswith("//config:config ")))
UTILITIES = tuple(name.upper() for name in (
    "awk basename bc chgrp chmod chown cksum cmp comm cp crontab cut date dd df diff dirname "
    "du ed env expand expr false find fold grep head id kill ln logger logname mesg mkdir "
    "mkfifo mv nice nohup od paste patch printf pwd readlink realpath renice rm rmdir sed "
    "sleep sort split strings stty tail tee test time timeout touch tr true tsort tty uname "
    "uncompress unexpand uniq uudecode uuencode xargs zcat busybox desktop ps feature_ps_wide feature_ps_long feature_ps_time feature_ps_additional_columns feature_ls_username feature_seamless_z feature_seamless_gz "
    "feature_mtab_support feature_awk_libm feature_awk_gnu_extensions feature_date_compat "
    "feature_date_isofmt feature_date_nano feature_dd_ibs_obs feature_dd_status feature_df_fancy "
    "feature_diff_dir feature_find_amin feature_find_atime "
    "feature_find_cmin feature_find_ctime feature_find_delete feature_find_depth "
    "feature_find_empty feature_find_exec feature_find_exec_ok feature_find_exec_plus "
    "feature_find_executable feature_find_group feature_find_inum feature_find_links "
    "feature_find_maxdepth feature_find_mmin feature_find_mtime feature_find_newer "
    "feature_find_not feature_find_paren feature_find_path feature_find_perm "
    "feature_find_print0 feature_find_prune feature_find_quit feature_find_regex "
    "feature_find_samefile feature_find_size feature_find_type feature_find_user "
    "feature_find_xdev feature_grep_context feature_readlink_follow feature_sort_big "
    "feature_split_fancy feature_test_64 feature_touch_susv3 feature_tr_classes "
    "feature_tr_equiv feature_xargs_support_args_file feature_xargs_support_confirmation "
    "feature_xargs_support_quotes feature_xargs_support_repl_str feature_xargs_support_termopt "
    "feature_xargs_support_zero_term feature_preserve_hardlinks feature_human_readable "
    # The features BusyBox's defconfig turns on for these utilities and that
    # fit the layer. ls sorts its names, shows the times (-c -t -u, the date of
    # -l), marks the types (-F -p), follows links (-H -L) and recurses (-R);
    # -w and -T take the width;
    # du counts in 1K blocks; the others are the usual extras of cat, cp,
    # cut, dd, echo, mesg, sleep, tail, tee, wc, xargs and ash's arithmetic.
    "feature_ls_sortfiles feature_ls_timestamps feature_ls_filetypes "
    "feature_ls_followlinks feature_ls_recursive feature_ls_width "
    "feature_du_default_blocksize_1k feature_fancy_echo feature_fancy_sleep "
    "feature_fancy_tail feature_catn feature_catv feature_cut_regex "
    "feature_dd_signal_handling feature_dd_third_status_line "
    "feature_tee_use_block_io feature_wc_large feature_xargs_support_parallel "
    "feature_mesg_enable_only_group feature_bc_interactive feature_sh_math_64 "
    "feature_sh_math_base feature_sh_read_frac feature_sh_histfilesize "
    # The size of the window and the table of processes: resize asks
    # the terminal for its size, top reads /proc/stat, meminfo, loadavg
    # and the files of each process.
    "resize feature_resize_print top feature_top_cpu_usage_percentage feature_top_cpu_global_percents "
    "feature_top_interactive "
    # The CPUs: nproc counts the mask of sched_getaffinity, taskset reads and
    # sets it (-p, -c and a command to run under a mask).
    "nproc taskset feature_taskset_fancy feature_taskset_cpulist "
    "").split()) + OWN_CONFIGS


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
    return Path(found).absolute()


def ready_utilities() -> None:
    """The archive of getconf, join, pathchk, file, iconv and compress, whose
    flags are those of BusyBox's objects."""
    spec = importlib.util.spec_from_file_location(
        "build_ready_utils", ROOT / "tools" / "build-ready-utils.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.build(WORK_READY, WORK_READY / "ready.a", [A53_ERRATA, *UNWIND_CFLAGS],
                 RELIBC / "include", f"relibc {relibc_commit()}")


def main() -> None:
    build(utilities=False)
    build(utilities=True)
    ready_utilities()


def build(utilities: bool) -> None:
    global SOURCE, LOG, STAMP
    work = WORK_UTILITIES if utilities else WORK
    SOURCE, LOG, STAMP = work / "source", work / "build.log", work / "config"
    names = UTILITIES if utilities else ()
    headers = sorted(COMPAT.rglob("*.h"))
    compatibility = sha256(b"".join(path.read_bytes() for path in headers)).hexdigest()
    # The script is part of the stamp: a patch it makes changes the objects.
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    own = sorted(OWN.rglob("*.c")) if utilities else []
    own_sources = sha256(b"".join(path.read_bytes() for path in own)).hexdigest()
    config_stamp = f"{VERSION} {SHA256} {PATCH} {sha256(" ".join(EXCLUDED_OBJECTS + BASE_OBJECTS + DIRECTORIES + names).encode()).hexdigest()} {compatibility} {own_sources} {script} relibc {relibc_commit()} unwind {" ".join(UNWIND_CFLAGS)}\n"
    if (STAMP.exists() and STAMP.read_text() == config_stamp
            and all((SOURCE / d / "lib.a").exists() for d in DIRECTORIES)):
        print(f"BusyBox objects ready: {SOURCE}")
        return
    work.mkdir(parents=True, exist_ok=True)
    LOG.write_text("")
    if not ARCHIVE.exists():
        with urlopen(PACKAGE["url"]) as response:
            ARCHIVE.write_bytes(response.read())
    if sha256(ARCHIVE.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("BusyBox source archive has an unexpected SHA-256")
    if SOURCE.exists():
        shutil.rmtree(SOURCE)
    run("tar", "-xjf", str(ARCHIVE), "-C", str(work))
    (work / f"busybox-{VERSION}").rename(SOURCE)
    # The small build of the probes has no process to fork for these
    # applets, so they run inside ash without a fork. The shell image forks
    # them like BusyBox does: an applet that runs in the shell leaves its
    # state in bb_common_bufsiz1 (ls, cat -v), and the applets the shell
    # forks (ps) start from a buffer they take for zero.
    if not utilities:
        replace(SOURCE / "coreutils/cat.c",
                "APPLET(cat, BB_DIR_BIN, BB_SUID_DROP)",
                "APPLET_NOFORK(cat, cat, BB_DIR_BIN, BB_SUID_DROP, cat)")
        for applet in ("ls", "mv", "rm", "ln", "chmod"):
            replace(SOURCE / f"coreutils/{applet}.c",
                    f"APPLET_NOEXEC({applet}, {applet}, BB_DIR_BIN, BB_SUID_DROP, {applet})",
                    f"APPLET_NOFORK({applet}, {applet}, BB_DIR_BIN, BB_SUID_DROP, {applet})")
    # relibc next to the other C libraries of platform.h: the glibc
    # extensions it lacks, alloca from its own header, and the declaration
    replace(SOURCE / "include/platform.h",
            "#if defined(ANDROID) || defined(__ANDROID__)\n# if __ANDROID_API__ < 8",
            "#if defined(__RELIBC__)\n# define _PATH_TTY \"/dev/tty\"\n# include <alloca.h>\n# undef HAVE_CLEARENV\n"
            "# undef HAVE_MEMPCPY\n# undef HAVE_STRVERSCMP\n# undef HAVE_UNLOCKED_STDIO\n"
            "# undef HAVE_UNLOCKED_LINE_OPS\n#endif\n\n"
            "#if defined(ANDROID) || defined(__ANDROID__)\n# if __ANDROID_API__ < 8")
    # Interactive input returns to ash's trap evaluation after a signal.
    # The terminal service supplies canonical input with Editing disabled.
    replace(SOURCE / "shell/ash.c",
            "#else\n\tnr = nonblock_immune_read(g_parsefile->pf_fd, buf, IBUFSIZ - 1);\n#endif",
            "#else\n"
            "# if defined(__RELIBC__)\n"
            "\tif (iflag && g_parsefile->pf_fd == STDIN_FILENO) {\n"
            "\t\tstruct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };\n"
            "\t\tfor (;;) {\n"
            "\t\t\tif (pending_sig && trap[pending_sig]) {\n"
            "\t\t\t\tbuf[0] = '\\n';\n"
            "\t\t\t\tbuf[1] = '\\0';\n"
            "\t\t\t\treturn 1;\n"
            "\t\t\t}\n"
            "\t\t\tnr = read(STDIN_FILENO, buf, IBUFSIZ - 1);\n"
            "\t\t\tif (nr <= 0 && pending_sig && trap[pending_sig]) {\n"
            "\t\t\t\tbuf[0] = '\\n';\n"
            "\t\t\t\tbuf[1] = '\\0';\n"
            "\t\t\t\treturn 1;\n"
            "\t\t\t}\n"
            "\t\t\tif (nr < 0 && errno == EAGAIN) {\n"
            "\t\t\t\tif (poll(&pfd, 1, -1) < 0 && errno != EINTR)\n"
            "\t\t\t\t\treturn -1;\n"
            "\t\t\t\tcontinue;\n"
            "\t\t\t}\n"
            "\t\t\tif (nr >= 0 || errno != EINTR)\n"
            "\t\t\t\tbreak;\n"
            "\t\t}\n"
            "\t} else\n"
            "# endif\n"
            "\t\tnr = nonblock_immune_read(g_parsefile->pf_fd, buf, IBUFSIZ - 1);\n"
            "#endif")
    # Our own applets and library functions go into the directory of the
    # same name, where BusyBox's build finds their //applet: and //kbuild:
    # lines like any other source.
    for source in own:
        shutil.copy(source, SOURCE / source.relative_to(OWN))
    kbuild = SOURCE / "libbb/Kbuild.src"
    if utilities:
        dropped = {f"lib-y += {name}" for name in EXCLUDED_OBJECTS}
        kbuild.write_text("\n".join(
            line for line in kbuild.read_text().splitlines() if line.strip() not in dropped) + "\n")
    else:
        lines = [line for line in kbuild.read_text().splitlines()
                 if not line.startswith("lib-y +=")]
        lines.append("lib-y += " + " ".join(BASE_OBJECTS))
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
    # The applets on names (5i-5): move, remove, make and remove a
    # directory, link, change the mode, touch, read a link.
    for name in ("MV", "RM", "MKDIR", "RMDIR", "LN", "CHMOD", "TOUCH", "READLINK"):
        replace(config, f"# CONFIG_{name} is not set", f"CONFIG_{name}=y")
    replace(config, "# CONFIG_WC is not set", "CONFIG_WC=y")
    replace(config, "# CONFIG_SLEEP is not set", "CONFIG_SLEEP=y")
    # timeout, and nc with its server and its -e.
    for name in ("TIMEOUT", "NC", "NC_SERVER", "NC_EXTRA"):
        replace(config, f"# CONFIG_{name} is not set", f"CONFIG_{name}=y")
    # The applets that take bytes or names from the random devices (5e').
    replace(config, "# CONFIG_HEAD is not set", "CONFIG_HEAD=y")
    replace(config, "# CONFIG_FEATURE_FANCY_HEAD is not set", "CONFIG_FEATURE_FANCY_HEAD=y")
    replace(config, "# CONFIG_MKTEMP is not set", "CONFIG_MKTEMP=y")
    replace(config, "# CONFIG_ASH_RANDOM_SUPPORT is not set", "CONFIG_ASH_RANDOM_SUPPORT=y")
    replace(config, "# CONFIG_SHOW_USAGE is not set", "CONFIG_SHOW_USAGE=y")
    replace(config, "# CONFIG_FEATURE_VERBOSE_USAGE is not set",
            "CONFIG_FEATURE_VERBOSE_USAGE=y")
    replace(config, "# CONFIG_FEATURE_CLEAN_UP is not set", "CONFIG_FEATURE_CLEAN_UP=y")
    replace(config, "# CONFIG_ASH is not set", "CONFIG_ASH=y")
    replace(config, "# CONFIG_ASH_ECHO is not set", "CONFIG_ASH_ECHO=y")
    replace(config, "# CONFIG_ASH_JOB_CONTROL is not set", "CONFIG_ASH_JOB_CONTROL=y")
    for name in ("FEATURE_SH_MATH", "ASH_TEST", "ASH_PRINTF", "ASH_GETOPTS",
                 "ASH_ALIAS", "ASH_CMDCMD"):
        replace(config, f"# CONFIG_{name} is not set", f"CONFIG_{name}=y")
    replace(config, "# CONFIG_KILL is not set", "CONFIG_KILL=y")
    # The line editor of the interactive shell, in the build of the shell
    # image only: the small build of the probes has no room for it (the
    # quota of a test of os-test holds the shell of popen with 10% to
    # spare). Cursor keys, Home, End, Delete, Ctrl-A/E/K/U/W, history with
    # Ctrl-R search, Tab completion of names and the escapes of PS1. The
    # terminal answers TIOCGWINSZ with a screen of 0 by 0 and BusyBox reads
    # that as unknown: the editor and ls take the 80 by 24 of its default
    # (or the sizes of LINES and COLUMNS).
    if utilities:
        replace(config, "# CONFIG_FEATURE_EDITING is not set", "CONFIG_FEATURE_EDITING=y")
        replace(config, "CONFIG_FEATURE_EDITING_MAX_LEN=0", "CONFIG_FEATURE_EDITING_MAX_LEN=1024")
        replace(config, "CONFIG_FEATURE_EDITING_HISTORY=0", "CONFIG_FEATURE_EDITING_HISTORY=255")
        for name in ("FEATURE_REVERSE_SEARCH", "FEATURE_TAB_COMPLETION",
                     "FEATURE_EDITING_FANCY_PROMPT", "FEATURE_EDITING_WINCH"):
            replace(config, f"# CONFIG_{name} is not set", f"CONFIG_{name}=y")
    # The utilities of XCU that BusyBox has, with the features their
    # pages ask for; ps is the BusyBox one, over the /proc of the layer.
    for name in names:
        text = config.read_text()
        if f"# CONFIG_{name} is not set" in text:
            config.write_text(text.replace(f"# CONFIG_{name} is not set", f"CONFIG_{name}=y"))
        elif f"CONFIG_{name}=y" not in text:
            raise SystemExit(f"BusyBox has no CONFIG_{name}")
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
    run("make", "-j4", *[d + "/" for d in DIRECTORIES], f"CC={clang}", f"LD={lld}",
        f"AR={ar}", "HOSTCC=cc",
        "EXTRA_CFLAGS=" + " ".join(("--target=aarch64-linux-gnu", "-nostdinc",
            f"-isystem {include}", f"-idirafter {COMPAT}", "-mno-outline-atomics", "-fno-stack-protector",
            "-ffunction-sections", "-fdata-sections", "-Dmain=applets_main",
            A53_ERRATA, *UNWIND_CFLAGS,
            # clang reads a global that is const only once, before BusyBox sets
            # ptr_to_globals (awk, among others, then ran with a null pointer).
            *(("-DBB_GLOBAL_CONST=",) if utilities else ()))), cwd=SOURCE)
    for archive in [SOURCE / d / "lib.a" for d in DIRECTORIES]:
        if not archive.exists():
            raise SystemExit(f"BusyBox did not produce {archive}")
    STAMP.write_text(config_stamp)
    print(f"BusyBox objects ready: {SOURCE}")


if __name__ == "__main__":
    main()
