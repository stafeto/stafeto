#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build nginx for the images with the network service (`/bin/nginx`) from
its release archive, with PCRE2 from its own, against relibc's headers and
the Linux AArch64 C ABI they describe.

nginx's `configure` runs with the cross compiler of the project (clang and
lld) for Linux (`--crossbuild=Linux::aarch64`). It compiles small probes and
runs some of them; a program of the target does not run here, so the
script applies tools/nginx/cross-autotest.patch (the three files of
`configure` that run a probe ask NGX_AUTOTEST_ANSWER) and
tools/nginx/autotest-answer.py answers: sizes and the byte order from the
compiler, every other probe from its table with a reason. A probe the table
does not know stops the build. No other file of nginx changes. Every step
compiles with target/nginx/cc, clang for the target with relibc's headers
alone, so that the probes see the same headers on any host.

The modules of TLS (`http_ssl_module`) and HTTP/2 (`http_v2_module`) are in.
OpenSSL is the static one of tools/build-openssl.py, found by `-I` and `-L`
(target/openssl/install): `--with-openssl` would make nginx run OpenSSL's
own `config` for the machine of the build. `configure` then checks the
library with a compile and a link of `SSL_CTX_set_options`, a probe that
does not run.

PCRE2 is built by nginx's own Makefile from its source tree, 8-bit, static,
without JIT (JIT needs memory that is writable and executable at once, which
the layer refuses). The gzip module is left out, as are threads, file AIO
and the stream module.

Two lines of the Makefile `configure` writes change: PCRE2's own
`configure` gets the options of a build for another machine (nginx's
`configure` has no option that passes them), and the link of objs/nginx
becomes a relocatable one. The result is one relocatable object,
target/nginx/nginx.o (nginx's objects, libpcre2-8.a, and OpenSSL's
libssl.a and libcrypto.a), that exports `main` alone: the names of nginx's own
helpers cannot meet relibc's or the program's. tools/build-libc-so.py
programs links it against libc.so. The answers given are in
target/nginx/autotest-answers.txt.

nginx is BSD-2-Clause and PCRE2 BSD-3-Clause with the PCRE2 exception: the
archives are fetched at build time with their SHA-256 checked, and the
image's licence notices name both and OpenSSL's (Apache-2.0)."""

from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from urllib.request import urlopen

import pkgdesc

import importlib.util


NGINX = pkgdesc.load("nginx")
PCRE2 = pkgdesc.load("pcre2")
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "nginx"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
# The headers and static archives of tools/build-openssl.py.
OPENSSL = ROOT / "target" / "openssl" / "install"
SSL_ARCHIVES = (OPENSSL / "lib" / "libssl.a", OPENSSL / "lib" / "libcrypto.a")
HERE = ROOT / "tools" / "nginx"
PATCH = HERE / "cross-autotest.patch"
ANSWER = HERE / "autotest-answer.py"
# Headers nginx includes on Linux that relibc lacks, searched after relibc's
# own (-idirafter); none so far.
COMPAT = HERE / "compat"
OUTPUT = WORK / "nginx.o"
UNKNOWN = WORK / "autotest-unknown.txt"
ANSWERS = WORK / "autotest-answers.txt"
# Cortex-A53 erratum 835769 (the PinePhone's A64), as BusyBox's objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
# Compiler-generated async unwind rows for C frames; no outlining
# (the native Rust policy owns it).
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")
# `--crossbuild` makes configure take the machine for i386: the alignment
# and the cache line of AArch64 (auto/os/conf) are given here, and its
# `#ifndef` keeps them.
MACHINE = ("-DNGX_ALIGNMENT=16", "-DNGX_CPU_CACHE_LINE=64")
CONFIGURE = (
    "--crossbuild=Linux::aarch64",
    "--prefix=/", "--sbin-path=/bin/nginx", "--conf-path=/etc/nginx/nginx.conf",
    "--pid-path=/var/run/nginx.pid", "--lock-path=/var/run/nginx.lock",
    "--error-log-path=/var/log/nginx/error.log", "--http-log-path=/var/log/nginx/access.log",
    "--http-client-body-temp-path=/var/lib/nginx/body",
    "--http-proxy-temp-path=/var/lib/nginx/proxy",
    "--http-fastcgi-temp-path=/var/lib/nginx/fastcgi",
    "--http-uwsgi-temp-path=/var/lib/nginx/uwsgi",
    "--http-scgi-temp-path=/var/lib/nginx/scgi",
    "--user=nobody", "--group=nobody",
    "--without-http_gzip_module",
    "--with-http_ssl_module", "--with-http_v2_module",
)
# --build differs from --host on every host on purpose, the Linux runner of
# ci too: autoconf takes the build for a cross one only when the two differ,
# and else tries to run a program of the target and fails.
PCRE2_CONFIGURE = ("--host=aarch64-linux-gnu", "--build=aarch64-apple-darwin", "--disable-jit",
                   "--disable-shared", "--disable-pcre2grep-libz", "--disable-pcre2grep-libbz2")


def tool(name: str, brew_formula: str | None = None) -> Path:
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM, lld and GNU Make")
    return Path(found).absolute()


def run(log: Path, *args, cwd: Path | None = None, env: dict | None = None,
        stdin: Path | None = None) -> None:
    with log.open("a") as out:
        out.write("$ " + " ".join(map(str, args)) + "\n")
        out.flush()
        with (stdin.open("rb") if stdin else open(os.devnull, "rb")) as given:
            result = subprocess.run([str(a) for a in args], cwd=cwd, stdout=out, stdin=given,
                                    stderr=subprocess.STDOUT, env=env)
    if result.returncode:
        print("\n".join(log.read_text(errors="replace").splitlines()[-60:]))
        raise SystemExit(f"command failed: {' '.join(map(str, args))}")


def ncurses_module():
    spec = importlib.util.spec_from_file_location(
        "build_ncurses", ROOT / "tools" / "build-ncurses.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fetch(description: dict, archive: Path) -> None:
    with urlopen(description["url"]) as response:
        archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != description["sha256"]:
        raise SystemExit(f"{description['name']} source archive has an unexpected SHA-256")


def relocatable_link(makefile: Path) -> None:
    """The recipe of `objs/nginx` in nginx's Makefile made a relocatable
    link of the same objects, PCRE2's archive and OpenSSL's two: the Rust
    program links relibc and the crt. The recipe must be found exactly once,
    ask OpenSSL's libraries exactly once (they become the paths of the
    archives) and name no other library."""
    lines = makefile.read_text().split("\n")
    heads = [i for i, line in enumerate(lines) if line.startswith("objs/nginx:")]
    if len(heads) != 1:
        raise SystemExit(f"{makefile}: {len(heads)} rules of objs/nginx")
    # The prerequisites go on over lines that end in a backslash.
    recipe = heads[0]
    while lines[recipe].endswith("\\"):
        recipe += 1
    recipe += 1
    while lines[recipe].strip() == "":
        recipe += 1
    if not lines[recipe].startswith("\t$(LINK) -o objs/nginx"):
        raise SystemExit(f"{makefile}: the link of objs/nginx is {lines[recipe]!r}")
    lines[recipe] = lines[recipe].replace("$(LINK)", "$(CC) -nostdlib -r", 1)
    end = recipe
    while lines[end].endswith("\\"):
        end += 1
    asked = " -lssl -lcrypto"
    found = sum(lines[i].count(asked) for i in range(recipe, end + 1))
    if found != 1:
        raise SystemExit(f"{makefile}: the link of objs/nginx asks OpenSSL {found} times")
    for i in range(recipe, end + 1):
        lines[i] = lines[i].replace("-Wl,-E", "").replace(f"-L{OPENSSL / 'lib'}", "")
        lines[i] = lines[i].replace(asked, "".join(f" {archive}" for archive in SSL_ARCHIVES))
        if " -l" in lines[i]:
            raise SystemExit(f"{makefile}: the link of objs/nginx asks a library: {lines[i]!r}")
    makefile.write_text("\n".join(lines))


def compiler(path: Path, clang: Path, lld: Path, stub: Path) -> None:
    """The compiler nginx's configure and Makefile and PCRE2's configure
    call: clang for the target with relibc's headers and libraries only
    (the sysroot is relibc's, so a Linux host's own libraries stay out of
    the default search of the linker), so that every probe (auto/include
    too, which passes no flags of its own) sees the target's on any host. A link of a program (no -c, -E, -S, -M,
    -r, -v, -fsyntax-only) gets relibc and the stubs, as the probes of the
    other packages' `configure` do; the program never runs."""
    path.write_text(f"""#!/bin/sh
# Written by tools/build-nginx.py.
link=yes
for arg in "$@"; do
    case "$arg" in
        -c|-E|-S|-M|-MM|-r|-v|--version|-fsyntax-only) link=no ;;
    esac
done
set -- --target=aarch64-linux-gnu --sysroot={RELIBC} -Qunused-arguments --ld-path={lld} \\
    -nostdinc -isystem {RELIBC / 'include'} -idirafter {COMPAT} "$@"
if [ $link = yes ]; then
    set -- "$@" -static -nostdlib -L{RELIBC / 'lib'} {stub} -lc
fi
exec {clang} "$@"
""")
    path.chmod(0o755)


def pcre2_options(makefile: Path) -> None:
    """The options of PCRE2's `configure` in nginx's Makefile: nginx's
    `configure` has no option for them. The line must be found exactly once."""
    text = makefile.read_text()
    line = "./configure --disable-shared"
    if text.count(line) != 1:
        raise SystemExit(f"{makefile}: {text.count(line)} runs of PCRE2's configure")
    makefile.write_text(text.replace(line, f"{line} {' '.join(PCRE2_CONFIGURE)}"))


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    libc = RELIBC / "lib" / "libc.a"
    if not (RELIBC / "include" / "stdio.h").exists() or not libc.exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    if not all(archive.exists() for archive in SSL_ARCHIVES):
        raise SystemExit("build OpenSSL with tools/build-openssl.py first")
    stamp = WORK / "stamp"
    text = " ".join((NGINX["version"], NGINX["sha256"], PCRE2["version"], PCRE2["sha256"], script,
                     *(sha256(p.read_bytes()).hexdigest()
                       for p in (PATCH, ANSWER, libc, *SSL_ARCHIVES)))) + "\n"
    if stamp.exists() and stamp.read_text() == text and OUTPUT.exists():
        print(f"nginx ready: {OUTPUT}")
        return
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    for description in (NGINX, PCRE2):
        archive = WORK / f"{description['name']}-{description['version']}.tar.gz"
        fetch(description, archive)
        with tarfile.open(archive) as members:
            members.extractall(WORK, filter="data")
    source = WORK / f"nginx-{NGINX['version']}"
    pcre2 = WORK / f"pcre2-{PCRE2['version']}"
    run(log, "patch", "-p1", "--forward", cwd=source, stdin=PATCH)
    clang, lld = tool("clang", "llvm"), tool("ld.lld", "lld")
    objcopy, nm = tool("llvm-objcopy", "llvm"), tool("llvm-nm", "llvm")
    ar, ranlib = tool("llvm-ar", "llvm"), tool("llvm-ranlib", "llvm")
    stub = WORK / "stubs.o"
    ncurses_module().stubs(log, clang, nm, libc, stub)
    cc = WORK / "cc"
    compiler(cc, clang, lld, stub)
    flags = " ".join(("-mno-outline-atomics", "-fno-stack-protector", "-ffunction-sections",
                      "-fdata-sections", A53_ERRATA, "-fPIC", *UNWIND_CFLAGS, "-Os"))
    UNKNOWN.write_text("")
    ANSWERS.write_text("")
    env = dict(os.environ,
               NGX_AUTOTEST_ANSWER=f"{sys.executable} -I {ANSWER}",
               NGX_AUTOTEST_CC=f"{cc} {flags} -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64",
               NGX_AUTOTEST_UNKNOWN=str(UNKNOWN), NGX_AUTOTEST_LOG=str(ANSWERS),
               AR=str(ar), RANLIB=str(ranlib))
    run(log, "./configure", *CONFIGURE,
        f"--with-cc={cc}",
        f"--with-cc-opt={flags} {' '.join(MACHINE)} -I{OPENSSL / 'include'} -Wno-error",
        f"--with-ld-opt=-L{OPENSSL / 'lib'}",
        f"--with-pcre={pcre2}", f"--with-pcre-opt={flags}",
        cwd=source, env=env)
    unknown = UNKNOWN.read_text().split("\n")
    if any(unknown):
        raise SystemExit(f"nginx: configure ran probes the answers do not know: "
                         f"{', '.join(n for n in unknown if n)} (tools/nginx/autotest-answer.py)")
    makefile = source / "objs" / "Makefile"
    pcre2_options(makefile)
    relocatable_link(makefile)
    run(log, "make", "-j4", "-f", "objs/Makefile", "objs/nginx", cwd=source, env=env)
    OUTPUT.unlink(missing_ok=True)
    # nginx's configure compiles with -g; the image needs no debug sections.
    run(log, objcopy, "--keep-global-symbol=main", "--strip-debug", source / "objs" / "nginx",
        OUTPUT)
    stamp.write_text(text)
    print(f"nginx ready: {OUTPUT}")


if __name__ == "__main__":
    main()
