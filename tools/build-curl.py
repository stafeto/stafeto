#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build curl for the images with the network service (`/bin/curl`) from its
release archive, unchanged, against relibc's headers and the Linux AArch64 C
ABI they describe, and against the OpenSSL of tools/build-openssl.py.

curl's own `configure` runs with the cross compiler of the project (clang
and lld) and the Linux platform (the host triple names it). The protocols
are file, HTTP and HTTPS; the CA file is the bundle of the image
(/etc/ssl/certs/ca-certificates.crt, the package ca-bundle). The resolver
runs on a thread: a time limit (`-m`, `--connect-timeout`) then needs no
SIGALRM and long jump out of the resolver of the C library. There is no
IPv6 (the network service has none) and no HTTP/2 (no nghttp2). The tests of
`configure` that would run a program on the target take their defaults for
a cross build; none needed another answer, so the dictionary of cache
variables below is empty and stays for checks a later version may add. The result is one relocatable object, target/curl/curl.o, that
exports `main` alone; tools/build-libc-so.py programs links it against
libc.so.

curl is under the curl licence: the archive is fetched at build time with
its SHA-256 checked, and the image's licence notices name it."""

from hashlib import sha256
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time
from urllib.request import urlopen

import pkgdesc


PACKAGE = pkgdesc.load("curl")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "curl"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
OPENSSL = ROOT / "target" / "openssl" / "install"
OUTPUT = WORK / "curl.o"
CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
# Cortex-A53 erratum 835769 (the PinePhone's A64), as BusyBox's objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
# Compiler-generated async unwind rows for C frames; no outlining
# (the native Rust policy owns it).
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")
# What `configure` cannot learn by running a program: filled in as the
# build needs them.
CACHE: dict[str, str] = {}
CONFIGURE = (
    "--host=aarch64-linux-gnu", "--build=aarch64-apple-darwin",
    f"--with-openssl={OPENSSL}", f"--with-ca-bundle={CA_BUNDLE}", "--without-ca-path",
    "--enable-static", "--disable-shared", "--disable-ipv6", "--enable-threaded-resolver",
    "--disable-ftp", "--disable-ldap", "--disable-ldaps", "--disable-rtsp", "--disable-dict",
    "--disable-telnet", "--disable-tftp", "--disable-pop3", "--disable-imap", "--disable-smb",
    "--disable-smtp", "--disable-gopher", "--disable-mqtt", "--disable-ipfs",
    "--disable-ntlm", "--disable-tls-srp", "--disable-manual", "--disable-docs",
    "--disable-libcurl-option",
    "--without-libpsl", "--without-libidn2", "--without-nghttp2", "--without-zlib",
    "--without-brotli", "--without-zstd", "--without-librtmp", "--without-libssh2",
    "--disable-ares", "--disable-dependency-tracking",
)


def tool(name: str, brew_formula: str | None = None) -> Path:
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM, lld and GNU Make")
    return Path(found).absolute()


def run(log: Path, *args, cwd: Path | None = None, env: dict | None = None) -> None:
    with log.open("a") as out:
        out.write("$ " + " ".join(map(str, args)) + "\n")
        out.flush()
        result = subprocess.run([str(a) for a in args], cwd=cwd, stdout=out,
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


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    libc = RELIBC / "lib" / "libc.a"
    crypto, ssl = OPENSSL / "lib" / "libcrypto.a", OPENSSL / "lib" / "libssl.a"
    if not (RELIBC / "include" / "stdio.h").exists() or not libc.exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    if not crypto.exists() or not ssl.exists():
        raise SystemExit("build OpenSSL with tools/build-openssl.py first")
    stamp = WORK / "stamp"
    text = (f"{VERSION} {SHA256} {script} {sha256(libc.read_bytes()).hexdigest()} "
            f"{sha256(crypto.read_bytes()).hexdigest()} {sha256(ssl.read_bytes()).hexdigest()}\n")
    if stamp.exists() and stamp.read_text() == text and OUTPUT.exists():
        print(f"curl ready: {OUTPUT}")
        return
    began = time.monotonic()
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    archive = WORK / f"curl-{VERSION}.tar.xz"
    with urlopen(URL) as response:
        archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("curl source archive has an unexpected SHA-256")
    with tarfile.open(archive) as members:
        members.extractall(WORK, filter="data")
    source = WORK / f"curl-{VERSION}"
    build = WORK / "build"
    build.mkdir()
    clang, lld = tool("clang", "llvm"), tool("ld.lld", "lld")
    ar, ranlib = tool("llvm-ar", "llvm"), tool("llvm-ranlib", "llvm")
    objcopy, nm = tool("llvm-objcopy", "llvm"), tool("llvm-nm", "llvm")
    stub = WORK / "stubs.o"
    ncurses_module().stubs(log, clang, nm, libc, stub)
    # The threads are in libc.a; `configure` looks for pthread_create in
    # -lpthread when the link without LIBS fails, and an empty archive
    # answers it.
    stubs = WORK / "stubs"
    stubs.mkdir()
    run(log, ar, "rcs", stubs / "libpthread.a")
    cc = " ".join((str(clang), "--target=aarch64-linux-gnu", "-nostdinc",
                   f"-isystem {RELIBC / 'include'}", "-mno-outline-atomics",
                   "-fno-stack-protector", "-ffunction-sections", "-fdata-sections",
                   A53_ERRATA, "-fPIC", *UNWIND_CFLAGS))
    env = dict(os.environ, **CACHE, CC=cc, CFLAGS="-Os -w",
               LDFLAGS=(f"-static -nostdlib --ld-path={lld} -L{RELIBC / 'lib'} -L{stubs} "
                        f"{stub}"),
               LIBS="-lc", AR=str(ar), RANLIB=str(ranlib),
               # No pkg-config of the host answers for the target.
               PKG_CONFIG="false")
    run(log, source / "configure", *CONFIGURE, cwd=build, env=env)
    # The link is a relocatable one: the Rust program links relibc and the
    # crt; the archives of OpenSSL go into the object.
    run(log, "make", "-j4", "-C", "lib", cwd=build)
    # The program takes the archive of libcurl itself: libcurl.la and the
    # Makefile would hand on the libraries of `configure`'s link tests
    # (libc.a among them), and the C library of the program is libc.so.
    run(log, "make", "-j4", "-C", "src", "curl", "LIBS=",
        "curl_LDADD=../lib/.libs/libcurl.a -lssl -lcrypto",
        f"LDFLAGS=-nostdlib -r --ld-path={lld} -L{OPENSSL / 'lib'}", cwd=build)
    joined = build / "src" / "curl"
    OUTPUT.unlink(missing_ok=True)
    run(log, objcopy, "--keep-global-symbol=main", joined, OUTPUT)
    listing = subprocess.run([str(nm), "-g", "--defined-only", str(OUTPUT)],
                             capture_output=True, text=True, check=True).stdout.split()
    if listing[-2:] != ["T", "main"] or len(listing) != 3:
        raise SystemExit(f"curl.o exports more than main: {listing[:12]}")
    stamp.write_text(text)
    print(f"curl ready: {OUTPUT} ({time.monotonic() - began:.0f} s)")


if __name__ == "__main__":
    main()
