#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Build OpenSSL for the images with the network service from its release
archive, unchanged, against relibc's headers and the Linux AArch64 C ABI
they describe.

The result is twofold. target/openssl/install holds the headers and the
static archives libcrypto.a and libssl.a, which curl links (`-I`, `-L`);
target/openssl/openssl.o is the program `openssl` as one relocatable object
that exports `main` alone, which tools/build-libc-so.py programs links
against libc.so. The loader of the system opens one library, libc.so, so
OpenSSL has no shared library of its own: each program links what it uses.

The compiler is a small wrapper script, target/openssl/cc, that holds the
target and the flags of every C program of the image; `Configure` takes it
from CC and runs it for its own checks. OpenSSL's AArch64 assembly is built:
the C library declares no __GLIBC__, so crypto/armcap.c learns the
extensions of the CPU by trying one instruction of each under a SIGILL
handler, which the layer delivers for an undefined instruction of EL0.
OPENSSL_NO_ASM=1 in the environment builds with `no-asm`, the fallback
path, with C code alone.

OpenSSL is Apache-2.0: the archive is fetched at build time with its
SHA-256 checked, and the image's licence notices name it."""

from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time
from urllib.request import urlopen

import pkgdesc


PACKAGE = pkgdesc.load("openssl")
VERSION = PACKAGE["version"]
SHA256 = PACKAGE["sha256"]
URL = PACKAGE["url"]
ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "openssl"
INSTALL = WORK / "install"
RELIBC = ROOT / "target" / "relibc" / "sysroot"
# Headers OpenSSL includes on Linux that relibc lacks; searched after
# relibc's own (-idirafter). None is needed today.
COMPAT = ROOT / "tools" / "openssl" / "compat"
OUTPUT = WORK / "openssl.o"
NO_ASM = os.environ.get("OPENSSL_NO_ASM") == "1"
# Cortex-A53 erratum 835769 (the PinePhone's A64), as BusyBox's objects.
A53_ERRATA = "-mfix-cortex-a53-835769"
# Compiler-generated async unwind rows for C frames; no outlining
# (the native Rust policy owns it).
UNWIND_CFLAGS = ("-fasynchronous-unwind-tables", "-mllvm", "-enable-machine-outliner=never")

# The one Configure line, by group:
CONFIGURE = (
    # The target: AArch64 with the GNU assembler syntax, pthreads, 64-bit
    # longs. OPENSSLDIR is /etc/ssl, which holds no openssl.cnf; the
    # programs name their CA file themselves.
    "linux-aarch64", "--prefix=/", "--openssldir=/etc/ssl", "--libdir=lib",
    # The seed comes from getentropy, which relibc gives from the entropy
    # service; the /dev/random path wants ioctl(RNDGETENTCNT) and a Linux
    # release number.
    "--with-rand-seed=getrandom",
    # The loader takes libc.so alone in DT_NEEDED: no shared libraries, no
    # loadable providers or engines.
    "no-shared", "no-dso", "no-module", "no-engine", "no-dynamic-engine",
    "no-static-engine", "no-legacy",
    # The async jobs need ucontext; compression is off in every client.
    "no-async", "no-comp", "no-zlib", "no-brotli", "no-zstd",
    # Datagrams (DTLS, SCTP, QUIC) and the old versions of TLS stay out:
    # TLS 1.3 and 1.2 remain.
    "no-dgram", "no-ssl3", "no-tls1", "no-tls1_1", "no-tls1-method", "no-tls1_1-method",
    "no-nextprotoneg",
    # Methods neither curl nor nginx calls.
    "no-srp", "no-psk", "no-gost", "no-ec2m", "no-tls-deprecated-ec",
    # Old ciphers and hashes that TLS 1.3 and 1.2 with modern suites need
    # not.
    "no-idea", "no-mdc2", "no-md4", "no-rc2", "no-rc4", "no-rc5", "no-bf", "no-cast",
    "no-camellia", "no-seed", "no-aria", "no-sm2", "no-sm3", "no-sm4", "no-whirlpool",
    "no-des", "no-siv", "no-ocb", "no-scrypt", "no-argon2",
    # Subsystems apart from TLS, and the post-quantum signatures (size);
    # ML-KEM stays for the hybrid key exchange of TLS 1.3.
    "no-ts", "no-cms", "no-cmp", "no-ct", "no-rfc3779", "no-srtp", "no-ssl-trace",
    "no-ml-dsa", "no-slh-dsa",
    # Platform engines, and what is not built at all.
    "no-afalgeng", "no-padlockeng", "no-capieng", "no-uplink", "no-tests", "no-docs",
    # Size first, as every program on libc.so; the assembly gives the speed.
    "-Os", "-fPIC",
)


def tool(name: str, brew_formula: str | None = None) -> Path:
    if brew_formula:
        path = Path(f"/opt/homebrew/opt/{brew_formula}/bin/{name}")
        if path.exists():
            return path
    found = shutil.which(name)
    if found is None:
        raise SystemExit(f"missing {name}; install LLVM, lld, GNU Make and Perl")
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


def configure_line() -> str:
    """The Configure line as the build runs it, for the licence notes."""
    return " ".join(("perl Configure", *CONFIGURE, *(("no-asm",) if NO_ASM else ())))


def compiler(clang: Path) -> str:
    """The wrapper script that Configure and make run as CC."""
    flags = ("--target=aarch64-linux-gnu", "-nostdinc", "-isystem", str(RELIBC / "include"),
             "-idirafter", str(COMPAT), "-mno-outline-atomics", "-fno-stack-protector",
             "-ffunction-sections", "-fdata-sections", A53_ERRATA, *UNWIND_CFLAGS)
    return "#!/bin/sh\nexec " + " ".join((str(clang), *flags)) + ' "$@"\n'


def main() -> None:
    script = sha256(Path(__file__).read_bytes()).hexdigest()
    libc = RELIBC / "lib" / "libc.a"
    if not (RELIBC / "include" / "stdio.h").exists() or not libc.exists():
        raise SystemExit("build relibc with cargo xtask relibc first")
    clang, lld = tool("clang", "llvm"), tool("ld.lld", "lld")
    ar, ranlib = tool("llvm-ar", "llvm"), tool("llvm-ranlib", "llvm")
    objcopy, nm = tool("llvm-objcopy", "llvm"), tool("llvm-nm", "llvm")
    wrapper = compiler(clang)
    stamp = WORK / "stamp"
    text = (f"{VERSION} {SHA256} {script} {sha256(wrapper.encode()).hexdigest()} "
            f"{sha256(libc.read_bytes()).hexdigest()} asm={not NO_ASM}\n")
    archives = [INSTALL / "lib" / "libcrypto.a", INSTALL / "lib" / "libssl.a"]
    if (stamp.exists() and stamp.read_text() == text and OUTPUT.exists()
            and all(a.exists() for a in archives)):
        print(f"openssl ready: {OUTPUT}")
        return
    began = time.monotonic()
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    log = WORK / "build.log"
    log.write_text("")
    archive = WORK / f"openssl-{VERSION}.tar.gz"
    with urlopen(URL) as response:
        archive.write_bytes(response.read())
    if sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("OpenSSL source archive has an unexpected SHA-256")
    with tarfile.open(archive) as members:
        members.extractall(WORK, filter="data")
    source = WORK / f"openssl-{VERSION}"
    cc = WORK / "cc"
    cc.write_text(wrapper)
    cc.chmod(0o755)
    # The target's libraries (-ldl, -pthread) are in libc.a: empty archives
    # satisfy the relocatable link of the program.
    stubs = WORK / "stubs"
    stubs.mkdir()
    for name in ("libdl.a", "libpthread.a"):
        run(log, ar, "rcs", stubs / name)
    env = dict(os.environ, CC=str(cc), AR=str(ar), RANLIB=str(ranlib), CROSS_COMPILE="")
    for key in ("CFLAGS", "CPPFLAGS", "LDFLAGS", "LIBS"):
        env.pop(key, None)
    run(log, "perl", "Configure", *CONFIGURE, *(("no-asm",) if NO_ASM else ()),
        cwd=source, env=env)
    run(log, "make", "-j4", "build_libs", cwd=source, env=env)
    run(log, "make", "install_dev", f"DESTDIR={INSTALL}", cwd=source, env=env)
    # The pkg-config and CMake files name the prefix of the image (/lib);
    # curl takes the paths of this tree from --with-openssl.
    for name in ("pkgconfig", "cmake"):
        shutil.rmtree(INSTALL / "lib" / name)
    # The link of the program is a relocatable one: the Rust program links
    # relibc and the crt.
    run(log, "make", "-j4", "build_programs",
        f"LDFLAGS=-nostdlib -r --ld-path={lld} -L{stubs}", cwd=source, env=env)
    OUTPUT.unlink(missing_ok=True)
    run(log, objcopy, "--keep-global-symbol=main", source / "apps" / "openssl", OUTPUT)
    listing = subprocess.run([str(nm), "-g", "--defined-only", str(OUTPUT)],
                             capture_output=True, text=True, check=True).stdout.split()
    if listing[-2:] != ["T", "main"] or len(listing) != 3:
        raise SystemExit(f"openssl.o exports more than main: {listing[:12]}")
    seconds = time.monotonic() - began
    stamp.write_text(text)
    (WORK / "configure-line.txt").write_text(configure_line() + "\n")
    print(f"openssl ready: {OUTPUT} ({'no-asm' if NO_ASM else 'asm'}, {seconds:.0f} s)")


if __name__ == "__main__":
    main()
