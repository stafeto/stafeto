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
PATCH = "echo cat wc sleep head-c mktemp ash-random ash-job-control ash-builtins ash-interruptible-input-eof math test printf getopts alias command kill ash ls-nofork relibc main-renamed a53-835769"
