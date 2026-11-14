# stafeto

A POSIX operating system on its own capability microkernel, written in Rust for AArch64.

Every path inside the kernel is bounded in time, and every driver and service runs as an ordinary isolated process. These are the properties that real-time, embedded and server systems need: predictable timing, and a fault in a driver that ends only that driver. The goal is a system that runs ordinary POSIX software (shells, editors, system tools) on top of a kernel small enough to reason about.

*Stafeto* is Esperanto for "messenger" and "relay": the system is built around messages that pass control from hand to hand.

## Try it

Download `stafeto-<version>-aarch64-virt-base.tar.xz` (the shell and the package tool) or `stafeto-<version>-aarch64-virt-full.tar.xz` (every package, with the network programs; it needs 1024M of memory) from the [latest release](https://github.com/stafeto/stafeto/releases), unpack it and run:

```sh
./run.sh              # QEMU with emulation, any host
./run.sh --cpus 4     # four CPUs
./run.sh --hvf        # hardware virtualization on a Mac with Apple silicon
```

You get a BusyBox `ash` shell with line editing. `bash`, `nano`, `htop`, `top` and `ncdu` are in the image; `exit` or Ctrl-A X ends QEMU. Files live in RAM, so changes are gone after a restart. The release notes also tell how to launch the system on an AWS EC2 Graviton instance.

## What works today

- **Kernel.** A capability microkernel of about 200 KiB (204,805 bytes as measured, with no size limit) with 37 system calls over handles with rights: processes, threads, channels, timers, memory objects, device windows and interrupts. Synchronous messages with priority inheritance, fixed-priority scheduling with 64 levels, per-process quotas for kernel memory, memory that is never writable and executable at once.
- **Bounded timing.** The longest stretch the kernel runs with interrupts off is measured and enforced in CI (8,870 of a limit of 18,000 instructions); long operations run in bounded portions. `cargo xtask wcet` adds kernel block coverage, stack depth and a static bound per system call.
- **Several CPUs.** Up to 4 CPUs are tested: per-CPU kernel data, one short object lock, commands between CPUs and partitioned scheduling, so a real-time task keeps its CPU and its bounds.
- **Services in user space.** `init` starts and supervises services and restarts a crashed one: console and Virtio drivers, a RAM file system, pipes, a terminal with pseudo-terminals, processes, clock and entropy.
- **POSIX.** All 1,035 interfaces that POSIX.1-2024 requires are present. os-test `basic` passes 1,184 of 1,187 tests and the Open POSIX Test Suite 1,986 of 2,036. `fork`, `exec`, signals, threads, timers, `mmap`, file locks, local sockets, `/proc`.
- **Programs.** relibc is the C library. BusyBox 1.37 and the ready-made utilities linked into it give 103 of the 112 POSIX utilities, and GNU bash 5.3, GNU nano, htop and ncdu run on it. Every third-party program is a package with one description file.
- **Network.** A TCP/IP service in user space with sockets and epoll, DHCP, `wget` and `curl` over TLS, and nginx, also on a user-space FreeBSD stack (F-Stack).
- **Security.** A set-ID program takes only verified sessions (pipes, network, entropy) from its caller, a wait on a shared-memory address needs the right to the object, the stack canary comes from `AT_RANDOM`, which the loader fills from a boot seed, all C code is built with `-fstack-protector-strong`, and `crypt` salts are random. Packages are signed, and releases carry a signed index.
- **Machines.** QEMU `virt` with emulation (GICv2 and GICv3), QEMU with HVF on Apple silicon, Apple Virtualization.framework, and AWS EC2 Graviton (t4g.small in `eu-central-1`, booted through an EFI loader, with the ENA network device).

The details of each part and the known limits are in [docs/status.md](docs/status.md).

## Where it is going

The work runs in subprojects. Subproject 1 (the kernel and a minimal userland) and subproject 2 (POSIX and services) are done; the network and the packages arrived in 0.3.0 and AWS EC2 Graviton in 0.4.0.

**Next, in this order**

- Reliability: every service step held to its bound and checked in CI, the defects that reviews find fixed before new parts.
- Scheduler time budgets: a thread runs within a budget per period, so an overrun stays inside its own process.
- AWS step g1: two ENA queues with RSS, one stack instance per queue, and measurements against Linux on network-optimised Graviton instances.
- Then the rest of the list below.
- Shared libraries: `libc.so` and a dynamic loader are in; next come `dlopen` of new libraries and more sharing of data pages between processes.
- The nine POSIX utilities that need services of their own: `at`, `batch`, `lp`, `mailx`, `locale`, `localedef`, `gettext`, `ngettext` and `msgfmt`.
- System integrity: every program carries an Ed25519 signature from the release key or from an approved developer. A program with a broken or foreign signature does not start, and a manual scan checks the whole system against a signed manifest, in the spirit of `sfc /scannow`.
- Hardware boards, later: the Allwinner A64 (the PINE A64-LTS) with U-Boot, the 16550 UART and real-time measurements on the board; then the STM32MP2.

**Later subprojects**

- Graphics and input: virtio-gpu, touch input, a compositor; Doom as the first playable target (under way).
- Network: IPv4 is in. BusyBox `wget` fetches over HTTP and over HTTPS with TLS 1.2 only; it checks no certificate, so use it where the content is verified another way (see `docs/posix-coverage.md`, Names and `wget`).
- Apps: an app sandbox. The package format and signed packages are in.

## Build from source

You need rustup, QEMU and dtc (on macOS: `brew install qemu dtc`); rustup installs the toolchain from `rust-toolchain.toml`. The POSIX programs also need Clang/LLVM, LLD, Python 3, GNU Make and Git (on macOS: `brew install llvm lld make gnu-sed`). The Apple Virtualization commands need the Xcode command line tools.

```sh
cargo xtask ash-shell    # build the shell image and boot it in QEMU (Ctrl-A X quits)
cargo xtask run          # the native shell; --hvf on Apple silicon
cargo xtask vz           # the shell through Apple Virtualization.framework
cargo xtask doom         # play Doom in a QEMU window (--machine hvf on a Mac; docs/doom.md)
cargo xtask test         # host tests, kernel tests, guest probes
cargo xtask ci           # everything CI runs: formatting, lints, licences, tests
cargo xtask dist         # the release files in target/dist
cargo xtask help         # every command
```

## Documentation

| Page | What it covers |
|---|---|
| [docs/status.md](docs/status.md) | each part of the system in detail, and the known limits |
| [docs/smp.md](docs/smp.md) | the model for several CPUs, its limits and how to measure them |
| [docs/wcet.md](docs/wcet.md) | the worst-case timing tools |
| [docs/non-preemptible-paths.md](docs/non-preemptible-paths.md) | bounded kernel paths and their costs |
| [docs/posix-coverage.md](docs/posix-coverage.md) | POSIX coverage and the conformance work left |
| [docs/packages.md](docs/packages.md) | how third-party programs are packaged |
| [docs/release.md](docs/release.md) | versions and how a release is made |
| [docs/debugging.md](docs/debugging.md) | debugging hangs and crashes |

## Repository layout

| Directory | Contents |
|---|---|
| `kernel/` | the microkernel: objects, IPC, processes, threads, memory, SMP, system calls, the ITS, the entry of exceptions |
| `karch/` | the AArch64 layer of the kernel: boot code, exception vectors, MMU, caches, GIC, timer |
| `kboot/` | what the kernel reads at boot: device tree, boot information, memory map; no `unsafe`, tested on the host |
| `kcore/` | kernel logic that builds and tests on the host |
| `lib/` | `abi`, `rt`, `bootimg`, `ext4ro` and the `posix-*` crates |
| `proto/` | message protocols between programs and services |
| `services/` | `init`, drivers and the system services |
| `apps/` | the native shell |
| `packages/` | descriptions of third-party programs |
| `tests/` | guest test programs and probes |
| `tools/` | builds of relibc and the packages, the VZ runner, release and licence tools |
| `xtask/` | build, run, test and measurement commands |
| `docs/` | documentation |
| `notes/` | design notes of individual parts |

## License

The kernel, `karch`, `kboot`, `kcore`, services, drivers, the shell, `xtask`, the tests,
`lib/ext4ro` and the POSIX crates that programs do not link
(`lib/posix-signal-queue`, `lib/posix-credentials`) are under
GPL-3.0-or-later ([LICENSE](LICENSE)). The libraries that programs link
(`lib/abi`, `lib/rt`, `lib/bootimg`, `lib/process-client`, `proto/*`) are
under MIT ([LICENSE-MIT](LICENSE-MIT)).

The POSIX system layer that programs link (crates listed by
`tools/check-licenses.py`) is GPL-3.0-or-later with the GCC Runtime Library
Exception 3.1 ([LICENSE-GCC-exception-3.1](LICENSE-GCC-exception-3.1)):
programs under any licence, including GPL-2.0-only BusyBox, may link it.
Services stay GPL-3.0-or-later. relibc and its dependencies keep their own
licences (THIRD-PARTY-NOTICES, which `tools/check-licenses.py` writes to
`target/relibc/` and every boot image with a program on relibc carries).

The shell image also holds ready-made utilities, built from their own
sources unchanged by `tools/build-ready-utils.py`: `getconf`, `join` and
`pathchk` of sbase (MIT), `file` and `iconv` of toybox (0BSD), `compress`
of ncompress (public domain), `csplit`, `gencat`, `m4` and `write` of
chimerautils (BSD), `pr` of nbase (BSD), `pax` of paxmirabilis (BSD, MirOS)
with the `fts` of musl-fts (BSD), `newgrp` of util-linux (GPL-2.0-or-later)
and `tput` and `tabs` of ncurses (MIT). Their licence texts and the exact
sources travel in the image next to BusyBox's (`BUSYBOX-LICENSE`,
`BUSYBOX-SOURCE`, `UTILITIES-LICENSE`).

Every source file carries an `SPDX-License-Identifier` line. `cargo xtask
ci` checks the licence of every crate and file, that the GPL-2.0-only
programs (BusyBox) link no bare GPL-3.0 code, and that relibc and everything it links are under licences
GPL-2.0-only takes. Other third-party dependencies keep their own licences
([docs/licenses](docs/licenses)).
