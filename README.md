# stafeto

A POSIX operating system on its own capability microkernel, written in Rust for AArch64.

Every path inside the kernel is bounded in time, and every driver and service runs as an ordinary isolated process. These are the properties that embedded, robotic and mobile devices need: predictable timing, and a fault in a driver that ends only that driver. The goal is a system that runs ordinary POSIX software (shells, editors, system tools) on top of a kernel small enough to reason about.

*Stafeto* is Esperanto for "messenger" and "relay": the system is built around messages that pass control from hand to hand.

## Try it

Download `stafeto-<version>-aarch64-virt.tar.xz` from the [latest release](https://github.com/stafeto/stafeto/releases), unpack it and run:

```sh
./run.sh              # QEMU with emulation, any host
./run.sh --cpus 4     # four CPUs
./run.sh --hvf        # hardware virtualization on a Mac with Apple silicon
```

You get a BusyBox `ash` shell with line editing. `bash`, `nano`, `htop`, `top` and `ncdu` are in the image; `exit` or Ctrl-A X ends QEMU. Files live in RAM, so changes are gone after a restart.

## What works today

- **Kernel.** A capability microkernel of about 160 KiB with 34 system calls over handles with rights: processes, threads, channels, timers, memory objects, device windows and interrupts. Synchronous messages with priority inheritance, fixed-priority scheduling with 64 levels, per-process quotas for kernel memory, memory that is never writable and executable at once.
- **Bounded timing.** The longest stretch the kernel runs with interrupts off is measured and enforced in CI (15,492 of a limit of 18,000 instructions); long operations run in bounded portions. `cargo xtask wcet` adds kernel block coverage, stack depth and a static bound per system call.
- **Several CPUs.** Up to 4 CPUs are tested: per-CPU kernel data, one short object lock, commands between CPUs and partitioned scheduling, so a real-time task keeps its CPU and its bounds.
- **Services in user space.** `init` starts and supervises services and restarts a crashed one: console and Virtio drivers, a RAM file system, pipes, a terminal with pseudo-terminals, processes, clock and entropy.
- **POSIX.** All 1,035 interfaces that POSIX.1-2024 requires are present. os-test `basic` passes 1,183 of 1,187 tests and the Open POSIX Test Suite 1,985 of 2,036. `fork`, `exec`, signals, threads, timers, `mmap`, file locks, local sockets, `/proc`.
- **Programs.** relibc is the C library. BusyBox 1.37 gives 94 of the 112 POSIX utilities, and GNU bash 5.3, GNU nano, htop and ncdu run on it. Every third-party program is a package with one description file.
- **Machines.** QEMU `virt` with emulation (GICv2 and GICv3), QEMU with HVF on Apple silicon, and Apple Virtualization.framework.

The details of each part and the known limits are in [docs/status.md](docs/status.md).

## Where it is going

The work runs in subprojects. Subproject 1 (the kernel and a minimal userland) is done; subproject 2 (POSIX and services) is nearly done and ends with release 0.2.0.

**Next**

- Finish subproject 2: the remaining kernel debts from the audits, the last 18 POSIX utilities, more stable tests on several CPUs.
- Shared libraries: `libc.so` and a dynamic loader, with the code pages of a library shared between processes. This makes the image and the memory of a running system much smaller.
- System integrity: every program carries an Ed25519 signature from the release key or from an approved developer. A program with a broken or foreign signature does not start, and a manual scan checks the whole system against a signed manifest, in the spirit of `sfc /scannow`.
- Hardware: Allwinner A64 boards (the PinePhone and the PINE A64-LTS) with U-Boot, the 16550 UART and real-time measurements on the board; then the STM32MP2.

**Later subprojects**

- Graphics and input: virtio-gpu, touch input, a compositor; Doom as the first playable target.
- Network: virtio-net, a TCP/IP stack and IPv4 sockets.
- Packages and apps: a package format, signed packages, an app sandbox.

## Build from source

You need rustup, QEMU and dtc (on macOS: `brew install qemu dtc`); rustup installs the toolchain from `rust-toolchain.toml`. The POSIX programs also need Clang/LLVM, LLD, Python 3, GNU Make and Git (on macOS: `brew install llvm lld make gnu-sed`). The Apple Virtualization commands need the Xcode command line tools.

```sh
cargo xtask ash-shell    # build the shell image and boot it in QEMU (Ctrl-A X quits)
cargo xtask run          # the native shell; --hvf on Apple silicon
cargo xtask vz           # the shell through Apple Virtualization.framework
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
| `kernel/` | the microkernel: boot, MMU, GIC, scheduler, system calls |
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

The kernel, `kcore`, services, drivers, the shell, `xtask`, the tests,
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
`pathchk` of sbase (MIT), `file` and `iconv` of toybox (0BSD) and `compress`
of ncompress (public domain). Their licence texts and the exact sources
travel in the image next to BusyBox's (`BUSYBOX-LICENSE`, `BUSYBOX-SOURCE`,
`UTILITIES-LICENSE`).

| `tools/` | relibc, BusyBox, ncurses, nano and bash builds, the VZ runner, licence check |

Every source file carries an `SPDX-License-Identifier` line. `cargo xtask
ci` checks the licence of every crate and file, that the GPL-2.0-only
programs (BusyBox) link no bare GPL-3.0 code, and that relibc and everything it links are under licences
GPL-2.0-only takes. Other third-party dependencies keep their own licences
([docs/licenses](docs/licenses)).
