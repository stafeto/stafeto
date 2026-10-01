# stafeto

A learning phone OS built on its own microkernel, written in Rust for
AArch64. The kernel keeps only what must run privileged: address spaces,
threads, scheduling, handles and messages. Drivers, file systems and the
POSIX layer run as ordinary processes that talk through synchronous
messages. The system boots in QEMU and on Apple silicon today; the
PinePhone is the first real phone it targets.

*Stafeto* is Esperanto for "messenger" and "relay". The system is built
around messages that pass control from hand to hand.

## Foundation

- a Rust microkernel for AArch64: QEMU first, then PinePhone;
- synchronous messages and handles with rights (a capability model);
- drivers and services run as ordinary processes;
- soft real time: every path inside the kernel is bounded in time;
- the kernel image stays under 200 KiB.

## Status

Numbers below are from `main` at 764be2a.

**Boot and machines.** The kernel boots as an arm64 Image from EL2 or EL1,
turns on the MMU, reads the device tree and checks its boot image. It runs
on three kinds of machine:

- QEMU `virt` under emulation (TCG), with GICv2 or GICv3;
- QEMU with HVF on a Mac with Apple silicon, on Apple's GICv3 and on
  QEMU's GICv2;
- Apple Virtualization.framework without QEMU, through a Virtio PCI
  console (`cargo xtask vz`).

**Kernel.** 34 system calls (35 in the VZ build) over 64-bit handles
with rights: processes, threads, channels, sessions, timers, memory
objects, device windows and interrupt bindings. Synchronous requests and replies carry up to 1 KiB and
four handles; a service runs at its client's priority under its own
ceiling, and a fast path hands the CPU straight to a waiting service. The
scheduler has 64 priority levels (round robin and FIFO) with tickless
preemption. Every process pays for its kernel memory from a quota, memory
is never writable and executable at once, and long operations run in
bounded portions. Device interrupts reach drivers as notifications. A
fault ends only its own process. The kernel image is 154,708 bytes of a
204,800-byte budget.

**User space and services.** `init` starts services from a table in
dependency order, hands out sessions by name, restarts a service that
crashes or goes silent and marks it broken after five failures in 60 s.
The PL011 driver (`services/uart`) owns the console on interrupts and
shows the kernel log. A RAM file service (`services/ramfs`) holds files
and directories. Programs build on `lib/rt`, which owns handles, runs
service loops and starts children through a start protocol.

**Shells.** The native shell boots by default and knows `help`, `echo`,
`uptime`, `ps`, `mem`, `bench`, `trace` and `crash uart`; the last one
crashes the driver, `init` restarts it and the shell reconnects. Separate
images run BusyBox 1.37.0 against the RAM file service: `cat`, `ash -c`
and an interactive `ash` on the UART with `echo` and `ls -la`. BusyBox
links statically with Picolibc 1.8.12 through a small bridge
(`lib/posix`).

**POSIX layer in Rust.** The goal is the full mandatory POSIX.1-2024
interface, implemented in Rust with a C ABI and a versioned sysroot
(`tools/build-posix-sysroot.py`). The current crates cover paths,
descriptors, files, `stat` and directories; the heap and the C locale;
pthreads with cancellation, keys, `once` and mutexes; clocks and sleep;
signal actions, masks, `sigwait`, `sigwaitinfo`, `sigtimedwait` and
`SA_SIGINFO`; process IDs and credentials. Guest probes check them on QEMU
and Apple VZ. The layer is a work in progress and paused: no real program
uses it yet, and `ash` still runs on Picolibc. Details are in
[docs/status.md](docs/status.md).

**Tests.** The kernel test image runs 166 tests (177 under `-icount`),
the EL0 test `init` runs 224 and `kcore` has 402 host tests; `cargo xtask
ci` runs them with the guest probes, and `cargo xtask hvf` runs them on
Apple silicon.

**Known limits.**

- The Apple VZ build keeps its Virtio console driver in the kernel and
  polls for input.
- One CPU core only; no SMP.
- No PinePhone port yet.
- `ash` cannot start external programs: no `exec`, `fork` or pipes.
- Files live in RAM; ext4 is read from an image inside the guest, with no
  block driver.

## Build and run

You need rustup, QEMU and dtc (on macOS: `brew install qemu dtc`); rustup
installs the toolchain from `rust-toolchain.toml`. The POSIX probes in
`test` and `ci` also need Clang/LLVM, LLD and Python 3; the Picolibc and
BusyBox commands need Meson, Ninja, GNU Make and Git as well (on macOS:
`brew install llvm lld meson ninja make`). The VZ commands need the Xcode
command line tools for `swiftc` and `codesign`.

```sh
cargo xtask build        # kernel and boot image in target/, checks the 200 KiB budget
cargo xtask run          # QEMU to the shell prompt (Ctrl-A X quits); --hvf on Apple silicon
cargo xtask vz           # the shell through Apple Virtualization.framework (Ctrl-C quits)
cargo xtask test         # host tests, boot checks, shell dialog, init and kernel tests, POSIX probes
cargo xtask ci           # formatting, clippy, licence checks, then everything test does
cargo xtask hvf          # the test set under HVF on Apple silicon; skips elsewhere
cargo xtask rtbench      # throughput and 1 ms timer wakeups on TCG, HVF and VZ
cargo xtask ash-shell    # interactive BusyBox ash over the QEMU UART
cargo xtask gdb          # QEMU halted at the first instruction, debugger on :1234
cargo xtask help         # every command, including single probes
```

How to debug hangs and crashes: [docs/debugging.md](docs/debugging.md).
Bounded kernel paths and their costs:
[docs/non-preemptible-paths.md](docs/non-preemptible-paths.md).

## Repository layout

| Directory | Contents |
|---|---|
| `kernel/` | the microkernel: boot, MMU, GIC, scheduler, system calls |
| `kcore/` | kernel logic that builds and tests on the host |
| `lib/` | `abi`, `rt`, `bootimg`, `ext4ro` and the `posix-*` crates |
| `proto/` | message protocols between programs and services |
| `services/` | `init`, the UART driver, the RAM file, clock and process services |
| `apps/` | the native shell |
| `tests/` | guest test programs and probes |
| `tools/` | Picolibc, BusyBox and sysroot builds, the VZ runner, licence check |
| `xtask/` | build, run, test and measurement commands |
| `docs/` | debugging, kernel paths, status details, third-party licences |
| `notes/` | design notes of individual parts |

## Roadmap

✅ done · 🚧 in progress · ⬜ planned

### Subproject 1: kernel and minimal userland ✅

| Stage | Parts | State |
|---|---|---|
| 1.1 Boot | QEMU boot, MMU, device tree, exceptions, in-kernel tests | ✅ [#2](https://github.com/stafeto/stafeto/pull/2) |
| 1.2 Kernel | a memory and handles · b threads, GICv2, timer, ASIDs · c system calls, scheduler, `init` | ✅ [#3](https://github.com/stafeto/stafeto/pull/3), [#4](https://github.com/stafeto/stafeto/pull/4), [#5](https://github.com/stafeto/stafeto/pull/5) |
| 1.3 Messages and objects | a teardown and quotas · b channels and timers · c requests and replies · d memory objects · e interrupts and devices; cleanups after audits 1 and 2 | ✅ [#6](https://github.com/stafeto/stafeto/pull/6), [#8](https://github.com/stafeto/stafeto/pull/8), [#11](https://github.com/stafeto/stafeto/pull/11), [#13](https://github.com/stafeto/stafeto/pull/13), [#14](https://github.com/stafeto/stafeto/pull/14); [#10](https://github.com/stafeto/stafeto/pull/10), [#12](https://github.com/stafeto/stafeto/pull/12), [#15](https://github.com/stafeto/stafeto/pull/15) |
| 1.4 Userland | a GICv3 and HVF · b runtime and protocols · c `init` services · d UART driver and shell · e measurements | ✅ [#16](https://github.com/stafeto/stafeto/pull/16)–[#20](https://github.com/stafeto/stafeto/pull/20) |

### Subproject 2: POSIX and services (so far)

| Area | What it brings | State |
|---|---|---|
| Apple VZ | the shell through Virtualization.framework without QEMU | ✅ [#21](https://github.com/stafeto/stafeto/pull/21) |
| Benchmarks | `rtbench`: workloads after Thread-Metric, 1 ms timer wakeups | ✅ [#22](https://github.com/stafeto/stafeto/pull/22) |
| ext4 | read-only ext4 in a guest | ✅ [#23](https://github.com/stafeto/stafeto/pull/23) |
| RAM files and BusyBox | RAM file service, Picolibc, BusyBox `cat`; Doom as a later target | ✅ [#24](https://github.com/stafeto/stafeto/pull/24), [#25](https://github.com/stafeto/stafeto/pull/25) |
| BusyBox shell | `ash -c`, interactive `ash`, `ls` | ✅ [#26](https://github.com/stafeto/stafeto/pull/26)–[#28](https://github.com/stafeto/stafeto/pull/28) |
| POSIX files | paths, files, `lseek`, descriptors, C ABI and `libc.a`, `stat`, directories, heap, `scandir`, shared file state | ✅ [#29](https://github.com/stafeto/stafeto/pull/29)–[#38](https://github.com/stafeto/stafeto/pull/38) |
| POSIX interruption | console waits, value messages, IPC interruption and `EINTR`, UART read recovery | ✅ [#39](https://github.com/stafeto/stafeto/pull/39)–[#42](https://github.com/stafeto/stafeto/pull/42) |
| POSIX threads and time | pthreads, deferred cancellation, keys, `once`, 64 threads, mutexes, clocks, timed mutexes, sleep | ✅ [#43](https://github.com/stafeto/stafeto/pull/43)–[#51](https://github.com/stafeto/stafeto/pull/51) |
| Nested entry | kernel upcalls into user threads; results kept across nested handlers | ✅ [#52](https://github.com/stafeto/stafeto/pull/52)–[#58](https://github.com/stafeto/stafeto/pull/58) |
| POSIX signals and processes | signal actions, `sigwait`, `sigwaitinfo`, PIDs, `SA_SIGINFO`, `sigtimedwait`, sender identity, credentials, pending-signal queues | ✅ [#59](https://github.com/stafeto/stafeto/pull/59)–[#67](https://github.com/stafeto/stafeto/pull/67) |

### Next

| Step | What it brings | State |
|---|---|---|
| Cleanup after kernel audit 3 | small kernel fixes, Cortex-A53 erratum 835769 workaround, EL2 boot in tests, fresh worst-case measurements | ✅ [#70](https://github.com/stafeto/stafeto/pull/70) |
| Subproject 2 design | process model, IPC transport for POSIX, libc choice and the licence of the in-process layer | 🚧 |
| Kernel | DMA memory objects, the Virtio console as a user-space service, process IDs out of the kernel | ⬜ |
| POSIX: transport | mutex and heap without IPC on the fast path, no helper threads per process | ⬜ |
| POSIX: C library | a standard libc on top of the Rust system layer; BusyBox and utilities build with it | ⬜ |
| POSIX: processes | process service, `waitpid`, `kill`, `posix_spawn` and `exec`, then `fork` | ⬜ |
| POSIX: shell | pipes, `SA_RESTART`, `SIGCHLD`, a terminal service with `termios` and job control; `ash` runs `ls \| cat` | ⬜ |
| POSIX: conformance | os-test and Open POSIX in `ci`; then conditions, semaphores, timers, `sigqueue` | ⬜ |
| PinePhone bring-up | U-Boot `booti`, 16550 UART driver, Allwinner A64 device tree, `ash` on the serial port | ⬜ |

### Later subprojects

- Graphics and input: virtio-gpu, touch input, a compositor; Doomgeneric started from `ash` as the first playable target.
- Phone shell: home screen, notifications, settings, a UI toolkit.
- Packages: package format, signatures, app sandbox.
- Network: virtio-net and a TCP/IP stack.
- SMP: more than one CPU core.

## License

The kernel, `kcore`, services, drivers, the shell, `xtask`, the tests,
`lib/ext4ro` and the Rust POSIX crates (`lib/posix-*`) are under
GPL-3.0-or-later ([LICENSE](LICENSE)). The libraries that programs link
(`lib/abi`, `lib/rt`, `lib/bootimg`, `lib/process-client`, `proto/*`) and
the temporary Picolibc bridge `lib/posix` are under MIT
([LICENSE-MIT](LICENSE-MIT)), so programs for stafeto can use any licence.
Every source file carries an `SPDX-License-Identifier` line.

BusyBox is GPL-2.0-only ([license](https://busybox.net/license.html)) and
cannot link GPL-3.0-or-later code. It links only the MIT bridge and talks
to GPL services through messages; `cargo xtask ci` checks this boundary
and the licence declarations of the POSIX crates. Third-party
dependencies keep their own licences ([docs/licenses](docs/licenses)).
