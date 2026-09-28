# stafeto

A learning phone OS built on its own microkernel (Rust, AArch64).

*Stafeto* is Esperanto for "messenger" and "relay". The system is built
around messages that pass control from hand to hand.

## Foundation

- a Rust microkernel for AArch64: QEMU first, then PinePhone;
- synchronous messages and handles with rights (a capability model);
- drivers and services run as ordinary processes;
- soft real time: every path inside the kernel is bounded in time;
- the kernel is under 200 KB.

## Status

stafeto boots in QEMU and runs programs at EL0, under QEMU's emulation
and on Apple silicon under HVF. The native Apple Virtualization.framework
port boots `init` and the shell through a Virtio PCI console without QEMU.
Console input currently uses polling; interrupt-driven input and a separate
user-space console driver remain future work. What works today:

- **Boot:** arm64 Image, drop from EL2, MMU on, device tree, checked boot
  image.
- **Interrupt controllers:** GICv2 and GICv3, chosen from the device tree;
  drivers reach device registers with single loads and stores, which a
  hypervisor can emulate.
- **Memory:** the kernel's own page tables with W^X, a buddy frame
  allocator, object pools, an address space with an ASID per process; every
  process pays for its kernel memory from its quota. Memory objects take all
  their pages when they are made, and a process maps them R, RW or RX,
  never writable and executable at once, into its own space or into a
  process whose handle with `MANAGE` it holds; long calls go in bounded
  portions that let interrupts in. The segments and the stack of `init`
  are memory objects too.
- **Execution:** threads at EL0 with registers and FP/SIMD saved on every
  switch; a scheduler with 64 priority levels (round robin with a 4 ms
  quantum, and FIFO) and tickless timer preemption.
- **Objects and calls:** 64-bit handles with rights; processes, threads,
  channels, sessions, program timers, memory objects, device windows and
  interrupt bindings; the system calls of the kernel (`debug_write`,
  `yield`, `thread_*`, `process_*`, `channel_create`, `notify`, `send`,
  `receive`, `reply`, `timer_*`, `mem_create`, `mem_map`, `mem_unmap`,
  `mem_protect`, `irq_bind`, `irq_ack`, `device_window_create`,
  `object_info`), whose `object_info` reports the state of processes,
  threads, channels, memory objects, device windows and interrupt
  bindings.
- **Messages:** synchronous requests and replies of up to 1 KB, the first
  64 bytes in registers and the rest through a per-thread message buffer;
  up to four handles move with a message, keeping their rights and labels;
  a memory object moves the same way, so larger data goes through pages
  both sides map; a service works at its client's priority under its own
  ceiling until it replies; a fast path hands the CPU straight to a waiting
  service.
- **Devices:** an interrupt of a device line comes to its driver as a
  notification of a channel, and the line stays masked until the driver
  calls `irq_ack`; a device window maps the registers of a device into a
  driver as device memory, never executable; a driver that dies frees its
  line at once. The tests drive the PL031 real-time clock of QEMU from
  EL0; a device window over the console's page takes the console from
  the kernel until the window goes.
- **Real time:** program timers fire at the priority of their slots, in
  bounded portions after the timer's interrupt, which takes no timer off
  itself.
- **Faults:** a program fault ends only its own process, and the parent
  learns why through its exit channel; the tests check it on child
  processes with code that `init` loads from the boot image.
- **Runtime:** programs build on `lib/rt`. A handle owns its table entry
  and closes it when dropped; a send or a reply the kernel refuses gives
  back the handles it left. The test images are strict builds, where
  `BAD_HANDLE` panics. The kernel and `rt` share one time scale, a
  multiply and a shift, and `rt` waits with a bound through a timer. A
  parent starts a child with named handles and arguments through the
  start protocol (`proto/wire`, `proto/init`). A service loop keeps a
  session per client label with its own limits, answers deferred replies
  when a client goes, and sends its heartbeat at absolute deadlines from
  the thread that serves requests. One ELF reader, `bootimg::elf`, builds
  the boot image, whose reader refuses two files with one name.
- **Services:** `init` starts the services of its table in the order of
  their dependencies and refuses a table with a cycle or a broken
  ceiling; it hands out sessions by name (`connect`), restarts a service
  that ends or goes silent after a growing pause, marks it broken after
  five failures in 60 s, and loads, kills and tears services down on a
  worker thread just above the service's ceiling. An image of a test
  table checks all of it.
- **Kernel log:** `debug_write` and the kernel's lines about processes go
  into a ring of 64 records in the kernel, which the console's driver
  reads and takes; the kernel prints a record itself only while no
  driver holds the console, `init` shows what is left once the driver
  is broken, and a panic prints what nobody showed.
- **UART driver:** the PL011 driver (`services/uart`) serves the console
  on interrupts at priority 60; it shows the kernel log between whole
  lines of its clients, lets writes wait whole for room and gives input
  to one reader at a time (`proto/uart`).
- **Shell:** `help`, `echo`, `uptime`, `ps`, `mem`, `bench`, `trace` and
  `crash uart`, which crashes the driver: `init` restarts it, and the
  shell connects to the new instance; after five crashes in 60 s the
  driver is broken, the shell says so through the kernel, and `init`
  shows the driver's last fault and its own decision.

`cargo xtask run` boots to the shell's prompt. `cargo xtask test` runs
the tests on QEMU's GICv2 and GICv3, a dialog with the shell through the
console among them; `cargo xtask hvf` runs them on a Mac with Apple
silicon, on Apple's GICv3 and on QEMU's GICv2.

## Roadmap

The work is split into subprojects; subproject 1 is split into stages and
parts. Each finished part is merged through a pull request.

✅ done · 🚧 in progress · ⬜ planned

### Subproject 1: kernel and minimal userland

| Stage | Part | What it brings | State |
|---|---|---|---|
| 1.1 Boot | | boot in QEMU, MMU, device tree, exceptions, in-kernel tests | ✅ [#2](https://github.com/stafeto/stafeto/pull/2) |
| 1.2 Kernel | 1.2a Memory | page tables with W^X, buddy allocator, object pools, handles | ✅ [#3](https://github.com/stafeto/stafeto/pull/3) |
| | 1.2b Threads and interrupts | GICv2, virtual timer, address spaces with ASIDs, EL0 threads with FP/SIMD | ✅ [#4](https://github.com/stafeto/stafeto/pull/4) |
| | 1.2c System calls and scheduler | first system calls, 64-level scheduler, `init` from the boot image | ✅ [#5](https://github.com/stafeto/stafeto/pull/5) |
| 1.3 Messages and objects | 1.3a Teardown and quotas | cleanup queue in bounded portions, process tree, quotas | ✅ [#6](https://github.com/stafeto/stafeto/pull/6) |
| | 1.3b Channels and timers | channels, notifications, sessions with `CLIENT_GONE`, exit channel, program timers | ✅ [#8](https://github.com/stafeto/stafeto/pull/8) |
| | 1.3c Requests and replies | `send`, `receive`, `reply`, message buffer, handle transfer, priority ceiling, fast path | ✅ [#11](https://github.com/stafeto/stafeto/pull/11) |
| | 1.3d Memory objects | `mem_create`, `mem_map`, memory objects in messages, child processes with code | ✅ [#13](https://github.com/stafeto/stafeto/pull/13) |
| | 1.3e Interrupts and devices | `irq_bind`, device windows, a test driver | ✅ [#14](https://github.com/stafeto/stafeto/pull/14) |
| 1.4 Userland | | `init` with a service table and a watchdog, UART driver, shell, measurements | ✅ |
| | 1.4a GICv3 and HVF | GICv3 driver, runs on Apple silicon under HVF, test runs end through PSCI | ✅ [#16](https://github.com/stafeto/stafeto/pull/16) |
| | 1.4b Runtime and protocols | handles that own their entries, strict test builds, one time scale, `proto/wire` and `proto/init`, start protocol, service loop with sessions and a heartbeat, ELF reader in `bootimg` | ✅ [#17](https://github.com/stafeto/stafeto/pull/17) |
| | 1.4c init services | `init` starts services from its table, refuses a table with a cycle or a broken ceiling, serves names through `connect`, restarts crashed and silent services and marks broken ones | ✅ [#18](https://github.com/stafeto/stafeto/pull/18) |
| | 1.4d UART driver and shell | the kernel log, the PL011 driver on interrupts and the shell join init's table, `crash uart` shows the driver restart and the shell reconnecting | ✅ [#19](https://github.com/stafeto/stafeto/pull/19) |
| | 1.4e Measurements and diagnostics | machine-specific TCG and HVF measurements, call maxima and entry timing, optional event trace, panic frame symbols | ✅ [#20](https://github.com/stafeto/stafeto/pull/20) |

Subproject 1 is done when `cargo xtask run` reaches a shell prompt,
`crash uart` shows the driver restart and the shell reconnecting, and the
kernel image stays under 200 KB.

### Subproject 2 and later

| # | Subproject | State |
|---|---|---|
| 2 | Name space and services: in-memory file system, virtio disk, programs from disk, and a Rust POSIX library with a C ABI | 🚧 |
| 3 | Graphics and input: virtio-gpu, touch input, compositor | ⬜ |
| 4 | Phone shell: home screen, notifications, settings, UI toolkit | ⬜ |
| 5 | Packages: package format, signatures, installing from any source, app sandbox | ⬜ |
| 6 | Network: virtio-net, a TCP/IP stack | ⬜ |
| 7 | PinePhone port: boot through U-Boot, Allwinner A64 drivers | ⬜ |

### Subproject 2: name space and services

| Step | Deliverable and check | State |
|---|---|---|
| Virtual console | Boot to the shell on Apple Silicon through Virtualization.framework with `cargo xtask vz`; QEMU and HVF remain test platforms. | ✅ [#21](https://github.com/stafeto/stafeto/pull/21) |
| File groundwork | Read an e2fsprogs ext4 image in a guest with `cargo xtask ext4ro`; exercise RAM file descriptors and static Picolibc I/O with `cargo xtask ramfs` and `cargo xtask cprobe`. | ✅ [#23](https://github.com/stafeto/stafeto/pull/23), [#24](https://github.com/stafeto/stafeto/pull/24) |
| BusyBox shell | Run `cat` and an `ash` builtin script from boot images, then type `echo` and `exit` at an interactive `ash` prompt through the UART service. | ✅ [#24](https://github.com/stafeto/stafeto/pull/24), [#26](https://github.com/stafeto/stafeto/pull/26), [#27](https://github.com/stafeto/stafeto/pull/27) |
| Directory utility | Run BusyBox `ls` over RAM files, including `ls -la` and `ls --help` from the interactive `ash` prompt. | ✅ [#28](https://github.com/stafeto/stafeto/pull/28) |
| External programs | Load a static ELF from a file service and let `ash` start it, pass arguments and descriptors, and wait for its exit status. | ⬜ |
| Shell composition | Add descriptor duplication, redirection, pipes, and the signal behavior needed for pipelines and exit status. | ⬜ |
| Persistent files | Read ext4 through a Virtio block service, then qualify writes with `e2fsck` after normal and interrupted runs. Keep RAM files available for tests. | ⬜ |
| Integrated userland | Boot `ash` and a small set of BusyBox utilities from storage on QEMU and Apple Virtualization.framework; check commands, redirection, pipelines, and exit status. | ⬜ |

Program launch and block storage can proceed independently after the
interactive shell check. An ext4 implementation becomes writable only
after the recovery checks pass.

#### Userland layers

The kernel supplies isolation, scheduling, memory, handles, and IPC. A
process service should use the existing `rt` ELF loader to start programs
after boot and report exits. File, namespace, and terminal services own
paths, descriptors, and interactive I/O. The target is a Rust POSIX
service with a stable C ABI library for compatible programs and a small MIT
client for GPLv2-only BusyBox. The current
Picolibc build and small C hooks bootstrap BusyBox while that Rust
implementation is built.

Build upstream packages against a versioned AArch64 stafeto sysroot with
headers, the appropriate C ABI client, startup code, and port patches. Keep one pinned source
and patch manifest in `tools/`, then stage selected binaries and data into
a root image. The current Picolibc and BusyBox build scripts are the first
two package recipes. GPLv2-only packages retain a compatible C runtime and
call the Rust POSIX service through the MIT client; compatible programs can
use the Rust library directly. This lets more utilities share one build
interface without copying their source into the kernel.

#### Rust POSIX implementation

The target is the full mandatory POSIX.1-2024 interface, implemented in Rust
with C-compatible entry points, plus a conforming shell and utilities. Track
optional interface groups separately. The current Picolibc bridge covers
basic file calls and standard streams only. The GPL-3.0-or-later
Rust crates now keep local path state, own a descriptor table with
duplication, and perform bounded file operations through the RAM service. Each step below needs guest
checks for successful calls, failures, and ABI layout.

| Step | Interface and guest check | State |
|---|---|---|
| Rust pathname state | Keep the working directory and byte-oriented path components in GPL-3.0-or-later Rust; verify on the host and in a RAM file guest probe without linking BusyBox. | ✅ [#29](https://github.com/stafeto/stafeto/pull/29) |
| Rust file client | Implement file metadata, relative file access, working-directory changes, and directory iteration in a GPL Rust package; verify through the RAM service in a guest. | ✅ [#30](https://github.com/stafeto/stafeto/pull/30) |
| Rust file positioning | Add signed 64-bit `lseek`, all five POSIX.1-2024 origins, unchanged offsets on failure, and validated zero-length file I/O; verify on RAM files in the guest. | ✅ [#31](https://github.com/stafeto/stafeto/pull/31) |
| Rust descriptor ownership | Own local descriptors, shared offsets, `dup`/`dup2`/`dup3`, descriptor flags, and standard-stream redirection; verify limits and lifetime in the guest. | ✅ [#32](https://github.com/stafeto/stafeto/pull/32) |
| Initial Rust C ABI | Build ABI 1 headers, Rust startup and `libc.a`; boot a C main without Picolibc through both Cargo and standalone Clang linking; verify native-thread errno. | ✅ [#33](https://github.com/stafeto/stafeto/pull/33) |
| Rust stat metadata | Export `stat`, `fstat` and `lstat` with a checked LP64 layout, stable RAM inode identity and timestamp updates; verify through Cargo and standalone C linking. | ✅ [#34](https://github.com/stafeto/stafeto/pull/34) |
| Rust directory C ABI | Enumerate directories through owned descriptors with `opendir`, `fdopendir`, `readdir`, `closedir`, `dirfd`, rewind and position cookies; check inode identity, shared offsets and resource limits. | ✅ [#35](https://github.com/stafeto/stafeto/pull/35) |
| Rust process allocation | Export malloc, calloc, realloc, reallocarray, free and aligned allocation over a shared process heap; verify overflow, quota failure, data preservation and cross-thread ownership. | ✅ [#36](https://github.com/stafeto/stafeto/pull/36) |
| Rust directory selection and ordering | Add owned `scandir` results, C/POSIX `alphasort`, `strcoll`/`strxfrm`, locale selection and allocation-free `qsort`/`qsort_r`; check callback reentry and cleanup after partial allocation failure. | ✅ [#37](https://github.com/stafeto/stafeto/pull/37) |
| Shared Rust process file state | Serialize current RAM file operations through one owner; verify cross-thread descriptors, offsets, cwd, DIR lifetime and independent errno. Request cancellation and future blocking file backends remain work. | ✅ [#38](https://github.com/stafeto/stafeto/pull/38) |
| Rust console read concurrency | Wait for console input outside the file owner; verify file and heap progress, descriptor close/reuse, stdin redirection and byte-at-a-time bursts on UART and native Virtio. | ✅ [#39](https://github.com/stafeto/stafeto/pull/39) |
| Rust file request lifetime | Replace caller-stack jobs with checked value messages; reject malformed requests before heap startup and preserve full message payloads across nested RAM calls. | ✅ [#40](https://github.com/stafeto/stafeto/pull/40) |
| Rust IPC wait interruption | Wake a live IPC client with Interrupted/EINTR, release queued transfers and wait references, preserve delivered handles and validate the next reply token; check UART and Virtio reads. | ✅ [#41](https://github.com/stafeto/stafeto/pull/41) |
| Rust cancellation and signals | Add pthread lifecycle, cancellation state/type and cleanup handlers, service-side removal of deferred reads, accepted-operation result cleanup, and signal delivery with documented restart behavior. | 🚧 |
| Rust library foundation | Complete allocation, ELF TLS loading, shared multi-thread file state, remaining C interfaces and headers, and argument/environment inheritance in the versioned sysroot. | 🚧 |
| Files and directories | Implement descriptors, paths, metadata, directory iteration, and errors in Rust; run BusyBox `ls /`, `ls /etc`, and `ls -la` against RAM files. The current C bridge is a temporary probe. | 🚧 |
| Program lifecycle | Load a static ELF from a file service and return its exit status through `posix_spawn` and `waitpid`; implement `fork` semantics for the standard and the shell's external-command path. | ⬜ |
| Shell I/O | Expose Rust descriptor duplication through the POSIX service and C ABI; add inherited descriptors and pipes, then verify `ash` pipelines and file output. | ⬜ |
| Terminal input | Add a terminal service with line discipline, `termios`, window size, and BusyBox line editing; verify backspace, arrows, history, and Ctrl-C. | ⬜ |
| Remaining interfaces | Add threads, signals, time, process control, sockets, permissions, and required utility behavior; publish a feature and option matrix. | ⬜ |
| Conformance checks | Run API, shell, and utility suites on QEMU and Apple Virtualization.framework; record every remaining standard requirement and fix failures. | ⬜ |

The initial Rust sysroot is experimental ABI 1 for AArch64 LP64.
`python3 tools/build-posix-sysroot.py --probe` stages headers and `lib/libc.a`
under `target/posix-sysroot/0.1.0/aarch64-stafeto` and links the C probe.
It currently covers file calls, stat metadata, directory streams, process
allocation, directory selection, sorting, the C/POSIX locale and startup
with an empty environment. Console waits leave the shared file owner available;
stdio, general ELF TLS, cancellation and the remaining headers are pending.
See [notes/m2-rust-posix-abi.md](notes/m2-rust-posix-abi.md) and
[notes/m2-rust-posix-stat.md](notes/m2-rust-posix-stat.md), plus
[notes/m2-rust-posix-dir.md](notes/m2-rust-posix-dir.md) and
[notes/m2-rust-posix-heap.md](notes/m2-rust-posix-heap.md) and
[notes/m2-rust-posix-scan.md](notes/m2-rust-posix-scan.md) and
[notes/m2-rust-posix-shared.md](notes/m2-rust-posix-shared.md) and
[notes/m2-rust-posix-input.md](notes/m2-rust-posix-input.md) and
[notes/m2-rust-posix-messages.md](notes/m2-rust-posix-messages.md) for the boundary.
Process file requests carry copied values instead of caller-stack jobs.
Directory identifiers remain process-local; cancellation, signals and recovery
still need implementation.
File timestamps currently use the platform counter; epoch time, symbolic
links, credential checks and terminal-owned metadata remain pending.

`ls` is a BusyBox utility. Its current in-shell path uses BusyBox's
single-process applet mode; other external programs still need the
process service. A claim of full support follows the conformance matrix,
not the first successful BusyBox build.

Multi-core support is a separate subproject; its place in the order will be
decided after subproject 3.

An integration target across subprojects 2 and 3 is to launch a separate
Doomgeneric program from BusyBox `ash` with a Freedoom IWAD. The first
playable QEMU check will open a level, accept keyboard input, and return
to the shell on exit. It depends on program launch, file access, graphics,
and input; sound, networking, and saved games can follow later.

## Build and run

You need rustup, QEMU, and dtc (on macOS: `brew install qemu dtc`). rustup
installs the Rust version, components, and targets itself from
`rust-toolchain.toml`.

| Command | What it does |
|---|---|
| `cargo xtask build` | builds the kernel into `target/stafeto.img` (under `CARGO_TARGET_DIR` when it is set) and checks that the image is under 200 KB |
| `cargo xtask run` | runs the system in QEMU to the shell's prompt; exit with Ctrl-A, then X |
| `cargo xtask run --hvf` | the same under HVF on a Mac with Apple silicon; elsewhere it fails and says why |
| `cargo xtask vz` | on an Apple silicon Mac, boots the shell through Virtualization.framework without QEMU; exit with Ctrl-C |
| `cargo xtask rtbench` | runs fixed-duration RTOS primitive and timer-wakeup workloads three times on QEMU TCG, and also HVF and VZ on Apple Silicon; `--repeats 1` is a quick smoke run |
| `cargo xtask ext4ro` | boots a QEMU guest that reads a checked-in ext4 image created by e2fsprogs; no block driver is involved yet |
| `cargo xtask ramfs` | boots a RAM file service and checks file descriptors, reads, writes, seeks, sizes, and standard output in QEMU |
| `cargo xtask posix-abi` | boots C file and allocation ABI probes linked with Rust startup through Cargo and standalone Clang, then checks errno isolation and shared allocation on native guest threads; no Picolibc |
| `cargo xtask posix-input` | verifies file and heap progress during a UART input wait, descriptor reuse, stdin redirection and burst reads; included in `posix-abi` and `ci` |
| `cargo xtask posix-input-vz` | verifies the same scenario through native Virtio input on Apple silicon without QEMU; requires Virtualization.framework |
| `cargo xtask posix-shared` | verifies shared Rust file state and errno, rejects malformed messages before heap startup, and checks full message payloads; included in `posix-abi` and `ci` |
| `cargo xtask posix-interrupt` | verifies IPC wait interruption, transfer cleanup, reply-token reuse and Rust POSIX EINTR on UART; included in `posix-abi` and `ci` |
| `cargo xtask posix-interrupt-vz` | verifies the same IPC cases and Virtio read interruption, including timer/channel cleanup, on Apple silicon |
| `cargo xtask cprobe` | builds pinned Picolibc 1.8.12 with local LLVM, then boots a static C program using file I/O and `printf` through the RAM service |
| `cargo xtask busybox` | builds pinned BusyBox 1.37.0 and Picolibc, then runs BusyBox `cat /etc/motd` against the RAM service in QEMU |
| `cargo xtask ash` | runs BusyBox `ash -c 'echo shell-ready; exit 0'` in QEMU and checks its output and exit code |
| `cargo xtask ash-shell` | opens BusyBox `ash` on the QEMU UART; `ls /` and `ls -la` work, `exit` leaves the shell, and Ctrl-A, X quits QEMU |
| `cargo xtask ash-dialog` | checks `echo`, `ls`, missing paths, and `exit` at the `ash` prompt in QEMU |
| `cargo xtask ls` | runs BusyBox `ls` against the RAM file service in a separate QEMU image |
| `cargo xtask test` | host tests, boot in QEMU, a dialog with the shell, and tests inside the kernel |
| `cargo xtask gdb` | QEMU stops before the kernel starts and waits for a debugger on port 1234 |
| `cargo xtask ci` | formatting, clippy, and all tests |
| `cargo xtask hvf` | on a Mac with Apple silicon: boot, the dialog with the shell, the test `init`, the tests of init's service table and the kernel tests under HVF, on Apple's GICv3 and on QEMU's GICv2; elsewhere it says why it skips; `ci` does not run it |

`rtbench` adapts six [Thread-Metric](https://github.com/zephyrproject-rtos/zephyr/blob/main/tests/benchmarks/thread_metric/thread_metric_readme.txt) workloads to stafeto's primitives: baseline arithmetic, cooperative yields, preemptive notifications, channel request/reply, self-notification, and memory-object allocation. It also follows [Zyclictest](https://docs.zephyrproject.org/latest/services/debugging/zyclictest.html) by measuring 1,000 periodic timer wakeups at 1 ms intervals, both while idle and with a lower-priority CPU load. It reports median operations per second across runs, timer p99 and worst observed latency, and missed periods. The guest prints only after each workload. These are adapted workloads, not official Thread-Metric results; the hardware-interrupt cases await a portable guest interrupt source. Virtual-machine measurements do not establish a physical worst-case latency.

The Rust POSIX probe included in `cargo xtask test` and `cargo xtask ci` needs Clang/LLVM, LLD and Python 3. The C and BusyBox probes need Clang/LLVM, LLD, Meson, Ninja, Python 3, GNU Make and Git. On macOS, install them with `brew install llvm lld meson ninja make`. Picolibc and BusyBox sources and build output stay under `target/`. See [notes/m2-ram-posix.md](notes/m2-ram-posix.md) for the current BusyBox port boundary.

How to debug hangs and crashes: [docs/debugging.md](docs/debugging.md).

## License

The kernel, services, drivers, tools, and Rust POSIX implementation
(beginning with `lib/posix-path`) are distributed under GPL-3.0-or-later
([LICENSE](LICENSE)). Libraries for programs (`lib/abi`, `lib/rt`,
`lib/bootimg`, `proto/*`) and the temporary Picolibc bridge (`lib/posix`)
are distributed under MIT
([LICENSE-MIT](LICENSE-MIT)), so programs for stafeto can be released under
any license.

BusyBox is GPL-2.0-only and links statically with the temporary MIT bridge.
The GPL-3.0-or-later Rust POSIX implementation will run in a separate service;
a small MIT client can carry requests from BusyBox without linking that service
into the BusyBox binary. Other programs can use a GPL-compatible Rust C ABI
library directly. See the [BusyBox license](https://busybox.net/license.html).
The [FSF compatibility table](https://www.gnu.org/licenses/gpl-faq.en.html)
explains the linking restriction. `cargo xtask ci` checks this dependency boundary.
It also checks the GPL-3.0-or-later package declarations and SPDX identifiers
in every Rust POSIX source module and C header. The generated Rust POSIX
sysroot includes the GPL license text as `LICENSE`. Third-party dependencies
retain their own licenses.
