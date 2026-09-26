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
and on Apple silicon under HVF. What works today:

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
  EL0.
- **Real time:** program timers fire at the priority of their slots, in
  bounded portions after the timer's interrupt, which takes no timer off
  itself.
- **Faults:** a program fault ends only its own process, and the parent
  learns why through its exit channel; the tests check it on child
  processes with code that `init` loads from the boot image.

`cargo xtask run` shows `init` saying hello from EL0 and two of its threads
taking turns. `cargo xtask test` runs the tests on QEMU's GICv2 and GICv3;
`cargo xtask hvf` runs them on a Mac with Apple silicon, on Apple's GICv3
and on QEMU's GICv2.

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
| 1.4 Userland | | `init` with a service table and a watchdog, UART driver, shell, measurements | 🚧 |
| | 1.4a GICv3 and HVF | GICv3 driver, runs on Apple silicon under HVF, test runs end through PSCI | 🚧 |

Subproject 1 is done when `cargo xtask run` reaches a shell prompt,
`crash uart` shows the driver restart and the shell reconnecting, and the
kernel image stays under 200 KB.

### Later subprojects

| # | Subproject | State |
|---|---|---|
| 2 | Name space and services: in-memory file system, virtio disk, programs from disk, a libc-like library, partial POSIX | ⬜ |
| 3 | Graphics and input: virtio-gpu, touch input, compositor | ⬜ |
| 4 | Phone shell: home screen, notifications, settings, UI toolkit | ⬜ |
| 5 | Packages: package format, signatures, installing from any source, app sandbox | ⬜ |
| 6 | Network: virtio-net, a TCP/IP stack | ⬜ |
| 7 | PinePhone port: boot through U-Boot, Allwinner A64 drivers | ⬜ |

Multi-core support is a separate subproject; its place in the order will be
decided after subproject 3.

## Build and run

You need rustup, QEMU, and dtc (on macOS: `brew install qemu dtc`). rustup
installs the Rust version, components, and targets itself from
`rust-toolchain.toml`.

| Command | What it does |
|---|---|
| `cargo xtask build` | builds the kernel into `target/stafeto.img` (under `CARGO_TARGET_DIR` when it is set) and checks that the image is under 200 KB |
| `cargo xtask run` | runs the system in QEMU; exit with Ctrl-A, then X |
| `cargo xtask test` | host tests, boot in QEMU, and tests inside the kernel |
| `cargo xtask gdb` | QEMU stops before the kernel starts and waits for a debugger on port 1234 |
| `cargo xtask ci` | formatting, clippy, and all tests |
| `cargo xtask hvf` | on a Mac with Apple silicon: boot, the test `init` and the kernel tests under HVF, on Apple's GICv3 and on QEMU's GICv2; elsewhere it says why it skips; `ci` does not run it |

How to debug hangs and crashes: [docs/debugging.md](docs/debugging.md).

## License

The kernel, services, drivers, and tools are distributed under
GPL-3.0-or-later ([LICENSE](LICENSE)). Libraries for programs (`lib/abi`,
`lib/rt`, `lib/bootimg`, `proto/*`) are distributed under MIT
([LICENSE-MIT](LICENSE-MIT)), so programs for stafeto can be released under
any license.
