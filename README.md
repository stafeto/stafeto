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

Subproject 1, stage 1.2 (kernel: memory, threads, scheduler) is done. The
kernel, in arm64 Image format, boots in QEMU, verifies the boot image, and
starts `init` from it at EL0. Programs use the first system calls
(`debug_write`, `yield`, `thread_*`, `process_*`, `handle_close`,
`object_info`). A scheduler with 64 priority levels, a round-robin queue
with a 4 ms quantum, and FIFO preempts threads on a timer with no periodic
tick. Each process has its own address space with an ASID; registers and
FP/SIMD state are saved on every switch. A program fault terminates only
its own process, and the parent reads the cause. Below the kernel: its own
page tables with W^X, a buddy allocator, object pools, 64-bit handles with
rights, a GICv2, and a virtual timer. `cargo xtask run` shows `init` saying
hello from EL0 and its two threads taking turns. Part 1.3a (teardown and
quotas) is done: kernel objects go through a cleanup queue in chunks with
interrupt polling, processes form a tree, and a process's death terminates
its descendants; each process's kernel memory is charged against its quota
and returned to the parent precisely. Next is part 1.3b: channels,
sessions, notifications, and program timers.

## Build and run

You need rustup, QEMU, and dtc (on macOS: `brew install qemu dtc`). rustup
installs the Rust version, components, and targets itself from
`rust-toolchain.toml`.

| Command | What it does |
|---|---|
| `cargo xtask build` | builds the kernel into `target/stafeto.img` and checks that the image is under 200 KB |
| `cargo xtask run` | runs the system in QEMU; exit with Ctrl-A, then X |
| `cargo xtask test` | host tests, boot in QEMU, and tests inside the kernel |
| `cargo xtask gdb` | QEMU stops before the kernel starts and waits for a debugger on port 1234 |
| `cargo xtask ci` | formatting, clippy, and all tests |

How to debug hangs and crashes: [docs/debugging.md](docs/debugging.md).

## License

The kernel, services, drivers, and tools are distributed under
GPL-3.0-or-later ([LICENSE](LICENSE)). Libraries for programs (`lib/abi`,
`lib/rt`, `lib/bootimg`, `proto/*`) are distributed under MIT
([LICENSE-MIT](LICENSE-MIT)), so programs for stafeto can be released under
any license.
