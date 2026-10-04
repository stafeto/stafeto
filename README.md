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

Numbers below are from step 5e (`m5e-pipes`).

**Boot and machines.** The kernel boots as an arm64 Image from EL2 or EL1,
turns on the MMU, reads the device tree and checks its boot image. It runs
on three kinds of machine:

- QEMU `virt` under emulation (TCG), with GICv2 or GICv3;
- QEMU with HVF on a Mac with Apple silicon, on Apple's GICv3 and on
  QEMU's GICv2;
- Apple Virtualization.framework without QEMU: the same kernel image,
  with the Virtio PCI console driven by a user-space service
  (`cargo xtask vz`).

**Kernel.** 33 system calls, the same on every machine, over 64-bit handles
with rights: processes, threads, channels, sessions, timers, memory
objects, device windows and interrupt bindings. Synchronous requests and replies carry up to 1 KiB and
four handles; a service runs at its client's priority under its own
ceiling, and a fast path hands the CPU straight to a waiting service. The
scheduler has 64 priority levels (round robin and FIFO) with tickless
preemption. Every process pays for its kernel memory from a quota, memory
is never writable and executable at once, and long operations run in
bounded portions. Device interrupts reach drivers as notifications, and
a driver gets contiguous, optionally uncached memory for DMA. The kernel
drives no device with DMA. A fault ends only its own process. The kernel
image is 158,784 bytes of a 204,800-byte budget, on QEMU and on Apple VZ.

**User space and services.** `init` starts services from a table in
dependency order, hands out sessions by name, restarts a service that
crashes or goes silent and marks it broken after five failures in 60 s.
The PL011 driver (`services/uart`) owns the console on interrupts and
shows the kernel log; on Apple VZ the Virtio console's driver
(`services/virtio-console`) does the same with the same protocol, and
`init` resets its device before its DMA memory goes. A RAM file service (`services/ramfs`) holds files
and directories. Programs build on `lib/rt`, which owns handles, runs
service loops and starts children through a start protocol.

**Shells.** The native shell boots by default and knows `help`, `echo`,
`uptime`, `ps`, `mem`, `bench`, `trace` and `crash uart`; the last one
crashes the driver, `init` restarts it and the shell reconnects. Separate
images run BusyBox 1.37.0 against the RAM file service: `cat`, `ash -c`
and an interactive `ash` on the UART with `echo` and `ls -la`. BusyBox
links statically with relibc over the Rust POSIX layer. The dialog's
`ash` is a POSIX process started from `/bin/ash`; it forks and execs the
files of `/bin` (`/bin/ls -la`, `/bin/ash -c 'exit 3'`). Pipelines work in
the dialog (`ls /etc | cat`, a pipeline of three, `ls /bin | wc -l`, a job
in the background with `wait`), and `/dev/null` takes redirections. The
terminal service provides canonical input, termios and window sizes,
process groups, Ctrl-C/Ctrl-Z and `jobs`, `bg` and `fg`. Interactive ash
also runs through a PTY master. The service has eight PTY pairs beside
the console; `posix_openpt`, `grantpt`, `unlockpt` and `ptsname` expose
`/dev/ptmx` and `/dev/pts/N`. `poll`, `ppoll`, `select` and `pselect`
wait on pipes and terminal descriptions. [notes/m5f-tty.md](notes/m5f-tty.md)
has their limits and checks.

**POSIX layer in Rust.** The goal is the full mandatory POSIX.1-2024
interface. The C library is relibc (a fork pinned by
`tools/build-relibc.py`, `cargo xtask relibc`); below it the Rust layer
is the system part, with no C names of its own: the platform functions
`stafeto_*` relibc calls (`lib/posix-platform`) over paths, descriptors,
files, `stat` and directories; the heap; the table of threads, waits by
address and deferred cancellation; clocks and sleep; signal actions,
masks, `sigwait`, `sigwaitinfo`, `sigtimedwait` and `SA_SIGINFO`; process
IDs and credentials. Every POSIX program starts through `posix-crt` and
relibc, the Rust guest probes on a C main too (`tests/libc-ffi`); the
native probe `posix-tls` checks the layer's TCB for threads relibc did not
start. The layer runs without helper
threads: a single-threaded program has one thread; mutexes, `once` and joins
wait by address in the layer with no kernel call when uncontended; the heap,
the descriptor table and the table of threads live under the layer's locks,
whose holders run at the process ceiling; a read of the console is a long
operation in two steps that a signal interrupts. Guest probes check them on
QEMU and Apple VZ.

**Processes.** The process service creates every POSIX process, keeps its
record (256 of them; PID = index + 256 * generation, never 1) and hands
out its sessions. `posix_spawn` and `exec` start a program from a file of
the RAM file service: a loader in the new process opens the file through
a session that only `init` and the process service hand out, maps its
segments and jumps; an error before the image is ready comes back from
`posix_spawn`, a set-ID file sets the new process's IDs, and the parent
holds no handle of the child. A spawned child shares the open
descriptions its parent keeps; `exec` keeps the PID, the open files and
the mask, and an `exec` that fails leaves the old image whole.
`posix_spawn` takes `POSIX_SPAWN_SETPGROUP`, `SETSID`, `SETSIGMASK`,
`SETSIGDEF`, `RESETIDS` and file actions; `waitpid`, `waitid` and
`WNOHANG` take zombies and
tell an exit from a death by a signal (`WIFSIGNALED` for `SIGTERM` differs
from `exit(143)`); `kill`, `killpg`, `kill(0)` and `kill(-1)` reach any
process, a handler runs on the target's router thread, and `SIGKILL`
works on a child that blocks every signal; `SIGCHLD` carries the child's
PID and status to `sigwaitinfo`. Process groups and sessions follow
`setpgid`, `setsid`, `getpgid` and `getsid`; orphans go to PID 1, which
the service itself plays. The clock service asks the process service for
the effective UID before `clock_settime`. The C probe `posix-procs`,
`cargo xtask process-steps` and `rtbench` rows S10 to S22 check it; on HVF a
`posix_spawn` of a file takes 102 us p50 to the child's `main` and an
`exec` 113 us (10-minute run of 5c; 121 and 139 us in the run of 5d, at a
host load of about 2).

`fork` copies the parent's whole memory (the heap, the segments, the
stack) into the child through the child's own loader, at the forking
thread's level and with no change to the kernel. The parent's other
threads stop first and the child has one thread; descriptions, offsets
and the mask carry over, pending signals do not, and a signal sent to the
group during the copy reaches both. `vfork` is `fork`, and `pthread_atfork`
handlers run in POSIX's order. There is no copy on write: the child pays
for every page, so the cost grows with the parent's memory. On HVF (10
minutes, p50) `fork` to the child's first statement takes 102 us for a
small parent, 172 us with 1 MiB of heap and 623 us with 8 MiB (rows S15);
`fork`, `exec` of a small file and `waitpid` take 246 us (S16); each other
thread of the parent adds about 7 us to a `fork` and 5 us to an `exec`
(S17, S18). [notes/m5d-fork.md](notes/m5d-fork.md) has the table and the
limits, [notes/m5b-processes.md](notes/m5b-processes.md) and
[notes/m5c-spawn-exec.md](notes/m5c-spawn-exec.md) those of the steps
before.

Pipes live in their own service (`services/pipe`): 64 pipes with a ring
of 4 KiB each, `PIPE_BUF` 512, blocking reads and writes as long
operations in two steps that a signal cancels (`SA_RESTART` continues them),
`SIGPIPE` before `EPIPE`, `O_NONBLOCK` as a flag of the description. Ends
cross `fork`, `posix_spawn` (`adddup2`) and `exec`, and the service sees a
dead process as an end that closes (the reader gets end of file). `/dev/null`
is a null device of the RAM service. Every step of the service stays below
the kernel's term B of 20,536 ticks (`cargo xtask process-steps`). On HVF
(10 minutes, p50) a byte goes through two pipes to another process and back
in 5.5 us (S19), 1 MiB goes through a pipe at 250 MB/s in writes of 512
bytes and 432 MB/s in writes of 4 KiB (S20), and `ls /etc | cat` as two
`fork`s and two `exec`s takes 623 us (S22).
[notes/m5e-pipes.md](notes/m5e-pipes.md) has the rows, the limits and the
conformance list.

**Random numbers.** A driver for the Virtio entropy device
(`services/virtio-rng`) feeds the entropy service (`services/entropy`), which
gives each POSIX process a key of 32 bytes; the layer of the process runs a
ChaCha20 generator with fast key erasure on it, so `getentropy`, `getrandom`,
`arc4random`, the reads of `/dev/random` and `/dev/urandom` (character
devices of the RAM service) and the names of `mkstemp` need no request once
the key is there, and a child of `fork` takes a key of its own. On HVF and
Apple VZ (10 minutes, p50) `getentropy` of 32 and of 256 bytes takes 0.21 and
0.93 us with two kernel calls (S23, S24), and a read of 4 KiB of
`/dev/urandom` 12.3 us (S25). Creating the temporary file waits for 5i.
[notes/m5e2-entropy.md](notes/m5e2-entropy.md) has the rows, the steps of
the services and the limits.

**C library.** relibc (MIT) is the C library of every POSIX program,
BusyBox included; its platform is the layer's `stafeto_*` functions.
os-test's io, malloc, process and signal suites, `basic/spawn`, `basic/unistd`
`exec*` and the `basic` tests that call `fork` run on it in `ci` from files,
one boot a suite. The baseline before the terminal extension had 121
passes, 73 failures and 11 unsupported cases out of 205; `ci` fails when
a test that passed stops passing. The PTY and termios suites now exercise
the terminal APIs, and readiness tests cover all four waiting interfaces.
The remaining file and signal work includes `mkstemp`, `access` and
`sigaltstack`. relibc
builds at its own level 3: user-space programs have no size limit, only
the kernel has one. Details are in
[docs/status.md](docs/status.md).

**Tests.** The kernel test image runs 182 tests (197 under `-icount`),
the EL0 test `init` runs 228 and `kcore` has 407 host tests; `cargo xtask
ci` runs them with the guest probes, and `cargo xtask hvf` runs them on
Apple silicon.

**Known limits.**

- Apple VZ gives the kernel no port: a kernel panic there shows nothing
  and powers the machine off (a VZ probe fails with a hint), and VZ
  clears RAM at a reset, so the log does not outlive it; the same image
  under HVF shows the panic. On VZ `rtbench` runs beside the console's
  driver.
- One CPU core only; no SMP.
- No PinePhone port yet.
- `fork` copies everything the layer maps, with no copy on write (about
  70 us a MiB on HVF); shared anonymous memory and mappings made past the
  layer are not in the copy, and a program that `init` starts itself gets
  `ENOSYS`.
- 255 POSIX processes at once: the process service holds 256 records,
  and the RAM file and clock services keep 320 sessions each.
- Pipes: 64 of 4 KiB in the pipe service; one session (a process) has 16
  live pipes (`EMFILE`), and a tree of processes under one program
  `init` started has 48 of them (`ENFILE`), 96 of the 128 blocking reads
  and writes that may wait (`EAGAIN` past them, and past 8 at one end or
  16 in one process) and 255 sessions of the service's 320.
- Random numbers come from the Virtio entropy device alone. After a
  restart of the entropy service the processes that ran before keep their
  generators but not their session: their children get `ENOSYS` from
  `getentropy`, and `arc4random` ends them.
- Files live in RAM; ext4 is read from an image inside the guest, with no
  block driver.

## Build and run

You need rustup, QEMU and dtc (on macOS: `brew install qemu dtc`); rustup
installs the toolchain from `rust-toolchain.toml`. The POSIX probes in
`test` and `ci` also need Clang/LLVM, LLD, Python 3, GNU Make and Git (for
relibc and BusyBox; on macOS: `brew install llvm lld make`). The VZ commands need the Xcode
command line tools for `swiftc` and `codesign`.

```sh
cargo xtask build        # kernel and boot image in target/, checks the 200 KiB budget
cargo xtask run          # QEMU to the shell prompt (Ctrl-A X quits); --hvf on Apple silicon
cargo xtask vz           # the shell through Apple Virtualization.framework (Ctrl-C quits)
cargo xtask test         # host tests, boot checks, shell dialog, init and kernel tests, POSIX probes; --jobs N boots at a time
cargo xtask ci           # formatting, clippy, licence checks, then everything test does; --jobs N as in test
cargo xtask hvf          # the test set under HVF on Apple silicon; skips elsewhere
cargo xtask rtbench      # throughput and 1 ms timer wakeups on TCG, HVF and VZ; --minutes N runs HVF and VZ together
cargo xtask ash-shell    # interactive BusyBox ash over the QEMU UART
cargo xtask os-test      # os-test's io and malloc suites on relibc, a table in target/measure/
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
| `tools/` | relibc and BusyBox builds, the VZ runner, licence check |
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
| Subproject 2 design | process model, IPC transport for POSIX, libc choice and the licence of the in-process layer | ✅ |
| Kernel | a DMA memory objects, the Virtio console as a user-space service · b process IDs out of the kernel, thread end notifications, teardown in portions | ✅ [#71](https://github.com/stafeto/stafeto/pull/71), [#72](https://github.com/stafeto/stafeto/pull/72) |
| POSIX: transport | mutex and heap without IPC on the fast path, no helper threads per process | ✅ [#74](https://github.com/stafeto/stafeto/pull/74) |
| POSIX: C library | relibc on top of the Rust system layer; BusyBox builds with it; the first os-test row | ✅ [#75](https://github.com/stafeto/stafeto/pull/75) |
| POSIX: process service | process service, `posix_spawn` from the boot image, `waitpid`, `kill`, process groups and sessions | ✅ [#76](https://github.com/stafeto/stafeto/pull/76) |
| POSIX: spawn and exec | boot image files in the RAM service, a loader, `posix_spawn` and `exec` from files, set-ID through the file service, os-test from files, measured steps of the process service | ✅ [#78](https://github.com/stafeto/stafeto/pull/78) |
| POSIX: fork | `fork` with the loader copying the parent; the other threads stop for it; `ash` runs external programs; rtbench rows by memory size | ✅ [#79](https://github.com/stafeto/stafeto/pull/79) |
| POSIX: pipes | a pipe service, `pipe`, ends across `fork`, `posix_spawn` and `exec`, `SA_RESTART` and `SIGCHLD` in the shell, `setpgid` of a child, `/dev/null`; `ash` runs `ls \| cat`; rtbench rows of pipes | ✅ [#80](https://github.com/stafeto/stafeto/pull/80) |
| POSIX: terminal | a terminal service with `termios`, pseudo-terminals, job control, `poll` and `select`, Ctrl-C to the foreground group, the missing `ash` built-ins | 🚧 |
| POSIX: random numbers | a Virtio entropy driver and an entropy service, a ChaCha20 generator in the layer, `getentropy`, `getrandom`, `arc4random`, `/dev/random` and `/dev/urandom`, names of `mkstemp` from the generator; rtbench rows of the generator | 🚧 |
| POSIX: files with writing | the RAM file service creates files and directories, `/tmp`, `fcntl` locks, FIFOs | ⬜ |
| POSIX: conformance | the full os-test suite and Open POSIX in `ci`, honest headers and `sysconf`, `cargo xtask coverage` checking the standard's interface list against the C library at every step | ⬜ |
| POSIX: timers and scheduling | POSIX timers, CPU time, `SCHED_FIFO` and `SCHED_RR`, queued signals | ⬜ |
| POSIX: shared memory | file `mmap`, `mprotect`, `shm_open`, named semaphores | ⬜ |
| POSIX: rest of the C library | complex and long double math, `fenv`, `iconv`, message catalogues, `wordexp`, user and group databases | ⬜ |
| POSIX: local sockets | AF_UNIX sockets; IPv4 comes with the network subproject | ⬜ |
| POSIX: utilities | the POSIX utilities from BusyBox and the missing ones | ⬜ |
| PinePhone bring-up | U-Boot `booti`, 16550 UART driver, Allwinner A64 device tree, `ash` on the serial port | ⬜ |

### Later subprojects

- Graphics and input: virtio-gpu, touch input, a compositor; Doomgeneric started from `ash` as the first playable target.
- Phone shell: home screen, notifications, settings, a UI toolkit.
- Packages: package format, signatures, app sandbox.
- Network: virtio-net, a TCP/IP stack and IPv4 sockets.
- SMP: more than one CPU core.

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

Every source file carries an `SPDX-License-Identifier` line. `cargo xtask
ci` checks the licence of every crate and file, that the GPL-2.0-only
programs (BusyBox) link no bare GPL-3.0 code, and that relibc and everything it links are under licences
GPL-2.0-only takes. Other third-party dependencies keep their own licences
([docs/licenses](docs/licenses)).
