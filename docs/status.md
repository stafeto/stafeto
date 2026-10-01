# Status details

The README gives the short status. This page keeps the details that are
useful when working on the code: what the kernel offers, what the Rust
POSIX layer covers, and which commands check each piece. It describes
`main` at 764be2a.

## Kernel

- **Boot:** arm64 Image, drop from EL2, MMU on, device tree, checked boot
  image. GICv2 or GICv3 is chosen from the device tree; drivers reach
  device registers with single loads and stores, which a hypervisor can
  emulate.
- **Memory:** kernel page tables with W^X, a buddy frame allocator,
  object pools, an address space with an ASID per process. Every process
  pays for its kernel memory from its quota. Memory objects take all their
  pages when they are made; a process maps them R, RW or RX into its own
  space or into a process whose handle with `MANAGE` it holds. The
  segments and the stack of `init` are memory objects too. A holder of
  `DEVICE` makes a contiguous object for a device's DMA: one aligned block
  whose physical address comes back with the handle, never executable,
  and uncached in every mapping when asked; `rt::dma` cleans and
  invalidates cache lines from EL0.
- **Execution:** EL0 threads with registers and FP/SIMD saved on every
  switch; 64 priority levels, round robin with a 4 ms quantum and FIFO;
  tickless timer preemption. A thread made with an exit channel
  (`thread_create` `x7`, `x8`) tells of its end through `thread_exit` with
  a notification once it left the scheduler, so its stack may go; the end
  of its process replaces it.
- **System calls:** `handle_close`, `handle_duplicate`, `channel_create`,
  `send`, `receive`, `reply`, `notify`, `mem_create`,
  `mem_map`, `mem_unmap`, `mem_protect`, `process_create`, `process_kill`,
  `process_exit`, `thread_create`, `thread_start`, `thread_exit`,
  `thread_set_priority`, `thread_interrupt`, `thread_upcall_bind`,
  `thread_upcall_control`, `thread_upcall_request`, `thread_upcall_return`,
  `yield`, `device_window_create`, `irq_bind`, `irq_ack`, `clock_now`,
  `timer_create`, `timer_set`, `timer_cancel`, `object_info`,
  `debug_write`; 33 in all, the same on every machine. Numbers 29
  (`console_poll` of the old VZ build) and 35 (`request_identity`) are
  retired and fail as unknown ones, and so does kind 10 of `object_info`;
  the process service names its clients by the labels of the sessions it
  gives. `process_kill` takes the level of the teardown it starts.
- **Messages:** requests and replies of up to 1 KiB, the first 64 bytes in
  registers and the rest through a per-thread message buffer; up to four
  handles move with a message and keep their rights and labels. A service
  works at its client's priority under its own ceiling until it replies; a
  fast path hands the CPU straight to a waiting service. A live IPC wait
  can be interrupted.
- **Upcalls:** a thread with `MANAGE` rights can enter a computing or
  IPC-waiting thread of another process and later restore its registers,
  TLS, FP/SIMD state and message buffer, including nested entries. The
  POSIX layer delivers signals this way.
- **Devices:** a device interrupt reaches its driver as a channel
  notification, and the line stays masked until `irq_ack`; a device window
  maps device registers into a driver, never executable; a driver that dies
  frees its line at once.
- **Timers:** program timers fire at the priority of their slots, in
  bounded portions after the timer interrupt; a process pays for up to
  192, the system holds up to 8,192, and arming never fails.
- **Faults:** a fault ends only its own process, and the parent learns why
  through its exit channel.
- **Kernel log:** a ring of 64 records that the console driver reads; the
  kernel prints a record itself only while no driver holds the console,
  and a panic prints what nobody showed.

Bounded paths with interrupts masked are listed in
[non-preemptible-paths.md](non-preemptible-paths.md).

## User space

- `lib/rt`: handles that own their table entries, one time scale shared
  with the kernel, bounded waits, the start protocol (`proto/wire`,
  `proto/init`), service loops with per-client sessions and a heartbeat.
- `services/init`: service table in dependency order, names through
  `connect`, restarts with a growing pause, broken after five failures in
  60 s.
- `services/uart`: PL011 console on interrupts at priority 60, kernel log
  between whole client lines, one input reader at a time (`proto/uart`).
- `services/virtio-console`: the Virtio PCI console of Apple VZ with the
  same protocol and the same rings, on its INTx line, its queues in a
  contiguous uncached DMA object from `init`; output never waits for
  the host, and the end of the host's input leaves the console with
  output; `init` resets the device and clears the function's command
  word before the object goes.
- `services/ramfs`: RAM files and directories (`proto/fs`).
- `services/clock` and `services/process`: realtime clock, process
  identity and credentials for the POSIX layer (`proto/clock`,
  `proto/process`). The process service keeps 256 records, PID = index +
  256 * generation, and gives each its session through a label of its
  own. A thread of the service asks `init` for each POSIX process `init`
  loaded (`ADOPT`, root only for the record of the table that has it),
  makes its record and gives `init` the session (`ADOPTED`), which `init`
  puts in the process's start data before the process starts; `init`
  never sends the service a request. A process gets a session for its
  native child (`Child`, 32 live children a record, a handle with
  `MANAGE`). A record goes with the last copy of its session.

## Rust POSIX layer

ABI 1 for AArch64 LP64 is experimental.
`python3 tools/build-posix-sysroot.py --probe` stages headers and
`lib/libc.a` under `target/posix-sysroot/0.1.0/aarch64-stafeto` and links
the C probe. No real program uses the layer yet; implementation is paused.

| Area | Interfaces | Notes |
|---|---|---|
| Paths and files | working directory, `open`/`read`/`write`, `lseek` with 64-bit offsets, `dup`/`dup2`/`dup3`, `stat`/`fstat`/`lstat` | [fs](../notes/m2-rust-posix-fs.md), [seek](../notes/m2-rust-posix-seek.md), [fds](../notes/m2-rust-posix-fds.md), [stat](../notes/m2-rust-posix-stat.md) |
| Directories | `opendir`, `fdopendir`, `readdir`, `closedir`, `dirfd`, rewind and position cookies, `scandir`, `alphasort` | [dir](../notes/m2-rust-posix-dir.md), [scan](../notes/m2-rust-posix-scan.md) |
| C runtime | startup, `errno` per thread, `malloc` family, C/POSIX locale, `strcoll`, `strxfrm`, `qsort`, `qsort_r` | [abi](../notes/m2-rust-posix-abi.md), [heap](../notes/m2-rust-posix-heap.md) |
| Shared state | one owner for file state across threads, console waits outside it, value messages | [shared](../notes/m2-rust-posix-shared.md), [input](../notes/m2-rust-posix-input.md), [messages](../notes/m2-rust-posix-messages.md) |
| Interruption | IPC interruption and `EINTR`, UART read recovery, nested cancellation windows, results kept across nested entry | [interrupt](../notes/m2-rust-posix-interrupt.md), [uart-cancel](../notes/m2-rust-posix-uart-cancel.md), [cancel-reentry](../notes/m2-rust-posix-cancel-reentry.md), [file](../notes/m2-rust-posix-file-replies.md), [thread](../notes/m2-rust-posix-thread-replies.md), [clock](../notes/m2-rust-posix-clock-replies.md), [heap](../notes/m2-rust-posix-heap-replies.md), [borrow guards](../notes/m2-interruptible-borrow-guards.md) |
| Threads | `pthread_create`/`join`/`detach`/`exit`, deferred cancellation and cleanup handlers, keys, `pthread_once`, 64 live threads | [threads](../notes/m2-rust-posix-threads.md), [cancel](../notes/m2-rust-posix-deferred-cancel.md), [keys](../notes/m2-rust-posix-thread-data.md), [once](../notes/m2-rust-posix-once.md), [capacity](../notes/m2-rust-posix-thread-capacity.md) |
| Mutexes and time | NORMAL, ERRORCHECK and RECURSIVE mutexes, `pthread_mutex_timedlock`, `pthread_mutex_clocklock`, `clock_gettime`/`getres`/`settime`, `nanosleep`, `clock_nanosleep` | [mutex](../notes/m2-rust-posix-mutex.md), [timed](../notes/m2-rust-posix-timed-mutex.md), [clocks](../notes/m2-rust-posix-clocks.md), [sleep](../notes/m2-rust-posix-sleep.md) |
| Signals | `sigaction`, masks, pending sets, `raise`, `pthread_kill`, `sigwait`, `sigwaitinfo`, `sigtimedwait`, `SA_SIGINFO` with a real interrupted context; host-tested pending-signal queues | [upcall](../notes/m2-native-upcall.md), [actions](../notes/m2-rust-posix-signal-actions.md), [sigwait](../notes/m2-rust-posix-sigwait.md), [sigwaitinfo](../notes/m2-rust-posix-sigwaitinfo.md), [context](../notes/m2-rust-posix-handler-context.md), [sigtimedwait](../notes/m2-rust-posix-sigtimedwait.md), [queues](../notes/m2-rust-posix-signal-queues.md) |
| Processes | `getpid`, `getppid`, real, effective and saved UID/GID (eight calls) through the session of the process service | [identity](../notes/m2-rust-posix-process-identity.md), [credentials](../notes/m2-rust-posix-credentials.md) |

Not there yet: `exec`, `fork`, `waitpid`, pipes, process-directed and
queued signals, `SA_RESTART`, conditions, semaphores, POSIX timers,
stdio, `termios`, asynchronous cancellation, general ELF TLS. BusyBox
still uses the Picolibc bridge; see [m2-ram-posix](../notes/m2-ram-posix.md).

## Probe commands

`cargo xtask help` lists them all. `posix-abi` runs the thread,
cancellation, shared-state, input and interruption probes as well, and
`test` and `ci` run `posix-abi`, `ramfs` and `ext4ro`. The BusyBox and
Picolibc probes run only on request.

| Command | Checks |
|---|---|
| `kernel-test`, `init-test` [machine] | the kernel test image or the EL0 test `init` alone, on `512M` or the machine named (`EL2`, `2G`, `GICv3`, `EL2 GICv3`, `HVF GICv3`, `HVF GICv2`); `kernel-test <machine> icount` runs the icount build under `-icount` |
| `ext4ro` | reads an e2fsprogs ext4 image inside the guest |
| `ramfs` | RAM file service: descriptors, reads, writes, seeks, sizes |
| `posix-abi` | C programs linked with Rust startup through Cargo and standalone Clang |
| `posix-threads`, `posix-cancel-input`, `posix-shared`, `posix-input`, `posix-interrupt` | single POSIX probes on QEMU |
| `posix-threads-vz`, `posix-cancel-input-vz`, `posix-input-vz`, `posix-interrupt-vz` | the same on Apple Virtualization.framework, through the Virtio console's driver; a stop of the machine before the end fails with a hint to rerun under HVF |
| `console-restart-vz` | `crash uart` on Apple VZ: `init` stops the Virtio function, restarts the driver, which finds it stopped, and input comes again |
| `console-early-exit-vz` | the driver ends on Apple VZ before its function decodes its BARs: `init` skips the reset through BAR 0, clears the command word and restarts it |
| `cprobe` | a static Picolibc C program against the RAM service |
| `busybox`, `ash`, `ash-dialog`, `ls` | BusyBox `cat`, `ash -c`, an `ash` dialog, `ls` |

## rtbench

`cargo xtask rtbench` adapts six
[Thread-Metric](https://github.com/zephyrproject-rtos/zephyr/blob/main/tests/benchmarks/thread_metric/thread_metric_readme.txt)
workloads to stafeto's primitives: baseline arithmetic, cooperative
yields, preemptive notifications, channel request and reply,
self-notification and memory-object allocation. After
[Zyclictest](https://docs.zephyrproject.org/latest/services/debugging/zyclictest.html)
it measures 1,000 periodic timer wakeups at 1 ms, idle and under a
lower-priority CPU load. It reports median operations per second, timer
p99 and worst latency, and missed periods, three runs per machine
(`--repeats N` changes that). These are adapted workloads, not official
Thread-Metric results, and virtual machines do not give a physical
worst-case latency. On Apple VZ the benchmark runs as a client of `init`
beside the Virtio console's driver, which shows its lines, at priority 60
with a 50 ms timer above every thread of the benchmark.
