# Status details

The README gives the short status. This page keeps the details that are
useful when working on the code: what the kernel offers, what the Rust
POSIX layer covers, and which commands check each piece. It describes
`main` at a2eb60a (step 5c, `posix_spawn` and `exec` from files) with step 5d (`fork`) and step 5e (pipes) on top.

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
  gives. Kind 11 of `object_info`, LABEL, gives the owner of a channel
  (with RECEIVE) the label of a labelled copy of it, O(1): the process
  service's Vouch. `process_kill` takes the level of the teardown it starts.
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
- `services/ramfs`: RAM files and directories (`proto/fs`). Next to its
  fixed tree it shows the files of the boot image's table `rootfs`
  (`lib/bootimg/src/rootfs.rs`): each has a path, a mode, an owner and
  the bytes of a file of the image (a program's ELF file), which the
  service reads from its read-only mapping of the image without a copy;
  `READ_AT` reads at an offset. Paths are at most 511 bytes (512 with the
  terminator, as `PATH_MAX`), names at most 255.
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

Since step 5a′ the C library is relibc (`tools/build-relibc.py`, the fork
pinned there): its headers and `libc.a` under `target/relibc/sysroot`, its
platform the layer's `stafeto_*` functions (`lib/posix-platform`, interface
14). The layer exports no C names (`cargo xtask ci` checks it) and keeps the
system part; the C probe `posix-abi` and the Rust guest probes on a C main
(`tests/libc-ffi`) are programs on relibc, and the native probe
`posix-tls` checks the layer's TCB for threads relibc did not start. Since step 5a the layer has no helper threads;
[m5a-transport](../notes/m5a-transport.md) says how it works and where it
stops. The rows below date from the layer's own C surface; relibc now
provides the C side of each.

| Area | Interfaces | Notes |
|---|---|---|
| Paths and files | working directory, `open`/`read`/`write`, `lseek` with 64-bit offsets, `dup`/`dup2`/`dup3`, `stat`/`fstat`/`lstat` | [fs](../notes/m2-rust-posix-fs.md), [seek](../notes/m2-rust-posix-seek.md), [fds](../notes/m2-rust-posix-fds.md), [stat](../notes/m2-rust-posix-stat.md) |
| Directories | `opendir`, `fdopendir`, `readdir`, `closedir`, `dirfd`, rewind and position cookies, `scandir`, `alphasort` | [dir](../notes/m2-rust-posix-dir.md), [scan](../notes/m2-rust-posix-scan.md) |
| C runtime | startup, `errno` per thread, `malloc` family, C/POSIX locale, `strcoll`, `strxfrm`, `qsort`, `qsort_r` | [abi](../notes/m2-rust-posix-abi.md), [heap](../notes/m2-rust-posix-heap.md) |
| Thread block and TCB | a TCB in relibc's layout per thread, the layer's block in it: mask, pending signals, cancellation, the thread's channel and timer, its node of a wait by address | [m5a](../notes/m5a-transport.md) |
| Waits and locks | a table of waits by address (`posix-sync`): no kernel call without waiters; the layer's locks, the heap's, the files', the threads' and the actions', raise their holder to the process ceiling; a signal inside a section comes at its end | [m5a](../notes/m5a-transport.md) |
| Shared state | the process's files and heap under the layer's locks, in the calling thread; console reads and writes outside the files' lock | [m5a](../notes/m5a-transport.md), [input](../notes/m2-rust-posix-input.md), [messages](../notes/m2-rust-posix-messages.md) |
| Interruption | IPC interruption and `EINTR`; an accepted request is answered once (no reply journals); console reads as long operations in two steps that a signal cancels, `SA_RESTART`; nested cancellation windows | [m5a](../notes/m5a-transport.md), [interrupt](../notes/m2-rust-posix-interrupt.md), [cancel-reentry](../notes/m2-rust-posix-cancel-reentry.md), [borrow guards](../notes/m2-interruptible-borrow-guards.md); history: [shared owner](../notes/m2-rust-posix-shared.md), [uart-cancel](../notes/m2-rust-posix-uart-cancel.md), [file](../notes/m2-rust-posix-file-replies.md), [thread](../notes/m2-rust-posix-thread-replies.md), [clock](../notes/m2-rust-posix-clock-replies.md), [heap](../notes/m2-rust-posix-heap-replies.md) |
| Threads | `pthread_create`/`join`/`detach`/`exit`, deferred cancellation and cleanup handlers, keys, `pthread_once`, 64 live threads | [threads](../notes/m2-rust-posix-threads.md), [cancel](../notes/m2-rust-posix-deferred-cancel.md), [keys](../notes/m2-rust-posix-thread-data.md), [once](../notes/m2-rust-posix-once.md), [capacity](../notes/m2-rust-posix-thread-capacity.md) |
| Mutexes and time | NORMAL, ERRORCHECK and RECURSIVE mutexes, `pthread_mutex_timedlock`, `pthread_mutex_clocklock`, `clock_gettime`/`getres`/`settime`, `nanosleep`, `clock_nanosleep` | [mutex](../notes/m2-rust-posix-mutex.md), [timed](../notes/m2-rust-posix-timed-mutex.md), [clocks](../notes/m2-rust-posix-clocks.md), [sleep](../notes/m2-rust-posix-sleep.md) |
| Signals | `sigaction`, masks, pending sets, `raise`, `pthread_kill`, `sigwait`, `sigwaitinfo`, `sigtimedwait`, `SA_SIGINFO` with a real interrupted context; host-tested pending-signal queues | [upcall](../notes/m2-native-upcall.md), [actions](../notes/m2-rust-posix-signal-actions.md), [sigwait](../notes/m2-rust-posix-sigwait.md), [sigwaitinfo](../notes/m2-rust-posix-sigwaitinfo.md), [context](../notes/m2-rust-posix-handler-context.md), [sigtimedwait](../notes/m2-rust-posix-sigtimedwait.md), [queues](../notes/m2-rust-posix-signal-queues.md) |
| Processes | `getpid`, `getppid`, `getpgrp` and `getsid(0)` read the process's page of its record; real, effective and saved UID/GID (eight calls) go through the session of the process service | [identity](../notes/m2-rust-posix-process-identity.md), [credentials](../notes/m2-rust-posix-credentials.md) |
| Spawn and `exec` | `posix_spawn` and `exec` of a file of the RAM service through a loader in the new process: `argv`, `envp`, the current directory, file actions (`adddup2`, `addclose`, `addopen`, `addchdir`), `SETPGROUP`, `SETSID`, `SETSIGMASK`, `SETSIGDEF`, `RESETIDS`, set-ID files, descriptions shared with the child, `FD_CLOEXEC`, a failed `exec` that leaves the old image whole | [m5c](../notes/m5c-spawn-exec.md) |
| `fork` | a full copy of the parent's memory by the child's loader, at the forking thread's level; the other threads stop first; the child has one thread, its descriptions shared with the parent's and its layer bound to its own handles; `vfork` is `fork`; `pthread_atfork` in POSIX's order | [m5d](../notes/m5d-fork.md) |
| Pipes | `pipe`, `pipe2` (`O_NONBLOCK`, `O_CLOEXEC`, `O_CLOFORK`) through the pipe service: a ring of 4 KiB per pipe, `PIPE_BUF` 512, blocking reads and writes as long operations in two steps that a signal cancels (`SA_RESTART`), `SIGPIPE` before `EPIPE`, `fstat` as a FIFO, `ESPIPE`; ends cross `fork`, `posix_spawn` (`adddup2`) and `exec`; `/dev/null` as a null device of the RAM service (`O_CHANGES`) | [m5e](../notes/m5e-pipes.md) |
| Terminals and jobs | `termios`, `/dev/console`, `/dev/tty`, eight PTYs with grant/unlock/name and window size; personal controlling terminals, foreground groups, Ctrl-C/Ctrl-Z, `SIGTTIN`/`SIGTTOU`, `SIGSTOP`/`SIGCONT`, `WUNTRACED`/`WCONTINUED`; `ash` built-ins and jobs through a PTY | [m5f](../notes/m5f-tty.md) |
| Readiness | `poll`, `ppoll`, `select`, `pselect`, up to 32 descriptors; masks and absolute deadlines, cancellable watches, one notification session across repeated Take calls; ready writers below the polling reader can run | [m5f](../notes/m5f-tty.md) |
| Random numbers | `getentropy` (up to 256 bytes, `EINVAL` past it), `getrandom` (`GRND_NONBLOCK`, `GRND_RANDOM`, `GRND_INSECURE`), `/dev/random` and `/dev/urandom` as character devices of the RAM service (reads served by the layer, writes dropped, `O_CHANGES`), `arc4random`, `arc4random_buf`, `arc4random_uniform`, the names of `mkstemp` and `mkdtemp`: a ChaCha20 generator with fast key erasure in each process, keyed by the entropy service (the Virtio entropy device through `virtio-rng`); a forked child takes its own key; `ENOSYS` without the service | [m5e2](../notes/m5e2-entropy.md) |
| Memory map | the layer keeps the handle of every memory object of the process: the loader hands over narrowed copies for the segments, the stack and the start area, and each chunk of the heap adds one; at most 128 regions, no device window or DMA object; `mmap` refuses `MAP_SHARED` with `ENOTSUP` (no shared memory yet). A mapping made past the layer by a direct kernel call is not in the map | `lib/posix-map`, `posix_abi::allocation::regions` |
| Process lifetime | `waitpid`, `waitid`, `WNOHANG`, `WIFSIGNALED` apart from `exit(143)`, `kill`, `killpg`, `kill(0)`, `kill(-1)`, `SIGKILL` through the kernel, `SIGCHLD` to `sigwaitinfo`, `setpgid`, `setsid`, `getpgid`, `getsid`, orphans to PID 1 | [m5b](../notes/m5b-processes.md) |

relibc gives conditions, semaphores and stdio over the layer
(`relibc-threads` checks the first two). Not there yet: `fexecve`,
named pipes, queued signals (`sigqueue`),
POSIX timers, asynchronous cancellation,
general ELF TLS. BusyBox
runs on relibc since 5a′; see [m2-ram-posix](../notes/m2-ram-posix.md) for
its first steps.

## Probe commands

`cargo xtask help` lists them all. `posix-abi` runs the thread,
cancellation, shared-state, input and interruption probes as well, and
`test` and `ci` run `posix-abi`, `ramfs`, `ext4ro`, the relibc probes,
`posix-procs`, the BusyBox probes and os-test's io, malloc and signal suites
(within 420 s).

| Command | Checks |
|---|---|
| `kernel-test`, `init-test` [machine] | the kernel test image or the EL0 test `init` alone, on `512M` or the machine named (`EL2`, `2G`, `GICv3`, `EL2 GICv3`, `HVF GICv3`, `HVF GICv2`); `kernel-test <machine> icount` runs the icount build under `-icount` |
| `ext4ro` | reads an e2fsprogs ext4 image inside the guest |
| `ramfs` | RAM file service: descriptors, reads, writes, seeks, sizes; the files of the boot image's table: modes, owners, links, reads at an offset, the longest path |
| `posix-abi` | a C program on relibc against relibc's headers: files, directories, threads, cancellation, keys, mutexes, clocks, signals, credentials; the layer's `.data` + `.bss` measured; size limits apply to the kernel |
| `relibc-hello`, `relibc-threads` | relibc's start, files, `mmap`, `fcntl`, `writev`; its pthreads over the layer, `siglongjmp`, the clock's page (`relibc-threads-hvf` on HVF) |
| `posix-poll` | mixed file/pipe/terminal readiness, masks and deadlines, Cancel/Take/Gone, 32 aliases and a ready writer below the waiting reader |
| `posix-pty`, `posix-pty-steps` | PTY lifecycle, real UID grant, spawn aliases and rollback, window size and signals, interactive ash jobs and HUP; the quiet steps variant measures a late Clone with 32 descriptions and a full root pool |
| `posix-tty-control-steps` | full terminal control intervals with sixteen live clients, including the first Acquire and inherited personal controlling-terminal pairs |
| `posix-procs` | the C probe of processes on relibc: `fork` (a copy of the parent's memory, descriptors, signals, threads, `vfork`, `pthread_atfork`), `posix_spawn` and `exec` from files (`/bin/ls /etc`, `argv`, `envp`, set-ID, 32 live children, 1,100 in a row, descriptors, a failed `exec`), exit status, `WIFSIGNALED`, `SIGKILL` of a child that blocks everything, a handler that exits with 42, a fault as `SIGSEGV`, `SIGCHLD` with `si_pid`, groups, sessions, `killpg`, `kill(0)`, `kill(-1)`, `clock_settime` by effective UID; the children end as `init` reports |
| `os-test` | os-test (Sortix, ISC, pinned) io, malloc, process and signal suites, `basic/spawn`, `basic/unistd` `exec*` and the `basic` tests that call `fork` or `pipe` (among them `stdio`, `wchar` and `fmtmsg`) on relibc, a boot a suite with the tests started from files; PASS, FAIL and UNSUPPORTED (unsupported cases) in `target/measure/os-test.txt`; a test that runs 10 s is killed, the run stops after 900 s, and it fails when a test of `tests/os-test/pass.txt` does not pass |
| `process-steps` [branches] | the longest step of the process service under `-icount` with a crowd of children (128 with 4 branches, in `ci`; 248 with 7), a child that forks among them, and the longest step of each kind of the loader's copy; it fails when the longest Vouch passes 6,000 ticks, a ForkStart passes the longest SpawnStart or a Clone of the RAM file service passes term B; the table is in `target/measure/process-steps.txt` and in [non-preemptible-paths](non-preemptible-paths.md) |
| `posix-threads`, `posix-cancel-input`, `posix-shared`, `posix-input`, `posix-interrupt` | single POSIX probes on QEMU |
| `posix-threads-vz`, `posix-cancel-input-vz`, `posix-input-vz`, `posix-interrupt-vz` | the same on Apple Virtualization.framework, through the Virtio console's driver; a stop of the machine before the end fails with a hint to rerun under HVF |
| `console-restart-vz` | `crash uart` on Apple VZ: `init` stops the Virtio function, restarts the driver, which finds it stopped, and input comes again |
| `console-early-exit-vz` | the driver ends on Apple VZ before its function decodes its BARs: `init` skips the reset through BAR 0, clears the command word and restarts it |
| `busybox`, `ash`, `ash-dialog`, `ls` | BusyBox on relibc: `cat`, `ash -c`, an `ash` dialog (a POSIX process from `/bin/ash` that forks and execs the files of `/bin`), `ls` |

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
(`--repeats N` changes that). These are adapted workloads, which give no official
Thread-Metric results, and virtual machines do not give a physical
worst-case latency. On Apple VZ the benchmark runs as a client of `init`
beside the Virtio console's driver, which shows its lines, at priority 60
with a 50 ms timer above every thread of the benchmark.

### rtbench 2

`cargo xtask rtbench --minutes N` runs rtbench 2 for N minutes on HVF,
then on Apple VZ; `cargo xtask rtbench --short` runs one round on TCG
(`ci` does). It is a C program over pthreads (`tests/rtbench-posix`)
beside a hostile load (`tests/rtbench-load`: a worker that makes and
kills processes of 128 threads and large memory objects). Its rows: S1 a
mutex without a rival, S2 `futex_wake` without waiters, S3 a mutex with
rivals at levels 10, 20 and 30, S4 `malloc`/`free` and `dup`/`close`, S5
`pthread_kill` to a sleeping, a reading and a busy thread, S6 a `read` of
ready data, S7 an absolute sleep of 1 ms, S8 a pair waiting by address
and a waiter in the same bucket, S9 a round trip to a service, S10 `kill` of another process to the first
statement of its handler (the target sleeps; and with a thread at level 25
running all the time), S11 a `waitpid` of a ready zombie and from a
child's `_exit` to the return of `waitpid`, S12 `killpg` to a group of
32 to the last `waitpid`, S13 `posix_spawn` of a file to the child's `main`,
S14 `exec` to the new image's `main`, S15 `fork` to the child's first
statement with a heap of the start size, 1 MiB and 8 MiB, S16 `fork`, `exec`
and `waitpid` of a small file, S17 `fork` with 1, 8, 32 and 63 other threads
(asleep or running below the forker), S18 `exec` with the same threads,
S19 a byte through two pipes to another process and back, S20 1 MiB through
a pipe in writes of 512 bytes and of 4 KiB, S22 `ls /etc | cat` as two
`fork`s, two `exec`s and two pipes.
Each row
gives n, min, p50, p99, max in ns and kernel calls per operation, with a
histogram, in `target/measure/rtbench-<machine>.txt`.

10 minutes at 8c254c0 against the same run before step 5a (bf764f6),
p50 on HVF and VZ: S1 3,327 → 0 ns with 12 → 0 kernel calls; S4
`malloc`/`free` 1,215 → 335 ns, `dup`/`close` 2,047 → 423 ns; S5 4,351 →
463 ns; S6 959 → 1,343 ns (the console's read in two steps); S3 rival at
20: 6,783 → 98,303 ns, since waiters now take the mutex by level and the
rival at 30 goes first.

10 minutes on the last commit of step 5a′ (relibc's mutex, dlmalloc and
pthreads over the layer, relibc at its own level 3) against 8c254c0, p50
/ p99 on HVF: every row within two counter ticks or 10 % of 5a; S1 and S2
still make no kernel call; S4 `malloc`/`free` of 64 bytes falls from 335
/ 3,007 ns to under one tick (dlmalloc's cache); S4 `dup`/`close` 375 /
463 ns, S6 1,343 / 2,495 ns, S7 3,583 / 7,039 ns. VZ: S4 `dup`/`close`
423 / 463 ns, S6 1,343 / 2,367 ns, S7 3,583 / 7,295 ns. relibc built for
size (level `s`) had S4 `dup`/`close` at 671 / 751 ns and S6 at 2,175 /
3,583 ns.

10 minutes on the head of step 5c (HVF / VZ, p50 / p99, 4,500 samples a
row): S13 `posix_spawn` of a file to the child's `main` 102 / 152 and 102 /
156 us (step 5b, from a boot-image record: 55 us p50; the first loader, that
read with `ReadAt`, took 221 us); S14 `exec` to the new image's `main` 113 /
143 and 113 / 147 us; S12 `killpg` to a group of 32 623 / 918 and 639 / 934
us.

10 minutes on the head of step 5d (HVF / VZ, p50 / p99, 1,260 samples a
row, 630 for S18; host load about 2): S15 `fork` to the child's first
statement 102 / 131 and 102 / 129 us with the start heap, 172 / 205 and
172 / 205 us with 1 MiB, 623 / 737 and 623 / 737 us with 8 MiB; S16 `fork`,
`exec` and `waitpid` 246 / 303 and 246 / 287 us; S17 with 63 sleeping
threads 541 / 754 and 524 / 721 us, with 63 running 639 / 885 and 639 / 819
us; S18 `exec` with 63 running threads 442 / 606 and 442 / 622 us. The
same run gave S13 121 / 205 and 117 / 209 us, S14 139 / 176 and 129 / 168
us. [notes/m5d-fork.md](../notes/m5d-fork.md) has every row.

10 minutes on the head of step 5e (HVF / VZ, p50 / p99, 125 rounds; 125,000
samples of S19, 375 of S20, 1,250 of S22): S19 a byte through two pipes and
back 5.5 / 6.4 and 5.5 / 6.3 us with 12 kernel calls (S9, an empty round
trip to a service, 0.42 us with one call); S20 1 MiB in writes of 512 bytes
250 / 222 and 250 / 221 MB/s (p50 / p99 of the time), in writes of 4 KiB
432 / 381 and 432 / 385 MB/s; S22 `ls /etc | cat` 623 / 770 and 623 / 770
us. [notes/m5e-pipes.md](../notes/m5e-pipes.md) has every row.
