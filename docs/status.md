# Status details

The README gives the short picture; this page keeps the details of each part of the system and its known limits. Numbers are from `main` after #165, unless a section names its own step.

**Boot and machines.** The kernel boots as an arm64 Image from EL2 or EL1,
turns on the MMU, reads the device tree and checks its boot image. It runs
on three kinds of machine:

- QEMU `virt` under emulation (TCG), with GICv2 or GICv3;
- QEMU with HVF on a Mac with Apple silicon, on Apple's GICv3 and on
  QEMU's GICv2;
- Apple Virtualization.framework without QEMU: the same kernel image,
  with the Virtio PCI console driven by a user-space service
  (`cargo xtask vz`).

**Kernel.** 34 system calls, the same on every machine, over 64-bit handles
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
image is 162,880 bytes of a 204,800-byte budget, on QEMU and on Apple VZ.
The longest stretch the kernel runs without taking an interrupt (term B of the
kernel) stays below the limit of 18,000 ticks that `xtask` enforces under
`-icount`; teardown of a session and its message buffers runs in
portions of 32 entries.

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
and an interactive `ash` on the UART with `echo` and `ls -la`. The shell image
of `cargo xtask ash-shell` is an interactive BusyBox `ash` with line editing
(cursor keys, history, Tab completion), GNU bash 5.3 (`bash`), GNU nano 9.2
(`nano`), htop 3.5.3 (`htop`) and BusyBox `top`, all running over ncurses 6.6
and the terminfo entries of `xterm`, `xterm-256color`, `vt100` and `linux`.
The terminal service keeps the window size: the host sends it on the first
prompt and on every resize, `TIOCGWINSZ` and `TIOCSWINSZ` work as on Linux, and
the foreground group gets `SIGWINCH`. The shell image carries 94 of the 112
utilities of POSIX.1-2024 XCU (each answers `command -v`): the ten built-ins of
`ash`, `sh`, 77 BusyBox applets and six ready-made programs (`getconf`, `join`,
`pathchk`, `file`, `iconv`, `compress`). `ps`, `top` and `df` read `/proc`,
which the layer serves. [docs/packages.md](packages.md) describes how every
third-party program of the image is a package built from one description
file. BusyBox
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
wait on pipes and terminal descriptions. [notes/m5f-tty.md](../notes/m5f-tty.md)
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
(S17, S18). [notes/m5d-fork.md](../notes/m5d-fork.md) has the table and the
limits, [notes/m5b-processes.md](../notes/m5b-processes.md) and
[notes/m5c-spawn-exec.md](../notes/m5c-spawn-exec.md) those of the steps
before.

Pipes live in their own service (`services/pipe`): 64 pipes with a ring
of 4 KiB each, `PIPE_BUF` 512, blocking reads and writes as long
operations in two steps that a signal cancels (`SA_RESTART` continues them),
`SIGPIPE` before `EPIPE`, `O_NONBLOCK` as a flag of the description. Ends
cross `fork`, `posix_spawn` (`adddup2`) and `exec`, and the service sees a
dead process as an end that closes (the reader gets end of file). `/dev/null`
is a null device of the RAM service. Every step of the service stays below
the services' budget of 20,410 ticks (`cargo xtask process-steps`). On HVF
(10 minutes, p50) a byte goes through two pipes to another process and back
in 5.5 us (S19), 1 MiB goes through a pipe at 250 MB/s in writes of 512
bytes and 432 MB/s in writes of 4 KiB (S20), and `ls /etc | cat` as two
`fork`s and two `exec`s takes 623 us (S22).
[notes/m5e-pipes.md](../notes/m5e-pipes.md) has the rows, the limits and the
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
`/dev/urandom` 12.3 us (S25). [notes/m5e2-entropy.md](../notes/m5e2-entropy.md) has the rows, the steps of
the services and the limits.

**C library.** relibc (MIT) is the C library of every POSIX program,
BusyBox included; its platform is the layer's `stafeto_*` functions.
os-test's `basic` suite passes 1,183 of its 1,187 tests (the three `dlfcn`
tests need a dynamic loader and `pthread_setcanceltype` is open), with no
listed exception; its io, malloc, process and signal suites, `basic/spawn`,
`basic/unistd` `exec*` and the `basic` tests that call `fork` run on it in
`ci` from files, one boot a suite. `ci` fails when a test that passed stops
passing. The Open POSIX Test Suite (LTP 20260930) runs on relibc in `ci` and
passes 1,985 of its 2,036 tests; the map of the rest is in
[docs/open-posix-map.md](open-posix-map.md). The PTY and termios suites
exercise the terminal APIs, and readiness tests cover all four waiting
interfaces. `cargo xtask coverage` counts all 1,035 required XSH interfaces
(1,035 of 1,035), and no required function only returns `ENOSYS`. The
`unistd.h` macros and `sysconf` agree and claim only what exists. relibc
builds at its own level 3: user-space programs have no size limit, only
the kernel has one. Coverage details are in
[posix-coverage.md](posix-coverage.md).

**Files, locks and memory.** The RAM file service creates files,
directories and FIFOs, keeps owners and modes, and serves `/tmp`. `fcntl`
record locks and open-file-description locks work, blocking ones included. `mmap`, `munmap`,
`mprotect` and `msync` cover anonymous and file mappings, private and shared;
shared objects reach a forked child as the same pages, and `shm_open` opens a
file of `/dev/shm`.

**Real time and timers.** The kernel counts the ticks every thread has run, which
`getrusage`, `times` and the CPU-time clocks report. `SCHED_FIFO` and
`SCHED_RR` run at priorities 1 to 32, `sched_*` and `pthread_*sched*` set them,
and `posix_spawn` takes `POSIX_SPAWN_SETSCHEDULER` and `SETSCHEDPARAM`.
`PTHREAD_PRIO_INHERIT` mutexes pass priority along chains up to depth 8 and
report a cycle with `EDEADLK`; `PTHREAD_PRIO_PROTECT` uses ceilings. POSIX
timers, `alarm` and `sigqueue` live in the process service, and faults reach
programs as signals on an alternate stack when asked.

**Sockets and message passing.** AF_UNIX stream and datagram sockets
(`socketpair`, names in the file system, `SCM_RIGHTS`) and the IPv4 loopback
run in the pipe service. The same service holds POSIX message queues, XSI
queues, semaphores and shared memory, and named semaphores. The library
brings asynchronous I/O (`aio_*`, `lio_listio`) over threads.

**Tests.** `kcore` has 438 host tests; `cargo xtask ci` runs them with the
kernel tests, the EL0 test `init` and the guest probes, and `cargo xtask hvf`
runs the set on Apple silicon. `ci` runs on every pull request on GitHub
Actions.

**Known limits.**

- Apple VZ gives the kernel no port: a kernel panic there shows nothing
  and powers the machine off (a VZ probe fails with a hint), and VZ
  clears RAM at a reset, so the log does not outlive it; the same image
  under HVF shows the panic. On VZ `rtbench` runs beside the console's
  driver.
- SMP runs on up to 8 CPUs (QEMU, HVF and VZ are tested with 4); the
  bounds of a real-time analysis on several CPUs still wait for a board
  (docs/smp.md).
- No PinePhone port yet.
- `fork` copies everything the layer maps, with no copy on write (about
  70 us a MiB on HVF); mappings made past the
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
