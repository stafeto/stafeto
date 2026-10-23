# SMP

How the kernel uses several CPUs, the limits that keep its blocking time
bounded, and how to measure them.

## Model

- Each CPU owns its current thread, ready queue (64 levels), timers, cleanup
  queue, log ring, time accounting and active ASID. Interrupts, scheduling and
  the way out to EL0 take no lock.
- Another CPU's state changes by a command: a one-writer queue "CPU i to CPU j"
  and an SGI. A thread has at most one command in flight.
- The objects that CPUs share (channels, handle tables, mappings, processes,
  thread numbers, frames, ASIDs) are guarded by one ticket lock, `OBJ`, taken
  with interrupts masked for the links of the objects only. Copies of
  messages and the teardown of detached objects run outside it. `obj::lock()`
  is the one way to take it and it does not nest: the code that holds a
  section hands no take to the code it calls, which asserts the section
  (`obj::assert_held`), and a datum that `OBJ` guards (`obj::Guarded`) is lent
  inside a section only. A call that never returns hands its section to
  `sched::resume_from` or `thread::run_from`. A test build stops on a second
  take and on a loan outside a section (`obj_checks`), and the step `obj lock
  sites` of the kernel group of `ci` holds the files and counts of the takes
  to a list in xtask, so that a take in a new place is a decision. The second
  lock CPUs share is the ticket lock of each CPU's cleanup queue
  (`queue_spin`): a section under `OBJ` may take it, and its holder takes
  nothing.
- A queue of commands carries threads alone, each once at most, so it never
  fills; a timer whose last reference goes on another CPU than its heap's
  joins a chain of that CPU under `OBJ`. The owner serves up to 8 threads in
  one section and sends itself an SGI for the rest.
- Freed memory waits for a quiescent period (QSBR) of all CPUs.
- Scheduling is partitioned and fixed-priority: a thread has a CPU mask, by
  default its creator's CPU, and the kernel does not balance. A service on
  another CPU than its client runs at the client's level (a command lifts it).

## Limits

| Name | Value | Meaning |
| --- | --- | --- |
| `KERNEL_B_MAX` | 18 000 | longest non-preemptible portion of one CPU, instructions |
| `OBJ_HOLD_MAX` | 4 000 | longest hold of `OBJ`, instructions (icount) |
| `B4_MAX` | 32 000 | B_4, below |
| `S5_ICOUNT_MAX` | 3 063 | S5 on one CPU, instructions |
| `S5X_HVF_MAX` | 294 / 101 (GICv3), 340 / 216 (GICv2) | median of S5x on HVF, ticks of 16 ns: target in WFI / behind a lower thread; the guard of a regression |

`S5X_HVF_MAX` is the guard of a regression: it bounds the median, which a host
that preempts a vCPU leaves alone. The real-time limit of S5x bounds the longest
request, and the board (stage 7) gives it.

Each take of `OBJ` waits for at most the holds of the N - 1 other CPUs, so a
stretch between two polls for an interrupt that runs C instructions and takes
`OBJ` k times blocks for C + k * (N - 1) * `OBJ_HOLD_MAX`, and B_N is the
largest of these over the stretches, and B + (N - 1) * `OBJ_HOLD_MAX` for the
rows of B. The measuring images count k from the tickets of the lock: `cargo
xtask kernel-test 512M icount` prints the longest stretch for each k
(`OBJ takes`) and for each kind of section (`obj takes of kind`), B_2, B_4,
B_8, and fails B + 3 * `OBJ_HOLD_MAX` above `B4_MAX` and B_4 with the takes
above it (`B4_TAKES_ENFORCED`, no exceptions). With `OBJ_HOLD_MAX` 4 000 a
stretch fits `B4_MAX` with one take and C up to 20 000, or with two and C up
to 8 000; every stretch takes it once. A turn of the loop of the way out of
the kernel takes `OBJ` once at most (the handling of an interrupt, the
freeing of up to `RECLAIM_BATCH` = 8 retired objects, the park of a thread
(a turn that took `OBJ` for the park ends there even when the gate opened
meanwhile), or a portion of cleanup), and polls for an interrupt before the
next. The portions of the cleanup of memory objects and of the stage Shell,
and the entries of mem_create, take `OBJ` once for up to
`FRAMES_PER_SECTION` = 6 frames. The long calls mem_map, mem_unmap,
mem_protect and process_create take it once in each stretch: the checks of
the call are one section and the interrupt is polled before its first
portion; the first portion of a mem_map pays for the tables; the last
portion of a change ends the call in its section; a portion that makes pages
executable finds their frames in the section of the portion before it
(`Change` has no room for them, a thread is three to a page of the pool), and
the instruction cache is made coherent for them outside any section before
the poll. process_create makes the child, its start channel and its exit
source in the first section and looks at its caller and at x3 and x5 again in
the second; a thread that leaves the call or enters with another number gives
the child up, silently, at its own priority. `wcet bound` counts the takes on the paths no test reaches (k_static, docs/wcet.md) and
refuses a kernel with a path that takes `OBJ` twice. S5_N = S5 + (N - 1) *
`OBJ_HOLD_MAX`.

A service on another CPU than its client runs at the client's level, a
distributed inheritance: the response time R of the client adds the
interference of the threads above that level on the service's CPU and the
longest request of another client to the service, and the call costs 347
ticks on HVF against 12 on one CPU: a real-time client wants the receiving
thread of its service on its own CPU.
Under `-icount` QEMU runs the CPUs one after the other, so waits for a lock
and cross-CPU latencies there show the length of its time slice. Path lengths
come from the single-CPU tests, waits and latencies from HVF.

## Numbers (M4 host, HVF, 4 CPUs, median of 3 runs)

| Row | GICv3 | GICv2 |
| --- | --- | --- |
| S5x, target in WFI | 246 ticks | 310 ticks |
| S5x, target behind a lower thread | 94 ticks | 199 ticks |
| call to a service on another CPU | 347 ticks | 493 ticks |
| call to a service on this CPU | 12 ticks | 12 ticks |
| S5 on CPU 0 under a call storm of the others | 21 ticks | 23 ticks |
| local call under the storm | 111 ticks | 52 ticks |
| wait for `OBJ`, share of kernel time under the storm, 2 / 4 CPUs | 11.8 % / 23.2 % | 12.0 % / 21.5 % |

The storm is the worst case: three CPUs that do nothing but calls on one table.
The rule of the decision (finer locks when the wait is over 10 % of the
kernel time, or its longest is over (N - 1) holds) fires on the share under the
storm. The holds and waits on a host include the time a CPU the host
preempted spent holding or waiting for the lock, so the board (stage 7) decides.

## How to measure

- `cargo xtask smp-measure [tcg|hvf|hvf2] [RUNS]`: the test init on 2 and 4 CPUs
  with the kernel built with `smp-measure`, which counts for each CPU the kernel
  time of its entries from EL0, the longest entry, the waits for `OBJ` and the
  longest hold; prints the table and the verdict of the rule; writes
  `target/measure/smp-<mode>.txt`.
- `cargo xtask smp-probe [machine]`: the test init on 4 CPUs; on HVF it checks the
  median of S5x against `S5X_HVF_MAX`, runs the litmus tests MP (release and
  acquire) and SB (dmb) for up to 10^6 rounds (on HVF the forbidden outcomes
  are 0, and SB without dmb shows both threads reading 0 in 9 rounds of 10)
  and a lock torture of 250 ms (some 850 000 calls on HVF).
- `cargo xtask smp-window`: the test init on 4 CPUs with a kernel that holds
  a thread at a chosen point (`window-probe`): a receive or a send holds
  before its section, until another CPU makes a request for its entry. A
  receive and a send are one section from the first look at a queue to the
  take of the request, so a head that moved or a receiver that left between
  the two cannot happen and nothing starts the call over for it. A section
  has a number, the ticket the lock serves while it lasts, and the test
  builds and the window kernels check it: `receive` and `send` keep the
  number at their first look (`obj::mark`) and check it in `take_request`
  and `meet`.
  Then the kernels that must fail: the one without the look under `OBJ`
  before a wait, the one without the second look at the life of a process
  after the instruction cache of a mem_map RX, and the one whose receive gives
  `OBJ` back and takes it again between its look at the head and the take
  (`break-one-section`), which stops at the number of the section.
  The one repeat of a receive that remains is the one for a request whose
  handles find no room: it fails that sender and takes one request off the
  queue, so the repeats of a call are at most the requests with handles that
  stood in the queue when it began (spec 6.1).
- `ci` runs the test init (also in the kernel built with the checks of `OBJ`,
  `smp 4 checks`), `smp 4 window` and `smp 4 asid` on 4 CPUs, the kernel tests
  (`kernel tests smp 4`), and seven guests on 4 CPUs beside their runs on one
  (`posix-threads` with 2 x 10^4 handoffs instead of 2 x 10^5, and `posix-procs`,
  with a limit of 180 s). `STAFETO_SMP=N` runs any probe on N
  CPUs; `STAFETO_MACHINE` names the machine of `posix-procs`.

## The probes and the deliberate breaks

The probes of the windows live in `kernel/src/window.rs`, built with the
feature `window-probe` only; the kernel as it ships has none of them, and
each point of call in the kernel is one line under that feature. The
features `break-*` take one check out of the kernel (their places stay in
the code of the call, under `cfg`), and the command named must fail on a
kernel built with the feature, for the reason in the last column.

| Feature | Command | What it takes out | What catches it |
|---|---|---|---|
| `break-block-check` | `smp-window` | The look under `OBJ` for a request for the entry before a receive or a send waits | `smp_request_before_a_receive_waits_ends_it` and the test of the send fail |
| `break-one-section` | `smp-window` | The single section of a receive from its look at a queue to the take of the request | The kernel stops at the number of the section |
| `break-alive-check` | `smp-window` | The second look at the life of a process after the portion of a mem_map RX | `smp_exec_map_of_a_process_killed_meanwhile_fails`, or the kernel stops on a process used after its space went |
| `break-spawn-check` | `smp-window` | The second look at x3, x5 and the life of the caller of process_create after the gap between its sections | A `smp_spawn_*_meanwhile_fails` test fails, or the kernel stops on a handle that went the wrong way |
| `break-asid-reserved` | `smp-asid` | The numbers a CPU runs stay out of a new generation | A test of the pages of processes across generations fails |
| `break-asid-flush` | `smp-asid` | The deferred flush of the other CPUs after a generation | The same |
| `break-asid-aside` | `smp-asid` | `aside1is` at the end of a process | `smp_asid_of_a_process_that_ended_is_clean_on_every_cpu` |
| `break-asid-retire` | `smp-asid` | The wait for every CPU to leave the tables before an ASID goes | The kernel stops at the first process whose tables a CPU holds |
| `break-unmap-local` | `smp-asid` | The broadcast of the TLBI of an unmapped page | `smp_unmap_reaches_a_thread_on_another_cpu` (on TCG; HVF hides it) |

A break for the check of one change is made by taking the change back in the
working tree and running the command; the report of the change says what
caught it. The probes of `window-probe` that need no break: the wait inside
the removal from a ready queue (`kcore` feature `ready-gap`: items of one
level, or of every level with the kernel feature `ready-gap`, for `STAFETO_READY_GAP=1
cargo xtask posix-procs`), the wait of a process at its stage Threads until
its timers fired (`hold_until_woken`), the hold of a `timer_create` between its
entry and its section (`entry_gap`), and the question for the state of a
thread whose wake is on its way (`info_in_flight`).

## What programs see of the CPUs

- `object_info` CPU (kind 15, no handle and no lock) gives the CPUs up, the
  ticks of one CPU since it started, those it slept in `wfi` and those its
  entries from EL0 spent in the kernel, and the caller's CPU. The owner of
  a CPU counts the ticks of its entries when the entry polls (`Local::time`,
  3 instructions on the path of the null call) and its sleeps in `sleep`;
  the other CPUs read the words with one load each.
- `sysconf(_SC_NPROCESSORS_CONF)` and `_SC_NPROCESSORS_ONLN`, `sched_getaffinity`
  and the listing of `/sys/devices/system/cpu` (which BusyBox `nproc --all`
  and htop count) give the CPUs that are up. `/proc/stat` has a line `cpuN`
  for each CPU (user, system and idle from that call) and `/proc/cpuinfo` a
  record for each; the field `processor` of `/proc/<pid>/stat` is the CPU of
  the process's main thread.
- The process service puts the main thread of every new image (spawn, fork
  and exec) on the least busy CPU of the mask its page allows
  (`Page::cpus`, 0 for all). A CPU is busy when it was awake a quarter of
  the last window of 10 ms (the time asleep from `object_info` CPU, read once
  per CPU when a window closes) and each image put on it in the last two
  windows counts as one more; among equals the CPU after the last choice wins,
  so images made in a row go to different CPUs. The step reads no process
  record, so it costs the same with a hundred processes (`process-steps`
  places on one CPU too, with 248 children live). A thread starts on the CPU of its creator or, when
  the mask does not allow that, on the lowest CPU it names.
  `sched_setaffinity` writes the mask of its process: the kernel moves no
  thread, so the mask works for the threads made later and for the next exec
  (`taskset -c N command`).
- `cargo xtask cpus-dialog [N]` runs the dialog on N CPUs: `nproc`, the CPU
  lines, `taskset -p`, one loop per CPU on different CPUs, the busy time of
  each CPU, a command under `taskset -c` and htop with a meter for each CPU.
  `ci` runs it on 1 and on 4 CPUs.

## Not on several CPUs

- One kernel test, `last_shell_reference_comes_with_the_binding_reclaim`, looks
  at a portion without a quiescent point of its own CPU and skips on several
  CPUs, with a line: the stages of a process wait for the other CPUs. The measures under `-icount`
  are of one CPU.
- The probes of the shell, `posix-sock`, `posix-ipc`, `posix-poll`, `posix-pty`
  steps and `posix-tty-control-steps`: with TCG on 4 CPUs the boot of `posix-sock` takes
  17 times as long (every invalidation of the TLB reaches all vCPUs), and the
  watchdogs of the services fire.
