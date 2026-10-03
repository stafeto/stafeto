# POSIX step 5d: `fork`

## Result

`fork` copies the whole memory of the calling process into a child. The
child's own loader makes the copy at the forking thread's level, out of
objects the parent's layer keeps handles of (the memory map), so the kernel
did not change and term B stays 20,536 ticks. The process service makes the
child's record and process (ForkStart), the loader fills the child's
objects at the parent's addresses, ForkCommit makes the child live, and the
child returns 0 from `fork` on the copy of the parent's stack with every
part of the layer bound to its own handles. BusyBox `ash` runs external
programs through it: `/bin/ls -la`, `echo hi && ls -1 /etc`, a nested
`ash`, `ash -c 'exit 3'` with `$?` 3, and a missing command gives "not
found" with status 127 (`ash-dialog` in `ci`).

- **Copy.** There is no copy on write. The child pays for every page out of
  the parent's quota class (the child's quota is the parent's, taken from
  the service's pool), and the cost grows with the parent's memory.
- **Threads.** `fork` and `exec` stop the other threads of the parent
  first (`signals::stop_others`); the child has the calling thread alone,
  and no lock of the layer is held in the copy. relibc's allocator lock
  goes through its `pthread_atfork` handlers, which run in POSIX's order
  (prepare in the opposite order of registration).
- **Signals.** The calling thread keeps every signal blocked from the entry
  to the return. The child's page of signals takes the parent's classes
  from ForkStart, so a signal sent to the group during the copy finds what
  the child ignores and catches; pending signals of the parent do not carry
  over; handlers and the mask do.
- **Descriptors.** The file, clock and console sessions are cloned for the
  child: the open descriptions and their offsets are shared, `FD_CLOFORK`
  descriptors are closed, `FD_CLOEXEC` stays.
- **`vfork`** is `fork`.

## Measurements

### rtbench, 10 minutes (HVF and VZ at the same time)

126 rounds, 1,260 samples a row (630 for S18), p50 / p99 / max in
microseconds (the counter ticks 41.7 ns; p50 and p99 are bucket ends 1/32
of an octave wide). The host's load average was about 2 before and after
(`uptime` in the raw files). Each forker is a spawned copy of the
benchmark that makes ten forks and leaves its samples in `/tmp/probe`, so
a row's heap and threads are the forker's own.

| Row | HVF | VZ |
|---|---|---|
| S13 `posix_spawn` of a file to the child's `main` (5c: 102 / 152 / 1,037) | 121 / 205 / 1,021 | 117 / 209 / 778 |
| S14 `exec` to the new image's `main` (5c: 113 / 143 / 1,062) | 139 / 176 / 1,093 | 129 / 168 / 1,031 |
| S15 `fork` to the child's first statement, start heap | 102 / 131 / 145 | 102 / 129 / 167 |
| S15 with 1 MiB of heap | 172 / 205 / 1,121 | 172 / 205 / 756 |
| S15 with 8 MiB of heap | 623 / 737 / 1,319 | 623 / 737 / 1,570 |
| S16 `fork`, `exec` of a small file, `waitpid` | 246 / 303 / 1,131 | 246 / 287 / 1,166 |
| S17 `fork` with 1 other thread asleep | 109 / 143 / 1,074 | 109 / 135 / 171 |
| with 8 | 156 / 201 / 1,051 | 156 / 197 / 991 |
| with 32 | 319 / 418 / 1,060 | 319 / 418 / 810 |
| with 63 | 541 / 754 / 1,554 | 524 / 721 / 1,504 |
| S17 with 1 other thread running (below the forker) | 104 / 131 / 179 | 102 / 129 / 174 |
| with 8 | 152 / 197 / 919 | 147 / 197 / 1,045 |
| with 32 | 336 / 442 / 1,322 | 336 / 475 / 1,313 |
| with 63 | 639 / 885 / 1,616 | 639 / 819 / 1,744 |
| S18 `exec` to the new image's `main` with 1 other thread running | 135 / 213 / 1,004 | 135 / 205 / 545 |
| with 8 | 160 / 254 / 723 | 156 / 258 / 668 |
| with 32 | 242 / 401 / 1,349 | 242 / 393 / 862 |
| with 63 | 442 / 606 / 1,281 | 442 / 622 / 1,426 |

The rows S13 and S14 of this run are 19 % and 23 % above the 5c run on
HVF (121 and 139 against 102 and 113 us); the load of the host differs,
and the S13 and S14 of the same run are the base for the fork rows. A fork
of a small parent (102 us) takes less than a spawn of a file (121 us): the
spawn opens the file and reads the 198 KB image through the file service,
the fork copies the parent's pages from memory.

**By memory size.** The three rows of S15 give 102, 172 and 623 us: 65 to
70 us a MiB, the double cost of the copy (`mem_create` zeroes a page, the
loader copies it). The size of the benchmark's own map is 198,764 bytes of
segments, a 64 KiB stack and 64 KiB chunks of heap. BusyBox `ash` has
471,040 bytes in its segments (three LOAD segments, 115 pages) plus the
stack, the start area and a heap of a few chunks, about 0.7 MiB, so a
`fork` of `ash` costs about 130 us by the slope; the design expected 1.5 to
2.5 MiB, and the measured map is a third of it. The 1 MiB row bounds `ash`
from above.

**Kernel calls.** The rows S15 and S17 of sleeping threads count the kernel
calls of the forking process over each fork: 45.7 for a small parent
(46.7 with 1 or 8 MiB: the heap's size does not change the calls of the
parent, since the copy is the child's), and with 1, 8, 32 and 63 sleeping
threads 55.7, 128.7, 378.7 and 700.7. The increments are 10.4 calls a
thread at every step (73 / 7, 250 / 24, 322 / 31): the stop is linear.

### The cost of stopping the other threads

`stop_others` walks the table of threads under its lock and asks each
thread that has not parked for its entry of signals (`thread_upcall_request`
once, `thread_info` at every look). A thread in a wait of the kernel counts
as stopped at the first look; a running thread parks, and every parking
wakes the stopper for another walk. The question of the review was
whether the walks grow as N squared.

| N other threads | 1 | 8 | 32 | 63 |
|---|---|---|---|---|
| `fork`, asleep (us, p50) | 109 | 156 | 319 | 541 |
| `fork`, running (us, p50) | 104 | 152 | 336 | 639 |
| `exec`, running (us, p50) | 135 | 160 | 242 | 442 |

- **Asleep.** The cost is linear: 6.2 to 7.0 us a thread (a step from 1 to
  8, 8 to 32, 32 to 63: 6.7, 6.8, 7.0 us a thread), 10.4 kernel calls a
  thread, one walk. About 2 us of each thread belongs to the copy of its
  stack and TCB (the child gets them), the rest to the stop and the clones.
- **Running.** The step grows with N: 6.9, 7.8 and 9.8 us a thread. A
  quadratic term of about 0.03 us times N squared fits it (about 120 us of
  639 at N = 63): the walks repeat at each parking. It is a fifth of the
  cost at the process's ceiling of 64 threads.
- **`exec`.** 3.6, 3.4 and 6.5 us a thread: the kill of the old image's 63
  threads at ExecCommit joins the stop.

So the growth is linear with a small quadratic part, and the worst case at
64 threads is 0.64 ms p50 and 1.7 ms max for a `fork`, below the copy of 8
MiB (0.62 ms) and inside the 1 ms spread that the rows of 5c show. The stop
is the forking process's own cost: it holds the lock of the table of
threads only for each walk, and no other process waits for it.

**Recommendation.** No code change in 5d. A cheap change exists for the
day it matters: let the stopper count the notifications it received and
walk again only when the number of parked threads can have reached the
number it still waits for, which makes the walks O(N) in all. It saves at
most 120 us at 63 running threads, so it belongs with the work of 5h on the
service's steps and the lending of levels.

**Threads run round robin.** The first version of the S17 spinners (a
loop with no call, eight threads at level 10, then first-in first-out)
hung on HVF and on TCG. The stop itself ended: the kernel enters every
thread on its way back to EL0, a spinner too once an interrupt or its
quantum ends its turn, and the parent got its PID after ForkCommit. The
child hung: its thread ran at the parent's level behind the spinners,
which first-in first-out never let go, at its first request to the process
service (`process::after_fork`). Spec 2 gives POSIX threads SCHED_OTHER,
round robin with the 4 ms quantum at the process's base level, and 5d had
made them all FIFO; they are round robin now (the first thread of a
program, the loader's thread that a forked child goes on, and each
pthread, which takes its creator's policy), and `rtbench --short` with
spinners that never yield passes. The rows keep their `sched_yield`, as
measured. A thread that asks for FIFO (the scheduling attributes of 5h)
and spins without a call still starves its level, the child of a fork
among it; posix-procs checks a spinner with the default policy (role
`forkspin`).

### The steps of the process service and of the loader under `-icount`

`cargo xtask process-steps` (in `ci`) boots the probe in its steps mode
with a crowd of 248 children, a child that forks five times among them
(role `stepfork`, a parent whose heap grew by 128 KiB), and the loader with
its feature `steps`. Ticks under `-icount`, the unit of term B (20,536):

| Step | Ticks |
|---|---|
| ForkStart | 50,596 |
| ForkCommit | 2,296 |
| SpawnStart in the same run (the longest step of the service) | 89,344 |
| ExecStart, Create | 47,963, 59,716 |
| RAM file service, Clone of a fork's descriptions | 17,437 |

ForkStart is a step above term B, as SpawnStart, ExecStart and Create are,
and constant in the number of processes; it is shorter than SpawnStart, and
`process-steps` fails when it is not. The Clone of the RAM file service is
under term B, and `process-steps` fails when it passes it. Splitting the
four steps into pieces no longer than B waits for 5h, as decided.

The loader's steps are the kernel calls of the copy, each with the ticks of
its longest call in the run (a copy of up to 82 pages in one call here):
`mem_create` 80,108 (about 977 a page, 7,800 for a portion of 8 pages),
`mem_map` of the new object 13,078, `mem_map` of a piece of the parent's
object 10,308 (about 4,700 for a portion of 32), `memcpy` of a piece
143,797 (user code, preemptible), `mem_unmap` 4,414, a remap of code with
its access 55,102 (`mem_unmap` and `mem_map` with the instruction cache
cleaned), `handle_duplicate` 457, Regions 2,719 and the whole Go 858,824.
Every kernel call works in the portions that the table of paths already
holds, each at most B, and preempts between them, so the copy adds no path
and the table of paths gets no new row. The full list is in
[docs/non-preemptible-paths.md](../docs/non-preemptible-paths.md).

Raw files: the commit's directory in `reports/raw` of the design
repository (the rtbench files of both machines, the steps table and log).

## Known limits

- **No copy on write; a full copy.** The child pays for every page that
  the layer's memory map holds, 70 us a MiB on HVF. The delay of a signal
  to the forking thread's process grows with the copy, since the copy
  runs at the forking thread's level and only threads above it preempt it.
- **What the copy holds.** Objects the layer made (the heap's chunks, the
  segments, the main stack, the start area), at most 128 regions. A
  mapping made past the layer by a direct call of the kernel is not in the
  copy. `mmap` of `MAP_SHARED` is ENOTSUP, so no shared anonymous memory
  exists to share. A program that `init` starts itself has no segments in
  its map and `fork` gives ENOSYS (the dialog's `ash` is a process from
  `/bin/ash`).
- **Service step above term B until 5h.** ForkStart takes 50,596 ticks,
  2.5 times B, and every thread below the service's level waits for at most
  one such step (the ceiling protocol); nothing of real time runs there
  yet. Splitting waits for 5h.
- **Other threads.** The child has one thread. The stacks and TCBs of the
  parent's other threads are in its copy and stay in its heap, unfreed.
  A spinning thread with FIFO at the forker's level that never yields
  starves the child (above); with the default round robin it does not.
- **Limits of the service.** 32 live children a process, 256 records in
  all, 16 loads at once with 2 for a parent: `fork` gives EAGAIN past
  them, ENOMEM when the pool or the child's quota is short. The child's
  quota is the parent's, so a parent that fills its quota cannot fork.
- **Not measured.** The delay of `kill` to another thread of the parent
  during its `fork`, which the design listed for this task; S15 gives the
  copy's length for the same sizes.
- **os-test budget.** The suites `process` and the `basic` tests that call
  `fork` raised the boots of `cargo xtask os-test` from 150 s to 226-241 s
  (runs of the branch). The budget is 420 s since, which leaves about 180
  s; past it the `basic` suite splits in two.

## Readiness criteria of 5d

From the table of steps in spec 2 (5d: "`ash` runs an external `ls`
through `fork` and `exec`; rows of the cost of `fork`, `exec` and `waitpid`
by memory size") and the design of the step.

1. **`ash` runs external programs through `fork`.** Met: `ash-dialog`
   in `ci` and under `hvf` runs `/bin/ls -la`, `echo hi && ls -1 /etc`,
   `/bin/ash -c 'exit 3'` with `$?` 3, a nested `ash` and "not found" with
   status 127.
2. **Rows of `fork`, `exec` and `waitpid` by memory size.** Met: S15
   at three sizes, S16, S17 and S18, 10 minutes on HVF and VZ, the raw
   files kept; `exec` and `posix_spawn` rows come from 5c (S13, S14).
3. **Full copy by the child's loader; the kernel unchanged.** Met:
   `ci` prints term B 20,536 as before and the kernel tests pass.
4. **Every call of the copy bounded.** Met: the loader's steps under
   `-icount` are calls in portions of the table of paths; ForkStart and
   ForkCommit are steps of the service (50,596 and 2,296), ForkStart above
   B and shorter than SpawnStart, as decided for 5h.
5. **A multithreaded parent.** Met: 40 forks with
   six busy threads, pairs of forks with no wait, a thread in a long read
   and in `waitpid` carry on, the child has one thread; the cost of the
   stop is measured (linear, a small quadratic part).
6. **Signals.** Met: classes on the child's page before it is a
   target, a signal to the group during the copy reaches both, pending
   signals do not carry over, the mask and the handlers do.
7. **Descriptors and sessions.** Met: shared offsets, `FD_CLOFORK`
   closed, `FD_CLOEXEC` open, clones of the file, clock and console
   sessions.
8. **`vfork` and `pthread_atfork`.** Met: `vfork` is `fork`;
   prepare handlers run in the opposite order of registration, parent and
   child handlers in order, from any thread.
9. **os-test.** Met: the `process` suite and the `basic` tests that
   call `fork` run in `ci`; 78 pass, 74 fail, 26 need pipes (5e) of 178,
   and `ci` fails when a test of `pass.txt` stops passing.
10. **Limits written down.** Met: the section above.
11. **Not met and carried over.** The delay of `kill` to the parent during
    the copy is not measured (above); the splitting of ForkStart into
    steps of at most B waits for 5h.
