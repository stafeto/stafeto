# POSIX step 5e: pipes

## Result

Pipes live in a service of their own (`services/pipe`), and the kernel did
not change: term B stays 20,536 ticks. A pipe is a ring of 4 KiB in the
service's `.bss`; a read or a write that has to wait is a long operation
in two steps, so a signal cancels it with no side effect and `SA_RESTART`
continues it. The layer sends `SIGPIPE` before it returns `EPIPE`. The
ends cross `fork`, `posix_spawn` (`adddup2`, `addclose`) and `exec`; a dead
process is an end that closes, so its reader gets end of file. BusyBox
`ash` runs pipelines (`ls /etc | cat`, a pipeline of three, `ls /bin | wc
-l`, `(ls /bin > /dev/null) | cat`, a job in the background with `wait`),
and `/dev/null` is a null device of the RAM service (`O_CHANGES`, a new
open flag of the layer). The process service gives a child's `setpgid` its
rules (`execed` flag) and wakes a `waitpid` on a group that emptied.

## Measurements

### rtbench, 10 minutes (HVF and VZ at the same time)

125 rounds, host load average 1.3 before and 2.2 after (`uptime` in the raw
files). Times in microseconds, p50 / p99 / max; the counter ticks 41.7 ns.
S20 gives the time of 1 MiB; the throughput below it is 1,048,576 bytes
over that time, so the p99 and the maximum of the time are the lowest rates.
The C scenarios are built with `-fno-builtin`.

| Row | HVF | VZ |
|---|---|---|
| S19 a byte through two pipes to another process and back (125,000 samples; 12 kernel calls a round trip) | 5.5 / 6.4 / 31.6 | 5.5 / 6.3 / 27.8 |
| S20 1 MiB in writes of 512 bytes (375 samples), time in us | 4,194 / 4,719 / 4,800 | 4,194 / 4,747 / 4,747 |
| the same as MB/s | 250 / 222 / 218 | 250 / 221 / 221 |
| S20 1 MiB in writes of 4 KiB, time in us | 2,425 / 2,753 / 2,764 | 2,425 / 2,726 / 2,726 |
| the same as MB/s | 432 / 381 / 379 | 432 / 385 / 385 |
| S22 `ls /etc \| cat` (1,250 samples; 132 kernel calls) | 623 / 770 / 1,698 | 623 / 770 / 1,658 |

The best of the 375 transfers took 3,841 us (273 MB/s) with 512-byte writes
and 2,173 us (483 MB/s) with 4 KiB writes on HVF.

For comparison, from the same run: S9, an empty round trip to a service,
0.42 / 0.46 / 9.2 us with one kernel call; S13 `posix_spawn` of a file to
the child's `main` 125 / 213 us p50 / p99 (HVF); S15 `fork` to the child's
first statement 106 / 143 us; S16 `fork`, `exec` of a small file and
`waitpid` 254 / 311 us.

- **A round trip through two pipes** takes 13 times an empty round trip to
  a service. Each half is a write (WriteStart) and a read (ReadStart,
  ReadTake after the wake-up) with 6 kernel calls, a copy of one byte in
  the service and the wake-up of a thread of another process: 2.7 us a
  half, against 0.42 us for the bare round trip.
- **Throughput.** A write of 4 KiB goes in four messages of 1,004 bytes at
  most (`MAX_WRITE`), a read of the sink takes at most 1,016, and a full
  ring of 4 KiB makes the writer wait for the sink: 9.5 us a write of 4 KiB
  (432 MB/s), against 4.1 us a write of 512 bytes. A byte costs less in
  the larger write because the fixed part of a message is paid once for
  1 KiB. The design expected hundreds of MB/s or less; the measure says
  250 to 430. The ring of 16 KiB and a data path through a shared object,
  the two answers the design kept for a rate that is too low, are not
  needed by `ash`.
- **`ls /etc | cat`** takes 623 us: two forks of a small parent (106 us
  each), two `exec`s of the 471 KB BusyBox through the file service (about
  150 us each, S16 minus S15) and the pipes. It is 2.4 times S16, which is
  a fork, an exec and a wait, and 4.9 times `posix_spawn` of a file. The
  pipes themselves cost the rest, about 100 us for 132 calls of the
  forker, from creating two pipes to the last wait.
- No row of the 5d table moved by more than the spread of the host's load
  (S13 125 us against 121, S14 139 against 139, S15 106 against 102, S16
  254 against 246).

S21 of the plan, from a write into an empty pipe to the return of a
waiting `read`, has no row of its own: it is the half of a S19 round trip
at most, and S19's histogram bounds it.

### The steps of the pipe service under `-icount`

`cargo xtask process-steps` (in `ci`, 128 children; 248 with 7 branches)
boots the service with its feature `steps`; the probe's role `steppipes`
makes each kind of step at its longest. Ticks, term B 20,536:

| Step | 128 children | 248 children |
|---|---|---|
| Clone of up to 32 ends | 12,914 | 17,382 |
| WriteStart | 9,047 | 9,047 |
| ReadStart | 8,625 | 8,625 |
| ReadTake | 7,211 | 7,211 |
| Close | 6,148 | 6,148 |
| Create | 5,141 | 5,141 |
| Abandon | 4,904 | 5,372 |
| WriteTake | 3,922 | 3,922 |
| own step (a description let go of, a session gone) | 3,894 | 5,682 |
| ReadCancel, WriteCancel | 2,130, 2,175 | 2,130, 2,175 |
| Stat, GetFlags, SetFlags | 1,432, 1,360, 1,360 | 1,432, 1,360, 1,360 |
| heartbeat: a send to init and its reply | 5,630 | 403,468 |

Every kind of step is below B, and `process-steps` fails when one passes
it. The heartbeat is the loop's wait for init's reply: processes of higher
levels run in it (the volley of 248 children), it is no work of the service,
and the check bounds it at 500,000 ticks apart from B. No step allocates
memory. The table of kernel paths is unchanged; the steps are recorded in
[docs/non-preemptible-paths.md](../docs/non-preemptible-paths.md).

## Known limits

- **16 pipes per session, 48 per tree.** One process (a session of the
  service) has 16 live pipes (`EMFILE`); all the processes under one program
  that `init` started share 48 (`ENFILE`). The service holds 64 pipes in
  all.
- **A ring of 4 KiB; `PIPE_BUF` is 512.** A write of at most 512 bytes
  goes in whole or waits for room, and so does a `writev` of at most 512
  bytes in all, which relibc gathers into one write; a longer one is cut
  into pieces of at most 1,004 bytes, and the pieces of two writers may mix.
  `readv` makes one read, as `read` does, and spreads its bytes over the
  parts. The pipe's size
  cannot be changed (`F_SETPIPE_SZ` is not there).
- **Waits.** At most 8 blocked operations at one end, 16 in one process, 96
  of the 128 that the service holds; `EAGAIN` past them (see the
  conformance list).
- **Sessions and records.** 255 clones per tree of processes, of the
  service's 320 sessions; `Clone` gives `EAGAIN` past them.
- **No `poll`, `ppoll`, `select`, `pselect`.** relibc builds them on
  `epoll`, which the platform answers with `ENOSYS`; the 11 tests of os-test
  that call them are UNSUPPORTED. They come with the terminal service in the
  next step (5f), which watches a set of descriptions; the pipe service
  already keeps its waiters by end.
- **No named pipes.** `mkfifo` waits for the file service's nodes.
- **`/dev/null` is a regular file** to `stat` (the root file system has no
  device nodes); it takes `O_CREAT`, `O_TRUNC`, `O_APPEND`.
- **Processes of `init`'s table have no `fork`** (`ENOSYS`), as in 5d.

## Conformance list

Deviations from POSIX.1-2024 that this step knows of:

1. **`setpgid` error order.** For a child of the caller, `EACCES` (the
   child has executed a program) is checked before `EPERM` for a child in
   another session. POSIX does not fix the order of the two; Linux gives
   `EPERM` first.
2. **Blocking reads and writes can fail with `EAGAIN`.** A read or write
   that would wait, past 8 waiters at one end, 16 in one process, 96 in
   the tree or 128 in the service, returns `EAGAIN` although the
   description is blocking (`read` and `write` list no such error for a
   blocking pipe). The limits keep the service's steps constant.
3. **`PIPE_BUF` is 512**, the least POSIX allows; a write of 4 KiB is not
   atomic.
4. **`fstat` of a pipe** gives `S_IFIFO` and the pipe's number in
   `st_ino`; the other fields carry no information.
5. **`pipe` and `pipe2` fail with `ENFILE` or `EMFILE` at 48 or 16 live
   pipes**, limits of the service that no system-wide file limit explains,
   and with `ENOSYS` in a program that was given no pipe service.
6. **`poll`, `select` and the like are `ENOSYS`** until 5f.
7. **`/dev/null` reports a regular file** and is the only device node.

## Readiness criteria of 5e

From the table of steps in spec 2 (5e: "`ash` runs `ls | cat`; the os-test
signal set in the count") and the design of the step.

1. **`ash` runs `ls | cat`.** Met: `ash-dialog` in `ci` and under `hvf`
   runs `ls /etc | cat`, `echo hello | cat | cat`, `ls /bin | wc -l`,
   `(/bin/ls /bin > /dev/null) | cat` and a missing command in a pipeline;
   `posix-procs` runs `ash -c '/bin/ls /etc | /bin/cat'` and compares the
   output and the status.
2. **The os-test signal set is in the count.** Met: 120 pass, 73 fail, 11
   UNSUPPORTED of 204; the `process` suite and `basic/signal/{kill,killpg}` pass; `ci` fails when a test of
   `pass.txt` stops passing.
3. **Pipes with the right semantics.** Met: end of file after the last
   writer closes or dies, `EPIPE` with `SIGPIPE` first, `O_NONBLOCK`
   by the tables of `read` and `write`, atomic writes up to `PIPE_BUF`
   (host tests of the service and the probe `posix-procs`).
4. **Signals and waits.** Met: `SA_RESTART` and `EINTR` on a pipe,
   `signal()`, `waitpid` interrupted by `SIGCHLD`, `sigsuspend` and
   `pause` woken by it, an ignored signal that a thread blocks stays
   pending until it is unblocked.
5. **Ends across processes.** Met: `fork`, `posix_spawn` with `adddup2` and
   `addclose`, `exec` with `FD_CLOEXEC`; the waiters of an old image are
   cancelled before `exec` (Abandon).
6. **The kernel unchanged, every step below B.** Met: `ci` prints term B
   20,536; every kind of step of the pipe service is below it
   (`process-steps`).
7. **rtbench rows.** Met: S19, S20 (two sizes) and S22, 10 minutes on HVF
   and VZ at the same time, raw files kept; S21 is covered by S19 (above).
8. **Limits written down.** Met: the section above, the conformance list
   and the README.
9. **Not met and carried over.** `poll` and `select` (5f); named pipes;
   splitting the long steps of the process service waits for 5h as decided.
