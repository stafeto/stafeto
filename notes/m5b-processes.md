# POSIX step 5b: the process service

## Result

The process service creates every POSIX process, keeps one record for each
and answers `waitpid`, `kill`, groups and sessions. `posix_spawn` starts a
program of the boot image as a child. The C probe `posix-procs` (in `ci`)
checks it on relibc.

- **Records and numbers.** 256 records; PID = index + 256 * generation, so
  the PID of a live process is never 1 and a number is not issued again
  while its record, zombie, process group or session lives. Lookup by
  label or by PID is O(1).
- **Creation.** The service calls `process_create` itself, so a child
  pays from the service's quota, and loads the image on two threads of
  its own (`rt::loader`) until the loader of step 5c replaces them. The
  child's exit channel is a copy of the service's channel with a label
  that names the record; the kernel says why a process ended (an exit
  code, a kill, a fault) and the service reads it in O(1).
- **`waitpid`.** A zombie that is ready answers at once; otherwise the
  wait is a long operation in two steps that a signal interrupts. An exit
  and a death by a signal are told apart: `_exit(n)` ends with `n & 0xFF`,
  death by signal `n` with `0x100 | n`, so `WIFSIGNALED` for `SIGTERM`
  differs from `exit(143)`.
- **`kill`.** The service sets a bit on the target's page of signals and
  asks the kernel to enter the target's router thread (`thread_upcall_request`);
  the layer picks the receiving thread late, by mask. `SIGKILL` goes
  through `process_kill_at` at the target's ceiling and works on a process that blocks everything.
  `killpg`, `kill(0)` and `kill(-1)` walk the records in steps that return
  to the service loop between deliveries.
- **Groups and sessions.** `setpgid`, `setsid`, `getpgid`, `getsid`,
  `POSIX_SPAWN_SETPGROUP` and `POSIX_SPAWN_SETSID`; orphans get PPID 1,
  which the service plays as a system process.
- **Credentials.** A session of identity and a page of generations let
  another service ask who a client is without a request per call; the
  clock service allows `clock_settime` only to an effective UID of 0.

## Found by the benchmark

A run of rtbench 2 spawns about 1,000 children in ten minutes and stopped
with `EAGAIN` at the 1,023rd: the end of an identity session waits in its
channel until it is received, and no loop receives on that channel, so the
sessions of the processes that went filled its 1,024 places. The
receiving and launch threads now empty the channel before each Create
(each end is received once, on their stack, so no step of the loop grows
with the number of processes). The probe `posix-procs` has a stage of 1,100 children
in a row for it.

## Measurements

`cargo xtask rtbench --minutes 10` has rows S10 to S13 (see
[status](../docs/status.md)). The group of S12 has seven members:
every child is a record of `init`'s table, which holds 16, and a record has
one live child.

## Known limits

- **Vouch is bounded, and measured in 5c.** Vouch (a service asking who a
  client is) emptied the identity channel before it notified through the
  copy it was given: 539 ticks an entry under `-icount`, 140,188 ticks with
  252 entries. Later in step 5c it reads the copy's
  label from the kernel (`object_info` LABEL) in O(1), about 2,800 ticks
  with any number of processes (see [m5c-spawn-exec](m5c-spawn-exec.md)).
- **Limits of the moment.** A second walk of one sender waits in a queue
  of 64 places; past them, and past 1,024 long waits, `EAGAIN`.

- **One CPU.** The service tells a notice from a forged one by reading
  which place of its channel a notification came to, between the
  notification and the read; that holds because the service's loop runs
  above every client on a single core. SMP needs the kernel to say whose
  channel a copy is.
- **32 live children a process.** The limit stays until `RLIMIT_NPROC`
  and `{CHILD_MAX}` count by real UID; zombies count.
- **16 records in `init`'s table.** Every program a process may spawn is
  a record of the table, and the table is full at 16, so a benchmark or a
  probe has as many different children as it has free records, and a
  record has one live child (`EAGAIN` for a second).
- **Router hand-over.** Signals go to the process's router thread, the
  main thread until step 5h; when it ends, the layer registers the next
  thread. A signal that arrives between the two waits on the page until a
  thread unblocks it or enters.
- **No `fork`, no `exec`, no file actions.** `posix_spawn` takes only a
  record of the boot image under `/boot`, the flags `SETPGROUP` and
  `SETSID`, no file actions and no attributes beyond them; the signal
  mask and `SIG_IGN` pass to the child.
- **No stop and continue.** The stop signals answer `EINVAL` until step 5f.
- **Spawn is not interrupted.** A signal does not interrupt `posix_spawn`
  while the service copies the image; the copy is bounded by the image.
- **`kill(-1)` from root** reaches every POSIX process but the caller and
  PID 1.
