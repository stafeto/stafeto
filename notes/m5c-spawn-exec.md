# POSIX step 5c: `posix_spawn` and `exec` from files

## Result

`posix_spawn` and `exec` start a program from a file of the RAM file
service. The boot image carries the files (a table of paths, modes and
owners next to each program's ELF file); a small loader program runs in
the new process, opens the file, maps its segments and jumps. The C probe
`posix-procs` (in `ci`, on QEMU and under HVF) runs `/bin/ls /etc` from a
spawn and from an `exec`, and `cargo xtask os-test` runs os-test from
files, a boot for each suite.

- **Files.** `lib/bootimg/src/rootfs.rs` holds the table (up to 1,024
  entries, paths up to 511 bytes, names up to 255). `services/ramfs` reads
  files from its read-only mapping of the image; `ReadAt` copies at most
  1 KiB a step. Modes and owners come from the table.
- **Loader.** `services/loader` runs in the child at `abi::LOADER_BASE`.
  The parent sends the block of `argv`, `envp`, the current directory and
  the descriptors (`proto/loader`, up to 64 KiB of strings), then
  `Go`; an error before the image is ready returns from `posix_spawn`
  synchronously (ENOENT, EACCES, ENOEXEC, ENOMEM, E2BIG, ENAMETOOLONG).
  The parent holds only a copy of the loader's channel and never a handle
  of the child's process.
- **OpenExec.** The loader opens the file itself through the session
  "loaders" that `init` gives the process service; the file service checks
  `x` for the effective IDs of the record the loader loads, takes the
  set-ID bits and sends them to the process service in the same step.
  A parent that lends a channel of its own gets nothing from it.
- **Descriptors.** A spawned child shares the open descriptions of its
  parent that the file actions leave (Clone with a list of numbers; one
  table of 128 descriptions with reference counts in the file service).
- **`exec`.** Seven steps (spec 2, 3.2): the other threads park, ExecStart
  makes a new process under the same record, the loader loads the file,
  descriptors move after "image ready", ExecCommit moves the record (PID,
  PPID, groups and open files stay), the old image ends. An error before
  ExecCommit leaves the old image whole.
- **Table of `init`.** Records of the table no longer start children; the
  children of `posix-procs` and `rtbench` come from `/bin` with the
  parent's quota out of the service's pool.

## Measurements

### rtbench, 10 minutes (HVF and VZ)

10 minutes, 222 rounds, 4,440 samples each (11,100 for S10), p50 / p99 / max in microseconds (the counter ticks 41.7 ns):

| Row | HVF | VZ |
|---|---|---|
| S13 `posix_spawn` of a file to the child's `main` | 221 / 303 / 1,159 | 221 / 295 / 1,189 |
| S14 `exec` to the new image's `main` | 229 / 270 / 878 | 229 / 270 / 901 |
| S12 `killpg` to a group of 32, to the last `waitpid` | 639 / 918 / 1,047 | 655 / 918 / 1,074 |
| S11 `waitpid` of a ready zombie | 1.2 / 2.0 / 5.1 | 1.2 / 1.9 / 5.0 |
| S10 `kill` of a process, target sleeping | 1.4 / 3.5 / 16 | 1.4 / 3.3 / 11 |

Step 5b measured `posix_spawn` from a boot-image record at 55 us p50.
From a file the same call takes 221 us: a spawn now makes the loader's
process, runs its boot and the OpenExec round trip, reads the image, and
clones three sessions. An `exec` costs about the same, since it makes the
new process under the same record. Both stay within 1.4 ms in the 4,440
samples of each run. The run is at the commit's tree with documents
(`+changes` in the file header). Raw files are in the closed reports
folder.

### The longest step of the process service, under `-icount`

`cargo xtask process-steps [branches]` (a part of `ci` with 4 branches)
boots the probe in its steps mode under `-icount shift=4,sleep=off` and
prints the longest step of the service's loop for each method; a tick is
the counter's tick, the unit of term B of the kernel (20,536). With 128
children, four branches of 32 each (`kill(-1)` twenty times, spawns and
`exec` among them, volleys of `SIGUSR1` that arm every identity session,
`kill(-1, SIGKILL)` and a spawn after the ends):

| Step | Ticks | Entries taken off the identity channel |
|---|---|---|
| SpawnStart | 158,692 | 128 |
| Vouch | 75,508 | 132 |
| ExecStart | 48,142 | 1 |
| Create | 59,602 | 0 |
| `STEP` notification (the walk of `kill(-1)`, ends) | 14,137 | 0 |
| Boot | 6,806 | 0 |
| WaitStart | 6,857 | 0 |
| Take | 5,422 | 0 |
| ExecCommit | 4,189 | 0 |
| SpawnCommit | 2,214 | 0 |
| Kill (one step of the walk) | 1,201 | 0 |

Without a backlog in the identity channel a SpawnStart takes 87,891 ticks
(32 children). The steps of `Kill`, `ExecCommit` and `SpawnCommit` do not
grow with the number of processes. SpawnStart, ExecStart, Create and
Vouch empty the channel of identity sessions before they notify (the
cost of 5b's Vouch), so each grows with the entries that wait there. The
line is in [docs/non-preemptible-paths.md](../docs/non-preemptible-paths.md)
next to the kernel paths.

### Vouch under `-icount`

The probe builds the most identities it can: 248 children (seven branches
of 32 and 24 of the probe's own, the limit of the 256 records), each
armed by a `SIGUSR1` volley, then `seteuid` and `clock_settime` make the
clock service ask Vouch with nothing draining the channel before it.

| Entries taken | Ticks |
|---|---|
| 36 | 23,764 |
| 132 | 75,508 |
| 252 | 140,188 |

Two segments both give 539 ticks an entry, about 4,360 ticks fixed. The
probe reached 252 of the 510 receives that the loop can face (255 ends
not yet received and 255 notifications of live processes) and cannot go
further, since every entry belongs to a process that lives or ended since
the last call that drained the channel. Linear extrapolation to 510:
about 279,000 ticks, 13.6 times term B (20,536). **The worst Vouch is far
above term B**: Vouch alone reaches B at about 30 entries. The cure is a
small kernel change (`object_info` of a copy a caller receives on gives
its label, O(1), which also removes the dependence on one processor).
This step leaves the kernel unchanged; the change is due before multicore
and before the process service takes a hostile load.

## Known limits

- **Vouch and the drain.** Above. SpawnStart, ExecStart and Create carry
  the same cost: SpawnStart takes 261,532 ticks with 248 entries.
- **About 60 POSIX processes at once.** The RAM file and clock services
  keep 64 sessions each, 128 clones in all, 48 live clones a client, and
  64 clones whose session has sent nothing yet (a child that never touches
  a file keeps one: `EAGAIN` for the next spawn). The probe of the steps
  builds both services with 320 places (feature `steps`); the shipping
  tables stay at 64.
- **Loads at once.** 16 loaders in all, 2 for a parent; a spawn past them
  is `EAGAIN` (a caller retries).
- **32 live children a process** (zombies count), 256 records in all.
- **Pool.** A child's quota is its parent's, from the service's pool;
  `ENOMEM` when the pool is short.
- **One `exec` at a time** for a record, `EAGAIN` for a second; the image
  number stops at 2^21 - 1 `exec` calls of one record.
- **Rights.** The file service checks `x` only; `r` and `w` wait for 5g.
  Set-ID images start with 0, 1 and 2 on a console that reads nothing.
- **Not interrupted.** `posix_spawn` and `exec` are not interrupted by a
  signal while the loader loads; the bound is the size of the image.
- **No `fork`, no `fexecve`** (ENOSYS until 5d). BusyBox `ash` starts
  external commands through `fork`, so `ash -c /bin/ls` waits for 5d.
- **Timers.** `alarm` and the word of pending timers cross `exec` as
  zeros until 5h.
- **os-test.** 63 PASS, 48 FAIL, 9 UNSUPPORTED of 120. The suite `process`
  is not in the run (all 24 tests call `fork`); `addchdir`, `addfchdir` and
  `posix_spawnp` fail on `access` and `mkstemp` of the layer (5g).
- **Not measured.** Design row S14 for BusyBox, the cost of reading an
  image a MiB, and the latency of `kill` to a parent that waits for
  "image ready" are left to the next measurement run.
- **Measurement builds.** The steps image enables `rt/step-stats` and the
  features `steps` of the RAM file and clock services; no other image does.

## Readiness criteria

From the table of steps in spec 2 and the first goals of the design.

1. **`ash` starts an external `ls` through `posix_spawn` or `exec`.** The
   first goal as set by decision of 2026-10-02: `posix_spawn("/bin/ls",
   "/etc")` and `waitpid` (met, `posix-procs` stage 7, in `ci` and under
   HVF) and `exec` into `/bin/ls` (met, stage 9). `ash -c /bin/ls` goes
   through `fork` in BusyBox and moves to 5d.
2. **The parent has no handle of the child's process.** Met by
   construction: `SpawnStart` returns a copy of the loader's channel and
   the PID. The probe checks the child's side (it holds no handle of its
   loader); no probe walks the parent's table.
3. **Checks run from files.** Met: `cargo xtask os-test` starts every test
   from `/os-test/<suite>/<name>`, a boot for each suite, 150 s of 300.
4. **Set-ID through the file service.** Met: OpenExec, SetId tied to the
   loader's place, probes of the forged channel and of a failed load.
5. **The 5b debts.** The group of 32 (met, row S12), the Vouch limit
   measured (done; above term B), the longest step of the service with 128
   children (done, above).
6. **Limits as specified.** 33rd child `EAGAIN`, 1,100 children in a row
   (met).
