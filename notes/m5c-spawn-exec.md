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
  1 KiB a step, and `ReadInto` of an image session copies up to 64 KiB
  into a memory object the loader gives. Modes and owners come from the
  table.
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
  PPID, groups and open files stay), the service kills the old image. An
  error before ExecCommit leaves the old image whole.
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
From a file the same call took 221 us: a spawn makes the loader's
process, runs its boot and the OpenExec round trip, reads the image, and
clones three sessions. An `exec` costs about the same, since it makes the
new process under the same record. Both stay within 1.4 ms in the 4,440
samples of each run. The run is at the commit's tree with documents
(`+changes` in the file header). Raw files are in the closed reports
folder.

### Where the 221 us went (fix wave after T6)

One-minute runs of `cargo xtask rtbench --minutes 1` (460 samples a row),
p50 / p99 in microseconds, HVF and VZ:

| Tree | S13 HVF | S13 VZ | S14 HVF | S14 VZ |
|---|---|---|---|---|
| reads by `ReadAt` (the loader of T6) | 221 / 287 | 225 / 270 | 233 / 270 | 238 / 270 |
| reads by `ReadInto` | 88 / 152 | 88 / 139 | 102 / 125 | 102 / 139 |

The child, `rtbench-posix`, has 198,764 bytes in its segments (39,412,
157,568 and 1,784). `ReadAt` carries at most 1,016 bytes in the reply
through the message buffers, so the loader made 196 round trips with the
file service: 133 us of the 221, about 0.68 us a request. `ReadInto`
takes a copy of the segment's object and the service copies up to 64 KiB
from its mapping of the boot image straight into it: five requests for
the three segments. The remaining 88 us are the steps no boot-image spawn
(55 us in 5b) had: the loader's process with its code, data and stack
(SpawnStart, about 88,000 ticks under `-icount`, the longest step of the
service), Boot, the copy of the block, OpenExec with the file service's
Vouch through the notary, InfoFd, the first page by `ReadAt`, Ready, the
three Clones of the files, clock and console sessions, Handles,
SpawnCommit and Take; each is a round trip or two, and none is measured
alone. The child's own start (relibc, its sessions) is in both numbers.

### The longest step of the process service, under `-icount`

`cargo xtask process-steps [branches]` (a part of `ci` with 4 branches)
boots the probe in its steps mode under `-icount shift=4,sleep=off` and
prints the longest step of the service's loop for each method; a tick is
the counter's tick, the unit of term B of the kernel (20,536). The crowd:
branches of 32 children (`kill(-1)` twenty times, spawns and `exec` among
them, volleys of `SIGUSR1` that arm every identity session, `kill(-1,
SIGKILL)` and a spawn after the ends), then `seteuid` and `clock_settime`
make the clock service ask Vouch with every identity session in the
identity channel. The table with 32, 128 and 248 children is in
[docs/non-preemptible-paths.md](../docs/non-preemptible-paths.md); no
step grows with the number of processes.

T6 measured the steps with a Vouch that emptied the identity channel,
539 ticks an entry and about 4,360 fixed: 23,764 ticks with 36 entries,
75,508 with 132 and 140,188 with 252, about 279,000 extrapolated to 510,
13.6 times term B; SpawnStart, ExecStart and Create emptied it too
(SpawnStart 261,532 ticks with 248 entries). The fix wave after T6 gave
the kernel `object_info` LABEL: the owner of a channel, which holds it
with RECEIVE, reads the label of a labelled copy of it in O(1). Vouch now
takes the label of the copy a client gave from the kernel and looks at
nothing in the channel: 2,837 ticks with 32 children, 2,798 with 248. A
thread of the service of its own (`services/process/src/ends.rs`) takes
the ends of identity sessions and the notifications through them, one
`receive` each, at the loop's level; no step of the loop empties the
channel, and the answer no longer depends on one processor.

## Known limits

- **Fixed steps above term B.** SpawnStart (about 88,000 ticks), Create
  (about 60,000) and ExecStart (about 47,000) make a process in the
  kernel a call at a time; they do not grow with the number of processes.
- **255 POSIX processes at once.** The process service holds 256
  records. The RAM file and clock services keep 320 sessions each and 320
  clones in all, 48 live clones a client; the RAM file service keeps 256
  clones whose session has sent nothing yet (a child that never touches a
  file keeps one), its tables in `.bss`. The UART driver keeps 128 clones
  and 8 sessions: a child that reads the console takes one. The steps
  probe runs 248 children on these shipping tables.
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
   measured (done; above term B, then O(1) through `object_info` LABEL),
   the longest step of the service with 128 children (done, above; none
   grows with the number of processes).
6. **Limits as specified.** 33rd child `EAGAIN`, 1,100 children in a row
   (met).
