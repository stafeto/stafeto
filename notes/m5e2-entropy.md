# POSIX step 5e': random numbers

## Result

Every POSIX process has a source of random numbers that needs no request to a service once it has its key. A driver for the Virtio entropy device
(`services/virtio-rng`, a trusted service with DMA) feeds the entropy
service (`services/entropy`), which gives each process a key of 32 bytes.
The layer of the process (`posix_abi::random`) runs a ChaCha20 generator
with fast key erasure on that key and serves `getentropy`, `getrandom`
(`GRND_NONBLOCK`, `GRND_RANDOM`, `GRND_INSECURE`), the reads of
`/dev/random` and `/dev/urandom`, and, through relibc, `arc4random`,
`arc4random_buf`, `arc4random_uniform` and the names of `mkstemp`,
`mkdtemp` and their relatives. A child of `fork` forgets the key and the
buffer it copied and asks for a key of its own. The kernel did not change.

`/dev/random` and `/dev/urandom` are entries of the boot image's table, like
`/dev/null`; the RAM service opens them as devices and marks the reply
(`RANDOM_DEVICE`), the layer keeps the descriptor as `Target::Random` and
serves its reads itself. Writes, `fstat`, `dup` and `close` go to the RAM
service as for any file: a write is taken and dropped, and `stat` shows a
character device (the null device is one now too). The descriptor crosses
`fork`, `posix_spawn` and `exec` (`Names::Random` in the loader's block).
The nodes are in every image where POSIX programs run (`ash` dialog,
`posix-procs`, steps, os-test, the random probe and rtbench), each with the
driver and the entropy service in `init`'s table.

relibc commit 6122dbb2 (`pin-6122dbb2`): `arc4random*` read `getrandom` and
end the process when the platform has no generator (as on OpenBSD); the
six characters of `mkstemp`, `mkostemp`, `mkstemps`, `mkdtemp` and `mktemp`
come from `getrandom`, one of 62 for each byte below 248, and a platform
whose `getrandom` fails keeps the clock's jitter.

BusyBox: `ash`'s `$RANDOM` is a generator of the shell (a feedback shift
register seeded with the process number and the time; it reads no device,
which is BusyBox's design), `mktemp` takes its names from `mkstemp`, and
the only other reader of `/dev/urandom` in the sources of the objects that
are built is `libbb`'s `generate_uuid`, which no applet of the build
calls. The
build now has `ASH_RANDOM_SUPPORT`, `head` with `-c` and `mktemp`
(`tools/build-busybox.py`). The dialog checks `head -c 4096 /dev/urandom |
wc -c`, `cat /dev/urandom | head -c 100 | wc -c` (the writer never ends,
the reader's exit closes the pipe), a write to `/dev/urandom`, `$RANDOM`
(two reads differ, `RANDOM=7` repeats), `ls -l` of the three nodes
(`crw-rw-rw-`) and a `mktemp` that fails with status 1.

## Measurements

### rtbench, 10 minutes (HVF and VZ at the same time)

125 rounds (the run's tree differs from this commit in the probe's last
checks and the steps image), 125,000 samples a row, host load average 1.8 before and 2.3
after (`uptime` in the raw files). Times in nanoseconds, p50 / p99 / max;
the counter ticks 41.7 ns, so the smallest values are a few ticks. The
three rows are new (S23 to S25); the C scenarios are built with
`-fno-builtin` and each result is compared.

| Row | HVF | VZ | kernel calls |
|---|---|---|---|
| S23 `getentropy` of 32 bytes | 211 / 959 / 23,875 | 211 / 959 / 11,625 | 2 |
| S24 `getentropy` of 256 bytes | 927 / 1,055 / 23,041 | 927 / 1,055 / 12,375 | 2 |
| S25 a read of 4 KiB of `/dev/urandom` (five reads of up to 1,016 bytes) | 12,287 / 13,311 / 94,916 | 12,287 / 13,311 / 42,375 | 38 |

The two kernel calls of `getentropy` are the layer's lock (raise and
lower the holder's level); no message goes anywhere. A read of 4 KiB gives
333 MB/s at the p50 (HVF, VZ the same); the layer serves it in five reads
of at most 1,016 bytes (`MAX_READ`), each held outside the lock, so it
costs about 7 kernel calls a read. The rows that came before did not move
except S22, which is 5% above 5e's: S9 0.42 us and S19 5.5 us as in 5e, S22
655 us p50 (HVF) against 623 us. The BusyBox of the image has `head`,
`mktemp` and `$RANDOM` now and the host's load differs; the two causes are
not separated.

### The steps of the services under `-icount`

`cargo xtask entropy` (in `ci`), term B 20,536 ticks:

| Step | Ticks |
|---|---|
| entropy service, SEED | 5,623 |
| entropy service, a seed with 32 waiting | 10,208 |
| entropy service, the feeder's bytes | 5,452 |
| entropy service, heartbeat | 5,064 |
| virtio-rng, FILL_START | 1,948 |
| virtio-rng, FILL_TAKE | 4,444 |
| virtio-rng, interrupt | 1,934 |

Every step is below B. Reads of the devices add no step: the layer serves
them. The services run beside the RAM and process services in the images
of the dialog, `posix-procs`, os-test and rtbench; `ci` ran in 6 min 33 s,
`hvf` in 3 min 23 s, and the seven probes of VZ passed.

### os-test

121 pass, 73 fail, 11 unsupported of 205 (120, 73, 11 of 204 before).
`basic/unistd/getentropy` joined the built tests (`tools/build-os-test.py`)
and passes; the os-test image has the driver and the service now. The 39
tests that fail in `mkstemp` stay (32 `ofd-*`, 6 `open-mkstemp-*`,
`posix_spawnp`): the names are random and every try meets the same refusal
of the RAM service, which creates no file until 5i.

## Tests and the breakage each catches

Each was applied, the affected set run, then reverted.

- `tests/posix-random` (C, `-fno-builtin`): both nodes are character devices
  by `stat` and `fstat`; 4,096 bytes of each, all different and nonzero; a
  write is taken whole; a description opened for writing alone cannot be
  read (`EBADF`); a `dup` reads after the original closed; `arc4random`,
  `arc4random_buf` (zeroed buffers), `arc4random_uniform` (bounds 0, 1, 3,
  10, 2^31 + 1, ten buckets of 4,000 draws); the names of `mkstemp` and
  `mkdtemp` are six letters and digits and differ; a short template gives
  `EINVAL`; a device descriptor crosses `posix_spawn`, an `FD_CLOEXEC` one
  is closed, and a descriptor crosses `fork` with bytes different from the
  parent's.
  - A kind of the device that reads as regular: the host test and the
    probe fail (`S_ISCHR`).
  - The layer reads a random device as a file: `EBADF` in the probe.
  - `Names::Random` sent as `Names::File`: the spawned child's read is
    refused (`EINVAL`), the probe fails.
  - The service does not mark the open of a device: the read goes to the
    service and is refused, the probe fails.
  - The layer gives zeros: the fork check (equal zeros) fails.
  - A write-only description read by the layer: the probe fails (`EBADF`).
  - `arc4random_uniform` without its bound: the probe fails; `arc4random_buf`
    that fills nothing: the probe fails.
- Host: `the_random_devices_are_characters_the_layer_reads` (ramfs): the mark
  of the open, a dropped write, a refused read and `pread`, kinds in
  `lookup`, `information` and the directory; a write kept as a file write
  fails it.
- Host: the loader's block carries `Names::Random`; every image's table
  lists the three device nodes; the orders of `init`'s tables.
- Dialog: the image without the `/dev/urandom` node fails `ls -l`.

## Known limits

- **The names of `mkstemp` and `mkdtemp` come from the generator, and no
  test tells.** Nothing observable separates them from the jitter fallback
  (the names are six letters and digits either way). Creating the file
  waits for 5i: each call makes its 100 tries and ends with `EEXIST`, and
  the template keeps the last name. `mktemp` of BusyBox fails the same way
  with status 1.
- **`$RANDOM` in `ash` does not use the generator** (seeded with the
  process number and the time).
- **A read of a device returns at most 1,016 bytes**, as every read of the
  layer does; a program that reads 4 KiB loops. `getrandom` and `getentropy`
  give the whole length asked for (up to 256 bytes for `getentropy`).
- **Reads wait for the first key.** A read, `getrandom` without
  `GRND_NONBLOCK` and `getentropy` wait for the entropy service's first
  bytes (a few milliseconds after boot); `O_NONBLOCK` of a device has no
  effect, and a signal handler without `SA_RESTART` ends the wait with
  `EINTR`. `/dev/random` and `/dev/urandom` are the same generator and never
  block after the first key.
- **No `pread` and `pwrite` on the devices** (`ESPIPE`); `lseek` takes any
  offset and has no effect.
- **Without the service**: a read of a node and `getrandom` give `ENOSYS`,
  `arc4random` ends the process. Images other than those listed above (for
  instance the POSIX probes of Apple VZ other than rtbench, which have no
  table of files) have no nodes.
- **The steps image has no entropy service.** `process-steps` measures the
  steps of the services under `-icount`, where the driver at 45 and the
  service at 44 preempt the RAM service at 40: with them in the image the
  READ_INTO step read 23,438 ticks (19,369 without them), past term B, by
  their boot work alone. The nodes are in that image, and a read of them
  gives `ENOSYS`.
- **The nodes' mode** is 0666 and the service checks no permission at open.
- **The reads of the devices do not reach the RAM service**, so its access
  time of them does not move.
- **Writes are dropped**: nothing mixes into the generator.
- **The device is trusted.** The entropy comes from the Virtio device alone
  (no `RNDR` on the hosts: the instruction traps on the M4 in a process
  and the guests of HVF and VZ do not show it); the platform's own source
  is a question of stage 4.
- **Fork and snapshots.** A child of `fork` takes its own key; a restored
  snapshot of a machine would repeat the generators of all processes
  (snapshots are not used).
- **Interface 13** of the platform and the loader slot 10 may meet step
  5e's numbers when the branches merge; the second to merge raises them.

## Readiness criteria of 5e' (issue #175)

1. **The entropy service, a Virtio entropy driver in user space (QEMU and
   VZ), `RNDR` checked under HVF**: done. The driver runs on QEMU's
   virtio-mmio and on VZ's Virtio PCI, by interrupt, with DMA and a reset
   at its stop; the service survives the driver's death; `RNDR` is no
   source (the instruction traps in a process on the M4 and neither HVF nor
   VZ shows `FEAT_RNG` to guests; the check in a guest was not made, the
   host's probe and `sysctl` decide it).
2. **A ChaCha20 generator in the layer, keyed by the service, with no
   kernel call for a read**: done (2 kernel calls of the layer's lock; the
   fast path takes the lock once). The key is replaced after 1 MiB and
   forgotten by a forked child.
3. **`getentropy` (POSIX.1-2024) and `getrandom` in relibc's platform**:
   done: `getentropy` of 256 bytes, `EINVAL` past `GETENTROPY_MAX`, a wait
   again after a handler; `getrandom` with the three flags; os-test's
   `basic/unistd/getentropy` passes.
4. **The nodes `/dev/random` and `/dev/urandom`**: done, as above.
5. **Probes and measurements; the kernel unchanged**: done: the probes
   `entropy`, `posix-random`, the dialog and the host tests; rtbench rows
   S23 to S25 on HVF and VZ; `entropy` steps below term B; `git diff
   main -- kernel kcore` is empty.
