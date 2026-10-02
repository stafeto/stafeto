# POSIX step 5a′: relibc over the Rust system layer

## Result

relibc is the C library of every POSIX program, BusyBox included. The
Rust layer below it is the system part and exports no C names.

- **The fork.** `stafeto/relibc`, branch `stafeto`, pinned by
  `tools/build-relibc.py` (tags `pin-<hash>` on each pinned commit). Its
  module `src/platform/stafeto` (MIT) implements relibc's platform by
  calling the layer's `stafeto_*` functions; the dependencies sit in
  `vendor/`, so the build runs `--frozen --offline` on
  `nightly-2026-05-24` with `-Z build-std`, its paths mapped to fixed
  names (`--remap-path-prefix`), so `libc.a` holds no path of the build
  machine. The branch's README describes it. Patches carry one topic each:
  deferred cancellation through the layer's block, waits by address,
  thread start, end and release, signals, files, directories, time,
  `mmap`, POSIX error numbers of mutexes and `sigwait`, `pthread_once`
  after an initializer that does not return, `times`, `readv`/`writev`.
- **The boundary.** Functions `stafeto_*` (`lib/posix-platform`) return a
  value or a negated errno; numbers and structures are Linux AArch64's as
  relibc's headers give them. `STAFETO_PLATFORM_ABI` carries the block's
  size and offset and the interface's version; relibc checks it at start.
- **Threads.** relibc builds each TCB; the layer's block is its
  `os_specific` at +32. The layer's table of 64 places frees a TCB and a
  stack once the kernel says the thread ended and relibc released it.
- **Start.** `posix-crt` starts the process (registration, clocks, files,
  heap, the clock's page) and hands the thread to `relibc_start_v1`.
- **Licences.** `tools/check-licenses.py` (items 1 to 6) runs first in
  `ci`; images with a program on relibc carry `THIRD-PARTY-NOTICES`
  (121 KB: the MIT text of a crate under MIT or another licence), and
  images with BusyBox carry its licence and the note of its exact source.
- **The layer's surface.** The layer's functions give a value or an errno
  (`Result<_, i32>`) and keep no errno and no C name; `cargo xtask
  layer-names` checks the symbols of `lib/posix-*`. Its `.data` and
  `.bss` in a program: 10.5 KB.

## Checks

`posix-abi` (C on relibc's headers), `relibc-hello`, `relibc-threads`,
the Rust probes on a C main (`tests/libc-ffi`), BusyBox `cat`, `ash -c`,
the `ash` dialog and `ls`, and os-test's io and malloc suites (one test a
boot, `cargo xtask os-test`): 18 pass, 38 fail, 2 need `fork`. All 38
fails stop at `mkstemp`: the RAM service creates no file yet (6 tests of
`open`, 32 of open file description locks). A test that faults, is killed
or gives no end within 60 s fails and the run goes on; the run stops once
its 300 s are spent; `ci` fails when a test of `tests/os-test/pass.txt`
does not pass.

## rtbench 2

10 minutes on HVF and VZ on the last commit of the step: every row within
two counter ticks or 10 % of step 5a; S1 and S2 make no kernel call;
`malloc`/`free` of 64 bytes falls under a tick (dlmalloc). p50 / p99 in
ns, HVF then VZ: S4 `dup`/`close` 375 / 463 and 423 / 463, S6 `read`
1,343 / 2,495 and 1,343 / 2,367 (5a: 423 / 503 and 1,343 / 2,431).

## Limits

`fork`, `exec` and pipes come with steps 5b to 5e; `ash` reports `can't
fork` for a command outside BusyBox. `times()` gives no CPU time. relibc
builds with its own release profile (level 3): built for size (level `s`)
it made S4 `dup`/`close` and S6 slower than step 5a. User-space programs
have no size limit; only the kernel has one. relibc adds about 222 KB of
`.text` to BusyBox (311 KB against 89 KB on Picolibc); five copies of
`printf` and relibc's own copy of `core` make much of it (patches to offer
to relibc upstream).
