# POSIX step 5a′: relibc over the Rust system layer

## Result

relibc is the C library of every POSIX program, BusyBox included. The
Rust layer below it is the system part and exports no C names.

- **The fork.** `stafeto/relibc`, branch `stafeto`, pinned by
  `tools/build-relibc.py` (tags `pin-<hash>` on each pinned commit). Its
  module `src/platform/stafeto` (MIT) implements relibc's platform by
  calling the layer's `stafeto_*` functions; the dependencies sit in
  `vendor/`, so the build runs `--frozen --offline` on
  `nightly-2026-05-24` with `-Z build-std`. Patches carry one topic each:
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
boot, `cargo xtask os-test`): 10 pass, 46 fail, 2 need `fork`. The fails
are the RAM service's missing file creation (`mkstemp`, `O_CREAT`,
`O_TRUNC`, `O_APPEND` on a directory give EEXIST or EINVAL) and open file
description locks.

## rtbench 2

10 minutes on HVF and VZ at b8141fd: every row within two counter ticks
or 10 % of step 5a; S1 and S2 make no kernel call; `malloc`/`free` of 64
bytes falls under a tick (dlmalloc).

## Limits

`fork`, `exec` and pipes come with steps 5b to 5e; `ash` reports `can't
fork` for a command outside BusyBox. `times()` gives no CPU time. relibc,
built for size (level `s`, one codegen unit, LTO), adds about 157 KB of
`.text` to BusyBox (246 KB against 89 KB on Picolibc); `ci` bounds it at
256 KiB. Five copies of `printf` and relibc's own copy of `core` make most
of it (#150).
