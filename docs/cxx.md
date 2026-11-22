# C++ on stafeto

Programs written in C++ run on relibc with the C++ standard library and runtime
of the LLVM project: libc++, libc++abi and libunwind, version 23.1.6
(Apache-2.0 WITH LLVM-exception OR MIT OR NCSA, the dual licence of
LLVM's libc++; `packages/libcxx.toml`). They are linked
statically into the program. The libraries are built by `cargo xtask libcxx`
(`tools/build-libcxx.py`) against the relibc sysroot and live in
`target/libcxx/`: the headers in `include/c++/v1` and the archives
`lib/libc++.a`, `lib/libc++abi.a` and `lib/libunwind.a`. The build fetches the
release archive once (SHA-256 pinned in the package record), unpacks only
libcxx, libcxxabi, libunwind and the header library of LLVM libc that
`std::from_chars` needs, applies one patch to libunwind and compiles the files
one at a time with clang. CMake is no part of the build.

## What a C++ program links

A program is a Rust start crate (`posix_crt::crt_main`, as the C programs) with
the C++ file compiled by its `build.rs`; `tests/cxx-probe` is the model.

```
clang++ --target=aarch64-linux-gnu -nostdinc -nostdinc++ -fno-pic -std=c++23 \
  -fexceptions -frtti -fasynchronous-unwind-tables -mllvm -enable-machine-outliner=never \
  -isystem target/libcxx/include/c++/v1 -isystem target/relibc/sysroot/include -c prog.cpp
link: prog.o, libc++.a, libc++abi.a, libunwind.a, libc.a (in this order)
```

The unwind tables of the program must stay (`-fasynchronous-unwind-tables`, no
machine outlining) and the link must keep the program header `PT_GNU_EH_FRAME`
(the default): libunwind finds the unwind rows of a static program through
`dl_iterate_phdr`, which relibc answers from `AT_PHDR`. `cargo xtask cxx-probe`
refuses a program without that header.

## What `cargo xtask cxx-probe` checks

One program, one line per check, compared by xtask in order (weight 20 in
`cargo xtask ci`):

- exceptions through five frames with their destructors, through a C frame
  (the comparison function of relibc's `qsort_r` throws), by base class,
  rethrown, `exception_ptr`, nested exceptions, `bad_alloc` from `new`, an
  exception handed from a thread through a promise, and one thrown by a signal
  handler and caught after `raise`;
- `std::terminate`: the handler of the program runs for an uncaught exception,
  and the default one aborts (SIGABRT);
- `dynamic_cast` up, across, down and to `void*`, `bad_cast`, `typeid`;
- `std::thread`, `std::mutex`, `std::condition_variable` with a deadline,
  `std::async`, `thread_local` objects with destructors (each ends with its
  thread, the main thread's before the static objects at exit);
- `std::atomic::wait` with `notify_one`, `std::latch`, `std::barrier` and
  `std::counting_semaphore` with timeouts: libc++ calls
  `syscall(SYS_futex, ...)`, and relibc's `syscall` answers `FUTEX_WAIT` and
  `FUTEX_WAKE` (private or not) with the layer's waits by address;
- iostreams (`cout`, `cerr`, string streams), the "C" locale and its facets, a
  facet of the program's own, `std::to_string`, `std::stod`, `std::from_chars`
  and `std::to_chars`, a named locale that does not exist (an exception);
- static constructors before `main`, and the order of destruction at exit:
  the atexit functions and the destructors of static objects share one list
  and run newest first.

## Decisions and limits

- Character classes: relibc does not define `__GLIBC__`, so libc++ takes its
  own table of character classes (`_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE` in
  the site configuration).
- Locales: `newlocale` and `uselocale` of relibc carry libc++'s locale
  support; `strtod_l`, `strtof_l` and `strtold_l` of relibc ignore the locale,
  until `strtod` honours `LC_NUMERIC` (the conversions are those of the "C"
  locale). `setlocale` and `newlocale` resolve the name "" by `LC_ALL`, then
  `LC_<category>`, then `LANG`, with "C" when none is set. A name from the
  environment of the form `*.UTF-8` or `*.utf8` with no locale file takes the
  data of C.UTF-8 under its own name (the one encoding is UTF-8); a name the
  program gives, and any other name with no file, fails, so that
  `std::locale(name)` throws `std::runtime_error`. A name with a slash fails in a set-ID program.
- Waits by address use only the two operations above; requeue, bit sets and
  priority inheritance of `futex` answer ENOSYS.
- libunwind: its check of the Linux signal-return trampoline is off for
  `__stafeto__` (it reads memory through a raw `rt_sigprocmask` call and
  decodes the trampoline of Linux).
- `pthread_cancel` ends a C++ thread without running the destructors of its
  frames and without a `catch (...)` block seeing it (no forced unwinding). A
  thread cancelled inside `condition_variable::wait` dies holding the mutex,
  so later waiters on that mutex block for good. `pthread_exit` called from
  C++ code behaves the same: the frames are left without their destructors.
  The cleanup handlers of `pthread_cleanup_push` run first, then the
  thread-local objects of C++, then the keys' destructors.
- A throw from a signal handler works for a synchronous `raise` (or `kill` of
  the thread itself) into a plain `sa_handler` installed with no `SA_ONSTACK`.
  The handler's signal mask stays blocked after the throw, as on Linux (the
  catching code unblocks it). A handler installed with `SA_SIGINFO`, an
  asynchronous signal and a fault signal that throws call `std::terminate`.
- `__dso_handle` in `libc.a` suits static programs only: a shared object needs
  its own, which a loader of several libraries would provide.
- The flag `FUTEX_CLOCK_REALTIME` of `futex` answers ENOSYS: the timeout of a
  wait is relative and runs on the monotonic clock.
- Not built: the time zone database (`std::chrono::tzdb`), the experimental
  library and the parallel backends of `<execution>` (serial only). A shared
  libc++ waits for a loader that handles several libraries.
- `fork` of a process with other threads leaves the child with the calling
  thread alone, as POSIX has it; a `std::mutex` that another thread held stays
  locked in the child. In that child the initialisation of a function-local
  static, `std::call_once` and a throw (which takes the lock of the unwinder's
  registry) may deadlock when another thread of the parent was inside one of
  them at the fork. The lists of `atexit` functions and the allocator are
  safe: `fork` holds their locks across the fork.
