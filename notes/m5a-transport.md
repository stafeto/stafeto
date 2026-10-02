# POSIX step 5a: transport without helper threads

## Result

The Rust POSIX layer runs without helper threads. A single-threaded
program has exactly one thread (the thread probe creates raw kernel
threads up to `LIMIT_REACHED` and counts `MAX_THREADS - 1`). Every
operation runs in the calling thread.

- **Thread block and TCB.** Each thread has a TCB in relibc's layout
  (`TPIDR_EL0` → ABI word → TCB, `os_specific` at +32); the layer's block
  in it holds the signal mask and pending set, cancellation flags, the
  thread's own channel and timer, and its node of a wait by address
  (`posix-thread`).
- **Waits by address** (`posix-sync`). A table of 64 buckets by the hash
  of the address. `futex_wake` without waiters and a mutex without a
  rival make no kernel call. A waiter counts itself in the bucket before
  it compares the word and waits in `receive` on its own channel; its
  timer bounds the wait. A signal handler that runs inside a wait first
  takes the thread's node out and leaves it a wake. A spare wake in the
  slot gives a later wait a spurious wakeup, which is allowed.
- **Locks of the layer.** `LayerLock` is a word over the table of waits.
  The locks of the heap, the files, the table of threads and the signal
  actions raise their holder to the process ceiling (main's level + 1)
  for the section; a signal inside a section waits for its end. Signal
  delivery reads the actions without a lock.
- **Heap and files.** The heap lives under its lock; zeroing for
  `calloc` and copying for a moving `realloc` run after the section. The
  process's files and directory streams live under the files' lock;
  console reads and writes leave the section.
- **pthreads.** No owner thread: the table of threads is under its lock,
  stacks and TCBs are made and taken back outside it, `join` waits for the
  kernel's notification of the end on the thread's own exit channel.
  Sleep, `sigwait*` and cancellation work through the thread's channel.
- **Long operations in two steps.** "Start" returns a ready result in one
  round trip; otherwise the service answers WAIT k and the thread sends
  "take k" with a labelled copy of its channel, then waits on that
  channel. A signal without `SA_RESTART` or a cancellation request ends
  the wait with "cancel k", which returns the result if it was ready:
  nothing is lost or done twice. The console's drivers and the test
  service `l` (`rt::service::LongOps`) speak it; `read` of the console
  uses it.
- **Kernel.** An accepted request is answered once: `thread_interrupt` of
  a thread that waits for a reply is `BAD_STATE`, and an entry request
  comes after the reply. Only the exit of a thread takes a wait for a
  reply back. The clock and process services have no reply journals.
- **Cost of rt.** A round trip through rt costs 3,934 instructions on
  512M under `-icount` (5,403 before), against 1,993 for raw calls.

## Known limits

- Requests to the file service run under the files' lock: posix-fs keeps
  a descriptor and its session together. The section lasts until the
  service replies, at worst until `init`'s watchdog restarts a hung
  service. It must split before pipes come.
- No priority inheritance on the layer's locks or on the mutex: the
  holders of the layer's locks run at the ceiling; a mutex waiter at a
  high level waits for a holder below it (rtbench S3).
- An absolute sleep on `CLOCK_REALTIME` does not wake early when the clock
  is set forward, until the clock patch of relibc.
- A thread that ends through `thread_exit` past `pthread_exit` as the last
  application thread does not end the process.
- One CPU: the lock of a bucket yields to its holder; SMP needs another
  step.

## Probes

`cargo xtask posix-threads` (and `-vz`): `tcb.rs`, `futex.rs`,
`blocks.rs`, `heap_lock.rs`, `one_thread.rs`, `long.rs`, `clocks.rs`
(300 clock SETs, each with an entry request while it waits for its
reply, take effect once). `cargo xtask posix-interrupt`: the UART read in
two steps under the host's input. `cargo xtask kernel-test`: the kernel
tests of the reply wait. `cargo xtask rtbench --minutes N`: rtbench 2.
