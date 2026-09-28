# Rust POSIX ordinary signal actions

## Interfaces and ownership

The GPL-3.0-or-later posix-signals model implements ordinary signal sets,
process dispositions and per-thread masks/pending state without allocation.
The C sysroot gains signal.h, sig_atomic_t, sigset_t and struct sigaction.
AArch64 sets occupy eight bytes; actions occupy 24 bytes with eight-byte
alignment. The handler address, mask and flags are owned snapshots.

The Rust C ABI exports set operations, sigaction, signal, pthread_sigmask,
sigprocmask, sigpending, pthread_kill and raise. pthread operations return
error numbers without changing errno; ordinary C errors set errno.
Mask queries ignore how when set is null. Invalid updates leave output and
state unchanged. SIGKILL/SIGSTOP cannot be caught, ignored or blocked.
Unsupported flags are rejected before changing the previous disposition.

The existing pthread owner serializes shared actions and each thread's
mask, pending set and readiness. No owner reference reaches a handler.
Six signal operations have prepaid retained-result slots; copied outcomes
are acknowledged with the existing nonce protocol. Interrupting a committed
reply or ACK neither repeats generation nor loses its result.

The owner runs at the highest priority permitted to its process. Startup
finds that level through channel creation; denied levels allocate no object.
This closes a scheduling gap after reply and before the next receive, when
priority donation no longer covers the owner and a computing FIFO thread
could prevent it from accepting a signal-generation RPC. Application FIFO
scheduling still governs runnable clients at the same priority.

The owner also reaps after receiving a request, before reserving its result.
A thread may end while the owner is blocked in receive. Its old retained
records must then be reclaimed before another client's JOIN, including
when all handles and dynamic journal storage are exhausted.

## Delivery

Every managed thread binds the native dispatcher before its user callback
and publishes readiness. Earlier generation survives until publication.
CREATE inherits a stable caller mask under a short native mask; pending
signals are not inherited. Nested TLS scopes retain managed identity.
Ordinary duplicates coalesce. Ignored dispositions discard all pending
instances and subsequent ignored generation does not interrupt IPC.

The dispatcher snapshots a disposition and installs sa_mask plus the
signal itself before calling user code. SA_NODEFER permits self nesting;
SA_RESETHAND resets before callback, except for SIGILL/SIGTRAP.
It restores the original mask even if the handler changes its mask and
restores errno. Each short signal-owner transaction is natively masked;
user callbacks execute outside owner transactions and can reenter the ABI.

## Tests and failures detected

Eight host tests cover signal boundaries, atomic validation, mask changes,
unblockable signals, coalescing, inherited empty pending state, ignored
signals, handler masks, NODEFER, RESETHAND and readiness publication.
C probes verify layout, errno rules, copied output on errors, set helpers,
self delivery before unblocking returns and unsupported-action rejection.

Guest cases check process-shared actions, self delivery, actual CPU and IPC
entry, nested/deferred handlers, reset visibility, inherited masks,
ignored pending signals, nested errno-only TLS and handler mask changes.
Handlers open/read/close a real RAM file through the shared Rust owner.
The pressure worker exhausts handles and retained journal storage, then
changes actions, blocks and raises twice, queries pending state and unblocks
for one delivery, with committed-reply/ACK interruption and managed exit.
Wait tests now distinguish registered mutex/sleep waits from earlier setup
RPCs, including cancellation requests. Their deadlines remain bounded.

Targeted QEMU, Apple Virtualization.framework and Clippy checks passed.
Nine mutations were caught: missing automatic mask, ignored NODEFER and
missing reset fail host tests; missing inheritance fails at 388, ignored
pending cleanup at 393, errno/mask restoration at 383. An unpaid MASK slot
panics on ENOMEM during pressure; owner priority 1 times out after entering
the CPU-delivery case. Every mutated source was restored.
Full cargo xtask ci passed on 863c798: eight signal-model tests, 400 kcore
host tests, 221 init checks, 165/176 kernel checks, BusyBox and shipping
hot-path validation. Normal/VZ kernels remain 154704/171072 bytes.
Thread/C ABI/standalone boot images are 577536/462848/483328 bytes.
Normal ticks remain 237/296/361/842/1761; icount IPC remains
245/467/1936/2125/3034/4209. Signal latency and a new global bound are unmeasured.

## Remaining standard requirements

Process-directed routing, real-time queues, siginfo, signal waiting,
SA_RESTART, alternate stacks, stop/continue, nonlocal exits and asynchronous
cancellation still require implementation. SIGCONT returns ENOSYS; default
stop actions also return ENOSYS. Default termination currently uses ordinary
process exit 128+signal, without a signaled wait status. Local RAM effects
and late discarded native wakeups still need explicit accounting/restart
policy. Full mandatory POSIX.1-2024 shell and utility support remains the goal.
No kernel implementation or global blocking-bound measurement changes here.
