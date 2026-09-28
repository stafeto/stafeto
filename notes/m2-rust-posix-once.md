# Rust pthread once initialization

## Interface and state

The GPL-3.0-or-later Rust C ABI provides pthread_once, pthread_once_t
and PTHREAD_ONCE_INIT. sys/types.h declares the eight-byte, eight-aligned
control type; pthread.h includes it and declares the routine.
Zero means uninitialized, a live pthread ID identifies the initializer,
and UINT64_MAX means completed. The existing ID allocator never issues
that reserved value. The application retains a static or extern control
and callable initializer throughout the associated calls.

The existing pthread owner serializes claims and parks contenders as IPC
clients. Each managed thread record retains at most one current once wait,
with its control address, nonce and reply token. There is no object registry,
allocation, separate control-count limit or busy wait in the application.
Different controls can initialize independently or nest. A recursive call
on the same control cannot return before its own initializer completes.

## Publication and cancellation

The initializer pushes an internal cleanup node before calling application
code. Normal return removes that node and publishes completion with Release
on the initializing application thread, then sends FINISH to wake waiters.
Every successful consumer loads the control with Acquire, including the
completed fast path. Application writes precede that Release publication.

Cancellation or explicit pthread_exit executes the internal rollback node.
The exiting thread publishes zero with Release before sending RESET.
Waiting callers receive RETRY and submit a new claim with a new nonce.
Exactly one starts the replacement attempt. Nested controls have independent
cleanup nodes. Rollback precedes older, outer application cleanup handlers,
which can call pthread_once again and observe successful initialization.
An inner initializer's own handlers retain the normal LIFO cleanup order.

pthread_once is not a deferred cancellation point. A contender with a pending
request continues waiting, returns after publication, then takes cancellation
at its next actual point. The initializer can call cancellation points.
The wrapper preserves errno; the initializer may change errno normally.
Asynchronous cancellation needs future protection of the claim-to-push and
pop-to-publication/notification regions. Fork recovery also remains work.

## Interrupted requests and lifetime

Claims, FINISH and RESET use the existing cached nonce protocol. A rejected
reply after a committed operation is replayed without repeating its effect.
A live interrupted contender retries its nonce and replaces the old token.
If it retries after publication but before FINISH, the owner removes the old
wait record before returning completion. Otherwise a later wake could
overwrite a cached answer for a different operation of that caller.
The caller keeps the control live throughout retries and pending waits.

## Checks

The C probe boots through Cargo and standalone Clang without Picolibc.
It checks layout, static initialization, repeated completed calls, independent
and nested controls, key and allocation reentry, and errno preservation.
129 independent controls demonstrate the absence of the 128-key limit here.
A self-canceled thread completes an initializer with no cancellation point,
uses the completed path, and only then takes testcancel. Explicit exit from
an initializer leaves a control available for a later successful attempt.

The native Rust probe starts an initializer that blocks before publishing.
Six priority-30 contenders must let the priority-10 initializer run,
enter AwaitingReply and remain there across three real
ThreadInterrupt calls each. One is already pending cancellation and must
return from once before taking it. Initialized ordinary data is checked after
publication. Sideband flags use Relaxed ordering and do not publish the data.

A probe-only gate stops FINISH after Release publication. An interrupted
contender must return through the owner's completed path and leave no
outstanding wait record. The hook is absent from the regular sysroot.
Committed BEGIN, FINISH and RESET replies are also interrupted once.

A canceled nested initializer rolls back both controls. An outer application
handler re-enters once successfully; another waiting thread also completes.
A separate cancellation has no application recovery handler, requiring
RESET itself to wake the contender. Both abandon a live join target, which
main later releases and joins. These checks run in QEMU and Apple VZ.

Five deliberate mutations were rejected: stale wait after completed retry
(stage 64), repeated completed initialization (C 240), early completion
(stage 52), omitted RESET notification (blocked sole contender), and lost
cached claim after interruption (blocked initializer). Sources were restored.

## Remaining requirements

The full mandatory POSIX.1-2024 objective includes mutexes, conditions,
read/write locks, barriers, semaphores, complete thread attributes and
mandatory capacity limits (currently 32 managed threads), ELF TLS,
asynchronous cancellation, signals, process/fork lifecycle, remaining C
interfaces, terminal behavior, shell and utilities. This step provides one
initialization primitive within that larger implementation.
