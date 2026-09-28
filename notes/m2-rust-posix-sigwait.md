# Rust POSIX synchronous signal acceptance

## Behavior and ownership

The GPL-3.0-or-later Rust C ABI now exports sigwait through signal.h.
The selected set must be blocked before calling. Acceptance copies its
signal number to the caller without changing the thread mask or invoking
that signal's handler. Ordinary repeated signals coalesce as before;
acceptance removes the selected pending bit and preserves other signals.
Actions, including RESETHAND, remain unchanged by synchronous acceptance.

The posix-signals model validates a set before modifying pending state.
It selects the lowest eligible ordinary bit and works independently of
native readiness. Invalid sets preserve the previous pending state.
The runtime also diagnoses a selected unblocked signal with EINVAL.
NULL input/output pointers return EFAULT. Errors leave output and errno
unchanged; success returns zero with the accepted number written once.

The pthread owner serializes checking an already pending signal and
registering a live wait. The record contains only a copied set, nonce and
reply token. No borrowed application pointer or Rust reference survives
into blocking IPC. No timer or polling loop is used by sigwait itself.
Signal generation offers a signal to its addressed thread's waiter before
native dispatch. Acceptance commits its retained result before replying;
no later fallible native request can roll the consumed bit back.

A retried wait with the same nonce replaces the invalidated reply token.
A ready result remains independent of other handler requests until ACK.
The new operation has its own prepaid result slot so a full dynamic
journal does not prevent acceptance or successful result delivery.

## Cancellation and handlers

sigwait opens the existing deferred cancellation window. Non-cancellation
IPC interruptions retry the same nonce. A cancellation interruption uses
ACK with abandonment to remove the matching wait and retained record
before application cleanup. Managed exit removes remaining registration.
Pending enabled cancellation acts before registration; disabled
cancellation leaves the wait active and the eventual result observable.

An unrelated unblocked signal can run its handler during sigwait.
The outer wait keeps its identity and cancellation window while the
handler opens, reads and closes a RAM file through the shared Rust owner.
After handler return, sigwait keeps waiting for its selected set.
No EINTR escapes from these internal interruption/retry paths.

## Verification

Two new host tests cover atomic selection, coalescing, pending remainder,
unchanged masks/actions, invalid-set failure and acceptance without READY.
Together with ordinary disposition tests, the model contains ten tests.
C and standalone C probes verify pending acceptance, errno preservation,
output preservation on invalid sets/NULL, and no reset or handler call.

The pthread probe runs pending and live waits with bounded parent waits.
Two concurrently waiting threads receive only their own directed signal;
a different blocked signal remains pending without satisfying the wait.
Three live IPC interruptions replace the token without changing identity.
A SIGTERM handler runs real file I/O while the outer signal wait survives.
A committed WAIT reply and its ACK are interrupted and safely retried.

Cancellation tests cover pending enabled cancellation before registration,
disabled pending cancellation through successful acceptance, and live
cancellation of an empty-set wait. Cleanup verifies registration is gone,
output, mask and errno before exit. Join verifies the cancellation result.

The existing pressure worker exhausts handles and dynamic journal storage.
It now accepts coalesced already pending signals, retries committed WAIT
and ACK, then registers a live wait completed by its parent. Masks, handler
count, errno and managed exit remain correct while resources are exhausted.

The C probe exposed missing 64-bit integer constant macros. INT64_C and
UINT64_C now match AArch64 LP64 int64_t/uint64_t; INT64_MAX uses the
compiler's typed bound. C _Generic assertions verify these types.
The rest of stdint.h still needs completion in the full library work.

Targeted QEMU, Apple Virtualization.framework, C ABI and standalone C
checks passed. Ten mutations were caught: kept pending/changed masks on
the host; missing offer/wrong target/early ACK at 396, lost token at 429,
lost abandonment at 446, ignored cancellation at 429, unpaid WAIT at 397,
and missing cancellation finish at 438. Sources were restored.
Full cargo xtask ci passed on 8fe3984: ten signal-model tests, 400 kcore
host tests, 221 init checks, 165/176 kernel checks, BusyBox and shipping
hot-path verification. Normal/VZ kernels remain 154704/171072 bytes.
Thread/C ABI/standalone images are 585728/475136/491520 bytes.
Normal/icount IPC timings remain unchanged from #59; new signal latency
and a fresh global blocking bound were not measured.

## Remaining requirements

Real-time queues, siginfo and sigwaitinfo/sigtimedwait, process-directed
signals, pause/sigsuspend, SA_RESTART, alternate stacks, stop/continue,
nonlocal exits and asynchronous cancellation remain implementation work.
This accepts ordinary thread-directed signals in the experimental sysroot.
Full mandatory POSIX.1-2024 shell and utility support remains the objective.
The kernel is unchanged; signal latency and a fresh global bound are unmeasured.
