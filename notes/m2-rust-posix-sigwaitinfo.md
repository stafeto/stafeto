# Rust POSIX signal information acceptance

## Behavior

The GPL-3.0-or-later Rust sysroot now exports sigwaitinfo and siginfo_t.
It accepts the same ordinary blocked signals as sigwait and returns the
selected signal number. A non-NULL info receives the number and source;
NULL info is permitted. Acceptance preserves masks and dispositions,
including RESETHAND, without invoking the selected signal's handler.

The current generators are pthread_kill and raise. Their documented
implementation-defined cause is SI_THREAD (128). Other fields are
unspecified for this source and initialized to zero. No process ID or
queued value is fabricated. SI_USER, SI_QUEUE and other standard cause
constants are declared for future generators; they are not emitted yet.
The C union sigval has integer and pointer members. Rust stores its
complete eight-byte representation without interpreting a pointer.

sigwaitinfo returns -1 with errno on failure, unlike sigwait's direct
error code. A failed call leaves info unchanged; success preserves errno.
NULL set receives EFAULT and unsupported sets receive EINVAL. The caller
must block selected signals before waiting. Unblocked selections are
diagnosed with EINVAL as in sigwait.

## Retained outcomes

The pthread owner's reply now contains status and seven data words.
Every dynamic and prepaid retained outcome stores the complete response
until ACK. Existing pair requests use its first two data words. Clients
copy all seven words before ACK releases the record. ACK and diagnostic
replies use the same 64-byte envelope, including probe-only raw clients.

Actions now return handler, full signal mask and flags independently.
The old packed 32-bit mask/flags encoding has been removed. The public
signal range remains 1..31 until real-time queues are implemented.
Transport is ready for upper mask bits without exposing incomplete
real-time delivery behavior.

WAIT commits the accepted number and copied signal information together.
Both waiting interfaces reuse its prepaid result, atomic pending/live
registration, retry nonce and abandonment protocol. No client pointer is
retained while blocked. Current ordinary generators have the same cause;
future queued sources must retain their actual source information.

## Interruption and cancellation

Both waits resume after internal IPC interrupts and unrelated caught
signals. sigwaitinfo does not return the optional EINTR in this runtime.
Handlers can perform signal-safe file I/O while the original wait lives.
Committed response and ACK interruption never accept a second instance.

Deferred cancellation removes registration and retained outcome before
user cleanup. Pending enabled cancellation acts before registration;
disabled cancellation can observe successful acceptance before being
enabled again. Exit also removes registration. The kernel is unchanged.

## Verification

A host transport test verifies upper mask bits independent of flags.
Another checks signed information fields, full address/value bits and
the current source. The signal/type packages contain 11 and 3 tests.
C assertions verify size, alignment and member offsets of siginfo_t and
union sigval, and the distinct cause. C probes check failure errno,
unchanged output, nullable info, coalescing and untouched dispositions.

The guest runs all seven wait scenarios for each interface: already
pending, two directed waiters, unrelated handler, committed response,
pending cancellation, disabled cancellation and live cancellation.
Cleanup checks information bytes as well as mask, errno and registration.
A probe-only dynamic result checks all seven retained words, including
upper bits, through response and ACK interruption.
The resource-pressure worker now uses sigwaitinfo for pending and live
acceptance with exhausted handles and dynamic journal storage.

Targeted QEMU, Apple Virtualization.framework and C ABI probes passed.
Clippy passed for host models and guest library/probe. Eight mutations
were caught: mask/value truncation on the host; lost cache/cause at 397,
last reply word at 449, early ACK at 396, cancellation finish at 438,
and missing error errno at C exit 168. All sources were restored.
Full cargo xtask ci passed on d957ed0: 400 kcore host tests, 221 init
checks and 165/176 kernel checks. Normal/VZ kernels remain 154704/171072
bytes. Thread/C ABI/standalone images are 626688/512000/532480 bytes.
Normal and icount IPC timings remain unchanged from #60. Signal latency
and a fresh global blocking bound were not measured.

## Remaining work

Queued real-time signals and source records, sigqueue with real process
identity/routing, SA_SIGINFO handlers and interrupted context,
sigtimedwait, pause/sigsuspend, SA_RESTART, alternate stacks,
stop/continue, signaled process status and asynchronous cancellation
remain implementation work. Complete mandatory POSIX.1-2024 shell and
utility support remains the objective; this is one verified library step.
