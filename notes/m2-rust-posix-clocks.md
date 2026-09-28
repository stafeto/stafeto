# Rust POSIX system clocks

## Interfaces and ownership

The GPL-3.0-or-later Rust ABI adds clock_gettime, clock_getres and clock_settime.
clockid_t is a 32-bit int; timespec retains the existing two signed 64-bit fields.
CLOCK_REALTIME is 0 and CLOCK_MONOTONIC is 1. Other identifiers report EINVAL.
clock_getres accepts a null destination. Successful calls preserve errno;
failed reads preserve the destination. Null required pointers report EFAULT.
Invalid nanoseconds, negative calendar settings and setting MONOTONIC report EINVAL.
A realtime reading beyond signed time_t reports EOVERFLOW.

MONOTONIC reads the common AArch64 virtual counter directly, using the same
nanosecond scale as the kernel's ClockNow and TimerSet. Its origin belongs to
that platform counter. Setting calendar time cannot change it.
Resolution is ceil(1,000,000,000 / CNTFRQ): 16 ns at QEMU's 62.5 MHz,
42 ns at Apple VZ's 24 MHz. It is independent of application priority.

The posix-clock-service package owns one realtime anchor shared by all connected processes.
Its initial value is the Unix epoch at service startup, explicitly unsynchronized.
RTC or time synchronization must supply an actual initial date in a later part.
Connecting to this endpoint grants setting permission under init's capability list.
Separate read/write permissions and user credentials remain future work.
The service uses Restart::Never to avoid silently resetting the date after failure.

## Arithmetic and retries

posix-time holds pure no_std arithmetic, the anchor and per-session retained settings.
Calendar arithmetic uses i128, supporting dates beyond u64 nanoseconds.
Settings round the entire absolute nanosecond value down to a resolution multiple.
Rounding only tv_nsec would be incorrect when one second is not a multiple
of the reported resolution. Invalid settings and generation overflow leave state intact.

proto-clock is an MIT wire format with GET, SET and ACK; no POSIX implementation.
GET returns seconds, nanoseconds, resolution and a setting generation in one snapshot.
SET carries a process-wide non-repeating nonce and the requested timespec.
Each of eight service sessions retains up to 64 unacknowledged successful settings.
A repeated SET with the same payload returns success without changing the anchor
or generation, even if another session has set a newer calendar value in between.
A changed payload under a retained nonce reports EINVAL. A full table reports EAGAIN
before changing the clock. ACK is idempotent; disconnect drops retained records.

posix-clock retries kernel Interrupted for GET, SET and ACK. SET retries keep the
same nonce and payload, followed by an acknowledged release of its retained record.
Clock operations are not deferred cancellation points. There is no application
buffer pointer in the service protocol and no process-local realtime offset.
Startup initializes the immutable process endpoint before creating native threads.

## Verification

Six host tests cover forward/backward settings, monotonic independence, whole-value
rounding, resolution, wide dates, time_t overflow, invalid inputs, generation overflow,
retry retention across sessions, exact retention capacity and acknowledgement reuse.
Cargo-linked C and independently linked Clang probes exercise the public header,
errno, pointer errors, destination preservation, wide dates, overflow and pthread reads.

The native pthread probe runs on QEMU and Apple Virtualization.framework.
A separately loaded clock-peer process forwards readings from its own clock session;
it verifies that another process observes both date and generation.
A test-only service method interrupts a native setter in AwaitingReply after SET
commits, then separately interrupts after ACK removes the retained record.
Both calls succeed and SET advances the generation exactly once.
The normal clock service does not expose this method or accept transferred handles.
Further guest checks replay an older retained SET after another client's newer setting,
reject changed payloads and trailing bytes, and check warmed quota and handle recovery.

Targeted tests, host/guest Clippy, license checks and final cargo xtask ci are recorded
with the ready implementation commit. Intentional mutations exercise lost rounding,
reapplied SET, an incorrect second-process date and failure to retry Interrupted.

## Remaining work

This is the common clock foundation for timed mutexes and other absolute waits.
Clock-step notifications, pthread_mutex_timedlock/clocklock, timers and sleeps remain.
Robust mutexes, process sharing, priority protocols, further synchronization,
credentials, RTC/time synchronization, other mandatory POSIX.1-2024 interfaces,
process/fork lifecycle, shell and utilities remain in the full project objective.
The kernel implementation is unchanged. Clock latency and a fresh global blocking
bound have not been established by this part.
