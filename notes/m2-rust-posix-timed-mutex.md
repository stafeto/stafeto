# Rust POSIX absolute mutex waits

## Interfaces and representation

The GPL-3.0-or-later C ABI adds pthread_mutex_timedlock and pthread_mutex_clocklock.
Timedlock uses CLOCK_REALTIME; clocklock accepts REALTIME or MONOTONIC.
Each call retains an absolute signed timespec across Interrupted. Invalid clocks
report EINVAL. Invalid nanoseconds report EINVAL only when acquisition would block.
An available mutex or immediate recursive relock succeeds even with an invalid
or expired timestamp. ERRORCHECK self-lock retains EDEADLK. Errors do not set errno.
Expiry reports ETIMEDOUT without granting or releasing ownership.
These functions are not deferred cancellation points; pending cancellation survives.

One deadline is stored in each existing waiter, alongside its nonce and reply token.
A retry replaces just that token, retaining the active deadline and its history.
Removing and registering the wait again could forget a clock crossing during retry.
Timeout removes the waiting record before caching and replying with its result.
A granted wait likewise disappears before replying; cached success remains success
when the deadline passes before an interrupted client receives ownership.
The previous effective-priority/nonce selection and Release/Acquire publication remain.

## Calendar observation

The MIT clock protocol adds WATCH, ANCHOR and OBSERVE. WATCH transfers only a
notification channel; one observer per session is replaced safely by repeated WATCH.
Disconnect closes it. Each genuine setting notifies observers. Replayed SET does not
create another setting or notification. ANCHOR returns a consistent calendar anchor,
its monotonic origin, resolution and generation, even after current time_t overflows.

An OBSERVE consumer obtains that anchor and a wide interval peak. The service records
calendar values before and after each SET, preserving a brief forward crossing even
when time returns backwards before the consumer runs. Sampling starts a new interval
at the current date. One exclusive observer consumer belongs to each subscribed session.
Its last nonce and full result remain cached until the next observation; Interrupted
cannot discard a consumed peak. The 60-byte result carries the peak in two u64 words.

The pthread owner flushes existing intervals before registering a new calendar wait,
so earlier crossings cannot expire a later wait. A retry retains its existing interval.
Calendar deadlines expire against the peak and schedule against the latest anchor.
Monotonic deadlines use the common counter, independent of calendar history.
Wide i128 arithmetic keeps dates beyond u64 nanoseconds from wrapping into early expiry.
Unrepresentable future monotonic instants wait without an early saturated timer;
calendar notifications can make their wake instant representable later.

## Wake scheduling

The process owner subscribes during startup. Its notification slot uses main's base
priority so clock changes can wake it without a new application RPC.
The existing single timer serves the earliest mutex deadline and the existing 1 ms
exit/cancellation polling. Later requests cannot postpone an already scheduled poll.
New earlier deadlines move the timer; backward steps move calendar wakes later.
Timer deliveries are hints to recheck the original clock, including stale deliveries.
Unlock checks expirations before handing ownership to the next eligible waiter.
A failed clock observation ends calendar waits with EIO; kernel code is unchanged.

## Verification

Ten host tests cover clock arithmetic, retention, wide anchors, signed deadlines,
forward/backward steps, interval peaks and reset boundaries.
C probes through Cargo and standalone Clang cover both interfaces, errno, immediate
acquisition, malformed/expired timestamps, recursive counts and ERRORCHECK.
Native QEMU and Apple VZ probes cover actual waits and three external interruptions,
interrupted timeout/grant results, an earlier deadline added later, both calendar steps,
monotonic independence, deferred pending cancellation and ordinary protected writes.
They also check a deadline at time_t::MAX and one beyond u64 monotonic nanoseconds.

Test gates park the actual owner outside its channel while time crosses and returns.
The consuming OBSERVE reply is interrupted after commitment; its saved peak must remain.
A separate gate parks it between accepting a retry and updating the original wait.
These checks detect lost interval history and resetting a live wait on retry.
Later registrations must not inherit earlier peaks. Warmed quota and handles recover.
Test gates and native-handle interruption methods are absent from the regular sysroot.

Intentional mutations exercise lost peaks, the wrong timer choice, missing notification,
a discarded observation result and restarting a wait on retry. Validation and image
sizes are recorded on the ready implementation commit before the documentation commit.
The notification check drains prior notices and observes the owner's receiving state
through the kernel. An application RPC here would wake it and hide a missing notice.

## Remaining work

Robust owner death and consistency, process sharing, priority protocols, conditions,
other synchronization, timer/sleep APIs, credentials, RTC/time synchronization,
remaining mandatory POSIX.1-2024 interfaces, process/fork lifecycle, shell and utilities
remain in the full project objective. No new clock/mutex latency or global blocking
bound has been established by these functional checks.
