# Rust POSIX relative and absolute sleep

## Interfaces

The GPL-3.0-or-later C ABI adds nanosleep and clock_nanosleep.
Both accept a signed LP64 timespec and are deferred cancellation points.
Clock_nanosleep supports CLOCK_REALTIME and CLOCK_MONOTONIC, with flags 0
for a relative interval or TIMER_ABSTIME (1) for an absolute instant.
Unknown clocks/flags, negative seconds and malformed nanoseconds return EINVAL.
A null request returns EFAULT. The input is copied before any output is written;
request and remaining may point to the same object.

Nanosleep returns zero or -1 and errno. Clock_nanosleep returns an error number
without changing errno. Success preserves errno and remaining in both interfaces.
An absolute call ignores remaining, including after an interruption.
An interrupted relative call writes the unslept interval if remaining is non-null.
An elapsed interval has a zero remainder. No signals or timers are reserved.

## Clock and owner model

Relative intervals use elapsed monotonic nanoseconds even for CLOCK_REALTIME;
calendar settings cannot shorten or extend a relative interval.
Absolute MONOTONIC uses the common counter. Absolute REALTIME follows the shared
calendar service, including both clock steps and a brief deadline crossing.
The posix-time Sleep model keeps relative endpoints in i128, so the maximum
signed time_t duration plus current uptime cannot saturate into an early wake.
Unrepresentable future u64 instants wait without a saturated timer.

Each existing pthread entry has one sleep record with a deadline, nonce and token.
IPC carries copied values and the invocation's monotonic start, never a pointer.
The existing owner computes one calendar observation for mutex and sleep waits.
Both consume the same retained interval peak before it resets; a second independent
OBSERVE for sleep would discard a brief crossing after mutex processing.
Before a new calendar registration, existing waits finish their previous interval.
One existing timer chooses the earliest sleep/mutex deadline and exit/cancel poll.
No kernel changes or per-call channel/timer allocations are needed.

## Interruption and cancellation

An interrupted sleep request returns EINTR instead of automatically restarting.
It may already have committed, so a subsequent ABANDON removes its record and
retries its own interrupted acknowledgement before returning to the caller.
The relative remainder is calculated after acknowledgement from the original end,
so bookkeeping cannot increase the interval. Remaining is updated before cleanup.

The existing cancellation window handles pending cancellation at entry, live wake
and the gap before IPC. The window stays active until internal operations finish.
Cleanup runs only after the wait record is removed; subsequent operations cannot
leave an old sleep token in the owner. Disabled cancellation stays pending through
successful sleep and runs at a later cancellation point after re-enabling.

Native interruption exercises the EINTR transport path. POSIX signal delivery,
handler dispatch and restart rules remain required work; these tests establish
no complete signal semantics. Timers with event delivery remain another step.

## Verification

Four new host tests, fourteen total for posix-time, cover duration and remainder,
calendar-independent relative clocks, absolute clock choice and retained peaks,
malformed inputs, zero interval and the maximum time_t interval without saturation.
C through Cargo and standalone Clang checks headers, flags, clocks, null, negative
and malformed requests, zero/past success, untouched remaining and errno rules.

Native QEMU and Apple VZ check actual relative and absolute sleeps, calendar steps,
interrupted nanosleep with aliased request/remainder, absolute EINTR without an
output update, shared mutex/sleep history and cancellation before/inside a wait.
A committed ABANDON reply is interrupted to prove cleanup acknowledgement retries.
Disabled pending cancellation preserves successful duration before testcancel.
The cleanup callback confirms owner removal and a normalized relative remainder.
Warmed process handles and memory must recover after joining every child.

Intentional mutations target saturation, incorrect relative clock selection,
automatic restart, unchanged remainder, missing ABANDON, consuming history twice,
and omitting cancellation completion. All seven were detected; restored sources
passed host tests, QEMU, Apple VZ, Clippy and the POSIX license audit.
Full cargo xtask ci passed on ea051b5: licenses, formatting, Clippy, host and guest
tests, BusyBox, image limits and shipping hot-path memcpy/memset checks.
Init checks: 221 per machine; kernel checks: 165, or 176 under icount.
Kernel images remain 150608 bytes normally and 171072 bytes for Apple VZ.
Boot images: C ABI 385024, standalone C and pthreads 405504 bytes each.
Normal null/clock/yield/notify/round_trip ticks remain 257/299/364/846/1763;
IPC probe ticks remain 259/463/1918/2109/3018/4254. No separate HVF series ran.

## Remaining work

Sleep signal delivery, timer creation/event delivery and overrun accounting,
robust/shared mutexes, priority protocols, conditions, other synchronization,
thread attributes, credentials, RTC/synchronization, ELF TLS, fork/processes,
remaining mandatory POSIX.1-2024 interfaces, shell and utilities remain work.
Functional sleep checks establish no latency or global blocking bound.
