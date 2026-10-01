# Timed signal acceptance for Rust POSIX

## Interface

The GPL-3.0-or-later Rust C ABI exports sigtimedwait through signal.h.
It returns the selected signal number or -1 with errno. info may be
null; errors preserve the entire supplied information object. Current
thread-directed sources still report SI_THREAD. The blocked-set rule
and disposition/mask behavior are shared with sigwaitinfo and sigwait.

A pending signal is accepted before checking the interval. Otherwise,
invalid nanoseconds or negative seconds return EINVAL. A zero interval
polls and returns EAGAIN when no selected signal is pending. NULL timeout
selects indefinite waiting, a documented choice where POSIX leaves the
behavior unspecified. Unrelated caught signals resume the original wait
without EINTR. sigwaitinfo delegates to this common indefinite path.

## Lifetime and deadlines

The client copies set/time values and captures one CLOCK_MONOTONIC start.
WAIT carries the set, timed flag, seconds, nanoseconds and original start.
The owner first offers pending acceptance, then builds the existing wide
relative Sleep deadline. Largest signed seconds are valid without wrapping
or truncating the deadline to u64. Calendar clock settings do not affect it.

A retry of the same nonce updates only the reply token and preserves its
original deadline. A different request cannot replace an active wait.
The existing preallocated WAIT recovery slot retains accepted signals,
errors and expiration until ACK. No new system call, owner, timer or
per-wait heap allocation is introduced. Cancellation removes registration
through the existing abandoned ACK before running application cleanup.

The common owner timer selects the earliest mutex, sleep or signal wake.
Every normal deadline pass removes expired registration and retains
EAGAIN. SEND also checks the target's current deadline before generating
its signal, covering expiry between the main deadline pass and generation.
A late signal remains pending after the timeout. A committed timeout
cannot change into signal acceptance when the rejected response retries.
Unrepresentable far-future wakes stay wide; they are never armed early.

## Verification

C and standalone probes check the declaration, malformed/negative and
zero intervals, pending-before-validation, optional info, NULL timeout,
real monotonic expiration, errno and unchanged failure output. The guest
checks the largest valid interval while it is actually registered.

The existing seven signal-wait scenarios now also run through sigtimedwait:
pending/live acceptance, two addressed threads, native token retries,
unrelated handler file I/O, committed reply/ACK interruptions, pending
cancellation, disabled cancellation through acceptance, and empty-set
live cancellation with cleanup. Existing indefinite APIs still run.

Nine additional real-thread modes check timeout and rejected error/ACK,
concurrent sleep/mutex deadlines, fixed deadlines after three IPC interrupts,
handler completion, both calendar steps, live acceptance, a wide future
interval, indefinite NULL timeout, empty-set expiration with another
pending signal, generation held past expiry, and a late signal between
committed expiration and client retry. Native gates and stored-deadline
queries were enabled only in the probes and went with the thread owner. They avoid scheduler
priority assumptions and physical upper-latency assertions.

The exhausted-handle/response-storage path also checks timed live
acceptance and expiration, rejected response/ACK, a second zero poll,
unchanged info and mask. Normal tests check resources after joining.
Targeted C/UART, pthread QEMU and guest Clippy passed. Nine mutations
were caught: validation before pending (C 180), wrong error (C 177),
unarmed wake (396), reset on retry (465), truncated interval (464),
late SEND accepted (474), missing cancellation finish (438), changed
error output (C 168), and early expiration ACK (475). All sources
were restored. Full cargo xtask ci passed on 921bbee: kcore 402, init
222, kernel 166/177, all POSIX/BusyBox probes, licenses and hot paths.
Separate Apple VZ passed with guest exit 0. Normal/VZ kernels remain
154708/171076 bytes; thread/C/standalone images are 647168/524288/540672.
Normal/icount IPC and IRQ paths match #63. A fresh global blocking bound
and signal-owner/handler latency were not measured.

## Remaining work

Full mandatory POSIX.1-2024 remains the goal. Real-time FIFO/value queues,
sender credentials, process-directed routing, alternate stacks, syscall
restart, nonlocal handler exit and process lifecycle remain work. The
Rust implementation stays GPL-3.0-or-later. BusyBox keeps its temporary
MIT bridge until the separate GPL POSIX service and MIT client exist.
