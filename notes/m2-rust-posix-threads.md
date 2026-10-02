# Initial Rust pthread lifecycle

## Behavior

The GPL-3.0-or-later Rust C ABI exports pthread_create, pthread_self,
pthread_equal, pthread_exit, pthread_join and pthread_detach through pthread.h.
Each created thread has independent errno and the process's shared files,
directory streams and heap. Callback return is equivalent to pthread_exit.
The creator's FPCR and FPSR are copied before running its callback.
Scheduling policy and base priority are inherited from the creating thread.

pthread functions return error numbers directly and preserve errno.
The runtime diagnoses self-join with EDEADLK, stale IDs with ESRCH,
non-joinable IDs with EINVAL and creation resource exhaustion with EAGAIN.
Error paths leave the caller's thread ID and result pointers unchanged.

## Ownership

One IPC owner manages 32 entries, including main and unjoined ended threads.
Monotonic nonzero IDs prevent a reused entry from accepting its old ID.
The default stack is 64 KiB, with a 4 KiB unmapped guard.
PTHREAD_STACK_MIN is 16 KiB; stack plus rounded guard must fit a 1 MiB reserve.
Attribute initialization, destruction, stack size, guard size and detach state
have C entry points. Changing attributes does not affect existing threads.

Thread stacks occupy separate mappings outside the process heap.
An EXIT request publishes completion but does not free a running stack.
The owner waits for the native Ended state before unmapping and closing.
Detached entries are then released; joinable entries retain the exit value.
Release/Acquire completion publication orders user writes before join returns.

Main can terminate through pthread_exit while other application threads run.
Internal file, heap and thread owners do not keep the process alive after the
last application thread exits. Returning from C main still exits the process.

## Interrupted requests

Requests carry unique nonces. The owner caches each client's latest answer.
A retry after Interrupted returns the cached result without repeating creation,
detachment or acknowledgement. pthread_join never returns EINTR.
One joiner claims a target; its retry replaces the obsolete reply token.
A separate JOIN_ACK releases the target ID after delivery of the exit value.
The result remains owned even when the first reply is rejected by the kernel.

The owner's timer is reserved during startup, before quota exhaustion. Since
[#72](https://github.com/stafeto/stafeto/pull/72) every pthread is made with the owner's channel as its exit channel: the
kernel's notification of its end, once it left the scheduler, makes the owner
take its stack back and wake its joiner, also for a thread that ended past the
library (its value is null). The 1 ms timer only watches main, which init made
with no exit channel, once it said EXIT, and retries a cancellation whose
thread has not begun to wait yet. The owner's channel has no label for the
ends, so each notification makes the owner read THREAD_STATE of every live
or exiting pthread, up to 64 calls at its ceiling. A session and its handle
for each thread would read one thread only.
Initial pthreads inherit main's priority; the timer uses that priority.
Future scheduling interfaces must update this priority arrangement.
Polling waits in the guest probe sleep, so that a FIFO IPC owner is never starved.
This is a functional lifecycle implementation.

## Verification

cargo xtask posix-abi boots the same C checks through Cargo and standalone
Clang linking with the staged Rust libc.a, without Picolibc.
The C checks cover pointer results, explicit exit, nested create/join,
shared file offsets, allocation transfer, independent errno and FP inheritance.
They also cover attributes, detached threads, stale IDs, 64 successive reuse
cycles, the 31-child entry limit and recovery after EAGAIN.

cargo xtask posix-threads checks accepted CREATE, JOIN and JOIN_ACK replies
interrupted after their results were committed. Exactly one child must run,
and its result and errno must survive all three retries.
The test exhausts native handle slots so creation fails after stack mapping;
handle count and memory quota must return to their baseline.
Another 32 create/join cycles verify complete native resource reclamation.
A live joiner is interrupted three times while its target waits on a gate;
it must keep waiting, then return the original result after target release.
Main exits first; the remaining child joins main, uses files and allocation,
and exits. Init must observe process exit code 0; the layer has no helper threads.

cargo xtask posix-threads-vz runs this probe on Apple Virtualization.framework.
The QEMU lifecycle probe is also included in cargo xtask test and ci.
Probe-only native-handle access uses the thread-probe feature of posix-abi;
it is absent from the normal sysroot library. The reply-interruption hooks
went with the reply journals: the kernel answers an accepted request once.

## Remaining standard work

The mandatory POSIX.1-2024 implementation remains the full project target.
General ELF TLS, thread-specific data, cleanup handlers, cancellation,
signal-mask inheritance, user-provided stacks and scheduler attributes remain.
Mutexes, conditions, semaphores and the remaining thread interfaces follow.
This checkpoint does not claim complete POSIX pthread conformance.

## Deliberate failures

Ignoring cached replies fails the committed-reply test at stage 1.
Skipping failed-create unmapping fails handle/quota recovery at stage 4.
Reusing an ID fails the C probe with exit code 207.
Dropping FP inheritance fails the C probe with exit code 204.
All four mutations were restored before the final checks.

Final cargo xtask ci passed on 749b925: init 221 on every guest machine,
kernel 165 normally and 176 under icount. Normal kernel 154704 bytes;
Apple VZ kernel 171072 bytes. The kernel implementation is unchanged.
Implementation: [#43](https://github.com/stafeto/stafeto/pull/43).
