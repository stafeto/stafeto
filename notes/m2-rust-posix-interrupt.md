# Rust POSIX IPC interruption

## Result

ThreadInterrupt (call 30) wakes a live thread from its current IPC wait.
Its target is a thread handle with MANAGE. Error::Interrupted is code 10.
Stopped, ready, running and ended threads return BadState.
An unsuccessful interruption does not queue a future interrupt.
Long memory calls are outside this mechanism.
The Rust file RPC adapter and console status mapping report EINTR (4).
Rust POSIX packages and headers retain GPL-3.0-or-later.

## Lifetime and cleanup

Queue removal, accepted-token abandonment, error registers and wakeup occur
under the scheduler lock. Only the target's x0 changes on interruption.
The live thread retains its number, message buffer and kernel reference.
Wait references and transit handles are released after the scheduler lock,
using the interrupting caller's effective priority for object cleanup.
There are at most four transit handles; no queue scan or allocation occurs.

A queued send has already consumed its outgoing handles.
Interruption releases those handles, including their RECEIVE rights.
A service owns handles of an accepted request; interruption preserves them.
A reply to an abandoned token returns PeerClosed and consumes reply handles.
Accepting the client's next request increments the count and clears DEAD.
The next token is valid; the older token then returns BadState.
The monotonic count and retirement rules remain unchanged.
The existing termination path still marks accepted requests dead.

Owned file messages remain valid while the caller resumes after interruption.
A queued request is removed before the file owner can execute it.
An accepted operation may already have side effects; it is not retried.
Application read and getcwd buffers remain unchanged on the tested EINTR paths.
Thread-local errno changes only on the interrupted calling thread.
Native console waiting drops its private timer and channel on return.

## Guest validation

cargo xtask posix-interrupt uses the normal kernel and UART service.
cargo xtask posix-interrupt-vz uses Apple Virtualization.framework and Virtio.
The host injects no input, so the console read waits before interruption.
The probe is a feature of the existing native posix-shared-probe package.
The UART variant is included in posix-abi and full CI.
Both probe features receive separate Clippy checks in CI.

The rights/state checks exercise bad handle, wrong type and absent MANAGE.
Stopped, ready, running and ended targets refuse interruption with x0 alone.
A stopped/ready refusal is followed by a real wait, checking no pending flag.
Interrupting receive removes its queue entry; a later notice stays available.
Interrupting a queued sender checks unchanged x1-x9 and consumed handle values.
Closing its last transferred RECEIVE handle is observed as PeerClosed by
another notifier, which detects leaked transit references.
A closed sender session posts CLIENT_GONE after its wait reference is released.
Accepted cancellation preserves a delivered handle, verified by notification.
A late reply similarly closes its transferred RECEIVE handle.
A third request from the same thread gets a valid response and ends normally.

The C ABI getcwd client queues ahead of the low-priority file owner.
Interruption returns EINTR with an untouched pathname buffer.
A successful main-thread getcwd then proves the owner remains usable.
The console client is observed in AwaitingReply (UART) or Receiving (Virtio).
Interruption returns EINTR with an untouched byte buffer.
Native timer/channel handle counts return to their pre-read total.
The main thread keeps its errno and reads a RAM file afterward.
The existing full-payload checks run before the interruption scenarios.

## Deliberate mutations

Retaining DEAD in accept fails the targeted next-token host test.
Discarding transit without reference release fails stage 76 through the notifier.
Mapping interrupted file RPC to EIO fails guest stage 86.
Each mutation runs only the relevant host test or interruption image.
Sources are restored before final validation.

## Remaining requirements

pthread lifecycle, cancellation state/type, pending cancellation, cancellation
points and cleanup handlers remain required, together with signals and join.
Accepted file operations need result cleanup and documented side effects.
UART still needs explicit cancellation of its deferred service-side read;
retrying input before removing that request remains unfinished.
These probes end after file recovery and do not claim UART read recovery.
No implicit cancellation point is introduced into allocation functions.

Reference: [POSIX cancellation](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html).
