# Pending signal queues for Rust POSIX

## Behavior

The GPL-3.0-or-later posix-signal-queue package supplies prepaid storage
for one process's pending signals. The owner selects its capacity;
the planned runtime pool is 128 occurrences shared by all threads.
There is no allocation, native syscall, callback or internal lock.
Authentication, process lookup and disposition policy belong to the owner.

Each entry holds a full SigInfo, a Process or Thread destination and an
opaque acceptance ticket. Process occurrences remain shared until a
specific eligible thread accepts one. Thread occurrences remain private.
Pending-set queries combine process and caller-directed entries with
the caller's blocked set, without consuming or assigning a signal.

Queue mode preserves every occurrence, including ordinary signal values
under SA_SIGINFO. Coalesce mode keeps the earliest source and ticket for
the same signal and destination. It still succeeds when storage is full.
Physical slot reuse never changes FIFO ordering for equal signal numbers.
The lowest eligible number is chosen first, including realtime candidates
32 through 64. Bit 63 represents signal 64 without shifting by 64.

## Acceptance and lifetime

Peek copies a candidate without changing state. The runtime must reserve
its retained reply before accept, then store the accepted full snapshot
before replying. Failure to reserve leaves the original signal pending.
Replaying a saved result must not invoke accept again.

Tickets include the owner's native PID and a monotonic serial. Reusing
a slot cannot revive a consumed ticket, and a ticket from another PID
cannot consume an occurrence. The pool is initialized once and retained
for its process lifetime. Native PIDs never repeat within one boot.
The final serial u64::MAX is valid; later insertions fail without wrap.
Existing entries remain selectable, acceptable and coalescible afterward.

Changing a disposition to ignore removes every occurrence of that number.
A dying thread removes only its directed entries. Process occurrences
and other threads' occurrences survive. Invalid arguments and full storage
are rejected before changing the queue. Selection and removal are O(N),
bounded by the prepaid capacity; a global latency bound is not claimed.

## Source and permission rules

SigInfo::queued copies the authenticated sender PID, real UID and full
64-bit C sigval representation, marks SI_QUEUE and initializes other
fields. Stored addresses and values are never dereferenced.
The credential model now checks the kill/sigqueue UID rule: effective
root or a sender real/effective UID matching a target real/saved UID.
A target's effective UID and a sender's saved UID do not grant access.
The routing owner must also validate lifetime and implement the same-session
SIGCONT permission exception when sessions exist.

## Verification

Thirteen queue tests cover all signal bits, FIFO under recycled slots,
numeric priority, per-thread/process eligibility, every information field,
a shared 128-slot limit, coalescing, ignore/exit cleanup, stale and foreign
PID tickets, final serial/exhaustion and paid acceptance snapshots.
One credential permission test covers all four permitted ID matches,
effective-target/saved-sender rejection and root privilege distinctions.
Existing credential and type tests remain in the targeted host run.
Host and AArch64 Clippy and the GPL/dependency checker passed.

Twelve deliberate mutations were detected: age before signal priority,
coalescing by physical slot, dropped queued occurrences, leaked thread
scope, cross-PID acceptance, wrapped serials, incorrect exit cleanup,
reused acceptance, wrong usage accounting, missing signal 64, lost sender
UID and permission granted by the target effective UID.
All mutation sources were restored before final verification.

## Integration still required

This implements the pending-storage mechanism for the planned owner.
The current C ABI continues to expose ordinary signals 1 through 31;
sigqueue and cross-process signal generation still require implementation.
Next, replace owner's pending storage and retain the queue snapshots across
reply/ACK interruption, timed acceptance and cancellation. Then register
an authenticated process delivery endpoint and add routing, permission
checks and retained sending outcomes through the shared process service.
Delivery must avoid synchronous IPC cycles between the two owners.
Stop/continue, sessions, alternate stacks, restart policy and the remaining
mandatory POSIX.1-2024 interfaces remain work. Rust POSIX stays GPL.
