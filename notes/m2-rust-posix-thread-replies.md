# Rust POSIX retained pthread replies

## Problem and result

The pthread owner previously kept one cached reply per caller. A native handler
could issue another owner request after an original operation had committed.
Its reply replaced the original, so retrying CREATE could create another thread
and a committed JOIN could lose its value. The owner now retains independent
results identified by the managed caller ID and checked process-wide nonce.

A pending journal record is reserved before any operation changes state.
Completion stores status/value/extra in that record, including asynchronous
join, once, mutex and sleep completion. Retrying a ready operation returns its
stored value. Pending retries keep the existing record and replace the rejected
wait token through the existing waiting protocols. No handler runs on the owner.

Clients copy all three reply words before REPLY_ACK. That private operation
removes only the caller/nonce pair, allocates no record, and tolerates repetition
after removal. Its interruption retries internally. A new nested request never
replaces an ancestor result, and no fixed per-thread reply depth is introduced.
All new implementation and probes remain Rust under GPL-3.0-or-later.

## Interrupted waits and managed exit

Sleep BEGIN and cancellation of JOIN can return before a terminal result.
Their acknowledgement carries an abandonment flag. The owner removes only
the matching pending sleep or join claim before releasing its journal record.
This prevents later asynchronous completion from updating freed storage.
The existing C boundaries still perform their idempotent ABANDON cleanup before
returning EINTR or acting on pending cancellation. Other operations retry their
original nonce until receiving a terminal reply, then acknowledge it.

EXIT clears waiting sleep/once/mutex state and claims owned by the exiting
caller. Once the kernel confirms native completion, reap releases every journal
record left by that caller. Other callers' pending joins remain retained.
The existing join result/target lifecycle acknowledgements remain separate.

## Storage and diagnostic gates

The journal uses posix_heap::Allocator with private 64 KiB kernel mappings
in 0x28000000..0x30000000. This is separate from the file journal, malloc,
thread message pages and stacks. threads::init already requires the initialized
allocation owner, whose process capability remains open for these mappings.
Warm storage is retained until process exit; released node storage is reused.
Each entry pre-reserves cleanup/key-query reply slots; occupied slots fall back
to dynamic storage. The sole owner uses a static registry (entry frame 1312 bytes)
and retains its 64 KiB stack without large stack initialization temporaries.
Reservation failure precedes effects, returning EAGAIN for CREATE and ENOMEM
for other operations. Acknowledgement can proceed with no free handle/memory.

The test owner-pause request now parks after its matching REPLY_ACK reply.
Parking after the initial reply would prevent the client from acknowledging it.
Caller/nonce captures keep a previous reply from using the next probe's gate.
Existing deadline, cancellation, priority and memory-baseline probes are retained.

## Real native verification

A normal 64 KiB managed worker binds the native trampoline and starts CREATE.
The owner requests entry after committing its result but before replying.
The first handler enables a second entry after its own diagnostic owner query
commits. Each query returns the same native identity. The inner acknowledgement
is interrupted after removal while both ancestor results remain retained.
The original CREATE must invoke exactly one child callback. The same nesting
then interrupts the original JOIN, which must return its child's exact value.
Handler count, errno, acknowledgement interruption count and resource baselines
are checked. These private diagnostic queries test transport reentry; they do
not declare pthread_create/join asynchronous-signal-safe.
The key-query case forces nested fallback from a reserved slot. A handler changes
the value; all interrupted GET calls must retain their earlier snapshots.

Two thousand acknowledged queries must reuse the warmed journal mapping.
One thousand managed workers intentionally leave a reply unacknowledged;
joining them must restore handle and memory baselines, proving exit reclamation.
Another worker holds completed replies until exhausted handles prevent journal
growth. Failed CREATE preserves its output and callback count; failed key
creation preserves its output and the number of remaining key slots. Key
creation needs no new kernel handle, so this checks reservation before effects.
Releasing held replies still succeeds while the resource table is full.
A worker with a full journal must run its destructor and complete managed exit;
joining it must reclaim all records, handles and warmed memory.

Restored-source QEMU/Apple VZ, C ABI, native input cancellation, Clippy and
license checks passed. Seven mutations were caught: eviction/neighbor ACK (281),
early release (1), missing free (87), missing reap (285), overwritten recovery
(296), and absent recovery slots (destructor ENOMEM). Full CI is pending.

## Remaining full POSIX work

There is still one waiting once/mutex/sleep operation per managed thread.
General signal policy must respect asynchronous-signal-safe interfaces and
protect unsafe library regions and exclusive local file borrows. Signal actions,
masks, queues, receiver selection, process delivery, stop/kill, restart policy,
alternate stacks and context-changing returns remain work. Clock owner state
also needs reentry-safe lifetimes. Abrupt native exit without the managed EXIT
protocol requires additional detection and cleanup. Full mandatory POSIX.1-2024,
conforming shell and utilities remain the target. No timing bound is established.
