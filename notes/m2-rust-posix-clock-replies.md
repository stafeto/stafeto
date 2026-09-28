# Rust POSIX retained clock replies

## Problem and result

The clock service retained only its most recent observation. A handler could
consume another observation after an outer call had reset interval history,
replacing the outer snapshot before its interrupted transport retried.
SET also used a fixed 64-entry retention table. Both operations now share a
session-label/nonce journal that reserves storage before their effects.

Each accepted SET retains its requested date and result. Repeating the same
body returns that result without changing the global anchor or generation.
A changed body or reuse by a different operation returns INVALID.
Each accepted OBSERVE retains its complete anchor and interval maximum.
Replaying it neither resets the current interval nor loses its original peak.
ACK releases only the matching session/nonce, tolerates repetition and needs
no allocation. Closing a session releases all of its abandoned results.

The client copies an observation before acknowledging it and retries an
interrupted ACK internally. SET acknowledges terminal error results as well
as success. The previous unused Settings table and its protocol capacity
constant are removed; service integration checks replace its two host tests.
The remaining twelve calendar, deadline and sleep host tests are unchanged.
All implementation and new probes remain Rust under GPL-3.0-or-later.
MIT clock protocol v2 documents retention until ACK or disconnect.
The version changes because OBSERVE now requires explicit acknowledgement.

## Memory and ownership

The service owns a posix_heap allocator and its process capability. Journal
storage grows through writable 64 KiB mappings in 0x28000000..0x30000000.
Only the service loop traverses or changes linked nodes; no node reference
escapes it. Each reservation completes before clock mutation or history reset.
No handler runs on the service, and ordinary application malloc is independent.
ACK and disconnect return nodes to the allocator. Warm chunks remain until
service exit. Normal mapping, handle, address-space and memory limits remain.
No fixed number of retained operations or nesting levels is introduced.
WATCH replacement preserves both interval history and retained observations.
A dead notification channel cannot make a retained snapshot inaccessible.
GET and ANCHOR continue to return fresh, side-effect-free snapshots.

## Verification

A managed worker binds the real native trampoline. The service requests entry
only after committing OBSERVE. Its first handler enables a second entry after
another observation. Each handler changes the date: the three peaks differ.
Both interrupted ancestors must return their original snapshots. The inner
ACK is interrupted after removal, exercising its idempotent retry.
The same two-level sequence interrupts SET. Exactly three settings advance the
generation; retrying either ancestor preserves the deepest handler's date.
Handler counts, depth and saved errno are checked.

The guest keeps 80 settings and 700 observations unacknowledged. Their storage
must grow past one chunk. Reverse replay returns exact anchors and peaks;
reverse and repeated ACKs preserve neighboring records. Changed operation
kinds and zero nonces are rejected. WATCH replacement cannot lose snapshots.
Two thousand normal observations reuse warm storage without resource growth.
Handle-table storage is warmed before the exhaustion baseline: its kernel pool
retains pages when freed, as documented by kernel::object::Chunks.

A session-specific reservation rejection checks that failed SET/OBSERVE leave
calendar generation and the previously recorded interval maximum unchanged.
The service also fills its actual kernel handle table. Observations fill all
remaining journal space until growing a mapping fails. SET then fails before
mutation; ACK still works, and a freed node supports another observation.
The probe checks warmed storage, handle and memory baselines afterwards.
One hundred new sessions leave SET/OBSERVE replies unacknowledged and close;
all service resource baselines must recover. Another session's ACK cannot
release those replies even when it supplies the same nonce.
The large snapshot array resides in static probe storage; placing it on the
initial stack caused a test fault and has been corrected.

## Validation and remaining work

QEMU, Apple VZ and twelve host time tests passed during implementation.
Eight mutations were caught: session eviction and neighbor removal at 300,
early release at 142, no deallocation exhausting journal storage with FULL,
no disconnect reclamation at 311, late SET/OBSERVE reservation at 307,
and requiring a live watch for retained replay at 303. Sources were restored.
Restored C ABI, standalone C, QEMU/VZ, Clippy and license checks passed.
Full cargo xtask ci passed on 32af6cb: BusyBox, image size, shipping hot paths,
221 init checks and 165/176 kernel checks. Shipping Clippy also passed after
fixing the session argument that is used only with diagnostic features.
Kernel images remain 154704 bytes (normal) and 171072 bytes (Apple VZ).
Thread/C ABI/standalone boot images are 516096/438272/454656 bytes.
No journal latency or new kernel non-preemption bound was measured.
Kernel behavior is unchanged. Library allocation reentry, nonlocal exits,
POSIX signal actions/masks/queues and restart policy remain separate work.
This milestone does not claim full POSIX.1-2024 shell or utility conformance.
