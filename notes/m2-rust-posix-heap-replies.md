# Rust POSIX retained heap replies

History: the heap worker and its reply journal are gone: the heap lives under a lock of the layer (notes/m5a-transport.md). This note records the earlier design.

## Problem and result

Allocation transport previously converted every interrupted send to ENOMEM.
A committed malloc could lose its address; blindly retrying realloc or free
could mutate the same object twice. Requests now carry a checked process-wide
nonce. The owner retains the original arguments and completed status/address.
A retry returns that outcome; changed arguments return EINVAL without effects.
The client copies both words before an allocation-free, idempotent ACK.
Interrupted operations and acknowledgements retry their original packet.

A growing private journal reserves metadata before malloc/calloc/realloc(NULL).
Reservation failure precedes the application heap operation. A successful
allocation prepays one live-block record. ACK clears its operation identity
while keeping the record associated with the live application address.
Realloc and free reuse that record and acquire no new journal storage.
A failed realloc retains the original live address and bytes. Success updates
the tracked address. Free mutates application storage once, keeping its result
until ACK releases the now-empty metadata record.

This prevents free from depending on new allocation when memory or handles
are exhausted. Another allocation can reuse the physical address before the
old FREE is acknowledged; its new live record remains independent. Replaying
the old nonce returns its old outcome without touching the replacement object.
Only acknowledged live records can start a new operation on their pointer.
Ordinary C pointer ownership and no-overlapping-access contracts still apply.
All implementation and probes remain Rust under GPL-3.0-or-later.

## Storage and ownership

The sole IPC worker owns both allocators and never binds a native handler.
Metadata uses independent writable 64 KiB mappings in 0x30000000..0x38000000,
separate from the application heap, file/thread journals and message buffers.
It calls kernel mapping functions directly and never application malloc.
A retained process capability keeps every mapping available before pthread
initialization. Warm chunks remain until process exit; released nodes reuse
the allocator's storage. Each live application block pays extra metadata.
Lookup is linear; no bounded allocator latency or new fixed nesting limit
is established. Complete process exit releases both sets of mappings.

## Real native verification

A managed worker performs malloc/calloc/realloc/free with native delivery
requested after each owner commit. The first handler enables a second entry
after its own allocation. Handlers allocate distinct objects, preserving the
interrupted object's ownership. The inner ACK is interrupted after release.
Eight handlers preserve errno, depth, original calloc zeroes and realloc data.
Moving realloc changes the address. The FREE handler keeps a new allocation
at the original freed address; replay must preserve its metadata and bytes.
Each completed round restores warmed metadata and application usage.

One thousand live one-byte blocks grow the metadata beyond one chunk.
Reverse frees release all records. Two thousand subsequent allocations/frees
reuse warmed metadata and application mappings. Opaque function calls and
volatile payload accesses prevent test allocations being removed or reordered
around injected failures or warm-up measurements.

New-record rejection leaves heap usage, posix_memalign output and errno
unchanged. Shrinking realloc and free still use their paid record. A huge
failed realloc preserves its original block, bytes and eventual release.
Actual handle exhaustion prevents either allocator growing; small allocations
fill remaining storage and every paid free must still succeed without growth.

Direct retained packets check exact replay, changed-body rejection, ACK of
an older record while a newer result remains ready, and repeated ACK.
A new block reuses the freed address, then the old FREE is retried before ACK;
application and metadata usage must remain unchanged until the real release.
Existing C ABI, standalone C, cancellation, file and thread probes remain.
The test makes no declaration that malloc/realloc are POSIX async-signal-safe.

## Validation and continuation

Targeted QEMU and Apple VZ cases, Clippy and license checks passed.
Six mutations were caught: lost replay, early release, wrong ACK and missing
metadata deallocation at stage 322; unpaid free and lost failed-realloc address
at stage 330. Sources were restored. C ABI, standalone C and QEMU/VZ passed.
Full cargo xtask ci passed on 1025760: BusyBox, image size, shipping hot paths,
221 init checks and 165/176 kernel checks. Kernel images remain 154704 bytes
(normal) and 171072 bytes (Apple VZ). Thread/C ABI/standalone boot images are
528384/442368/454656 bytes. No allocator latency or new kernel bound was measured.
Kernel behavior is unchanged. Nonlocal exits from interrupted allocation,
asynchronous cancellation and remaining exclusive library borrows require
further work with signal actions, masks, queues and restart policy.
Full mandatory POSIX.1-2024 shell and utility conformance remains the goal.
