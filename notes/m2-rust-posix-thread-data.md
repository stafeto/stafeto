# Rust pthread keys and thread-specific destruction

## Interface

The GPL-3.0-or-later Rust C ABI now provides pthread_key_create,
pthread_key_delete, pthread_getspecific and pthread_setspecific.
pthread_key_t is a 64-bit unsigned type declared in sys/types.h and
included by pthread.h. Existing pthread ID and attribute layouts stay fixed.
PTHREAD_KEYS_MAX is 128 and PTHREAD_DESTRUCTOR_ITERATIONS is four.
The initial limits.h declares these limits and their POSIX minimum constants;
the remaining limits and header interfaces still require implementation.
Key operations return pthread error numbers directly and preserve errno.
Invalid keys receive EINVAL; getspecific returns NULL for an invalid key.
Key operations are not deferred cancellation points.

## Ownership

The existing pthread IPC owner serializes process-wide key operations.
Its registry holds 128 optional keys and a checked monotonic generation.
A key encodes that generation and its slot; generation exhaustion returns
EAGAIN without reusing an old identifier. Live capacity exhaustion also
returns EAGAIN and leaves the caller's output unchanged.
No application allocator is needed to create keys or establish bindings.

Each launch record has 128 atomic pointer values in static storage,
adding 32 KiB for all 32 managed application thread records.
Only the owner writes those values. Key creation clears the selected column
across every record, including other live threads. Thread creation resets
its entire row before publishing the new ID. Thread values are not inherited.
Deleting a key frees its registry entry without running a destructor or
freeing any application allocation. New keys never expose deleted bindings.

## Exit

pthread_exit first runs its LIFO cleanup handlers with cancellation disabled.
It then performs up to four destructor passes, still on the exiting thread.
The fast path reads atomic bindings with Acquire and skips empty slots.
For a nonempty slot, the owner checks the current key and its destructor,
clears the value, and returns a snapshot of the value and callback address.
The caller invokes the callback after the IPC operation has returned.
Callbacks can get/set values, create/delete keys and allocate or free memory.
Callback order is unspecified. A callback may repopulate its own binding;
the next pass examines it again. After four passes outstanding bindings
are abandoned, and their allocations remain the application's responsibility.

Completion is published only after both handlers and destructors return.
Native Ended remains necessary before stack reclamation or a successful join.
Main's pthread_exit follows the same path; the last application thread
still determines process lifetime. Returning from C main exits the process.

## Interrupted requests

The private pthread reply is now 24 bytes: status, value, callback address.
All operations retain the existing per-caller nonce and cached-answer rule.
An interruption after creating/deleting a key, setting a binding, or taking
a destructor value replays the same committed result exactly once.
The owner never calls application destructors or holds an application lock.
Destructor code must remain callable while a selected invocation is in flight.

## Verification

The C probe runs through Cargo and standalone Clang linking without Picolibc.
It checks 128 keys, capacity failure, deletion/reuse, new-thread NULL values,
thread isolation, errno preservation and non-cancellation of key operations.
Return, explicit exit and cancellation each execute four rearmed passes.
Callbacks verify NULL before invocation, other bindings, disabled cancellation,
allocation reentry, cleanup-before-destructor order, and key creation/deletion.
A separate case deletes and recreates its own key inside a destructor.
Reused thread records must start empty despite the previous final rearm.

The Rust guest interrupts committed CREATE, GET, SET, TAKE and DELETE replies
using real kernel ThreadInterrupt. A gated destructor blocks while another
thread joins; the join remains pending until the destructor is released.
Another live thread retains a deleted binding while main reuses the key slot;
it must observe NULL for the replacement and no old destructor invocation.
Main's rearmed destructor runs four times before its surviving child's join.
These scenarios run in QEMU and Apple Virtualization.framework.

Four deliberate mutations were rejected: omitted pre-callback clearing
(C exit 235), two destructor passes (235), stale reused-key values (232),
and omitted thread-row reset (236). All mutated sources were restored.

## Remaining work

Thread-specific keys do not complete ELF TLS loading, asynchronous
cancellation, signal inheritance, scheduler attributes or synchronization.
Remaining C interfaces, sysconf limits, shell and utility behavior remain
part of the full mandatory POSIX.1-2024 objective.
