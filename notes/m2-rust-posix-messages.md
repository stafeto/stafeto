# Rust POSIX file value messages

## Result

The private file owner no longer receives an executor address or a pointer
into the caller's stack. All current file, metadata and directory entry
points send explicit methods through posix-request, licensed GPL-3.0-or-later.
The protocol encodes arguments and replies independently of Rust/C layout.
Local file scopes share the same operation handlers; numeric results bypass
IPC serialization to preserve the original fixed-stack budget.
There is no per-request heap allocation, including before heap startup and
while allocation failure is being handled by scandir.

## Ownership and IPC

The client encodes pathname and write bytes before send.
RT copies the non-inline payload into the client's message page; inline data
travels in registers. Kernel delivery copies both parts to the receiver.
The worker immediately copies its received page into a bounded local buffer
before decoding or issuing any nested request to the RAM service.
Decoded borrows refer only to that owned buffer for the duration of execution.
Nested calls cannot overwrite the request's path or write data.
Reply encoding also uses worker-owned storage until kernel reply copies it.
No client job, closure, result slot, application buffer or callback escapes.

Kernel channel cancellation removes a queued sender or marks an accepted
reply token dead before releasing the departed thread's message buffer.
The receiver's copy stays valid after the client goes; a failed reply does
not expose freed client storage. IPC errors now report EIO, and the entire
process no longer terminates to protect a stack job.
No failed request is automatically retried, since it might have taken effect.
This storage model supports future cancellation, but does not implement it.

## Message bounds and validation

Version 1 uses the common eight-byte request header and 21 explicit methods.
Open flags, descriptors, signed offsets, directory identifiers, paths and
write bytes have explicit integer or byte encodings.
The decoder checks version, method, reserved fields, required size, trailing
fields, path bounds, embedded NUL, seek origin and overall message length.
Replies check errno, tags, lengths, node fields and console route extents.
Read length shares a tag word, retaining the full existing MAX_READ payload.
A full write request and a full read reply each fit exactly 1024 bytes.
Rust C write may return one bounded chunk; clients must handle short writes.

Directory stream and entry addresses remain process-local identifiers.
The owner checks registry membership before dereferencing a stream address.
Escaped buffers remain live under the existing application's synchronization
contract. A separate service will need session identifiers and client buffers.
Console routes borrow the transport retained by the process file owner;
blocking input still runs on the calling thread.

## Validation

Five host checks cover all request kinds, explicit little-endian fields,
truncated fixed fields, versions, methods, reserved fields, path bounds,
reply validation and full-size messages. Mutating source bytes after encoding
also verifies payload copying into the encoded request.
The native shared-file probe rejects short, unknown-version, unknown-method,
reserved-field and former address-based messages before heap initialization.
A made-up DIR address returns EBADF without a dereference.
An 81-byte pathname checks received data beyond the inline register payload.
A valid getcwd after errors verifies that the file owner remains usable.

The guest writes 1024 patterned bytes in bounded chunks and reads them back.
Full request and reply messages exercise non-inline delivery and nested RAM
calls; offsets, exact bytes and errno are checked before closing the fd.
The existing descriptor/cwd/DIR and concurrent-offset checks remain in place.
Cargo and standalone C, UART input, Apple VZ input, RAM, Picolibc and ash
checks exercise the same public behavior after replacing the transport.

Deliberately clearing received non-inline bytes fails startup at stage 65.
Deliberately accepting trailing request bytes fails the fixed-field host test.
Both modifications are restored before final checks.
CI also detected stack overflow in the local ABI directory scope of the RAM
probe. Numeric local operations now bypass packet buffers, and large read/write
buffers stay in out-of-line helpers. The unchanged 16-KiB stack passes again.

## Remaining requirements

pthread cancellation points, cleanup handlers, signals, worker health,
recovery and fork/exec inheritance remain required. A future blocking file
backend needs deferred execution. BusyBox retains its compatible MIT bridge;
the new GPL message package is not linked into that binary.

Reference: [POSIX thread cancellation](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html).

Current live IPC interruption and EINTR behavior is recorded in
[m2-rust-posix-interrupt.md](m2-rust-posix-interrupt.md).
