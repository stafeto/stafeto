# Rust POSIX console cancellation recovery

## Result

UART protocol version 1 gains ReadCancelable (5) and CancelRead (6).
Legacy Read (2), its layout and the reserved Trace number (4) stay intact.
The Rust console transport assigns a nonzero process-wide u64 read ID.
Atomic allocation is monotonic; overflow refuses a new read before sending.
Cancellation matches both session label and read ID, preserving console
ownership, another pending request, and buffered input.
Repeated cancellation has the same successful acknowledgement.
Rust POSIX packages remain GPL-3.0-or-later; shared RT/protocol code is MIT.

## Request and acknowledgement

ReadCancelable carries the max u32, reserved zero u32 and request ID u64.
CancelRead carries its request ID u64 and receives a status-only reply.
Codecs check exact lengths, reserved bytes, bounds and nonzero IDs.
The driver removes only the matching deferred read before acknowledging.
A live matching client receives Interrupted; an abandoned token is harmless.

After an interrupted read RPC the transport sends CancelRead before returning
Interrupted to the C ABI as EINTR. Cancellation is idempotent, so an interrupted
acknowledgement is retried. PeerClosed means the endpoint closed, finishing
cleanup; other cleanup failures are returned explicitly.
A successful acknowledgement must be exactly the eight-byte status reply.
No automatic replay of the original read occurs.

## Data delivery

UART takes bytes out of its bounded RX ring to prepare a read reply.
Both the immediate and deferred paths now check whether delivery succeeded.
A rejected reply restores those bytes to the front of the ring in order.
The single driver thread has handled no other request or IRQ in between.
At most RX_RING (256) bytes are restored; no allocation is needed.
Error counters retain their original hardware-event count.
Console ownership remains with the same session after cancellation.

The transport copies the complete delivered input before attempting echo.
Echo interruption or failure preserves the successful byte count and input.
This avoids returning EINTR after consuming bytes that cannot be reread.
Terminal attributes and moving echo into the terminal service remain work.

## Host validation

One protocol test checks the new method numbers, exact little-endian fixtures,
truncated fields, trailing bytes, reserved fields, zero IDs and max bounds.
UART model tests check wrong session, stale ID, zero ID, repeated cancellation,
owner preservation, buffered bytes and a newer pending request's lifetime.
A second model test restores a failed read across the ring boundary and
checks exact ordering of restored and remaining bytes on the next read.
The protocol package has seven tests; the UART library has twenty-three.

## Guest validation

cargo xtask posix-interrupt runs the UART recovery dialog in QEMU.
cargo xtask posix-interrupt-vz repeats read recovery and echo interruption on
Apple Virtualization.framework with native Virtio console input.
The first read starts without input and is observed blocked.
On UART its interrupted client stays Ready at priority 10 while main stays 29.
UART runs at 60: host input arrives before the client can issue CancelRead.
The driver rejects its old token, and main obtains the restored bytes through
the same console session. The original client then completes cleanup.

A second read of the same client is interrupted while no input arrives.
Its third read must be observed waiting before the host sends fresh bytes.
This detects a missing CancelRead handler even when an IRQ could retire an
old token. The same thread, descriptor and UART session read the new bytes.
Buffers remain unchanged on EINTR, and successful retry retains errno.
Native timer/channel counts return to their pre-read total after each wait.
The main thread retains its own errno and continues ordinary RAM file I/O.

A live tagged UART reader is cancelled directly; it receives Interrupted
while the cancelling thread receives a successful acknowledgement.
A controlled UART endpoint delivers bytes, then holds their echo reply.
Interrupting echo must return the delivered count and exact normalized bytes.
The native probe uses this endpoint too; it does not depend on UART hardware.

## Deliberate mutations

Skipping service-side cancellation fails the guest before retry input.
Skipping driver rollback prevents the restored-input stage from completing.
Propagating the interrupted echo error fails guest stage 95.
Returning PeerClosed to a live cancelled reader fails guest stage 97.
Only the relevant interruption image runs for each mutation.
Sources are restored before the final tests and full CI.

## Remaining requirements

pthread cancellation state/type, pending cancellation, cleanup handlers,
join and signal delivery remain required. Accepted file operations and writes
need their own result/side-effect cleanup; they are not automatically replayed.
Driver restart and POSIX session reconnection remain separate requirements.
Full POSIX.1-2024 and shell/utilities conformance remain the project target.

Reference: [POSIX read and interruption](https://pubs.opengroup.org/onlinepubs/9799919799/functions/read.html).
