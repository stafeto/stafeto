# Rust POSIX blocking input concurrency

## Result

Rust C read now prepares an operation through the process file owner.
RAM reads still execute under that owner, preserving shared offsets.
Console reads validate the descriptor and return a transport snapshot.
The calling thread waits for input and copies successful bytes to the
application buffer; waiting does not hold the file owner's request loop.
Dispatch follows the descriptor's backend, including duplicated stdin
and stdin redirected to a RAM file.
Zero-length reads validate descriptors without waiting or opening wait handles.

## Endpoint lifetime

The snapshot contains a UART handle value or the native-console route,
never a pointer to PosixFs, a worker stack, or an application buffer.
The process file owner retains Files and its UART session until process exit.
Closing or replacing a local descriptor therefore does not invalidate an
already prepared console read. A later call validates the current descriptor.
The general Rust preparation API requires retaining its Files owner until
pending reads complete; snapshots do not themselves retain sessions.
Kernel handle generations protect against referring to a recycled handle.
A stopped driver returns a transport error; reconnection remains pending.

## Native console waiting

A polling reader previously yielded only among its own priority level.
A continuously ready reader could starve lower-priority file and heap owners.
After an empty poll, native input now creates a private channel and timer,
then blocks in receive between polls, at one-millisecond deadlines.
The timer slot has priority 1 and does not raise a client's base priority.
Both temporary handles close when the operation completes or fails.
This is bounded-rate polling, which gives no device-driven wakeup and no hard RT guarantee.

ConsolePoll accepts a consumption limit of 1 through 8 in x1.
Zero preserves the original eight-byte kernel ABI.
Invalid limits above eight are rejected before consuming input.
The driver extracts only the requested bytes, leaving excess input queued.
This prevents small read buffers from discarding the rest of a burst.
UART keeps the existing echo and CR-to-LF behavior; native input stays raw.

## Guest checks

cargo xtask posix-input starts a Rust native program with RAM and UART.
The host sends xyz and Enter only after the file-progress marker.
A higher-priority reader first waits on a duplicate of stdin.
Main verifies zero-length input, EBADF for a non-readable descriptor,
metadata access while input waits, close and descriptor-number reuse,
stdin redirected to a RAM file, and its shared offset.
It also allocates and frees through the lower-priority heap owner.
The outstanding read finishes through the original console despite close.
A retained duplicate reads the remaining burst one byte at a time.
Both threads keep independent errno; cleanup happens after the reader finishes.

cargo xtask posix-input-vz runs the same scenario against the native Virtio
console on an Apple silicon Mac. It also checks the raw CR byte and the
consumption limit, without a UART service or QEMU.
The regular POSIX ABI/CI path includes the portable UART dialog.
Target Clippy includes the input test module.

## Deliberate failures

Reading input inside prepare_read prevents file progress and times out the
UART dialog before the host sends data.
Ignoring the native consumption limit loses burst bytes and prevents the
native completion marker after one-byte reads.
The initial native run, whose waits yielded, also failed before
the file-progress marker; timer-backed waiting resolved that failure.

## Remaining requirements

Private file calls now use [owned value messages](m2-rust-posix-messages.md).
Thread cancellation, signals, terminal discipline, device
notifications, session recovery and fork/exec inheritance remain mandatory work.
This stage covers console waiting; a future blocking file backend must
also defer its request without holding the descriptor owner.
BusyBox continues to use its temporary MIT bridge; the new POSIX code is GPL-3.0-or-later.

Reference: [POSIX read](https://pubs.opengroup.org/onlinepubs/9799919799/functions/read.html).
