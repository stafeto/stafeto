# Rust POSIX nested cancellation windows

## Problem and result

A native dispatcher can enter a C read/write cancellation boundary while an
interrupted caller already holds an active cancellation window. Previously,
Point::end cleared active to zero. Returning from that nested call therefore
removed the outer wait's generation; a later pthread_cancel could not wake it.

Point now captures the former active generation with one atomic swap while
publishing its own generation. End restores that former value. Finish closes
the same frame before deciding whether to act on a pending cancellation.
The outermost window still ends with active zero. The test-only console-phase
marker is captured and restored alongside the generation, retaining diagnostics
for a caller interrupted during console input.

Frames live on the existing user stack and close in nesting order.
There is no new nesting limit, memory allocation, busy lock or kernel call.
Generation exhaustion keeps the existing explicit failure. The IPC owner still
reads the same active field, and no thread protocol or cancellation policy changes.
All implementation and tests remain Rust under GPL-3.0-or-later.
Native rt/ABI infrastructure retains its existing MIT license.

## Real nested entry probe

A managed worker creates an outer cancellation window and binds the native
upcall trampoline. Its first dispatcher creates another window and explicitly
enables a second native entry on the same thread. Each dispatcher writes one
byte to a shared RAM descriptor, then performs a zero-byte write and an invalid
write. A positive result follows Point::end; zero/error follow Point::finish.
Each return must retain the containing generation and console-phase marker.
The dispatcher saves/restores errno; the worker's value must remain 777.

After both handlers return, the worker blocks in a raw receive inside its
original window. Its parent requests deferred cancellation. A bounded 500 ms
wait must observe cleanup; joining must return PTHREAD_CANCELED. This checks
that the restored outer window actually causes an IPC wake, rather than only
checking its numeric value. The parent validates both bytes through the C ABI,
closes the descriptor, and verifies joined-thread handle and memory recovery.
The parent's own inactive window remains zero.

The handlers start between file requests, so this probe establishes cancellation
window preservation. Retention of an already committed outer IPC outcome needs
its own protocol and tests before general POSIX signal delivery is enabled.

## Verification

QEMU and Apple Virtualization.framework passed the native probe, including
nested handlers, the three write outcomes, cancellation cleanup, bytes and quota.
The guest Clippy and GPL-3.0-or-later/BusyBox dependency checks passed.
Intentional mutations target zeroing the parent generation, dropping its console
marker, and leaving Point::finish without closing its frame. All three were
detected: lost cancellation wake at guest stage 243, and invalid state at stage
244 for the marker and finish mutations. Sources were restored. Full CI and
cargo xtask ci passed on 6d44b62: licenses, formatting, Clippy, host and guest
checks, BusyBox, image limits and shipping hot-path memcpy/memset checks.
Init: 221 per machine; kernel: 165 normally and 176 under icount.
Kernel images remain 154704 bytes normally and 171072 for Apple VZ.
The pthread boot image is 425984 bytes; C ABI/standalone: 385024/405504 bytes.
Normal null/clock/yield/notify/round_trip ticks remain 237/296/361/841/1756;
test IPC ticks remain 245/467/1931/2122/3031/4267. Kernel code is unchanged.

## Remaining full POSIX work

The pthread owner currently retains one reply per caller. A handler's owner
request can replace a committed original result before the original retries.
File calls currently expose transport interruption, without a multi-operation
retention/acknowledgement protocol. Clock setting/observation also need reentry
lifetime checks. Local file scopes must avoid overlapping exclusive Rust borrows.
Allocation and other unsafe library regions need controlled delivery boundaries.

POSIX signal dispositions, masks, queues, receiver selection, process delivery,
SIGKILL/SIGSTOP, alternate stacks, context-changing returns and restart rules
remain work. Pending cancellation inside a handler requires the standard's
async-cancel safety rules, including disabling cancellation when required.
This patch preserves the existing deferred policy; it does not enable signals
or asynchronous cancellation. Full mandatory POSIX.1-2024, shell and utilities
remain the objective. Functional tests establish no worst-case latency bound.
