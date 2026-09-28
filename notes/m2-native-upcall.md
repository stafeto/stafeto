# Native user entries for POSIX signal delivery

## Kernel boundary

Four generic calls prepare asynchronous user entry on a selected native thread.
ThreadUpcallBind (31) binds the current thread's entry; zero removes it.
ThreadUpcallControl (32) masks (0), enables (1), or takes original PC/PSTATE (2).
Control returns the former mask in x1; TAKE returns PC in x2 and PSTATE in x3.
ThreadUpcallRequest (33) requires a MANAGE target handle.
ThreadUpcallReturn (34) restores the current thread from a fixed reserved area.

A request coalesces into one pending bit. A masked target stays masked.
An enabled IPC waiter is released through the existing Interrupted path.
A ready target keeps its priority; entry occurs before its next EL0 return.
A kernel long-call continuation completes before entry, so dispatcher calls
cannot accidentally enter that continuation. Stopped/ended targets reject requests.
Ordinary threads have no registered entry. No signal policy runs in the kernel.

The small kcore state model is GPL-3.0-or-later, as are kernel and guest tests.
Generic rt entry helpers and ABI definitions retain MIT.
Signal dispositions, masks, queues and C interfaces will stay in GPL Rust POSIX.
The BusyBox dependency boundary and GPL-3.0-or-later checks remain unchanged.

## Context and stack

The rt::upcall_entry! naked trampoline saves 31 GPRs, SP, TLS, 32 SIMD registers,
FPCR/FPSR and 1088 IPC bytes. TAKE retrieves the interrupted PC and full PSTATE.
The dispatcher starts masked and can enable explicit nested entries.
Each stack frame occupies 1904 bytes plus the dispatcher's own stack use.

Before returning, the trampoline masks entry, restores IPC and copies 816 bytes
of saved context into the held message-buffer page, starting at byte 1120.
The kernel reads its retained frame mapping; it never dereferences a user pointer.
The area does not overlap IPC data or handle metadata. Nested frames live on stack;
masking protects the shared scratch area while a completed frame is restored.

Validation checks user PC, aligned PC/SP, unchanged read-only buffer pointer,
and AArch64 user PSTATE: NZCV, TCO, DIT, SSBS and BTYPE. Privilege modes,
interrupt masks and other reserved/privileged bits are rejected before any change.
The entry clears BTYPE for its new control flow; return restores the original.
The field positions follow Arm Trusted Firmware include/arch/aarch64/arch.h.
Feature availability and future architecture extensions remain platform work.
Successful return skips the usual syscall result, retaining the saved x0.
FP hardware is explicitly loaded even when returning to the same native thread.

## Verification

Four host model tests check registration, pending/coalescing, mask/unmask,
long-call deferral, nested PC/PSTATE capture and invalid operations.
They reject privileged return modes, IRQ masks, wrong buffers and bad addresses.
ABI tests pin all four call numbers and the fixed reserved context layout.

The native probe interrupts an assembly loop without cooperative syscall entry.
It seeds all 31 GPRs and 32 vectors and independently records stack, flags and TLS.
The dispatcher changes FP/TLS and fills IPC with other bytes; resumed assembly
checks the original values and IPC. Another mode explicitly nests two entries.
Masked requests coalesce, stay deferred, and run when enabled. A blocked receive
gets Interrupted and resumes after its dispatcher returns. Invalid return frames
reject EL1 mode, masked IRQ, a foreign buffer, misaligned SP and misaligned PC.
Requests without MANAGE and after join fail; warmed handles and quota recover.

The test publishes the native handle before the CPU loop: asking the priority-1
pthread owner during that loop would starve its response behind the worker.
It also drains the startup notification boost before lowering effective priority.
The parent's timed waits then permit the priority-10 worker to run and wake safely.

QEMU and Apple Virtualization.framework probes passed. Intentional mutations
must detect lost pending, widened privilege access, dropped extra PSTATE bits,
omitted FP load, one damaged GPR, missing IPC restore and overwritten x0.
Full CI and final image measurements are recorded after the implementation commit.

## Remaining POSIX work

This generic entry mechanism supplies the context boundary for Rust signals.
It does not implement sigaction, signal masks/queues, thread selection, kill,
SIGKILL/SIGSTOP, process groups, timers or interrupted-call restart policy.
Before enabling handlers in Rust POSIX, audit asynchronous reentry into IPC caches,
returned-buffer lifetimes and cancellation windows; a nested handler must preserve
an interrupted operation's retained outcome and active cancellation state.
Alternate signal stacks and context-changing interfaces also remain required work.
Full mandatory POSIX.1-2024, shell and utilities remain the project objective.
These functional checks establish no physical latency or global blocking bound.
