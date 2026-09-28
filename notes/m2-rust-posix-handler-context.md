# Signal information and interrupted context for Rust POSIX

## Behavior

SA_SIGINFO selects a three-argument C handler: signal number, siginfo_t
and a pointer to ucontext_t. The GPL-3.0-or-later Rust ABI and signal.h
share the handler/sa_sigaction address while preserving sigaction's
24-byte layout. Ordinary one-argument handlers continue to work.

Current pthread_kill/raise sources report SI_THREAD. Their remaining
information fields are deterministically zeroed, as before sigwaitinfo.
TAKE now retains all five information words beside the number, flags
and handler address until ACK. Retries do not take a second signal or
reconstruct an already-committed delivery. A future queued source must
retain its original instance information at generation.

## Context and return

The MIT rt trampoline gains a context-aware macro variant. It passes a
pointer to its actual 816-byte interrupted AArch64 frame. The original
no-argument macro and its native register-preservation checks remain.
Compile-time assertions check the SP, PC, SIMD and FP offsets and size.

The POSIX machine context has 31 general registers, SP, PC, user PSTATE,
32 SIMD vectors, FPCR and FPSR. These are stafeto-specific ABI fields.
The native TLS and IPC address remain private, unchanged return metadata.
mcontext_t is 800 bytes, aligned to 16; ucontext_t is 848 bytes with its
machine context at offset 48. C and Rust check matching layouts.

uc_sigmask contains the mask before this delivery. Valid edits replace
the return mask with unmaskable signals removed. Register, SP, PC, SIMD,
FP and PSTATE edits are copied back into the native return frame. The
kernel validates SP, PC, user flags and the native IPC address before
restoring execution. Invalid return-context edits are undefined.

uc_link is null for a signal frame. uc_stack reports the disabled
alternate signal stack, with null address, zero size and SS_DISABLE.
This does not implement sigaltstack or getcontext/setcontext. Context
objects and information are live only for their handler invocation.

The effective mask is installed before enabling nested native entries.
Each entry gets its own context and information snapshot. SA_RESETHAND
clears SA_SIGINFO before the callback, except for SIGILL and SIGTRAP.
The handler's errno changes do not escape into interrupted application
code. Callbacks may use the existing required signal-safe file calls.

## Verification

The C probe checks handler union storage, structure sizes/alignment and
field offsets. Its three-argument callback checks information, context,
original/effective masks and reset-before-entry; a return-mask edit
persists, while errno remains unchanged. Standalone linking uses the
same sysroot and callback checks.

A worker executes the existing real AArch64 assembly loop with seeded
GPR, SIMD, flags and FP state. Four modes inspect every register and PC/SP;
edit a GPR, PC, SIMD, FP, PSTATE and return mask; enter a nested NODEFER
handler; and observe reset before entry. PC redirection lands in a
separate assembly block with a distinct output marker. Restored TLS,
IPC metadata, original/edited registers and masks are checked after
return. Resources return to baseline after join.

The exhausted-handle/response-storage probe also uses SA_SIGINFO,
coalesced pending delivery, interrupted TAKE and signal-safe file I/O.
Nine mutations were caught: missing information/wrong cause at stage 397;
wrong SP at 456; lost GPR/PC/SIMD edits at 457; lost return mask at C exit
174; reset retaining SIGINFO on the host; missing frame argument by a
guest null-address fault. All altered files were restored afterward.
Targeted C/UART and pthread QEMU checks and Apple VZ passed. Full
cargo xtask ci passed on 9f1db19, including C/standalone, pthreads,
BusyBox, licenses, kcore 402, init 222 and kernel 166/177. Normal/VZ
kernels remain 154708/171076 bytes. Thread/C/standalone images are
634880/516096/532480 bytes. Normal and icount IPC/IRQ timings match
#62. A fresh global blocking bound and handler latency were not measured.

## Remaining requirements

Full mandatory POSIX.1-2024 remains the target. Real-time value queues,
process-directed routing, sender credentials, timed signal acceptance,
alternate stacks, syscall restart, nonlocal handler exit and process
lifecycle still need implementation. BusyBox continues to use its MIT
bridge; the future GPL Rust POSIX service boundary remains necessary.
