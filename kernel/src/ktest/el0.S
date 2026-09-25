// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//
// Programs for the kernel tests at EL0 (ktest::el0). They lie in a
// page-aligned section of the kernel image that the kernel never runs: a
// test copies the section into a frame of its process and maps it there. On
// entry x0 holds the test's argument: the address of a register pattern,
// or an address to load from. A program ends with `svc #SVC_DONE`, where
// the kernel judges its registers.

.equ SVC_NOP, 0xFF00                    // ktest::el0::SVC_NOP
.equ SVC_DONE, 0xFF01                   // ktest::el0::SVC_DONE
.equ SVC_UNKNOWN, 0xFFFF                // no build knows this number
.equ CALL_HANDLE_CLOSE, 1               // abi::Call::HandleClose
.equ CALL_THREAD_SET_PRIORITY, 18       // abi::Call::ThreadSetPriority
.equ CALL_YIELD, 19                     // abi::Call::Yield
.equ CALL_OBJECT_INFO, 27               // abi::Call::ObjectInfo
.equ CALL_DEBUG_WRITE, 28               // abi::Call::DebugWrite
.equ P_SP, 248                          // offsets in ktest::el0::Pattern; x0-x30 come first
.equ P_NZCV, 256
.equ P_TPIDR, 264
.equ P_FPCR, 272
.equ P_FPSR, 280
.equ P_V, 288

.arch_extension fp
.arch_extension simd

// Loads every register from the pattern at x0: v0-v31, FPCR, FPSR, SP,
// TPIDR_EL0, the flags, then x0-x30. x30 holds the pattern's address until
// the last load replaces it.
.macro LOAD_PATTERN
    mov     x30, x0
    ldp     q0, q1, [x30, #(P_V + 32 * 0)]
    ldp     q2, q3, [x30, #(P_V + 32 * 1)]
    ldp     q4, q5, [x30, #(P_V + 32 * 2)]
    ldp     q6, q7, [x30, #(P_V + 32 * 3)]
    ldp     q8, q9, [x30, #(P_V + 32 * 4)]
    ldp     q10, q11, [x30, #(P_V + 32 * 5)]
    ldp     q12, q13, [x30, #(P_V + 32 * 6)]
    ldp     q14, q15, [x30, #(P_V + 32 * 7)]
    ldp     q16, q17, [x30, #(P_V + 32 * 8)]
    ldp     q18, q19, [x30, #(P_V + 32 * 9)]
    ldp     q20, q21, [x30, #(P_V + 32 * 10)]
    ldp     q22, q23, [x30, #(P_V + 32 * 11)]
    ldp     q24, q25, [x30, #(P_V + 32 * 12)]
    ldp     q26, q27, [x30, #(P_V + 32 * 13)]
    ldp     q28, q29, [x30, #(P_V + 32 * 14)]
    ldp     q30, q31, [x30, #(P_V + 32 * 15)]
    ldr     x0, [x30, #P_FPCR]
    msr     fpcr, x0
    ldr     x0, [x30, #P_FPSR]
    msr     fpsr, x0
    ldr     x0, [x30, #P_SP]
    mov     sp, x0
    ldr     x0, [x30, #P_TPIDR]
    msr     tpidr_el0, x0
    ldr     x0, [x30, #P_NZCV]
    msr     nzcv, x0
    ldp     x0, x1, [x30, #(8 * 0)]
    ldp     x2, x3, [x30, #(8 * 2)]
    ldp     x4, x5, [x30, #(8 * 4)]
    ldp     x6, x7, [x30, #(8 * 6)]
    ldp     x8, x9, [x30, #(8 * 8)]
    ldp     x10, x11, [x30, #(8 * 10)]
    ldp     x12, x13, [x30, #(8 * 12)]
    ldp     x14, x15, [x30, #(8 * 14)]
    ldp     x16, x17, [x30, #(8 * 16)]
    ldp     x18, x19, [x30, #(8 * 18)]
    ldp     x20, x21, [x30, #(8 * 20)]
    ldp     x22, x23, [x30, #(8 * 22)]
    ldp     x24, x25, [x30, #(8 * 24)]
    ldp     x26, x27, [x30, #(8 * 26)]
    ldp     x28, x29, [x30, #(8 * 28)]
    ldr     x30, [x30, #(8 * 30)]
.endm

.section .rodata.el0_programs, "a"
.balign 4096
.global el0_programs, el0_programs_end
el0_programs:

// Reads the virtual counter and its frequency, as EL0 may (CNTKCTL_EL1).
.global el0_read_counter
el0_read_counter:
    mrs     x0, cntvct_el0
    mrs     x1, cntfrq_el0
    svc     #SVC_DONE

// Fills every register, makes a system call that changes x0 alone.
.global el0_pattern_nop
el0_pattern_nop:
    LOAD_PATTERN
    svc     #SVC_NOP
    svc     #SVC_DONE

// The same with a number no build knows: x0 gets INVALID_ARGS.
.global el0_pattern_unknown
el0_pattern_unknown:
    LOAD_PATTERN
    svc     #SVC_UNKNOWN
    svc     #SVC_DONE

// Fills every register and waits in a loop for the timer's interrupt;
// the kernel moves the thread past the loop once it has come.
.global el0_pattern_loop, el0_wait_loop
el0_pattern_loop:
    LOAD_PATTERN
el0_wait_loop:
    b       el0_wait_loop
    svc     #SVC_DONE

// Fills every register and yields to the test's other thread, a FIFO
// thread at the same level, which fills them with its own pattern.
.global el0_pattern_yield
el0_pattern_yield:
    LOAD_PATTERN
    svc     #CALL_YIELD
    svc     #SVC_DONE

// Loads from the kernel address in x0, which must fault.
.global el0_load
el0_load:
    ldr     x1, [x0]
    svc     #SVC_DONE

// Ends at once: the kernel checks the FP and SIMD registers a new thread
// finds, after tests that left their patterns in them.
.global el0_done_at_once
el0_done_at_once:
    svc     #SVC_DONE

// Fill every register from a pattern whose x0-x9 hold a call's arguments,
// make the call and end: the kernel checks what the call wrote.
.global el0_pattern_close
el0_pattern_close:
    LOAD_PATTERN
    svc     #CALL_HANDLE_CLOSE
    svc     #SVC_DONE

.global el0_pattern_object_info
el0_pattern_object_info:
    LOAD_PATTERN
    svc     #CALL_OBJECT_INFO
    svc     #SVC_DONE

.global el0_pattern_debug_write
el0_pattern_debug_write:
    LOAD_PATTERN
    svc     #CALL_DEBUG_WRITE
    svc     #SVC_DONE

// Scheduling tests (ktest::el0). The threads of a test share the words of
// one data page and take their arguments in x0 and up. Counter readings
// follow an ISB, so that they are not taken early.

// Adds 1 to the word at x0 and ends: a mark that the thread ran.
.global el0_mark
el0_mark:
    ldr     x1, [x0]
    add     x1, x1, #1
    str     x1, [x0]
    svc     #SVC_DONE

// Adds 1 to the word at x0 over and over until the word at x1 is set.
.global el0_count_until
el0_count_until:
1:  ldr     x2, [x0]
    add     x2, x2, #1
    str     x2, [x0]
    ldr     x3, [x1]
    cbz     x3, 1b
    svc     #SVC_DONE

// Spins until x1 counter ticks have passed, then yields. Ends with the
// word at x0 read before the yield in x3, after it in x4, and the yield's
// result in x0.
.global el0_spin_then_yield
el0_spin_then_yield:
    mov     x2, x0
    isb
    mrs     x5, cntvct_el0
    add     x5, x5, x1
1:  isb
    mrs     x6, cntvct_el0
    cmp     x6, x5
    b.lo    1b
    ldr     x3, [x2]
    svc     #CALL_YIELD
    ldr     x4, [x2]
    svc     #SVC_DONE

// thread_set_priority(x0 thread, x1 priority, x2 policy), with the word at
// x3 read before the call into x4 and after it into x5.
.global el0_set_priority
el0_set_priority:
    ldr     x4, [x3]
    svc     #CALL_THREAD_SET_PRIORITY
    ldr     x5, [x3]
    svc     #SVC_DONE

// The same once the word at x3, a peer's count, has moved: the peer at
// the same level ran, after this thread's quantum ended, and the call
// comes at the start of the new quantum this thread gets back after the
// peer's. Afterwards sets the word at x6, which lets the peer end.
.global el0_set_priority_after_peer
el0_set_priority_after_peer:
    ldr     x4, [x3]
1:  ldr     x5, [x3]
    cmp     x5, x4
    b.eq    1b
    mov     x4, x5
    svc     #CALL_THREAD_SET_PRIORITY
    ldr     x5, [x3]
    mov     x7, #1
    str     x7, [x6]
    svc     #SVC_DONE

// Round robin next to a peer at the same level. x0: this thread's words
// {count, switches}; x1: the peer's; x2: switches to wait for. Each turn
// of the loop adds 1 to the count, reads the counter, the peer's count
// and the counter again. When the peer's count has moved since the last
// turn, the peer ran in between: a switch. The stretch from the first
// reading of the last turn to the second of this one holds that whole
// run; the shortest such stretch goes to x3, the switches seen to x4
// (stretches after the x2-th switch do not count: a peer that is done
// ends its run early). Ends once both threads have seen x2 switches.
.global el0_alternate
el0_alternate:
    mov     x3, #-1
    mov     x4, #0
    isb
    mrs     x6, cntvct_el0              // first reading of the last turn
    ldr     x5, [x1]                    // the peer's count at the last turn
1:  ldr     x7, [x0]
    add     x7, x7, #1
    str     x7, [x0]
    isb
    mrs     x8, cntvct_el0
    ldr     x9, [x1]
    isb
    mrs     x10, cntvct_el0
    cmp     x9, x5
    b.eq    2f
    mov     x5, x9
    cmp     x4, x2
    b.hs    2f
    add     x4, x4, #1
    str     x4, [x0, #8]
    sub     x11, x10, x6
    cmp     x11, x3
    csel    x3, x11, x3, lo
2:  mov     x6, x8
    cmp     x4, x2
    b.lo    1b
    ldr     x9, [x1, #8]
    cmp     x9, x2
    b.lo    1b
    svc     #SVC_DONE

el0_programs_end:
