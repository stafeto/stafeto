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
.equ SVC_YIELD, 0xFF02                  // ktest::el0::SVC_YIELD
.equ SVC_UNKNOWN, 0xFFFF                // no build knows this number
.equ CALL_HANDLE_CLOSE, 1               // abi::Call::HandleClose
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

// Fills every register and lets the test's other thread, in another
// process, run and fill them with its own pattern.
.global el0_pattern_yield
el0_pattern_yield:
    LOAD_PATTERN
    svc     #SVC_YIELD
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

el0_programs_end:
