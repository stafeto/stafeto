// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//
// Exception vectors: 16 entries of 0x80 bytes in a 2 KiB aligned table.
// Every entry saves a full trap frame on the current stack, adds a frame
// record that links the interrupted code into backtraces and calls
// handle_exception(frame, index). Milestone 1.2b moves EL0 entries to
// per-thread register areas.

.equ FRAME_SIZE, 288                    // x0-x30, sp_el0, elr_el1, spsr_el1, frame record
.equ FRAME_RECORD, 272                  // offset of the frame record in the trap frame

.macro VECTOR index
    .org    exception_vectors + \index * 0x80   // fails to assemble if a slot overflows
    sub     sp, sp, #FRAME_SIZE
    stp     x0, x1, [sp]
    mov     x0, #\index
    b       exception_common
.endm

.section .text.vectors, "ax"
.balign 0x800
.global exception_vectors
exception_vectors:
    VECTOR 0                            // current EL, SP_EL0: sync
    VECTOR 1                            //   irq
    VECTOR 2                            //   fiq
    VECTOR 3                            //   serror
    VECTOR 4                            // current EL, SP_EL1: sync
    VECTOR 5                            //   irq
    VECTOR 6                            //   fiq
    VECTOR 7                            //   serror
    VECTOR 8                            // lower EL, AArch64: sync
    VECTOR 9                            //   irq
    VECTOR 10                           //   fiq
    VECTOR 11                           //   serror
    VECTOR 12                           // lower EL, AArch32: sync
    VECTOR 13                           //   irq
    VECTOR 14                           //   fiq
    VECTOR 15                           //   serror

exception_common:
    stp     x2, x3, [sp, #(16 * 1)]
    stp     x4, x5, [sp, #(16 * 2)]
    stp     x6, x7, [sp, #(16 * 3)]
    stp     x8, x9, [sp, #(16 * 4)]
    stp     x10, x11, [sp, #(16 * 5)]
    stp     x12, x13, [sp, #(16 * 6)]
    stp     x14, x15, [sp, #(16 * 7)]
    stp     x16, x17, [sp, #(16 * 8)]
    stp     x18, x19, [sp, #(16 * 9)]
    stp     x20, x21, [sp, #(16 * 10)]
    stp     x22, x23, [sp, #(16 * 11)]
    stp     x24, x25, [sp, #(16 * 12)]
    stp     x26, x27, [sp, #(16 * 13)]
    stp     x28, x29, [sp, #(16 * 14)]
    mrs     x21, sp_el0
    stp     x30, x21, [sp, #(16 * 15)]
    mrs     x22, elr_el1
    mrs     x23, spsr_el1
    stp     x22, x23, [sp, #(16 * 16)]
    // Frame record {interrupted x29, ELR + 4}: the backtrace prints each
    // return address minus 4, so the interrupted instruction itself shows.
    add     x24, x22, #4
    stp     x29, x24, [sp, #FRAME_RECORD]
    add     x29, sp, #FRAME_RECORD
    mov     x1, x0                      // vector index
    mov     x0, sp                      // &mut TrapFrame
    bl      handle_exception
    ldp     x22, x23, [sp, #(16 * 16)]
    msr     elr_el1, x22
    msr     spsr_el1, x23
    ldp     x30, x21, [sp, #(16 * 15)]
    msr     sp_el0, x21
    ldp     x0, x1, [sp, #(16 * 0)]
    ldp     x2, x3, [sp, #(16 * 1)]
    ldp     x4, x5, [sp, #(16 * 2)]
    ldp     x6, x7, [sp, #(16 * 3)]
    ldp     x8, x9, [sp, #(16 * 4)]
    ldp     x10, x11, [sp, #(16 * 5)]
    ldp     x12, x13, [sp, #(16 * 6)]
    ldp     x14, x15, [sp, #(16 * 7)]
    ldp     x16, x17, [sp, #(16 * 8)]
    ldp     x18, x19, [sp, #(16 * 9)]
    ldp     x20, x21, [sp, #(16 * 10)]
    ldp     x22, x23, [sp, #(16 * 11)]
    ldp     x24, x25, [sp, #(16 * 12)]
    ldp     x26, x27, [sp, #(16 * 13)]
    ldp     x28, x29, [sp, #(16 * 14)]
    add     sp, sp, #FRAME_SIZE
    eret
