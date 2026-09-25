// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//
// Exception vectors: 16 entries of 0x80 bytes in a 2 KiB aligned table.
// Entries from EL1 save a full trap frame on the kernel stack, add a frame
// record that links the interrupted code into backtraces and call
// handle_exception(frame, index); they first check that the frame fits on
// the kernel stack and otherwise switch to the emergency stack. Entries
// from AArch64 EL0 save the program's registers straight into the running
// thread (spec 8.1) and call handle_user_exception(index), which returns
// to EL0 through return_to_user. AArch32 EL0 never runs; its entries take
// the kernel's path to a report.

.equ FRAME_SIZE, 304                    // x0-x30, sp_el0, elr_el1, spsr_el1, sp, padding, frame record
.equ FRAME_SP, 272                      // offset of the interrupted SP in the trap frame
.equ FRAME_RECORD, 288                  // offset of the frame record in the trap frame
.equ KERNEL_STACK_SHIFT, 16             // kcore::layout::KERNEL_STACK_SHIFT
.global vectors_stack_shift             // kernel.ld checks it against the boot stack
.set vectors_stack_shift, KERNEL_STACK_SHIFT
.equ EMERGENCY_BIT, 4                   // set in the vector index after a switch to the emergency stack
.equ EMERGENCY_STACK_SIZE, 8192         // kernel.ld places it right below the guard page
.equ USER_SP, 248                       // offsets in arch::user::UserRegs; x0-x30 come first
.equ USER_ELR, 256
.equ USER_SPSR, 264
.equ USER_TPIDR, 272                    // TPIDR_EL0, then TPIDRRO_EL0

.macro VECTOR index
    .org    exception_vectors + \index * 0x80   // fails to assemble if a slot overflows
    sub     sp, sp, #FRAME_SIZE
    stp     x0, x1, [sp]
    mov     x0, #\index
    b       exception_common
.endm

// Entry from EL1 on the kernel stack. Kernel stacks are aligned to twice
// their size, so bit KERNEL_STACK_SHIFT of the SP is set once the frame
// would reach below the stack (kcore::layout::frame_fits). The test needs a
// register: x0 and the SP swap through arithmetic, and nothing is lost.
// Without room the entry stashes the SP and x0 in the EL0 thread registers
// (the running thread's values are saved in its register area, and an
// overflow stops the kernel, so nothing returns to EL0) and builds the
// frame at the top of the emergency stack. The emergency stack lies in the
// same 64 KiB below the boot stack, so an exception taken on it starts over
// at its top and the emergency stack cannot overflow; handle_exception
// stops the machine on such a second entry.
.macro KERNEL_VECTOR index
    .org    exception_vectors + \index * 0x80
    sub     sp, sp, #FRAME_SIZE
    add     sp, sp, x0                  // sp' = sp + x0
    sub     x0, sp, x0                  // x0' = sp' - x0 = sp
    tbnz    x0, #KERNEL_STACK_SHIFT, 1f
    sub     x0, sp, x0                  // x0 = sp' - sp, the interrupted x0
    sub     sp, sp, x0                  // sp = sp' - x0, the frame
    stp     x0, x1, [sp]
    mov     x0, #\index
    b       exception_common
1:  msr     tpidr_el0, x0               // interrupted SP - FRAME_SIZE
    sub     x0, sp, x0
    msr     tpidrro_el0, x0             // interrupted x0
    adrp    x0, emergency_stack_top
    add     x0, x0, :lo12:emergency_stack_top
    mov     sp, x0
    sub     sp, sp, #FRAME_SIZE
    mrs     x0, tpidrro_el0
    stp     x0, x1, [sp]
    mov     x0, #(\index + (1 << EMERGENCY_BIT))
    b       exception_common
.endm

// Entry from EL0. SP_EL1 is the top of the kernel stack: return_to_user
// leaves it there, so the stack is empty on every entry (spec 8.1). The
// registers go straight into the running thread's area, which TPIDR_EL1
// points at; x0 and x1 wait on the stack meanwhile, because the entry
// needs two registers to work with.
.macro USER_VECTOR index
    .org    exception_vectors + \index * 0x80
    stp     x0, x1, [sp, #-16]!
    mrs     x0, tpidr_el1
    stp     x2, x3, [x0, #(8 * 2)]
    ldp     x2, x3, [sp], #16
    stp     x2, x3, [x0]
    mov     x1, #\index
    b       user_exception
.endm

.section .text.vectors, "ax"
.balign 0x800
.global exception_vectors
exception_vectors:
    VECTOR 0                            // current EL, SP_EL0: sync
    VECTOR 1                            //   irq
    VECTOR 2                            //   fiq
    VECTOR 3                            //   serror
    KERNEL_VECTOR 4                     // current EL, SP_EL1: sync
    KERNEL_VECTOR 5                     //   irq
    KERNEL_VECTOR 6                     //   fiq
    KERNEL_VECTOR 7                     //   serror
    USER_VECTOR 8                       // lower EL, AArch64: sync
    USER_VECTOR 9                       //   irq
    USER_VECTOR 10                      //   fiq
    USER_VECTOR 11                      //   serror
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
    // The interrupted SP: right above this frame or, after a switch to the
    // emergency stack, what the vector stashed in TPIDR_EL0.
    add     x25, sp, #FRAME_SIZE
    tbz     x0, #EMERGENCY_BIT, 1f
    mrs     x25, tpidr_el0
    add     x25, x25, #FRAME_SIZE
1:  str     x25, [sp, #FRAME_SP]
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

// x0 = the running thread's register area, x1 = vector index; x0-x3 are
// saved already.
user_exception:
    stp     x4, x5, [x0, #(8 * 4)]
    stp     x6, x7, [x0, #(8 * 6)]
    stp     x8, x9, [x0, #(8 * 8)]
    stp     x10, x11, [x0, #(8 * 10)]
    stp     x12, x13, [x0, #(8 * 12)]
    stp     x14, x15, [x0, #(8 * 14)]
    stp     x16, x17, [x0, #(8 * 16)]
    stp     x18, x19, [x0, #(8 * 18)]
    stp     x20, x21, [x0, #(8 * 20)]
    stp     x22, x23, [x0, #(8 * 22)]
    stp     x24, x25, [x0, #(8 * 24)]
    stp     x26, x27, [x0, #(8 * 26)]
    stp     x28, x29, [x0, #(8 * 28)]
    mrs     x2, sp_el0
    stp     x30, x2, [x0, #(8 * 30)]    // x30, then SP_EL0 at USER_SP
    mrs     x2, elr_el1
    mrs     x3, spsr_el1
    stp     x2, x3, [x0, #USER_ELR]
    mrs     x2, tpidr_el0
    mrs     x3, tpidrro_el0
    stp     x2, x3, [x0, #USER_TPIDR]
    mov     x29, xzr                    // backtraces end at the entry from EL0
    mov     x0, x1
    bl      handle_user_exception
    udf     #0                          // not reached: the handler returns to EL0 itself

// return_to_user(regs x0): leaves the kernel for EL0 with the registers at
// x0, which become the running thread's (TPIDR_EL1). SP_EL1 goes back to
// the top of the kernel stack for the next entry. CLREX drops an exclusive
// reservation, so that one thread's cannot let another's store-exclusive
// succeed.
.global return_to_user
return_to_user:
    msr     tpidr_el1, x0
    adrp    x1, boot_stack_top
    add     x1, x1, :lo12:boot_stack_top
    mov     sp, x1
    ldp     x1, x2, [x0, #USER_SP]      // SP_EL0, ELR
    msr     sp_el0, x1
    msr     elr_el1, x2
    ldr     x1, [x0, #USER_SPSR]
    msr     spsr_el1, x1
    ldp     x1, x2, [x0, #USER_TPIDR]   // TPIDR_EL0, TPIDRRO_EL0
    msr     tpidr_el0, x1
    msr     tpidrro_el0, x2
    clrex
    ldp     x2, x3, [x0, #(8 * 2)]
    ldp     x4, x5, [x0, #(8 * 4)]
    ldp     x6, x7, [x0, #(8 * 6)]
    ldp     x8, x9, [x0, #(8 * 8)]
    ldp     x10, x11, [x0, #(8 * 10)]
    ldp     x12, x13, [x0, #(8 * 12)]
    ldp     x14, x15, [x0, #(8 * 14)]
    ldp     x16, x17, [x0, #(8 * 16)]
    ldp     x18, x19, [x0, #(8 * 18)]
    ldp     x20, x21, [x0, #(8 * 20)]
    ldp     x22, x23, [x0, #(8 * 22)]
    ldp     x24, x25, [x0, #(8 * 24)]
    ldp     x26, x27, [x0, #(8 * 26)]
    ldp     x28, x29, [x0, #(8 * 28)]
    ldr     x30, [x0, #(8 * 30)]
    ldp     x0, x1, [x0]
    eret

// The stack for exception entries that find no room on the kernel stack.
.section .emergency_stack, "aw", %nobits
.balign 4096
.global emergency_stack, emergency_stack_top
emergency_stack:        .skip EMERGENCY_STACK_SIZE
emergency_stack_top:
