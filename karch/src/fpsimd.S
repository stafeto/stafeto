// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//
// fp_save(regs x0) and fp_load(regs x0): a program's FP and SIMD
// registers, v0-v31, then FPCR and FPSR (arch::user::FpRegs). The kernel
// is built without FP, so these registers always hold the state of the
// thread that ran last, and only a switch between threads saves and loads
// them (spec 8).

.equ FP_FPCR, 512                       // offsets in arch::user::FpRegs
.equ FP_FPSR, 520

.arch_extension fp
.arch_extension simd

.section .text.fpsimd, "ax"
.global fp_save
fp_save:
    stp     q0, q1, [x0, #(32 * 0)]
    stp     q2, q3, [x0, #(32 * 1)]
    stp     q4, q5, [x0, #(32 * 2)]
    stp     q6, q7, [x0, #(32 * 3)]
    stp     q8, q9, [x0, #(32 * 4)]
    stp     q10, q11, [x0, #(32 * 5)]
    stp     q12, q13, [x0, #(32 * 6)]
    stp     q14, q15, [x0, #(32 * 7)]
    stp     q16, q17, [x0, #(32 * 8)]
    stp     q18, q19, [x0, #(32 * 9)]
    stp     q20, q21, [x0, #(32 * 10)]
    stp     q22, q23, [x0, #(32 * 11)]
    stp     q24, q25, [x0, #(32 * 12)]
    stp     q26, q27, [x0, #(32 * 13)]
    stp     q28, q29, [x0, #(32 * 14)]
    stp     q30, q31, [x0, #(32 * 15)]
    mrs     x1, fpcr
    mrs     x2, fpsr
    str     x1, [x0, #FP_FPCR]
    str     x2, [x0, #FP_FPSR]
    ret

.global fp_load
fp_load:
    ldp     q0, q1, [x0, #(32 * 0)]
    ldp     q2, q3, [x0, #(32 * 1)]
    ldp     q4, q5, [x0, #(32 * 2)]
    ldp     q6, q7, [x0, #(32 * 3)]
    ldp     q8, q9, [x0, #(32 * 4)]
    ldp     q10, q11, [x0, #(32 * 5)]
    ldp     q12, q13, [x0, #(32 * 6)]
    ldp     q14, q15, [x0, #(32 * 7)]
    ldp     q16, q17, [x0, #(32 * 8)]
    ldp     q18, q19, [x0, #(32 * 9)]
    ldp     q20, q21, [x0, #(32 * 10)]
    ldp     q22, q23, [x0, #(32 * 11)]
    ldp     q24, q25, [x0, #(32 * 12)]
    ldp     q26, q27, [x0, #(32 * 13)]
    ldp     q28, q29, [x0, #(32 * 14)]
    ldp     q30, q31, [x0, #(32 * 15)]
    ldr     x1, [x0, #FP_FPCR]
    ldr     x2, [x0, #FP_FPSR]
    msr     fpcr, x1
    msr     fpsr, x2
    ret
