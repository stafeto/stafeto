// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

.section .text.upcall_probe, "ax"
.global native_upcall_register_probe
native_upcall_register_probe:
sub sp, sp, #672
stp x0, x1, [sp, #0]
stp x19, x20, [sp, #16]
stp x21, x22, [sp, #32]
stp x23, x24, [sp, #48]
stp x25, x26, [sp, #64]
stp x27, x28, [sp, #80]
stp x29, x30, [sp, #96]
stp q0, q1, [sp, #128]
stp q2, q3, [sp, #160]
stp q4, q5, [sp, #192]
stp q6, q7, [sp, #224]
stp q8, q9, [sp, #256]
stp q10, q11, [sp, #288]
stp q12, q13, [sp, #320]
stp q14, q15, [sp, #352]
stp q16, q17, [sp, #384]
stp q18, q19, [sp, #416]
stp q20, q21, [sp, #448]
stp q22, q23, [sp, #480]
stp q24, q25, [sp, #512]
stp q26, q27, [sp, #544]
stp q28, q29, [sp, #576]
stp q30, q31, [sp, #608]
mrs x2, fpcr
str x2, [sp, #640]
mrs x2, fpsr
str x2, [sp, #648]
mov x2, sp
str x2, [x0, #816]
mrs x2, tpidr_el0
str x2, [x0, #824]
mrs x2, tpidrro_el0
str x2, [x0, #832]
mov x9, x1
movi v0.16b, #1
movi v1.16b, #2
movi v2.16b, #3
movi v3.16b, #4
movi v4.16b, #5
movi v5.16b, #6
movi v6.16b, #7
movi v7.16b, #8
movi v8.16b, #9
movi v9.16b, #10
movi v10.16b, #11
movi v11.16b, #12
movi v12.16b, #13
movi v13.16b, #14
movi v14.16b, #15
movi v15.16b, #16
movi v16.16b, #17
movi v17.16b, #18
movi v18.16b, #19
movi v19.16b, #20
movi v20.16b, #21
movi v21.16b, #22
movi v22.16b, #23
movi v23.16b, #24
movi v24.16b, #25
movi v25.16b, #26
movi v26.16b, #27
movi v27.16b, #28
movi v28.16b, #29
movi v29.16b, #30
movi v30.16b, #31
movi v31.16b, #32
mov x2, #0x800000
msr fpcr, x2
mov x2, #0x1
msr fpsr, x2
mov x0, #1000
mov x1, #1001
mov x2, #1002
mov x3, #1003
mov x4, #1004
mov x5, #1005
mov x6, #1006
mov x7, #1007
mov x8, #1008
mov x11, #1011
mov x12, #1012
mov x13, #1013
mov x14, #1014
mov x15, #1015
mov x16, #1016
mov x17, #1017
mov x18, #1018
mov x19, #1019
mov x20, #1020
mov x21, #1021
mov x22, #1022
mov x23, #1023
mov x24, #1024
mov x25, #1025
mov x26, #1026
mov x27, #1027
mov x28, #1028
mov x29, #1029
mov x30, #1030
mov x10, #0xa0000000
msr nzcv, x10
mov x10, #1
stlr x10, [x9]
mov x10, #0
2:
ldr x10, [x9, #8]
cbz x10, 2b
str x11, [sp, #664]
ldr x11, [sp, #0]
str x0, [x11, #0]
str x1, [x11, #8]
str x2, [x11, #16]
str x3, [x11, #24]
str x4, [x11, #32]
str x5, [x11, #40]
str x6, [x11, #48]
str x7, [x11, #56]
str x8, [x11, #64]
str x9, [x11, #72]
str x10, [x11, #80]
str x12, [x11, #96]
str x13, [x11, #104]
str x14, [x11, #112]
str x15, [x11, #120]
str x16, [x11, #128]
str x17, [x11, #136]
str x18, [x11, #144]
str x19, [x11, #152]
str x20, [x11, #160]
str x21, [x11, #168]
str x22, [x11, #176]
str x23, [x11, #184]
str x24, [x11, #192]
str x25, [x11, #200]
str x26, [x11, #208]
str x27, [x11, #216]
str x28, [x11, #224]
str x29, [x11, #232]
str x30, [x11, #240]
ldr x12, [sp, #664]
str x12, [x11, #88]
mov x12, sp
str x12, [x11, #248]
mrs x12, nzcv
str x12, [x11, #256]
mrs x12, tpidr_el0
str x12, [x11, #264]
mrs x12, tpidrro_el0
str x12, [x11, #272]
stp q0, q1, [x11, #288]
stp q2, q3, [x11, #320]
stp q4, q5, [x11, #352]
stp q6, q7, [x11, #384]
stp q8, q9, [x11, #416]
stp q10, q11, [x11, #448]
stp q12, q13, [x11, #480]
stp q14, q15, [x11, #512]
stp q16, q17, [x11, #544]
stp q18, q19, [x11, #576]
stp q20, q21, [x11, #608]
stp q22, q23, [x11, #640]
stp q24, q25, [x11, #672]
stp q26, q27, [x11, #704]
stp q28, q29, [x11, #736]
stp q30, q31, [x11, #768]
mrs x12, fpcr
str x12, [x11, #800]
mrs x12, fpsr
str x12, [x11, #808]
ldp q0, q1, [sp, #128]
ldp q2, q3, [sp, #160]
ldp q4, q5, [sp, #192]
ldp q6, q7, [sp, #224]
ldp q8, q9, [sp, #256]
ldp q10, q11, [sp, #288]
ldp q12, q13, [sp, #320]
ldp q14, q15, [sp, #352]
ldp q16, q17, [sp, #384]
ldp q18, q19, [sp, #416]
ldp q20, q21, [sp, #448]
ldp q22, q23, [sp, #480]
ldp q24, q25, [sp, #512]
ldp q26, q27, [sp, #544]
ldp q28, q29, [sp, #576]
ldp q30, q31, [sp, #608]
ldr x12, [sp, #640]
msr fpcr, x12
ldr x12, [sp, #648]
msr fpsr, x12
ldp x19, x20, [sp, #16]
ldp x21, x22, [sp, #32]
ldp x23, x24, [sp, #48]
ldp x25, x26, [sp, #64]
ldp x27, x28, [sp, #80]
ldp x29, x30, [sp, #96]
add sp, sp, #672
ret
