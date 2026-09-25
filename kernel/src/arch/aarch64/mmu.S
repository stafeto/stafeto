// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//
// switch_ttbr1(new_root x0, identity_root x1, empty_root x2, trampoline_pa x3)
//
// Replaces the kernel's translation tables while running from them. The
// switch itself runs at its physical address through the identity map in
// TTBR0: TTBR1 first goes to an empty table and the TLBs are flushed, then
// to the new tables, so old 2 MiB blocks and new 4 KiB pages never meet in
// the TLB (break-before-make for the whole of TTBR1). The caller must mask
// interrupts (DAIF) before calling and keep them masked until it returns.

.section .text.mmu, "ax"
.global switch_ttbr1
switch_ttbr1:
    dsb     ishst                   // the new tables are visible to the walker
    msr     ttbr0_el1, x1           // identity map of the kernel's GiB
    isb
    adr     x4, 1f                  // virtual address to come back to
    br      x3                      // continue at the trampoline's physical address
1:  msr     ttbr0_el1, x2           // drop the identity map again
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    ret

.global ttbr1_trampoline
ttbr1_trampoline:
    msr     ttbr1_el1, x2
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    msr     ttbr1_el1, x0
    isb
    br      x4
