// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
//
// Kernel entry. The loader (QEMU or U-Boot booti) jumps here with the MMU
// off, x0 = physical address of the device tree, at EL2 or EL1. This code
// drops to EL1, builds boot page tables, turns the MMU on, continues in the
// upper half and calls kernel_main(dtb_pa, kernel_pa).
//
// Boot page tables (1 GiB and 2 MiB blocks):
//   TTBR1 L0[0]   -> linear map: PA 0..1 GiB as device memory; the GiBs that
//                    hold the kernel and the device tree as normal memory
//   TTBR1 L0[511] -> L1[511] -> kernel image at 0xFFFF_FFFF_C000_0000
//   TTBR0         -> identity map of the kernel's GiB, used only while the MMU
//                    is being switched on, then replaced by an empty table
// The image blocks are writable and executable at once; mm::kmap replaces
// them with 4 KiB pages that keep W^X once the frame allocator works.

.equ MAIR_VALUE,     0x4404FF            // Attr0 normal WB, Attr1 Device-nGnRE, Attr2 normal non-cacheable
.equ TCR_BASE,       0xB5103510          // T0SZ=T1SZ=16, TG0=4K (0b00), TG1=4K (0b10), WBWA walks, inner shareable
.equ TCR_AS,         (1 << 36)           // 16-bit ASIDs
.equ SCTLR_MMU_OFF,  0x30D00800          // ARMv8.0 RES1 bits only
.equ SCTLR_MMU_ON,   0x30D0181D          // RES1 | M | C | SA | SA0 | I
.equ PTE_TABLE,      0x3
.equ BLOCK_KERNEL,   0x0040000000000701  // normal, inner shareable, AF, UXN; EL1 may execute
.equ BLOCK_RAM,      0x0060000000000701  // normal, inner shareable, AF, PXN, UXN
.equ BLOCK_DEVICE,   0x0060000000000405  // Device-nGnRE (AttrIndx 1), AF, PXN, UXN

.macro ADR_L reg, sym
    adrp    \reg, \sym
    add     \reg, \reg, :lo12:\sym
.endm

.section .text.head, "ax"
.global _head
_head:
    b       primary_entry           // code0
    .long   0                       // code1
    .quad   0                       // text_offset
    .quad   __image_size            // image_size: file plus .bss, the stack guard page, the boot stack and the boot page tables
    .quad   0xa                     // flags: little endian, 4 KiB pages, place anywhere
    .quad   0                       // res2
    .quad   0                       // res3
    .quad   0                       // res4
    .long   0x644d5241              // magic "ARM\x64"
    .long   0                       // res5

.section .text.boot, "ax"
primary_entry:
    msr     daifset, #0xf
    mov     x19, x0                 // device tree PA (0 when QEMU boots the ELF)
    adr     x20, _head              // kernel image PA
    mrs     x1, mpidr_el1
    and     x1, x1, #0xff
    cbnz    x1, park                // one CPU in subproject 1

    mrs     x1, CurrentEL
    ubfx    x1, x1, #2, #2
    cmp     x1, #2
    b.ne    at_el1

    // EL2 (U-Boot, or QEMU with virtualization=on): drop to EL1.
    mov     x1, #(1 << 31)          // HCR_EL2.RW: EL1 runs AArch64; no traps, no stage 2
    msr     hcr_el2, x1
    mov     x1, #3                  // CNTHCTL_EL2: EL1 may use the physical counter and timer
    msr     cnthctl_el2, x1
    msr     cntvoff_el2, xzr        // virtual time equals physical time
    mov     x1, #0x33ff             // CPTR_EL2: RES1 bits, FP/SIMD not trapped
    msr     cptr_el2, x1
    msr     hstr_el2, xzr
    msr     vttbr_el2, xzr
    // MDCR_EL2, whose fields may hold anything after a warm reset: no debug
    // or PMU traps to EL2 (TDE, TDA, TDOSA, TDRA, TPM, TPMCR clear), so the
    // kernel's writes to MDSCR_EL1 and PMUSERENR_EL0 stay at EL1; there are
    // no EL2 vectors to take them. HPMN leaves EL1 all PMCR_EL0.N event
    // counters (HPMN = 0 is CONSTRAINED UNPREDICTABLE on v8.0). Without a
    // PMU, or with an IMPLEMENTATION DEFINED one (PMUVer 0 or 0xF, the rule
    // of kcore::sysreg::has_pmu), PMCR_EL0 is not read and HPMN is 0, as in
    // Linux's EL2 setup. The profiling and trace buffers (v8.2 and later)
    // stay with EL2: the kernel uses neither.
    mov     x2, xzr
    mrs     x1, id_aa64dfr0_el1
    ubfx    x1, x1, #8, #4          // ID_AA64DFR0_EL1.PMUVer
    cbz     x1, .Lset_mdcr
    cmp     x1, #0xf
    b.eq    .Lset_mdcr
    mrs     x2, pmcr_el0
    ubfx    x2, x2, #11, #5         // PMCR_EL0.N
.Lset_mdcr:
    msr     mdcr_el2, x2
    mrs     x1, midr_el1            // EL1 reads VPIDR/VMPIDR as MIDR/MPIDR
    msr     vpidr_el2, x1
    mrs     x1, mpidr_el1
    msr     vmpidr_el2, x1
    ldr     x1, =SCTLR_MMU_OFF
    msr     sctlr_el1, x1
    mov     x1, #0x3c5              // SPSR_EL2: EL1h with D, A, I, F masked
    msr     spsr_el2, x1
    adr     x1, at_el1
    msr     elr_el2, x1
    eret

at_el1:
    msr     spsel, #1
    ldr     x1, =SCTLR_MMU_OFF      // known state: MMU, caches and alignment checks off
    msr     sctlr_el1, x1
    isb

    // Drop any cache lines over the boot page tables first: the stores
    // below go to memory, and a dirty line the loader left there, evicted
    // later, would overwrite them ([G10]; Linux does the same).
    ADR_L   x0, __boot_pt_start
    ADR_L   x1, __boot_pt_end
    bl      inval_boot_pt
    // Zero the boot page tables. The MMU is off: aligned stores only.
    ADR_L   x0, __boot_pt_start
    ADR_L   x1, __boot_pt_end
1:  cmp     x0, x1
    b.hs    2f
    stp     xzr, xzr, [x0], #16
    b       1b
2:
    ADR_L   x2, l0_high
    ADR_L   x3, l1_linear
    ADR_L   x4, l1_image
    ADR_L   x5, l2_image
    ADR_L   x6, l0_identity
    ADR_L   x7, l1_identity

    // TTBR1: L0[0] -> linear map; L0[511] -> L1[511] -> image blocks.
    orr     x8, x3, #PTE_TABLE
    str     x8, [x2]
    orr     x8, x4, #PTE_TABLE
    str     x8, [x2, #(511 * 8)]
    orr     x8, x5, #PTE_TABLE
    str     x8, [x4, #(511 * 8)]

    // Linear map: devices in the first GiB, RAM for the kernel's and the device tree's GiBs.
    ldr     x9, =BLOCK_DEVICE
    str     x9, [x3]
    ldr     x9, =BLOCK_RAM
    lsr     x10, x20, #30
    lsl     x11, x10, #30
    orr     x11, x11, x9
    str     x11, [x3, x10, lsl #3]
    // Device tree GiB index must be 1..511: keep in sync with kcore::layout::dtb_gib_is_mappable.
    lsr     x10, x19, #30
    cbz     x10, 3f
    cmp     x10, #511
    b.hi    3f
    lsl     x11, x10, #30
    orr     x11, x11, x9
    str     x11, [x3, x10, lsl #3]
3:
    // Kernel image: 2 MiB blocks from the load address, which the loaders align to 2 MiB.
    ldr     x9, =BLOCK_KERNEL
    ldr     x12, =__image_size
    add     x12, x12, x20
    mov     x13, x20
    mov     x14, x5
4:  orr     x11, x13, x9
    str     x11, [x14], #8
    add     x13, x13, #(1 << 21)
    cmp     x13, x12
    b.lo    4b

    // Identity map of the kernel's GiB for the instructions that switch the MMU on.
    lsr     x10, x20, #39
    orr     x8, x7, #PTE_TABLE
    str     x8, [x6, x10, lsl #3]
    lsr     x10, x20, #30
    lsl     x11, x10, #30
    orr     x11, x11, x9            // x9 still holds BLOCK_KERNEL
    and     x10, x10, #0x1ff
    str     x11, [x7, x10, lsl #3]

    // The tables were written with the MMU off: drop stale cache lines over
    // them [G10]. DC IVAC is ordered after the Device stores above only by
    // a barrier.
    dmb     sy
    ADR_L   x0, __boot_pt_start
    ADR_L   x1, __boot_pt_end
    bl      inval_boot_pt

    ADR_L   x21, boot_empty_l0      // physical address, installed after the jump

    ldr     x0, =MAIR_VALUE
    msr     mair_el1, x0
    ldr     x0, =TCR_BASE
    mrs     x1, id_aa64mmfr0_el1
    and     x2, x1, #0xf            // PARange
    mov     x3, #5
    cmp     x2, x3
    csel    x2, x2, x3, ls          // IPS: at most 48-bit physical addresses
    bfi     x0, x2, #32, #3
    ubfx    x2, x1, #4, #4          // ASIDBits: 0b0010 means 16-bit ASIDs
    cmp     x2, #2
    b.ne    6f
    orr     x0, x0, #TCR_AS
6:  msr     tcr_el1, x0
    ADR_L   x0, l0_identity
    msr     ttbr0_el1, x0
    ADR_L   x0, l0_high
    msr     ttbr1_el1, x0
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    ldr     x1, =upper_half         // link-time (virtual) address
    ldr     x0, =SCTLR_MMU_ON
    msr     sctlr_el1, x0
    isb
    ic      iallu
    dsb     nsh
    isb
    br      x1

upper_half:
    msr     ttbr0_el1, x21          // drop the identity map
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    ldr     x0, =boot_stack_top
    mov     sp, x0
    // Zero .bss only now: zeroing it with caches off could leave stale lines visible.
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
7:  cmp     x0, x1
    b.hs    8f
    stp     xzr, xzr, [x0], #16
    b       7b
8:  mov     x0, x19
    mov     x1, x20
    mov     x29, xzr                // the frame-record chain ends here
    bl      kernel_main

park:
    wfe
    b       park

// DC IVAC over [x0, x1) by the smallest data cache line of CTR_EL0, then
// DSB SY [G10]. Clobbers x0, x2 and x3.
inval_boot_pt:
    mrs     x2, ctr_el0
    ubfx    x2, x2, #16, #4
    mov     x3, #4
    lsl     x3, x3, x2              // smallest data cache line in bytes
5:  dc      ivac, x0
    add     x0, x0, x3
    cmp     x0, x1
    b.lo    5b
    dsb     sy
    ret

.ltorg

.section .boot_pt, "aw", %nobits
.balign 4096
l0_high:        .skip 4096
l1_linear:      .skip 4096
l1_image:       .skip 4096
l2_image:       .skip 4096
.global l0_identity, boot_empty_l0
l0_identity:    .skip 4096
l1_identity:    .skip 4096
boot_empty_l0:  .skip 4096

// The boot stack, the kernel stack of CPU 0, in its own section: the
// linker script aligns it to 128 KiB and puts an unmapped guard page and the
// emergency stack below it. Its size is kcore::layout::KERNEL_STACK_SIZE.
.section .boot_stack, "aw", %nobits
.balign 4096
.global boot_stack, boot_stack_top
boot_stack:     .skip 65536
boot_stack_top:
