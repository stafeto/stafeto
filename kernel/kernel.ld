/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The image is linked at KERNEL_VIRT (must equal kcore::layout::KERNEL_VIRT).
 * Load addresses start at KERNEL_PHYS, where QEMU places an Image; the boot
 * code is position independent, so any 2 MiB aligned load address works. */
KERNEL_PHYS = 0x40200000;
KERNEL_VIRT = 0xFFFFFFFFC0000000;
KOFF = KERNEL_VIRT - KERNEL_PHYS;

ENTRY(_head)

SECTIONS
{
    . = KERNEL_VIRT;
    __image_start = .;

    .text : AT(ADDR(.text) - KOFF) {
        KEEP(*(.text.head))
        *(.text.boot)
        *(.text .text.*)
    }

    . = ALIGN(4096);
    __text_end = .;
    .rodata : AT(ADDR(.rodata) - KOFF) {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4096);
    __rodata_end = .;
    .data : AT(ADDR(.data) - KOFF) {
        *(.data .data.*)
        *(.got .got.*)
    }

    . = ALIGN(4096);
    .bss (NOLOAD) : AT(ADDR(.bss) - KOFF) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    . = ALIGN(4096);
    .boot_pt (NOLOAD) : AT(ADDR(.boot_pt) - KOFF) {
        __boot_pt_start = .;
        *(.boot_pt)
        __boot_pt_end = .;
    }

    /* The boot stack is aligned to twice its size (vectors.S tests one
     * address bit to spot an SP below it). Right below it lies one page that
     * the kernel page tables leave unmapped, so a stack overflow faults
     * there first, and below that the emergency stack, where exception
     * entry reports such a fault. */
    . = ALIGN(. + 0x3000, 0x20000) - 0x3000;
    .emergency_stack (NOLOAD) : AT(ADDR(.emergency_stack) - KOFF) {
        *(.emergency_stack)
    }

    __stack_guard = .;
    . += 4096;

    .boot_stack (NOLOAD) : AT(ADDR(.boot_stack) - KOFF) {
        *(.boot_stack)
    }
    ASSERT(boot_stack % 0x20000 == 0 && boot_stack_top - boot_stack == 0x10000,
           "the boot stack must be 64 KiB aligned to 128 KiB")
    ASSERT(boot_stack_top - boot_stack == (1 << vectors_stack_shift),
           "vectors.S tests another stack size")
    ASSERT(__stack_guard == boot_stack - 0x1000 && emergency_stack_top == __stack_guard,
           "the guard page and the emergency stack must lie right below the boot stack")

    . = ALIGN(4096);
    __image_end = .;
    __image_size = __image_end - __image_start;

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
    }
}
