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
    .rodata : AT(ADDR(.rodata) - KOFF) {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4096);
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

    /* One page that the kernel page tables leave unmapped: a stack overflow
     * faults there instead of overwriting .bss. */
    . = ALIGN(4096);
    __stack_guard = .;
    . += 4096;

    .boot_stack (NOLOAD) : AT(ADDR(.boot_stack) - KOFF) {
        *(.boot_stack)
    }

    . = ALIGN(4096);
    .boot_pt (NOLOAD) : AT(ADDR(.boot_pt) - KOFF) {
        __boot_pt_start = .;
        *(.boot_pt)
        __boot_pt_end = .;
    }

    __image_end = .;
    __image_size = __image_end - __image_start;

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
    }
}
