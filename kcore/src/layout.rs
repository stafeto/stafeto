// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Virtual address layout shared by the boot code and the kernel.

/// Start of the linear map: virtual address `LINEAR_BASE + pa` reaches physical address `pa`.
pub const LINEAR_BASE: usize = 0xFFFF_0000_0000_0000;

/// Virtual address of the first byte of the kernel image.
pub const KERNEL_VIRT: usize = 0xFFFF_FFFF_C000_0000;

/// End of the lower half, which TTBR0 translates (T0SZ = 16) and which
/// belongs to the running process: user addresses lie in `[0, USER_END)`.
pub const USER_END: usize = 1 << 48;

/// Physical address of `va` inside the kernel image loaded at `kernel_pa`.
pub fn image_pa(kernel_pa: u64, va: usize) -> u64 {
    let offset = va
        .checked_sub(KERNEL_VIRT)
        .expect("address below the kernel image");
    kernel_pa + offset as u64
}

/// The boot page tables map physical memory in whole, naturally aligned GiBs.
pub const GIB: u64 = 1 << 30;

/// True when `[base, base + size)` lies inside one naturally aligned GiB.
pub fn fits_in_one_gib(base: u64, size: u64) -> bool {
    if size == 0 {
        return true;
    }
    match base.checked_add(size - 1) {
        Some(last) => base / GIB == last / GIB,
        None => false,
    }
}

/// True when the boot page tables can map the GiB holding physical address pa: not the first GiB (devices) and inside the 512 GiB one L1 table covers.
pub fn dtb_gib_is_mappable(pa: u64) -> bool {
    (1..512).contains(&(pa / GIB))
}

/// Kernel stacks are 2^KERNEL_STACK_SHIFT bytes and aligned to twice that,
/// so bit KERNEL_STACK_SHIFT of an address is clear inside a stack and set
/// in the KERNEL_STACK_SIZE bytes below it. Exception entry tests that bit
/// (vectors.S) to learn whether the trap frame fits before storing it.
pub const KERNEL_STACK_SHIFT: u32 = 16;

pub const KERNEL_STACK_SIZE: usize = 1 << KERNEL_STACK_SHIFT;

/// True when a trap frame at `frame`, the kernel SP after exception entry
/// reserved the frame, lies inside the kernel stack; false when the SP
/// has run past the stack's bottom.
pub fn frame_fits(frame: usize) -> bool {
    frame & KERNEL_STACK_SIZE == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_inside_a_gib_fits() {
        assert!(fits_in_one_gib(0x4800_0000, 0x10_0000));
    }

    #[test]
    fn region_ending_exactly_at_the_boundary_fits() {
        assert!(fits_in_one_gib(0x7FFF_F000, 0x1000));
    }

    #[test]
    fn region_crossing_the_boundary_does_not_fit() {
        assert!(!fits_in_one_gib(0x7FFF_F000, 0x2000));
    }

    #[test]
    fn region_wrapping_the_address_space_does_not_fit() {
        assert!(!fits_in_one_gib(u64::MAX - 10, 100));
    }

    #[test]
    fn empty_region_fits() {
        assert!(fits_in_one_gib(0x4000_0000, 0));
    }

    #[test]
    fn linear_map_and_kernel_window_are_in_the_upper_half() {
        assert_eq!(LINEAR_BASE >> 48, 0xFFFF);
        const { assert!(LINEAR_BASE < KERNEL_VIRT) };
        assert_eq!(KERNEL_VIRT % (GIB as usize), 0);
    }

    #[test]
    fn image_pa_offsets_from_the_load_address() {
        assert_eq!(image_pa(0x4020_0000, KERNEL_VIRT), 0x4020_0000);
        assert_eq!(image_pa(0x4020_0000, KERNEL_VIRT + 0x1234), 0x4020_1234);
    }

    #[test]
    #[should_panic(expected = "below the kernel image")]
    fn address_below_the_image_has_no_image_pa() {
        image_pa(0x4020_0000, KERNEL_VIRT - 1);
    }

    #[test]
    fn dtb_in_a_ram_gib_is_mappable() {
        assert!(dtb_gib_is_mappable(0x4800_0000));
    }

    #[test]
    fn dtb_at_zero_is_not_mappable() {
        assert!(!dtb_gib_is_mappable(0x0));
    }

    #[test]
    fn dtb_in_the_device_gib_is_not_mappable() {
        assert!(!dtb_gib_is_mappable(0x0900_0000));
    }

    #[test]
    fn dtb_in_the_last_gib_of_the_l1_table_is_mappable() {
        assert!(dtb_gib_is_mappable(511 * GIB + 0x1000));
    }

    #[test]
    fn dtb_at_512_gib_is_not_mappable() {
        assert!(!dtb_gib_is_mappable(512 * GIB));
    }

    #[test]
    fn dtb_at_the_top_of_the_address_space_is_not_mappable() {
        assert!(!dtb_gib_is_mappable(u64::MAX));
    }

    /// A kernel stack in the image, aligned to twice its size.
    const STACK: usize = KERNEL_VIRT + 2 * KERNEL_STACK_SIZE;

    #[test]
    fn frame_fits_anywhere_in_a_kernel_stack() {
        assert!(frame_fits(STACK));
        assert!(frame_fits(STACK + KERNEL_STACK_SIZE / 2));
        assert!(frame_fits(STACK + KERNEL_STACK_SIZE - 16));
    }

    #[test]
    fn frame_does_not_fit_below_a_kernel_stack() {
        assert!(!frame_fits(STACK - 16));
        assert!(!frame_fits(STACK - 4096));
        assert!(!frame_fits(STACK - KERNEL_STACK_SIZE));
    }
}
