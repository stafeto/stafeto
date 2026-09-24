// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Virtual address layout shared by the boot code and the kernel.

/// Start of the linear map: virtual address `LINEAR_BASE + pa` reaches physical address `pa`.
pub const LINEAR_BASE: usize = 0xFFFF_0000_0000_0000;

/// Virtual address of the first byte of the kernel image.
pub const KERNEL_VIRT: usize = 0xFFFF_FFFF_C000_0000;

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
        assert!(LINEAR_BASE < KERNEL_VIRT);
        assert_eq!(KERNEL_VIRT % (GIB as usize), 0);
    }
}
