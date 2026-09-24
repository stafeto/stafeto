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

/// True when the boot page tables can map the GiB holding physical address pa: not the first GiB (devices) and inside the 512 GiB one L1 table covers.
pub fn dtb_gib_is_mappable(pa: u64) -> bool {
    (1..512).contains(&(pa / GIB))
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
}
