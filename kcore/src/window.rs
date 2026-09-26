// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Device windows (spec 7.3, 9): the physical range device_window_create
//! gives a memory object, rounded out to whole pages, and the check that
//! it touches no page the kernel keeps for itself: RAM, the GIC's
//! distributor and CPU interface, and the PL011 of the kernel's console
//! until milestone 1.4. A page shared with any of them is refused, so no
//! window reaches a register of the kernel's devices.

use crate::PAGE_SIZE;
use crate::bootinfo::{BootInfo, Region, RegionList};
use abi::{Error, MAX_MEMORY};

/// The end of the output addresses a descriptor holds (OA[47:12], [G8]).
pub const OUTPUT_END: u64 = 1 << 48;

/// What a window may not touch: the RAM regions of the device tree, at most
/// 8, the GIC's two blocks and the PL011.
pub type Forbidden = RegionList<11>;

/// The range of `len` bytes from `addr` rounded out to whole pages: its
/// first page and its count of pages. INVALID_ARGS for a length of 0, a
/// range that wraps around or ends past OUTPUT_END, and more pages than a
/// memory object has (abi::MAX_MEMORY).
pub fn round_out(addr: u64, len: u64) -> Result<(u64, u64), Error> {
    let end = addr.checked_add(len).filter(|_| len > 0);
    let top = end.and_then(|e| e.checked_next_multiple_of(PAGE_SIZE));
    let base = addr & !(PAGE_SIZE - 1);
    match top {
        Some(top) if top <= OUTPUT_END && top - base <= MAX_MEMORY => {
            Ok((base, (top - base) / PAGE_SIZE))
        }
        _ => Err(Error::InvalidArgs),
    }
}

/// What windows may not touch on the machine `info` describes: its RAM,
/// the GIC's blocks and the PL011.
pub fn forbidden(info: &BootInfo) -> Forbidden {
    let mut list = Forbidden::new();
    let devices = [
        info.gic_distributor,
        info.gic_cpu_interface,
        info.uart_pl011,
    ];
    for r in info
        .memory
        .as_slice()
        .iter()
        .copied()
        .chain(devices.into_iter().flatten())
    {
        list.push(r)
            .expect("room for 8 regions of RAM and 3 devices");
    }
    list
}

/// INVALID_ARGS when the `pages` pages from `base`, a range `round_out`
/// gave, share a page with any region of `forbidden`. O(regions).
pub fn check(base: u64, pages: u64, forbidden: &[Region]) -> Result<(), Error> {
    let end = base + pages * PAGE_SIZE;
    let touches = forbidden.iter().any(|r| {
        let first = r.base & !(PAGE_SIZE - 1);
        let last = r.base.saturating_add(r.size).next_multiple_of(PAGE_SIZE);
        r.size > 0 && first < end && base < last
    });
    if touches {
        Err(Error::InvalidArgs)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootinfo::parse;
    use crate::fdt::Fdt;

    const VIRT: &[u8] = include_bytes!("../tests/fixtures/virt.dtb");

    /// What windows may not touch on QEMU `virt` (the fixture): RAM from
    /// 0x4000_0000, the GIC at 0x0800_0000 and 0x0801_0000, the PL011 at
    /// 0x0900_0000.
    fn virt() -> Forbidden {
        forbidden(&parse(&Fdt::new(VIRT).unwrap()).unwrap())
    }

    /// `round_out` and `check` together, as device_window_create takes a
    /// range.
    fn window(addr: u64, len: u64) -> Result<(u64, u64), Error> {
        let (base, pages) = round_out(addr, len)?;
        check(base, pages, virt().as_slice())?;
        Ok((base, pages))
    }

    #[test]
    fn window_rounds_outward_to_pages() {
        assert_eq!(round_out(0x0901_0000, 0x1000), Ok((0x0901_0000, 1)));
        assert_eq!(round_out(0x0901_0FF0, 0x20), Ok((0x0901_0000, 2)));
        assert_eq!(round_out(0x0901_0004, 1), Ok((0x0901_0000, 1)));
        assert_eq!(round_out(0, MAX_MEMORY), Ok((0, MAX_MEMORY / PAGE_SIZE)));
        assert_eq!(round_out(0x0901_0000, 0), Err(Error::InvalidArgs));
        assert_eq!(round_out(1, MAX_MEMORY), Err(Error::InvalidArgs));
        assert_eq!(round_out(0, MAX_MEMORY + 1), Err(Error::InvalidArgs));
        assert_eq!(round_out(u64::MAX - 0x10, 0x20), Err(Error::InvalidArgs));
    }

    #[test]
    fn window_over_ram_is_refused() {
        for (addr, len) in [
            (0x4000_0000, 0x1000),
            (0x5FFF_F000, 0x1000),
            (0x3FFF_F000, 0x2000),
            (0x3FFF_FFFF, 2),
        ] {
            assert_eq!(window(addr, len), Err(Error::InvalidArgs), "{addr:#x}");
        }
        assert_eq!(window(0x3FFF_F000, 0x1000), Ok((0x3FFF_F000, 1)));
        assert_eq!(window(0x6000_0000, 0x1000), Ok((0x6000_0000, 1)));
    }

    #[test]
    fn window_over_a_kernel_device_page_is_refused() {
        for (addr, len) in [
            (0x0800_0000, 0x1000),
            (0x0800_F000, 0x1000),
            (0x0801_0000, 0x1000),
            (0x0801_FFF0, 0x10),
            (0x0900_0000, 0x1000),
            (0x0900_0FF0, 0x20),
            (0x08FF_FFF0, 0x20),
        ] {
            assert_eq!(window(addr, len), Err(Error::InvalidArgs), "{addr:#x}");
        }
    }

    #[test]
    fn window_between_devices_is_allowed() {
        assert_eq!(window(0x0903_0000, 0x1000), Ok((0x0903_0000, 1)));
        assert_eq!(window(0x08FF_F000, 0x1000), Ok((0x08FF_F000, 1)));
        assert_eq!(window(0x0900_1000, 0x1000), Ok((0x0900_1000, 1)));
        assert_eq!(window(0x0901_0FF0, 0x20), Ok((0x0901_0000, 2)));
        assert_eq!(window(0x0A00_0000, 0x4_0000), Ok((0x0A00_0000, 64)));
    }

    #[test]
    fn window_past_the_output_address_is_refused() {
        let last = OUTPUT_END - PAGE_SIZE;
        assert_eq!(window(last, PAGE_SIZE), Ok((last, 1)));
        assert_eq!(window(last, PAGE_SIZE + 1), Err(Error::InvalidArgs));
        assert_eq!(window(OUTPUT_END, 1), Err(Error::InvalidArgs));
        assert_eq!(window(u64::MAX, 1), Err(Error::InvalidArgs));
    }
}
