// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Where the network devices sit on Apple VZ: Red Hat's Virtio network
//! device, modern (1af4:1041, Virtio 1.2, 4.1.2), at device 1 of bus 0
//! and, for a second device, device 2, ahead of the console (5) and the
//! entropy device (6) (a walk of the bus, `cargo xtask pci-walk-vz --net
//! N`). Each has BAR 0 of 64 KiB, 64-bit memory, with the Virtio
//! structures in it (common configuration at 0, ISR at 0x1000,
//! notification at 0x4000, device configuration at 0x8000), and BAR 2 of 64
//! bytes in 32-bit memory. The BARs go past those of the console
//! (virtio_console::pci) and the entropy device (virtio_rng::PLACE), each
//! aligned to its size. INTA of device N goes to INTID 64 + N through the
//! tree's `interrupt-map`.
//!
//! One window `ecam` covers the pages of both functions (device 1 to
//! device 2, nine pages) and one window `bar` both BARs 0, so that a
//! record of two devices has four names with the two lines
//! (proto_init::START_NAMES).

use virtio_pci::Place;

/// The PCI device of the first and of the second network device on bus 0.
pub const DEVICE: [u64; 2] = [1, 2];
/// The vendor and device of the modern network device, offset 0.
pub const NET_ID: u32 = 0x1041_1af4;
/// The bytes of BAR 0, as the walk measured them.
pub const BAR_LEN: u64 = 0x1_0000;
/// The bytes of BAR 2 (the walk's measure): the sizes CLAIM tells the owner
/// of the second device, which has no window `ecam` to measure them.
pub const BAR2_LEN: u64 = 0x40;
pub const BAR_SIZES: [u64; 6] = [BAR_LEN, 0, BAR2_LEN, 0, 0, 0];
pub const PAGE: u64 = 4096;
/// ECAM of bus 0: the page of function 0 of device `n` is at
/// `ECAM + (n << 15)`.
pub const ECAM: u64 = 0x4000_0000;
/// The start of the 64-bit window past the entropy device's BAR (the
/// console's 64 KiB, then the entropy device's 32 KiB, the first 128 KiB
/// of the window rounded up to the size of this BAR).
pub const BAR_BASE: u64 = 0x1_0002_0000;
/// The start of the 32-bit BAR 2 past the console's and the entropy
/// device's.
pub const BAR2_BASE: u32 = 0x5002_0000;
/// `device_status` of the Virtio common configuration at the start of BAR
/// 0, which init writes 0 to once an instance ended.
pub const DEVICE_STATUS: u64 = 0x14;

/// Where the driver puts the network device `i` (0 or 1).
pub const PLACES: [Place; 2] = [place(0), place(1)];

const fn place(i: u64) -> Place {
    Place {
        id: NET_ID,
        bar: BAR_BASE + i * BAR_LEN,
        bar_len: BAR_LEN,
        bar2: BAR2_BASE + (i as u32) * 0x1_0000,
    }
}

/// The physical address of the page of configuration of device `i`.
pub const fn function(i: usize) -> u64 {
    ECAM + (DEVICE[i] << 15)
}

/// INTA of device `i` as an INTID.
pub const fn line(i: usize) -> u32 {
    64 + DEVICE[i] as u32
}

/// The window `ecam` of a record of `count` devices: from the page of
/// device 0 to the end of the page of the last.
pub const fn ecam_window(count: usize) -> (u64, u64) {
    (function(0), function(count - 1) + PAGE - function(0))
}

/// The window `bar` of a record of `count` devices: the BARs 0 together.
pub const fn bar_window(count: usize) -> (u64, u64) {
    (PLACES[0].bar, count as u64 * BAR_LEN)
}

/// Where device `i` lies inside the window `ecam` and inside the window
/// `bar`.
pub const fn ecam_offset(i: usize) -> u64 {
    function(i) - function(0)
}

pub const fn bar_offset(i: usize) -> u64 {
    PLACES[i].bar - PLACES[0].bar
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each BAR is aligned to its size, the 64-bit ones past the console's
    // and the entropy device's.
    const _: () = assert!(PLACES[0].bar.is_multiple_of(BAR_LEN));
    const _: () = assert!(PLACES[1].bar.is_multiple_of(BAR_LEN));
    const _: () = assert!(PLACES[0].bar >= virtio_rng::PLACE.bar + virtio_rng::PLACE.bar_len);
    const _: () =
        assert!(PLACES[0].bar >= virtio_console::pci::BAR_BASE + virtio_console::pci::BAR_LEN);
    const _: () = assert!(PLACES[1].bar == PLACES[0].bar + BAR_LEN);
    // BAR 2: 64 bytes aligned, past the others.
    const _: () = assert!(PLACES[0].bar2 > virtio_rng::PLACE.bar2);
    const _: () = assert!(PLACES[0].bar2 > virtio_console::pci::BAR2_BASE);
    const _: () = assert!(PLACES[0].bar2.is_multiple_of(64));
    // The window of the two functions touches neither the console's
    // (device 5) nor the entropy device's (device 6) page.
    const _: () = assert!(ecam_window(2).0 + ecam_window(2).1 <= ECAM + (5 << 15));

    #[test]
    fn the_second_device_is_the_next_slot() {
        assert_eq!(function(0), 0x4000_8000);
        assert_eq!(function(1), 0x4001_0000);
        assert_eq!(line(0), 65);
        assert_eq!(line(1), 66);
    }

    #[test]
    fn the_windows_hold_the_pages_and_the_bars() {
        assert_eq!(ecam_window(1), (0x4000_8000, PAGE));
        assert_eq!(ecam_window(2), (0x4000_8000, 9 * PAGE));
        assert_eq!(bar_window(2), (0x1_0002_0000, 2 * BAR_LEN));
        assert_eq!(ecam_offset(1), 8 * PAGE);
        assert_eq!(bar_offset(1), BAR_LEN);
    }

    #[test]
    fn the_bar_of_each_device_goes_past_the_consoles_and_the_entropy_devices() {
        let writes = PLACES[1].set_up(0);
        assert_eq!(writes[1], (virtio_pci::BAR0, 0x0003_0004));
        assert_eq!(writes[2], (virtio_pci::BAR1, 1));
        assert_eq!(writes[3], (virtio_pci::BAR2, 0x5003_0000));
    }
}
