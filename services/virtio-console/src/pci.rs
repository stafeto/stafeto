// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The configuration space of the console's PCI function on Apple VZ: the
//! writes and the walk of the capability list are those every Virtio PCI
//! driver of stafeto makes (virtio_pci); here is where the console goes.

pub use virtio_pci::*;

/// Red Hat's Virtio console, modern.
pub const CONSOLE_ID: u32 = 0x1043_1af4;
/// BAR 0 and 1 at the start of the host bridge's 64-bit window, where the
/// device's Virtio structures lie, and BAR 2 at the start of its 32-bit
/// window.
pub const BAR_BASE: u64 = 0x1_0000_0000;
pub const BAR2_BASE: u32 = 0x5000_0000;
/// The bytes of BAR 0 the driver maps: the Virtio structures.
pub const BAR_LEN: u64 = 0x1_0000;

pub const CONSOLE: Place = Place {
    id: CONSOLE_ID,
    bar: BAR_BASE,
    bar_len: BAR_LEN,
    bar2: BAR2_BASE,
};

/// The writes that set the console's function up (Place::set_up).
pub fn set_up(command: u32) -> [(usize, u32); 5] {
    CONSOLE.set_up(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_console_keeps_its_bars() {
        let writes = set_up(0x0010_0007);
        assert_eq!(writes[1..4], [(BAR0, 4), (BAR1, 1), (BAR2, 0x5000_0000)]);
    }
}
