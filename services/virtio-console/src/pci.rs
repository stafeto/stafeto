// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The configuration space of the console's PCI function on Apple VZ, as
//! the driver sets it up before the Virtio transport reads it: memory
//! decoding off, the BARs at addresses of the host bridge's windows
//! (`ranges` of the tree), then memory decoding on; bus mastering comes
//! only after the driver reset the device (`bus_master`), so that the
//! device starts from no queue.
//! Each access is 32 bits wide [G34]; the status half of the command
//! word clears its bits when written with 1, so the driver writes 0 there.

/// Vendor and device, offset 0: Red Hat's Virtio console, modern.
pub const ID: usize = 0x00;
pub const CONSOLE_ID: u32 = 0x1043_1af4;
/// Command (low half) and status (high half).
pub const COMMAND: usize = 0x04;
pub const MEMORY: u32 = 1 << 1;
pub const BUS_MASTER: u32 = 1 << 2;
/// The 64-bit BAR 0 and 1, and BAR 2.
pub const BAR0: usize = 0x10;
pub const BAR1: usize = 0x14;
pub const BAR2: usize = 0x18;

/// Where the BARs go: BAR 0 and 1 at the start of the 64-bit window of
/// the host bridge, where the device's Virtio structures lie, and BAR 2
/// at the start of its 32-bit window.
pub const BAR_BASE: u64 = 0x1_0000_0000;
pub const BAR2_BASE: u32 = 0x5000_0000;
/// The bytes of BAR 0 the driver maps: the Virtio structures.
pub const BAR_LEN: u64 = 0x1_0000;

/// The writes that set the function up, in their order, as (offset,
/// value), from `command`, the command word read before them: decoding
/// and bus mastering off, the BARs, decoding on.
pub fn set_up(command: u32) -> [(usize, u32); 5] {
    let command = command & 0xFFFF & !BUS_MASTER;
    [
        (COMMAND, command & !MEMORY),
        // The low word keeps only its type bits: a 64-bit memory BAR.
        (BAR0, 0b100),
        (BAR1, (BAR_BASE >> 32) as u32),
        (BAR2, BAR2_BASE),
        (COMMAND, command | MEMORY),
    ]
}

/// The command word once the device is reset: decoding and bus mastering.
pub fn bus_master(command: u32) -> u32 {
    (command & 0xFFFF) | MEMORY | BUS_MASTER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_up_turns_decoding_off_around_the_bars_and_leaves_mastering_off() {
        let writes = set_up(0x0010_0007);
        assert_eq!(writes[0], (COMMAND, 0x0001));
        assert_eq!(writes[4], (COMMAND, 0x0003));
        assert_eq!(writes[1..4], [(BAR0, 4), (BAR1, 1), (BAR2, 0x5000_0000)]);
        let mut commands = writes.iter().filter(|&&(at, _)| at == COMMAND);
        assert!(commands.clone().count() == 2 && commands.all(|&(_, v)| v & BUS_MASTER == 0));
        assert_eq!(bus_master(0x0010_0001), 0x0007);
    }
}
