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
/// INTx Disable: with it set the function raises no INTA, and the port's
/// writes, which end only by the interrupt, would stop after the first.
pub const INTX_DISABLE: u32 = 1 << 10;
/// The capabilities pointer, in the low byte of the word at 0x34.
pub const CAPABILITIES: usize = 0x34;
/// A vendor capability, which Virtio uses for its structures, and its
/// `cfg_type` of the common configuration (Virtio 1.2, 4.1.4).
const VENDOR_CAPABILITY: u32 = 0x09;
const COMMON_CONFIG: u32 = 1;
/// The first byte past the header of the configuration space, where
/// capabilities begin.
const FIRST_CAPABILITY: usize = 0x40;
/// The capabilities a list may hold: 48 fit in the 192 bytes past the
/// header, so a longer walk is a loop in the list.
const MOST_CAPABILITIES: usize = 48;
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
    let command = command & 0xFFFF & !BUS_MASTER & !INTX_DISABLE;
    [
        (COMMAND, command & !MEMORY),
        // The low word keeps only its type bits: a 64-bit memory BAR.
        (BAR0, 0b100),
        (BAR1, (BAR_BASE >> 32) as u32),
        (BAR2, BAR2_BASE),
        (COMMAND, command | MEMORY),
    ]
}

/// The command word once the device is reset: decoding and bus mastering,
/// and the interrupt let through.
pub fn bus_master(command: u32) -> u32 {
    (command & 0xFFFF & !INTX_DISABLE) | MEMORY | BUS_MASTER
}

/// Where the function's capability list puts the Virtio common
/// configuration, as (BAR, offset), from `read`, the 32-bit registers of
/// the configuration space: the first vendor capability of `cfg_type` 1
/// and at least 16 bytes long. None when the list holds none or does not
/// end. The walk follows the rules of `virtio-drivers`, so that both take
/// the same structure: a capability shorter than 16 bytes is passed over,
/// and a next pointer below 0x40 or off a word ends the list. init stops the device
/// through `device_status` at 0x14 of BAR 0 (init's table for VZ), so the
/// driver starts only where the structure lies at offset 0 of BAR 0.
pub fn common_config(mut read: impl FnMut(usize) -> u32) -> Option<(u8, u32)> {
    let mut at = (read(CAPABILITIES) & 0xFC) as usize;
    if at < FIRST_CAPABILITY {
        return None;
    }
    for _ in 0..MOST_CAPABILITIES {
        // cap_vndr, cap_next, cap_len, cfg_type; then bar; then offset.
        let head = read(at);
        let len = (head >> 16) & 0xFF;
        if head & 0xFF == VENDOR_CAPABILITY && len >= 16 && head >> 24 == COMMON_CONFIG {
            return Some((read(at + 4) as u8, read(at + 8)));
        }
        at = ((head >> 8) & 0xFF) as usize;
        if at < FIRST_CAPABILITY || at & 3 != 0 {
            return None;
        }
    }
    None
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

    #[test]
    fn intx_disable_found_set_is_cleared() {
        let writes = set_up(0x0000_0400);
        assert!(writes.iter().all(|&(_, v)| v & INTX_DISABLE == 0));
        assert_eq!(writes[4], (COMMAND, MEMORY));
        assert_eq!(bus_master(0x0000_0402), 0x0006);
    }

    /// A configuration space of 256 bytes as words, read by offset.
    fn space(words: &[(usize, u32)]) -> impl FnMut(usize) -> u32 + '_ {
        |at| words.iter().find(|&&(o, _)| o == at).map_or(0, |&(_, v)| v)
    }

    #[test]
    fn common_config_is_found_through_the_list() {
        // At 0x40 an MSI-X capability (0x11), at 0x50 the notify (type 2),
        // at 0x64 the common configuration in BAR 0 at 0.
        let vz = [
            (CAPABILITIES, 0x40),
            (0x40, 0x0000_5011),
            (0x50, 0x0214_6409),
            (0x64, 0x0110_0009),
            (0x68, 0),
            (0x6C, 0),
        ];
        assert_eq!(common_config(space(&vz)), Some((0, 0)));
        // The structure moved: BAR 2, or offset 0x1000 of BAR 0.
        let mut moved = vz;
        moved[4].1 = 2;
        assert_eq!(common_config(space(&moved)), Some((2, 0)));
        moved[4].1 = 0;
        moved[5].1 = 0x1000;
        assert_eq!(common_config(space(&moved)), Some((0, 0x1000)));
    }

    #[test]
    fn common_config_is_none_without_it_or_in_a_loop() {
        assert_eq!(common_config(space(&[])), None);
        // Only the notify capability.
        let notify = [(CAPABILITIES, 0x50), (0x50, 0x0214_0009)];
        assert_eq!(common_config(space(&notify)), None);
        // A list whose last entry points back at its first.
        let looped = [
            (CAPABILITIES, 0x40),
            (0x40, 0x0000_5011),
            (0x50, 0x0214_4009),
        ];
        assert_eq!(common_config(space(&looped)), None);
        // A common configuration of 12 bytes is passed over, and the one
        // after it taken, as virtio-drivers does.
        let short = [
            (CAPABILITIES, 0x40),
            (0x40, 0x010C_5009),
            (0x50, 0x0110_0009),
            (0x54, 2),
            (0x58, 0),
        ];
        assert_eq!(common_config(space(&short)), Some((2, 0)));
        // A next pointer into the header, or off a word, ends the list
        // before the common configuration behind it.
        let into_header = [
            (CAPABILITIES, 0x40),
            (0x40, 0x0000_3011),
            (0x30, 0x0110_0009),
        ];
        assert_eq!(common_config(space(&into_header)), None);
        let unaligned = [
            (CAPABILITIES, 0x40),
            (0x40, 0x0000_5211),
            (0x52, 0x0110_0009),
        ];
        assert_eq!(common_config(space(&unaligned)), None);
    }
}
