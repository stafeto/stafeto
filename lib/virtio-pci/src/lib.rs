// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The configuration space of a Virtio PCI function on Apple VZ and on
//! QEMU's `virt` machine, as its driver sets it up before the Virtio transport reads it: memory
//! and I/O decoding off, the BARs at addresses of the host bridge's windows
//! (`ranges` of the tree) that the driver's `Place` names, then memory
//! decoding on; bus mastering comes only after the driver reset the
//! device (`bus_master`), so that the device starts from no queue. The
//! drivers of the console (services/virtio-console) and of the entropy
//! device (services/virtio-rng) share it, each with its own `Place`.
//! Each access is 32 bits wide [G34]; the status half of the command
//! word clears its bits when written with 1, so the driver writes 0 there.

#![cfg_attr(not(test), no_std)]

/// Where a driver puts its function: the vendor and device it expects at
/// offset 0, BAR 0 and 1 (a 64-bit memory BAR) in the 64-bit window of the
/// host bridge, where the device's Virtio structures lie, the bytes of it
/// the driver maps, and BAR 2 in the 32-bit window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    pub id: u32,
    pub bar: u64,
    pub bar_len: u64,
    pub bar2: u32,
}

/// Vendor and device, offset 0.
pub const ID: usize = 0x00;
/// Command (low half) and status (high half).
pub const COMMAND: usize = 0x04;
/// I/O space decoding.
pub const IO: u32 = 1 << 0;
pub const MEMORY: u32 = 1 << 1;
pub const BUS_MASTER: u32 = 1 << 2;
/// INTx Disable: with it set the function raises no INTA, and a driver's
/// requests, which end only by the interrupt, would stop after the first.
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

impl Place {
    /// The writes that set the function up, in their order, as (offset,
    /// value), from `command`, the command word read before them:
    /// memory and I/O decoding and bus mastering off, the BARs, decoding on.
    pub fn set_up(&self, command: u32) -> [(usize, u32); 5] {
        let command = command & 0xFFFF & !BUS_MASTER & !INTX_DISABLE;
        [
            (COMMAND, command & !(MEMORY | IO)),
            // The low word keeps its type bits and the low half of the
            // address: a 64-bit memory BAR.
            (BAR0, self.bar as u32 | 0b100),
            (BAR1, (self.bar >> 32) as u32),
            (BAR2, self.bar2),
            (COMMAND, command | MEMORY),
        ]
    }
}

/// A function whose Virtio structures lie in one 64-bit memory BAR, the
/// register pair `index`, `index + 1`: the shape of a modern Virtio PCI
/// device on QEMU's `virt` machine, where no firmware has placed the BAR
/// and the driver does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bar64 {
    pub id: u32,
    pub index: usize,
    pub bar: u64,
    pub len: u64,
}

impl Bar64 {
    /// The offset of the low register of the BAR.
    pub const fn register(&self) -> usize {
        0x10 + 4 * self.index
    }

    /// The writes that set the function up, in their order, as (offset,
    /// value), from `command`, the command word read before them:
    /// memory and I/O decoding and bus mastering off, the BAR, decoding on.
    pub fn set_up(&self, command: u32) -> [(usize, u32); 4] {
        let command = command & 0xFFFF & !BUS_MASTER & !INTX_DISABLE;
        [
            (COMMAND, command & !(MEMORY | IO)),
            // The type bits (64-bit, prefetchable) are the device's own;
            // writing them leaves them as they are.
            (self.register(), self.bar as u32 | 0b1100),
            (self.register() + 4, (self.bar >> 32) as u32),
            (COMMAND, command | MEMORY),
        ]
    }

    /// `set_up` with one more BAR register written while decoding is off:
    /// `(offset, value)`, the 32-bit BAR of the function's MSI-X table.
    pub fn set_up_with(&self, command: u32, also: (usize, u32)) -> [(usize, u32); 5] {
        let [off, low, high, on] = self.set_up(command);
        [off, low, high, also, on]
    }
}

/// QEMU's `virt` machine with `highmem-ecam=off` (xtask sets it on every
/// machine): ECAM below 4 GiB, the 32-bit window of the host bridge, and
/// the INTx swizzle of the tree's `interrupt-map`.
pub mod qemu {
    use super::Bar64;

    /// ECAM: buses 0 to 15.
    pub const ECAM: u64 = 0x3f00_0000;
    pub const ECAM_LEN: u64 = 0x100_0000;
    /// The 32-bit window of the host bridge; PCI address = CPU address.
    pub const MMIO32: u64 = 0x1000_0000;
    pub const MMIO32_LEN: u64 = 0x2eff_0000;
    /// The 64-bit window. Unused: QEMU drops it under HVF on hosts with a
    /// 36-bit IPA, so every BAR of the table lies in `MMIO32`.
    pub const MMIO64: u64 = 0x80_0000_0000;
    pub const MMIO64_LEN: u64 = 0x80_0000_0000;
    /// INTA to INTD of device 0 are SPI 3 to 6.
    pub const INTX_FIRST: u32 = 35;
    pub const PAGE: u64 = 4096;

    /// The page of function 0 of `device` on bus 0.
    pub const fn function(device: u64) -> u64 {
        ECAM + (device << 15)
    }

    /// The INTID of pin `pin` (1 = INTA) of `device`: the swizzle of the
    /// tree's `interrupt-map`.
    pub const fn intx(device: u64, pin: u32) -> u32 {
        assert!(pin >= 1 && pin <= 4);
        INTX_FIRST + ((device as u32 + pin - 1) % 4)
    }

    /// The disk: device 1, modern virtio-blk, BAR 4 of 16 KiB at the start
    /// of `MMIO32`. Further devices of the table follow from there, each
    /// aligned to its size.
    pub const DISK_DEVICE: u64 = 1;
    pub const DISK: Bar64 = Bar64 {
        id: 0x1042_1af4,
        index: 4,
        bar: MMIO32,
        len: 0x4000,
    };
    pub const DISK_FUNCTION: u64 = function(DISK_DEVICE);
    pub const DISK_LINE: u32 = intx(DISK_DEVICE, 1);

    /// The network device of the machine with an ITS (xtask's `VIRT_ITS`):
    /// device 2, modern virtio-net-pci with MSI-X. BAR 4 of 16 KiB lies past
    /// the disk's, and BAR 1, the 4 KiB of the MSI-X table and its pending
    /// bits, right after it, so that one window holds both.
    pub const NET_DEVICE: u64 = 2;
    pub const NET: Bar64 = Bar64 {
        id: 0x1041_1af4,
        index: 4,
        bar: MMIO32 + 0x1_0000,
        len: 0x4000,
    };
    pub const NET_MSIX_BAR: u8 = 1;
    pub const NET_MSIX: u64 = NET.bar + NET.len;
    pub const NET_MSIX_LEN: u64 = 0x1000;
    pub const NET_FUNCTION: u64 = function(NET_DEVICE);
    /// The requester ID of the function (bus 0, device 2, function 0),
    /// which the kernel turns into the ITS's DeviceID through `msi-map`.
    pub const NET_RID: u32 = (NET_DEVICE as u32) << 3;

    const _: () = {
        assert!(DISK.bar.is_multiple_of(DISK.len));
        assert!(DISK.bar + DISK.len <= MMIO32 + MMIO32_LEN);
        assert!(DISK_FUNCTION + PAGE <= ECAM + ECAM_LEN);
        assert!(DISK_LINE >= INTX_FIRST && DISK_LINE <= INTX_FIRST + 3);
        assert!(NET.bar >= DISK.bar + DISK.len && NET.bar.is_multiple_of(NET.len));
        assert!(NET_MSIX.is_multiple_of(NET_MSIX_LEN));
        assert!(NET_MSIX + NET_MSIX_LEN <= MMIO32 + MMIO32_LEN);
    };
}

/// The command word once the device is reset: decoding and bus mastering,
/// and the interrupt let through.
pub fn bus_master(command: u32) -> u32 {
    (command & 0xFFFF & !INTX_DISABLE) | MEMORY | BUS_MASTER
}

/// The offset of the first capability of the function's list, from
/// `read`, the 32-bit registers of the configuration space, whose first
/// word `wanted` takes. None when the list holds none or does not end: a
/// next pointer below 0x40 or off a word ends the list, as `virtio-drivers`
/// reads it.
fn capability(read: &mut impl FnMut(usize) -> u32, wanted: impl Fn(u32) -> bool) -> Option<usize> {
    let mut at = (read(CAPABILITIES) & 0xFC) as usize;
    if at < FIRST_CAPABILITY {
        return None;
    }
    for _ in 0..MOST_CAPABILITIES {
        let head = read(at);
        if wanted(head) {
            return Some(at);
        }
        at = ((head >> 8) & 0xFF) as usize;
        if at < FIRST_CAPABILITY || at & 3 != 0 {
            return None;
        }
    }
    None
}

/// Where the function's capability list puts the Virtio common
/// configuration, as (BAR, offset), from `read`, the 32-bit registers of
/// the configuration space: the first vendor capability of `cfg_type` 1
/// and at least 16 bytes long. None when the list holds none or does not
/// end. The walk follows the rules of `virtio-drivers`, so that both take
/// the same structure: a capability shorter than 16 bytes is passed over,
/// and a next pointer below 0x40 or off a word ends the list. init stops
/// the device through `device_status` at 0x14 of BAR 0 (init's tables for
/// VZ), so a driver starts only where the structure lies at offset 0 of
/// BAR 0.
pub fn common_config(mut read: impl FnMut(usize) -> u32) -> Option<(u8, u32)> {
    // cap_vndr, cap_next, cap_len, cfg_type; then bar; then offset.
    let at = capability(&mut read, |head| {
        head & 0xFF == VENDOR_CAPABILITY && (head >> 16) & 0xFF >= 16 && head >> 24 == COMMON_CONFIG
    })?;
    Some((read(at + 4) as u8, read(at + 8)))
}

/// The MSI-X capability (PCI Local Bus 3.0, 6.8.2): its ID, and the bits of
/// its first word, whose upper half is Message Control: MSI-X Enable (15),
/// Function Mask (14) and the table's size less one (10:0).
pub const MSIX_CAPABILITY: u32 = 0x11;
pub const MSIX_ENABLE: u32 = 1 << 31;
pub const MSIX_FUNCTION_MASK: u32 = 1 << 30;
/// An entry of the table: 16 bytes, the address (low, high), the data and
/// Vector Control, whose bit 0 masks the vector.
pub const MSIX_ENTRY: usize = 16;
pub const MSIX_MASKED: u32 = 1;
/// The fields of the Virtio common configuration that tie a queue to an
/// MSI-X vector (Virtio 1.2, 4.1.4.3), 16 bits each, and the value of no
/// vector.
pub const MSIX_CONFIG: usize = 0x10;
pub const QUEUE_SELECT: usize = 0x16;
pub const QUEUE_MSIX_VECTOR: usize = 0x1A;
pub const NO_VECTOR: u16 = 0xFFFF;

/// The function's MSI-X capability: where it lies in the configuration
/// space, the vectors of its table, and the table's BAR and offset there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msix {
    pub at: usize,
    pub vectors: u16,
    pub bar: u8,
    pub offset: u32,
}

impl Msix {
    /// The first word of the capability with MSI-X on and no function
    /// mask, from the word `head` read there; the ID and next pointer are
    /// read-only, and the table size too.
    pub const fn enabled(head: u32) -> u32 {
        (head | MSIX_ENABLE) & !MSIX_FUNCTION_MASK
    }

    /// The four words of the table entry of a vector that writes `data` to
    /// `address`, unmasked.
    pub const fn entry(address: u64, data: u32) -> [u32; 4] {
        [address as u32, (address >> 32) as u32, data, 0]
    }

    /// The vector of queue `queue`: queue i takes vector i while the table
    /// has one, and none past it (a driver then polls that queue).
    pub const fn queue_vector(&self, queue: u16) -> u16 {
        if queue < self.vectors {
            queue
        } else {
            NO_VECTOR
        }
    }
}

/// The function's MSI-X capability, from `read` as `common_config` takes
/// it; None without one.
pub fn msix(mut read: impl FnMut(usize) -> u32) -> Option<Msix> {
    let at = capability(&mut read, |head| head & 0xFF == MSIX_CAPABILITY)?;
    let table = read(at + 4);
    Some(Msix {
        at,
        vectors: ((read(at) >> 16) & 0x7FF) as u16 + 1,
        bar: (table & 0b111) as u8,
        offset: table & !0b111,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The console's place on VZ.
    const CONSOLE: Place = Place {
        id: 0x1043_1af4,
        bar: 0x1_0000_0000,
        bar_len: 0x1_0000,
        bar2: 0x5000_0000,
    };

    #[test]
    fn set_up_turns_decoding_off_around_the_bars_and_leaves_mastering_off() {
        let writes = CONSOLE.set_up(0x0010_0007);
        assert_eq!(writes[0], (COMMAND, 0x0000));
        assert_eq!(writes[4], (COMMAND, 0x0003));
        assert_eq!(writes[1..4], [(BAR0, 4), (BAR1, 1), (BAR2, 0x5000_0000)]);
        let mut commands = writes.iter().filter(|&&(at, _)| at == COMMAND);
        assert!(commands.clone().count() == 2 && commands.all(|&(_, v)| v & BUS_MASTER == 0));
        assert_eq!(bus_master(0x0010_0001), 0x0007);
    }

    #[test]
    fn the_low_half_of_bar_0_goes_into_its_low_word() {
        let rng = Place {
            bar: 0x1_0001_0000,
            bar2: 0x5001_0000,
            ..CONSOLE
        };
        let writes = rng.set_up(0);
        assert_eq!(
            writes[1..4],
            [(BAR0, 0x0001_0004), (BAR1, 1), (BAR2, 0x5001_0000)]
        );
    }

    #[test]
    fn intx_disable_found_set_is_cleared() {
        let writes = CONSOLE.set_up(0x0000_0400);
        assert!(writes.iter().all(|&(_, v)| v & INTX_DISABLE == 0));
        assert_eq!(writes[4], (COMMAND, MEMORY));
        assert_eq!(bus_master(0x0000_0402), 0x0006);
    }

    #[test]
    fn bar64_sets_the_function_up_around_its_bar() {
        let writes = qemu::DISK.set_up(0x0010_0407);
        assert_eq!(
            writes,
            [
                (COMMAND, 0x0000),
                (0x20, 0x1000_000C),
                (0x24, 0),
                (COMMAND, 0x0003),
            ]
        );
        assert!(
            writes
                .iter()
                .filter(|&&(at, _)| at == COMMAND)
                .all(|&(_, v)| v & (BUS_MASTER | INTX_DISABLE) == 0)
        );
        let high = Bar64 {
            bar: 0x80_0000_4000,
            ..qemu::DISK
        };
        assert_eq!(high.set_up(0)[1..3], [(0x20, 0x0000_400C), (0x24, 0x80)]);
        assert_eq!(qemu::DISK.register(), 0x20);
    }

    #[test]
    fn intx_follows_the_interrupt_map_of_the_tree() {
        // QEMU 11.1.2, dumpdtb, highmem-ecam=off: (device, pin, SPI).
        let map: [(u64, u32, u32); 16] = [
            (0, 1, 3),
            (0, 2, 4),
            (0, 3, 5),
            (0, 4, 6),
            (1, 1, 4),
            (1, 2, 5),
            (1, 3, 6),
            (1, 4, 3),
            (2, 1, 5),
            (2, 2, 6),
            (2, 3, 3),
            (2, 4, 4),
            (3, 1, 6),
            (3, 2, 3),
            (3, 3, 4),
            (3, 4, 5),
        ];
        for (device, pin, spi) in map {
            assert_eq!(
                qemu::intx(device, pin),
                32 + spi,
                "device {device} pin {pin}"
            );
        }
    }

    #[test]
    fn the_disk_sits_where_the_tree_puts_it() {
        assert_eq!(qemu::function(1), 0x3f00_8000);
        assert_eq!(qemu::DISK_FUNCTION, 0x3f00_8000);
        assert_eq!(qemu::DISK_LINE, 36);
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

    /// A list shaped as that of QEMU's virtio-net-pci with three vectors:
    /// MSI-X at 0x98 with its table at offset 0 of BAR 1, then the common
    /// configuration at offset 0 of BAR 4.
    const NET_SPACE: [(usize, u32); 6] = [
        (CAPABILITIES, 0x98),
        (0x98, 0x0002_8411),
        (0x9C, 0x0000_0001),
        (0x84, 0x0110_7009),
        (0x88, 4),
        (0x8C, 0),
    ];

    #[test]
    fn msix_is_found_through_the_list() {
        let found = msix(space(&NET_SPACE)).unwrap();
        assert_eq!(
            found,
            Msix {
                at: 0x98,
                vectors: 3,
                bar: 1,
                offset: 0
            }
        );
        // The common configuration behind it is still found.
        assert_eq!(common_config(space(&NET_SPACE)), Some((4, 0)));
        // A table at 0x800 of BAR 2.
        let mut moved = NET_SPACE;
        moved[2].1 = 0x802;
        assert_eq!(
            msix(space(&moved)).map(|m| (m.bar, m.offset)),
            Some((2, 0x800))
        );
        // No MSI-X: VZ's list without it, or a list that loops.
        assert_eq!(
            msix(space(&[(CAPABILITIES, 0x50), (0x50, 0x0214_0009)])),
            None
        );
        let looped = [(CAPABILITIES, 0x40), (0x40, 0x0000_4009)];
        assert_eq!(msix(space(&looped)), None);
    }

    #[test]
    fn msix_is_enabled_unmasked_and_one_vector_a_queue() {
        // Enable set and the function mask cleared; the ID, the pointer
        // and the size kept.
        assert_eq!(Msix::enabled(0x4002_8411), 0x8002_8411);
        assert_eq!(Msix::enabled(0x8002_8411), 0x8002_8411);
        assert_eq!(
            Msix::entry(0x0808_0040, 7),
            [0x0808_0040, 0, 7, 0],
            "the address of GITS_TRANSLATER [G43], the EventID, unmasked"
        );
        assert_eq!(Msix::entry(0x1_2345_6780, 1)[..2], [0x2345_6780, 1]);
        assert_eq!(Msix::entry(0, 0)[3] & MSIX_MASKED, 0);
        let three = msix(space(&NET_SPACE)).unwrap();
        assert_eq!(
            [0, 1, 2, 3].map(|q| three.queue_vector(q)),
            [0, 1, 2, NO_VECTOR]
        );
        let one = Msix {
            vectors: 1,
            ..three
        };
        assert_eq!(one.queue_vector(1), NO_VECTOR);
        assert_eq!(MSIX_ENTRY * 3, 48);
    }

    #[test]
    fn the_network_device_of_the_its_machine_has_one_window_for_its_bars() {
        let writes = qemu::NET.set_up_with(0x0010_0407, (0x14, qemu::NET_MSIX as u32));
        assert_eq!(
            writes,
            [
                (COMMAND, 0x0000),
                (0x20, 0x1001_000C),
                (0x24, 0),
                (0x14, 0x1001_4000),
                (COMMAND, 0x0003),
            ]
        );
        assert_eq!(qemu::NET_FUNCTION, 0x3f01_0000);
        assert_eq!(qemu::NET_RID, 0x10);
        assert_eq!(qemu::NET_MSIX, qemu::NET.bar + qemu::NET.len);
    }
}
