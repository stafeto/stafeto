// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the shell on EC2 (t4g.small): the dialog of
//! `ramfs::BUSYBOX_DIALOG_TABLE` with the 16550 the SPCR names for the
//! console, polled, and nothing that needs Virtio, NVMe or the network
//! device: no entropy service, no `net`, no windows over PCI.

use super::{GENERAL_CPUS, Kind, Record, Restart, Shares, Window};
use crate::PAGE;
use crate::watch::Watch;

const MS: u64 = 1_000_000;
/// The console port of the SPCR of a t4g.small: a 16550 with byte
/// registers one apart (`boot/firmware-tree/tests/fixtures/graviton-t4g`).
pub const SPCR_PORT: u64 = 0x090a_0000;
/// The kind byte of `uart`'s arguments: a 16550 that is polled.
const KIND_16550: u8 = 1;

const ARGS: [u8; 9] = {
    let base = SPCR_PORT.to_le_bytes();
    [
        base[0], base[1], base[2], base[3], base[4], base[5], base[6], base[7], KIND_16550,
    ]
};

/// The driver of the console: its window over the port, no binding.
pub const CONSOLE: Record = Record {
    name: "uart",
    program: "uart",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 60,
    ceiling: 60,
    quota: 32 * PAGE,
    handle_limit: 32,
    restart: Restart::Always,
    console: true,
    log: true,
    trace: false,
    windows: &[Window {
        name: "regs",
        base: SPCR_PORT,
        len: PAGE,
        duplicate: false,
    }],
    bindings: &[],
    connects: &[],
    args: &ARGS,
    dma: &[],
    quiesce: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
};

pub const TABLE: &[Record] = &[
    CONSOLE,
    super::ramfs::RAM_FIFO_CLOCKED,
    super::ramfs::BUSYBOX_DIALOG_TABLE[2],
    // No PL031 on EC2: the clock starts at the time the image was built.
    super::ramfs::POSIX_ABI_TABLE[2],
    super::ramfs::BUSYBOX_DIALOG_TABLE[4],
    // The image of this table has no entropy service.
    Record {
        connects: &["ramfs", "tty", "pipe", "clock", "posix"],
        ..super::ramfs::BUSYBOX_DIALOG_TABLE[5]
    },
    super::ramfs::TTY,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_console_window_is_the_address_of_the_spcr_of_a_t4g() {
        let spcr = include_bytes!(
            "../../../../boot/firmware-tree/tests/fixtures/graviton-t4g/02-SPCR.bin"
        );
        let base = u64::from_le_bytes(spcr[44..52].try_into().unwrap());
        assert_eq!(base, SPCR_PORT);
        assert_eq!(CONSOLE.windows[0].base, base);
        assert_eq!(&CONSOLE.args[..8], &base.to_le_bytes());
        assert_eq!(CONSOLE.args[8], KIND_16550);
        assert!(CONSOLE.bindings.is_empty());
    }

    #[test]
    fn no_record_connects_to_net_or_entropy_or_a_pci_window() {
        for r in TABLE {
            assert!(!r.connects.contains(&"net") && !r.connects.contains(&"entropy"));
            assert!(r.windows.iter().all(|w| w.base == SPCR_PORT));
            assert!(r.bindings.is_empty());
        }
    }

    #[test]
    fn no_window_lies_in_the_ram_of_the_firmware_map() {
        let map =
            include_bytes!("../../../../boot/firmware-tree/tests/fixtures/graviton-t4g/memmap.bin");
        for rec in map.as_chunks::<32>().0 {
            let ty = u64::from_le_bytes(rec[0..8].try_into().unwrap());
            let phys = u64::from_le_bytes(rec[8..16].try_into().unwrap());
            let pages = u64::from_le_bytes(rec[16..24].try_into().unwrap());
            if ty == 7 {
                assert!(!(phys..phys + pages * 4096).contains(&SPCR_PORT));
            }
        }
    }
}
