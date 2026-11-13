// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the shell on EC2 (t4g.small): the dialog of
//! `ramfs::BUSYBOX_DIALOG_TABLE` with the 16550 the SPCR names for the
//! console, polled, and nothing that needs Virtio, NVMe or the network
//! device besides the ENA's service `net` (polled, optional): no entropy
//! service, no Virtio window.

use super::{At, Dma, GENERAL_CPUS, Kind, Record, Restart, Shares, Window, Write};
use crate::PAGE;
use crate::resolve::Platform;
use crate::watch::Watch;
use pci::Ecam;

const MS: u64 = 1_000_000;
/// The console port of the SPCR of a t4g.small: a 16550 with byte
/// registers one apart (`boot/firmware-tree/tests/fixtures/graviton-t4g`).
pub const SPCR_PORT: u64 = 0x090a_0000;
/// The ECAM of a t4g.small as its MCFG names it: segment 0, buses 0 to 255
/// from 0x20000000 (`fixtures/graviton-t4g/04-MCFG.bin`).
pub const ECAM: Ecam = Ecam {
    base: 0x2000_0000,
    first_bus: 0,
    last_bus: 255,
};
/// The platform the places of this table are found on. The walk covers bus 0
/// alone: every function of the instance is there (`pci.txt` of the fixtures)
/// and the host bridge at 00:00.0 is class 0x0600, so no bridge leads to
/// another bus; a test keeps this true of the fixture. There is no I/O
/// window (`iomem.txt`), so the shift of an I/O BAR is 0.
pub const PLATFORM: Platform = Platform {
    ecam: ECAM,
    scan_last_bus: 0,
    io_shift: 0,
    optional: &[super::NET_SERVICE],
};
/// The ENA function: Amazon's vendor id and device 0xec20 (`pci.txt` of the
/// fixtures), the first and only one.
pub const ENA_ID: u32 = 0x1d0f_ec20;
/// The bytes of BAR 0 of the ENA the service maps: the registers and the
/// doorbells lie in the first 16 KiB (`iomem.txt` of the fixtures).
const ENA_BAR_LEN: u64 = 4 * PAGE;
/// The command word of a function.
const COMMAND: u64 = 4;
/// The stop of the ENA: bus mastering and memory decoding off (the command
/// word 0 of function 0, through the page of its configuration in ECAM), so
/// that the device writes no frame the allocator gives back. That the device
/// stops DMA at once on it is the question the next step settles by killing
/// the service in the middle of the receiving of frames (the note
/// `2026-11-13-aws-ena.md`, section 2).
static ENA_STOP: [Write; 1] = [Write {
    window: "ecam",
    offset: COMMAND,
    bits: 32,
    value: 0,
    settled: 0xFFFF,
    only_if: None,
}];
/// The memory of the admin structures: one uncached object of 128 KiB (order
/// 5), where the queue pairs of the next step go too.
const ENA_DMA: &[Dma] = &[Dma {
    name: "ena",
    size: 32 * PAGE,
    uncached: true,
    duplicate: false,
}];

/// The network service with the ENA of the instance: the windows are found
/// by the walk of the function (`At`), no interrupt is bound (the device is
/// polled), and the record is optional.
pub const NET: Record = Record {
    windows: &[
        Window {
            name: "bar",
            base: 0,
            len: ENA_BAR_LEN,
            duplicate: false,
            at: At::Bar {
                id: ENA_ID,
                index: 0,
                bar: 0,
            },
        },
        Window {
            name: "ecam",
            base: 0,
            len: PAGE,
            duplicate: false,
            at: At::Config {
                id: ENA_ID,
                index: 0,
            },
        },
    ],
    bindings: &[],
    connects: &[],
    args: &[],
    dma: ENA_DMA,
    quiesce: &ENA_STOP,
    restart: Restart::Never,
    waits: &[],
    ..super::net::NETD
};

/// The kind byte of `uart`'s arguments: a 16550 that is polled.
const KIND_16550: u8 = 1;

/// The register shift and access width of the console, from the same
/// SPCR: byte registers one apart.
const SHIFT: u8 = 0;
const WIDTH: u8 = 1;

const ARGS: [u8; 11] = {
    let base = SPCR_PORT.to_le_bytes();
    [
        base[0], base[1], base[2], base[3], base[4], base[5], base[6], base[7], KIND_16550, SHIFT,
        WIDTH,
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
        at: crate::table::At::Fixed,
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

const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The record of `table` named `name`: the records of the shell's table are
/// chosen by name, so that a change of their order elsewhere cannot change this
/// image.
const fn named(table: &[Record], name: &str) -> Record {
    let mut i = 0;
    while i < table.len() {
        if same(table[i].name, name) {
            return table[i];
        }
        i += 1;
    }
    panic!("the table has no record of that name")
}

const DIALOG: &[Record] = super::ramfs::BUSYBOX_DIALOG_TABLE;

pub const TABLE: &[Record] = &[
    CONSOLE,
    named(DIALOG, "ramfs"),
    named(DIALOG, "posix"),
    // No PL031 on EC2: the clock starts at the time the image was built.
    named(super::ramfs::POSIX_ABI_TABLE, "clock"),
    named(DIALOG, "pipe"),
    // The image of this table has no entropy service.
    Record {
        connects: &["ramfs", "tty", "pipe", "clock", "posix"],
        ..named(DIALOG, "busybox-probe")
    },
    named(DIALOG, "tty"),
    NET,
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
        // The access size of the SPCR is one byte, the registers one apart.
        assert_eq!((CONSOLE.args[9], CONSOLE.args[10]), (0, 1));
        assert_eq!(spcr[43], 1, "GAS access size: byte");
        assert!(CONSOLE.bindings.is_empty());
    }

    #[test]
    fn the_records_are_the_ones_the_names_say() {
        let names: Vec<&str> = TABLE.iter().map(|r| r.name).collect();
        assert_eq!(
            names,
            [
                "uart",
                "ramfs",
                "posix",
                "clock",
                "pipe",
                "busybox-probe",
                "tty",
                "net"
            ]
        );
        // The posix record is the shell dialog's, with its larger quota; the
        // clock is the plain one, without the PL031's window.
        let posix = TABLE.iter().find(|r| r.name == "posix").unwrap();
        assert!(posix.quota > super::super::ramfs::POSIX_ABI_TABLE[1].quota);
        let clock = TABLE.iter().find(|r| r.name == "clock").unwrap();
        assert!(clock.windows.is_empty());
        let launcher = TABLE.iter().find(|r| r.name == "busybox-probe").unwrap();
        assert_eq!(launcher.program, "ash-launcher");
    }

    #[test]
    fn no_record_connects_to_net_or_entropy_and_only_net_has_pci_windows() {
        for r in TABLE {
            assert!(!r.connects.contains(&"net") && !r.connects.contains(&"entropy"));
            if r.name == "net" {
                assert!(r.windows.iter().all(|w| w.at != At::Fixed));
            } else {
                assert!(r.windows.iter().all(|w| w.base == SPCR_PORT));
                assert!(r.bindings.is_empty());
            }
        }
    }

    #[test]
    fn the_platform_is_the_mcfg_of_a_t4g_and_its_walk_reaches_every_function() {
        let mcfg = include_bytes!(
            "../../../../boot/firmware-tree/tests/fixtures/graviton-t4g/04-MCFG.bin"
        );
        // The allocation structure follows the 36-byte header and 8 reserved
        // bytes: base (8), segment (2), first bus, last bus.
        let base = u64::from_le_bytes(mcfg[44..52].try_into().unwrap());
        assert_eq!(base, ECAM.base);
        assert_eq!((mcfg[54], mcfg[55]), (ECAM.first_bus, ECAM.last_bus));
        assert_eq!(
            PLATFORM.scan_last_bus, 0,
            "the walk covers bus 0, which the MCFG range holds"
        );
        // Every function of the fixture is on bus 0, and none is a bridge to
        // another bus (class 0x0604): the walk of bus 0 is the walk of all.
        let pci =
            include_str!("../../../../boot/firmware-tree/tests/fixtures/graviton-t4g/pci.txt");
        let mut functions = 0;
        for line in pci.lines().filter(|l| l.starts_with("0000:")) {
            assert!(line.starts_with("0000:00:"), "{line}");
            assert!(!line.contains("class=0x0604"), "{line}");
            functions += 1;
        }
        assert_eq!(functions, 5);
        // The ENA's id is the one of the fixture.
        assert!(pci.contains("vendor=0x1d0f device=0xec20"));
        assert_eq!(ENA_ID, 0x1d0f_ec20);
    }

    #[test]
    fn the_net_record_gets_the_bar_of_the_fixtures_iomem_and_its_page_of_ecam() {
        let mut config = pci::fake::t4g();
        let store: &'static mut crate::resolve::Store =
            Box::leak(Box::new(crate::resolve::Store::EMPTY));
        let found = crate::resolve::resolve(TABLE, &PLATFORM, &mut config, store).unwrap();
        let net = found.table.iter().find(|r| r.name == "net").unwrap();
        // `iomem.txt`: 80004000-80007fff : 0000:00:05.0.
        let iomem =
            include_str!("../../../../boot/firmware-tree/tests/fixtures/graviton-t4g/iomem.txt");
        assert!(iomem.contains("80004000-80007fff : 0000:00:05.0"));
        let bar = net.windows.iter().find(|w| w.name == "bar").unwrap();
        assert_eq!((bar.base, bar.len), (0x8000_4000, 0x4000));
        let ecam = net.windows.iter().find(|w| w.name == "ecam").unwrap();
        assert_eq!((ecam.base, ecam.len), (0x2000_0000 + (5 << 15), PAGE));
        assert!(net.windows.iter().all(|w| w.at == At::Fixed));
        // The resolved table is a good table, and the other records are untouched.
        assert!(crate::table::check(found.table).is_ok());
        assert_eq!(found.table.len(), TABLE.len());
        assert!(found.skipped.iter().all(Option::is_none));
    }

    #[test]
    fn without_the_ena_the_net_record_is_left_out_with_its_cause_and_the_table_stays_whole() {
        let mut config = pci::fake::Fake::default();
        config.function(pci::Address::new(0, 1, 0), 0x1d0f, 0x8250, 0x070003, false);
        let store: &'static mut crate::resolve::Store =
            Box::leak(Box::new(crate::resolve::Store::EMPTY));
        let found = crate::resolve::resolve(TABLE, &PLATFORM, &mut config, store).unwrap();
        assert!(found.table.iter().all(|r| r.name != "net"));
        assert_eq!(found.table.len(), TABLE.len() - 1);
        let left = found.skipped[0].unwrap();
        assert_eq!(left.record, "net");
        assert!(matches!(
            left.cause,
            crate::resolve::Cause::NoFunction {
                id: ENA_ID,
                index: 0
            }
        ));
        assert!(crate::table::check(found.table).is_ok());
    }

    #[test]
    fn the_net_record_stops_the_function_by_its_command_word() {
        let q = NET.quiesce[0];
        assert_eq!((q.window, q.offset, q.bits, q.value), ("ecam", 4, 32, 0));
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
