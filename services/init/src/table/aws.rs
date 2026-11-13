// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the shell on EC2 (t4g.small): the dialog of
//! `ramfs::BUSYBOX_DIALOG_TABLE` with the 16550 the SPCR names for the
//! console, polled, and nothing that needs Virtio, NVMe or the network
//! device besides the ENA's service `net` (polled, optional): no entropy
//! service, no Virtio window.

use super::{
    At, Binding, Confirm, Dma, GENERAL_CPUS, Kind, Record, Restart, Shares, Window, Write,
};
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
/// The registers of BAR 0 the stop writes: `DEV_CTL` and `DEV_STS`, and the
/// words of them (`lib/ena/src/regs.rs`).
const DEV_CTL: u64 = 0x54;
const DEV_STS: u64 = 0x58;
/// `DEV_CTL`: the reset bit with the reason SHUTDOWN (11) in bits 31:28.
const RESET_SHUTDOWN: u32 = 1 | 11 << 28;
/// `DEV_STS.RESET_IN_PROGRESS`.
const IN_PROGRESS: u32 = 0x8;
/// The stop of the ENA, in its order: the device is reset through BAR 0 (the reset
/// bit, then the device's own acknowledgement in `DEV_STS`, then the bit
/// cleared and the end of the reset in `DEV_STS`). `DEV_CTL` is not read back
/// (`settled` 0): the device may not hold what is written to it. When a
/// confirmation fails, init keeps the DMA object and marks the record broken.
static ENA_STOP: [Write; 2] = [
    Write {
        window: "bar",
        offset: DEV_CTL,
        bits: 32,
        value: RESET_SHUTDOWN,
        settled: 0,
        only_if: None,
        confirm: Some(Confirm {
            window: "bar",
            offset: DEV_STS,
            mask: IN_PROGRESS,
            value: IN_PROGRESS,
        }),
    },
    Write {
        window: "bar",
        offset: DEV_CTL,
        bits: 32,
        value: 0,
        settled: 0,
        only_if: None,
        confirm: Some(Confirm {
            window: "bar",
            offset: DEV_STS,
            mask: IN_PROGRESS,
            value: 0,
        }),
    },
];
/// The command word of function 0 goes to 0 (bus mastering and memory decoding
/// off, through the page of its configuration in ECAM) after the reset, and also
/// when a step of the reset did not confirm: the device writes no frame once init
/// lets the DMA object go, and a device that did not stop is kept from mastering
/// the bus.
static ENA_RELEASE: [Write; 1] = [Write {
    window: "ecam",
    offset: COMMAND,
    bits: 32,
    value: 0,
    settled: 0xFFFF,
    only_if: None,
    confirm: None,
}];
/// The command word the start writes: memory decoding, bus mastering and INTx
/// off, as `pci::enable` sets them. The stop clears them, and init applies this
/// before each load of the service, so that the next instance reads BAR 0
/// and the device masters the bus.
const ENA_COMMAND: u32 = pci::MEMORY | pci::BUS_MASTER | pci::INTX_DISABLE;
static ENA_START: [Write; 1] = [Write {
    window: "ecam",
    offset: COMMAND,
    bits: 32,
    value: ENA_COMMAND,
    settled: ENA_COMMAND,
    only_if: None,
    confirm: None,
}];
/// The memory of the device: the admin structures and the queue pair in one uncached
/// object of 128 KiB (order 5; the admin structures take 12 KiB and the pair 16 KiB
/// from 16 KiB), and the 512 buffers of frames (`net`, 1 MiB, cached: the t4g has no
/// SMMU, the device addresses physical memory, and its DMA is coherent). The device
/// addresses both as the physical addresses init gives the service, `ena` first.
const ENA_DMA: &[Dma] = &[
    Dma {
        name: "ena",
        size: 32 * PAGE,
        uncached: true,
        duplicate: false,
    },
    Dma {
        name: "net",
        size: 256 * PAGE,
        uncached: false,
        duplicate: false,
    },
];

/// The two MSI-X vectors of the function: 0 for the admin queue and its events, 1 for
/// the pair. Each is an event of the function's MSI device, bound through the
/// switch thread's channel with the label of its binding.
const ENA_BINDINGS: &[Binding] = &[
    Binding::msi_of("irq0", ENA_ID, 0, 0),
    Binding::msi_of("irq1", ENA_ID, 0, 1),
];

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
    bindings: ENA_BINDINGS,
    // `/etc/netd.conf` and `/etc/resolv.conf` (the boot profile of the file service).
    connects: &["ramfs"],
    args: &[],
    dma: ENA_DMA,
    quiesce: &ENA_STOP,
    start: &ENA_START,
    release: &ENA_RELEASE,
    // Init starts the service again after a failure (`FAILED`, 8) it cannot get over;
    // the driver tries three resets a minute before it gives up.
    restart: Restart::Always,
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
    start: &[],
    release: &[],
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

/// The launcher of the shell with a session with the network service: the shell and its
/// commands get the same (the launcher's connections are the shell's), and the quota of a
/// command that links OpenSSL. No entropy service on EC2: the launcher does not name it.
const LAUNCHER: Record = Record {
    connects: &["ramfs", "tty", "pipe", "clock", "posix", super::NET_SERVICE],
    quota: super::net::NET_COMMAND_QUOTA,
    ..named(DIALOG, "busybox-probe")
};

pub const TABLE: &[Record] = &[
    CONSOLE,
    named(DIALOG, "ramfs"),
    // The process service with the pool of the shell's image with the network: `httpd` forks
    // a child for each connection.
    super::net::NET_PROCESS_SERVICE,
    // No PL031 on EC2: the clock starts at the time the image was built.
    named(super::ramfs::POSIX_ABI_TABLE, "clock"),
    named(DIALOG, "pipe"),
    // The image of this table has no entropy service.
    LAUNCHER,
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
    fn only_the_launcher_connects_to_net_none_to_entropy_and_only_net_has_pci_windows() {
        for r in TABLE {
            assert!(!r.connects.contains(&"entropy"));
            assert_eq!(
                r.connects.contains(&"net"),
                r.name == "busybox-probe",
                "{}",
                r.name
            );
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
    fn the_net_record_has_the_queues_object_the_buffers_and_the_two_vectors_of_the_function() {
        let mut config = pci::fake::t4g();
        let store: &'static mut crate::resolve::Store =
            Box::leak(Box::new(crate::resolve::Store::EMPTY));
        let found = crate::resolve::resolve(TABLE, &PLATFORM, &mut config, store).unwrap();
        let net = found.table.iter().find(|r| r.name == "net").unwrap();
        // The objects, in the order the service reads their addresses: the queues' memory
        // (uncached) and the 512 buffers (cached, 1 MiB).
        let names: Vec<_> = net
            .dma
            .iter()
            .map(|d| (d.name, d.size, d.uncached))
            .collect();
        assert_eq!(
            names,
            [("ena", 32 * PAGE, true), ("net", 256 * PAGE, false)]
        );
        // The admin structures (12 KiB) and the pair's queues (16 KiB from 16 KiB) fit the
        // first object.
        assert!(0x4000 + 0x4000 <= (32 * PAGE) as usize);
        // Two events of the MSI device of the function at 00:05.0 (RID 0x28), bound by
        // their order: vector 0 for the admin queue, vector 1 for the pair.
        let events: Vec<_> = net.bindings.iter().map(|b| (b.name, b.event())).collect();
        assert_eq!(
            events,
            [("irq0", Some((0x28, 0))), ("irq1", Some((0x28, 1)))]
        );
        assert_eq!(crate::table::msi_events(net, 0x28), 2);
        // The service has the second channel for them, and the file service for its settings.
        assert!(crate::table::line_thread(net));
        assert_eq!(net.connects, ["ramfs"]);
        // The 128 LPIs the kernel allows (a t4g gives 3 to this record at most).
        assert!(net.bindings.len() <= 128);
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
    fn the_net_record_resets_the_device_through_bar_0_and_clears_the_command_word_after() {
        let q = NET.quiesce;
        // The reset with its reason, confirmed by DEV_STS; then released, confirmed.
        assert_eq!(q.len(), 2);
        assert_eq!(
            (q[0].window, q[0].offset, q[0].value),
            ("bar", 0x54, 0xB000_0001)
        );
        assert_eq!(
            q[0].confirm.map(|c| (c.offset, c.mask, c.value)),
            Some((0x58, 8, 8))
        );
        assert_eq!((q[1].offset, q[1].value), (0x54, 0));
        assert_eq!(
            q[1].confirm.map(|c| (c.offset, c.mask, c.value)),
            Some((0x58, 8, 0))
        );
        // The command word goes to 0 after, whatever the confirmations showed.
        let r = NET.release;
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].window, r[0].offset, r[0].bits, r[0].value),
            ("ecam", 4, 32, 0)
        );
        // The start writes it back: memory, bus master, INTx disable.
        let s = NET.start;
        assert_eq!(s.len(), 1);
        assert_eq!(
            (s[0].window, s[0].offset, s[0].bits, s[0].value),
            ("ecam", 4, 32, 0x0406)
        );
        // The record is restarted by init after a failure.
        assert_eq!(NET.restart, Restart::Always);
    }

    /// A model of the ENA's command word and registers behind the windows of the
    /// record: BAR 0 reads all ones while memory decoding is off, as the device
    /// does, and the reset is acknowledged when `acknowledges`.
    struct Model {
        command: u32,
        reset: bool,
        acknowledges: bool,
        /// The order the accesses came in.
        log: Vec<String>,
    }

    impl Model {
        fn new() -> Self {
            Model {
                command: ENA_COMMAND,
                reset: false,
                acknowledges: true,
                log: Vec::new(),
            }
        }

        /// What a service reads of DEV_STS: all ones with decoding off.
        fn dev_sts(&self) -> u32 {
            if self.command & pci::MEMORY == 0 {
                0xFFFF_FFFF
            } else {
                u32::from(self.reset) * IN_PROGRESS
            }
        }
    }

    impl crate::device::Regs for Model {
        fn write(&mut self, _: &Record, q: &Write) -> bool {
            self.log
                .push(format!("{}@{:#x}={:#x}", q.window, q.offset, q.value));
            match (q.window, q.offset) {
                ("ecam", COMMAND) => {
                    self.command = q.value;
                    true
                }
                ("bar", DEV_CTL) if self.command & pci::MEMORY != 0 => {
                    self.reset = q.value & 1 != 0 && self.acknowledges;
                    true
                }
                _ => false,
            }
        }

        fn confirmed(&mut self, _: &Record, c: Confirm) -> bool {
            self.log.push(format!("confirm {:#x}", c.offset));
            self.dev_sts() & c.mask == c.value
        }

        fn gate_open(&mut self, _: &Record, _: crate::table::Gate) -> bool {
            true
        }
    }

    #[test]
    fn a_restarted_service_finds_decoding_and_bus_mastering_on() {
        let mut device = Model::new();
        assert!(crate::device::stop(&NET, &mut device));
        assert_eq!(device.command, 0);
        // Without the start the next instance reads all ones from BAR 0.
        assert_eq!(device.dev_sts(), 0xFFFF_FFFF);
        assert!(crate::device::start(&NET, &mut device));
        assert_eq!(device.command & (pci::MEMORY | pci::BUS_MASTER), 0x6);
        assert_ne!(device.dev_sts(), 0xFFFF_FFFF);
    }

    #[test]
    fn a_stop_whose_confirmation_fails_still_turns_bus_mastering_off() {
        let mut device = Model::new();
        device.acknowledges = false;
        assert!(!crate::device::stop(&NET, &mut device));
        assert_eq!(device.command & pci::BUS_MASTER, 0);
        assert_eq!(device.command, 0);
        // The first reset step did not confirm, so the second never went.
        assert_eq!(
            device.log,
            ["bar@0x54=0xb0000001", "confirm 0x58", "ecam@0x4=0x0"]
        );
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
