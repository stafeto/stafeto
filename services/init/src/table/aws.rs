// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the shell on EC2 (t4g.small): the dialog of
//! `ramfs::BUSYBOX_DIALOG_TABLE` with the 16550 the SPCR names for the
//! console, polled, and nothing that needs Virtio, NVMe or the network
//! device besides the ENA's service `net` (polled, optional): no Virtio
//! window. The entropy service has no driver here (the t4g has no device of
//! random bytes): the boot loader puts the seed it took from the firmware
//! in the device tree, the kernel gives it to init, and init to the
//! service (`ENTROPY`). The package service (`pkgd`) keeps its store in memory, on the
//! disk service over a memory object (`MEMBLK`, 256 MiB): the packages installed with
//! `pkg` are gone after a reboot, like every file of the image. The second EBS volume of
//! the image (`/dev/sdf`, 2 GiB) is the data volume: the disk service `datadisk` serves it
//! only when the name EBS gives it is `sdf`, `datafs` keeps the files of `/data` on it, and
//! `datakey` keeps the SSH host key there. An instance launched without that volume leaves
//! `datadisk` out and makes a new host key at each boot.

use super::{
    At, Binding, Confirm, Dma, GENERAL_CPUS, Kind, Record, Restart, Shares, Wait, Window, Write,
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
    optional: &[super::NET_SERVICE, "datadisk"],
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
    // `/etc/netd.conf` and `/etc/resolv.conf` (the boot profile of the file service), and
    // the key of the stack from the entropy service.
    connects: &["ramfs", "entropy"],
    args: &[],
    dma: ENA_DMA,
    quiesce: &ENA_STOP,
    start: &ENA_START,
    release: &ENA_RELEASE,
    // Init starts the service again after a failure (`FAILED`, 8) it cannot get over;
    // the driver tries three resets a minute before it gives up.
    restart: Restart::Always,
    waits: &[],
    // The consumers of the switch (`switch N` in `netd.conf`): the table of flows and the
    // translation tables of the rings of the consumers.
    quota: super::net::NETD.quota + super::net::SWITCH_QUOTA_PAGES * PAGE,
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
    budgets: &[],
    free: 0,
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

/// The entropy service with no driver to connect to: its source is the boot seed. With
/// no seed either, it says so and keeps every key waiting.
pub const ENTROPY: Record = Record {
    connects: &[],
    ..super::entropy::ENTROPY
};

/// The quota of a command: the launcher's, which the shell and every command it starts get
/// too, is the one of the images of `nginx-fast` (`FAST_COMMAND_QUOTA`): the master of
/// `nginx-fast` (6 MB of code and read-only data) and its workers run beside the shell, and
/// OpenSSL makes the certificate of the instance at its first boot.
pub const COMMAND_QUOTA: u64 = super::fstack::FAST_COMMAND_QUOTA;

/// The quotas of a command in the pool of the process service. The image of the try-out runs
/// at once the boot script and its waiting subshells (about six), the shell of the console,
/// nginx (a master and two workers), nginx-fast (a master and two workers), the SSH server and
/// its sessions (two processes each: the server's child and the shell it starts), and the
/// commands of the visitor (`pkg`, `openssl`, `curl`). Twenty-four hold that with room for
/// four sessions; a fork that finds the pool empty fails with an out-of-memory error and the
/// system goes on (a login then gets no answer until another session ends).
pub const COMMANDS: u64 = 24;

/// The process service of the shell on EC2: the pool of the shell's image and `COMMANDS`
/// quotas of a command.
pub const PROCESS_SERVICE: Record = Record {
    quota: super::ramfs::POSIX_ABI_TABLE[1].quota
        + super::ramfs::BUSYBOX_DIALOG_POOL
        + COMMANDS * COMMAND_QUOTA,
    ..super::net::NET_PROCESS_SERVICE
};

/// How long the launcher waits for the host key service.
pub const DATAKEY_READY_MS: u32 = 30_000;

/// The launcher of the shell with a session with the network service: the shell and its
/// commands get the same (the launcher's connections are the shell's), and the quota of a
/// command that runs `nginx-fast` or links OpenSSL; and the entropy service, for getrandom
/// and the keys of the shell's programs. It runs the boot script `/etc/rc` beside the shell:
/// the script waits for the network itself, so the record needs no order beyond its session
/// with the service.
pub const LAUNCHER: Record = Record {
    args: super::net::RC_LAUNCH_ARGS,
    connects: &[
        "ramfs",
        "tty",
        "pipe",
        "clock",
        "posix",
        "entropy",
        super::NET_SERVICE,
        "pkgd",
    ],
    quota: COMMAND_QUOTA,
    // The shell starts once `pkgd` says READY (the store is formatted at the start); past
    // this it starts without waiting, as on the base image.
    //
    // The boot script starts Dropbear with the key `datakey` has put into `/etc/dropbear`, so
    // the launcher waits for that service too (30 s: the first start formats the volume).
    waits: &[
        Wait {
            service: "pkgd",
            deadline_ms: super::base::PKGD_READY_MS,
        },
        Wait {
            service: "datakey",
            deadline_ms: DATAKEY_READY_MS,
        },
    ],
    ..named(DIALOG, "busybox-probe")
};

/// The NVMe function of an EBS volume: Amazon's vendor id and device 0x8061 (`pci.txt` of the
/// fixtures), one function per volume in the order of the walk.
pub const EBS_NVME_ID: u32 = 0x1d0f_8061;
/// The walk index of the data volume: the root volume is the function 0 (00:04.0) and the volume
/// attached as `/dev/sdf` the function 1 (00:1f.0) in the measurement of the fixtures
/// (`nvme-map.txt`). The index only places the record; the name EBS writes into Identify
/// Controller decides which volume the service serves, so a volume in the wrong function is left
/// alone.
const DATA_INDEX: u8 = 1;
/// The own arguments of `datadisk` after the addresses of its DMA objects: the kind 2 (the name of
/// the block device in Identify Controller bytes 3072..3104) and the name `sdf`.
const DATADISK_WANT: &[u8] = b"\x02sdf";
const DATADISK_WINDOWS: &[Window] = &[
    Window {
        name: "bar",
        base: 0,
        len: 4 * PAGE,
        duplicate: false,
        at: At::Bar {
            id: EBS_NVME_ID,
            index: DATA_INDEX,
            bar: 0,
        },
    },
    Window {
        name: "ecam",
        base: 0,
        len: PAGE,
        duplicate: false,
        at: At::Config {
            id: EBS_NVME_ID,
            index: DATA_INDEX,
        },
    },
];
const DATADISK_BINDINGS: &[Binding] = &[
    Binding::msi_of("irq0", EBS_NVME_ID, DATA_INDEX, 0),
    Binding::msi_of("irq1", EBS_NVME_ID, DATA_INDEX, 1),
];

/// The disk service of the data volume: the NVMe service of the QEMU machine's data disk with the
/// function of the second EBS volume and the check of its name. It is optional on this platform
/// (`PLATFORM.optional`): with no second volume init leaves it out and `datafs` says `no disk`.
pub const DATADISK: Record = Record {
    name: "datadisk",
    windows: DATADISK_WINDOWS,
    bindings: DATADISK_BINDINGS,
    args: DATADISK_WANT,
    ..super::pkg::NVME_QEMU_BLK
};

/// The GPIO block of a t4g.small, `GPO0` in its DSDT (`ARMH0061`, a PL061): its page and its
/// interrupt, level-triggered, GSIV 39 (INTID 39, SPI 7). `_AEI` gives pin 3 the power button
/// (`_E03`) as a rising-edge GpioInt. QEMU `virt` has the block at the same place on the same
/// line (`fixtures/graviton-t4g/DSDT.aml`, bytes 3870 to 4060).
pub const GPIO_BASE: u64 = 0x0903_0000;
pub const GPIO_LINE: u32 = 39;
/// GPIOIE of the PL061: the interrupt mask the stop clears, so that no pin of the block raises
/// the line once the service is gone.
const GPIO_IE: u64 = 0x410;

/// The service of the power button (services/power): the window over the GPIO page and the
/// binding of its line. It is the one record init answers SHUTDOWN for (`POWER_SERVICE`), so
/// it is a native service that connects to nothing. A stop of its instance masks the block's
/// interrupts.
pub const POWER: Record = Record {
    name: super::POWER_SERVICE,
    program: "power",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 45,
    ceiling: 45,
    quota: 32 * PAGE,
    handle_limit: 32,
    restart: Restart::Always,
    console: true,
    log: false,
    args: &[],
    windows: &[Window {
        name: "regs",
        base: GPIO_BASE,
        len: PAGE,
        duplicate: false,
        at: At::Fixed,
    }],
    bindings: &[Binding {
        name: "irq",
        line: GPIO_LINE,
        edge: false,
        of: None,
    }],
    quiesce: &[Write {
        window: "regs",
        offset: GPIO_IE,
        bits: 32,
        value: 0,
        settled: 0xFF,
        only_if: None,
        confirm: None,
    }],
    ..CONSOLE
};

pub const TABLE: &[Record] = &[
    CONSOLE,
    named(DIALOG, "ramfs"),
    // The process service with the pool of the shell's image and the quotas of a command of
    // the try-out (nginx, nginx-fast, the SSH server and its sessions).
    PROCESS_SERVICE,
    // No PL031 on EC2: the clock starts at the time of the firmware, which the EFI loader writes
    // into the file `boot-time` of the image (UEFI GetTime); without it, at 2026-01-01.
    named(super::ramfs::POSIX_ABI_TABLE, "clock"),
    named(DIALOG, "pipe"),
    ENTROPY,
    LAUNCHER,
    named(DIALOG, "tty"),
    NET,
    super::pkg::MEMBLK,
    super::pkg::PKGD,
    DATADISK,
    super::pkg::DATAFS,
    super::pkg::DATAKEY,
    POWER,
];

/// The closest image on QEMU to the table above (`cargo xtask net-try`): the services of the
/// table of EC2 with the PL011 for the console, the Virtio RNG for the entropy service, and the
/// network service on Virtio over QEMU's user network with the switch (`netd.conf` has
/// `switch 8`), in the order of the shell's image with the network.
pub const QEMU_TABLE: &[Record] = &[
    super::net::NET_TABLE[0],
    super::net::NET_TABLE[1],
    PROCESS_SERVICE,
    super::net::NET_TABLE[3],
    super::net::NET_TABLE[4],
    LAUNCHER,
    super::net::NET_TABLE[6],
    super::net::NET_TABLE[7],
    super::net::NET_TABLE[8],
    super::net::NETD_SWITCH,
    super::pkg::MEMBLK,
    super::pkg::PKGD,
    super::pkg::NVME_QEMU_DATA,
    super::pkg::DATAFS,
    super::pkg::DATAKEY,
    POWER,
];

/// The pages of RAM of a t4g.small: 2 GiB.
#[cfg(test)]
const T4G_SMALL_PAGES: u64 = (2u64 << 30) / PAGE;

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
                "entropy",
                "busybox-probe",
                "tty",
                "net",
                "blk",
                "pkgd",
                "datadisk",
                "datafs",
                "datakey",
                "power"
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
        // The launcher runs the boot script of the image next to the shell.
        assert_eq!(launcher.args, b"ash-launch\0/etc/rc\0");
    }

    #[test]
    fn only_the_launcher_connects_to_net_the_launcher_and_net_to_entropy_and_only_net_and_datadisk_have_pci_windows()
     {
        for r in TABLE {
            // No driver of random bytes: the boot seed is the source.
            assert!(!r.connects.contains(&"rng"));
            assert_eq!(
                r.connects.contains(&"entropy"),
                r.name == "busybox-probe" || r.name == "net",
                "{}",
                r.name
            );
            assert_eq!(
                r.connects.contains(&"net"),
                r.name == "busybox-probe",
                "{}",
                r.name
            );
            if r.name == "net" || r.name == "datadisk" {
                assert!(r.windows.iter().all(|w| w.at != At::Fixed));
            } else if r.name == "power" {
                assert!(r.windows.iter().all(|w| w.base == GPIO_BASE));
                assert_eq!(r.bindings.len(), 1);
            } else {
                assert!(r.windows.iter().all(|w| w.base == SPCR_PORT));
                assert!(r.bindings.is_empty());
            }
        }
    }

    /// The window, the line and the pin of the power button are the bytes of the DSDT of the
    /// t4g sample: the device `GPO0` (`ARMH0061`) with Memory32Fixed 0x09030000 of 0x1000 bytes,
    /// the Extended Interrupt 39 (level), and `_AEI` with a rising-edge GpioInt on pin 3 whose
    /// method `_E03` notifies the power button.
    #[test]
    fn the_power_record_is_the_gpio_block_the_dsdt_names_with_its_interrupt_and_pin() {
        let dsdt =
            include_bytes!("../../../../boot/firmware-tree/tests/fixtures/graviton-t4g/DSDT.aml");
        let find = |needle: &[u8], from: usize| {
            from + dsdt[from..]
                .windows(needle.len())
                .position(|w| w == needle)
                .expect("the bytes are in the DSDT")
        };
        let device = find(b"GPO0", 0);
        assert!(dsdt[device..].starts_with(b"GPO0"));
        let hid = find(b"ARMH0061", device);
        // Memory32Fixed (0x86, length 9): read-write, base, length.
        let mem = find(&[0x86, 0x09, 0x00, 0x01], hid);
        let base = u32::from_le_bytes(dsdt[mem + 4..mem + 8].try_into().unwrap());
        let len = u32::from_le_bytes(dsdt[mem + 8..mem + 12].try_into().unwrap());
        assert_eq!((u64::from(base), u64::from(len)), (GPIO_BASE, PAGE));
        // Extended Interrupt (0x89): flags 0x01 (consumer, level, active high), one
        // interrupt, its number.
        let irq = find(&[0x89, 0x06, 0x00, 0x01, 0x01], mem);
        let line = u32::from_le_bytes(dsdt[irq + 5..irq + 9].try_into().unwrap());
        assert_eq!(line, GPIO_LINE);
        // `_AEI`: GpioInt (0x8C) with edge, active high in its interrupt flags (0x0001), and
        // the pin of its table, for the pins 3 and 4; `_E03` notifies PWRB.
        let aei = find(b"_AEI", irq);
        let gpio = find(&[0x8C, 0x1B, 0x00, 0x01, 0x00], aei);
        assert_eq!(&dsdt[gpio + 7..gpio + 9], [0x01, 0x00], "edge, active high");
        let pin = u16::from_le_bytes(dsdt[gpio + 0x17..gpio + 0x19].try_into().unwrap());
        assert_eq!(u32::from(pin), power::PIN);
        let e03 = find(b"_E03", aei);
        assert!(dsdt[e03..e03 + 16].windows(4).any(|w| w == b"PWRB"));
        // The record has that window and that line, level, as a native service.
        for table in [TABLE, QEMU_TABLE] {
            let record = table.iter().find(|r| r.name == "power").unwrap();
            assert_eq!(record.windows.len(), 1);
            assert_eq!(
                (record.windows[0].base, record.windows[0].len),
                (base.into(), len.into())
            );
            assert_eq!(
                record.bindings,
                [Binding {
                    name: "irq",
                    line,
                    edge: false,
                    of: None
                }]
            );
            assert!(!record.is_client() && !record.is_posix() && record.connects.is_empty());
            assert!(record.args.is_empty());
            assert_eq!(record.program, "power");
        }
        assert_eq!((power::BASE, power::LINE), (GPIO_BASE, GPIO_LINE));
        // The stop masks every pin of the block.
        assert_eq!(
            POWER
                .quiesce
                .iter()
                .map(|w| (w.window, w.offset, w.value))
                .collect::<Vec<_>>(),
            [("regs", power::GPIOIE as u64, 0)]
        );
    }

    /// The tables with `power` pass the check of the name (`check_power`), and the stop goes
    /// in waves with `power` in the first and the console's driver last.
    #[test]
    fn power_stops_first_and_the_console_last_on_both_tables() {
        for table in [TABLE, QEMU_TABLE] {
            assert!(crate::table::check(table).is_ok());
            let alive = (1u32 << table.len()) - 1;
            let first = crate::shutdown::wave(table, alive);
            let names = |mask: u32| -> Vec<&str> {
                (0..table.len())
                    .filter(|p| mask & (1 << p) != 0)
                    .map(|p| table[p].name)
                    .collect()
            };
            assert!(
                names(first).contains(&"power"),
                "power has no record that connects to it"
            );
            let mut left = alive & !first;
            let mut last = Vec::new();
            while left != 0 {
                let wave = crate::shutdown::wave(table, left);
                assert_ne!(wave, 0);
                last = names(wave);
                left &= !wave;
            }
            assert_eq!(last, ["uart"]);
        }
    }

    #[test]
    fn a_power_record_that_is_a_client_or_connects_to_the_process_service_is_refused() {
        let mut client = *TABLE.iter().find(|r| r.name == "power").unwrap();
        client.kind = Kind::Client;
        client.windows = &[];
        client.bindings = &[];
        client.quiesce = &[];
        let bad: Vec<Record> = TABLE
            .iter()
            .map(|r| if r.name == "power" { client } else { *r })
            .collect();
        assert!(matches!(
            crate::table::check(&bad),
            Err(crate::table::TableError::Power { .. })
        ));
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
        // The service has the second channel for them, the file service for its settings and
        // the entropy service for its key.
        assert!(crate::table::line_thread(net));
        assert_eq!(net.connects, ["ramfs", "entropy"]);
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
        // The volume's record is left out as well: no function of its id is there.
        assert_eq!(found.table.len(), TABLE.len() - 2);
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

    /// The pages the table holds for its records: each record's quota and its DMA objects
    /// (init pays for them apart from the quota).
    fn pages_held(table: &[Record]) -> u64 {
        table
            .iter()
            .map(|r| r.quota / PAGE + r.dma.iter().map(|d| d.size / PAGE).sum::<u64>())
            .sum()
    }

    /// The memory budget of the try-out on a t4g.small (2 GiB): the quotas and DMA objects of
    /// the table, the boot image (about 96 MiB with nginx, nginx-fast, OpenSSL, curl and
    /// Dropbear: its files are in the memory of init), the kernel and its tables (64 MiB), and
    /// the 16 384 pages init keeps free after the services started (`cargo xtask
    /// pkg-identity` holds the base image to the same) all fit in the 524 288 pages.
    #[test]
    fn the_quotas_of_the_table_with_nginx_and_nginx_fast_fit_a_t4g_small() {
        const IMAGE_PAGES: u64 = (96 << 20) / PAGE;
        const KERNEL_PAGES: u64 = (64 << 20) / PAGE;
        const INIT_FREE: u64 = 16_384;
        let held = pages_held(TABLE);
        let need = held + IMAGE_PAGES + KERNEL_PAGES + INIT_FREE;
        assert!(
            need <= T4G_SMALL_PAGES,
            "the table holds {held} pages and with the image, the kernel and init's free pages {need} of the {T4G_SMALL_PAGES} of a t4g.small"
        );
        // The pool holds the quotas of a command the plan counts for.
        let pool = TABLE.iter().find(|r| r.name == "posix").unwrap();
        assert!(pool.quota >= COMMANDS * COMMAND_QUOTA);
        let launcher = TABLE.iter().find(|r| r.name == "busybox-probe").unwrap();
        // nginx-fast's master and worker run under the launcher's quota.
        assert_eq!(launcher.quota, super::super::fstack::FAST_COMMAND_QUOTA);
        // The memory disk of 256 MiB and the package service are in the sum above.
        assert!(
            TABLE
                .iter()
                .any(|r| r.name == "blk" && r.quota >= 256 << 20)
        );
        assert!(TABLE.iter().any(|r| r.name == "pkgd"));
        // The switch of the network service has the pages of its flows and rings.
        let net = TABLE.iter().find(|r| r.name == "net").unwrap();
        assert_eq!(
            net.quota,
            super::super::net::NETD.quota + super::super::net::SWITCH_QUOTA_PAGES * PAGE
        );
    }

    /// The table of the closest image on QEMU is a good table, has the records of EC2's in the
    /// order of the shell's image with the network, and holds the same memory but for the
    /// network service's.
    #[test]
    fn the_qemu_table_is_ec2s_with_the_pl011_the_virtio_rng_and_the_virtio_net() {
        assert!(crate::table::check(QEMU_TABLE).is_ok());
        let names: Vec<&str> = QEMU_TABLE.iter().map(|r| r.name).collect();
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
                "rng",
                "entropy",
                "net",
                "blk",
                "pkgd",
                "datadisk",
                "datafs",
                "datakey",
                "power"
            ]
        );
        let of =
            |table: &'static [Record], name: &str| *table.iter().find(|r| r.name == name).unwrap();
        for name in ["posix", "busybox-probe", "blk", "pkgd"] {
            assert_eq!(of(QEMU_TABLE, name).quota, of(TABLE, name).quota, "{name}");
        }
        // The network service has the same quota with the switch on either device.
        assert_eq!(of(QEMU_TABLE, "net").quota, of(TABLE, "net").quota);
        assert_eq!(
            of(QEMU_TABLE, "busybox-probe").args,
            b"ash-launch\0/etc/rc\0"
        );
        assert!(pages_held(QEMU_TABLE) <= pages_held(TABLE) + 1_000);
    }

    /// The own arguments of `nvme-blk` as the service reads them: the addresses of its DMA
    /// objects, then the record's bytes.
    fn own_arguments(record: &Record) -> Vec<u8> {
        let mut own = vec![0u8; nvme_blk::ADDRESS_BYTES];
        own.extend_from_slice(record.args);
        own
    }

    /// Identify Controller of an EBS volume with `name` in bytes 3072..3104, padded with spaces.
    fn identify(name: &[u8]) -> [u8; 4096] {
        let mut id = [0u8; 4096];
        id[3072..3104].fill(b' ');
        id[3072..3072 + name.len()].copy_from_slice(name);
        id
    }

    #[test]
    fn datadisk_serves_the_volume_named_sdf_and_no_other() {
        let want = nvme_blk::Want::parse(&own_arguments(&DATADISK));
        assert_eq!(DATADISK.args[0], nvme_blk::WANT_EBS_NAME);
        assert!(nvme_blk::identity(&identify(b"sdf"), &want));
        assert!(!nvme_blk::identity(&identify(b"xvda"), &want));
        assert!(!nvme_blk::identity(&identify(b"sda1"), &want));
        assert!(!nvme_blk::identity(&[0; 4096], &want));
        // The QEMU record of the same name asks for a serial number: an EBS name cannot open it.
        let qemu = nvme_blk::Want::parse(&own_arguments(&super::super::pkg::NVME_QEMU_DATA));
        assert!(!nvme_blk::identity(&identify(b"sdf"), &qemu));
    }

    #[test]
    fn datadisk_is_the_second_nvme_function_of_the_instance() {
        let mut config = pci::fake::t4g();
        let store: &'static mut crate::resolve::Store =
            Box::leak(Box::new(crate::resolve::Store::EMPTY));
        let found = crate::resolve::resolve(TABLE, &PLATFORM, &mut config, store).unwrap();
        let disk = found.table.iter().find(|r| r.name == "datadisk").unwrap();
        // `nvme-map.txt`: 00:04.0 is the root volume (walk index 0), 00:1f.0 the volume of
        // /dev/sdf (index 1); `pci.txt`: its BAR at 0x80000000, 16 KiB.
        let nvme_map =
            include_str!("../../../../boot/firmware-tree/tests/fixtures/graviton-t4g/nvme-map.txt");
        assert!(nvme_map.contains("pci=0000:00:1f.0 role=sdf"));
        let bar = disk.windows.iter().find(|w| w.name == "bar").unwrap();
        assert_eq!((bar.base, bar.len), (0x8000_0000, 0x4000));
        let ecam = disk.windows.iter().find(|w| w.name == "ecam").unwrap();
        assert_eq!(ecam.base, ECAM.base + (0x1f << 15));
        let events: Vec<_> = disk.bindings.iter().map(|b| b.event()).collect();
        assert_eq!(events, [Some((0xf8, 0)), Some((0xf8, 1))]);
        assert!(found.skipped.iter().all(Option::is_none));
        assert!(crate::table::check(found.table).is_ok());
        // The net record is on its own function and the two volumes never share one.
        assert_eq!(EBS_NVME_ID, 0x1d0f_8061);
    }

    #[test]
    fn an_instance_without_the_second_volume_leaves_datadisk_out_and_datafs_goes_on() {
        let mut config = pci::fake::Fake::default();
        config.function(pci::Address::new(0, 4, 0), 0x1d0f, 0x8061, 0x010802, false);
        config.mem32(pci::Address::new(0, 4, 0), 0, 0x8000_8000, 0x4000);
        config.function(pci::Address::new(0, 5, 0), 0x1d0f, 0xec20, 0x020000, false);
        config.mem32(pci::Address::new(0, 5, 0), 0, 0x8000_4000, 0x4000);
        let store: &'static mut crate::resolve::Store =
            Box::leak(Box::new(crate::resolve::Store::EMPTY));
        let found = crate::resolve::resolve(TABLE, &PLATFORM, &mut config, store).unwrap();
        assert!(found.table.iter().all(|r| r.name != "datadisk"));
        let left = found.skipped.iter().flatten().next().unwrap();
        assert_eq!(left.record, "datadisk");
        let datafs = found.table.iter().find(|r| r.name == "datafs").unwrap();
        assert!(datafs.connects.is_empty());
        assert!(found.table.iter().any(|r| r.name == "datakey"));
        assert!(crate::table::check(found.table).is_ok());
    }

    #[test]
    fn only_datakey_connects_to_datafs_on_both_tables() {
        for table in [TABLE, QEMU_TABLE] {
            let clients: Vec<&str> = table
                .iter()
                .filter(|r| r.connects.contains(&"datafs"))
                .map(|r| r.name)
                .collect();
            assert!(clients.is_empty() || clients == ["datakey"], "{clients:?}");
            // The launcher is the POSIX launcher: it only waits for the key service.
            let launcher = table.iter().find(|r| r.name == "busybox-probe").unwrap();
            assert!(!launcher.connects.contains(&"datafs"));
            assert!(!launcher.connects.contains(&"datakey"));
        }
    }

    #[test]
    fn the_launcher_waits_for_pkgd_and_for_the_host_key_service() {
        for table in [TABLE, QEMU_TABLE] {
            let launcher = table.iter().find(|r| r.name == "busybox-probe").unwrap();
            let waited: Vec<_> = launcher.waits.iter().map(|w| w.service).collect();
            assert_eq!(waited, ["pkgd", "datakey"]);
            let datakey = table.iter().find(|r| r.name == "datakey").unwrap();
            assert!(datakey.waits.is_empty());
            assert!(!datakey.is_client());
        }
    }

    /// The budgets on CPU 0 of the EC2 table: the network service 40 % and 20 %, the file
    /// service 5 %, the pipe service 1.5 %, the terminal service 1.5 %, the NVMe service 1 %
    /// and the data file service 1 %, and the reserve of 3 % for the process service and the
    /// package service: 73 % under the 75 % the table allows.
    #[test]
    fn the_budgets_of_cpu_zero_on_ec2_are_73_percent_under_the_cap_of_75() {
        for table in [TABLE, QEMU_TABLE] {
            let on_zero: u64 = table
                .iter()
                .flat_map(|r| r.budgets.iter())
                .filter(|b| b.cpu == 0)
                .map(crate::table::Budget::share_ppm)
                .sum();
            assert_eq!(
                on_zero + crate::table::CPU0_RESERVE_PPM,
                730_000,
                "40 + 20 + 5 + 1.5 + 1.5 + 1 + 1 + 3 per cent"
            );
            assert!(on_zero + crate::table::CPU0_RESERVE_PPM <= crate::table::BUDGET_SHARE_MAX_PPM);
        }
        for name in ["datadisk", "datafs"] {
            let r = TABLE.iter().find(|r| r.name == name).unwrap();
            assert_eq!(r.budgets.iter().map(|b| b.share_ppm()).sum::<u64>(), 10_000);
        }
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
