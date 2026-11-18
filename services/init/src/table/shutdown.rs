// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the probe of the stop of the system (feature
//! `table-shutdown`, `cargo xtask nvme-persist shutdown`): the PL011's driver, the
//! NVMe disk service of QEMU's machine with edk2 under the name `blk`, two
//! test services of tests/svc (`echo`, which ends at init's stop notice, and
//! `quiet`, which ignores it), and `power`, which opens a session with each
//! of them and asks init to stop the system. The waves are `power`; `echo`,
//! `quiet` and `blk`; the console's driver last.

use super::test::{WATCH, echo};
use super::{Kind, Record, Wait};
use crate::watch::Watch;

const MS: u64 = 1_000_000;

pub const TABLE: &[Record] = &[
    super::normal::TABLE[0],
    super::pkg::NVME_QEMU_BLK,
    echo("echo", 35, WATCH, b"e"),
    echo("quiet", 35, WATCH, b"q"),
    // It asks after it opened its sessions, which waits for the disk
    // service: the watchdog gives it that time.
    Record {
        console: true,
        connects: &["blk", "echo", "quiet"],
        kind: Kind::Service(Watch {
            period_ns: 20 * MS,
            deadline_ns: 20_000 * MS,
        }),
        ..echo("power", 30, WATCH, b"p")
    },
];

/// The two POSIX programs of tests/relibc-stop (the table allows one record with `root`): `handle` takes SIGTERM with a handler and exits,
/// `ignore` ignores it and is killed by the process service after its wait.
const fn posix_program(name: &'static str, args: &'static [u8], root: bool) -> Record {
    Record {
        name,
        program: "relibc-stop",
        root,
        args,
        connects: &["ramfs", "clock", "posix", "entropy"],
        quota: 512 * crate::PAGE,
        ..super::ramfs::POSIX
    }
}

/// The table of the probe of the stop handlers of `datafs` and of the process service (feature
/// `table-stop-handlers`, `cargo xtask nvme-persist stop-handlers`, with nvme-store): the PL011's
/// driver, the RAM files, the process and clock services, the entropy service on the boot seed, the
/// NVMe data disk with `datafs`, two POSIX programs, `stop-writer` and `power`. `stop-writer`
/// (tests/svc role `W`) waits for the file service, writes `/stop/f` through its session with no
/// sync and no close (or reads it back when an earlier boot left it) and keeps the session open
/// to the end; `power` (role `w`) asks it for an answer, waits a while, and asks init to stop the
/// system.
pub const STOP_TABLE: &[Record] = &[
    super::normal::TABLE[0],
    super::ramfs::RAM_CLOCKED,
    super::ramfs::POSIX_ABI_TABLE[1],
    super::ramfs::POSIX_ABI_TABLE[2],
    super::aws::ENTROPY,
    super::pkg::NVME_QEMU_DATA,
    super::pkg::DATAFS,
    posix_program("stop-handle", b"relibc-stop\0handle\0", true),
    posix_program("stop-ignore", b"relibc-stop\0ignore\0", false),
    // The writer is in the last tier of the stop (`log`: the tier of the console), so its session
    // and the file it holds open are still there when `datafs` gets its stop notice.
    Record {
        log: true,
        connects: &["datafs"],
        waits: &[Wait {
            service: "datafs",
            deadline_ms: 30_000,
        }],
        kind: Kind::Service(Watch {
            period_ns: 20 * MS,
            deadline_ns: 20_000 * MS,
        }),
        ..echo("stop-writer", 30, WATCH, b"W")
    },
    // It asks once the writer answered: the writer is a service with a wait of its own, so `power`
    // cannot wait for it by a record.
    Record {
        connects: &["stop-writer"],
        kind: Kind::Service(Watch {
            period_ns: 20 * MS,
            deadline_ns: 20_000 * MS,
        }),
        ..echo("power", 30, WATCH, b"w")
    },
];

/// The table of the probe of the power button (feature `table-power-button`, `cargo xtask
/// power-button`): the PL011's driver and the real service `power` (`aws::POWER`), on the
/// kernel booted with no firmware. QEMU `virt` routes the monitor's `system_powerdown` to
/// pin 3 of its PL061 only then; with edk2 and ACPI the machine has a GED device for it.
pub const POWER_BUTTON_TABLE: &[Record] = &[super::normal::TABLE[0], super::aws::POWER];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown;

    #[test]
    fn the_table_passes_the_check_and_stops_in_the_waves_the_probe_expects() {
        assert!(crate::table::check(TABLE).is_ok());
        let alive = (1u32 << TABLE.len()) - 1;
        let first = shutdown::wave(TABLE, alive);
        let names = |mask: u32| -> Vec<&str> {
            (0..TABLE.len())
                .filter(|p| mask & (1 << p) != 0)
                .map(|p| TABLE[p].name)
                .collect()
        };
        assert_eq!(names(first), ["power"]);
        let second = shutdown::wave(TABLE, alive & !first);
        assert_eq!(names(second), ["blk", "echo", "quiet"]);
        let third = shutdown::wave(TABLE, alive & !first & !second);
        assert_eq!(names(third), ["uart"]);
    }

    #[test]
    fn the_quiet_service_is_killed_before_the_disk_service_gets_its_time() {
        let of = |name: &str| TABLE.iter().find(|r| r.name == name).unwrap();
        assert_eq!(shutdown::stop_ns(of("quiet")), shutdown::DEFAULT_STOP_NS);
        assert_eq!(shutdown::stop_ns(of("blk")), shutdown::DISK_STOP_NS);
    }

    #[test]
    fn the_stop_handlers_table_passes_the_check_and_stops_the_files_before_their_disk() {
        crate::table::check(STOP_TABLE).unwrap();
        let place = |name: &str| STOP_TABLE.iter().position(|r| r.name == name).unwrap();
        let mut alive = (1u32 << STOP_TABLE.len()) - 1;
        let mut order = Vec::new();
        loop {
            let next = shutdown::wave(STOP_TABLE, alive);
            if next == 0 {
                break;
            }
            order.push(next);
            alive &= !next;
        }
        let wave_of = |name: &str| {
            order
                .iter()
                .position(|w| w & (1 << place(name)) != 0)
                .unwrap_or_else(|| panic!("{name} is in no wave"))
        };
        assert_eq!(wave_of("power"), 0);
        // The writer keeps its session with `datafs` open until the file service has stopped.
        assert!(wave_of("datafs") < wave_of("stop-writer"));
        assert_eq!(wave_of("stop-writer"), wave_of("uart"));
        assert!(wave_of("datafs") < wave_of("datadisk"));
        assert!(wave_of("datadisk") < wave_of("uart"));
        assert_eq!(wave_of("uart"), order.len() - 1);
        // The POSIX programs end with the process service, in its wave.
        assert_eq!(wave_of("stop-handle"), wave_of("posix"));
        assert_eq!(wave_of("stop-ignore"), wave_of("posix"));
        // The two records of the files and of the processes get their own deadlines.
        let of = |name: &str| &STOP_TABLE[place(name)];
        assert_eq!(shutdown::stop_ns(of("datafs")), shutdown::FILES_STOP_NS);
        assert_eq!(shutdown::stop_ns(of("posix")), shutdown::PROCESS_STOP_NS);
    }

    #[test]
    fn the_stop_handlers_power_and_writer_records_are_services_that_hold_the_files_open() {
        let power = STOP_TABLE.iter().find(|r| r.name == "power").unwrap();
        assert!(!power.is_client() && !power.is_posix());
        assert!(power.connects.contains(&"stop-writer"));
        let writer = STOP_TABLE.iter().find(|r| r.name == "stop-writer").unwrap();
        assert!(writer.connects.contains(&"datafs") && writer.log);
        assert_eq!(writer.waits.len(), 1);
        assert_eq!(STOP_TABLE.iter().filter(|r| r.is_posix()).count(), 2);
    }

    #[test]
    fn the_power_button_table_is_the_console_and_the_real_power_record() {
        use crate::table::POWER_SERVICE;
        assert!(crate::table::check(POWER_BUTTON_TABLE).is_ok());
        let names: Vec<&str> = POWER_BUTTON_TABLE.iter().map(|r| r.name).collect();
        assert_eq!(names, ["uart", POWER_SERVICE]);
        assert_eq!(POWER_BUTTON_TABLE[1], super::super::aws::POWER);
        let alive = 0b11;
        let first = shutdown::wave(POWER_BUTTON_TABLE, alive);
        assert_eq!(first, 0b10, "power first, the console after");
        assert_eq!(shutdown::wave(POWER_BUTTON_TABLE, alive & !first), 0b01);
    }
}
