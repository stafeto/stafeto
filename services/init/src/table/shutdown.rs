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
use super::{Kind, Record};
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
