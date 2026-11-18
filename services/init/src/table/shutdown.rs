// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the probe of the stop of the system (feature
//! `table-shutdown`, `cargo xtask init-shutdown`): the PL011's driver, the
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
}
