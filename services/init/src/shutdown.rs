// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What init decides when the system stops (proto_init SHUTDOWN): the waves
//! in which it stops its records and the time each gets. The program calls
//! these functions from serve.rs; everything here builds for the host too.
//!
//! The records stop in waves, the reverse of their connections: a wave is
//! the live records that no other live record connects to. The records of
//! POSIX processes are in no wave of their own: they end with the process
//! service, and its wave carries those that still live. The driver of the
//! console (`log`, which reads the kernel log) goes last, so
//! that the lines of the stop reach the port. (The `console` flag of a
//! record gives it the right to print and many records have it.) Each wave
//! gets a notice and a time (`stop_ns`), and the whole stop gets OVERALL_NS;
//! what has not ended by then is killed, and its device still stops (the
//! worker's `Kill`).

use crate::table::{MAX_RECORDS, POWER_SERVICE, PROCESS_SERVICE, Record};

/// A set of records by their places in the table, a bit each.
pub type Mask = u32;

const _: () = assert!(MAX_RECORDS <= Mask::BITS as usize);

const MS: u64 = 1_000_000;

/// The time a record gets to stop when nothing says otherwise: an exit at
/// once is all the default handler of rt::service does.
pub const DEFAULT_STOP_NS: u64 = 500 * MS;
/// The process service sends SIGTERM to its processes, waits 3 s for their
/// ends, sends SIGKILL and exits (its stop handler).
pub const PROCESS_STOP_NS: u64 = 5_000 * MS;
/// The file service finishes the jobs of its queue (2 s at most), unmounts the volume and exits
/// (its stop handler).
pub const FILES_STOP_NS: u64 = 3_000 * MS;
/// A disk service exits; its device stops after that (`Record::quiesce`).
pub const DISK_STOP_NS: u64 = 1_000 * MS;
/// The whole stop: past it init kills every record that is left at once.
pub const OVERALL_NS: u64 = 30_000 * MS;

/// The name of the file service of the data volume (table/pkg.rs).
const FILES_SERVICE: &str = "datafs";

/// The time `record` has to end after the stop notice.
pub fn stop_ns(record: &Record) -> u64 {
    match record.name {
        PROCESS_SERVICE => PROCESS_STOP_NS,
        FILES_SERVICE => FILES_STOP_NS,
        "datadisk" | "blk" => DISK_STOP_NS,
        _ if !record.quiesce.is_empty() => DISK_STOP_NS,
        _ => DEFAULT_STOP_NS,
    }
}

/// Whether the record that sent SHUTDOWN may stop the system: the one named
/// POWER_SERVICE (the caller is the record of the label of the request, which
/// init gave the instance and nobody can forge; `table::check` makes that
/// record a native service).
pub fn may_ask(caller: &Record) -> bool {
    caller.name == POWER_SERVICE
}

/// The records of `table` of which `pred` holds, as a mask.
fn mask_of(table: &[Record], pred: impl Fn(&Record) -> bool) -> Mask {
    table
        .iter()
        .enumerate()
        .filter(|(_, r)| pred(r))
        .fold(0, |mask, (place, _)| mask | 1 << place)
}

/// Whether the record at `from` connects to the record at `to`.
fn connects(table: &[Record], from: usize, to: usize) -> bool {
    table[from].connects.contains(&table[to].name)
}

/// The next wave when the records of `alive` are left: the live records of
/// no POSIX process that no other live record connects to, in the tiers of
/// `tier_of` (the console last); the wave of the process
/// service takes the live records of POSIX processes with it. 0 when no
/// record outside the POSIX processes lives: the stop is done. A table
/// without cycles (table::check) always gives a record to a nonzero set.
pub fn wave(table: &[Record], alive: Mask) -> Mask {
    let posix = mask_of(table, Record::is_posix);
    let process = table.iter().position(|r| r.name == PROCESS_SERVICE);
    let process_alive = process.is_some_and(|p| alive & (1 << p) != 0);
    let native = alive & !posix;
    // The records stop by tiers: the others, then the driver of the console.
    // The console never holds another record back, so a record of it that
    // connects to services stops after them all.
    let tier = |t: u8| mask_of(table, |r| tier_of(r) == t);
    let Some(first) = (0..2).find(|&t| native & tier(t) != 0) else {
        return 0;
    };
    let candidates = native & tier(first);
    // A live POSIX process holds the services it connects to, as long as the
    // process service that ends it lives.
    let holders = if first == 0 && process_alive {
        alive & tier(0)
    } else {
        candidates
    };
    let mut wave = 0;
    for place in 0..table.len() {
        if candidates & (1 << place) == 0 {
            continue;
        }
        let held = (0..table.len()).any(|from| {
            from != place
                && holders & (1 << from) != 0
                && connects(table, from, place)
                // The process service ends its processes in its own wave.
                && !(posix & (1 << from) != 0 && Some(place) == process)
        });
        if !held {
            wave |= 1 << place;
        }
    }
    if process.is_some_and(|p| wave & (1 << p) != 0) {
        wave |= alive & posix;
    }
    wave
}

/// The tier of `record`: 1 for the driver of the console (`log`, which reads
/// the kernel log and so prints the lines of the stop), 0 for the others.
fn tier_of(record: &Record) -> u8 {
    u8::from(record.log)
}

/// The deadline of a record that gets the notice at `now`: its time, cut at
/// the end of the whole stop that began at `began`.
pub fn deadline(now: u64, began: u64, record: &Record) -> u64 {
    now.saturating_add(stop_ns(record))
        .min(began.saturating_add(OVERALL_NS))
}

/// Whether the whole stop that began at `began` is over at `now`: init kills
/// what is left without a notice.
pub fn overall_over(now: u64, began: u64) -> bool {
    now >= began.saturating_add(OVERALL_NS)
}

/// What init keeps of the stop of the system: what was asked, when it began,
/// the records of the wave that stops now, those that got their notice (and
/// so a deadline of the stop in place of their watchdog's), and the label of
/// the timer of the whole stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stop {
    pub kind: u32,
    pub began: u64,
    pub wave: Mask,
    pub noticed: Mask,
    pub overall_label: u64,
}

/// What an expiry of a record's timer means while the system stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// The record got its notice: its deadline came, it is killed.
    Deadline,
    /// The record has not been told yet: its watchdog goes on as before, so a
    /// service that spins in a wave to come is still found.
    Watchdog,
}

impl Stop {
    pub const fn new(kind: u32, began: u64, overall_label: u64) -> Stop {
        Stop {
            kind,
            began,
            wave: 0,
            noticed: 0,
            overall_label,
        }
    }

    /// When the whole stop ends: the time of the timer init arms at the
    /// highest level, which kills what is left whatever the lower timers do.
    pub fn overall_at(&self) -> u64 {
        self.began.saturating_add(OVERALL_NS)
    }

    /// Whether the timer with `label` is the timer of the whole stop.
    pub fn is_overall(&self, label: u64) -> bool {
        label != 0 && label == self.overall_label
    }

    /// The records of `wave` got their notice, or the deadline of the process
    /// service in place of one.
    pub fn notice(&mut self, wave: Mask) {
        self.wave = wave;
        self.noticed |= wave;
    }

    /// The meaning of an expiry of the timer of the record at `place`.
    pub fn expiry(&self, place: usize) -> Expiry {
        if self.noticed & (1 << place) != 0 {
            Expiry::Deadline
        } else {
            Expiry::Watchdog
        }
    }
}

/// What init does with a SHUTDOWN from `caller`, with the system stopping
/// already or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// BAD_STATE: the caller is no `power`.
    Refuse,
    /// Status 0 and nothing changes: the stop is on.
    Already,
    /// Status 0, and the stop begins.
    Begin,
}

/// The decision on SHUTDOWN from `caller`.
pub fn decide(caller: &Record, stopping: bool) -> Decision {
    match (may_ask(caller), stopping) {
        (false, _) => Decision::Refuse,
        (true, true) => Decision::Already,
        (true, false) => Decision::Begin,
    }
}

/// Whether CONNECT gets a session: a stopping system gives none (BAD_STATE).
pub const fn connect_allowed(stopping: bool) -> bool {
    !stopping
}

/// The longest a stop can take from SHUTDOWN to init's exit, in
/// nanoseconds, for `table`, with every record ignoring the notice: the
/// whole stop, plus what the worker still does after the last kill (the
/// stop of each device with a confirmation, CONFIRM_NS twice at most for
/// each of `devices` records, one after the other).
pub const fn worst_case_ns(devices: u64, confirm_ns: u64) -> u64 {
    OVERALL_NS + devices * 2 * confirm_ns
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::{aws, base, normal, test};

    fn names(table: &[Record], mask: Mask) -> Vec<&'static str> {
        (0..table.len())
            .filter(|p| mask & (1 << p) != 0)
            .map(|p| table[p].name)
            .collect()
    }

    /// The waves of `table` with every record alive, each as its names.
    fn waves(table: &[Record]) -> Vec<Vec<&'static str>> {
        let mut alive = mask_of(table, |_| true);
        let mut out = Vec::new();
        loop {
            let next = wave(table, alive);
            if next == 0 {
                return out;
            }
            out.push(names(table, next));
            alive &= !next;
        }
    }

    fn index(waves: &[Vec<&str>], name: &str) -> usize {
        waves
            .iter()
            .position(|w| w.contains(&name))
            .unwrap_or_else(|| panic!("{name} is in no wave"))
    }

    /// Every record of a table outside the POSIX processes stops in some wave,
    /// after each record that connects to it, and the drivers of the console
    /// last.
    fn check_order(table: &[Record]) {
        let waves = waves(table);
        for r in table.iter().filter(|r| !r.is_posix()) {
            let at = index(&waves, r.name);
            for client in table.iter().filter(|c| !c.is_posix() && !r.log) {
                if client.connects.contains(&r.name) && !client.log {
                    assert!(
                        index(&waves, client.name) < at,
                        "{} stops before {}",
                        r.name,
                        client.name
                    );
                }
            }
            if r.log {
                let others = table.iter().filter(|o| !o.log && !o.is_posix());
                for o in others {
                    assert!(
                        index(&waves, o.name) < at,
                        "{} stops after {}",
                        o.name,
                        r.name
                    );
                }
            }
        }
        let in_waves: usize = waves.iter().map(Vec::len).sum();
        assert_eq!(in_waves, table.len(), "each record stops once");
    }

    #[test]
    fn the_aws_table_stops_in_the_order_of_the_decision() {
        // The table of the shell on EC2 as it is with the second volume
        // and the power service added by its own step: the order of the
        // waves is that of this table plus `power`.
        let mut table: Vec<Record> = aws::TABLE.to_vec();
        table.push(Record {
            name: crate::table::POWER_SERVICE,
            program: "power",
            connects: &[],
            ..test::TABLE[0]
        });
        let waves = waves(&table);
        assert_eq!(
            waves,
            [
                vec!["posix", "busybox-probe", "datakey", "power"],
                vec!["tty", "net", "pkgd", "datafs"],
                vec!["ramfs", "entropy", "blk", "datadisk"],
                vec!["clock", "pipe"],
                vec!["uart"],
            ]
        );
        let power = index(&waves, "power");
        let posix = index(&waves, "posix");
        let datafs = index(&waves, "datafs");
        let net = index(&waves, "net");
        let ramfs = index(&waves, "ramfs");
        let disk = index(&waves, "datadisk");
        let console = table.iter().find(|r| r.log).map(|r| r.name).unwrap();
        let last = index(&waves, console);
        assert!(power <= posix, "{waves:?}");
        assert!(posix < datafs && posix < net && posix < ramfs, "{waves:?}");
        assert!(datafs < disk && net < disk && ramfs <= disk, "{waves:?}");
        assert!(disk < last, "{waves:?}");
        assert_eq!(last, waves.len() - 1, "the console is the last wave");
        // POSIX records leave with the process service.
        for r in table.iter().filter(|r| r.is_posix()) {
            assert_eq!(
                index(&waves, r.name),
                posix,
                "{} with the process service",
                r.name
            );
        }
        check_order(&table);
    }

    #[test]
    fn the_other_real_tables_stop_clients_before_their_services() {
        use crate::table::{comp, entropy, focus, gpu, input, pkg, vz};
        for table in [
            aws::QEMU_TABLE,
            base::BASE_TABLE,
            normal::TABLE,
            test::TABLE,
            crate::table::net::NET_TABLE,
            crate::table::ramfs::TABLE,
            vz::TABLE,
            vz::POSIX_ABI_TABLE,
            vz::POSIX_NATIVE_TABLE,
            vz::BUSYBOX_DIALOG_TABLE,
            vz::POSIX_TTY_TABLE,
            vz::RTBENCH_TABLE,
            vz::RTBENCH_POSIX_TABLE,
            vz::TTY_TABLE,
            pkg::BLK_PROBE_TABLE,
            pkg::DATA_PROBE_TABLE,
            pkg::DATAKEY_PROBE_TABLE,
            pkg::STORE_PROBE_TABLE,
            pkg::PKG_SLOT_TABLE,
            pkg::INIT_WAIT_TABLE,
            gpu::TABLE,
            comp::TABLE,
            input::TABLE,
            focus::TABLE,
            entropy::TABLE,
            entropy::VZ_TABLE,
        ] {
            check_order(table);
        }
    }

    #[test]
    fn a_second_shutdown_gets_zero_and_changes_nothing() {
        let power = Record {
            name: POWER_SERVICE,
            ..test::TABLE[0]
        };
        assert_eq!(decide(&power, false), Decision::Begin);
        assert_eq!(decide(&power, true), Decision::Already);
    }

    #[test]
    fn a_shutdown_from_another_record_is_refused_stopping_or_not() {
        for table in [aws::TABLE, base::BASE_TABLE, test::TABLE] {
            for r in table {
                assert_eq!(decide(r, false), Decision::Refuse, "{}", r.name);
                assert_eq!(decide(r, true), Decision::Refuse, "{}", r.name);
            }
        }
    }

    #[test]
    fn connect_is_refused_while_the_system_stops() {
        assert!(connect_allowed(false));
        assert!(!connect_allowed(true));
    }

    #[test]
    fn a_record_that_got_no_notice_keeps_its_watchdog() {
        let mut stop = Stop::new(0, 100, 7);
        assert_eq!(stop.expiry(2), Expiry::Watchdog);
        stop.notice(1 << 2);
        assert_eq!(stop.expiry(2), Expiry::Deadline);
        assert_eq!(stop.expiry(3), Expiry::Watchdog);
        stop.notice(1 << 3);
        assert_eq!(stop.expiry(2), Expiry::Deadline);
        assert_eq!(stop.expiry(3), Expiry::Deadline);
    }

    #[test]
    fn the_whole_stop_has_a_timer_of_its_own_at_its_end() {
        let stop = Stop::new(1, 5_000, 9);
        assert_eq!(stop.overall_at(), 5_000 + OVERALL_NS);
        assert!(stop.is_overall(9));
        assert!(!stop.is_overall(8));
        // No label, no timer: a label of 0 is nobody's.
        assert!(!Stop::new(0, 0, 0).is_overall(0));
        // No record deadline goes past it.
        let record = &aws::TABLE[0];
        assert!(deadline(stop.began, stop.began, record) <= stop.overall_at());
        assert_eq!(
            deadline(stop.overall_at() - 1, stop.began, record),
            stop.overall_at()
        );
    }

    #[test]
    fn a_console_driver_that_connects_to_services_does_not_hold_them() {
        // A driver of the console that connects to services (a record of a
        // test table) stops last all the same, and holds none of them.
        let mut table = test::TABLE.to_vec();
        let checker = table.iter().position(|r| r.name == "checker").unwrap();
        table[checker].log = true;
        let waves = waves(&table);
        assert_eq!(index(&waves, "checker"), waves.len() - 1);
    }

    #[test]
    fn nothing_is_left_when_only_posix_records_live() {
        let table = aws::TABLE;
        let posix = mask_of(table, Record::is_posix);
        assert_ne!(posix, 0);
        assert_eq!(wave(table, posix), 0);
        assert_eq!(wave(table, 0), 0);
    }

    #[test]
    fn the_wave_of_the_process_service_carries_the_posix_records_that_live() {
        let table = aws::TABLE;
        let process = table
            .iter()
            .position(|r| r.name == PROCESS_SERVICE)
            .unwrap();
        let posix = mask_of(table, Record::is_posix);
        let alive = mask_of(table, |_| true);
        // Everything else stopped: the process service goes with its processes.
        let left = alive & (posix | 1 << process);
        let next = wave(table, left);
        assert_eq!(next & (1 << process), 1 << process);
        assert_eq!(next & posix, posix);
        // With the service gone the processes that live make no wave.
        assert_eq!(wave(table, left & !(1 << process)), 0);
    }

    #[test]
    fn only_the_record_named_power_may_ask() {
        let tables: [&[Record]; 4] = [aws::TABLE, aws::QEMU_TABLE, base::BASE_TABLE, test::TABLE];
        for table in tables {
            for r in table {
                assert!(!may_ask(r), "{} may stop the system", r.name);
            }
        }
        let power = Record {
            name: POWER_SERVICE,
            ..test::TABLE[0]
        };
        assert!(may_ask(&power));
        // The process service, which holds the start channels of the POSIX
        // records, and a POSIX record are no callers.
        for name in [PROCESS_SERVICE, "datafs", "powerx", "Power", ""] {
            assert!(!may_ask(&Record { name, ..power }), "{name}");
        }
    }

    #[test]
    fn the_table_check_wants_power_to_be_a_native_service() {
        use crate::table::{Kind, TableError, check};
        let power = Record {
            name: POWER_SERVICE,
            program: "power",
            connects: &[],
            ..test::TABLE[0]
        };
        assert!(check(&[power]).is_ok());
        let posix = Record {
            connects: &[PROCESS_SERVICE],
            ..power
        };
        let process = Record {
            name: PROCESS_SERVICE,
            connects: &[],
            ..test::TABLE[0]
        };
        assert!(matches!(
            check(&[process, posix]),
            Err(TableError::Power {
                record: POWER_SERVICE
            })
        ));
        let client = Record {
            kind: Kind::Client,
            ..power
        };
        assert!(matches!(
            check(&[client]),
            Err(TableError::Power {
                record: POWER_SERVICE
            })
        ));
    }

    #[test]
    fn the_bounds_are_those_of_the_decision() {
        let table = aws::TABLE;
        let of = |name: &str| table.iter().find(|r| r.name == name).map(stop_ns);
        assert_eq!(of("posix"), Some(5_000 * MS));
        assert_eq!(of("datafs"), Some(3_000 * MS));
        assert_eq!(of("datadisk"), Some(1_000 * MS));
        assert_eq!(of("ramfs"), Some(500 * MS));
        assert_eq!(OVERALL_NS, 30_000 * MS);
    }

    #[test]
    fn deadlines_are_cut_by_the_whole_stop() {
        let record = &aws::TABLE[0];
        let began = 1_000;
        assert_eq!(deadline(began, began, record), began + stop_ns(record));
        // A wave that starts late gets what is left of the whole stop.
        let late = began + OVERALL_NS - 10;
        assert_eq!(deadline(late, began, record), began + OVERALL_NS);
        assert!(!overall_over(began + OVERALL_NS - 1, began));
        assert!(overall_over(began + OVERALL_NS, began));
        assert!(overall_over(u64::MAX, u64::MAX / 2));
    }

    #[test]
    fn the_worst_case_adds_the_confirmations_of_the_devices_to_the_whole_stop() {
        assert_eq!(worst_case_ns(0, 2_500 * MS), OVERALL_NS);
        assert_eq!(worst_case_ns(1, 2_500 * MS), OVERALL_NS + 5_000 * MS);
    }
}
