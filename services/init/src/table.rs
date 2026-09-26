// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of init (spec 13.4): what it starts, and the checks the
//! table passes before init starts anything. A record is a service, which
//! registers its channel, sends heartbeats and serves the records that
//! connect to it, or a client, which does none of that (the shell, the
//! test program `checker`). `check` refuses a table init could not keep
//! its promises with, and gives the order to start the records in:
//! services before their clients, among those ready the highest ceiling
//! first, then the order of the table. `TABLE` is the table init starts:
//! the one that ships, or a table of the test images, which a feature of
//! the build names (`table-test`, `table-cycle`, `table-ceiling`).

use crate::PAGE;
use crate::watch::Watch;
use core::fmt;
use core::ops::RangeInclusive;
use proto_init::{OWN_ARGS_MAX, START_NAMES};
use proto_wire::Name;

/// The records of a table at most: the checks, LIST and the queue of the
/// worker stay short.
pub const MAX_RECORDS: usize = 16;
/// The highest ceiling of a record: init's worker thread works one level
/// above the ceiling of the service it works for, at most at 62, under
/// init's 63 (spec 8).
pub const MAX_CEILING: u8 = 61;
/// The most handles a process has room for (process_create, spec 5.1).
pub const HANDLE_LIMIT_MAX: u32 = 16_384;
/// The least quota of a record: a program that owns no object loads and
/// runs with 15 pages (spec 7.5).
pub const MIN_QUOTA: u64 = 15 * PAGE;
/// The lines a binding takes: the shared lines of the GIC (spec 9).
pub const SHARED_LINES: RangeInclusive<u32> = 32..=1019;

/// What a record is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Registers its channel, sends heartbeats under this watchdog, and
    /// serves the records that connect to it.
    Service(Watch),
    /// Neither registers nor sends heartbeats, and no record connects to
    /// it.
    Client,
}

/// Whether init starts a record again after its instance ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restart {
    Always,
    /// The record ends with its instance.
    Never,
}

/// A device window init makes for a service and gives it in the reply to
/// its REGISTER, under `name`: `len` bytes of physical memory from `base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub name: &'static str,
    pub base: u64,
    pub len: u64,
}

/// An interrupt binding init makes for a service through its registered
/// channel and gives it in the reply to its REGISTER, under `name`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub name: &'static str,
    pub line: u32,
    /// Edge-triggered; level-triggered otherwise.
    pub edge: bool,
}

/// A record of the table (spec 13.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: &'static str,
    /// The program's name in the boot image.
    pub program: &'static str,
    pub kind: Kind,
    /// The base priority of its first thread, and its ceiling.
    pub priority: u8,
    pub ceiling: u8,
    /// In bytes, whole pages.
    pub quota: u64,
    pub handle_limit: u32,
    pub restart: Restart,
    /// A copy of the system resource with DEBUG and TRANSFER in its start
    /// data, under the name `console`.
    pub console: bool,
    pub windows: &'static [Window],
    pub bindings: &'static [Binding],
    /// The services it may connect to, by name.
    pub connects: &'static [&'static str],
    /// Its own arguments (proto_init::ServiceArgs).
    pub args: &'static [u8],
}

impl Record {
    /// The watchdog of a service; None for a client.
    pub const fn watch(&self) -> Option<Watch> {
        match self.kind {
            Kind::Service(w) => Some(w),
            Kind::Client => None,
        }
    }

    pub const fn is_client(&self) -> bool {
        matches!(self.kind, Kind::Client)
    }
}

/// The place in `table` of the record named `name`.
pub fn find(table: &[Record], name: &[u8]) -> Option<usize> {
    table.iter().position(|r| r.name.as_bytes() == name)
}

/// The order to start the records of a table in, by their places.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Order {
    places: [usize; MAX_RECORDS],
    len: usize,
}

impl Order {
    pub fn as_slice(&self) -> &[usize] {
        &self.places[..self.len]
    }
}

/// A cycle of connections in `table`: the places of its records, the
/// first again at its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cycle<'a> {
    table: &'a [Record],
    places: [u8; MAX_RECORDS + 1],
    len: usize,
}

impl Cycle<'_> {
    /// The names of the records of the cycle, in its order.
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        let places = self.places[..self.len].iter();
        places.map(|&p| self.table[usize::from(p)].name)
    }
}

/// Why `check` refused a table; `Display` gives the reason init prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError<'a> {
    TooMany {
        count: usize,
    },
    /// Record `place` has a name that is not 1 to 16 bytes, none zero.
    Name {
        place: usize,
    },
    Repeated {
        name: &'static str,
    },
    Unknown {
        record: &'static str,
        to: &'static str,
    },
    ToClient {
        record: &'static str,
        to: &'static str,
    },
    Cycle(Cycle<'a>),
    BelowClient {
        service: &'static str,
        priority: u8,
        client: &'static str,
        ceiling: u8,
    },
    Levels {
        record: &'static str,
        priority: u8,
        ceiling: u8,
    },
    Watchdog {
        record: &'static str,
        watch: Watch,
    },
    ClientObjects {
        record: &'static str,
    },
    Objects {
        record: &'static str,
        count: usize,
    },
    ObjectName {
        record: &'static str,
        name: &'static str,
    },
    Window {
        record: &'static str,
        name: &'static str,
    },
    Line {
        record: &'static str,
        line: u32,
    },
    Args {
        record: &'static str,
        len: usize,
    },
    HandleLimit {
        record: &'static str,
        limit: u32,
    },
    Quota {
        record: &'static str,
        quota: u64,
    },
}

impl fmt::Display for TableError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TableError::TooMany { count } => {
                write!(f, "{count} records, at most {MAX_RECORDS}")
            }
            TableError::Name { place } => {
                write!(f, "record {place} has no name of 1 to 16 bytes, none zero")
            }
            TableError::Repeated { name } => write!(f, "the name {name} comes twice"),
            TableError::Unknown { record, to } => {
                write!(f, "{record} connects to {to}, which is no record")
            }
            TableError::ToClient { record, to } => {
                write!(f, "{record} connects to {to}, a client")
            }
            TableError::Cycle(cycle) => {
                write!(f, "the connections make a cycle:")?;
                for (i, name) in cycle.names().enumerate() {
                    let arrow = if i == 0 { "" } else { " ->" };
                    write!(f, "{arrow} {name}")?;
                }
                Ok(())
            }
            TableError::BelowClient {
                service,
                priority,
                client,
                ceiling,
            } => write!(
                f,
                "{service} at priority {priority} is below the ceiling {ceiling} of its client {client}"
            ),
            TableError::Levels {
                record,
                priority,
                ceiling,
            } => write!(
                f,
                "{record} has priority {priority} and ceiling {ceiling}: 1 <= priority <= ceiling <= {MAX_CEILING}"
            ),
            TableError::Watchdog { record, watch } => write!(
                f,
                "{record} has a watchdog of {} ns for heartbeats every {} ns: at least three periods, of more than 0",
                watch.deadline_ns, watch.period_ns
            ),
            TableError::ClientObjects { record } => {
                write!(f, "{record} is a client with a window or a binding")
            }
            TableError::Objects { record, count } => write!(
                f,
                "{record} has {count} windows and bindings, at most {START_NAMES}"
            ),
            TableError::ObjectName { record, name } => write!(
                f,
                "{record} has a window or a binding named {name:?}: 1 to 16 bytes, none zero, each once"
            ),
            TableError::Window { record, name } => {
                write!(f, "{record} has the window {name} off whole pages")
            }
            TableError::Line { record, line } => write!(
                f,
                "{record} binds line {line}, which is no shared line ({}-{})",
                SHARED_LINES.start(),
                SHARED_LINES.end()
            ),
            TableError::Args { record, len } => write!(
                f,
                "{record} has {len} bytes of its own arguments, at most {OWN_ARGS_MAX}"
            ),
            TableError::HandleLimit { record, limit } => write!(
                f,
                "{record} has room for {limit} handles: 1 to {HANDLE_LIMIT_MAX}"
            ),
            TableError::Quota { record, quota } => write!(
                f,
                "{record} has a quota of {quota} bytes: whole pages, at least {MIN_QUOTA}"
            ),
        }
    }
}

/// Checks `table` (spec 13.4) and gives the order to start its records
/// in. The checks, in this order: at most MAX_RECORDS records; names of 1
/// to 16 bytes, none zero, none twice; each connection names a service of
/// the table; no cycle of connections, a record that connects to itself
/// among them; the base priority of each service not below the ceiling of
/// any record that connects to it; 1 <= priority <= ceiling <=
/// MAX_CEILING; the watchdog of a service at least three periods of more
/// than 0, and no window or binding for a client; at most START_NAMES
/// windows and bindings, all named once, windows of whole pages and lines
/// in SHARED_LINES; at most OWN_ARGS_MAX bytes of its own arguments, room
/// for 1 to HANDLE_LIMIT_MAX handles and a quota of whole pages, at least
/// MIN_QUOTA. Whether the program is in the boot image, init checks at
/// its start.
pub fn check(table: &[Record]) -> Result<Order, TableError<'_>> {
    if table.len() > MAX_RECORDS {
        return Err(TableError::TooMany { count: table.len() });
    }
    for (place, r) in table.iter().enumerate() {
        if Name::new(r.name.as_bytes()).is_err() {
            return Err(TableError::Name { place });
        }
        if find(table, r.name.as_bytes()) != Some(place) {
            return Err(TableError::Repeated { name: r.name });
        }
    }
    for r in table {
        for &to in r.connects {
            match find(table, to.as_bytes()) {
                None => return Err(TableError::Unknown { record: r.name, to }),
                Some(s) if table[s].is_client() => {
                    return Err(TableError::ToClient { record: r.name, to });
                }
                Some(_) => {}
            }
        }
    }
    if let Some(cycle) = cycle(table) {
        return Err(TableError::Cycle(cycle));
    }
    for client in table {
        for s in connections(table, client) {
            let service = &table[s];
            if service.priority < client.ceiling {
                return Err(TableError::BelowClient {
                    service: service.name,
                    priority: service.priority,
                    client: client.name,
                    ceiling: client.ceiling,
                });
            }
        }
    }
    for r in table {
        check_record(r)?;
    }
    Ok(order(table))
}

/// The checks of one record by itself, from its levels on (`check`).
fn check_record(r: &Record) -> Result<(), TableError<'static>> {
    let record = r.name;
    if r.priority == 0 || r.priority > r.ceiling || r.ceiling > MAX_CEILING {
        return Err(TableError::Levels {
            record,
            priority: r.priority,
            ceiling: r.ceiling,
        });
    }
    match r.kind {
        Kind::Service(watch) => {
            if watch.period_ns == 0 || watch.deadline_ns / 3 < watch.period_ns {
                return Err(TableError::Watchdog { record, watch });
            }
        }
        Kind::Client => {
            if !r.windows.is_empty() || !r.bindings.is_empty() {
                return Err(TableError::ClientObjects { record });
            }
        }
    }
    let count = r.windows.len() + r.bindings.len();
    if count > START_NAMES {
        return Err(TableError::Objects { record, count });
    }
    let windows = r.windows.iter().map(|w| w.name);
    let names = windows.clone().chain(r.bindings.iter().map(|b| b.name));
    for (i, name) in names.clone().enumerate() {
        let once = names.clone().position(|n| n == name) == Some(i);
        if Name::new(name.as_bytes()).is_err() || !once {
            return Err(TableError::ObjectName { record, name });
        }
    }
    for w in r.windows {
        if w.len == 0 || !w.base.is_multiple_of(PAGE) || !w.len.is_multiple_of(PAGE) {
            return Err(TableError::Window {
                record,
                name: w.name,
            });
        }
    }
    for b in r.bindings {
        if !SHARED_LINES.contains(&b.line) {
            return Err(TableError::Line {
                record,
                line: b.line,
            });
        }
    }
    if r.args.len() > OWN_ARGS_MAX {
        return Err(TableError::Args {
            record,
            len: r.args.len(),
        });
    }
    if !(1..=HANDLE_LIMIT_MAX).contains(&r.handle_limit) {
        return Err(TableError::HandleLimit {
            record,
            limit: r.handle_limit,
        });
    }
    if r.quota < MIN_QUOTA || !r.quota.is_multiple_of(PAGE) {
        return Err(TableError::Quota {
            record,
            quota: r.quota,
        });
    }
    Ok(())
}

/// The places of the records `r` connects to, those of the table.
fn connections<'a>(table: &'a [Record], r: &'a Record) -> impl Iterator<Item = usize> + 'a {
    r.connects
        .iter()
        .filter_map(|to| find(table, to.as_bytes()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    New,
    Open,
    Done,
}

/// The first cycle of connections a search in depth finds, from the
/// records in the order of the table.
fn cycle(table: &[Record]) -> Option<Cycle<'_>> {
    let mut marks = [Mark::New; MAX_RECORDS];
    let mut path = [0; MAX_RECORDS];
    for start in 0..table.len() {
        if marks[start] == Mark::New
            && let Some(cycle) = visit(table, start, &mut marks, &mut path, 0)
        {
            return Some(cycle);
        }
    }
    None
}

/// Visits record `at` at depth `depth` of the search, `path[..depth]`
/// the records on the way to it.
fn visit<'a>(
    table: &'a [Record],
    at: usize,
    marks: &mut [Mark; MAX_RECORDS],
    path: &mut [u8; MAX_RECORDS],
    depth: usize,
) -> Option<Cycle<'a>> {
    marks[at] = Mark::Open;
    // A table has at most MAX_RECORDS records (`check`).
    path[depth] = at as u8;
    for next in connections(table, &table[at]) {
        match marks[next] {
            Mark::Open => {
                let from = path[..=depth]
                    .iter()
                    .position(|&p| usize::from(p) == next)?;
                let mut cycle = Cycle {
                    table,
                    places: [0; MAX_RECORDS + 1],
                    len: depth + 2 - from,
                };
                cycle.places[..depth + 1 - from].copy_from_slice(&path[from..=depth]);
                cycle.places[depth + 1 - from] = next as u8;
                return Some(cycle);
            }
            Mark::New => {
                if let Some(cycle) = visit(table, next, marks, path, depth + 1) {
                    return Some(cycle);
                }
            }
            Mark::Done => {}
        }
    }
    marks[at] = Mark::Done;
    None
}

/// The order of a table with no cycle: each time, of the records whose
/// connections all started, the one with the highest ceiling, then the
/// first in the table.
fn order(table: &[Record]) -> Order {
    let mut order = Order {
        places: [0; MAX_RECORDS],
        len: 0,
    };
    let mut started = [false; MAX_RECORDS];
    while order.len < table.len() {
        let ready = (0..table.len())
            .filter(|&p| !started[p])
            .filter(|&p| connections(table, &table[p]).all(|s| started[s]));
        // The highest ceiling, the first place of equals: max_by_key
        // gives the last of equals, so the places go by in reverse.
        let Some(next) = ready.rev().max_by_key(|&p| table[p].ceiling) else {
            break;
        };
        started[next] = true;
        order.places[order.len] = next;
        order.len += 1;
    }
    order
}

pub mod ceiling;
pub mod cycle;
pub mod normal;
pub mod test;

#[cfg(any(
    all(feature = "table-test", feature = "table-cycle"),
    all(feature = "table-test", feature = "table-ceiling"),
    all(feature = "table-cycle", feature = "table-ceiling"),
))]
compile_error!("init builds with one table: table-test, table-cycle or table-ceiling");

/// The table init starts (spec 13.4): the one of the build's feature, or
/// the one that ships. The tables are constants, so a build carries only
/// the one it starts.
#[cfg(not(any(
    feature = "table-test",
    feature = "table-cycle",
    feature = "table-ceiling"
)))]
pub const TABLE: &[Record] = normal::TABLE;
#[cfg(feature = "table-test")]
pub const TABLE: &[Record] = test::TABLE;
#[cfg(feature = "table-cycle")]
pub const TABLE: &[Record] = cycle::TABLE;
#[cfg(feature = "table-ceiling")]
pub const TABLE: &[Record] = ceiling::TABLE;

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;
    const WATCH: Watch = Watch {
        period_ns: 20 * MS,
        deadline_ns: 100 * MS,
    };

    /// A service of the program `svc` at `priority` under `ceiling`.
    const fn service(name: &'static str, priority: u8, ceiling: u8) -> Record {
        Record {
            name,
            program: "svc",
            kind: Kind::Service(WATCH),
            priority,
            ceiling,
            quota: 16 * PAGE,
            handle_limit: 16,
            restart: Restart::Always,
            console: false,
            windows: &[],
            bindings: &[],
            connects: &[],
            args: &[],
        }
    }

    /// A client with the console that connects to `connects`.
    const fn client(
        name: &'static str,
        priority: u8,
        ceiling: u8,
        connects: &'static [&'static str],
    ) -> Record {
        Record {
            kind: Kind::Client,
            restart: Restart::Never,
            console: true,
            connects,
            ..service(name, priority, ceiling)
        }
    }

    const RTC: Window = Window {
        name: "rtc",
        base: 0x0901_0000,
        len: PAGE,
    };
    const RTC_IRQ: Binding = Binding {
        name: "rtc-irq",
        line: 34,
        edge: false,
    };

    /// The table of the test image of init (spec 15.2).
    const TEST: [Record; 10] = [
        service("sink", 40, 40),
        service("echo", 40, 40),
        Record {
            kind: Kind::Service(Watch {
                period_ns: 20 * MS,
                deadline_ns: 1000 * MS,
            }),
            ..service("slow", 40, 40)
        },
        Record {
            windows: &[RTC],
            bindings: &[RTC_IRQ],
            ..service("device", 40, 40)
        },
        service("crash", 35, 35),
        Record {
            kind: Kind::Service(Watch {
                period_ns: 20 * MS,
                deadline_ns: 300 * MS,
            }),
            connects: &["sink"],
            ..service("silent", 30, 32)
        },
        service("mute", 30, 30),
        client(
            "checker",
            30,
            30,
            &["sink", "echo", "slow", "device", "crash", "silent", "mute"],
        ),
        service("private", 20, 20),
        Record {
            quota: 1 << 40,
            ..service("hog", 20, 20)
        },
    ];

    /// The names of `table` in the order `check` gives.
    fn order_of(table: &[Record]) -> Vec<&'static str> {
        let order = check(table).expect("the table passes");
        order.as_slice().iter().map(|&p| table[p].name).collect()
    }

    /// `check` of a table of `r` alone, which stays for the test.
    fn check_one(r: Record) -> Result<Order, TableError<'static>> {
        check(Box::leak(Box::new([r])))
    }

    /// Why `check` refuses `table`, as init prints it.
    fn refused(table: &[Record]) -> String {
        check(table).expect_err("the table is refused").to_string()
    }

    #[test]
    fn a_good_table_passes_in_dependency_order() {
        let names: Vec<&str> = TEST.iter().map(|r| r.name).collect();
        assert_eq!(order_of(&TEST), names);
        // Services before their clients, the highest ceiling first, then
        // the order of the table.
        let mixed = [
            client("checker", 30, 30, &["echo"]),
            service("low", 20, 20),
            service("echo", 40, 40),
            service("mid", 30, 35),
            service("peer", 20, 20),
        ];
        assert_eq!(order_of(&mixed), ["echo", "mid", "checker", "low", "peer"]);
        // At one ceiling, a record waits for the services it connects to,
        // though the table puts it first.
        let level = [
            client("checker", 30, 30, &["silent"]),
            Record {
                connects: &["sink"],
                ..service("silent", 30, 30)
            },
            service("sink", 30, 30),
        ];
        assert_eq!(order_of(&level), ["sink", "silent", "checker"]);
        assert_eq!(order_of(&[]), [""; 0]);
    }

    #[test]
    fn a_cycle_is_refused_with_its_path() {
        let three = [
            Record {
                connects: &["b"],
                ..service("a", 40, 40)
            },
            Record {
                connects: &["c"],
                ..service("b", 40, 40)
            },
            Record {
                connects: &["a"],
                ..service("c", 40, 40)
            },
        ];
        assert_eq!(
            refused(&three),
            "the connections make a cycle: a -> b -> c -> a"
        );
        // The way into the cycle is no part of it.
        let tail = [
            Record {
                connects: &["a"],
                ..service("x", 40, 40)
            },
            Record {
                connects: &["b"],
                ..service("a", 40, 40)
            },
            Record {
                connects: &["a"],
                ..service("b", 40, 40)
            },
        ];
        let Err(TableError::Cycle(cycle)) = check(&tail) else {
            panic!("a cycle passed");
        };
        assert_eq!(cycle.names().collect::<Vec<_>>(), ["a", "b", "a"]);
    }

    #[test]
    fn a_self_connection_is_a_cycle() {
        let own = [
            service("echo", 40, 40),
            Record {
                connects: &["echo", "a"],
                ..service("a", 40, 40)
            },
        ];
        assert_eq!(refused(&own), "the connections make a cycle: a -> a");
    }

    #[test]
    fn a_server_below_its_client_is_refused() {
        let low = [
            service("echo", 30, 30),
            client("checker", 40, 40, &["echo"]),
        ];
        assert_eq!(
            refused(&low),
            "echo at priority 30 is below the ceiling 40 of its client checker"
        );
        // A client whose ceiling is above its base priority: the ceiling
        // counts.
        let raised = [
            service("echo", 35, 35),
            client("checker", 30, 40, &["echo"]),
        ];
        assert!(matches!(
            check(&raised),
            Err(TableError::BelowClient { ceiling: 40, .. })
        ));
        let level = [
            service("echo", 40, 40),
            client("checker", 30, 40, &["echo"]),
        ];
        assert!(check(&level).is_ok());
        // A service that connects to another is its client too.
        let services = [
            service("sink", 30, 30),
            Record {
                connects: &["sink"],
                ..service("silent", 30, 32)
            },
        ];
        assert!(matches!(
            check(&services),
            Err(TableError::BelowClient {
                service: "sink",
                client: "silent",
                ..
            })
        ));
    }

    #[test]
    fn unknown_and_repeated_names_are_refused() {
        let twice = [service("echo", 40, 40), service("echo", 30, 30)];
        assert_eq!(refused(&twice), "the name echo comes twice");
        let unknown = [client("checker", 30, 30, &["nobody"])];
        assert_eq!(
            refused(&unknown),
            "checker connects to nobody, which is no record"
        );
        for bad in ["", "seventeen-bytes!!", "e\0cho"] {
            let table = [service("echo", 40, 40), service(bad, 40, 40)];
            assert_eq!(check(&table), Err(TableError::Name { place: 1 }), "{bad:?}");
        }
        assert!(check(&[service("sixteen-bytes!!!", 40, 40)]).is_ok());
        let names = [
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
        ];
        let many = names.map(|n| service(n, 40, 40));
        assert!(check(&many[..MAX_RECORDS]).is_ok());
        assert_eq!(refused(&many), "17 records, at most 16");
    }

    #[test]
    fn levels_leave_room_for_the_worker() {
        assert!(check(&[service("top", 61, 61)]).is_ok());
        assert!(check(&[service("low", 1, 61)]).is_ok());
        assert_eq!(
            refused(&[service("top", 61, 62)]),
            "top has priority 61 and ceiling 62: 1 <= priority <= ceiling <= 61"
        );
        for (priority, ceiling) in [(0, 20), (30, 20), (62, 62), (63, 63)] {
            let table = [service("bad", priority, ceiling)];
            assert!(
                matches!(check(&table), Err(TableError::Levels { .. })),
                "{priority} under {ceiling}"
            );
        }
        let high_client = [client("checker", 30, 62, &[])];
        assert!(matches!(
            check(&high_client),
            Err(TableError::Levels { .. })
        ));
    }

    #[test]
    fn watchdog_is_at_least_three_periods() {
        let with = |period_ns, deadline_ns| {
            [Record {
                kind: Kind::Service(Watch {
                    period_ns,
                    deadline_ns,
                }),
                ..service("echo", 40, 40)
            }]
        };
        assert!(check(&with(20 * MS, 60 * MS)).is_ok());
        assert!(check(&with(1, 3)).is_ok());
        assert_eq!(
            refused(&with(20 * MS, 60 * MS - 1)),
            "echo has a watchdog of 59999999 ns for heartbeats every 20000000 ns: at least three periods, of more than 0"
        );
        for (period, deadline) in [
            (20 * MS, 40 * MS),
            (0, 100 * MS),
            (0, 0),
            (u64::MAX, u64::MAX),
        ] {
            assert!(
                matches!(
                    check(&with(period, deadline)),
                    Err(TableError::Watchdog { .. })
                ),
                "{deadline} for {period}"
            );
        }
    }

    #[test]
    fn register_objects_fit_one_reply() {
        const W2: Window = Window {
            name: "rtc2",
            base: 0x0902_0000,
            len: PAGE,
        };
        const W3: Window = Window {
            name: "rtc3",
            base: 0x0903_0000,
            len: PAGE,
        };
        const B2: Binding = Binding {
            name: "irq2",
            line: 1019,
            edge: true,
        };
        let with = |windows: &'static [Window], bindings: &'static [Binding]| {
            [Record {
                windows,
                bindings,
                ..service("device", 40, 40)
            }]
        };
        assert!(check(&with(&[RTC, W2], &[RTC_IRQ, B2])).is_ok());
        assert_eq!(
            refused(&with(&[RTC, W2, W3], &[RTC_IRQ, B2])),
            "device has 5 windows and bindings, at most 4"
        );
        // Lines 32 to 1019.
        for line in [0, 31, 1020, u32::MAX] {
            let bad = [Binding { line, ..RTC_IRQ }];
            let table = [Record {
                bindings: Box::leak(Box::new(bad)),
                ..service("device", 40, 40)
            }];
            assert_eq!(
                check(&table),
                Err(TableError::Line {
                    record: "device",
                    line
                })
            );
        }
        let low = [Record {
            bindings: &[Binding {
                line: 32,
                ..RTC_IRQ
            }],
            ..service("device", 40, 40)
        }];
        assert!(check(&low).is_ok());
        // The names of a reply: each once, and names.
        let twice = with(
            &[RTC],
            &[Binding {
                name: "rtc",
                ..RTC_IRQ
            }],
        );
        assert!(matches!(
            check(&twice),
            Err(TableError::ObjectName { name: "rtc", .. })
        ));
        let empty = with(&[Window { name: "", ..RTC }], &[]);
        assert!(matches!(
            check(&empty),
            Err(TableError::ObjectName { name: "", .. })
        ));
    }

    #[test]
    fn windows_are_on_their_own_pages() {
        let with = |base, len| {
            let w = [Window {
                name: "rtc",
                base,
                len,
            }];
            check_one(Record {
                windows: Box::leak(Box::new(w)),
                ..service("device", 40, 40)
            })
        };
        assert!(with(0x0901_0000, PAGE).is_ok());
        assert!(with(0x0901_0000, 16 * PAGE).is_ok());
        for (base, len) in [
            (0x0901_0008, PAGE),
            (0x0901_0000, 0x100),
            (0x0901_0000, PAGE + 1),
            (0x0901_0000, 0),
        ] {
            assert_eq!(
                with(base, len),
                Err(TableError::Window {
                    record: "device",
                    name: "rtc"
                }),
                "{base:#x}, {len:#x}"
            );
        }
    }

    #[test]
    fn a_client_has_no_watchdog_and_serves_nobody() {
        let checker = client("checker", 30, 30, &["echo"]);
        assert_eq!(checker.watch(), None);
        assert!(checker.is_client());
        assert_eq!(service("echo", 40, 40).watch(), Some(WATCH));
        let with_window = [Record {
            windows: &[RTC],
            ..client("checker", 30, 30, &[])
        }];
        assert_eq!(
            refused(&with_window),
            "checker is a client with a window or a binding"
        );
        let with_binding = [Record {
            bindings: &[RTC_IRQ],
            ..client("checker", 30, 30, &[])
        }];
        assert!(matches!(
            check(&with_binding),
            Err(TableError::ClientObjects { .. })
        ));
        let served = [
            client("checker", 30, 30, &[]),
            Record {
                connects: &["checker"],
                ..service("echo", 40, 40)
            },
        ];
        assert_eq!(refused(&served), "echo connects to checker, a client");
        let clients = [
            client("shell", 20, 20, &[]),
            client("checker", 20, 20, &["shell"]),
        ];
        assert!(matches!(check(&clients), Err(TableError::ToClient { .. })));
    }

    #[test]
    fn own_arguments_handles_and_quota_have_limits() {
        let args = [7; OWN_ARGS_MAX + 1];
        let with = check_one;
        let own = |n: usize| Record {
            args: Box::leak(Box::new(args))[..n].as_ref(),
            ..service("echo", 40, 40)
        };
        assert!(with(own(OWN_ARGS_MAX)).is_ok());
        assert_eq!(
            with(own(OWN_ARGS_MAX + 1)).map_err(|e| e.to_string()),
            Err("echo has 241 bytes of its own arguments, at most 240".into())
        );
        let room = |handle_limit| Record {
            handle_limit,
            ..service("echo", 40, 40)
        };
        assert!(with(room(1)).is_ok());
        assert!(with(room(HANDLE_LIMIT_MAX)).is_ok());
        for limit in [0, HANDLE_LIMIT_MAX + 1] {
            assert!(matches!(
                with(room(limit)),
                Err(TableError::HandleLimit { .. })
            ));
        }
        let quota = |quota| Record {
            quota,
            ..service("echo", 40, 40)
        };
        assert!(with(quota(MIN_QUOTA)).is_ok());
        for bad in [MIN_QUOTA - PAGE, MIN_QUOTA + 1, 0] {
            assert!(matches!(with(quota(bad)), Err(TableError::Quota { .. })));
        }
    }

    /// The tables of the images (spec 15.2): the one that ships and the
    /// test table pass, in the order of their dependencies; the two bad
    /// tables are refused with the reasons xtask looks for in their runs.
    #[test]
    fn the_tables_of_the_images_pass_or_are_refused() {
        assert_eq!(order_of(normal::TABLE), [""; 0]);
        assert_eq!(
            order_of(test::TABLE),
            [
                "echo", "slow", "device", "crash", "checker", "private", "hog"
            ]
        );
        assert_eq!(
            refused(cycle::TABLE),
            "the connections make a cycle: a -> b -> a"
        );
        assert_eq!(
            refused(ceiling::TABLE),
            "low at priority 40 is below the ceiling 50 of its client high"
        );
    }
}
