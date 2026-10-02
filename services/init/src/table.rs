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
/// The DMA objects of a record at most.
pub const MAX_DMA: usize = 2;
/// The names init gives in start data besides the DMA objects (worker.rs):
/// no window, binding or DMA object takes one.
pub const START_DATA_NAMES: [&str; 6] = [
    "console",
    "log",
    "trace",
    PROCESS_SERVICE,
    BOOT_IMAGE,
    IDENTITY_SESSION,
];
/// The name of the boot image, read-only, in the start data of the
/// process service: until the loader of 5c it loads the POSIX processes
/// from there (serve.rs).
pub const BOOT_IMAGE: &str = "bootimage";
/// The name of the POSIX process service (spec 2, section 3.1). A record
/// that connects to it is a POSIX process: init takes no CONNECT to it and
/// loads no program for it; the service takes the record with ADOPT,
/// creates and loads the process itself, and gives init the session of
/// its record with ADOPTED, which init puts in the process's start data
/// under this name (serve.rs); the service pays for the process. Init
/// never sends the service a request (spec 6.7).
pub const PROCESS_SERVICE: &str = "posix";
/// The name of the identity session of a POSIX process in its start data
/// (spec 2, 3.1): the process gives copies of it to the services it asks
/// something of, which ask the process service who it is.
pub const IDENTITY_SESSION: &str = "posix-id";
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

/// A contiguous DMA object init makes for each instance of a driver (spec
/// 7.3; spec 2, section 4) and gives it in its start data under `name`,
/// its physical address first in the own arguments: `size` bytes, a power
/// of two of pages up to abi::MAX_CONTIGUOUS_PAGES, uncached in every
/// mapping when `uncached`. Init keeps a handle of its own until the
/// instance ended and its device stopped (`quiesce`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dma {
    pub name: &'static str,
    pub size: u64,
    pub uncached: bool,
}

/// A write of `bits` bits, 8 or 32, init makes through a window of its own
/// over the window `window` of the record, at byte `offset`, aligned to
/// its width, once an instance ended and before its DMA objects go; init
/// reads the register back until its bits `settled` show `value`, at most
/// worker::SETTLE_READS times, and the stop failed otherwise. A write
/// with `only_if` goes only while that register shows one of its bits; it
/// is skipped otherwise. In their order the writes stop the device's DMA:
/// for a Virtio PCI function a reset (`device_status` 0, which reads 0
/// once done) only while the function decodes its BARs, then its command
/// word 0 (no decoding, no bus mastering). A function that does not decode
/// reads 0xff in BAR 0 and drops the write, and it runs no queue: its
/// driver sets queues up only once decoding is on, and every stop before
/// reset the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Write {
    pub window: &'static str,
    pub offset: u64,
    pub bits: u8,
    pub value: u32,
    pub settled: u32,
    pub only_if: Option<Gate>,
}

/// A 32-bit register a Write depends on: at word `offset` of the record's
/// window `window`, read through init's own window; the write goes while
/// its value has a bit of `bits`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gate {
    pub window: &'static str,
    pub offset: u64,
    pub bits: u32,
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
    /// A copy of the system resource with KSTATS and TRANSFER in its start
    /// data, under the name `log`: the console's driver reads the kernel
    /// log with it (spec 13.3, 16.3).
    pub log: bool,
    /// Gives the shell a KSTATS resource for non-destructive tracing.
    pub trace: bool,
    pub windows: &'static [Window],
    pub bindings: &'static [Binding],
    /// The services it may connect to, by name.
    pub connects: &'static [&'static str],
    /// Its own arguments (proto_init::ServiceArgs), after the physical
    /// addresses of its DMA objects, 8 bytes each.
    pub args: &'static [u8],
    /// The DMA objects of each of its instances.
    pub dma: &'static [Dma],
    /// The writes that stop its device once an instance ended.
    pub quiesce: &'static [Write],
    /// A driver of a device that masters the bus with no SMMU between
    /// them: it can write any memory, so it is in the trusted base (spec
    /// 9; spec 2, section 4). Only such a record has DMA objects.
    pub trusted: bool,
    /// The first POSIX process, whose record the process service gives
    /// root credentials (spec 2, section 3.1); one record at most, a POSIX
    /// process. The others init starts have none, and their children
    /// inherit by the rules of setuid.
    pub root: bool,
    /// A POSIX client init does not start at its start: the process
    /// service starts it for posix_spawn of `/boot/<name>` (SPAWN,
    /// serve.rs), one instance at a time, until the loader of 5c.
    pub on_demand: bool,
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

    /// Whether it is a POSIX process: it connects to PROCESS_SERVICE.
    pub fn is_posix(&self) -> bool {
        self.connects.contains(&PROCESS_SERVICE)
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
    /// A DMA object of a record that is no trusted service, or of a size
    /// no contiguous object has, or a name that is no name.
    Dma {
        record: &'static str,
        name: &'static str,
    },
    /// A write that names no window of the record, or lies past it or off
    /// a word.
    Quiesce {
        record: &'static str,
        window: &'static str,
    },
    /// Root for a record that is no POSIX process, or for a second one.
    Root {
        record: &'static str,
    },
    /// A record started on demand that is no POSIX client, has root or
    /// restarts.
    OnDemand {
        record: &'static str,
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
            TableError::Dma { record, name } => write!(
                f,
                "{record} has the DMA object {name}: a trusted service's, of a power of two of pages up to {}",
                abi::MAX_CONTIGUOUS_PAGES
            ),
            TableError::Quiesce { record, window } => write!(
                f,
                "{record} has a stopping write through {window}: a window of its own, 8 or 32 bits aligned within it"
            ),
            TableError::Root { record } => write!(
                f,
                "{record} has root: one POSIX process at most, which connects to {PROCESS_SERVICE}"
            ),
            TableError::OnDemand { record } => write!(
                f,
                "{record} starts on demand: a POSIX client without root that does not restart"
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
/// in SHARED_LINES; at most OWN_ARGS_MAX bytes of its own arguments, the
/// addresses of its DMA objects among them, room for 1 to
/// HANDLE_LIMIT_MAX handles and a quota of whole pages, at least
/// MIN_QUOTA; DMA objects only for a trusted service, each named and of a
/// power of two of pages up to abi::MAX_CONTIGUOUS_PAGES; each write that
/// stops the device on a word within a window of the record; root for one
/// POSIX process at most; a start on demand only for a POSIX client
/// without root that does not restart. Whether the program is in the boot image, init checks at
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
    for (place, r) in table.iter().enumerate() {
        let first = table.iter().position(|r| r.root) == Some(place);
        if r.root && (!r.is_posix() || !first) {
            return Err(TableError::Root { record: r.name });
        }
        let restarts = r.restart == Restart::Always;
        if r.on_demand && (!r.is_posix() || !r.is_client() || r.root || restarts) {
            return Err(TableError::OnDemand { record: r.name });
        }
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
    // The names of the reply to REGISTER and those of the start data
    // init gives (START_DATA_NAMES and the DMA objects): each once, so no
    // handle is given under a name another took.
    let windows = r.windows.iter().map(|w| w.name);
    let names = windows
        .clone()
        .chain(r.bindings.iter().map(|b| b.name))
        .chain(r.dma.iter().map(|d| d.name));
    for (i, name) in names.clone().enumerate() {
        let once = names.clone().position(|n| n == name) == Some(i);
        if Name::new(name.as_bytes()).is_err() || !once || START_DATA_NAMES.contains(&name) {
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
    let own = r.args.len() + 8 * r.dma.len();
    if own > OWN_ARGS_MAX {
        return Err(TableError::Args { record, len: own });
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
    for d in r.dma {
        let pages = d.size / PAGE;
        let fits = d.size.is_multiple_of(PAGE)
            && pages.is_power_of_two()
            && pages <= abi::MAX_CONTIGUOUS_PAGES;
        let named = Name::new(d.name.as_bytes()).is_ok() && r.dma.len() <= MAX_DMA;
        if !r.trusted || r.is_client() || !fits || !named {
            return Err(TableError::Dma {
                record,
                name: d.name,
            });
        }
    }
    for q in r.quiesce {
        let window = r.windows.iter().find(|w| w.name == q.window);
        let bytes = u64::from(q.bits / 8);
        let width = matches!(q.bits, 8 | 32) && (q.bits == 32 || q.value <= 0xFF);
        let gate = q.only_if.is_none_or(|g| {
            r.windows
                .iter()
                .any(|w| w.name == g.window && g.offset.is_multiple_of(4) && g.offset + 4 <= w.len)
        });
        let within = width
            && gate
            && window.is_some_and(|w| q.offset.is_multiple_of(bytes) && q.offset + bytes <= w.len);
        if !within {
            return Err(TableError::Quiesce {
                record,
                window: q.window,
            });
        }
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
pub mod ramfs;
pub mod test;
pub mod vz;

/// The table features of the build: one at most.
const TABLE_FEATURES: usize = cfg!(feature = "table-test") as usize
    + cfg!(feature = "table-cycle") as usize
    + cfg!(feature = "table-ceiling") as usize
    + cfg!(feature = "vz") as usize
    + cfg!(feature = "table-ramfs") as usize
    + cfg!(feature = "table-busybox") as usize
    + cfg!(feature = "table-busybox-dialog") as usize
    + cfg!(feature = "table-posix-dialog") as usize
    + cfg!(feature = "table-posix-dialog-vz") as usize
    + cfg!(feature = "table-posix-abi") as usize
    + cfg!(feature = "table-relibc") as usize
    + cfg!(feature = "table-relibc-threads") as usize
    + cfg!(feature = "table-posix-procs") as usize
    + cfg!(feature = "table-os-test") as usize
    + cfg!(feature = "table-posix-abi-vz") as usize
    + cfg!(feature = "table-busybox-dialog-vz") as usize
    + cfg!(feature = "table-rtbench-vz") as usize
    + cfg!(feature = "table-rtbench-posix") as usize
    + cfg!(feature = "table-rtbench-posix-vz") as usize;
const _: () = assert!(
    matches!(TABLE_FEATURES, 0 | 1),
    "init builds with one table feature at a time"
);

/// The table init starts (spec 13.4): the one of the build's feature, or
/// the one that ships. The tables are constants, so a build carries only
/// the one it starts.
#[cfg(not(any(
    feature = "table-test",
    feature = "table-cycle",
    feature = "table-ceiling",
    feature = "vz",
    feature = "table-ramfs",
    feature = "table-busybox",
    feature = "table-busybox-dialog",
    feature = "table-posix-dialog",
    feature = "table-posix-dialog-vz",
    feature = "table-posix-abi",
    feature = "table-relibc",
    feature = "table-relibc-threads",
    feature = "table-posix-procs",
    feature = "table-os-test",
    feature = "table-posix-abi-vz",
    feature = "table-busybox-dialog-vz",
    feature = "table-rtbench-vz",
    feature = "table-rtbench-posix",
    feature = "table-rtbench-posix-vz"
)))]
pub const TABLE: &[Record] = normal::TABLE;
#[cfg(feature = "table-ramfs")]
pub const TABLE: &[Record] = ramfs::TABLE;
#[cfg(feature = "table-posix-abi")]
pub const TABLE: &[Record] = ramfs::POSIX_ABI_TABLE;
#[cfg(feature = "table-relibc")]
pub const TABLE: &[Record] = ramfs::RELIBC_TABLE;
#[cfg(feature = "table-posix-procs")]
pub const TABLE: &[Record] = ramfs::POSIX_PROCS_TABLE;
#[cfg(feature = "table-relibc-threads")]
pub const TABLE: &[Record] = ramfs::RELIBC_THREADS_TABLE;
#[cfg(feature = "table-os-test")]
pub const TABLE: &[Record] = ramfs::OS_TEST_TABLE;
#[cfg(feature = "table-busybox")]
pub const TABLE: &[Record] = ramfs::BUSYBOX_TABLE;
#[cfg(feature = "table-busybox-dialog")]
pub const TABLE: &[Record] = ramfs::BUSYBOX_DIALOG_TABLE;
#[cfg(feature = "table-posix-dialog")]
pub const TABLE: &[Record] = ramfs::POSIX_DIALOG_TABLE;
#[cfg(feature = "table-posix-dialog-vz")]
pub const TABLE: &[Record] = vz::POSIX_DIALOG_TABLE;
#[cfg(feature = "vz")]
pub const TABLE: &[Record] = vz::TABLE;
#[cfg(feature = "table-posix-abi-vz")]
pub const TABLE: &[Record] = vz::POSIX_ABI_TABLE;
#[cfg(feature = "table-busybox-dialog-vz")]
pub const TABLE: &[Record] = vz::BUSYBOX_DIALOG_TABLE;
#[cfg(feature = "table-rtbench-vz")]
pub const TABLE: &[Record] = vz::RTBENCH_TABLE;
#[cfg(feature = "table-rtbench-posix")]
pub const TABLE: &[Record] = ramfs::RTBENCH_POSIX_TABLE;
#[cfg(feature = "table-rtbench-posix-vz")]
pub const TABLE: &[Record] = vz::RTBENCH_POSIX_TABLE;
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
            log: false,
            trace: false,
            windows: &[],
            bindings: &[],
            connects: &[],
            args: &[],
            dma: &[],
            quiesce: &[],
            trusted: false,
            root: false,
            on_demand: false,
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

    /// A DMA object belongs to a trusted service and has the size of a
    /// contiguous object; its address counts among the own arguments; a
    /// write that stops the device lies on a word of a window of the
    /// record.
    #[test]
    fn dma_objects_and_quiesce_writes_have_limits() {
        const DMA: Dma = Dma {
            name: "dma",
            size: 16 * PAGE,
            uncached: true,
        };
        const STOP: Write = Write {
            window: "rtc",
            offset: 4,
            bits: 32,
            value: 0,
            settled: u32::MAX,
            only_if: None,
        };
        let driver = |dma: &'static [Dma], trusted| Record {
            windows: &[RTC],
            dma,
            quiesce: &[STOP],
            trusted,
            ..service("driver", 40, 40)
        };
        assert!(check_one(driver(&[DMA], true)).is_ok());
        let gated = Record {
            quiesce: &[Write {
                only_if: Some(Gate {
                    window: "rtc",
                    offset: 4,
                    bits: 2,
                }),
                ..STOP
            }],
            ..driver(&[DMA], true)
        };
        assert!(check_one(gated).is_ok());
        // A DMA object's name is a name of the start data: none twice, none
        // a window's or a binding's, and none init gives itself.
        for name in ["rtc", "log", "console", "trace"] {
            let d: &'static [Dma] = Box::leak(Box::new([Dma { name, ..DMA }]));
            assert!(
                matches!(
                    check_one(driver(d, true)),
                    Err(TableError::ObjectName { .. })
                ),
                "{name}"
            );
        }
        let twice = driver(&[DMA, DMA], true);
        assert!(matches!(
            check_one(twice),
            Err(TableError::ObjectName { .. })
        ));
        let byte = Record {
            quiesce: &[Write {
                offset: 0x15,
                bits: 8,
                ..STOP
            }],
            ..driver(&[DMA], true)
        };
        assert!(check_one(byte).is_ok());
        assert_eq!(
            check_one(driver(&[DMA], false)).map_err(|e| e.to_string()),
            Err(
                "driver has the DMA object dma: a trusted service's, of a power of two of pages up to 1024"
                    .into()
            )
        );
        for size in [3 * PAGE, 2048 * PAGE, PAGE + 1, 0] {
            let d: &'static [Dma] = Box::leak(Box::new([Dma { size, ..DMA }]));
            assert!(
                matches!(check_one(driver(d, true)), Err(TableError::Dma { .. })),
                "{size:#x}"
            );
        }
        let args = Box::leak(Box::new([7; OWN_ARGS_MAX - 7]));
        let crowded = Record {
            args: &args[..],
            ..driver(&[DMA], true)
        };
        assert!(matches!(check_one(crowded), Err(TableError::Args { .. })));
        for stop in [
            Write {
                window: "regs",
                ..STOP
            },
            Write { offset: 2, ..STOP },
            Write { bits: 16, ..STOP },
            Write {
                bits: 8,
                value: 0x100,
                ..STOP
            },
            Write {
                offset: PAGE - 2,
                ..STOP
            },
            Write {
                offset: PAGE,
                ..STOP
            },
            Write {
                only_if: Some(Gate {
                    window: "regs",
                    offset: 4,
                    bits: 2,
                }),
                ..STOP
            },
            Write {
                only_if: Some(Gate {
                    window: "rtc",
                    offset: 2,
                    bits: 2,
                }),
                ..STOP
            },
        ] {
            let quiesce: &'static [Write] = Box::leak(Box::new([stop]));
            let r = Record {
                quiesce,
                ..driver(&[DMA], true)
            };
            assert!(
                matches!(check_one(r), Err(TableError::Quiesce { .. })),
                "{stop:?}"
            );
        }
    }

    /// The tables of the images (spec 15.2): the one that ships and the
    /// test table pass, in the order of their dependencies; the two bad
    /// tables are refused with the reasons xtask looks for in their runs.
    #[test]
    fn the_tables_of_the_images_pass_or_are_refused() {
        assert_eq!(order_of(normal::TABLE), ["uart", "shell"]);
        assert_eq!(order_of(vz::TABLE), ["uart", "shell"]);
        assert_eq!(
            order_of(vz::POSIX_ABI_TABLE),
            [
                "uart",
                "long",
                "ramfs",
                "posix",
                "clock",
                "clock-peer",
                "posix-abi-probe",
                "posix-sender"
            ]
        );
        assert_eq!(
            order_of(vz::BUSYBOX_DIALOG_TABLE),
            ["uart", "ramfs", "posix", "clock", "busybox-probe"]
        );
        assert_eq!(order_of(vz::RTBENCH_TABLE), ["uart", "rtbench"]);
        assert_eq!(
            order_of(ramfs::RELIBC_TABLE),
            [
                "ramfs",
                "posix",
                "clock",
                "relibc-hello",
                "relibc-abort",
                "relibc-assert",
                "relibc-panic"
            ]
        );
        assert_eq!(
            order_of(ramfs::RELIBC_THREADS_TABLE),
            ["ramfs", "posix", "clock", "relibc-threads"]
        );
        assert_eq!(
            order_of(ramfs::POSIX_PROCS_TABLE),
            [
                "ramfs",
                "posix",
                "clock",
                "posix-procs",
                "procs-child",
                "procs-sleeper",
                "procs-big",
                "procs-nap",
                "procs-exit7",
                "procs-segv",
                "procs-middle",
                "procs-orphan",
                "procs-catch",
                "procs-sleep2",
                "procs-ids",
                "procs-block"
            ]
        );
        for table in [ramfs::RTBENCH_POSIX_TABLE, vz::RTBENCH_POSIX_TABLE] {
            assert_eq!(
                order_of(table),
                [
                    "console",
                    "ramfs",
                    "posix",
                    "clock",
                    "uart",
                    "rtbench-load",
                    "rtbench-posix"
                ]
            );
        }
        assert_eq!(
            order_of(test::TABLE),
            [
                "sink", "echo", "slow", "device", "hog", "crash", "oneshot", "silent", "mute",
                "checker", "private"
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

    /// Every POSIX process leaves one level above main for its thread
    /// owner, heap and file workers and sleep timer, and its table passes.
    #[test]
    fn posix_processes_have_a_ceiling_above_main() {
        let tables = [
            ramfs::BUSYBOX_TABLE,
            ramfs::BUSYBOX_DIALOG_TABLE,
            ramfs::POSIX_DIALOG_TABLE,
            vz::POSIX_DIALOG_TABLE,
            ramfs::POSIX_ABI_TABLE,
            ramfs::RELIBC_TABLE,
            ramfs::RELIBC_THREADS_TABLE,
            ramfs::OS_TEST_TABLE,
            vz::POSIX_ABI_TABLE,
            vz::BUSYBOX_DIALOG_TABLE,
            ramfs::RTBENCH_POSIX_TABLE,
            vz::RTBENCH_POSIX_TABLE,
        ];
        for table in tables {
            assert!(check(table).is_ok());
            let posix = table.iter().filter(|r| {
                [
                    "busybox-probe",
                    "posix-probe",
                    "posix-abi-probe",
                    "relibc-hello",
                    "relibc-threads",
                    "os-test",
                    "rtbench-posix",
                ]
                .contains(&r.program)
            });
            // One POSIX program; relibc's table runs it four times.
            assert!(posix.clone().count() >= 1);
            for r in posix {
                assert_eq!(r.ceiling, r.priority + 1, "{}", r.name);
            }
        }
        // The probe is the first POSIX process; the clock peer is one
        // without root.
        for table in [ramfs::POSIX_ABI_TABLE, vz::POSIX_ABI_TABLE] {
            let roots: Vec<_> = table.iter().filter(|r| r.root).map(|r| r.name).collect();
            assert_eq!(roots, ["posix-abi-probe"]);
            assert!(table.iter().any(|r| r.name == "clock-peer" && r.is_posix()));
        }
    }

    /// Root goes to one POSIX process at most: a record that does not
    /// connect to the process service, or a second one, is refused.
    #[test]
    fn root_is_for_one_posix_process() {
        const POSIX: &[&str] = &[PROCESS_SERVICE];
        let process = service(PROCESS_SERVICE, 50, 50);
        let root = Record {
            root: true,
            ..client("first", 20, 20, POSIX)
        };
        assert!(check(&[process, root, client("other", 20, 20, POSIX)]).is_ok());
        let second = Record {
            root: true,
            ..client("second", 20, 20, POSIX)
        };
        assert_eq!(
            check(&[process, root, second]),
            Err(TableError::Root { record: "second" })
        );
        let plain = Record {
            root: true,
            ..client("plain", 20, 20, &[])
        };
        assert_eq!(
            check(&[process, plain]),
            Err(TableError::Root { record: "plain" })
        );
        assert_eq!(
            TableError::Root { record: "plain" }.to_string(),
            "plain has root: one POSIX process at most, which connects to posix"
        );
    }

    /// A start on demand goes to a POSIX client without root that does
    /// not restart alone.
    #[test]
    fn on_demand_is_for_posix_clients() {
        const POSIX: &[&str] = &[PROCESS_SERVICE];
        let process = service(PROCESS_SERVICE, 50, 50);
        let child = Record {
            on_demand: true,
            ..client("child", 20, 20, POSIX)
        };
        assert!(check(&[process, child]).is_ok());
        for (refused, name) in [
            (
                Record {
                    on_demand: true,
                    ..client("plain", 20, 20, &[])
                },
                "plain",
            ),
            (
                Record {
                    on_demand: true,
                    root: true,
                    ..client("root", 20, 20, POSIX)
                },
                "root",
            ),
            (
                Record {
                    on_demand: true,
                    restart: Restart::Always,
                    ..client("again", 20, 20, POSIX)
                },
                "again",
            ),
            (
                Record {
                    on_demand: true,
                    connects: POSIX,
                    ..service("daemon", 20, 20)
                },
                "daemon",
            ),
        ] {
            assert_eq!(
                check(&[process, refused]),
                Err(TableError::OnDemand { record: name })
            );
        }
        assert_eq!(
            TableError::OnDemand { record: "plain" }.to_string(),
            "plain starts on demand: a POSIX client without root that does not restart"
        );
    }
}
