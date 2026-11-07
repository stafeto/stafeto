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
/// The DMA objects of a record at most: the network service with two
/// devices has seven (table/net.rs).
pub const MAX_DMA: usize = 8;
/// The names of the start data of an instance at most, besides `process`
/// and `thread`: those of rt::startup (NAMES_MAX), which the worker's giver
/// holds (worker.rs).
pub const START_DATA_MAX: usize = 8;
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
/// process service, which loads the POSIX processes from there (serve.rs),
/// of the RAM file service, which shows the files of its table, and of the
/// clock service, which reads the start time of a VZ machine from it.
pub const BOOT_IMAGE: &str = "bootimage";
/// The name of the RAM file service's record: it gets the boot image.
pub const RAM_SERVICE: &str = "ramfs";
pub const CLOCK_SERVICE: &str = "clock";
pub const PIPE_SERVICE: &str = "pipe";
/// The network service's name.
pub const NET_SERVICE: &str = "net";
/// The clients init gives the RAM file service's boot profile
/// (proto_fs::BOOT_PROFILE): the diagnostic client of the RAM service and
/// the network service, which reads `/etc/netd.conf` as the boot root.
pub const BOOT_PROFILE_CLIENTS: &[&str] = &["ramfs-probe", NET_SERVICE, "layer-probe"];

/// The client init gives the RAM file service's layer session
/// (`proto_fs::LAYERS`, attach and detach of package files): the diagnostic client of the
/// layers now, the package service later. It asks for the session by the name
/// `RAM_LAYERS`, which is the RAM service under another mark; its record connects to
/// `ramfs` as for any session.
pub const LAYER_CLIENTS: &[&str] = &["layer-probe", "pkgd"];
/// The name a layer client connects by to get the layer session of the RAM service.
pub const RAM_LAYERS: &str = "ramfs/layers";

/// Whether `client` asking for `name` gets the layer session of the RAM service: only the
/// client the table names, by the name `RAM_LAYERS`.
pub fn layer_grant(client: &Record, name: &[u8]) -> bool {
    name == RAM_LAYERS.as_bytes() && LAYER_CLIENTS.contains(&client.name) && !client.is_posix()
}

/// Only the RAM service receives the named-pipe broker authority.
pub fn fifo_broker_grant(client: &Record, service: &[u8]) -> bool {
    client.name == RAM_SERVICE
        && !client.is_client()
        && !client.is_posix()
        && service == PIPE_SERVICE.as_bytes()
}

/// These connections obtain roots for loaders at service startup.
/// Processes keeps these endpoints solely to give narrowed loader copies.
pub fn loader_grant(client: &str, service: &[u8]) -> bool {
    client == PROCESS_SERVICE
        && (service == RAM_SERVICE.as_bytes() || service == CLOCK_SERVICE.as_bytes())
}
/// The name of the POSIX process service (spec 2, section 3.1). A record
/// that connects to it is a POSIX process: init takes no CONNECT to it and
/// loads no program for it; the service takes the record with ADOPT,
/// creates and loads the process itself, and gives init the session of
/// its record with ADOPTED, which init puts in the process's start data
/// under this name (serve.rs); the service pays for the process. Init
/// never sends the service a request (spec 6.7).
pub const PROCESS_SERVICE: &str = "posix";
/// The services init gives a notary session of the process service on
/// CONNECT (proto_process::NOTARY): through it they ask who a client is
/// (Vouch) and map the page of the credentials generations (Register).
pub const VOUCHERS: &[&str] = &[
    "clock",
    RAM_SERVICE,
    TERMINAL_SERVICE,
    PIPE_SERVICE,
    NET_SERVICE,
    PACKAGE_SERVICE,
];
/// The vouchers whose notary session may tell the process service that a
/// file is set-ID (proto_process SetId, spec 2, 3.2): the file services.
pub const SET_ID_VOUCHERS: &[&str] = &[RAM_SERVICE];
/// The package service: it attaches the packages of its store as layers of the RAM file
/// service, asks the process service who a client is (a notary session), and gets the boot
/// image to read the packages the image holds.
pub const PACKAGE_SERVICE: &str = "pkgd";
/// The name of the terminal service (5f): its notary session may send
/// TtySignal, SetCtty and DropCtty (proto_process::TERMINAL).
pub const TERMINAL_SERVICE: &str = "tty";
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
/// The service's copy has MAP_READ, MAP_WRITE and TRANSFER, and DUPLICATE
/// as well when `duplicate`: the network service hands copies of the
/// window of its second device to the program that claims it, one after
/// another, and keeps its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub name: &'static str,
    pub base: u64,
    pub len: u64,
    pub duplicate: bool,
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
/// instance ended and its device stopped (`quiesce`). The instance's copy
/// has MAP_READ, MAP_WRITE and TRANSFER, and DUPLICATE as well when
/// `duplicate`: the display service hands copies of its buffer with fewer
/// rights to the owner of the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dma {
    pub name: &'static str,
    pub size: u64,
    pub uncached: bool,
    pub duplicate: bool,
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

/// The thread numbers and the timer places a record has of its own (spec
/// 7.5, process_create x6 and x7), taken off init's: a record with none
/// pays from init's own, which every record of the table shares. A share of
/// either is a share of both, as the call has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shares {
    pub threads: u32,
    pub timers: u32,
}

impl Shares {
    /// No share of its own.
    pub const CREATOR: Shares = Shares {
        threads: 0,
        timers: 0,
    };
}

/// The share of the process service: its POSIX processes pay from it, a
/// child of the service draws on it and the processes of the table that
/// are not the service's cannot run it dry. 768 thread numbers cover 248
/// processes of one thread each and a process of 128 threads beside them.
pub const POSIX_SHARES: Shares = Shares {
    threads: 768,
    timers: 6144,
};
/// The thread numbers and timer places init keeps for itself (its two
/// threads and a timer for each record) and for the records with no share
/// of their own: the shares of the table add up to the system's 1 024 and
/// 8 192 less these.
pub const INIT_KEEP_THREADS: u32 = 128;
pub const INIT_KEEP_TIMERS: u32 = 1024;
/// The system's thread numbers and timer places (abi::MAX_SYSTEM_TIMERS and
/// the kernel's table of thread numbers), init's shares at its start.
pub const SYSTEM_THREADS: u32 = 1024;
pub const SYSTEM_TIMERS: u32 = abi::MAX_SYSTEM_TIMERS;

/// The CPUs of the services, the drivers and the processes of the shell
/// (SMP decision): the first two. The hard tasks of realtime get CPUs of
/// their own (`RT_CPUS`, kernel spec 8), where no ordinary process runs.
pub const GENERAL_CPUS: u8 = 0b0011;
/// The CPU of the network service: the boot CPU, where every shared
/// interrupt line is delivered, so that the line of its device and the
/// service meet on one CPU.
pub const NETD_CPUS: u8 = 0b0001;
/// The CPUs of the tasks of realtime, away from the ordinary processes.
pub const RT_CPUS: u8 = 0b1100;
/// The CPUs of the shell and its processes in the image of the measurement
/// of stage P7 (`bench::BENCH_VZ_TABLE`): all four, as the Linux guest it is
/// measured against has them. That image has no tasks of realtime, so the
/// decision of the SMP stage for the other images stands, and no table but
/// `bench.rs` names this constant.
pub const BENCH_CPUS: u8 = 0b1111;
/// The CPUs of the shell's processes in the pinned variant of that image
/// (`bench::BENCH_PINNED_VZ_TABLE`): CPUs 1 to 3, so that no worker of nginx
/// shares the CPU of the network service.
pub const BENCH_PINNED_CPUS: u8 = 0b1110;
/// Every CPU that is up: a record with it is cut to the CPUs the machine
/// has (the process service has them all, to give its processes the CPUs
/// they may use).
pub const ALL_CPUS: u8 = 0xff;

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
    /// The thread numbers and timer places of its own (`Shares::CREATOR`
    /// for none).
    pub shares: Shares,
    /// The CPUs its threads run on (process_create x8): init cuts it to
    /// the CPUs that are up (`on_cpus`); the POSIX processes of a record
    /// inherit it through the process service.
    pub cpus: u8,
    /// The services whose READY the record waits for before it starts
    /// (spec 5, section 4; `waits.rs`): at most two, each a service of the
    /// table with no waits of its own.
    pub waits: &'static [Wait],
}

/// A service a record waits for: its name, and how long the record waits at
/// most before it starts all the same, in milliseconds (1 to `WAIT_MAX_MS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wait {
    pub service: &'static str,
    pub deadline_ms: u32,
}

/// The waits of one record at most.
pub const WAITS_MAX: usize = 2;
/// The longest deadline of a wait, in milliseconds.
pub const WAIT_MAX_MS: u32 = 60_000;

/// `cpus` cut to the CPUs that are up (the mask `up`): a record whose mask
/// names none of them gets all that are up, and `false` says that was so.
pub fn on_cpus(cpus: u8, up: u8) -> (u8, bool) {
    match cpus & up {
        0 => (up, false),
        mask => (mask, true),
    }
}

/// The CPU the first thread of an instance is asked for (the loader's
/// `Params::cpu`: 0 for none, else the CPU plus one) when its mask is `mask`:
/// the driver of the console and its log (`log`) goes to CPU 1 when the mask
/// has it, and every other instance, or one whose mask lacks CPU 1, is asked
/// for none, so that the kernel puts it on the CPU of the caller or the
/// lowest of the mask. An explicit CPU outside the mask is ACCESS_DENIED.
pub fn first_cpu(log: bool, mask: u8) -> u8 {
    if log && mask & 0b0010 != 0 { 2 } else { 0 }
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
    /// More names in the start data than START_DATA_MAX.
    StartNames {
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
    /// Explicit shares that add up to more than init can give, or a share
    /// of one kind without the other.
    Shares {
        threads: u64,
        timers: u64,
    },
    /// A record with an empty CPU mask, or a POSIX process with CPUs the
    /// process service lacks.
    Cpus {
        record: &'static str,
    },
    /// A second layer client, or one that is a POSIX process or does not connect to the RAM
    /// service.
    Layers {
        record: &'static str,
    },
    /// A wait for a record that does not exist, is a client, waits itself or
    /// is the record, a deadline outside 1 to WAIT_MAX_MS ms, or more than
    /// WAITS_MAX waits.
    Waits {
        record: &'static str,
        service: &'static str,
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
            TableError::StartNames { record, count } => write!(
                f,
                "{record} has {count} names in its start data, at most {START_DATA_MAX}"
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
            TableError::Shares { threads, timers } => write!(
                f,
                "the shares add up to {threads} thread numbers and {timers} timer places: at most {} and {}, one of either with the other",
                SYSTEM_THREADS - INIT_KEEP_THREADS,
                SYSTEM_TIMERS - INIT_KEEP_TIMERS
            ),
            TableError::Cpus { record } => write!(
                f,
                "{record} has no CPU, or a POSIX process has a CPU the process service lacks"
            ),
            TableError::Layers { record } => write!(
                f,
                "{record} is a layer client: there is one at most, it is a native program, and it connects to {RAM_SERVICE}"
            ),
            TableError::Waits { record, service } => write!(
                f,
                "{record} waits for {service}: a wait names another record that is a service with no waits of its own, a deadline of 1 to {WAIT_MAX_MS} ms, and a record has {WAITS_MAX} waits at most, each service once"
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
/// POSIX process at most. Whether the program is in the boot image, init
/// checks at its start.
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
            if !loader_grant(client.name, service.name.as_bytes())
                && service.priority < client.ceiling
            {
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
    }
    check_shares(table)?;
    check_cpus(table)?;
    check_layers(table)?;
    check_waits(table)?;
    Ok(order(table))
}

/// The explicit shares of `table` (spec 13.4): each of both kinds or of
/// neither, and their sums at most what init has left of the system's after
/// it keeps INIT_KEEP_THREADS and INIT_KEEP_TIMERS for itself.
fn check_shares(table: &[Record]) -> Result<(), TableError<'static>> {
    let (mut threads, mut timers) = (0u64, 0u64);
    for r in table {
        threads += u64::from(r.shares.threads);
        timers += u64::from(r.shares.timers);
        if (r.shares.threads == 0) != (r.shares.timers == 0) {
            return Err(TableError::Shares { threads, timers });
        }
    }
    if threads > u64::from(SYSTEM_THREADS - INIT_KEEP_THREADS)
        || timers > u64::from(SYSTEM_TIMERS - INIT_KEEP_TIMERS)
    {
        return Err(TableError::Shares { threads, timers });
    }
    Ok(())
}

/// The layer clients of `table`: the layer session is one client's, which is not a POSIX
/// process and connects to the RAM service.
fn check_layers(table: &[Record]) -> Result<(), TableError<'static>> {
    let mut seen = false;
    for r in table.iter().filter(|r| LAYER_CLIENTS.contains(&r.name)) {
        if seen || r.is_posix() || !r.connects.contains(&RAM_SERVICE) {
            return Err(TableError::Layers { record: r.name });
        }
        seen = true;
    }
    Ok(())
}

/// The waits of `table` (spec 5, section 4): each names another record that
/// is a service and waits for none (so no chain and no cycle of waits), once,
/// with a deadline of 1 to WAIT_MAX_MS ms; WAITS_MAX at most.
fn check_waits(table: &[Record]) -> Result<(), TableError<'static>> {
    for r in table {
        for (i, wait) in r.waits.iter().enumerate() {
            let fine = i < WAITS_MAX
                && (1..=WAIT_MAX_MS).contains(&wait.deadline_ms)
                && wait.service != r.name
                && !r.waits[..i].iter().any(|w| w.service == wait.service)
                && find(table, wait.service.as_bytes())
                    .is_some_and(|s| !table[s].is_client() && table[s].waits.is_empty());
            if !fine {
                return Err(TableError::Waits {
                    record: r.name,
                    service: wait.service,
                });
            }
        }
    }
    Ok(())
}

/// The CPU masks of `table` (spec 13.4): none empty, and those of the POSIX
/// processes within the mask of the process service they connect to.
fn check_cpus(table: &[Record]) -> Result<(), TableError<'static>> {
    for r in table {
        if r.cpus == 0 {
            return Err(TableError::Cpus { record: r.name });
        }
        if r.is_posix()
            && let Some(service) = find(table, PROCESS_SERVICE.as_bytes())
            && r.cpus & !table[service].cpus != 0
        {
            return Err(TableError::Cpus { record: r.name });
        }
    }
    Ok(())
}

/// The names init gives an instance of `r` in its start data besides
/// `process` and `thread` (worker.rs, `start_data`; serve.rs,
/// `posix_instance`): the resources of `console`, `log` and `trace`, the
/// boot image of the services that read it, the DMA objects, and for a
/// POSIX process its sessions with the process service (the identity
/// session counted whether or not the instance gets one).
pub fn start_data_names(r: &Record) -> usize {
    let resources = usize::from(r.console) + usize::from(r.log) + usize::from(r.trace);
    let image = [PROCESS_SERVICE, RAM_SERVICE, CLOCK_SERVICE].contains(&r.name);
    let posix = if r.is_posix() { 2 } else { 0 };
    resources + usize::from(image) + r.dma.len() + posix
}

/// The label init binds line `i` of `r` through (serve.rs, `objects`):
/// `proto_init::binding_label(i)` for a record with more than one binding,
/// so that the service tells its lines apart; none for a record with one,
/// whose interrupts come through the registered channel itself.
pub fn binding_label(r: &Record, i: usize) -> Option<u64> {
    (r.bindings.len() > 1 && i < r.bindings.len()).then(|| proto_init::binding_label(i))
}

/// The services that may bring a second channel in REGISTER: a thread of
/// their own waits on it for the interrupts of the first line (netd's switch
/// thread, a level above the loop). The record's ceiling is above its
/// priority, and init binds that line through the channel at the ceiling.
pub const LINE_THREAD: &[&str] = &[NET_SERVICE];

/// Whether `r` declares a thread of its own for its first line.
pub fn line_thread(r: &Record) -> bool {
    LINE_THREAD.contains(&r.name) && r.ceiling > r.priority && !r.bindings.is_empty()
}

/// Where init binds line `i` of `r` (serve.rs, `objects`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Through {
    /// The second channel the service brought, at the record's ceiling.
    Bound,
    /// A session of the registered channel with this label.
    Labelled(u64),
    /// The registered channel itself.
    Plain,
}

/// The route of line `i` of `r` when the service brought `bound` (a second
/// channel): the first line of a record that declares a thread for it goes
/// through that channel, the others as `binding_label` says.
pub fn binding_route(r: &Record, i: usize, bound: bool) -> Through {
    if bound && i == 0 && line_thread(r) {
        return Through::Bound;
    }
    match binding_label(r, i) {
        Some(label) => Through::Labelled(label),
        None => Through::Plain,
    }
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
    let count = start_data_names(r);
    if count > START_DATA_MAX {
        return Err(TableError::StartNames { record, count });
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

pub mod base;
pub mod bench;
pub mod ceiling;
pub mod cycle;
pub mod doom;
pub mod entropy;
pub mod fstack;
pub mod gpu;
pub mod input;
#[cfg(any(feature = "table-posix-lock-ring", test))]
pub mod lock_ring;
pub mod net;
pub mod normal;
pub mod pkg;
pub mod ramfs;
pub mod test;
pub mod vz;

/// The table features of the build: one at most.
const TABLE_FEATURES: usize = cfg!(feature = "table-test") as usize
    + cfg!(feature = "table-cycle") as usize
    + cfg!(feature = "table-ceiling") as usize
    + cfg!(feature = "vz") as usize
    + cfg!(feature = "table-ramfs") as usize
    + cfg!(feature = "table-layer-probe") as usize
    + cfg!(feature = "table-busybox") as usize
    + cfg!(feature = "table-busybox-dialog") as usize
    + cfg!(feature = "table-doom") as usize
    + cfg!(feature = "table-base") as usize
    + cfg!(feature = "table-posix-dialog") as usize
    + cfg!(feature = "table-posix-dialog-vz") as usize
    + cfg!(feature = "table-posix-abi") as usize
    + cfg!(feature = "table-relibc") as usize
    + cfg!(feature = "table-relibc-threads") as usize
    + cfg!(feature = "table-posix-procs") as usize
    + cfg!(feature = "table-posix-lock-ring") as usize
    + cfg!(feature = "table-posix-shares") as usize
    + cfg!(feature = "table-posix-native-vz") as usize
    + cfg!(feature = "table-posix-files") as usize
    + cfg!(feature = "table-loader-channels") as usize
    + cfg!(feature = "table-posix-poll") as usize
    + cfg!(feature = "table-posix-sock") as usize
    + cfg!(feature = "table-posix-ipc") as usize
    + cfg!(feature = "table-posix-pty") as usize
    + cfg!(feature = "table-posix-steps") as usize
    + cfg!(feature = "table-os-test") as usize
    + cfg!(feature = "table-posix-abi-vz") as usize
    + cfg!(feature = "table-busybox-dialog-vz") as usize
    + cfg!(feature = "table-rtbench-vz") as usize
    + cfg!(feature = "table-rtbench-posix") as usize
    + cfg!(feature = "table-rtbench-posix-vz") as usize
    + cfg!(feature = "table-tty") as usize
    + cfg!(feature = "table-tty-vz") as usize
    + cfg!(feature = "table-tty-steps") as usize
    + cfg!(feature = "table-posix-tty") as usize
    + cfg!(feature = "table-posix-tty-vz") as usize
    + cfg!(feature = "table-entropy") as usize
    + cfg!(feature = "table-entropy-vz") as usize
    + cfg!(feature = "table-gpu") as usize
    + cfg!(feature = "table-net") as usize
    + cfg!(feature = "table-net-probe") as usize
    + cfg!(feature = "table-pci-walk-vz") as usize
    + cfg!(feature = "table-pci-walk-qemu") as usize
    + cfg!(feature = "table-blk-probe") as usize
    + cfg!(feature = "table-store-probe") as usize
    + cfg!(feature = "table-init-wait") as usize
    + cfg!(feature = "table-pkg-slot") as usize
    + cfg!(feature = "table-net-vz") as usize
    + cfg!(feature = "table-net-vz2") as usize
    + cfg!(feature = "table-bench-vz") as usize
    + cfg!(feature = "table-bench-pinned-vz") as usize
    + cfg!(feature = "table-bench-cpu0-vz") as usize
    + cfg!(feature = "table-bench-fast-vz") as usize
    + cfg!(feature = "table-net-probe-two") as usize
    + cfg!(feature = "table-net-two") as usize
    + cfg!(feature = "table-input") as usize
    + cfg!(feature = "table-posix-random") as usize
    + cfg!(feature = "table-posix-display") as usize
    + cfg!(feature = "table-display") as usize
    + cfg!(feature = "table-fstack-probe") as usize
    + cfg!(feature = "table-fstack-device") as usize
    + cfg!(feature = "table-fast-nginx") as usize
    + cfg!(feature = "table-fast-nginx-vz") as usize
    + cfg!(feature = "table-fast-scale") as usize
    + cfg!(feature = "table-fast-scale-vz") as usize
    + cfg!(feature = "table-fast-switch") as usize
    + cfg!(feature = "table-fast-switch-vz") as usize
    + cfg!(feature = "table-fast-switch-scale") as usize
    + cfg!(feature = "table-fast-switch-scale-vz") as usize
    + cfg!(feature = "table-posix-map-big") as usize;
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
    feature = "table-layer-probe",
    feature = "table-busybox",
    feature = "table-busybox-dialog",
    feature = "table-doom",
    feature = "table-base",
    feature = "table-posix-dialog",
    feature = "table-posix-dialog-vz",
    feature = "table-posix-abi",
    feature = "table-relibc",
    feature = "table-relibc-threads",
    feature = "table-posix-procs",
    feature = "table-posix-lock-ring",
    feature = "table-posix-shares",
    feature = "table-posix-native-vz",
    feature = "table-posix-files",
    feature = "table-loader-channels",
    feature = "table-posix-poll",
    feature = "table-posix-sock",
    feature = "table-posix-ipc",
    feature = "table-posix-pty",
    feature = "table-posix-steps",
    feature = "table-os-test",
    feature = "table-posix-abi-vz",
    feature = "table-busybox-dialog-vz",
    feature = "table-rtbench-vz",
    feature = "table-rtbench-posix",
    feature = "table-rtbench-posix-vz",
    feature = "table-tty",
    feature = "table-tty-vz",
    feature = "table-tty-steps",
    feature = "table-posix-tty",
    feature = "table-posix-tty-vz",
    feature = "table-entropy",
    feature = "table-entropy-vz",
    feature = "table-gpu",
    feature = "table-net",
    feature = "table-net-probe",
    feature = "table-pci-walk-vz",
    feature = "table-pci-walk-qemu",
    feature = "table-blk-probe",
    feature = "table-store-probe",
    feature = "table-init-wait",
    feature = "table-pkg-slot",
    feature = "table-net-vz",
    feature = "table-net-vz2",
    feature = "table-bench-vz",
    feature = "table-bench-pinned-vz",
    feature = "table-bench-cpu0-vz",
    feature = "table-bench-fast-vz",
    feature = "table-net-probe-two",
    feature = "table-net-two",
    feature = "table-input",
    feature = "table-posix-random",
    feature = "table-posix-display",
    feature = "table-display",
    feature = "table-fstack-probe",
    feature = "table-fstack-device",
    feature = "table-fast-nginx",
    feature = "table-fast-nginx-vz",
    feature = "table-fast-scale",
    feature = "table-fast-scale-vz",
    feature = "table-fast-switch",
    feature = "table-fast-switch-vz",
    feature = "table-fast-switch-scale",
    feature = "table-fast-switch-scale-vz",
    feature = "table-posix-map-big"
)))]
pub const TABLE: &[Record] = normal::TABLE;
#[cfg(feature = "table-ramfs")]
pub const TABLE: &[Record] = ramfs::TABLE;
#[cfg(feature = "table-layer-probe")]
pub const TABLE: &[Record] = ramfs::LAYER_PROBE_TABLE;
#[cfg(feature = "table-posix-files")]
pub const TABLE: &[Record] = ramfs::POSIX_FILES_TABLE;
#[cfg(feature = "table-posix-abi")]
pub const TABLE: &[Record] = ramfs::POSIX_ABI_TABLE;
#[cfg(feature = "table-relibc")]
pub const TABLE: &[Record] = ramfs::RELIBC_TABLE;
#[cfg(feature = "table-loader-channels")]
pub const TABLE: &[Record] = ramfs::LOADER_CHANNELS_TABLE;
#[cfg(feature = "table-posix-poll")]
pub const TABLE: &[Record] = ramfs::POSIX_POLL_TABLE;
#[cfg(feature = "table-posix-sock")]
pub const TABLE: &[Record] = ramfs::POSIX_SOCK_TABLE;
#[cfg(feature = "table-posix-ipc")]
pub const TABLE: &[Record] = ramfs::POSIX_IPC_TABLE;
#[cfg(feature = "table-posix-pty")]
pub const TABLE: &[Record] = ramfs::POSIX_PTY_TABLE;
#[cfg(feature = "table-posix-lock-ring")]
pub const TABLE: &[Record] = lock_ring::TABLE;
#[cfg(feature = "table-posix-procs")]
pub const TABLE: &[Record] = ramfs::POSIX_PROCS_TABLE;
#[cfg(feature = "table-posix-shares")]
pub const TABLE: &[Record] = ramfs::POSIX_SHARES_TABLE;
#[cfg(feature = "table-posix-native-vz")]
pub const TABLE: &[Record] = vz::POSIX_NATIVE_TABLE;
#[cfg(feature = "table-posix-steps")]
pub const TABLE: &[Record] = ramfs::POSIX_STEPS_TABLE;
#[cfg(feature = "table-relibc-threads")]
pub const TABLE: &[Record] = ramfs::RELIBC_THREADS_TABLE;
#[cfg(feature = "table-os-test")]
pub const TABLE: &[Record] = ramfs::OS_TEST_TABLE;
#[cfg(feature = "table-busybox")]
pub const TABLE: &[Record] = ramfs::BUSYBOX_TABLE;
#[cfg(feature = "table-busybox-dialog")]
pub const TABLE: &[Record] = ramfs::BUSYBOX_DIALOG_TABLE;
#[cfg(feature = "table-doom")]
pub const TABLE: &[Record] = doom::TABLE;
#[cfg(feature = "table-base")]
pub const TABLE: &[Record] = base::BASE_TABLE;
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
#[cfg(feature = "table-tty")]
pub const TABLE: &[Record] = ramfs::TTY_TABLE;
#[cfg(feature = "table-tty-vz")]
pub const TABLE: &[Record] = vz::TTY_TABLE;
#[cfg(feature = "table-tty-steps")]
pub const TABLE: &[Record] = ramfs::TTY_STEPS_TABLE;
#[cfg(feature = "table-posix-tty")]
pub const TABLE: &[Record] = ramfs::POSIX_TTY_TABLE;
#[cfg(feature = "table-posix-tty-vz")]
pub const TABLE: &[Record] = vz::POSIX_TTY_TABLE;
#[cfg(feature = "table-entropy")]
pub const TABLE: &[Record] = entropy::TABLE;
#[cfg(feature = "table-entropy-vz")]
pub const TABLE: &[Record] = entropy::VZ_TABLE;
#[cfg(feature = "table-gpu")]
pub const TABLE: &[Record] = gpu::TABLE;
#[cfg(feature = "table-net")]
pub const TABLE: &[Record] = net::NET_TABLE;
#[cfg(feature = "table-net-probe")]
pub const TABLE: &[Record] = net::NET_PROBE_TABLE;
#[cfg(feature = "table-net-vz")]
pub const TABLE: &[Record] = net::NET_VZ_TABLE;
#[cfg(feature = "table-net-vz2")]
pub const TABLE: &[Record] = net::NET_VZ2_TABLE;
#[cfg(feature = "table-bench-vz")]
pub const TABLE: &[Record] = bench::BENCH_VZ_TABLE;
#[cfg(feature = "table-bench-pinned-vz")]
pub const TABLE: &[Record] = bench::BENCH_PINNED_VZ_TABLE;
#[cfg(feature = "table-bench-cpu0-vz")]
pub const TABLE: &[Record] = bench::BENCH_CPU0_VZ_TABLE;
#[cfg(feature = "table-bench-fast-vz")]
pub const TABLE: &[Record] = bench::BENCH_FAST_VZ_TABLE;
#[cfg(feature = "table-net-probe-two")]
pub const TABLE: &[Record] = net::NET_PROBE_TWO_TABLE;
#[cfg(feature = "table-net-two")]
pub const TABLE: &[Record] = net::NET_TWO_TABLE;
#[cfg(feature = "table-pci-walk-vz")]
pub const TABLE: &[Record] = vz::PCI_WALK_TABLE;
#[cfg(feature = "table-pci-walk-qemu")]
pub const TABLE: &[Record] = pkg::PCI_WALK_QEMU_TABLE;
#[cfg(feature = "table-blk-probe")]
pub const TABLE: &[Record] = pkg::BLK_PROBE_TABLE;
#[cfg(feature = "table-store-probe")]
pub const TABLE: &[Record] = pkg::STORE_PROBE_TABLE;
#[cfg(feature = "table-init-wait")]
pub const TABLE: &[Record] = pkg::INIT_WAIT_TABLE;
#[cfg(feature = "table-pkg-slot")]
pub const TABLE: &[Record] = pkg::PKG_SLOT_TABLE;
#[cfg(feature = "table-input")]
pub const TABLE: &[Record] = input::TABLE;
#[cfg(feature = "table-posix-random")]
pub const TABLE: &[Record] = ramfs::POSIX_RANDOM_TABLE;
#[cfg(feature = "table-posix-display")]
pub const TABLE: &[Record] = ramfs::POSIX_DISPLAY_TABLE;
#[cfg(feature = "table-display")]
pub const TABLE: &[Record] = ramfs::DISPLAY_TABLE;
#[cfg(feature = "table-fstack-probe")]
pub const TABLE: &[Record] = fstack::FSTACK_TABLE;
#[cfg(feature = "table-fstack-device")]
pub const TABLE: &[Record] = fstack::FSTACK_DEVICE_TABLE;
#[cfg(feature = "table-fast-nginx")]
pub const TABLE: &[Record] = fstack::FAST_NGINX_TABLE;
#[cfg(feature = "table-fast-nginx-vz")]
pub const TABLE: &[Record] = fstack::FAST_NGINX_VZ_TABLE;
#[cfg(feature = "table-fast-scale")]
pub const TABLE: &[Record] = fstack::FAST_SCALE_TABLE;
#[cfg(feature = "table-fast-scale-vz")]
pub const TABLE: &[Record] = fstack::FAST_SCALE_VZ_TABLE;
#[cfg(feature = "table-fast-switch")]
pub const TABLE: &[Record] = fstack::FAST_SWITCH_TABLE;
#[cfg(feature = "table-fast-switch-vz")]
pub const TABLE: &[Record] = fstack::FAST_SWITCH_VZ_TABLE;
#[cfg(feature = "table-fast-switch-scale")]
pub const TABLE: &[Record] = fstack::FAST_SWITCH_SCALE_TABLE;
#[cfg(feature = "table-fast-switch-scale-vz")]
pub const TABLE: &[Record] = fstack::FAST_SWITCH_SCALE_VZ_TABLE;
#[cfg(feature = "table-posix-map-big")]
pub const TABLE: &[Record] = ramfs::POSIX_MAP_BIG_TABLE;

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
            shares: Shares::CREATOR,
            cpus: GENERAL_CPUS,
            waits: &[],
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
        duplicate: false,
    };
    const RTC_IRQ: Binding = Binding {
        name: "rtc-irq",
        line: 34,
        edge: false,
    };

    /// The layer session goes to one named client that connects to the RAM service.
    #[test]
    fn layer_clients_are_one_non_posix_client_of_the_ram_service() {
        let ram = service("ramfs", 40, 40);
        let layer = client("layer-probe", 30, 30, &["ramfs"]);
        assert!(check(&[ram, layer]).is_ok());
        let blind = client("layer-probe", 30, 30, &[]);
        assert!(matches!(
            check(&[ram, blind]),
            Err(TableError::Layers {
                record: "layer-probe"
            })
        ));
        let posix = client("layer-probe", 30, 30, &["ramfs", PROCESS_SERVICE]);
        assert!(matches!(
            check(&[ram, service(PROCESS_SERVICE, 40, 40), posix]),
            Err(TableError::Layers {
                record: "layer-probe"
            })
        ));
        // The session is not the boot profile: the label of one is not the other's.
        assert!(!proto_fs::is_boot_profile(proto_fs::LAYERS | 1));
        assert!(!proto_fs::is_layers(proto_fs::BOOT_PROFILE | 1));
        assert!(layer_grant(&layer, RAM_LAYERS.as_bytes()));
        assert!(!layer_grant(&layer, RAM_SERVICE.as_bytes()));
        let other = client("other", 30, 30, &["ramfs"]);
        assert!(!layer_grant(&other, RAM_LAYERS.as_bytes()));
        assert!(!layer_grant(&posix, RAM_LAYERS.as_bytes()));
        assert!(LAYER_CLIENTS.contains(&"layer-probe"));
        assert!(!LAYER_CLIENTS.contains(&"ramfs-probe") && !LAYER_CLIENTS.contains(&NET_SERVICE));
    }

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
    fn native_vz_keeps_the_existing_paid_pool_and_hardware_owners() {
        let table = vz::POSIX_NATIVE_TABLE;
        check(table).unwrap();
        assert_eq!(table.len(), ramfs::POSIX_PROCS_TABLE.len() + 1);
        assert_eq!(table[0], vz::CONSOLE);
        assert_eq!(&table[1..6], &ramfs::POSIX_PROCS_TABLE[..5]);
        assert_eq!(table[6], entropy::RNG_VZ);
        assert_eq!(table[7], ramfs::POSIX_PROCS_TABLE[6]);
        assert_eq!(table[2].quota, ramfs::POSIX_PROCS_TABLE[1].quota);
    }

    #[test]
    fn loader_roots_keep_start_dependencies_and_allow_lower_service_levels() {
        let records = [
            Record {
                connects: &["ramfs", "clock"],
                ..service("posix", 48, 48)
            },
            service("ramfs", 40, 40),
            service("clock", 32, 32),
        ];
        assert_eq!(order_of(&records), ["ramfs", "clock", "posix"]);
        let ordinary = [
            Record {
                name: "ordinary",
                ..records[0]
            },
            records[1],
            records[2],
        ];
        assert!(matches!(
            check(&ordinary),
            Err(TableError::BelowClient { .. })
        ));
        let missing = [records[0], records[1]];
        assert!(matches!(check(&missing), Err(TableError::Unknown { .. })));
        let cycle = [
            records[0],
            records[1],
            Record {
                connects: &["posix"],
                ..records[2]
            },
        ];
        assert!(matches!(check(&cycle), Err(TableError::Cycle(_))));
    }

    /// Spec 2, 2: the process service at 52, the terminal at 50, the files
    /// and the pipes at 48, the clock no lower than the files (their client);
    /// a client of the terminal above 50 is refused by rule 6.6.
    #[test]
    fn the_services_stand_at_their_levels() {
        let table = ramfs::RTBENCH_POSIX_TABLE;
        assert!(check(table).is_ok());
        let level = |name: &str| table.iter().find(|r| r.name == name).unwrap().priority;
        assert_eq!(level("posix"), 52);
        assert_eq!(level("tty"), 50);
        assert_eq!((level("ramfs"), level("pipe")), (48, 48));
        assert!(level("clock") >= level("ramfs"));
        // Every record that is a POSIX process stays below the services.
        assert!(
            table
                .iter()
                .filter(|r| r.is_posix())
                .all(|r| r.ceiling < 40)
        );
        let mut raised = table.to_vec();
        raised.push(client("loud", 30, 53, &["tty"]));
        assert_eq!(
            refused(&raised),
            "tty at priority 50 is below the ceiling 53 of its client loud"
        );
        raised.pop();
        raised.push(client("fine", 30, 50, &["tty"]));
        assert!(check(&raised).is_ok());
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
            duplicate: false,
        };
        const W3: Window = Window {
            name: "rtc3",
            base: 0x0903_0000,
            len: PAGE,
            duplicate: false,
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
                duplicate: false,
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
            duplicate: false,
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

    /// No two records of a table hold windows on one page: a device window
    /// is a page, and a second device on it would share the registers of
    /// the first (spec 9). The page of the transports 0 to 6 and the
    /// network device is 0xa000000; the keyboard has 0xa001000 and the
    /// display device 0xa002000.
    #[test]
    fn no_two_records_of_a_table_share_a_device_page() {
        for table in [
            net::NET_TABLE,
            net::NET_PROBE_TABLE,
            net::NET_VZ_TABLE,
            net::NET_VZ2_TABLE,
            bench::BENCH_VZ_TABLE,
            bench::BENCH_PINNED_VZ_TABLE,
            bench::BENCH_CPU0_VZ_TABLE,
            bench::BENCH_FAST_VZ_TABLE,
            net::NET_PROBE_TWO_TABLE,
            net::NET_TWO_TABLE,
            doom::TABLE,
            base::BASE_TABLE,
            gpu::TABLE,
            input::TABLE,
            entropy::TABLE,
            normal::TABLE,
        ] {
            let mut pages: Vec<(u64, &str)> = Vec::new();
            for r in table {
                for w in r.windows {
                    for page in (w.base / PAGE..(w.base + w.len) / PAGE).map(|p| p * PAGE) {
                        if let Some((_, other)) = pages.iter().find(|(p, _)| *p == page) {
                            panic!("{} and {other} share the page {page:#x}", r.name);
                        }
                        pages.push((page, r.name));
                    }
                }
            }
        }
    }

    /// The records of the network on VZ hold the numbers the service has
    /// (`netd::pci`), and their windows touch neither the pages of the
    /// console's function (device 5) and the entropy device's (6) nor the
    /// BARs of those two, which sit before the network's.
    #[test]
    fn the_network_records_of_vz_agree_with_the_service_and_leave_the_others_alone() {
        let record = net::NETD_VZ;
        let window = |name: &str| *record.windows.iter().find(|w| w.name == name).unwrap();
        let (ecam_base, ecam_len) = netd::pci::ecam_window(1);
        assert_eq!(
            (window("ecam").base, window("ecam").len),
            (ecam_base, ecam_len)
        );
        let (bar_base, bar_len) = netd::pci::bar_window(1);
        assert_eq!((window("bar").base, window("bar").len), (bar_base, bar_len));
        assert_eq!(record.bindings[0].line, netd::pci::line(0));
        assert_eq!(record.args[..8], netd::pci::function(0).to_le_bytes());
        // The stop: the reset through BAR 0 gated on decoding, then the
        // command word, at the offsets of device 0 inside the windows.
        assert_eq!(record.quiesce.len(), 2);
        assert_eq!(
            record.quiesce[0].offset,
            netd::pci::bar_offset(0) + netd::pci::DEVICE_STATUS
        );
        assert_eq!(
            record.quiesce[1].offset,
            netd::pci::ecam_offset(0) + COMMAND_WORD
        );
        let mut pages: Vec<(u64, &str)> = Vec::new();
        for r in net::NET_VZ_TABLE {
            for w in r.windows {
                for page in (w.base / PAGE..(w.base + w.len) / PAGE).map(|p| p * PAGE) {
                    if let Some((_, other)) = pages.iter().find(|(p, _)| *p == page) {
                        panic!("{} and {other} share the page {page:#x}", r.name);
                    }
                    pages.push((page, r.name));
                }
            }
        }
        assert!(pages.iter().any(|&(_, n)| n == "uart"));
        assert!(pages.iter().any(|&(_, n)| n == "rng"));
    }

    /// The record of two network devices holds the windows of both, the
    /// lines of both, and four names in all (REGISTER's reply gives at
    /// most `START_NAMES`).
    #[test]
    fn the_records_of_two_network_devices_have_four_names_and_the_numbers_of_the_service() {
        for record in [net::NETD_VZ2, net::NETD_TWO] {
            assert_eq!(record.windows.len() + record.bindings.len(), 4);
            assert_eq!(record.args.len(), 16);
            // The first device's objects as in the record of one device,
            // the second device's own: its queues and four objects of 4 MiB,
            // which the service hands on (DUPLICATE).
            assert_eq!(record.dma[..2], net::NETD.dma[..]);
            let names: Vec<_> = record.dma.iter().map(|d| d.name).collect();
            assert_eq!(
                names,
                ["dma", "net", "dma1", "net1a", "net1b", "net1c", "net1d"]
            );
            assert_eq!(
                (record.dma[2].size, record.dma[2].uncached),
                (8 * PAGE, true)
            );
            for d in &record.dma[3..] {
                assert_eq!((d.size, d.uncached), (4 * 1024 * 1024, false), "{}", d.name);
                assert_eq!(d.size / PAGE, abi::MAX_CONTIGUOUS_PAGES);
            }
            assert!(record.dma[2..].iter().all(|d| d.duplicate));
            assert!(!record.dma[..2].iter().any(|d| d.duplicate));
            // `console` and the seven objects: all the names start data has.
            assert_eq!(start_data_names(&record), START_DATA_MAX);
            // The window of the second device can be copied; the first's
            // window on QEMU cannot.
            assert!(record.windows[record.windows.len() - 1].duplicate);
            // Each line has its own label, in the order of the bindings.
            assert_eq!(binding_label(&record, 0), Some(proto_init::BINDING_LABEL));
            assert_eq!(
                binding_label(&record, 1),
                Some(proto_init::BINDING_LABEL | 1)
            );
            assert_eq!(binding_label(&record, 2), None);
        }
        assert!(!net::NETD_TWO.windows[0].duplicate);
        // Only the network service declares a thread of its own for its first
        // line, and its ceiling is above its priority; its first line goes
        // through the second channel when one comes, the second line of a
        // record of two devices keeps its label, and no other service gets
        // the second channel.
        for record in [net::NETD, net::NETD_VZ, net::NETD_VZ2, net::NETD_TWO] {
            assert!(line_thread(&record), "{}", record.name);
            assert!(record.ceiling > record.priority);
            assert_eq!(binding_route(&record, 0, true), Through::Bound);
            assert_eq!(
                binding_route(&record, 0, false),
                match binding_label(&record, 0) {
                    Some(label) => Through::Labelled(label),
                    None => Through::Plain,
                }
            );
        }
        assert_eq!(
            binding_route(&net::NETD_TWO, 1, true),
            Through::Labelled(proto_init::BINDING_LABEL | 1)
        );
        assert_eq!(binding_route(&net::NETD, 1, true), Through::Plain);
        // Another service, or the same one with no room above its priority
        // or with no line, has none.
        assert!(!line_thread(&service("rng-like", 35, 36)));
        let flat = Record {
            ceiling: net::NETD.priority,
            ..net::NETD
        };
        assert!(!line_thread(&flat));
        let lineless = Record {
            bindings: &[],
            ..net::NETD
        };
        assert!(!line_thread(&lineless));
        assert_eq!(binding_route(&flat, 0, true), Through::Plain);
        // The records of one device bind their line through the channel.
        for record in [net::NETD, net::NETD_VZ] {
            assert_eq!(binding_label(&record, 0), None);
            assert!(record.windows.iter().all(|w| !w.duplicate));
        }
        let vz = net::NETD_VZ2;
        let (ecam, ecam_len) = netd::pci::ecam_window(2);
        let (bar, bar_len) = netd::pci::bar_window(2);
        assert_eq!((vz.windows[0].base, vz.windows[0].len), (ecam, ecam_len));
        assert_eq!((vz.windows[1].base, vz.windows[1].len), (bar, bar_len));
        assert_eq!(vz.bindings[0].line, netd::pci::line(0));
        assert_eq!(vz.bindings[1].line, netd::pci::line(1));
        assert_eq!(vz.args[8..], netd::pci::function(1).to_le_bytes());
        // Four writes: the reset through BAR 0 and the command word of
        // each device, at its own offsets in the windows.
        assert_eq!(vz.quiesce.len(), 4);
        assert_eq!(
            vz.quiesce[2].offset,
            netd::pci::bar_offset(1) + netd::pci::DEVICE_STATUS
        );
        assert_eq!(
            vz.quiesce[3].offset,
            netd::pci::ecam_offset(1) + COMMAND_WORD
        );
        assert_eq!(vz.quiesce[2].window, "bar");
        assert_eq!(vz.quiesce[3].window, "ecam");
        // Their windows and lines are those of the one-device record's,
        // extended.
        assert_eq!(vz.windows[0].base, net::NETD_VZ.windows[0].base);
        assert_eq!(vz.bindings[0], net::NETD_VZ.bindings[0]);
        // QEMU: the transports 7 and 14, lines 55 and 62, in two pages.
        let qemu = net::NETD_TWO;
        assert_eq!(qemu.windows[0].base, 0x0a00_0000);
        assert_eq!(qemu.windows[1].base, 0x0a00_1000);
        assert_eq!(qemu.bindings[1].line, 62);
        assert_eq!(qemu.args[8..], 0x0a00_1c00u64.to_le_bytes());
        assert_eq!(qemu.quiesce[1].offset, 0xc70);
    }

    #[test]
    fn the_names_of_the_start_data_fit_the_giver() {
        static OBJECTS: [Dma; 8] = [Dma {
            name: "o",
            size: PAGE,
            uncached: false,
            duplicate: false,
        }; 8];
        let objects = &OBJECTS;
        let names = ["o0", "o1", "o2", "o3", "o4", "o5", "o6", "o7"];
        let with = |count: usize, log: bool| {
            let dma: Vec<Dma> = (0..count)
                .map(|i| Dma {
                    name: names[i],
                    ..objects[i]
                })
                .collect();
            check_one(Record {
                dma: Box::leak(dma.into_boxed_slice()),
                console: true,
                log,
                trusted: true,
                ..service("driver", 40, 40)
            })
        };
        let record = |count, log| Record {
            dma: &objects[..count],
            console: true,
            log,
            ..service("driver", 40, 40)
        };
        assert_eq!(start_data_names(&record(7, false)), 8, "console and 7");
        assert!(with(7, false).is_ok());
        assert_eq!(
            with(7, true),
            Err(TableError::StartNames {
                record: "driver",
                count: 9
            })
        );
        assert_eq!(
            with(8, false),
            Err(TableError::StartNames {
                record: "driver",
                count: 9
            })
        );
        assert!(with(6, true).is_ok());
    }

    #[test]
    fn the_images_of_two_network_devices_pass_the_table_check() {
        let shell = order_of(net::NET_VZ2_TABLE);
        assert_eq!(shell.len(), 10);
        assert_eq!(shell[8], NET_SERVICE);
        assert_eq!(
            order_of(net::NET_PROBE_TWO_TABLE),
            ["ramfs", "rng", "entropy", "net", "net-probe"]
        );
        // The shell's image of QEMU with both devices: the shell's order,
        // the service with the objects of the second device.
        assert_eq!(order_of(net::NET_TWO_TABLE), order_of(net::NET_TABLE));
        assert_eq!(net::NET_TWO_TABLE[9].dma.len(), 7);
    }

    /// The command word of a PCI function.
    const COMMAND_WORD: u64 = 4;

    #[test]
    fn the_network_image_of_vz_passes_the_table_check() {
        assert_eq!(
            order_of(net::NET_VZ_TABLE),
            [
                "uart",
                "tty",
                "clock",
                "pipe",
                "ramfs",
                "posix",
                "rng",
                "entropy",
                "net",
                "busybox-probe"
            ]
        );
    }

    /// The image of the measurement of stage P7 is the network image of VZ
    /// with the launcher of the shell on all four CPUs; the network service
    /// stays on the boot CPU and the services on the CPUs of the services.
    /// The log driver's first thread asks for CPU 1 only when its mask has
    /// it: the image `cpu0` keeps every program but the process service on
    /// CPU 0 and must start on two CPUs or more.
    #[test]
    fn the_first_cpu_of_the_log_driver_is_in_its_mask() {
        assert_eq!(first_cpu(true, GENERAL_CPUS), 2);
        assert_eq!(first_cpu(true, BENCH_CPUS), 2);
        assert_eq!(first_cpu(true, NETD_CPUS), 0);
        assert_eq!(first_cpu(true, RT_CPUS), 0);
        assert_eq!(first_cpu(false, GENERAL_CPUS), 0);
        for r in bench::BENCH_CPU0_VZ_TABLE {
            let (mask, _) = on_cpus(r.cpus, 0b1111);
            let cpu = first_cpu(r.log, mask);
            assert!(cpu == 0 || mask & (1 << (cpu - 1)) != 0, "{}", r.name);
        }
        assert!(
            bench::BENCH_CPU0_VZ_TABLE
                .iter()
                .any(|r| r.log && first_cpu(r.log, r.cpus) == 0)
        );
    }

    #[test]
    fn the_bench_image_differs_from_the_network_image_of_vz_in_the_launcher_alone() {
        assert_eq!(order_of(bench::BENCH_VZ_TABLE), order_of(net::NET_VZ_TABLE));
        assert_eq!(BENCH_CPUS, 0b1111);
        assert_eq!(bench::BENCH_LAUNCHER.name, net::NET_LAUNCHER.name);
        assert_eq!(
            bench::BENCH_VZ_TABLE
                .iter()
                .filter(|r| r.cpus == BENCH_CPUS)
                .count(),
            1
        );
        for (bench, net) in bench::BENCH_VZ_TABLE.iter().zip(net::NET_VZ_TABLE) {
            if bench.name == bench::BENCH_LAUNCHER.name {
                assert_eq!(bench.cpus, BENCH_CPUS);
                assert_eq!(
                    Record {
                        cpus: net.cpus,
                        ..*bench
                    },
                    *net
                );
            } else {
                assert_eq!(bench, net, "{}", bench.name);
            }
        }
        let netd = bench::BENCH_VZ_TABLE
            .iter()
            .find(|r| r.name == NET_SERVICE)
            .unwrap();
        assert_eq!(netd.cpus, NETD_CPUS);
    }

    /// The pinned variant of the image of the measurement differs from it in
    /// the launcher's mask alone: CPUs 1 to 3.
    #[test]
    fn the_pinned_bench_image_differs_from_the_bench_image_in_the_launcher_mask_alone() {
        assert_eq!(BENCH_PINNED_CPUS, 0b1110);
        assert_eq!(
            order_of(bench::BENCH_PINNED_VZ_TABLE),
            order_of(bench::BENCH_VZ_TABLE)
        );
        for (pinned, plain) in bench::BENCH_PINNED_VZ_TABLE
            .iter()
            .zip(bench::BENCH_VZ_TABLE)
        {
            if pinned.name == bench::BENCH_LAUNCHER.name {
                assert_eq!(pinned.cpus, BENCH_PINNED_CPUS);
                assert_eq!(
                    Record {
                        cpus: plain.cpus,
                        ..*pinned
                    },
                    *plain
                );
            } else {
                assert_eq!(pinned, plain, "{}", pinned.name);
            }
        }
    }

    /// The table of the image with every program on CPU 0 differs from the
    /// image of the measurement in the masks alone: all on the boot CPU but
    /// the process service, which keeps every CPU to place its processes.
    #[test]
    fn the_cpu0_bench_image_puts_every_program_but_the_process_service_on_cpu_0() {
        assert_eq!(
            order_of(bench::BENCH_CPU0_VZ_TABLE),
            order_of(bench::BENCH_VZ_TABLE)
        );
        for (one, plain) in bench::BENCH_CPU0_VZ_TABLE.iter().zip(bench::BENCH_VZ_TABLE) {
            let cpus = if plain.cpus == ALL_CPUS {
                ALL_CPUS
            } else {
                0b0001
            };
            assert_eq!(*one, Record { cpus, ..*plain }, "{}", one.name);
        }
    }

    /// The grants of quota in the tables (spec 2, 3.12.2, K5): every line
    /// is read, the init record it is `under` is the only one of its
    /// program in the same table, and the pool of the process service holds
    /// the pages of all the places.
    #[test]
    fn the_grants_of_the_tables_are_read_name_a_record_and_fit_the_pool() {
        let tables: [(&[Record], &[Record]); 4] = [
            (fstack::FAST_SCALE_TABLE, fstack::FAST_NGINX_TABLE),
            (fstack::FAST_SCALE_VZ_TABLE, fstack::FAST_NGINX_VZ_TABLE),
            (ramfs::POSIX_MAP_BIG_TABLE, ramfs::POSIX_PROCS_TABLE),
            (ramfs::POSIX_STEPS_TABLE, ramfs::POSIX_STEPS_TABLE),
        ];
        for (n, (table, plain)) in tables.into_iter().enumerate() {
            let service = table
                .iter()
                .find(|r| r.args.starts_with(b"grant "))
                .expect("the process service carries the grants");
            assert_eq!(service.program, "posix-process-service");
            let grants = proto_init::Grants::parse(service.args).expect("the lines are read");
            assert!(proto_init::OWN_ARGS_MAX >= service.args.len());
            assert!(grants.len > 0);
            for line in grants.lines() {
                let under = core::str::from_utf8(line.under()).unwrap();
                assert_eq!(
                    table.iter().filter(|r| r.program == under).count(),
                    1,
                    "{under} is not the program of exactly one record of the table"
                );
            }
            let pool = service.quota;
            if n < 3 {
                let base = plain.iter().find(|r| r.program == service.program).unwrap();
                assert_eq!(
                    pool,
                    base.quota + grants.pages_total() * PAGE,
                    "the pool holds the places of the grants and no more"
                );
            }
            assert!(
                pool >= grants.pages_total() * PAGE + 384 * PAGE,
                "the pool holds the places of the grants and the reserve of the service"
            );
        }
    }

    /// The image of the row F1 is the image of nginx on the stack on VZ with
    /// the launcher of the shell on all four CPUs and nothing else changed.
    #[test]
    fn the_fast_bench_image_differs_from_the_image_of_nginx_on_vz_in_the_launcher_alone() {
        assert_eq!(
            order_of(bench::BENCH_FAST_VZ_TABLE),
            order_of(fstack::FAST_NGINX_VZ_TABLE)
        );
        assert_eq!(
            bench::BENCH_FAST_VZ_TABLE
                .iter()
                .filter(|r| r.cpus == BENCH_CPUS)
                .count(),
            1
        );
        for (bench, fast) in bench::BENCH_FAST_VZ_TABLE
            .iter()
            .zip(fstack::FAST_NGINX_VZ_TABLE)
        {
            if bench.name == net::NET_LAUNCHER.name {
                assert_eq!(bench.cpus, BENCH_CPUS);
                assert_eq!(
                    Record {
                        cpus: fast.cpus,
                        ..*bench
                    },
                    *fast
                );
            } else {
                assert_eq!(bench, fast, "{}", bench.name);
            }
        }
        let netd = bench::BENCH_FAST_VZ_TABLE
            .iter()
            .find(|r| r.name == NET_SERVICE)
            .unwrap();
        assert_eq!(netd.cpus, NETD_CPUS);
    }

    /// No other table names `BENCH_CPUS`: not by the constant (a scan of the
    /// sources of `table/`), and not by the value (every record of every
    /// other table stands on a mask of the SMP decision or on a mask of a
    /// test image's own, which is none of the four CPUs).
    #[test]
    fn only_the_bench_table_stands_on_the_bench_cpus() {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/table");
        let mut users = Vec::new();
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if std::fs::read_to_string(&path)
                .unwrap()
                .contains("BENCH_CPUS")
            {
                users.push(path.file_name().unwrap().to_string_lossy().into_owned());
            }
        }
        assert_eq!(users, ["bench.rs"]);
        for table in all_tables() {
            for r in table {
                assert_ne!(r.cpus, BENCH_CPUS, "{}", r.name);
            }
        }
    }

    /// Every table of the images but the bench table (feature-gated tables
    /// are listed as they stand in a test build).
    fn all_tables() -> Vec<&'static [Record]> {
        vec![
            normal::TABLE,
            cycle::TABLE,
            ceiling::TABLE,
            test::TABLE,
            lock_ring::TABLE,
            doom::TABLE,
            base::BASE_TABLE,
            gpu::TABLE,
            input::TABLE,
            entropy::TABLE,
            entropy::VZ_TABLE,
            fstack::FSTACK_TABLE,
            fstack::FSTACK_DEVICE_TABLE,
            fstack::FAST_NGINX_TABLE,
            fstack::FAST_NGINX_VZ_TABLE,
            fstack::FAST_SCALE_TABLE,
            fstack::FAST_SCALE_VZ_TABLE,
            fstack::FAST_SWITCH_TABLE,
            fstack::FAST_SWITCH_VZ_TABLE,
            fstack::FAST_SWITCH_SCALE_TABLE,
            fstack::FAST_SWITCH_SCALE_VZ_TABLE,
            ramfs::POSIX_MAP_BIG_TABLE,
            net::NET_TABLE,
            net::NET_TWO_TABLE,
            net::NET_VZ_TABLE,
            net::NET_VZ2_TABLE,
            net::NET_PROBE_TABLE,
            net::NET_PROBE_TWO_TABLE,
            vz::TABLE,
            vz::PCI_WALK_TABLE,
            pkg::PCI_WALK_QEMU_TABLE,
            pkg::BLK_PROBE_TABLE,
            vz::POSIX_ABI_TABLE,
            vz::POSIX_NATIVE_TABLE,
            vz::BUSYBOX_DIALOG_TABLE,
            vz::POSIX_TTY_TABLE,
            vz::POSIX_DIALOG_TABLE,
            vz::RTBENCH_TABLE,
            vz::RTBENCH_POSIX_TABLE,
            vz::TTY_TABLE,
            ramfs::TABLE,
            ramfs::BUSYBOX_TABLE,
            ramfs::BUSYBOX_DIALOG_TABLE,
            ramfs::POSIX_TTY_TABLE,
            ramfs::POSIX_DIALOG_TABLE,
            ramfs::POSIX_FILES_TABLE,
            ramfs::LAYER_PROBE_TABLE,
            ramfs::POSIX_ABI_TABLE,
            ramfs::RELIBC_TABLE,
            ramfs::POSIX_PROCS_TABLE,
            ramfs::POSIX_SHARES_TABLE,
            ramfs::POSIX_STEPS_TABLE,
            ramfs::OS_TEST_TABLE,
            ramfs::RELIBC_THREADS_TABLE,
            ramfs::RTBENCH_POSIX_TABLE,
            ramfs::TTY_TABLE,
            ramfs::TTY_STEPS_TABLE,
            ramfs::POSIX_RANDOM_TABLE,
            ramfs::POSIX_DISPLAY_TABLE,
            ramfs::DISPLAY_TABLE,
            ramfs::LOADER_CHANNELS_TABLE,
            ramfs::POSIX_POLL_TABLE,
            ramfs::POSIX_SOCK_TABLE,
            ramfs::POSIX_IPC_TABLE,
            ramfs::POSIX_PTY_TABLE,
        ]
    }

    #[test]
    fn the_network_service_is_given_the_boot_profile_and_the_probe_is_not() {
        assert!(BOOT_PROFILE_CLIENTS.contains(&net::NETD.name));
        assert!(BOOT_PROFILE_CLIENTS.contains(&"ramfs-probe"));
        assert!(!BOOT_PROFILE_CLIENTS.contains(&net::PROBE.name));
        let ram = net::NET_PROBE_TABLE
            .iter()
            .find(|r| r.name == RAM_SERVICE)
            .unwrap();
        assert!(net::NETD.connects.contains(&ram.name));
    }

    /// Only the image with the network service gives its launcher (and so
    /// the shell) a session with it, and its process service has the pool
    /// for the children of `httpd`: ten more quotas of a command than the
    /// shell's image.
    #[test]
    fn the_network_session_goes_to_the_launcher_of_the_network_image_alone() {
        let has = |table: &[Record]| table.iter().any(|r| r.connects.contains(&NET_SERVICE));
        assert!(has(net::NET_TABLE));
        // The base image has the network service too, with the screen.
        assert!(has(base::BASE_TABLE));
        let launcher = net::NET_TABLE
            .iter()
            .find(|r| r.program == "ash-launcher")
            .unwrap();
        assert!(launcher.connects.contains(&NET_SERVICE));
        assert!(
            !ramfs::BUSYBOX_DIALOG_TABLE
                .iter()
                .any(|r| r.connects.contains(&NET_SERVICE))
        );
        for table in [
            ramfs::TABLE,
            ramfs::BUSYBOX_TABLE,
            ramfs::POSIX_ABI_TABLE,
            ramfs::POSIX_SOCK_TABLE,
            ramfs::POSIX_POLL_TABLE,
            ramfs::POSIX_PROCS_TABLE,
            doom::TABLE,
            normal::TABLE,
        ] {
            assert!(!has(table));
        }
        let plain = ramfs::BUSYBOX_DIALOG_TABLE[2];
        let process = net::NET_TABLE[2];
        assert_eq!(process.program, plain.program);
        assert_eq!(process.quota - plain.quota, 16 * net::NET_COMMAND_QUOTA);
        assert_eq!(launcher.quota, net::NET_COMMAND_QUOTA);
    }

    #[test]
    fn fifo_broker_authority_is_limited_to_the_ram_service() {
        let ram = ramfs::POSIX_PROCS_TABLE[0];
        assert!(fifo_broker_grant(&ram, PIPE_SERVICE.as_bytes()));
        assert!(!fifo_broker_grant(&ram, RAM_SERVICE.as_bytes()));
        for record in ramfs::POSIX_PROCS_TABLE.iter().skip(1) {
            assert!(!fifo_broker_grant(record, PIPE_SERVICE.as_bytes()));
        }
        let counterfeit = Record {
            kind: Kind::Client,
            ..ram
        };
        assert!(!fifo_broker_grant(&counterfeit, PIPE_SERVICE.as_bytes()));
        assert_eq!(proto_pipe::RAM_BROKER & proto_pipe::OWN, 0);
    }

    #[test]
    fn ram_time_profiles_require_clock_before_ram_and_process() {
        assert_eq!(ramfs::TABLE[0].args, proto_fs::RAM_TIME_LEGACY);
        assert!(ramfs::TABLE[0].connects.is_empty());
        for table in [
            ramfs::BUSYBOX_TABLE,
            ramfs::BUSYBOX_DIALOG_TABLE,
            doom::TABLE,
            base::BASE_TABLE,
            ramfs::POSIX_TTY_TABLE,
            ramfs::POSIX_DIALOG_TABLE,
            ramfs::POSIX_FILES_TABLE,
            ramfs::POSIX_ABI_TABLE,
            ramfs::RELIBC_TABLE,
            ramfs::POSIX_PROCS_TABLE,
            ramfs::POSIX_STEPS_TABLE,
            ramfs::OS_TEST_TABLE,
            ramfs::RELIBC_THREADS_TABLE,
            ramfs::RTBENCH_POSIX_TABLE,
            ramfs::POSIX_RANDOM_TABLE,
            ramfs::POSIX_DISPLAY_TABLE,
            ramfs::DISPLAY_TABLE,
            ramfs::LOADER_CHANNELS_TABLE,
            ramfs::POSIX_POLL_TABLE,
            ramfs::POSIX_SOCK_TABLE,
            ramfs::POSIX_IPC_TABLE,
            ramfs::POSIX_PTY_TABLE,
            vz::POSIX_ABI_TABLE,
            vz::POSIX_NATIVE_TABLE,
            vz::BUSYBOX_DIALOG_TABLE,
            vz::POSIX_TTY_TABLE,
            vz::POSIX_DIALOG_TABLE,
            vz::RTBENCH_POSIX_TABLE,
        ] {
            check(table).unwrap();
            let ram = table.iter().find(|r| r.name == "ramfs").unwrap();
            let clock = table.iter().find(|r| r.name == "clock").unwrap();
            assert_eq!(ram.args, proto_fs::RAM_TIME_CLOCKED);
            let has_pipe = table.iter().any(|r| r.name == PIPE_SERVICE);
            assert_eq!(
                ram.connects,
                if has_pipe {
                    &["clock", "pipe"][..]
                } else {
                    &["clock"][..]
                }
            );
            if has_pipe {
                assert!(fifo_broker_grant(ram, PIPE_SERVICE.as_bytes()));
            }
            assert!(clock.connects.is_empty());
            let order = order_of(table);
            let position = |name| order.iter().position(|n| *n == name).unwrap();
            assert!(position("clock") < position("ramfs"));
            if has_pipe {
                assert!(position("pipe") < position("ramfs"));
            }
            assert!(position("ramfs") < position("posix"));
        }
        let bad: Vec<_> = ramfs::POSIX_FILES_TABLE
            .iter()
            .map(|r| {
                if r.name == "clock" {
                    Record {
                        connects: &["clock"],
                        ..*r
                    }
                } else {
                    *r
                }
            })
            .collect();
        assert!(check(&bad).is_err());
    }

    /// The tables of the images (spec 15.2): the one that ships and the
    /// test table pass, in the order of their dependencies; the two bad
    /// tables are refused with the reasons xtask looks for in their runs.
    #[test]
    fn the_tables_of_the_images_pass_or_are_refused() {
        assert_eq!(
            order_of(ramfs::LOADER_CHANNELS_TABLE),
            [
                "uart",
                "tty",
                "clock",
                "pipe",
                "ramfs",
                "posix",
                "rng",
                "entropy",
                "posix-procs"
            ]
        );
        assert_eq!(order_of(normal::TABLE), ["uart", "shell"]);
        assert_eq!(
            order_of(fstack::FSTACK_TABLE),
            order_of(ramfs::BUSYBOX_DIALOG_TABLE)
        );
        assert_eq!(
            order_of(fstack::FSTACK_DEVICE_TABLE),
            order_of(net::NET_TWO_TABLE)
        );
        assert_eq!(
            order_of(fstack::FAST_NGINX_TABLE),
            order_of(net::NET_TWO_TABLE)
        );
        assert_eq!(
            order_of(fstack::FAST_NGINX_VZ_TABLE),
            order_of(net::NET_VZ2_TABLE)
        );
        assert_eq!(
            order_of(fstack::FAST_SCALE_TABLE),
            order_of(fstack::FAST_NGINX_TABLE)
        );
        assert_eq!(
            order_of(fstack::FAST_SCALE_VZ_TABLE),
            order_of(fstack::FAST_NGINX_VZ_TABLE)
        );
        for (switch, one) in [
            (fstack::FAST_SWITCH_TABLE, net::NET_TABLE),
            (fstack::FAST_SWITCH_SCALE_TABLE, net::NET_TABLE),
            (fstack::FAST_SWITCH_VZ_TABLE, net::NET_VZ_TABLE),
            (fstack::FAST_SWITCH_SCALE_VZ_TABLE, net::NET_VZ_TABLE),
        ] {
            assert_eq!(order_of(switch), order_of(one));
        }
        assert_eq!(
            order_of(ramfs::POSIX_MAP_BIG_TABLE),
            order_of(ramfs::POSIX_PROCS_TABLE)
        );
        assert_eq!(order_of(vz::TABLE), ["uart", "shell"]);
        assert_eq!(
            order_of(vz::POSIX_ABI_TABLE),
            [
                "uart",
                "long",
                "clock",
                "ramfs",
                "posix",
                "clock-peer",
                "posix-abi-probe",
                "posix-sender"
            ]
        );
        for table in [vz::POSIX_TTY_TABLE, ramfs::POSIX_TTY_TABLE] {
            assert_eq!(
                order_of(table),
                [
                    "uart",
                    "tty",
                    "clock",
                    "pipe",
                    "ramfs",
                    "posix",
                    "posix-tty"
                ]
            );
        }
        for table in [ramfs::TTY_TABLE, vz::TTY_TABLE, ramfs::TTY_STEPS_TABLE] {
            assert_eq!(order_of(table), ["uart", "tty", "tty-probe"]);
        }
        assert_eq!(
            order_of(vz::BUSYBOX_DIALOG_TABLE),
            [
                "uart",
                "tty",
                "clock",
                "pipe",
                "ramfs",
                "posix",
                "busybox-probe"
            ]
        );
        assert_eq!(
            order_of(ramfs::BUSYBOX_DIALOG_TABLE),
            [
                "uart",
                "tty",
                "clock",
                "pipe",
                "ramfs",
                "posix",
                "rng",
                "entropy",
                "busybox-probe"
            ]
        );
        assert_eq!(
            order_of(ramfs::OS_TEST_TABLE),
            [
                "uart",
                "tty",
                "clock",
                "pipe",
                "ramfs",
                "posix",
                "rng",
                "entropy",
                "os-test-run"
            ]
        );
        assert_eq!(order_of(vz::RTBENCH_TABLE), ["uart", "rtbench"]);
        assert_eq!(
            order_of(ramfs::RELIBC_TABLE),
            [
                "clock",
                "ramfs",
                "posix",
                "relibc-hello",
                "relibc-abort",
                "relibc-assert",
                "relibc-panic"
            ]
        );
        assert_eq!(
            order_of(ramfs::RELIBC_THREADS_TABLE),
            ["clock", "ramfs", "posix", "relibc-threads"]
        );
        assert_eq!(
            order_of(ramfs::POSIX_PROCS_TABLE),
            [
                "clock",
                "pipe",
                "ramfs",
                "posix",
                "rng",
                "entropy",
                "posix-procs"
            ]
        );
        for table in [ramfs::RTBENCH_POSIX_TABLE, vz::RTBENCH_POSIX_TABLE] {
            assert_eq!(
                order_of(table),
                [
                    "uart",
                    "tty",
                    "clock",
                    "pipe",
                    "ramfs",
                    "posix",
                    "bench-uart",
                    "rtbench-load",
                    "rng",
                    "entropy",
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
            order_of(entropy::TABLE),
            ["rng", "entropy", "entropy-probe", "entropy-probe-b"]
        );
        assert_eq!(
            order_of(entropy::VZ_TABLE),
            ["uart", "rng", "entropy", "entropy-probe", "entropy-probe-b"]
        );
        assert_eq!(order_of(gpu::TABLE), ["gpu", "gpu-probe", "gpu-probe-b"]);
        assert_eq!(
            order_of(net::NET_PROBE_TABLE),
            ["ramfs", "rng", "entropy", "net", "net-probe"]
        );
        let shell = order_of(net::NET_TABLE);
        assert!(shell.contains(&NET_SERVICE));
        assert_eq!(
            order_of(input::TABLE),
            ["input", "gpu", "input-probe", "input-probe-x"]
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

    /// The games image is the shell's dialog with the launcher's quota of
    /// 3 072 pages and a pool of four and a half such quotas, and the
    /// input and display services, which the launcher (and so the shell and
    /// Doom) reaches by a session with the display service.
    #[test]
    fn the_games_table_is_the_dialog_with_the_quota_of_doom() {
        assert!(check(doom::TABLE).is_ok());
        let games = order_of(doom::TABLE);
        let at = |name: &str| games.iter().position(|&n| n == name).unwrap();
        assert!(at("input") < at("gpu"));
        assert!(at("gpu") < at("busybox-probe"));
        let mut names = games.clone();
        names.retain(|&n| n != "input" && n != "gpu");
        let mut dialog = order_of(ramfs::BUSYBOX_DIALOG_TABLE);
        names.sort_unstable();
        dialog.sort_unstable();
        assert_eq!(names, dialog);
        let launcher = doom::TABLE
            .iter()
            .find(|r| r.program == "ash-launcher")
            .unwrap();
        let posix = doom::TABLE
            .iter()
            .find(|r| r.name == PROCESS_SERVICE)
            .unwrap();
        assert_eq!(launcher.quota, 3072 * PAGE);
        assert!(launcher.connects.contains(&"gpu"));
        // The display service is the only one that names the input service.
        let named: Vec<_> = doom::TABLE
            .iter()
            .filter(|r| r.connects.contains(&"input"))
            .map(|r| r.name)
            .collect();
        assert_eq!(named, ["gpu"]);
        assert_eq!(posix.quota, ramfs::POSIX_ABI_TABLE[1].quota + 13_824 * PAGE);
    }

    /// The base image is the games table with the network service: the
    /// launcher reaches the display and the network services under the
    /// larger quota of a command, the process service has the pool of the
    /// network image, and the services of both tables are in it once, with
    /// the disk and the package service, which the launcher waits for.
    #[test]
    fn the_base_table_is_the_games_table_with_the_network_service() {
        assert!(check(base::BASE_TABLE).is_ok());
        let mut names = order_of(base::BASE_TABLE);
        let at = |names: &[&str], name: &str| names.iter().position(|&n| n == name).unwrap();
        assert!(at(&names, "input") < at(&names, "gpu"));
        assert!(at(&names, NET_SERVICE) < names.len());
        assert!(at(&names, "blk") < at(&names, "pkgd"));
        assert!(at(&names, "ramfs") < at(&names, "pkgd"));
        names.retain(|&n| n != NET_SERVICE && n != "blk" && n != "pkgd");
        let mut games = order_of(doom::TABLE);
        names.sort_unstable();
        games.sort_unstable();
        assert_eq!(names, games);
        let launcher = base::BASE_TABLE
            .iter()
            .find(|r| r.program == "ash-launcher")
            .unwrap();
        assert!(launcher.connects.contains(&"gpu"));
        assert!(launcher.connects.contains(&NET_SERVICE));
        assert_eq!(launcher.quota, net::NET_COMMAND_QUOTA);
        // The launcher gets the package session, and waits 30 s for READY.
        assert!(launcher.connects.contains(&"pkgd"));
        assert_eq!(
            launcher.waits,
            &[Wait {
                service: "pkgd",
                deadline_ms: 30_000
            }]
        );
        assert_eq!(base::PKGD_READY_MS, 30_000);
        let posix = base::BASE_TABLE
            .iter()
            .find(|r| r.name == PROCESS_SERVICE)
            .unwrap();
        // The pool of the network image less the two quotas of a command that
        // the package service takes from init.
        assert_eq!(
            posix.quota + (16 - base::COMMAND_QUOTAS) * net::NET_COMMAND_QUOTA,
            net::NET_TABLE[2].quota
        );
        // The service of the network is the one of the network image, and the
        // disk and package services close the table: 14 of 16 records.
        assert_eq!(base::BASE_TABLE[11].name, net::NETD.name);
        assert_eq!(base::BASE_TABLE.last().unwrap().name, "pkgd");
        assert_eq!(base::BASE_TABLE.len(), 14);
    }

    /// Every POSIX process leaves one level above main for its thread
    /// owner, heap and file workers and sleep timer, and its table passes.
    #[test]
    fn posix_processes_have_a_ceiling_above_main() {
        let tables = [
            ramfs::BUSYBOX_TABLE,
            ramfs::BUSYBOX_DIALOG_TABLE,
            doom::TABLE,
            base::BASE_TABLE,
            ramfs::POSIX_DIALOG_TABLE,
            vz::POSIX_DIALOG_TABLE,
            ramfs::POSIX_ABI_TABLE,
            ramfs::POSIX_PROCS_TABLE,
            ramfs::RELIBC_TABLE,
            ramfs::RELIBC_THREADS_TABLE,
            ramfs::OS_TEST_TABLE,
            ramfs::POSIX_PTY_TABLE,
            vz::POSIX_ABI_TABLE,
            vz::POSIX_NATIVE_TABLE,
            vz::BUSYBOX_DIALOG_TABLE,
            ramfs::RTBENCH_POSIX_TABLE,
            vz::RTBENCH_POSIX_TABLE,
            ramfs::POSIX_RANDOM_TABLE,
            ramfs::POSIX_DISPLAY_TABLE,
            ramfs::DISPLAY_TABLE,
        ];
        for table in tables {
            assert!(check(table).is_ok());
            let posix = table.iter().filter(|r| {
                [
                    "busybox-probe",
                    "ash-launcher",
                    "posix-probe",
                    "posix-abi-probe",
                    "posix-procs",
                    "relibc-hello",
                    "relibc-threads",
                    "os-test-run",
                    "rtbench-posix",
                    "posix-random",
                    "posix-display",
                    "display-run",
                    "posix-pty",
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

    #[test]
    fn the_probe_of_shares_gives_the_service_a_small_share() {
        let table = ramfs::POSIX_SHARES_TABLE;
        assert!(check(table).is_ok());
        let service = &table[find(table, PROCESS_SERVICE.as_bytes()).unwrap()];
        assert_eq!(service.shares.threads, ramfs::SHARES_PROBE_THREADS);
        assert_eq!(service.shares.timers, POSIX_SHARES.timers);
        assert_eq!(table[4].args, b"posix-procs\0shares-main\0");
    }

    #[test]
    fn shares_add_up_to_what_init_can_give() {
        const MAX_T: u32 = SYSTEM_THREADS - INIT_KEEP_THREADS;
        const MAX_M: u32 = SYSTEM_TIMERS - INIT_KEEP_TIMERS;
        let shared = |name, threads, timers| Record {
            shares: Shares { threads, timers },
            ..service(name, 40, 40)
        };
        // The share of the process service and what is left of the limit.
        assert_eq!(POSIX_SHARES.threads, 768);
        assert!(check(&[shared("a", MAX_T, MAX_M)]).is_ok());
        assert!(
            check(&[
                shared("a", POSIX_SHARES.threads, POSIX_SHARES.timers),
                shared(
                    "b",
                    MAX_T - POSIX_SHARES.threads,
                    MAX_M - POSIX_SHARES.timers
                ),
            ])
            .is_ok()
        );
        let over = |threads, timers| {
            check(Box::leak(Box::new([
                shared("a", POSIX_SHARES.threads, POSIX_SHARES.timers),
                shared("b", threads, timers),
            ])))
        };
        let (rest_t, rest_m) = (MAX_T - POSIX_SHARES.threads, MAX_M - POSIX_SHARES.timers);
        assert!(matches!(
            over(rest_t + 1, 1),
            Err(TableError::Shares { threads, .. }) if threads == u64::from(MAX_T) + 1
        ));
        assert!(matches!(
            over(1, rest_m + 1),
            Err(TableError::Shares { .. })
        ));
        // Both kinds or neither.
        assert!(matches!(over(5, 0), Err(TableError::Shares { .. })));
        assert!(matches!(over(0, 5), Err(TableError::Shares { .. })));
        assert_eq!(
            TableError::Shares {
                threads: 897,
                timers: 3
            }
            .to_string(),
            "the shares add up to 897 thread numbers and 3 timer places: at most 896 and 7168, one of either with the other"
        );
    }

    #[test]
    fn cpu_masks_are_not_empty_and_posix_stays_within_its_service() {
        const POSIX: &[&str] = &[PROCESS_SERVICE];
        let process = Record {
            cpus: ALL_CPUS,
            ..service(PROCESS_SERVICE, 50, 50)
        };
        let at = |cpus| Record {
            cpus,
            ..client("app", 20, 20, POSIX)
        };
        assert!(check(&[process, at(GENERAL_CPUS)]).is_ok());
        assert!(check(&[process, at(ALL_CPUS)]).is_ok());
        assert_eq!(
            check(&[process, at(0)]),
            Err(TableError::Cpus { record: "app" })
        );
        // The process service on the CPUs of the services cannot give its
        // POSIX processes the CPUs of realtime.
        let narrow = Record {
            cpus: GENERAL_CPUS,
            ..process
        };
        assert_eq!(
            check(&[narrow, at(RT_CPUS)]),
            Err(TableError::Cpus { record: "app" })
        );
        assert_eq!(
            check(&[narrow, at(ALL_CPUS)]),
            Err(TableError::Cpus { record: "app" })
        );
        // A record that is no POSIX process may stand anywhere.
        assert!(
            check(&[
                process,
                Record {
                    cpus: RT_CPUS,
                    ..service("hard", 40, 40)
                }
            ])
            .is_ok()
        );
    }

    #[test]
    fn a_mask_is_cut_to_the_cpus_that_are_up() {
        assert_eq!(on_cpus(GENERAL_CPUS, 0b1111), (0b0011, true));
        assert_eq!(on_cpus(ALL_CPUS, 0b1111), (0b1111, true));
        assert_eq!(on_cpus(GENERAL_CPUS, 0b0001), (0b0001, true));
        // None of its CPUs is up: all that are, and the line says so.
        assert_eq!(on_cpus(RT_CPUS, 0b0011), (0b0011, false));
    }
}
