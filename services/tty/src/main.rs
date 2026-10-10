// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The terminal service (5f; spec 2, 2 and 3.8): the console as a
//! terminal over the console's driver, in one thread at 50, below the
//! driver at 60 and above the POSIX processes. Its line discipline, the
//! output's pump and the waiters are the library's (`tty`); here are the
//! loop, the calls to the driver and the long operations of the clients
//! (proto_tty).
//!
//! The service never waits for the driver: input comes as a read in two
//! steps whose notification sets a bit in the service's own place
//! DRIVER_IN, which has the highest priority of its places, so input and
//! INTR overtake the requests of the clients; output goes with WRITE_SOME,
//! and a part the driver had no room for waits for ROOM's notification
//! (DRIVER_ROOM). A read or write of a client that finds nothing to do is
//! a long operation in two steps (proto_wire::long, spec 2, 3.4): the
//! service keeps who waits and no byte of a write. Work left after a step
//! of bounded length (a chunk of input, a message of output) goes on in
//! the next, which the service tells itself through STEP.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use proto_init::ServiceArgs;
use proto_tty::{
    CONSOLE, Cancel, Control, Drain, FLOW_IN_OFF, FLOW_IN_ON, FLOW_OUT_OFF, FLOW_OUT_ON, FLUSH,
    INVALID, MAX_READ, Method, NO_IDENTITY, OWN, PERMISSION, QUEUE_BOTH, QUEUE_IN, QUEUE_OUT, Read,
    SetAttr, VERSION, VSTART, VSTOP, WAITERS, Write,
};
use proto_uart::{ReadKey, ReadRequest, RoomReply, WriteReply, WriteRequest};
use proto_wire::clones::{Clones, ROOTS};
use proto_wire::{Status, Writer, long, watch};
use rt::abi::{Error, MESSAGE_MAX, Rights, Source};
use rt::handle::{Channel, Handle, Memory, Outgoing, Process, Timer};
use rt::service::{
    Answer, Config, Heartbeat, LongOps, LongSession, Notice, Request, Service, Session,
};
use rt::{sys, time};
use tty::discipline::{self, Signal, Terminal};
use tty::endpoints::{Endpoint, Endpoints, Failure, Holds, Side, TERMINALS};
use tty::holdsets::{HoldSet, HoldSets};
use tty::jobs::{self, Caller, Departed, Departures, Jobs};
use tty::{Driver, Pump, Pumped, Waiter, Waiters};

rt::entry!(main);

/// The sessions: room for the 255 records of the process service and the
/// services beside them, as the pipe service has.
const SESSIONS: usize = 320;
/// The clones the service keeps alive at most.
const CLONES: usize = 320;
/// The sets of holds: one for each clone, and one for each root.
const HOLDSETS: usize = CLONES + ROOTS;
/// The live clones of one root at most: one for each record of the process
/// service, so that a tree of processes has a session each, and the other
/// roots keep CLONES - ROOT_CLONES of them.
const ROOT_CLONES: usize = 255;
/// The long operations that wait in the service at most.
const OPERATIONS: usize = 128;
/// The bytes of input one step takes from the driver at most.
const CHUNK: u32 = 64;
/// The messages of output one step gives the driver at most.
const WRITES: usize = 1;
/// The bytes of a client's write one step takes at most: a write of
/// more gets the count of those (the layer writes the rest).
const WRITE_STEP: usize = 256;
/// The service's own places: none of init's labels and none of its
/// clones' has bit 62 with bit 63.
const STEP: u64 = OWN | 1 << 62 | 1;
const DRIVER_IN: u64 = OWN | 1 << 62 | 2;
const DRIVER_ROOM: u64 = OWN | 1 << 62 | 3;
const DEPARTURES: u64 = OWN | 1 << 62 | 5;
const LOADERS: u64 = OWN | 1 << 62 | 6;
/// The label of the copy of the channel the timer of VTIME posts through.
const TIMER: u64 = 1;

/// The codes of a start that failed.
const NO_START_DATA: u64 = 1;
const NO_CHANNEL: u64 = 2;
const NOT_REGISTERED: u64 = 3;
const NO_DRIVER: u64 = 4;
const NO_PLACES: u64 = 5;
const STOPPED: u64 = 6;

/// What the service keeps for a client: its long operations, and the
/// root of its chain of clones: the label of init's client whose process
/// forked or spawned it, or its own label for such a client (0 until its
/// first request). The clones count by the root, as in the pipe service,
/// so that one process tree cannot take the service from the others.
#[derive(Default)]
struct Client {
    long: LongSession,
    root: u64,
    /// Who the process of the session is, as the process service vouched
    /// for it (5f, T3).
    who: Option<Who>,
    holding: usize,
}

/// What the process service said of a session's process: the index of
/// its record, its PID, and the generation of its credentials then, which
/// moves when the record goes or execs.
#[derive(Clone, Copy)]
struct Who {
    index: usize,
    pid: u32,
    generation: u64,
    loader: bool,
    uid: u32,
    euid: u32,
    egid: u32,
    ctty: Option<(u32, u64)>,
}

/// Where the service maps the page of the generations (proto_process
/// Register), read-only.
const GENERATIONS_AT: usize = 0x41_0000_0000;

/// The tables of the sessions and long operations and the console's
/// discipline, in `.bss`: too big for the stack.
#[derive(Clone, Copy)]
struct Pin {
    label: u64,
    key: u64,
    description: u32,
    kind: u8,
    drain: tty::drain::Prefix,
}

struct Tables {
    sessions: [Option<Session<Client, 0>>; SESSIONS],
    ops: LongOps<OPERATIONS>,
    watches: watch::Pool<OPERATIONS>,
    clones: Clones<CLONES>,
    devices: [Device; TERMINALS],
    endpoints: Endpoints,
    holdsets: HoldSets<CLONES, HOLDSETS>,
    pins: [Option<Pin>; OPERATIONS],
}

struct Device {
    console: Terminal,
    winsize: proto_tty::Winsize,
    readers: Waiters<WAITERS>,
    writers: Waiters<WAITERS>,
    drainers: Waiters<WAITERS>,
    master_readers: Waiters<WAITERS>,
    master_writers: Waiters<WAITERS>,
    watchers: Waiters<WAITERS>,
    jobs: Jobs,
    job_generation: u64,
    disconnect_pending: bool,
    disconnect_wake: bool,
    departed: Departures,
}
impl Device {
    const fn new() -> Self {
        Self {
            console: Terminal::new(),
            winsize: proto_tty::Winsize::new(),
            readers: Waiters::new(),
            writers: Waiters::new(),
            drainers: Waiters::new(),
            master_readers: Waiters::new(),
            master_writers: Waiters::new(),
            watchers: Waiters::new(),
            jobs: Jobs::new(),
            job_generation: 0,
            disconnect_pending: false,
            disconnect_wake: false,
            departed: Departures::new(),
        }
    }
}
struct Bss(UnsafeCell<Tables>);
// SAFETY: only the main thread reaches it, once (`main`).
unsafe impl Sync for Bss {}
static TABLES: Bss = Bss(UnsafeCell::new(Tables {
    sessions: [const { None }; SESSIONS],
    ops: LongOps::new(),
    watches: watch::Pool::new(),
    clones: Clones::new(),
    devices: [const { Device::new() }; TERMINALS],
    endpoints: Endpoints::new(),
    holdsets: HoldSets::new(),
    pins: [None; OPERATIONS],
}));

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = start.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    let args = ServiceArgs::read(start.args()).ok();
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return NO_CHANNEL;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return NOT_REGISTERED;
    }
    let Ok(driver) = rt::service::connect(&start.parent, "uart") else {
        return NO_DRIVER;
    };
    #[cfg(feature = "steps")]
    let connect_began = time::now();
    // Startup may wait for the process service to register. It finishes
    // before client work; registration and mapping are separate own steps.
    let notary = rt::service::connect(&start.parent, "posix").ok();
    #[cfg(feature = "steps")]
    rt::println!(
        "tty preparation: Connect {} ticks (including startup wait)",
        time::now().saturating_sub(connect_began)
    );
    let place = |label| sys::handle_label(&channel, Rights::NOTIFY, label, level);
    let (Ok(step), Ok(view)) = (
        place(STEP),
        sys::handle_label(&channel, Rights::RECEIVE, TIMER, level),
    ) else {
        return NO_PLACES;
    };
    let Ok(timer) = sys::timer_create(&view, level) else {
        return NO_PLACES;
    };
    // SAFETY: only the main thread reaches TABLES, here once.
    let tables = unsafe { &mut *TABLES.0.get() };
    let mut service = Tty {
        channel: Handle::borrowed(channel.raw()),
        parent: Handle::borrowed(start.parent.raw()),
        level,
        clones: &mut tables.clones,
        ops: &mut tables.ops,
        watches: &mut tables.watches,
        driver,
        room_given: false,
        draining: None,
        devices: &mut tables.devices,
        active: 0,
        endpoints: &mut tables.endpoints,
        holdsets: &mut tables.holdsets,
        pins: &mut tables.pins,
        retired: tty::retired::Retired::new(),
        pin_cleanup_due: false,
        watch_cleanup_due: false,
        disconnect_work_due: false,
        pump: Pump::new(),
        input: Input::Idle,
        timer,
        _view: view,
        armed: None,
        step,
        step_told: false,
        step_due: false,
        process: Handle::borrowed(start.process.raw()),
        preparation: if notary.is_some() { 1 } else { 3 },
        notary,
        generations: None,
        departure_left: 0,
        departure_cursor: 0,
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &start.parent,
            period_ns: args.map_or(0, |args| args.period_ns),
            priority: level,
        }),
    };
    for phase in [1, 2] {
        if service.preparation == phase {
            #[cfg(feature = "steps")]
            let began = time::now();
            service.prepare();
            #[cfg(feature = "steps")]
            rt::println!(
                "tty preparation: phase {phase} {} ticks (including dependency wait)",
                time::now().saturating_sub(began)
            );
        }
    }
    let _ = service.pull();
    rt::println!("tty: ready");
    #[cfg(feature = "steps")]
    rt::service::report_steps(5);
    #[cfg(feature = "quiet-steps")]
    rt::service::quiet_steps();
    let _ = rt::service::run_in(&channel, &mut service, config, &mut tables.sessions);
    STOPPED
}

/// What a long operation that waits is.
#[derive(Clone, Copy)]
enum Wait {
    /// A read, with the deadline of its VTIME.
    Read(Option<u64>),
    Write,
    Drain(u64),
    MasterRead,
    MasterWrite,
}
impl Wait {
    fn number(self) -> u8 {
        match self {
            Self::Read(_) => 1,
            Self::Write => 2,
            Self::Drain(_) => 3,
            Self::MasterRead => 4,
            Self::MasterWrite => 5,
        }
    }
}

/// Where the read of input from the driver stands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Input {
    /// No read: the next step starts one.
    Idle,
    /// The driver's read `key` waits; `armed` once the driver keeps the
    /// handle that tells the service of input.
    Waiting { key: u64, armed: bool },
}

struct Tty {
    /// The service's channel, which its own sessions are copies of.
    channel: ManuallyDrop<Handle<Channel>>,
    /// The connection to init, for a session with a driver that started
    /// again.
    parent: ManuallyDrop<Handle<Channel>>,
    level: u8,
    clones: &'static mut Clones<CLONES>,
    ops: &'static mut LongOps<OPERATIONS>,
    watches: &'static mut watch::Pool<OPERATIONS>,
    /// The session with the console's driver, and whether it keeps the
    /// handle of ROOM.
    driver: Handle<Channel>,
    room_given: bool,
    draining: Option<u64>,
    devices: &'static mut [Device; TERMINALS],
    active: usize,
    endpoints: &'static mut Endpoints,
    holdsets: &'static mut HoldSets<CLONES, HOLDSETS>,
    pins: &'static mut [Option<Pin>; OPERATIONS],
    retired: tty::retired::Retired<HOLDSETS>,
    pin_cleanup_due: bool,
    watch_cleanup_due: bool,
    disconnect_work_due: bool,
    pump: Pump,
    input: Input,
    /// The timer of VTIME and the deadline it is armed for.
    timer: Handle<Timer>,
    _view: Handle<Channel>,
    armed: Option<u64>,
    /// The copy of the service's channel with NOTIFY, label STEP; whether
    /// a step was told and not taken; a step due that no notification
    /// told.
    step: Handle<Channel>,
    step_told: bool,
    step_due: bool,
    /// The service's process, where it maps the page of the generations.
    process: ManuallyDrop<Handle<Process>>,
    /// The notary session with the process service (TERMINAL) and the
    /// page of the generations, asked for at the first request of the
    /// controlling terminal.
    notary: Option<Handle<Channel>>,
    generations: Option<Handle<Memory>>,
    preparation: u8,
    departure_left: usize,
    departure_cursor: usize,
}

/// The time on the scale of timer_set.
fn now() -> u64 {
    time::ticks_to_ns(time::now())
}

fn status(code: u32) -> Answer {
    Answer::Status(Status::from_code(code))
}

fn long_answer(r: &mut Request<'_>, reply: long::Reply<'_>) -> Answer {
    match reply.write(r.reply()) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}

/// A request to the driver and its reply into `buffer`; a send the
/// kernel took back goes again.
fn call<'a>(
    driver: &Handle<Channel>,
    request: &[u8],
    handle: Option<Handle<Channel>>,
    buffer: &'a mut [u8; MESSAGE_MAX],
) -> Result<&'a [u8], Error> {
    let reply = match handle {
        None => loop {
            match sys::send(driver, request) {
                Err(Error::Interrupted) => continue,
                other => break other?,
            }
        },
        Some(handle) => {
            sys::send_handles(driver, request, [handle.erase()]).map_err(|refused| refused.error)?
        }
    };
    Ok(reply.bytes(buffer))
}

/// The driver as the pump sees it.
struct Port<'a> {
    driver: &'a Handle<Channel>,
    channel: &'a Handle<Channel>,
    level: u8,
    room_given: &'a mut bool,
}

impl Driver for Port<'_> {
    type Error = Error;

    fn write_some(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let mut w = Writer::new();
        WriteRequest { bytes }
            .write_some(&mut w)
            .map_err(|_| Error::InvalidArgs)?;
        let mut buffer = [0; MESSAGE_MAX];
        let reply = call(self.driver, w.as_bytes(), None, &mut buffer)?;
        let written = WriteReply::read(reply).map_err(|_| Error::BadState)?;
        Ok(written.written as usize)
    }

    fn room(&mut self) -> Result<bool, Error> {
        let handle = if *self.room_given {
            None
        } else {
            Some(sys::handle_label(
                self.channel,
                Rights::NOTIFY | Rights::TRANSFER,
                DRIVER_ROOM,
                self.level,
            )?)
        };
        let given = handle.is_some();
        let mut buffer = [0; MESSAGE_MAX];
        let request = proto_uart::Method::Room.header().bytes();
        let reply = call(self.driver, &request, handle, &mut buffer)?;
        let room = RoomReply::read(reply).map_err(|_| Error::BadState)?;
        *self.room_given |= given;
        Ok(!room.armed)
    }
}

impl Tty {
    fn select(&mut self, terminal: usize) {
        assert!(terminal < TERMINALS);
        self.active = terminal;
    }

    fn endpoint_error(error: Failure) -> u32 {
        match error {
            Failure::BadDescription => proto_tty::BAD_DESCRIPTION,
            Failure::Invalid => INVALID,
            Failure::Limit | Failure::Overflow => Status::Kernel(Error::LimitReached).code(),
            Failure::Locked => PERMISSION,
        }
    }

    fn select_description(&mut self, s: &Session<Client, 0>, id: u32) -> Result<Endpoint, u32> {
        let endpoint = if id == CONSOLE {
            Endpoint {
                terminal: 0,
                generation: 1,
                side: Side::Slave,
                flags: 2,
            }
        } else {
            self.endpoints
                .resolve(&self.holdsets[s.data.holding].holds, id)
                .map_err(Self::endpoint_error)?
        };
        self.select(endpoint.terminal);
        Ok(endpoint)
    }

    fn operation(
        &mut self,
        s: &Session<Client, 0>,
        id: u32,
        key: Option<u64>,
        kind: u8,
    ) -> Result<Endpoint, u32> {
        let endpoint = match key {
            None => self.select_description(s, id)?,
            Some(key) => {
                let pin = self
                    .pins
                    .get((key as u32).wrapping_sub(1) as usize)
                    .and_then(|pin| *pin)
                    .filter(|pin| {
                        pin.label == s.label()
                            && pin.key == key
                            && pin.description == id
                            && pin.kind == kind
                    })
                    .filter(|_| self.ops.waits(s.label(), key))
                    .ok_or(Status::Kernel(Error::BadState).code())?;
                let endpoint = if pin.description == CONSOLE {
                    Endpoint {
                        terminal: 0,
                        generation: 1,
                        side: Side::Slave,
                        flags: 2,
                    }
                } else {
                    self.endpoints.pinned(id).map_err(Self::endpoint_error)?
                };
                self.select(endpoint.terminal);
                endpoint
            }
        };
        if (kind >= 4) != (endpoint.side == Side::Master) {
            return Err(INVALID);
        }
        if matches!(kind, 1 | 4) && endpoint.flags & 3 == 1
            || matches!(kind, 2 | 5) && endpoint.flags & 3 == 0
        {
            return Err(proto_tty::BAD_DESCRIPTION);
        }
        Ok(endpoint)
    }

    fn disconnect(&mut self, terminal: usize) {
        self.select(terminal);
        self.devices[terminal].console.flush_input();
        self.devices[terminal].console.flush_output();
        self.devices[terminal].disconnect_pending = self.devices[terminal].job_generation != 0;
        self.devices[terminal].disconnect_wake = !self.devices[terminal].disconnect_pending;
        self.disconnect_work_due = true;
        self.kick();
    }

    fn disconnect_link(&mut self) {
        let Some(notary) = self.notary.as_ref() else {
            self.kick();
            return;
        };
        let device = &self.devices[self.active];
        let Some(sid) = device.jobs.session() else {
            self.devices[self.active].disconnect_pending = false;
            self.devices[self.active].disconnect_wake = true;
            return;
        };
        let generation = device.job_generation;
        let hup = device.console.termios().cflag & proto_tty::CLOCAL == 0;
        let mut w = Writer::new();
        let _ = proto_process::Method::DisconnectCtty.header().write(&mut w);
        let _ = w.u32(self.active as u32);
        let _ = w.u32(sid);
        let _ = w.u64(generation);
        let _ = w.u32(u32::from(hup));
        let mut buffer = [0; MESSAGE_MAX];
        if let Ok(reply) = sys::send(notary, w.as_bytes())
            && proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() == Ok(0)
        {
            // Process publishes HUP before this accepted reply. EOF and
            // readiness notifications are published in the next step.
            self.devices[self.active].disconnect_pending = false;
            self.devices[self.active].disconnect_wake = true;
        } else {
            self.kick();
        }
    }

    fn clear_pin(&mut self, index: usize) {
        if let Some(pin) = self.pins[index].take() {
            let terminal = if pin.description == CONSOLE {
                Some(0)
            } else {
                self.endpoints
                    .pinned(pin.description)
                    .ok()
                    .map(|e| e.terminal)
            };
            if let Some(terminal) = terminal {
                let device = &mut self.devices[terminal];
                device.readers.remove(pin.label, pin.key);
                device.writers.remove(pin.label, pin.key);
                device.drainers.remove(pin.label, pin.key);
                device.master_readers.remove(pin.label, pin.key);
                device.master_writers.remove(pin.label, pin.key);
            }
            if pin.description != CONSOLE {
                let _ = self.endpoints.unpin(pin.description);
            }
        }
    }

    fn disconnected(&self) -> bool {
        self.endpoints
            .instance(self.active)
            .is_some_and(|i| i.disconnected)
    }

    fn open(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let request = match proto_tty::Open::parse(r.body()) {
            Ok(request) => request,
            Err(code) => return Answer::Status(code),
        };
        if request.flags & !(3 | tty::endpoints::NONBLOCK) != 0 || request.flags & 3 == 3 {
            return status(INVALID);
        }
        let (caller, who) = match self.caller_identity(s, r) {
            Ok(identity) => identity,
            Err(code) => return status(code),
        };
        let flags = request.flags & (3 | 0o4000);
        let result = match request.kind {
            proto_tty::OPEN_CONSOLE => self
                .endpoints
                .open_console(&mut self.holdsets[s.data.holding].holds, flags),
            proto_tty::OPEN_MASTER => {
                let result = self
                    .endpoints
                    .open_master(&mut self.holdsets[s.data.holding].holds, flags);
                if let Ok(id) = result {
                    let e = self
                        .endpoints
                        .resolve(&self.holdsets[s.data.holding].holds, id)
                        .expect("fresh description");
                    self.devices[e.terminal] = Device::new();
                }
                result
            }
            proto_tty::OPEN_SLAVE => {
                if who.euid != 0
                    && let Some(instance) = self.endpoints.instance(request.number as usize + 1)
                {
                    let permissions = if who.euid == instance.uid {
                        (instance.mode >> 6) & 7
                    } else if who.egid == 0 {
                        (instance.mode >> 3) & 7
                    } else {
                        instance.mode & 7
                    };
                    let required = match flags & 3 {
                        0 => 4,
                        1 => 2,
                        _ => 6,
                    };
                    if permissions & required != required {
                        return status(PERMISSION);
                    }
                }
                self.endpoints.open_slave(
                    &mut self.holdsets[s.data.holding].holds,
                    request.number as usize,
                    flags,
                )
            }
            proto_tty::OPEN_CONTROLLING => {
                let Some((terminal, generation)) = caller.ctty else {
                    return status(proto_tty::NOT_CONTROLLING);
                };
                let Some(device) = self.devices.get(terminal as usize) else {
                    return status(proto_tty::NOT_CONTROLLING);
                };
                if device.job_generation != generation || device.jobs.session() != Some(caller.sid)
                {
                    return status(proto_tty::NOT_CONTROLLING);
                }
                if terminal == 0 {
                    self.endpoints
                        .open_console(&mut self.holdsets[s.data.holding].holds, flags)
                } else {
                    self.endpoints.open_slave(
                        &mut self.holdsets[s.data.holding].holds,
                        terminal as usize - 1,
                        flags,
                    )
                }
            }
            _ => return status(INVALID),
        };
        match result {
            Ok(id) => {
                let w = r.reply();
                let _ = w.u32(0);
                let _ = w.u32(id);
                Answer::Reply(Outgoing::new())
            }
            Err(error) => status(Self::endpoint_error(error)),
        }
    }

    fn description(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
        method: Method,
    ) -> Answer {
        let mut body = r.body();
        let Ok(id) = body.u32() else {
            return Answer::Status(Status::BadSize);
        };
        if method == Method::Stat && id == proto_tty::STAT_PATH && body.left() == 4 {
            let (Ok(terminal), Ok(())) = (body.u32(), body.finish()) else {
                return Answer::Status(Status::BadSize);
            };
            let info = if terminal == proto_tty::STAT_PATH {
                proto_tty::Stat {
                    mode: 0o20666,
                    uid: 0,
                    gid: 0,
                    terminal: 0,
                    side: 1,
                }
            } else {
                let Some(instance) = self.endpoints.instance(terminal as usize) else {
                    return status(proto_tty::NO_ENTRY);
                };
                proto_tty::Stat {
                    mode: 0o20000 | instance.mode,
                    uid: instance.uid,
                    gid: 0,
                    terminal,
                    side: 0,
                }
            };
            let w = r.reply();
            let _ = w.u32(0);
            let _ = info.write(w);
            return Answer::Reply(Outgoing::new());
        }
        let word = if matches!(method, Method::Lock | Method::SetFlags) {
            match body.u32() {
                Ok(word) => word,
                Err(code) => return Answer::Status(code),
            }
        } else {
            0
        };
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let endpoint = match self.select_description(s, id) {
            Ok(e) => e,
            Err(code) => return status(code),
        };
        let mut value = None;
        let result = match method {
            Method::Close => self
                .endpoints
                .close(&mut self.holdsets[s.data.holding].holds, id)
                .map(|effect| {
                    if let Some(effect) = effect {
                        self.disconnect(effect.terminal);
                    }
                }),
            Method::Lock if word <= 1 => {
                self.endpoints
                    .lock(&self.holdsets[s.data.holding].holds, id, word != 0)
            }
            Method::Lock => Err(Failure::Invalid),
            Method::Number => self
                .endpoints
                .number(&self.holdsets[s.data.holding].holds, id)
                .map(|number| value = Some(number)),
            Method::Grant => {
                let (_, who) = match self.caller_identity(s, r) {
                    Ok(identity) => identity,
                    Err(code) => return status(code),
                };
                self.endpoints
                    .grant(&self.holdsets[s.data.holding].holds, id, who.uid)
            }
            Method::GetFlags => {
                value = Some(endpoint.flags);
                Ok(())
            }
            Method::SetFlags => {
                self.endpoints
                    .set_flags(&self.holdsets[s.data.holding].holds, id, word)
            }
            Method::Stat => {
                let i = self
                    .endpoints
                    .instance(endpoint.terminal)
                    .expect("live description");
                let info = proto_tty::Stat {
                    mode: 0o20000 | i.mode,
                    uid: i.uid,
                    gid: 0,
                    terminal: endpoint.terminal as u32,
                    side: u32::from(endpoint.side == Side::Master),
                };
                let w = r.reply();
                let _ = w.u32(0);
                let _ = info.write(w);
                return Answer::Reply(Outgoing::new());
            }
            _ => Err(Failure::Invalid),
        };
        match result {
            Ok(()) => {
                let w = r.reply();
                let _ = w.u32(0);
                if let Some(value) = value {
                    let _ = w.u32(value);
                }
                Answer::Reply(Outgoing::new())
            }
            Err(error) => status(Self::endpoint_error(error)),
        }
    }

    fn tell_place(&self, label: u64) {
        if let Ok(place) = sys::handle_label(&self.channel, Rights::NOTIFY, label, self.level) {
            let _ = sys::notify(&place, 1);
        }
    }

    /// Registration and mapping finish during measured startup preparation.
    fn prepare(&mut self) {
        match self.preparation {
            0 => self.notary = rt::service::connect(&self.parent, "posix").ok(),
            1 => {
                let Some(notary) = self.notary.as_ref() else {
                    return;
                };
                let Ok(notice) = sys::handle_label(
                    &self.channel,
                    Rights::NOTIFY | Rights::TRANSFER,
                    DEPARTURES,
                    self.level,
                ) else {
                    return;
                };
                let request = proto_process::Method::Register.header().bytes();
                let Ok(loaders) = sys::handle_label(
                    &self.channel,
                    Rights::SEND | Rights::DUPLICATE | Rights::TRANSFER,
                    LOADERS,
                    self.level,
                ) else {
                    return;
                };
                let Ok(mut reply) =
                    sys::send_handles(notary, &request, [notice.erase(), loaders.erase()])
                else {
                    return;
                };
                let mut buffer = [0; MESSAGE_MAX];
                if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
                    return;
                }
                self.generations = reply.handles.take::<Memory>(0).ok();
            }
            2 => {
                let Some(memory) = self.generations.as_ref() else {
                    return;
                };
                if sys::mem_map(
                    &self.process,
                    memory,
                    0,
                    4096,
                    GENERATIONS_AT,
                    rt::abi::Access::Read,
                )
                .is_err()
                {
                    return;
                }
            }
            _ => return,
        }
        self.preparation += 1;
    }

    /// One old connection per step; its foreground remains available
    /// until acknowledgement even when a new generation has acquired.
    fn departure(&mut self) {
        let Some(notary) = self.notary.as_ref() else {
            return;
        };
        let mut w = Writer::new();
        let _ = proto_process::Method::TtyEvents.header().write(&mut w);
        let _ = w.u32(self.active as u32);
        let Ok(reply) = sys::send(notary, w.as_bytes()) else {
            return;
        };
        let mut buffer = [0; MESSAGE_MAX];
        let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
        if r.u32() != Ok(0) {
            return;
        }
        let (Ok(sid), Ok(generation), Ok(disconnect)) = (r.u32(), r.u64(), r.u32()) else {
            return;
        };
        if generation == 0 {
            return;
        }
        if self.devices[self.active].job_generation == generation {
            let old = Departed {
                generation,
                sid,
                foreground: if disconnect != 0 {
                    None
                } else {
                    self.devices[self.active].jobs.foreground()
                },
            };
            if !self.devices[self.active].departed.keep(old) {
                return;
            }
            self.devices[self.active].jobs.release();
            self.devices[self.active].job_generation = 0;
        }
        self.finish_departure(generation);
    }

    /// Complete the exact old connection even if an earlier departure remains.
    fn finish_departure(&mut self, generation: u64) {
        let Some(notary) = self.notary.as_ref() else {
            return;
        };
        let mut buffer = [0; MESSAGE_MAX];
        let old = self.devices[self.active].departed.find(generation);
        if let Some(old) = old
            && let Some(group) = old.foreground
        {
            for signal in [proto_process::SIGHUP, proto_process::SIGCONT] {
                let mut w = Writer::new();
                let _ = proto_process::Method::TtySignal.header().write(&mut w);
                let _ = w.u32(self.active as u32);
                let _ = w.u32(group);
                let _ = w.u32(signal as u32);
                let _ = w.u64(generation);
                let Ok(reply) = sys::send(notary, w.as_bytes()) else {
                    return;
                };
                let code = proto_wire::Reader::new(reply.bytes(&mut buffer)).u32();
                if !matches!(code, Ok(0 | proto_process::NO_PROCESS)) {
                    return;
                }
            }
        }
        let mut w = Writer::new();
        let _ = proto_process::Method::AckCtty.header().write(&mut w);
        let _ = w.u32(self.active as u32);
        let _ = w.u64(generation);
        if let Ok(reply) = sys::send(notary, w.as_bytes())
            && proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() == Ok(0)
        {
            self.devices[self.active].departed.forget(generation);
            if self.devices[self.active].job_generation == 0
                && let Some(i) = self.endpoints.instance(self.active)
            {
                let _ = self.endpoints.set_link(self.active, i.generation, false);
            }
        }
        self.departure_left = TERMINALS;
        self.tell_place(DEPARTURES);
    }

    /// Tells the loop of a step, unless one is told already; a refused
    /// notification leaves the step due for the next request or
    /// notification (`due`).
    fn kick(&mut self) {
        if self.step_told {
            return;
        }
        if sys::notify(&self.step, 1).is_ok() {
            self.step_told = true;
            self.step_due = false;
        } else {
            self.step_due = true;
        }
    }

    fn due(&mut self) {
        if self.step_due && !self.step_told {
            // The work goes into a step of its own, which the measure sees.
            self.kick();
        }
    }

    /// The work of a step: a chunk of input unless the driver's read
    /// waits armed, or else a piece of output; a step that took input
    /// leaves the output to the next.
    fn work(&mut self) {
        if self.disconnect_work_due {
            if let Some(terminal) = self.devices.iter().position(|d| d.disconnect_pending) {
                self.select(terminal);
                self.disconnect_link();
                self.kick();
                return;
            }
            if let Some(terminal) = self.devices.iter().position(|d| d.disconnect_wake) {
                self.select(terminal);
                self.devices[terminal].disconnect_wake = false;
                self.tell_readers();
                self.tell_output();
                self.tell_master_readers();
                self.tell_master_writers();
                self.kick();
                return;
            }
            self.disconnect_work_due = false;
        }
        if let Some(slot) = self.retired.first() {
            if let Some(id) = self.holdsets[slot].holds.first() {
                if let Ok(Some(effect)) = self.endpoints.close(&mut self.holdsets[slot].holds, id) {
                    self.disconnect(effect.terminal);
                }
            } else {
                self.holdsets.release(slot);
                self.retired.pop();
            }
            self.kick();
            return;
        }
        if self.pin_cleanup_due {
            if let Some(index) = self
                .pins
                .iter()
                .position(|p| p.is_some_and(|p| !self.ops.waits(p.label, p.key)))
            {
                self.clear_pin(index);
                self.kick();
                return;
            }
            self.pin_cleanup_due = false;
            self.kick();
            return;
        }
        if self.watch_cleanup_due {
            if let Some((label, key, id)) = self.watches.cleanup() {
                let terminal = if id == CONSOLE {
                    Some(0)
                } else {
                    self.endpoints.pinned(id).ok().map(|e| e.terminal)
                };
                if let Some(terminal) = terminal {
                    self.devices[terminal].watchers.remove(label, key);
                }
                if id != CONSOLE {
                    let _ = self.endpoints.unpin(id);
                }
                self.kick();
                return;
            }
            self.watch_cleanup_due = false;
            self.kick();
            return;
        }
        self.select(0);
        if !matches!(self.input, Input::Waiting { armed: true, .. }) && self.pull() {
            return;
        }
        self.push();
    }

    /// A new session with the driver, once the old one broke (the driver
    /// started again): its read and ROOM's handle went with it.
    fn reconnect(&mut self) {
        if let Ok(driver) = rt::service::connect(&self.parent, "uart") {
            self.driver = driver;
        }
        self.room_given = false;
        self.draining = None;
        for waiter in self.devices[0].drainers.iter() {
            if let Some(pin) = self.pins[(waiter.key as u32 - 1) as usize].as_mut() {
                if !pin.drain.ready {
                    pin.drain.failed = true;
                }
                self.ops.tell(waiter.label, waiter.key);
            }
        }
        self.pump.room_came();
        self.input = Input::Idle;
    }

    /// Output to the driver: WRITES messages at most, then the writers
    /// hear of room; the next step goes on with what is left.
    /// Update sticky terminal prefixes immediately after send or existing flush.
    fn mark_drains(&mut self) {
        let sent = self.devices[self.active].console.sent_total();
        for waiter in self.devices[self.active].drainers.iter() {
            if let Some(pin) = self.pins[(waiter.key as u32 - 1) as usize].as_mut() {
                pin.drain.advance(sent, waiter.started);
                if self.active != 0 {
                    pin.drain.complete();
                }
                if pin.drain.ready || pin.drain.failed {
                    self.ops.tell(waiter.label, waiter.key);
                }
            }
        }
    }

    fn driver_drain(&self, method: proto_uart::Method, key: Option<u64>) -> Result<bool, Error> {
        let mut request = Writer::new();
        match key {
            Some(key) => proto_uart::DrainKey { key }.write(method, &mut request),
            None => method.header().write(&mut request),
        }
        .map_err(|_| Error::InvalidArgs)?;
        let mut buffer = [0; MESSAGE_MAX];
        let reply = call(&self.driver, request.as_bytes(), None, &mut buffer)?;
        proto_uart::DrainReply::read(reply)
            .map(|reply| reply.ready)
            .map_err(|_| Error::BadState)
    }

    /// One driver observation RPC per output step. Future bytes remain in TTY
    /// until the captured UART prefix physically completes.
    fn observe_drain(&mut self) -> bool {
        if self.active != 0 {
            return false;
        }
        let reached = self.devices[0]
            .drainers
            .iter()
            .find(|waiter| {
                self.pins[(waiter.key as u32 - 1) as usize]
                    .is_some_and(|pin| pin.drain.reached && !pin.drain.ready && !pin.drain.failed)
            })
            .map(|waiter| waiter.key);
        let key = self.draining.or(reached);
        let Some(key) = key else { return false };
        if !self.room_given {
            let mut port = Port {
                driver: &self.driver,
                channel: &self.channel,
                level: self.level,
                room_given: &mut self.room_given,
            };
            if port.room().is_err() {
                self.reconnect();
            }
            self.kick();
            return true;
        }
        // Bind all already reached TTY prefixes to this immutable observer key.
        for waiter in self.devices[0].drainers.iter_mut() {
            if self.pins[(waiter.key as u32 - 1) as usize]
                .is_some_and(|pin| pin.drain.reached && !pin.drain.ready && !pin.drain.failed)
            {
                waiter.deadline = Some(key);
            }
        }
        let has_waiters = self.devices[0]
            .drainers
            .iter()
            .any(|waiter| waiter.deadline == Some(key));
        let method = if !has_waiters {
            proto_uart::Method::DrainRelease
        } else if self.draining.is_some() {
            proto_uart::Method::DrainTake
        } else {
            proto_uart::Method::DrainStart
        };
        match self.driver_drain(method, Some(key)) {
            Ok(ready) => {
                self.draining = has_waiters.then_some(key);
                if ready {
                    for waiter in self.devices[0].drainers.iter() {
                        if waiter.deadline == Some(key)
                            && let Some(pin) = self.pins[(waiter.key as u32 - 1) as usize].as_mut()
                        {
                            pin.drain.complete();
                            self.ops.tell(waiter.label, waiter.key);
                        }
                    }
                    self.draining = None;
                }
                if ready || !has_waiters {
                    self.kick();
                }
            }
            Err(_) => {
                self.reconnect();
                self.kick();
            }
        }
        true
    }

    fn push(&mut self) {
        self.mark_drains();
        if self.observe_drain() {
            return;
        }
        let target = self.devices[self.active]
            .drainers
            .iter()
            .filter(|waiter| {
                self.pins[(waiter.key as u32 - 1) as usize]
                    .is_some_and(|pin| !pin.drain.reached && !pin.drain.failed)
            })
            .map(|waiter| waiter.started)
            .min_by_key(|target| {
                target.wrapping_sub(self.devices[self.active].console.sent_total())
            });
        let mut port = Port {
            driver: &self.driver,
            channel: &self.channel,
            level: self.level,
            room_given: &mut self.room_given,
        };
        match self.pump.run_prefix(
            &mut self.devices[self.active].console,
            &mut port,
            WRITES,
            target,
        ) {
            Ok(Pumped::More) => self.kick(),
            Ok(Pumped::Idle | Pumped::WaitsRoom) => {}
            Err(_) => {
                self.reconnect();
                self.kick();
            }
        }
        self.tell_output();
        if target == Some(self.devices[self.active].console.sent_total()) {
            self.kick();
        }
    }

    /// The writes that wait hear of room, and the drains of an output that
    /// went.
    fn tell_output(&mut self) {
        self.tell_watches();
        if self.disconnected() || !self.devices[self.active].console.output().is_empty() {
            for waiter in self.devices[self.active].master_readers.iter() {
                self.ops.tell(waiter.label, waiter.key);
            }
        }
        if self.disconnected() || self.devices[self.active].console.writable() {
            for w in self.devices[self.active].writers.iter() {
                self.ops.tell(w.label, w.key);
            }
        }
        self.mark_drains();
    }

    /// Input from the driver: a read in two steps, a chunk of CHUNK bytes
    /// at most. Bytes that came go through the discipline, and the next
    /// read starts in the next step; with none, the read waits armed.
    fn pull(&mut self) -> bool {
        let mut bytes = [0; CHUNK as usize];
        let mut buffer = [0; MESSAGE_MAX];
        let mut w = Writer::new();
        let (request, handle) = match self.input {
            Input::Idle => {
                if (ReadRequest { max: CHUNK }).write_start(&mut w).is_err() {
                    return false;
                }
                (w.as_bytes(), None)
            }
            Input::Waiting { key, armed } => {
                if (ReadKey { key })
                    .write(proto_uart::Method::ReadTake, &mut w)
                    .is_err()
                {
                    return false;
                }
                let handle = if armed {
                    None
                } else {
                    sys::handle_label(
                        &self.channel,
                        Rights::NOTIFY | Rights::TRANSFER,
                        DRIVER_IN,
                        self.level,
                    )
                    .ok()
                };
                (w.as_bytes(), handle)
            }
        };
        let given = handle.is_some();
        let reply = match call(&self.driver, request, handle, &mut buffer) {
            Ok(reply) => reply,
            Err(_) => {
                self.reconnect();
                self.kick();
                return false;
            }
        };
        let n = match long::Reply::read(reply) {
            Ok(long::Reply::Ready(got)) => {
                let n = got.len().min(bytes.len());
                bytes[..n].copy_from_slice(&got[..n]);
                self.input = Input::Idle;
                n
            }
            Ok(long::Reply::Wait(key)) => {
                self.input = Input::Waiting { key, armed: false };
                // The take that arms comes in the next step.
                self.kick();
                return false;
            }
            Ok(long::Reply::Armed) => {
                if let Input::Waiting { key, armed } = self.input {
                    self.input = Input::Waiting {
                        key,
                        armed: armed || given,
                    };
                    if !(armed || given) {
                        // No handle went with the take: the next step
                        // brings one.
                        self.kick();
                    }
                }
                return false;
            }
            _ => {
                // The read is unknown to the driver: start another.
                self.input = Input::Idle;
                self.kick();
                return false;
            }
        };
        self.devices[self.active].console.input(&bytes[..n], now());
        let mut signals = [None; 3];
        for (place, signal) in signals
            .iter_mut()
            .zip(self.devices[self.active].console.take_signals())
        {
            *place = Some(signal);
        }
        for signal in signals.into_iter().flatten() {
            let (name, number) = match signal {
                Signal::Interrupt => ("SIGINT", SIGINT),
                Signal::Quit => ("SIGQUIT", SIGQUIT),
                Signal::Suspend => ("SIGTSTP", SIGTSTP),
            };
            match self.devices[self.active].jobs.foreground() {
                Some(group) => self.signal_group(group, number),
                None => rt::println!("tty: {name}, no foreground process group"),
            }
        }
        self.tell_readers();
        self.kick();
        true
    }

    /// Every read that waits looks again: input came, or the settings
    /// changed.
    fn tell_readers(&mut self) {
        self.tell_watches();
        for reader in self.devices[self.active].readers.iter() {
            self.ops.tell(reader.label, reader.key);
        }
    }

    fn readiness(&self, id: u32) -> u32 {
        let endpoint = if id == CONSOLE {
            Endpoint {
                terminal: 0,
                generation: 1,
                side: Side::Slave,
                flags: 2,
            }
        } else {
            match self.endpoints.pinned(id) {
                Ok(e) => e,
                Err(_) => return watch::NVAL,
            }
        };
        if self
            .endpoints
            .instance(endpoint.terminal)
            .is_some_and(|i| i.disconnected)
        {
            return if self.devices[endpoint.terminal].disconnect_pending {
                0
            } else {
                watch::READ | watch::ERR | watch::HUP
            };
        }
        let terminal = &self.devices[endpoint.terminal].console;
        if endpoint.side == Side::Slave {
            terminal.readiness(false)
        } else {
            (u32::from(!terminal.output().is_empty()) * watch::READ)
                | (u32::from(terminal.input_room()) * watch::WRITE)
        }
    }

    fn tell_watches(&mut self) {
        for waiter in self.devices[self.active].watchers.iter() {
            if let Some(set) = self.watches.get(waiter.label, waiter.key)
                && set.ready(|id| self.readiness(id)).any()
            {
                self.ops.tell(waiter.label, waiter.key);
            }
        }
    }

    /// The timer of VTIME at the earliest deadline of the reads that wait.
    fn arm_timer(&mut self) {
        let deadline = self
            .devices
            .iter()
            .filter_map(|d| d.readers.deadline())
            .min();
        if deadline == self.armed {
            return;
        }
        self.armed = deadline;
        // The service's own timer: neither call has an error to give.
        match deadline {
            Some(d) => {
                let _ = sys::timer_set(&self.timer, d);
            }
            None => {
                let _ = sys::timer_cancel(&self.timer);
            }
        }
    }

    /// The handle with NOTIFY a take brought, the first time.
    fn notify_of(
        &self,
        r: &mut Request<'_>,
        take: bool,
    ) -> Result<Option<Handle<Channel>>, Answer> {
        let slot = usize::from(self.preparation == 3 && self.notary.is_some());
        if !take || r.handles.len() <= slot {
            return Ok(None);
        }
        r.handles
            .take::<Channel>(slot)
            .map(Some)
            .map_err(|e| Answer::Status(Status::Kernel(e)))
    }

    /// A read, write or drain with nothing to do: a start makes the
    /// operation and has it wait in `readers`, `writers` or `drainers`
    /// (WAIT k); a take keeps the handle it brought (ARMED) or waits on
    /// with the one it has.
    fn wait(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
        key: Option<u64>,
        kind: Wait,
        description: u32,
        notify: Option<Handle<Channel>>,
    ) -> Answer {
        let label = s.label();
        let reader = match kind {
            Wait::Read(deadline) => Some(deadline),
            Wait::Write | Wait::Drain(_) | Wait::MasterRead | Wait::MasterWrite => None,
        };
        match key {
            None => {
                let ops = &self.ops;
                self.devices[self.active]
                    .watchers
                    .retain(|label, key| ops.waits(label, key));
                if self.devices[self.active].readers.len()
                    + self.devices[self.active].writers.len()
                    + self.devices[self.active].drainers.len()
                    + self.devices[self.active].watchers.len()
                    + self.devices[self.active].master_readers.len()
                    + self.devices[self.active].master_writers.len()
                    >= WAITERS
                {
                    return Answer::Status(Status::Kernel(Error::LimitReached));
                }
                let list = match kind {
                    Wait::Read(_) => &mut self.devices[self.active].readers,
                    Wait::Write => &mut self.devices[self.active].writers,
                    Wait::Drain(_) => &mut self.devices[self.active].drainers,
                    Wait::MasterRead => &mut self.devices[self.active].master_readers,
                    Wait::MasterWrite => &mut self.devices[self.active].master_writers,
                };
                if list.len() == WAITERS {
                    return Answer::Status(Status::Kernel(Error::LimitReached));
                }
                let key = match self.ops.start(&mut s.data.long, label) {
                    Ok(key) => key,
                    Err(e) => return Answer::Status(Status::Kernel(e)),
                };
                if description != CONSOLE
                    && let Err(error) = self
                        .endpoints
                        .pin(&self.holdsets[s.data.holding].holds, description)
                {
                    self.ops.finish(&mut s.data.long, label, key);
                    return status(Self::endpoint_error(error));
                }
                let index = (key as u32 - 1) as usize;
                if let Some(old) = self.pins[index].take()
                    && old.description != CONSOLE
                {
                    let _ = self.endpoints.unpin(old.description);
                }
                self.pins[index] = Some(Pin {
                    label,
                    key,
                    description,
                    kind: kind.number(),
                    drain: tty::drain::Prefix::default(),
                });
                list.add(Waiter {
                    label,
                    key,
                    started: match kind {
                        Wait::Drain(target) => target,
                        _ => now(),
                    },
                    deadline: reader.flatten(),
                });
                self.arm_timer();
                long_answer(r, long::Reply::Wait(key))
            }
            Some(key) => {
                match notify {
                    Some(handle) => {
                        if let Err(e) = self.ops.arm(label, key, handle) {
                            return Answer::Status(Status::Kernel(e));
                        }
                    }
                    None => self.ops.untell(label, key),
                }
                if let Some(deadline) = reader
                    && let Some(waiter) = self.devices[self.active].readers.find(label, key)
                {
                    waiter.deadline = deadline;
                }
                self.arm_timer();
                long_answer(r, long::Reply::Armed)
            }
        }
    }

    /// The operation `key` of `label`, if any, is over.
    fn finish(&mut self, s: &mut Session<Client, 0>, key: Option<u64>) {
        if let Some(key) = key {
            let label = s.label();
            self.ops.finish(&mut s.data.long, label, key);
            self.devices[self.active].readers.remove(label, key);
            self.devices[self.active].writers.remove(label, key);
            self.devices[self.active].drainers.remove(label, key);
            self.devices[self.active].master_readers.remove(label, key);
            self.devices[self.active].master_writers.remove(label, key);
            if let Some(pin) = self.pins[(key as u32 - 1) as usize].take()
                && pin.description != CONSOLE
            {
                let _ = self.endpoints.unpin(pin.description);
            }
            self.arm_timer();
        }
    }

    /// READ_START (`take` false) or READ_TAKE.
    fn read(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
        take: bool,
        master: bool,
    ) -> Answer {
        let read = match Read::parse(r.body(), take) {
            Ok(read) => read,
            Err(status) => return Answer::Status(status),
        };
        let endpoint = match self.operation(s, read.terminal, read.key, if master { 4 } else { 1 })
        {
            Ok(endpoint) => endpoint,
            Err(code) => return status(code),
        };
        if master {
            return self.master_read(s, r, read, endpoint);
        }
        if self.devices[self.active].disconnect_pending {
            if endpoint.flags & tty::endpoints::NONBLOCK != 0 {
                return status(Status::Kernel(Error::LimitReached).code());
            }
            let notify = match self.notify_of(r, take) {
                Ok(notify) => notify,
                Err(answer) => return answer,
            };
            self.kick();
            return self.wait(s, r, read.key, Wait::Read(None), read.terminal, notify);
        }
        if self.disconnected() {
            self.finish(s, read.key);
            return long_answer(r, long::Reply::Ready(&[]));
        }
        let caller = match self.caller(s, r) {
            Ok(caller) => caller,
            Err(code) => return status(code),
        };
        if let Err(code) = self.background(caller, proto_tty::READ_ACCESS, read.blocked) {
            return status(code);
        }
        let notify = match self.notify_of(r, take) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        let at = now();
        let started = match read.key {
            Some(key) => match self.devices[self.active].readers.find(s.label(), key) {
                Some(waiter) => waiter.started,
                None => return Answer::Status(Status::Kernel(Error::BadState)),
            },
            None => at,
        };
        let mut out = [0; MAX_READ];
        match self.devices[self.active]
            .console
            .read(&mut out[..read.count as usize], started, at)
        {
            discipline::Read::Ready(n) => {
                self.finish(s, read.key);
                self.tell_master_writers();
                long_answer(r, long::Reply::Ready(&out[..n]))
            }
            discipline::Read::Wait(deadline) => {
                if endpoint.flags & tty::endpoints::NONBLOCK != 0 {
                    status(Status::Kernel(Error::LimitReached).code())
                } else {
                    self.wait(s, r, read.key, Wait::Read(deadline), read.terminal, notify)
                }
            }
        }
    }

    /// WRITE_START (`take` false) or WRITE_TAKE.
    fn write(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
        take: bool,
        master: bool,
    ) -> Answer {
        let write = match Write::parse(r.body(), take) {
            Ok(write) => write,
            Err(status) => return Answer::Status(status),
        };
        let endpoint =
            match self.operation(s, write.terminal, write.key, if master { 5 } else { 2 }) {
                Ok(endpoint) => endpoint,
                Err(code) => return status(code),
            };
        if master {
            return self.master_write(s, r, write, endpoint);
        }
        if self.disconnected() {
            return status(proto_tty::IO_ERROR);
        }
        let caller = match self.caller(s, r) {
            Ok(caller) => caller,
            Err(code) => return status(code),
        };
        if let Err(code) = self.background(caller, proto_tty::WRITE_ACCESS, write.blocked) {
            return status(code);
        }
        let notify = match self.notify_of(r, take) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if let Some(key) = write.key
            && self.devices[self.active]
                .writers
                .find(s.label(), key)
                .is_none()
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let part = &write.bytes[..write.bytes.len().min(WRITE_STEP)];
        let n = self.devices[self.active].console.write(part);
        if n == 0 {
            return if endpoint.flags & tty::endpoints::NONBLOCK != 0 {
                status(Status::Kernel(Error::LimitReached).code())
            } else {
                self.wait(s, r, write.key, Wait::Write, write.terminal, notify)
            };
        }
        self.finish(s, write.key);
        // The output goes to the driver in the next step.
        self.tell_master_readers();
        self.kick();
        long_answer(r, long::Reply::Ready(&(n as u32).to_le_bytes()))
    }

    fn master_notify(
        &self,
        r: &mut Request<'_>,
        take: bool,
    ) -> Result<Option<Handle<Channel>>, Answer> {
        if r.handles.len() > usize::from(take) {
            return Err(Answer::Status(Status::BadSize));
        }
        if take && !r.handles.is_empty() {
            r.handles
                .take::<Channel>(0)
                .map(Some)
                .map_err(|error| Answer::Status(Status::Kernel(error)))
        } else {
            Ok(None)
        }
    }

    fn master_read(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
        read: Read,
        endpoint: Endpoint,
    ) -> Answer {
        let notify = match self.master_notify(r, read.key.is_some()) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if self.devices[self.active].disconnect_pending {
            if endpoint.flags & tty::endpoints::NONBLOCK != 0 {
                return status(Status::Kernel(Error::LimitReached).code());
            }
            self.kick();
            return self.wait(s, r, read.key, Wait::MasterRead, read.terminal, notify);
        }
        if self.disconnected() {
            self.finish(s, read.key);
            return long_answer(r, long::Reply::Ready(&[]));
        }
        let part = self.devices[self.active].console.output();
        let n = part.len().min(read.count as usize).min(WRITE_STEP);
        if n != 0 {
            let mut out = [0; WRITE_STEP];
            out[..n].copy_from_slice(&part[..n]);
            self.devices[self.active].console.sent(n);
            self.finish(s, read.key);
            self.tell_output();
            return long_answer(r, long::Reply::Ready(&out[..n]));
        }
        if endpoint.flags & tty::endpoints::NONBLOCK != 0 {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        }
        self.wait(s, r, read.key, Wait::MasterRead, read.terminal, notify)
    }

    fn master_write(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
        write: Write<'_>,
        endpoint: Endpoint,
    ) -> Answer {
        let notify = match self.master_notify(r, write.key.is_some()) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if self.disconnected() {
            return status(proto_tty::IO_ERROR);
        }
        let part = &write.bytes[..write.bytes.len().min(WRITE_STEP)];
        let n = self.devices[self.active].console.input_some(part, now());
        if n == 0 {
            if endpoint.flags & tty::endpoints::NONBLOCK != 0 {
                return Answer::Status(Status::Kernel(Error::LimitReached));
            }
            return self.wait(s, r, write.key, Wait::MasterWrite, write.terminal, notify);
        }
        let mut signals = [None; 3];
        for (out, signal) in signals
            .iter_mut()
            .zip(self.devices[self.active].console.take_signals())
        {
            *out = Some(signal);
        }
        for signal in signals.into_iter().flatten() {
            if let Some(group) = self.devices[self.active].jobs.foreground() {
                let number = match signal {
                    Signal::Interrupt => 2,
                    Signal::Quit => 3,
                    Signal::Suspend => 20,
                };
                self.signal_group(group, number);
            }
        }
        self.finish(s, write.key);
        self.tell_readers();
        self.tell_master_readers();
        self.tell_output();
        long_answer(r, long::Reply::Ready(&(n as u32).to_le_bytes()))
    }

    fn tell_master_readers(&mut self) {
        self.tell_watches();
        if self.disconnected() || !self.devices[self.active].console.output().is_empty() {
            for waiter in self.devices[self.active].master_readers.iter() {
                self.ops.tell(waiter.label, waiter.key);
            }
        }
    }
    fn tell_master_writers(&mut self) {
        self.tell_watches();
        if self.disconnected() || self.devices[self.active].console.input_room() {
            for waiter in self.devices[self.active].master_writers.iter() {
                self.ops.tell(waiter.label, waiter.key);
            }
        }
    }

    /// DRAIN_START or DRAIN_TAKE: captured output is physically transmitted.
    fn drain(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>, take: bool) -> Answer {
        let drain = match Drain::parse(r.body(), take) {
            Ok(drain) => drain,
            Err(status) => return Answer::Status(status),
        };
        let _endpoint = match self.operation(s, drain.terminal, drain.key, 3) {
            Ok(endpoint) => endpoint,
            Err(code) => return status(code),
        };
        if self.disconnected() {
            return status(proto_tty::IO_ERROR);
        }
        let caller = match self.caller(s, r) {
            Ok(caller) => caller,
            Err(code) => return status(code),
        };
        if let Err(code) = self.background(caller, proto_tty::CHANGE_ACCESS, drain.blocked) {
            return status(code);
        }
        let notify = match self.notify_of(r, take) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if let Some(key) = drain.key
            && self.devices[self.active]
                .drainers
                .find(s.label(), key)
                .is_none()
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        self.mark_drains();
        if let Some(key) = drain.key {
            let pin = self.pins[(key as u32 - 1) as usize].expect("a pinned drain");
            if pin.drain.failed {
                self.finish(s, Some(key));
                return status(proto_tty::IO_ERROR);
            }
            if pin.drain.ready {
                self.finish(s, Some(key));
                return long_answer(r, long::Reply::Ready(&[]));
            }
        } else if self.devices[self.active].console.output_len() == 0 {
            let ready = if self.active == 0 {
                match self.driver_drain(proto_uart::Method::DrainState, None) {
                    Ok(ready) => ready,
                    Err(_) => {
                        self.reconnect();
                        return status(proto_tty::IO_ERROR);
                    }
                }
            } else {
                true
            };
            if ready {
                return long_answer(r, long::Reply::Ready(&[]));
            }
        }
        let target = self.devices[self.active].console.output_target();
        self.kick();
        self.wait(s, r, drain.key, Wait::Drain(target), drain.terminal, notify)
    }

    /// READ_CANCEL, WRITE_CANCEL or DRAIN_CANCEL: the operation goes, with
    /// no effect.
    fn cancel(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let cancel = match Cancel::parse(r.body()) {
            Ok(cancel) => cancel,
            Err(status) => return Answer::Status(status),
        };
        if !self.ops.waits(s.label(), cancel.key)
            || self.watches.get(s.label(), cancel.key).is_some()
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let kind = match Method::from_number(r.method()) {
            Some(Method::ReadCancel) => 1,
            Some(Method::WriteCancel) => 2,
            Some(Method::DrainCancel) => 3,
            Some(Method::MasterReadCancel) => 4,
            Some(Method::MasterWriteCancel) => 5,
            _ => return status(INVALID),
        };
        if let Err(code) = self.operation(s, cancel.terminal, Some(cancel.key), kind) {
            return status(code);
        }
        let ready = kind == 3
            && self.pins[(cancel.key as u32 - 1) as usize].is_some_and(|pin| pin.drain.ready);
        self.finish(s, Some(cancel.key));
        if kind == 3 {
            self.kick();
        }
        long_answer(
            r,
            if ready {
                long::Reply::Ready(&[])
            } else {
                long::Reply::Cancelled
            },
        )
    }

    fn watch_ready(r: &mut Request<'_>, ready: watch::Ready) -> Answer {
        let mut body = Writer::new();
        if let Err(status) = ready.write(&mut body) {
            return Answer::Status(status);
        }
        long_answer(r, long::Reply::Ready(body.as_bytes()))
    }

    fn watch_start(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let set = match watch::Set::parse(r.body()) {
            Ok(set) if r.handles.is_empty() => set,
            _ => return Answer::Status(Status::BadSize),
        };
        if set.len > proto_tty::WATCH_MAX {
            return Answer::Status(Status::BadSize);
        }
        // The elements that name one description are met once: its
        // endpoint is resolved and its readiness read once for all of
        // them, and the pins they take are made in one step. Only the
        // elements are compared, a walk of at most `watch::MAX` squared.
        let mut terminals = [false; TERMINALS];
        let mut ready = watch::Ready {
            len: set.len,
            events: [0; watch::MAX],
        };
        let mut distinct = [(0u32, 0u32); watch::MAX];
        let mut distinct_len = 0;
        for (i, item) in set.items[..set.len].iter().enumerate() {
            if set.items[..i]
                .iter()
                .any(|before| before.description == item.description)
            {
                continue;
            }
            let endpoint = match self.select_description(s, item.description) {
                Ok(e) => e,
                Err(code) => return status(code),
            };
            terminals[endpoint.terminal] = true;
            let state = self.readiness(item.description);
            let mut named = 0;
            for (j, other) in set.items[i..set.len].iter().enumerate() {
                if other.description == item.description {
                    ready.events[i + j] = state & (other.events | watch::ALWAYS);
                    named += 1;
                }
            }
            distinct[distinct_len] = (item.description, named);
            distinct_len += 1;
        }
        rt::service::step_detail(set.len as u64);
        if ready.any() {
            return Self::watch_ready(r, ready);
        }
        for (n, used) in terminals.iter().enumerate() {
            if !used {
                continue;
            }
            let ops = &self.ops;
            let device = &mut self.devices[n];
            device.watchers.retain(|label, key| ops.waits(label, key));
            if device.readers.len()
                + device.writers.len()
                + device.drainers.len()
                + device.master_readers.len()
                + device.master_writers.len()
                + device.watchers.len()
                >= WAITERS
            {
                return Answer::Status(Status::Kernel(Error::LimitReached));
            }
        }
        let label = s.label();
        let key = match self.ops.start(&mut s.data.long, label) {
            Ok(key) => key,
            Err(error) => return Answer::Status(Status::Kernel(error)),
        };
        if !self.watches.insert(label, key, set) {
            self.ops.finish(&mut s.data.long, label, key);
            return Answer::Status(Status::Kernel(Error::LimitReached));
        }
        for (index, &(description, named)) in distinct[..distinct_len].iter().enumerate() {
            if description != CONSOLE
                // Resolved above, in this step: the table index is the
                // low byte of the number.
                && let Err(error) = self.endpoints.pin_at((description & 255) as usize, named)
            {
                for &(previous, named) in &distinct[..index] {
                    if previous != CONSOLE {
                        for _ in 0..named {
                            let _ = self.endpoints.unpin(previous);
                        }
                    }
                }
                self.watches.remove(label, key);
                self.ops.finish(&mut s.data.long, label, key);
                return status(Self::endpoint_error(error));
            }
        }
        // A Watch may reuse the operation place of an already retired I/O.
        self.clear_pin((key as u32 - 1) as usize);
        for (n, used) in terminals.iter().enumerate() {
            if *used {
                let _ = self.devices[n].watchers.add(Waiter {
                    label,
                    key,
                    started: now(),
                    deadline: None,
                });
            }
        }
        long_answer(r, long::Reply::Wait(key))
    }

    fn watch_keyed(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
        cancel: bool,
    ) -> Answer {
        let key = match watch::key(r.body()) {
            Ok(key) => key,
            Err(status) => return Answer::Status(status),
        };
        let label = s.label();
        let Some(set) = self
            .watches
            .get(label, key)
            .copied()
            .filter(|_| self.ops.waits(label, key))
        else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        if cancel {
            if !r.handles.is_empty() {
                return Answer::Status(Status::BadSize);
            }
        } else {
            if r.handles.len() > 1
                || (!r.handles.is_empty()
                    && !matches!(r.handles.info(0), Some((rt::abi::ObjectKind::Channel, rights)) if rights.contains(Rights::NOTIFY)))
            {
                return Answer::Status(Status::BadSize);
            }
            // Watch carries no identity; its only handle is Notify in slot 0.
            let notify = if r.handles.is_empty() {
                None
            } else {
                match r.handles.take::<Channel>(0) {
                    Ok(handle) => Some(handle),
                    Err(error) => return Answer::Status(Status::Kernel(error)),
                }
            };
            match notify {
                Some(handle) => {
                    if let Err(error) = self.ops.arm(label, key, handle) {
                        return Answer::Status(Status::Kernel(error));
                    }
                }
                None => self.ops.untell(label, key),
            }
        }
        rt::service::step_detail(set.len as u64);
        let ready = set.ready(|id| self.readiness(id));
        if cancel {
            for device in self.devices.iter_mut() {
                device.watchers.remove(label, key);
            }
            for item in &set.items[..set.len] {
                if item.description != CONSOLE {
                    let _ = self.endpoints.unpin(item.description);
                }
            }
            self.watches.remove(label, key);
            self.ops.finish(&mut s.data.long, label, key);
            Self::watch_ready(r, ready)
        } else if ready.any() {
            Self::watch_ready(r, ready)
        } else {
            long_answer(r, long::Reply::Armed)
        }
    }

    /// CLONE: a session of the service's own label for a child of the
    /// client.
    fn clone_session(&mut self, s: &Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let mut body = r.body();
        let parent = if body.left() == 0 {
            self.holdsets[s.data.holding].holds.clone()
        } else {
            let Ok(count) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            if count as usize > tty::endpoints::HOLDS {
                return status(INVALID);
            }
            let mut ids = [0; tty::endpoints::HOLDS];
            for id in &mut ids[..count as usize] {
                match body.u32() {
                    Ok(word) => *id = word,
                    Err(code) => return Answer::Status(code),
                }
            }
            if body.finish().is_err() {
                return Answer::Status(Status::BadSize);
            }
            match self.holdsets[s.data.holding]
                .holds
                .selected(&ids[..count as usize])
            {
                Ok(holds) => holds,
                Err(error) => return status(Self::endpoint_error(error)),
            }
        };
        self.new_clone(s.data.root, &parent, r)
    }

    fn new_clone(&mut self, root: u64, parent: &Holds, r: &mut Request<'_>) -> Answer {
        let Ok(label) = self.clones.give_within(OWN, root, ROOT_CLONES) else {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        };
        let Some(slot) = self.holdsets.take() else {
            self.clones.gone(label);
            return Answer::Status(Status::Kernel(Error::LimitReached));
        };
        let priority = self.level.saturating_sub(1).max(1);
        let session = match sys::handle_label(
            &self.channel,
            Rights::SEND | Rights::TRANSFER,
            label,
            priority,
        ) {
            Ok(session) => session,
            Err(error) => {
                self.holdsets.release(slot);
                self.clones.gone(label);
                return Answer::Status(Status::Kernel(error));
            }
        };
        // The kernel may report this label's Gone after a later request.
        // Every label is given once, even if inheritance fails.
        let child = match self.endpoints.clone_holds(parent) {
            Ok(child) => child,
            Err(error) => {
                self.holdsets.release(slot);
                self.clones.gone(label);
                return status(Self::endpoint_error(error));
            }
        };
        self.holdsets[slot] = HoldSet {
            label,
            root,
            holds: child,
            retired: false,
        };
        // `give_within` just gave the label a place.
        let place = self.clones.place_of(label).expect("a label just given");
        self.holdsets.bind_clone(place, slot);
        let _ = r.reply().u32(0);
        Answer::Reply([session.erase()].into())
    }

    /// GET_ATTR: the settings of the terminal.
    fn get_attr(&mut self, s: &Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let terminal = match body.u32().and_then(|t| body.finish().map(|()| t)) {
            Ok(terminal) => terminal,
            Err(status) => return Answer::Status(status),
        };
        if let Err(code) = self.select_description(s, terminal) {
            return status(code);
        }
        let termios = *self.devices[self.active].console.termios();
        let w = r.reply();
        if w.u32(0).is_err() || termios.write(w).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    fn get_winsize(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let description = match body.u32().and_then(|id| body.finish().map(|()| id)) {
            Ok(id) => id,
            Err(status) => return Answer::Status(status),
        };
        if let Err(code) = self.select_description(s, description) {
            return status(code);
        }
        if let Err(code) = self.caller(s, r) {
            return status(code);
        }
        let size = self.devices[self.active].winsize;
        if r.reply()
            .u32(0)
            .and_then(|()| size.write(r.reply()))
            .is_err()
        {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    fn set_winsize(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let set = match proto_tty::SetWinsize::parse(r.body()) {
            Ok(set) => set,
            Err(status) => return Answer::Status(status),
        };
        let endpoint = match self.select_description(s, set.description) {
            Ok(endpoint) => endpoint,
            Err(code) => return status(code),
        };
        let caller = match self.caller(s, r) {
            Ok(caller) => caller,
            Err(code) => return status(code),
        };
        if endpoint.side == Side::Slave
            && let Err(code) = self.background(caller, proto_tty::CHANGE_ACCESS, set.blocked)
        {
            return status(code);
        }
        let before = self.devices[self.active].winsize;
        if before != set.size {
            self.devices[self.active].winsize = set.size;
            if let Some(group) = self.devices[self.active].jobs.foreground()
                && let Err(code) = self.try_signal_group(group, 28)
            {
                self.devices[self.active].winsize = before;
                return status(code);
            }
        }
        Answer::Status(Status::Ok)
    }

    /// FLUSH_QUEUES: the input not read, or the output the driver did not
    /// take, goes.
    fn flush_queues(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let control = match Control::parse(r.body()) {
            Ok(control) => control,
            Err(status) => return Answer::Status(status),
        };
        if let Err(code) = self.select_description(s, control.terminal) {
            return status(code);
        }
        let caller = match self.caller(s, r) {
            Ok(caller) => caller,
            Err(code) => return status(code),
        };
        if let Err(code) = self.background(caller, proto_tty::CHANGE_ACCESS, control.blocked) {
            return status(code);
        }
        if !matches!(control.word, QUEUE_IN | QUEUE_OUT | QUEUE_BOTH) {
            return status(INVALID);
        }
        if control.word != QUEUE_OUT {
            self.devices[self.active].console.flush_input();
            self.tell_readers();
        }
        if control.word != QUEUE_IN {
            self.devices[self.active].console.flush_output();
            self.tell_output();
        }
        Answer::Status(Status::Ok)
    }

    /// FLOW: the output stops or goes on, or the STOP or START character
    /// goes out.
    fn flow(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let control = match Control::parse(r.body()) {
            Ok(control) => control,
            Err(status) => return Answer::Status(status),
        };
        if let Err(code) = self.select_description(s, control.terminal) {
            return status(code);
        }
        let caller = match self.caller(s, r) {
            Ok(caller) => caller,
            Err(code) => return status(code),
        };
        if let Err(code) = self.background(caller, proto_tty::CHANGE_ACCESS, control.blocked) {
            return status(code);
        }
        match control.word {
            FLOW_OUT_OFF => self.devices[self.active].console.set_stopped(true),
            FLOW_OUT_ON => {
                self.devices[self.active].console.set_stopped(false);
                self.kick();
            }
            FLOW_IN_OFF | FLOW_IN_ON => {
                let index = if control.word == FLOW_IN_OFF {
                    VSTOP
                } else {
                    VSTART
                };
                if self.devices[self.active].console.termios().cc[index] != proto_tty::DISABLED
                    && !self.devices[self.active].console.send_control(index)
                {
                    return Answer::Status(Status::Kernel(Error::LimitReached));
                }
                self.kick();
            }
            _ => return status(INVALID),
        }
        Answer::Status(Status::Ok)
    }

    /// SET_ATTR: new settings at once (DRAIN as NOW, FLUSH dropping the
    /// input not read); the reads that wait look again.
    fn set_attr(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let set = match SetAttr::parse(r.body()) {
            Ok(set) => set,
            Err(status) => return Answer::Status(status),
        };
        if let Err(code) = self.select_description(s, set.terminal) {
            return status(code);
        }
        let caller = match self.caller(s, r) {
            Ok(caller) => caller,
            Err(code) => return status(code),
        };
        if let Err(code) = self.background(caller, proto_tty::CHANGE_ACCESS, set.blocked) {
            return status(code);
        }
        if set.action > FLUSH {
            return status(INVALID);
        }
        self.devices[self.active]
            .console
            .set_termios(set.termios, set.action == FLUSH);
        self.tell_readers();
        Answer::Status(Status::Ok)
    }
}

/// The numbers of the signals of the terminal (Linux's).
const SIGINT: u32 = 2;
const SIGQUIT: u32 = 3;
const SIGTSTP: u32 = 20;
#[cfg(all(feature = "trust-probe", not(feature = "steps")))]
const PROBE_METHODS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
];

impl Tty {
    #[cfg(feature = "trust-probe")]
    fn trust_probe(&mut self, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let (Ok(target), Ok(())) = (body.u32(), body.finish()) else {
            return Answer::Status(Status::BadSize);
        };
        let terminal = self.active as u32;
        let sid = self.devices[self.active].jobs.session().unwrap_or(0);
        let generation = self.devices[self.active].job_generation;
        let Some(notary) = self.notary() else {
            return status(NO_IDENTITY);
        };
        let mut w = Writer::new();
        if r.method() == 21 {
            let _ = proto_process::Method::TtySignal.header().write(&mut w);
            let _ = w.u32(terminal);
            let _ = w.u32(target);
            let _ = w.u32(28);
            let _ = w.u64(generation);
        } else if r.method() == 22 {
            let _ = proto_wire::Header::new(42, proto_process::VERSION).write(&mut w);
            let _ = w.u32(target);
        } else {
            let _ = proto_wire::Header::new(44, proto_process::VERSION).write(&mut w);
            let _ = w.u32(target);
            let _ = w.u32(sid);
        }
        let Ok(reply) = sys::send(notary, w.as_bytes()) else {
            return status(PERMISSION);
        };
        let mut buffer = [0; MESSAGE_MAX];
        if r.reply().bytes(reply.bytes(&mut buffer)).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// The notary session and the page of the generations, asked for once
    /// (none in an image without the process service).
    fn notary(&mut self) -> Option<&Handle<Channel>> {
        if self.preparation == 3 {
            self.notary.as_ref()
        } else {
            None
        }
    }

    /// The word at byte `at` of the page of the generations, once mapped.
    fn word(&self, at: usize) -> u64 {
        if self.generations.is_none() || at + 8 > 4096 {
            return 0;
        }
        // SAFETY: the page is mapped readable at GENERATIONS_AT for as long
        // as the service lives (`notary`); `at` is aligned and in it.
        let word = unsafe { &*((GENERATIONS_AT + at) as *const core::sync::atomic::AtomicU64) };
        word.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Who sent `r` through `s`: the process service vouches for the
    /// identity the request brought, once and again when the record's
    /// generation moved; its group and session come from the page.
    fn caller_identity(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
    ) -> Result<(Caller, Who), u32> {
        if self.notary().is_none() && self.devices[self.active].job_generation == 0 {
            return Ok((
                Caller {
                    pid: 0,
                    pgid: 0,
                    sid: 0,
                    ctty: None,
                },
                Who {
                    index: 0,
                    pid: 0,
                    generation: 0,
                    loader: false,
                    ctty: None,
                    uid: 0,
                    euid: 0,
                    egid: 0,
                },
            ));
        }
        let offered = if r.handles.is_empty() {
            None
        } else {
            r.handles.take::<Channel>(0).ok()
        };
        self.notary().ok_or(NO_IDENTITY)?;
        let current = s
            .data
            .who
            .filter(|w| !w.loader && self.word(w.index * 8) == w.generation);
        let who = match (current, offered) {
            (Some(who), _) => who,
            (None, Some(identity)) => {
                let notary = self.notary.as_ref().ok_or(NO_IDENTITY)?;
                let request = proto_process::Method::Vouch.header().bytes();
                let reply = sys::send_handles(notary, &request, [identity.erase()])
                    .map_err(|_| NO_IDENTITY)?;
                let mut buffer = [0; MESSAGE_MAX];
                let said = proto_process::WhoReply::read(reply.bytes(&mut buffer))
                    .map_err(|_| NO_IDENTITY)?;
                Who {
                    index: said.index as usize,
                    pid: said.pid,
                    generation: said.generation,
                    loader: said.loader.is_some(),
                    uid: said.credentials.uid,
                    euid: said.credentials.euid,
                    egid: said.credentials.egid,
                    ctty: said.ctty,
                }
            }
            (None, None) => return Err(NO_IDENTITY),
        };
        s.data.who = (!who.loader).then_some(who);
        let word = self.word(proto_process::GROUPS_AT + who.index * 8);
        let (pgid, sid) = proto_process::groups_of(word).ok_or(NO_IDENTITY)?;
        Ok((
            Caller {
                pid: who.pid,
                pgid,
                sid,
                ctty: who.ctty,
            },
            who,
        ))
    }

    fn caller(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Result<Caller, u32> {
        self.caller_identity(s, r).map(|(caller, _)| caller)
    }

    /// A request of the controlling terminal (ACQUIRE, SET_PGRP, GET_PGRP,
    /// GET_SID, CONTROLLING).
    fn job(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>, method: Method) -> Answer {
        let mut body = r.body();
        let Ok(terminal) = body.u32() else {
            return Answer::Status(Status::BadSize);
        };
        let group = if method == Method::SetPgrp {
            match body.u32() {
                Ok(group) => group,
                Err(status) => return Answer::Status(status),
            }
        } else {
            0
        };
        let blocked = if method == Method::SetPgrp {
            match body.u32() {
                Ok(v) if v <= 1 => v,
                _ => return status(INVALID),
            }
        } else {
            0
        };
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        if let Err(code) = self.select_description(s, terminal) {
            return status(code);
        }
        if terminal & proto_tty::MASTER != 0 || self.disconnected() {
            return status(proto_tty::NOT_CONTROLLING);
        }
        let caller = match self.caller(s, r) {
            Ok(caller) => caller,
            Err(code) => return status(code),
        };
        if method != Method::Acquire
            && caller.ctty != Some((self.active as u32, self.devices[self.active].job_generation))
        {
            return status(proto_tty::NOT_CONTROLLING);
        }
        let result = match method {
            Method::Acquire => self.acquire(caller).map(|()| None),
            Method::Detach => self.detach(caller).map(|()| None),
            Method::SetPgrp => {
                if let Err(code) = self.background(caller, proto_tty::CHANGE_ACCESS, blocked) {
                    return status(code);
                }
                #[cfg(all(feature = "steps", not(feature = "quiet-steps")))]
                let began = time::now();
                let in_session = |pgid, sid| {
                    jobs::group_in_session(
                        proto_process::RECORDS,
                        |i| self.word(proto_process::GROUPS_AT + i * 8),
                        pgid,
                        sid,
                    )
                };
                let mut jobs = self.devices[self.active].jobs;
                let set = jobs.set_foreground(caller, group, in_session);
                self.devices[self.active].jobs = jobs;
                #[cfg(all(feature = "steps", not(feature = "quiet-steps")))]
                rt::println!(
                    "tty group scan: group {group} {} ticks code {}",
                    time::now().saturating_sub(began),
                    set.as_ref().err().copied().unwrap_or(0)
                );
                set.map(|()| None)
            }
            Method::GetPgrp => self.devices[self.active]
                .jobs
                .get_foreground(caller)
                .map(Some),
            Method::GetSid => self.devices[self.active].jobs.get_session(caller).map(Some),
            _ => self.devices[self.active]
                .jobs
                .controlling(caller)
                .map(|()| None),
        };
        match result {
            Ok(None) => Answer::Status(Status::Ok),
            Ok(Some(word)) => {
                let w = r.reply();
                if w.u32(0).is_err() || w.u32(word).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply(Outgoing::new())
            }
            Err(code) => status(code),
        }
    }

    fn detach(&mut self, caller: Caller) -> Result<(), u32> {
        if caller.ctty != Some((self.active as u32, self.devices[self.active].job_generation)) {
            return Err(proto_tty::NOT_CONTROLLING);
        }
        let generation = self.devices[self.active].job_generation;
        let terminal = self.active as u32;
        let notary = self.notary().ok_or(NO_IDENTITY)?;
        let mut w = Writer::new();
        proto_process::Method::DetachCtty
            .header()
            .write(&mut w)
            .map_err(|_| PERMISSION)?;
        w.u32(terminal)
            .and_then(|()| w.u32(caller.pid))
            .and_then(|()| w.u64(generation))
            .map_err(|_| PERMISSION)?;
        let reply = sys::send(notary, w.as_bytes()).map_err(|_| PERMISSION)?;
        let mut buffer = [0; MESSAGE_MAX];
        if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
            return Err(PERMISSION);
        }
        if caller.pid == caller.sid {
            if !self.devices[self.active].departed.keep(Departed {
                generation,
                sid: caller.sid,
                foreground: self.devices[self.active].jobs.foreground(),
            }) {
                return Err(PERMISSION);
            }
            self.devices[self.active].jobs.release();
            self.devices[self.active].job_generation = 0;
            self.finish_departure(generation);
        }
        Ok(())
    }

    /// ACQUIRE: the process service gives the console to the caller's
    /// session (SetCtty), unless the session has it already.
    fn acquire(&mut self, caller: Caller) -> Result<(), u32> {
        if !self.devices[self.active].jobs.may_acquire(caller)?
            && caller.ctty == Some((self.active as u32, self.devices[self.active].job_generation))
        {
            return Ok(());
        }
        let terminal = self.active as u32;
        let notary = self.notary().ok_or(PERMISSION)?;
        let mut w = Writer::new();
        let written = proto_process::Method::SetCtty
            .header()
            .write(&mut w)
            .and_then(|()| w.u32(terminal))
            .and_then(|()| w.u32(caller.sid));
        if written.is_err() {
            return Err(PERMISSION);
        }
        let reply = sys::send(notary, w.as_bytes()).map_err(|_| PERMISSION)?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
        if r.u32() != Ok(0) {
            return Err(PERMISSION);
        }
        let generation = r.u64().map_err(|_| PERMISSION)?;
        if self.devices[self.active].job_generation != 0
            && !self.devices[self.active].departed.keep(Departed {
                generation: self.devices[self.active].job_generation,
                sid: self.devices[self.active].jobs.session().unwrap_or(0),
                foreground: self.devices[self.active].jobs.foreground(),
            })
        {
            return Err(PERMISSION);
        }
        self.devices[self.active].job_generation = generation;
        self.devices[self.active].jobs.acquired(caller);
        let instance = self
            .endpoints
            .instance(self.active)
            .expect("controlling instance")
            .generation;
        self.endpoints
            .set_link(self.active, instance, true)
            .map_err(Self::endpoint_error)?;
        Ok(())
    }

    /// Recheck the current foreground immediately before an actual effect.
    fn background(&mut self, caller: Caller, kind: u32, blocked: u32) -> Result<(), u32> {
        if caller.ctty != Some((self.active as u32, self.devices[self.active].job_generation))
            || self.devices[self.active].jobs.session() != Some(caller.sid)
            || self.devices[self.active].jobs.foreground() == Some(caller.pgid)
            || kind == proto_tty::WRITE_ACCESS
                && self.devices[self.active].console.termios().lflag & proto_tty::TOSTOP == 0
        {
            return Ok(());
        }
        if blocked != 0 {
            return if kind == proto_tty::READ_ACCESS {
                Err(proto_tty::IO_ERROR)
            } else {
                Ok(())
            };
        }
        let signal = if kind == proto_tty::READ_ACCESS {
            proto_process::SIGTTIN
        } else {
            proto_process::SIGTTOU
        };
        let Some(notary) = self.notary.as_ref() else {
            return Err(NO_IDENTITY);
        };
        let mut w = Writer::new();
        let _ = proto_process::Method::TtySignal.header().write(&mut w);
        let _ = w.u32(self.active as u32);
        let _ = w.u32(caller.pgid);
        let _ = w.u32(signal as u32);
        let _ = w.u64(self.devices[self.active].job_generation);
        let Ok(reply) = sys::send(notary, w.as_bytes()) else {
            return Err(proto_tty::IO_ERROR);
        };
        let mut buffer = [0; MESSAGE_MAX];
        match proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() {
            Ok(0) => Err(proto_tty::RESTART),
            _ => Err(proto_tty::IO_ERROR),
        }
    }

    /// The signal `number` of INTR, QUIT or SUSP to the foreground group
    /// `group` (XBD 11.1.9): the process service walks the group
    /// (TtySignal) and answers at the walk's end. A group of a session
    /// the console is no longer the controlling terminal of gets none.
    fn signal_group(&mut self, group: u32, number: u32) {
        let _ = self.try_signal_group(group, number);
    }

    fn try_signal_group(&mut self, group: u32, number: u32) -> Result<(), u32> {
        let generation = self.devices[self.active].job_generation;
        let terminal = self.active as u32;
        let Some(notary) = self.notary() else {
            return Err(NO_IDENTITY);
        };
        let mut w = Writer::new();
        let written = proto_process::Method::TtySignal
            .header()
            .write(&mut w)
            .and_then(|()| w.u32(terminal))
            .and_then(|()| w.u32(group))
            .and_then(|()| w.u32(number))
            .and_then(|()| w.u64(generation));
        if written.is_err() {
            return Err(INVALID);
        }
        let reply = loop {
            match sys::send(notary, w.as_bytes()) {
                Err(Error::Interrupted) => continue,
                Err(_) => return Err(proto_tty::IO_ERROR),
                Ok(reply) => break reply,
            }
        };
        let mut buffer = [0; MESSAGE_MAX];
        match proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() {
            Ok(0 | proto_process::NO_PROCESS) => Ok(()),
            _ => Err(proto_tty::IO_ERROR),
        }
    }
}

impl Tty {
    fn retire_holds(&mut self, slot: usize) {
        if !self.holdsets[slot].retired {
            // A slot remains occupied until the queue releases it.
            // There are HOLDSETS slots, and each enters only once.
            assert!(self.retired.push(slot));
            self.holdsets[slot].retired = true;
        }
    }

    fn abandon(&mut self, s: &mut Session<Client, 0>) {
        let label = s.label();
        self.watches.retire(label);
        self.ops.gone(&mut s.data.long);
        self.pin_cleanup_due = true;
        self.watch_cleanup_due = true;
        for device in self.devices.iter_mut() {
            device.readers.remove_all(label);
            device.writers.remove_all(label);
            device.drainers.remove_all(label);
            device.master_readers.remove_all(label);
            device.master_writers.remove_all(label);
        }
        self.arm_timer();
        self.kick();
    }
}

impl Service<0> for Tty {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = {
        #[cfg(all(feature = "trust-probe", feature = "steps"))]
        {
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
                46,
            ]
        }
        #[cfg(all(feature = "trust-probe", not(feature = "steps")))]
        {
            PROBE_METHODS
        }
        #[cfg(all(not(feature = "trust-probe"), feature = "steps"))]
        {
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 24, 25, 26,
                27, 28, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            ]
        }
        #[cfg(all(not(feature = "trust-probe"), not(feature = "steps")))]
        {
            proto_tty::METHODS
        }
    };
    type Data = Client;

    fn request(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        self.select(0);
        self.due();
        #[cfg(feature = "steps")]
        if r.method() == 30 {
            return rt::service::step_snapshot(r);
        }
        #[cfg(feature = "trust-probe")]
        if (21..=23).contains(&r.method()) {
            return self.trust_probe(r);
        }
        if s.data.root == 0 {
            let label = r.label();
            // A clone's set is found by the place of its label, a root's
            // in the small table of roots; a session with none takes one.
            let holding = match self.holdsets.find(label, &*self.clones) {
                Some(holding) => holding,
                // A label of the service's own that is no longer found is a
                // clone that ended, and is no root. The roots with such a
                // label are the service's own sessions, which carry bit 62
                // too (`LOADERS`, the session the process service holds
                // for the loaders); a clone's label never does.
                None if label & OWN != 0 && label & 1 << 62 == 0 => {
                    return Answer::Status(Status::Kernel(Error::BadState));
                }
                None => {
                    let Some(holding) = self.holdsets.take() else {
                        return Answer::Status(Status::Kernel(Error::LimitReached));
                    };
                    if !self.holdsets.bind_root(label, holding) {
                        self.holdsets.release(holding);
                        return Answer::Status(Status::Kernel(Error::LimitReached));
                    }
                    self.holdsets[holding].label = label;
                    self.holdsets[holding].root = label;
                    holding
                }
            };
            if self.holdsets[holding].retired {
                return Answer::Status(Status::Kernel(Error::BadState));
            }
            s.data.holding = holding;
            s.data.root = self.holdsets[holding].root;
        }
        match Method::from_number(r.method()) {
            Some(Method::Open) => self.open(s, r),
            Some(
                m @ (Method::Close
                | Method::Lock
                | Method::Number
                | Method::Grant
                | Method::GetFlags
                | Method::SetFlags
                | Method::Stat),
            ) => self.description(s, r, m),
            Some(Method::MasterReadStart) => self.read(s, r, false, true),
            Some(Method::MasterReadTake) => self.read(s, r, true, true),
            Some(Method::MasterWriteStart) => self.write(s, r, false, true),
            Some(Method::MasterWriteTake) => self.write(s, r, true, true),
            Some(Method::WatchStart) => self.watch_start(s, r),
            Some(Method::WatchTake) => self.watch_keyed(s, r, false),
            Some(Method::WatchCancel) => self.watch_keyed(s, r, true),
            Some(Method::ReadStart) => self.read(s, r, false, false),
            Some(Method::ReadTake) => self.read(s, r, true, false),
            Some(Method::WriteStart) => self.write(s, r, false, false),
            Some(Method::WriteTake) => self.write(s, r, true, false),
            Some(Method::DrainStart) => self.drain(s, r, false),
            Some(Method::DrainTake) => self.drain(s, r, true),
            Some(Method::FlushQueues) => self.flush_queues(s, r),
            Some(Method::Flow) => self.flow(s, r),
            Some(
                Method::ReadCancel
                | Method::WriteCancel
                | Method::DrainCancel
                | Method::MasterReadCancel
                | Method::MasterWriteCancel,
            ) => self.cancel(s, r),
            Some(Method::Clone) => self.clone_session(s, r),
            Some(Method::VerifySession) => {
                if r.body().finish().is_err() || r.handles.len() != 1 {
                    return Answer::Status(Status::BadSize);
                }
                if !matches!(r.handles.info(0), Some((rt::abi::ObjectKind::Channel, rights)) if rights.contains(Rights::SEND | Rights::TRANSFER))
                {
                    return Answer::Status(Status::BadSize);
                }
                let Ok(offered) = r.handles.take::<Channel>(0) else {
                    return Answer::Status(Status::BadSize);
                };
                if sys::copy_label(&self.channel, &offered).is_ok() {
                    if r.reply().u32(0).is_err() {
                        return Answer::Status(Status::BadSize);
                    }
                    Answer::Reply([offered.erase()].into())
                } else {
                    // The counterfeit endpoint receives no request or
                    // identity. Return an ordinary unique trusted clone.
                    drop(offered);
                    let parent = self.holdsets[s.data.holding].holds.clone();
                    self.new_clone(s.data.root, &parent, r)
                }
            }
            Some(Method::GetAttr) => self.get_attr(s, r),
            Some(Method::GetWinsize) => self.get_winsize(s, r),
            Some(Method::SetWinsize) => self.set_winsize(s, r),
            Some(Method::SetAttr) => self.set_attr(s, r),
            Some(
                m @ (Method::Acquire
                | Method::SetPgrp
                | Method::GetPgrp
                | Method::GetSid
                | Method::Controlling
                | Method::Detach),
            ) => self.job(s, r, m),
            Some(Method::Abandon) => {
                if r.body().finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                self.abandon(s);
                Answer::Status(Status::Ok)
            }
            None => Answer::Status(Status::UnknownMethod),
        }
    }

    fn gone(&mut self, s: &mut Session<Client, 0>) {
        self.abandon(s);
        // The set was bound by the first request; a session that made
        // none looks for it as a request would.
        let set = if s.data.root != 0 {
            Some(s.data.holding)
        } else {
            self.holdsets.find(s.label(), &*self.clones)
        };
        if let Some(slot) = set {
            self.retire_holds(slot);
        }
        self.kick();
    }

    fn closed(&mut self, label: u64) {
        // The set is found by the place of the clone: unbind it before the
        // place is free. It stays in the queue of retired sets until its
        // holds are closed, and only then is it free for another session.
        let set = self.holdsets.unbind(label, &*self.clones);
        self.clones.gone(label);
        if let Some(slot) = set {
            self.retire_holds(slot);
        }
        self.kick();
    }

    /// The driver's input (DRIVER_IN) and room (DRIVER_ROOM), the step of
    /// the work left (STEP), and the timer of VTIME.
    fn notification(&mut self, n: Notice) {
        self.select(0);
        match (n.source, n.label) {
            (Source::Session, DEPARTURES) => {
                rt::service::step_own();
                if self.departure_left == 0 {
                    self.departure_left = TERMINALS;
                }
                let terminal = self.departure_cursor;
                self.departure_cursor = (terminal + 1) % TERMINALS;
                self.departure_left -= 1;
                self.select(terminal);
                self.departure();
                if self.departure_left != 0 {
                    self.tell_place(DEPARTURES);
                }
            }
            (Source::Session, DRIVER_IN) => {
                rt::service::step_own();
                let _ = self.pull();
            }
            (Source::Session, DRIVER_ROOM) => {
                rt::service::step_own();
                if n.bits & 1 != 0 {
                    self.pump.room_came();
                }
                self.push();
            }
            (Source::Session, STEP) => {
                rt::service::step_own();
                self.step_told = false;
                self.work();
            }
            (Source::Timer, TIMER) => {
                rt::service::step_own();
                self.armed = None;
                let ops = &mut *self.ops;
                for device in self.devices.iter_mut() {
                    device.readers.expire(now(), |w| ops.tell(w.label, w.key));
                }
                self.arm_timer();
            }
            _ => self.due(),
        }
    }
}
