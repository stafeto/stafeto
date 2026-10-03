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
    BAD_TERMINAL, CONSOLE, Cancel, Control, Drain, FLOW_IN_OFF, FLOW_IN_ON, FLOW_OUT_OFF,
    FLOW_OUT_ON, FLUSH, INVALID, MAX_READ, Method, NO_IDENTITY, OWN, PERMISSION, QUEUE_BOTH,
    QUEUE_IN, QUEUE_OUT, Read, SetAttr, VERSION, VSTART, VSTOP, WAITERS, Write,
};
use proto_uart::{ReadKey, ReadRequest, RoomReply, WriteReply, WriteRequest};
use proto_wire::clones::Clones;
use proto_wire::{Status, Writer, long};
use rt::abi::{Error, MESSAGE_MAX, Rights, Source};
use rt::handle::{Channel, Handle, Memory, Outgoing, Process, Timer};
use rt::service::{
    Answer, Config, Heartbeat, LongOps, LongSession, Notice, Request, Service, Session,
};
use rt::{sys, time};
use tty::discipline::{self, Signal, Terminal};
use tty::jobs::{self, Caller, Jobs};
use tty::{Driver, Pump, Pumped, Waiter, Waiters};

rt::entry!(main);

/// The sessions: room for the 255 records of the process service and the
/// services beside them, as the pipe service has.
const SESSIONS: usize = 320;
/// The clones the service keeps alive at most.
const CLONES: usize = 320;
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
}

/// What the process service said of a session's process: the index of
/// its record, its PID, and the generation of its credentials then, which
/// moves when the record goes or execs.
#[derive(Clone, Copy)]
struct Who {
    index: usize,
    pid: u32,
    generation: u64,
}

/// Where the service maps the page of the generations (proto_process
/// Register), read-only.
const GENERATIONS_AT: usize = 0x41_0000_0000;

/// The tables of the sessions and long operations and the console's
/// discipline, in `.bss`: too big for the stack.
struct Tables {
    sessions: [Option<Session<Client, 0>>; SESSIONS],
    ops: LongOps<OPERATIONS>,
    clones: Clones<CLONES>,
    console: Terminal,
}
struct Bss(UnsafeCell<Tables>);
// SAFETY: only the main thread reaches it, once (`main`).
unsafe impl Sync for Bss {}
static TABLES: Bss = Bss(UnsafeCell::new(Tables {
    sessions: [const { None }; SESSIONS],
    ops: LongOps::new(),
    clones: Clones::new(),
    console: Terminal::new(),
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
        given: 0,
        clones: &mut tables.clones,
        ops: &mut tables.ops,
        driver,
        room_given: false,
        console: &mut tables.console,
        pump: Pump::new(),
        input: Input::Idle,
        readers: Waiters::new(),
        writers: Waiters::new(),
        drainers: Waiters::new(),
        timer,
        _view: view,
        armed: None,
        step,
        step_told: false,
        step_due: false,
        process: Handle::borrowed(start.process.raw()),
        notary: None,
        generations: None,
        jobs: Jobs::new(),
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &start.parent,
            period_ns: args.map_or(0, |args| args.period_ns),
            priority: level,
        }),
    };
    let _ = service.pull();
    rt::println!("tty: ready");
    #[cfg(feature = "steps")]
    rt::service::report_steps(5);
    let _ = rt::service::run_in(&channel, &mut service, config, &mut tables.sessions);
    STOPPED
}

/// What a long operation that waits is.
#[derive(Clone, Copy)]
enum Wait {
    /// A read, with the deadline of its VTIME.
    Read(Option<u64>),
    Write,
    Drain,
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
    given: u64,
    clones: &'static mut Clones<CLONES>,
    ops: &'static mut LongOps<OPERATIONS>,
    /// The session with the console's driver, and whether it keeps the
    /// handle of ROOM.
    driver: Handle<Channel>,
    room_given: bool,
    console: &'static mut Terminal,
    pump: Pump,
    input: Input,
    readers: Waiters<WAITERS>,
    writers: Waiters<WAITERS>,
    /// The drains (tcdrain) that wait for the output to go.
    drainers: Waiters<WAITERS>,
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
    /// The console as a controlling terminal (5f, T3).
    jobs: Jobs,
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
        self.pump.room_came();
        self.input = Input::Idle;
    }

    /// Output to the driver: WRITES messages at most, then the writers
    /// hear of room; the next step goes on with what is left.
    fn push(&mut self) {
        let mut port = Port {
            driver: &self.driver,
            channel: &self.channel,
            level: self.level,
            room_given: &mut self.room_given,
        };
        match self.pump.run(self.console, &mut port, WRITES) {
            Ok(Pumped::More) => self.kick(),
            Ok(Pumped::Idle | Pumped::WaitsRoom) => {}
            Err(_) => {
                self.reconnect();
                self.kick();
            }
        }
        self.tell_output();
    }

    /// The writes that wait hear of room, and the drains of an output that
    /// went.
    fn tell_output(&mut self) {
        if self.console.writable() {
            for w in self.writers.iter() {
                self.ops.tell(w.label, w.key);
            }
        }
        if self.console.output_len() == 0 {
            for d in self.drainers.iter() {
                self.ops.tell(d.label, d.key);
            }
        }
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
        self.console.input(&bytes[..n], now());
        let mut signals = [None; 3];
        for (place, signal) in signals.iter_mut().zip(self.console.take_signals()) {
            *place = Some(signal);
        }
        for signal in signals.into_iter().flatten() {
            let (name, number) = match signal {
                Signal::Interrupt => ("SIGINT", SIGINT),
                Signal::Quit => ("SIGQUIT", SIGQUIT),
                Signal::Suspend => ("SIGTSTP", SIGTSTP),
            };
            match self.jobs.foreground() {
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
        for reader in self.readers.iter() {
            self.ops.tell(reader.label, reader.key);
        }
    }

    /// The timer of VTIME at the earliest deadline of the reads that wait.
    fn arm_timer(&mut self) {
        let deadline = self.readers.deadline();
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
    fn notify_of(r: &mut Request<'_>, take: bool) -> Result<Option<Handle<Channel>>, Answer> {
        if !take || r.handles.is_empty() {
            return Ok(None);
        }
        r.handles
            .take::<Channel>(0)
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
        notify: Option<Handle<Channel>>,
    ) -> Answer {
        let label = s.label();
        let reader = match kind {
            Wait::Read(deadline) => Some(deadline),
            Wait::Write | Wait::Drain => None,
        };
        match key {
            None => {
                let list = match kind {
                    Wait::Read(_) => &mut self.readers,
                    Wait::Write => &mut self.writers,
                    Wait::Drain => &mut self.drainers,
                };
                if list.len() == WAITERS {
                    return Answer::Status(Status::Kernel(Error::LimitReached));
                }
                let key = match self.ops.start(&mut s.data.long, label) {
                    Ok(key) => key,
                    Err(e) => return Answer::Status(Status::Kernel(e)),
                };
                list.add(Waiter {
                    label,
                    key,
                    started: now(),
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
                    && let Some(waiter) = self.readers.find(label, key)
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
            self.readers.remove(label, key);
            self.writers.remove(label, key);
            self.drainers.remove(label, key);
            self.arm_timer();
        }
    }

    /// READ_START (`take` false) or READ_TAKE.
    fn read(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>, take: bool) -> Answer {
        let read = match Read::parse(r.body(), take) {
            Ok(read) => read,
            Err(status) => return Answer::Status(status),
        };
        let notify = match Self::notify_of(r, take) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if read.terminal != CONSOLE {
            return status(BAD_TERMINAL);
        }
        let at = now();
        let started = match read.key {
            Some(key) => match self.readers.find(s.label(), key) {
                Some(waiter) => waiter.started,
                None => return Answer::Status(Status::Kernel(Error::BadState)),
            },
            None => at,
        };
        let mut out = [0; MAX_READ];
        match self
            .console
            .read(&mut out[..read.count as usize], started, at)
        {
            discipline::Read::Ready(n) => {
                self.finish(s, read.key);
                long_answer(r, long::Reply::Ready(&out[..n]))
            }
            discipline::Read::Wait(deadline) => {
                self.wait(s, r, read.key, Wait::Read(deadline), notify)
            }
        }
    }

    /// WRITE_START (`take` false) or WRITE_TAKE.
    fn write(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>, take: bool) -> Answer {
        let write = match Write::parse(r.body(), take) {
            Ok(write) => write,
            Err(status) => return Answer::Status(status),
        };
        let notify = match Self::notify_of(r, take) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if write.terminal != CONSOLE {
            return status(BAD_TERMINAL);
        }
        if let Some(key) = write.key
            && self.writers.find(s.label(), key).is_none()
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let part = &write.bytes[..write.bytes.len().min(WRITE_STEP)];
        let n = self.console.write(part);
        if n == 0 {
            return self.wait(s, r, write.key, Wait::Write, notify);
        }
        self.finish(s, write.key);
        // The output goes to the driver in the next step.
        self.kick();
        long_answer(r, long::Reply::Ready(&(n as u32).to_le_bytes()))
    }

    /// DRAIN_START (`take` false) or DRAIN_TAKE: READY once no output is
    /// left for the driver.
    fn drain(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>, take: bool) -> Answer {
        let drain = match Drain::parse(r.body(), take) {
            Ok(drain) => drain,
            Err(status) => return Answer::Status(status),
        };
        let notify = match Self::notify_of(r, take) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if drain.terminal != CONSOLE {
            return status(BAD_TERMINAL);
        }
        if let Some(key) = drain.key
            && self.drainers.find(s.label(), key).is_none()
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        if self.console.output_len() == 0 {
            self.finish(s, drain.key);
            return long_answer(r, long::Reply::Ready(&[]));
        }
        // The output goes to the driver in the step, which tells the drain.
        self.kick();
        self.wait(s, r, drain.key, Wait::Drain, notify)
    }

    /// READ_CANCEL, WRITE_CANCEL or DRAIN_CANCEL: the operation goes, with
    /// no effect.
    fn cancel(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let cancel = match Cancel::parse(r.body()) {
            Ok(cancel) => cancel,
            Err(status) => return Answer::Status(status),
        };
        if !self.ops.waits(s.label(), cancel.key) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        self.finish(s, Some(cancel.key));
        long_answer(r, long::Reply::Cancelled)
    }

    /// CLONE: a session of the service's own label for a child of the
    /// client.
    fn clone_session(&mut self, root: u64, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        if self.clones.room_within(root, ROOT_CLONES).is_err() {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        }
        self.given += 1;
        let label = OWN | self.given;
        let rights = Rights::SEND | Rights::TRANSFER;
        // Below the service's own places, so that input overtakes the
        // requests of the clones too.
        let priority = self.level.saturating_sub(1).max(1);
        match sys::handle_label(&self.channel, rights, label, priority) {
            Ok(session) => {
                if r.reply().u32(0).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                let _ = self.clones.add_within(label, root, ROOT_CLONES);
                Answer::Reply([session.erase()].into())
            }
            Err(e) => Answer::Status(Status::Kernel(e)),
        }
    }

    /// GET_ATTR: the settings of the terminal.
    fn get_attr(&mut self, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let terminal = match body.u32().and_then(|t| body.finish().map(|()| t)) {
            Ok(terminal) => terminal,
            Err(status) => return Answer::Status(status),
        };
        if terminal != CONSOLE {
            return status(BAD_TERMINAL);
        }
        let termios = *self.console.termios();
        let w = r.reply();
        if w.u32(0).is_err() || termios.write(w).is_err() {
            return Answer::Status(Status::BadSize);
        }
        Answer::Reply(Outgoing::new())
    }

    /// FLUSH_QUEUES: the input not read, or the output the driver did not
    /// take, goes.
    fn flush_queues(&mut self, r: &mut Request<'_>) -> Answer {
        let control = match Control::parse(r.body()) {
            Ok(control) => control,
            Err(status) => return Answer::Status(status),
        };
        if control.terminal != CONSOLE {
            return status(BAD_TERMINAL);
        }
        if !matches!(control.word, QUEUE_IN | QUEUE_OUT | QUEUE_BOTH) {
            return status(INVALID);
        }
        if control.word != QUEUE_OUT {
            self.console.flush_input();
            self.tell_readers();
        }
        if control.word != QUEUE_IN {
            self.console.flush_output();
            self.tell_output();
        }
        Answer::Status(Status::Ok)
    }

    /// FLOW: the output stops or goes on, or the STOP or START character
    /// goes out.
    fn flow(&mut self, r: &mut Request<'_>) -> Answer {
        let control = match Control::parse(r.body()) {
            Ok(control) => control,
            Err(status) => return Answer::Status(status),
        };
        if control.terminal != CONSOLE {
            return status(BAD_TERMINAL);
        }
        match control.word {
            FLOW_OUT_OFF => self.console.set_stopped(true),
            FLOW_OUT_ON => {
                self.console.set_stopped(false);
                self.kick();
            }
            FLOW_IN_OFF | FLOW_IN_ON => {
                let index = if control.word == FLOW_IN_OFF {
                    VSTOP
                } else {
                    VSTART
                };
                self.console.send_control(index);
                self.kick();
            }
            _ => return status(INVALID),
        }
        Answer::Status(Status::Ok)
    }

    /// SET_ATTR: new settings at once (DRAIN as NOW, FLUSH dropping the
    /// input not read); the reads that wait look again.
    fn set_attr(&mut self, r: &mut Request<'_>) -> Answer {
        let set = match SetAttr::parse(r.body()) {
            Ok(set) => set,
            Err(status) => return Answer::Status(status),
        };
        if set.terminal != CONSOLE {
            return status(BAD_TERMINAL);
        }
        if set.action > FLUSH {
            return status(INVALID);
        }
        self.console.set_termios(set.termios, set.action == FLUSH);
        self.tell_readers();
        Answer::Status(Status::Ok)
    }
}

/// The numbers of the signals of the terminal (Linux's).
const SIGINT: u32 = 2;
const SIGQUIT: u32 = 3;
const SIGTSTP: u32 = 20;

impl Tty {
    /// The notary session and the page of the generations, asked for once
    /// (none in an image without the process service).
    fn notary(&mut self) -> Option<&Handle<Channel>> {
        if self.notary.is_none() {
            self.notary = rt::service::connect(&self.parent, "posix").ok();
        }
        let notary = self.notary.as_ref()?;
        if self.generations.is_none() {
            let request = proto_process::Method::Register.header().bytes();
            let mut reply = sys::send(notary, &request).ok()?;
            let mut buffer = [0; MESSAGE_MAX];
            if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
                return None;
            }
            let memory = reply.handles.take::<Memory>(0).ok()?;
            let access = rt::abi::Access::Read;
            sys::mem_map(&self.process, &memory, 0, 4096, GENERATIONS_AT, access).ok()?;
            self.generations = Some(memory);
        }
        self.notary.as_ref()
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
    fn caller(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Result<Caller, u32> {
        let offered = if r.handles.is_empty() {
            None
        } else {
            r.handles.take::<Channel>(0).ok()
        };
        self.notary().ok_or(NO_IDENTITY)?;
        let current = s
            .data
            .who
            .filter(|w| self.word(w.index * 8) == w.generation);
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
                if said.loader.is_some() {
                    return Err(NO_IDENTITY);
                }
                Who {
                    index: said.index as usize,
                    pid: said.pid,
                    generation: said.generation,
                }
            }
            (None, None) => return Err(NO_IDENTITY),
        };
        s.data.who = Some(who);
        let word = self.word(proto_process::GROUPS_AT + who.index * 8);
        let (pgid, sid) = proto_process::groups_of(word).ok_or(NO_IDENTITY)?;
        Ok(Caller {
            pid: who.pid,
            pgid,
            sid,
        })
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
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        if terminal != CONSOLE {
            return status(BAD_TERMINAL);
        }
        let caller = match self.caller(s, r) {
            Ok(caller) => caller,
            Err(code) => return status(code),
        };
        let result = match method {
            Method::Acquire => self.acquire(caller).map(|()| None),
            Method::SetPgrp => {
                let in_session = |pgid, sid| {
                    jobs::group_in_session(
                        proto_process::RECORDS,
                        |i| self.word(proto_process::GROUPS_AT + i * 8),
                        pgid,
                        sid,
                    )
                };
                let mut jobs = self.jobs;
                let set = jobs.set_foreground(caller, group, in_session);
                self.jobs = jobs;
                set.map(|()| None)
            }
            Method::GetPgrp => self.jobs.get_foreground(caller).map(Some),
            Method::GetSid => self.jobs.get_session(caller).map(Some),
            _ => self.jobs.controlling(caller).map(|()| None),
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

    /// ACQUIRE: the process service gives the console to the caller's
    /// session (SetCtty), unless the session has it already.
    fn acquire(&mut self, caller: Caller) -> Result<(), u32> {
        if !self.jobs.may_acquire(caller)? {
            return Ok(());
        }
        let notary = self.notary().ok_or(PERMISSION)?;
        let mut w = Writer::new();
        let written = proto_process::Method::SetCtty
            .header()
            .write(&mut w)
            .and_then(|()| w.u32(CONSOLE))
            .and_then(|()| w.u32(caller.sid));
        if written.is_err() {
            return Err(PERMISSION);
        }
        let reply = sys::send(notary, w.as_bytes()).map_err(|_| PERMISSION)?;
        let mut buffer = [0; MESSAGE_MAX];
        if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
            return Err(PERMISSION);
        }
        self.jobs.acquired(caller);
        Ok(())
    }

    /// The signal `number` of INTR, QUIT or SUSP to the foreground group
    /// `group` (XBD 11.1.9): the process service walks the group
    /// (TtySignal) and answers at the walk's end. A group of a session
    /// the console is no longer the controlling terminal of gets none.
    fn signal_group(&mut self, group: u32, number: u32) {
        let Some(notary) = self.notary() else {
            return;
        };
        let mut w = Writer::new();
        let written = proto_process::Method::TtySignal
            .header()
            .write(&mut w)
            .and_then(|()| w.u32(CONSOLE))
            .and_then(|()| w.u32(group))
            .and_then(|()| w.u32(number));
        if written.is_err() {
            return;
        }
        let Ok(reply) = sys::send(notary, w.as_bytes()) else {
            return;
        };
        let mut buffer = [0; MESSAGE_MAX];
        let code = proto_wire::Reader::new(reply.bytes(&mut buffer))
            .u32()
            .unwrap_or(0);
        if code == proto_process::PERMISSION {
            // The session's leader ended: the console is no session's.
            self.jobs.release();
        }
    }
}

impl Service<0> for Tty {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = proto_tty::METHODS;
    type Data = Client;

    fn request(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        self.due();
        if s.data.root == 0 {
            let label = r.label();
            s.data.root = self.clones.client_of(label).unwrap_or(label);
        }
        match Method::from_number(r.method()) {
            Some(Method::ReadStart) => self.read(s, r, false),
            Some(Method::ReadTake) => self.read(s, r, true),
            Some(Method::WriteStart) => self.write(s, r, false),
            Some(Method::WriteTake) => self.write(s, r, true),
            Some(Method::DrainStart) => self.drain(s, r, false),
            Some(Method::DrainTake) => self.drain(s, r, true),
            Some(Method::FlushQueues) => self.flush_queues(r),
            Some(Method::Flow) => self.flow(r),
            Some(Method::ReadCancel | Method::WriteCancel | Method::DrainCancel) => {
                self.cancel(s, r)
            }
            Some(Method::Clone) => self.clone_session(s.data.root, r),
            Some(Method::GetAttr) => self.get_attr(r),
            Some(Method::SetAttr) => self.set_attr(r),
            Some(
                m @ (Method::Acquire
                | Method::SetPgrp
                | Method::GetPgrp
                | Method::GetSid
                | Method::Controlling),
            ) => self.job(s, r, m),
            Some(Method::Abandon) => {
                if r.body().finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                self.gone(s);
                Answer::Status(Status::Ok)
            }
            None => Answer::Status(Status::UnknownMethod),
        }
    }

    /// The client of `s` went, or abandoned its operations: they go.
    fn gone(&mut self, s: &mut Session<Client, 0>) {
        let label = s.label();
        self.ops.gone(&mut s.data.long);
        self.readers.remove_all(label);
        self.writers.remove_all(label);
        self.drainers.remove_all(label);
        self.arm_timer();
    }

    /// The last copy of a session CLONE gave went.
    fn closed(&mut self, label: u64) {
        self.clones.gone(label);
    }

    /// The driver's input (DRIVER_IN) and room (DRIVER_ROOM), the step of
    /// the work left (STEP), and the timer of VTIME.
    fn notification(&mut self, n: Notice) {
        match (n.source, n.label) {
            (Source::Session, DRIVER_IN) => {
                rt::service::step_own();
                let _ = self.pull();
            }
            (Source::Session, DRIVER_ROOM) => {
                rt::service::step_own();
                self.pump.room_came();
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
                self.readers.expire(now(), |w| ops.tell(w.label, w.key));
                self.arm_timer();
            }
            _ => self.due(),
        }
    }
}
