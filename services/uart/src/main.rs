// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The driver of the PL011, the console's port (spec 13.5): a service at
//! 60 in one thread (rt::service), which init gives `console` and `log`
//! in its start data and the window `regs` over the port and the binding
//! `irq` of its level-triggered line in the reply to its REGISTER. It sets
//! the PL011 up, serves its interrupts and WRITE and READ of proto_uart
//! (CRASH too with the feature `crash`), and shows the kernel log: at its
//! start, on a timer of its own every LOG_PERIOD_NS, and at once again
//! while the kernel says records are left. What it decides comes from the
//! library (uart::irq, output, writes, input, log); here are the calls and
//! the registers, which it reaches through rt::mmio alone [G34]. The
//! program ends with a code of its own when its start fails; init
//! restarts it.

#![no_std]
#![no_main]

use abi::time::next_release;
use abi::{Access, Error, LOG_BATCH, LOG_RECORD, Source};
use core::cell::UnsafeCell;
use core::fmt::{self, Write};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
use proto_init::ServiceArgs;
use proto_uart::{
    Method, ReadKey, ReadReply, ReadRequest, RoomReply, VERSION, WriteReply, WriteRequest,
};
use proto_wire::clones::Clones;
use proto_wire::{Status, Writer, long};
use rt::handle::{Channel, Interrupt, Memory, Outgoing, Resource, Timer};
use rt::service::{Answer, Config, Heartbeat, Notice, Pending, Request, Service, Session};
use rt::{Handle, mmio, sys, time};
use uart::input::{self, Input, RX_RING};
use uart::irq::{self, Irq, RX_PASS};
use uart::output::Output;
use uart::regs::{
    ALL, CR, CR_ON, DR, FR, FR_BUSY, FR_RXFE, FR_TXFF, ICR, IFLS, IFLS_HALF, IMSC, LCR_H,
    LCR_H_FEN, LCR_H_WLEN_8, MIS,
};
use uart::writes::{self, Armed, Rooms, Writes};

rt::entry!(main);

/// Where the driver maps its window over the PL011.
const REGS_AT: usize = 0x10_0000_0000;
const PAGE: u64 = 4096;
/// The period of the reads of the kernel log.
const LOG_PERIOD_NS: u64 = 50_000_000;
/// The label of the copy of the driver's channel its timer posts through.
const TIMER_LABEL: u64 = 1;
/// How long the driver waits for the transmitter to go idle before it
/// sets the PL011 up: the kernel wrote to the port until the window came.
const IDLE_NS: u64 = 10_000_000;
/// The priority of the slot of label 0 of the driver's channel: no handle
/// without a label notifies it.
const CHANNEL_PRIORITY: u8 = 1;
/// The sessions of the driver's channel, and what each holds at most.
const SESSIONS: usize = 8;
/// The clones the service keeps alive at most, for all its clients: room
/// for the 32 children of rtbench's S12 and the probes beside them, as the
/// RAM file service's 128.
const CLONES: usize = 128;
const HELD: usize = 2;
/// Batches of the kernel log one read takes in a row at most, while each
/// goes out whole at once: the whole ring of the kernel.
const LOG_BATCHES: usize = 64 / LOG_BATCH + 1;

/// The codes of a start that failed: the start data, `log` among them;
/// REGISTER, the window or the binding; the map of the window; the loop.
const NO_START_DATA: u64 = 1;
const NO_LOG: u64 = 2;
const NOT_REGISTERED: u64 = 3;
const NOT_MAPPED: u64 = 4;
const STOPPED: u64 = 5;

/// What the driver keeps in its data segment (spec 13.5): the rings of
/// output and input, the writes that wait, the clients of ROOM, a batch of
/// the kernel log and the bytes of a reply to READ.
struct State {
    output: Output,
    writes: Writes<Pending>,
    rooms: Rooms<Handle<Channel>>,
    input: Input<Pending, Handle<Channel>>,
    records: [[u8; LOG_RECORD]; LOG_BATCH],
    read: [u8; RX_RING],
}

struct Cell(UnsafeCell<MaybeUninit<State>>);

// SAFETY: `state` gives the state out once, to the driver's one thread.
unsafe impl Sync for Cell {}

/// The state (spec 13.5), uninitialised until `state` fills it: in .bss,
/// with none of its bytes in the program's file.
static STATE: Cell = Cell(UnsafeCell::new(MaybeUninit::uninit()));
static TAKEN: AtomicBool = AtomicBool::new(false);

/// The table of the clones, outside the loop's stack: about 2.9 K bytes of
/// places and roots, with no guard page below the stack.
struct CloneTable(UnsafeCell<Clones<CLONES>>);

// SAFETY: only the main thread reaches it, once.
unsafe impl Sync for CloneTable {}

static CLONE_TABLE: CloneTable = CloneTable(UnsafeCell::new(Clones::new()));

/// The state, empty, at the first call only.
fn state() -> Option<&'static mut State> {
    if TAKEN.swap(true, Ordering::Relaxed) {
        return None;
    }
    // SAFETY: TAKEN lets one call through, and nothing else reaches STATE.
    let place = unsafe { &mut *STATE.0.get() };
    Some(place.write(State {
        output: Output::new(),
        writes: Writes::new(),
        rooms: Rooms::new(),
        input: Input::new(),
        records: [[0; LOG_RECORD]; LOG_BATCH],
        read: [0; RX_RING],
    }))
}

/// The registers of the PL011 through the window mapped at its base.
struct Regs(usize);

impl Regs {
    fn read(&self, reg: usize) -> u32 {
        // SAFETY: the window maps the PL011's page at self.0, readable and
        // writable, as device memory; `reg` is the offset of a 32-bit
        // register of uart::regs.
        unsafe { mmio::read32(self.0 + reg) }
    }

    fn write(&self, reg: usize, value: u32) {
        // SAFETY: as for `read`.
        unsafe { mmio::write32(self.0 + reg, value) }
    }
}

fn main(_: u64) -> u64 {
    let Ok(mut s) = rt::startup() else {
        return NO_START_DATA;
    };
    if let Ok(console) = s.take::<Resource>("console") {
        rt::console::set(console);
    }
    let Ok(log) = s.take::<Resource>("log") else {
        return NO_LOG;
    };
    let Some(state) = state() else {
        return NO_START_DATA;
    };
    let args = ServiceArgs::read(s.args()).ok();
    let level = sys::thread_info(&s.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(CHANNEL_PRIORITY) else {
        return NOT_REGISTERED;
    };
    let Ok(mut got) = rt::service::register(&s.parent, &channel) else {
        return NOT_REGISTERED;
    };
    let (Ok(window), Ok(irq)) = (got.take::<Memory>("regs"), got.take::<Interrupt>("irq")) else {
        return NOT_REGISTERED;
    };
    if sys::mem_map(&s.process, &window, 0, PAGE, REGS_AT, Access::ReadWrite).is_err() {
        return NOT_MAPPED;
    }
    let Ok(view) = sys::handle_label(&channel, abi::Rights::RECEIVE, TIMER_LABEL, level) else {
        return NOT_REGISTERED;
    };
    let Ok(timer) = sys::timer_create(&view, level) else {
        return NOT_REGISTERED;
    };
    let mut uart = Uart {
        channel: Handle::borrowed(channel.raw()),
        level,
        // SAFETY: only the main thread reaches CLONE_TABLE, here once.
        clones: unsafe { &mut *CLONE_TABLE.0.get() },
        regs: Regs(REGS_AT),
        irq,
        log,
        timer,
        _view: view,
        t0: time::ticks_to_ns(time::now()),
        deadline: 0,
        left: 0,
        irqs: Irq::new(),
        state,
    };
    uart.set_up();
    uart.take_log();
    uart.arm();
    let base = args
        .and_then(|a| a.own.get(..8))
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes);
    let line = sys::irq_info(&uart.irq).map_or(0, |info| info.line);
    uart.say(format_args!("uart: pl011 at {base:#x}, line {line}\n"));
    let heartbeat = Heartbeat {
        to: &s.parent,
        period_ns: args.map_or(0, |a| a.period_ns),
        priority: level,
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(heartbeat),
    };
    let _ = rt::service::run::<Uart, SESSIONS, HELD>(&channel, &mut uart, config);
    STOPPED
}

/// The driver: the registers, the binding of the line, `log`, the timer
/// of the reads of the log, the copy of IMSC and the state.
struct Uart {
    /// The driver's channel, which the sessions of CLONE are copies of,
    /// the level of its loop, and how many it gave.
    channel: core::mem::ManuallyDrop<Handle<Channel>>,
    level: u8,
    /// The sessions CLONE gave that live, bounded for each client.
    clones: &'static mut Clones<CLONES>,
    regs: Regs,
    irq: Handle<Interrupt>,
    log: Handle<Resource>,
    timer: Handle<Timer>,
    /// The copy of the channel with RECEIVE the timer posts through, with
    /// TIMER_LABEL: it lives as long as the timer.
    _view: Handle<Channel>,
    /// The timer fires at t0 + k * LOG_PERIOD_NS; `deadline` is the next.
    t0: u64,
    deadline: u64,
    /// The records of the kernel log left after the last batch.
    left: u64,
    irqs: Irq,
    state: &'static mut State,
}

impl Uart {
    /// Sets the PL011 up (spec 13.5): waits up to IDLE_NS for the
    /// transmitter, turns the UART off, the FIFOs on with words of 8 bits,
    /// both levels at half, clears every interrupt, reads what the receive
    /// FIFO holds into the ring (its interrupt comes again only once the
    /// FIFO was empty), lets input out, turns the UART on and reads IMSC
    /// back, then opens the line (irq_ack). The divisors of the rate stay
    /// as the firmware left them.
    fn set_up(&mut self) {
        let regs = &self.regs;
        let until = time::now().saturating_add(time::ns_to_ticks(IDLE_NS));
        while regs.read(FR) & FR_BUSY != 0 && time::now() < until {}
        regs.write(CR, 0);
        regs.write(LCR_H, LCR_H_FEN | LCR_H_WLEN_8);
        regs.write(IFLS, IFLS_HALF);
        regs.write(ICR, ALL);
        let input = &mut self.state.input;
        let limit = RX_PASS.min(input.room());
        irq::receive(
            limit,
            || regs.read(FR) & FR_RXFE != 0,
            || regs.read(DR),
            input,
        );
        regs.write(IMSC, self.irqs.imsc());
        regs.write(CR, CR_ON);
        regs.read(IMSC);
        // The binding lives as long as the driver.
        let _ = sys::irq_ack(&self.irq);
    }

    /// Formats a line of the driver into its output, the way the clients'
    /// bytes go, and starts it.
    fn say(&mut self, args: fmt::Arguments<'_>) {
        let mut line = Line {
            bytes: [0; LINE_MAX],
            len: 0,
        };
        // A line cut at LINE_MAX still goes.
        let _ = line.write_fmt(args);
        let _ = self.state.output.put(&line.bytes[..line.len]);
        self.kick();
    }

    /// Starts output after bytes came into it outside a pass (spec 13.5):
    /// the writes that wait go into the ring as room allows, and while the
    /// transmit interrupt is masked the driver writes the first bytes to
    /// the FIFO itself, since the interrupt comes only as the FIFO drains,
    /// and lets it out while bytes wait (Irq::start).
    fn kick(&mut self) {
        self.flush();
        let regs = &self.regs;
        let output = &mut self.state.output;
        let tx_full = || regs.read(FR) & FR_TXFF != 0;
        if let Some(imsc) = self
            .irqs
            .start(output, tx_full, |b| regs.write(DR, u32::from(b)))
        {
            regs.write(IMSC, imsc);
            regs.read(IMSC);
        }
    }

    /// The writes that wait go into the ring in their order while they
    /// fit; each that went gets its reply; the clients of ROOM hear of room
    /// once there is.
    fn flush(&mut self) {
        let State {
            output,
            writes,
            rooms,
            ..
        } = &mut *self.state;
        writes.flush(output, answer_write);
        rooms.to_tell(writes.roomy(output), |notify| {
            // A client that went closed it: nothing to tell then.
            let _ = sys::notify(notify, 1);
        });
    }

    /// An interrupt of the line (spec 9, 13.5): the kernel masked it at
    /// delivery. Reads MIS; reads the receive FIFO into the ring, which
    /// clears input, and answers a read that waits; writes up to TX_PASS
    /// bytes; answers the writes that fit and takes the next batch of the
    /// log once the last went; then ICR and IMSC as Irq::end decides (never
    /// input in ICR), IMSC read back so that the writes reached the device
    /// [G34], and irq_ack.
    fn interrupt(&mut self) {
        let regs = &self.regs;
        let mis = regs.read(MIS);
        let State { output, input, .. } = &mut *self.state;
        let limit = self.irqs.receive_limit(mis, input.room());
        irq::receive(
            limit,
            || regs.read(FR) & FR_RXFE != 0,
            || regs.read(DR),
            input,
        );
        let limit = self.irqs.transmit_limit(mis);
        irq::transmit(
            limit,
            || regs.read(FR) & FR_TXFF != 0,
            |b| regs.write(DR, u32::from(b)),
            output,
        );
        self.answer_read();
        self.tell();
        self.flush();
        if self.left > 0 {
            self.take_log();
        }
        let State { output, input, .. } = &mut *self.state;
        let end = self.irqs.end(mis, input.is_full(), output.is_idle());
        self.regs.write(ICR, end.icr);
        self.regs.write(IMSC, end.imsc);
        self.regs.read(IMSC);
        // The binding lives as long as the driver.
        let _ = sys::irq_ack(&self.irq);
    }

    /// The read that waits gets what came.
    fn answer_read(&mut self) {
        let State { input, read, .. } = &mut *self.state;
        if let Some((pending, n)) = input.answer(read)
            && !answer_read(pending, &read[..n])
        {
            input.restore(&read[..n]);
        }
    }

    /// Takes batches of the kernel log into the output (spec 13.5, 16.3)
    /// once the last went out whole, and starts them: one, and the next
    /// at once while records are left and each went out whole in its
    /// start, LOG_BATCHES at most.
    fn take_log(&mut self) {
        for _ in 0..LOG_BATCHES {
            let State {
                output, records, ..
            } = &mut *self.state;
            if !output.log_done() {
                return;
            }
            let Ok(batch) = sys::log_take(&self.log, records) else {
                return;
            };
            self.left = batch.left;
            uart::log::text(records, batch, |bytes| {
                // A batch fits: twelve records and the line of those lost.
                let _ = output.put_log(bytes);
            });
            self.kick();
            if self.left == 0 {
                return;
            }
        }
    }

    /// Arms the timer at the first deadline t0 + k * LOG_PERIOD_NS after
    /// now (spec 10): those that passed are not made up.
    fn arm(&mut self) {
        let now = time::ticks_to_ns(time::now());
        self.deadline = next_release(self.t0, LOG_PERIOD_NS, now);
        // The driver's own timer: timer_set has no error to give.
        let _ = sys::timer_set(&self.timer, self.deadline);
    }

    /// WRITE (spec 13.5, 13.8): the bytes go into the ring whole and the
    /// reply goes at once, or they wait whole for room (Writes::write); a
    /// fifth write that would wait gets LIMIT_REACHED.
    fn write(&mut self, r: &mut Request<'_>) -> Answer {
        let bytes = match WriteRequest::read(r.body()) {
            Ok(request) => request.bytes,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        let Some(pending) = r.defer() else {
            return Answer::Deferred;
        };
        let State { output, writes, .. } = &mut *self.state;
        match writes.write(output, label, bytes, pending) {
            writes::Taken::Now(n, pending) => answer_write(pending, n),
            writes::Taken::Waits => {}
            writes::Taken::Full(pending) => refuse(pending, Error::LimitReached),
        }
        self.kick();
        Answer::Deferred
    }

    /// WRITE_SOME (5f): the part of the bytes that fits goes into the ring,
    /// and the reply goes at once with its count.
    fn write_some(&mut self, r: &mut Request<'_>) -> Answer {
        let bytes = match WriteRequest::read(r.body()) {
            Ok(request) => request.bytes,
            Err(status) => return Answer::Status(status),
        };
        let State { output, writes, .. } = &mut *self.state;
        let n = writes.write_some(output, bytes);
        let reply = WriteReply { written: n as u32 }.write(r.reply());
        self.kick();
        match reply {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }

    /// ROOM (5f): the room of the ring, and the notification armed below
    /// ROOM_MARK, through the handle the client's first ROOM brought.
    fn room(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || r.handles.len() > 1 {
            return Answer::Status(Status::BadSize);
        }
        let notify = if r.handles.is_empty() {
            None
        } else {
            match r.handles.take::<Channel>(0) {
                Ok(handle) => Some(handle),
                Err(error) => return Answer::Status(Status::Kernel(error)),
            }
        };
        let label = r.label();
        let State {
            output,
            writes,
            rooms,
            ..
        } = &mut *self.state;
        let roomy = writes.roomy(output);
        let armed = match rooms.room(label, notify, roomy) {
            Armed::Now => false,
            Armed::Armed => true,
            Armed::Refused => return Answer::Status(Status::Kernel(Error::LimitReached)),
        };
        let room = output.room() as u32;
        match (RoomReply { room, armed }).write(r.reply()) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }

    /// READ (spec 13.5, 13.8): the first client that reads owns the
    /// console; the bytes that came go at once, or the reply waits for
    /// input (Input::read); another client, or a second read that would
    /// wait, gets BAD_STATE. Input masked for a full ring is let out again
    /// once bytes went.
    fn read(&mut self, r: &mut Request<'_>) -> Answer {
        let max = match ReadRequest::read(r.body()) {
            Ok(request) => request.max as usize,
            Err(status) => return Answer::Status(status),
        };
        let label = r.label();
        let Some(pending) = r.defer() else {
            return Answer::Deferred;
        };
        let State { input, read, .. } = &mut *self.state;
        match input.read(label, max, pending, read) {
            input::Taken::Now(n, pending) => {
                if !answer_read(pending, &read[..n]) {
                    input.restore(&read[..n]);
                }
            }
            input::Taken::Waits => {}
            input::Taken::Refused(pending) => refuse(pending, Error::BadState),
        }
        if let Some(imsc) = self.irqs.drained(self.state.input.is_full()) {
            self.regs.write(IMSC, imsc);
            self.regs.read(IMSC);
        }
        Answer::Deferred
    }

    /// READ_START (proto_uart, proto_wire::long): the bytes there are, or
    /// WAIT with the key of the read, which waits holding no reply.
    fn read_start(&mut self, r: &mut Request<'_>) -> Answer {
        let max = match ReadRequest::read(r.body()) {
            Ok(request) => request.max as usize,
            Err(status) => return Answer::Status(status),
        };
        let State { input, read, .. } = &mut *self.state;
        let reply = match input.start(r.label(), max, read) {
            input::Start::Now(n) => long::Reply::Ready(&read[..n]),
            input::Start::Wait(key) => long::Reply::Wait(key),
            input::Start::Refused => return Answer::Status(Status::Kernel(Error::BadState)),
        };
        let answer = long_answer(r, reply);
        if let Some(imsc) = self.irqs.drained(self.state.input.is_full()) {
            self.regs.write(IMSC, imsc);
            self.regs.read(IMSC);
        }
        answer
    }

    /// READ_TAKE and READ_CANCEL: the bytes that came, or ARMED (keeping
    /// the handle with NOTIFY the first READ_TAKE brings), or CANCELLED.
    fn read_take(&mut self, r: &mut Request<'_>, cancel: bool) -> Answer {
        let key = match ReadKey::read(r.body()) {
            Ok(key) => key.key,
            Err(status) => return Answer::Status(status),
        };
        let notify = if cancel || r.handles.is_empty() {
            None
        } else {
            match r.handles.take::<Channel>(0) {
                Ok(handle) => Some(handle),
                Err(error) => return Answer::Status(Status::Kernel(error)),
            }
        };
        let label = r.label();
        let State { input, read, .. } = &mut *self.state;
        let taken = if cancel {
            input.cancel(label, key, read)
        } else {
            input.take(label, key, notify, read)
        };
        let reply = match taken {
            input::Taken2::Ready(n) => long::Reply::Ready(&read[..n]),
            input::Taken2::Armed => long::Reply::Armed,
            input::Taken2::Cancelled => long::Reply::Cancelled,
            input::Taken2::Unknown => return Answer::Status(Status::Kernel(Error::BadState)),
        };
        let answer = long_answer(r, reply);
        if let Some(imsc) = self.irqs.drained(self.state.input.is_full()) {
            self.regs.write(IMSC, imsc);
            self.regs.read(IMSC);
        }
        answer
    }

    /// Tells the waiting read in two steps that input came: bit 0 in its
    /// slot, once.
    fn tell(&mut self) {
        if let Some(notify) = self.state.input.to_tell() {
            // A client that went closed it: nothing to tell then.
            let _ = sys::notify(notify, 1);
        }
    }
}

/// The methods of the driver: CRASH only with the feature `crash`, and
/// the loop answers UNKNOWN_METHOD to it without (spec 13.5).
#[cfg(feature = "crash")]
const METHODS: &[u16] = &[
    Method::Write.number(),
    Method::Read.number(),
    Method::ReadStart.number(),
    Method::ReadTake.number(),
    Method::ReadCancel.number(),
    Method::Clone.number(),
    Method::WriteSome.number(),
    Method::Room.number(),
    Method::Crash.number(),
];
#[cfg(not(feature = "crash"))]
const METHODS: &[u16] = &[
    Method::Write.number(),
    Method::Read.number(),
    Method::ReadStart.number(),
    Method::ReadTake.number(),
    Method::ReadCancel.number(),
    Method::Clone.number(),
    Method::WriteSome.number(),
    Method::Room.number(),
];

impl Service<HELD> for Uart {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = METHODS;
    type Data = ();

    fn request(&mut self, _: &mut Session<(), HELD>, r: &mut Request<'_>) -> Answer {
        match Method::from_number(r.method()) {
            Some(Method::Write) => self.write(r),
            Some(Method::Read) => self.read(r),
            Some(Method::ReadStart) => self.read_start(r),
            Some(Method::ReadTake) => self.read_take(r, false),
            Some(Method::ReadCancel) => self.read_take(r, true),
            Some(Method::Clone) => self.clone_session(r),
            Some(Method::WriteSome) => self.write_some(r),
            Some(Method::Room) => self.room(r),
            #[cfg(feature = "crash")]
            Some(Method::Crash) => crash(r),
            _ => Answer::Status(Status::UnknownMethod),
        }
    }

    /// The client went: its writes that wait leave, its handle of ROOM
    /// goes, and when it owned the console, the console is free and its
    /// read that waits goes.
    fn gone(&mut self, s: &mut Session<(), HELD>) {
        let label = s.label();
        let State {
            writes,
            input,
            rooms,
            ..
        } = &mut *self.state;
        writes.gone(label, drop);
        rooms.gone(label);
        drop(input.gone(label));
    }

    /// The last copy of a session CLONE gave went.
    fn closed(&mut self, label: u64) {
        self.clones.gone(label);
    }

    /// The interrupt of the line, and the timer of the reads of the log:
    /// a stale expiry, before its deadline, changes nothing.
    fn notification(&mut self, n: Notice) {
        match (n.source, n.label) {
            (Source::Interrupt, _) => self.interrupt(),
            (Source::Timer, TIMER_LABEL) if time::reached(self.deadline) => {
                self.take_log();
                self.arm();
            }
            _ => {}
        }
    }
}

impl Uart {
    /// CLONE: a session of the driver's own label (bit 63, which no label
    /// of init has) for a child of the client.
    fn clone_session(&mut self, r: &mut Request<'_>) -> Answer {
        if r.body().finish().is_err() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let Ok(label) = self.clones.give(1 << 63, r.label()) else {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        };
        let rights = abi::Rights::SEND.union(abi::Rights::TRANSFER);
        match sys::handle_label(&self.channel, rights, label, self.level) {
            Ok(session) => {
                if r.reply().u32(0).is_err() {
                    self.clones.gone(label);
                    return Answer::Status(Status::BadSize);
                }
                Answer::Reply([session.erase()].into())
            }
            Err(e) => {
                self.clones.gone(label);
                Answer::Status(Status::Kernel(e))
            }
        }
    }
}

/// CRASH (spec 13.5): BAD_SIZE for a request with a body; otherwise a
/// load from page 0, which nothing maps, ends the driver with a fault
/// while it holds the request: the kernel ends the process alone (spec
/// 7.9), answers the client PEER_CLOSED (spec 6.8) and writes its line of
/// the fault into its log, and init starts the driver again.
#[cfg(feature = "crash")]
fn crash(r: &Request<'_>) -> Answer {
    if r.body().finish().is_err() {
        return Answer::Status(Status::BadSize);
    }
    // SAFETY: the load is the fault the method exists for; the thread
    // never runs after it.
    unsafe {
        core::arch::asm!(
            "ldr {t}, [{a}]",
            t = out(reg) _,
            a = in(reg) 0_usize,
            options(nostack, readonly),
        )
    };
    // Never reached: the kernel ended the thread at the load.
    Answer::Status(Status::Kernel(Error::BadState))
}

/// The reply to a WRITE of `n` bytes that all went into the ring.
fn answer_write(pending: Pending, n: u32) {
    let mut w = Writer::new();
    // Eight bytes fit a reply.
    let _ = WriteReply { written: n }.write(&mut w);
    // A reply the client could not take is no error of the driver.
    let _ = pending.answer(w.as_bytes(), Outgoing::new());
}

/// The reply to a READ with `bytes`, 1 to RX_RING of them.
fn answer_read(pending: Pending, bytes: &[u8]) -> bool {
    let mut w = Writer::new();
    // At most RX_RING bytes after eight fit a reply.
    let _ = ReadReply { bytes }.write(&mut w);
    pending.answer(w.as_bytes(), Outgoing::new()).is_ok()
}

/// The reply of a long operation, through the request's reply buffer.
fn long_answer(r: &mut Request<'_>, reply: long::Reply<'_>) -> Answer {
    match reply.write(r.reply()) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}

/// A reply that is the status of `error` alone.
fn refuse(pending: Pending, error: Error) {
    let _ = pending.answer(&proto_wire::reply(Status::Kernel(error)), Outgoing::new());
}

/// The longest line the driver says of itself.
const LINE_MAX: usize = 64;

/// Bytes formatted into a line of LINE_MAX bytes at most.
struct Line {
    bytes: [u8; LINE_MAX],
    len: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        let room = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        room.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// The loop's structure stays small, as the stack is its home and has no
/// guard page: it takes 96 bytes with the clones in `CLONE_TABLE`, and
/// would take several K more with the table in it.
const _: () = assert!(core::mem::size_of::<Uart>() <= 512);
