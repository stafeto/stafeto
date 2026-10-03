// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The pipe service (5e; spec 2, 2): the pipes of POSIX processes in one
//! thread (the library has their state). Reads and writes that wait are
//! long operations in two steps (proto_wire::long, spec 2, 3.4): the
//! service keeps who waits at each end and no byte of a write, so a
//! cancel has no effect. A session that goes lets go of its descriptions
//! one at a time, a step of the loop each: the service tells itself of
//! the next step through a notification to its own channel (STEP), which
//! waits in the queue with the requests. The service sends no request to
//! any other.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use pipe::{Held, Pipes, Roots, Wakes};
use proto_init::ServiceArgs;
use proto_pipe::{Cancel, HELD_MAX, MAX_READ, Method, OWN, Read, VERSION, Write};
use proto_wire::clones::Clones;
use proto_wire::{Status, long, watch};
use rt::abi::{Error, Rights, Source};
use rt::handle::{Channel, Handle, Outgoing, Resource};
use rt::service::{
    Answer, Config, Heartbeat, LongOps, LongSession, Notice, Request, Service, Session,
};
use rt::sys;

rt::entry!(main);

/// The sessions: room for the 255 records of the process service and the
/// services beside them, as the RAM file service has.
const SESSIONS: usize = 320;
/// The clones the service keeps alive at most, and so the clones whose
/// sessions sent nothing yet (births).
const CLONES: usize = 320;
const BIRTHS: usize = CLONES;
/// The live clones of one root at most: one for each record of the process
/// service, so that a tree of processes has a session each, and the
/// others' roots keep CLONES - ROOT_CLONES of them.
const ROOT_CLONES: usize = 255;
/// The long operations that wait in the service at most.
const OPERATIONS: usize = 128;
/// The label of the service's own place for the notification of the next
/// step of the sessions that went: none of init's labels and none of the
/// service's clones has bit 62 with bit 63.
const STEP: u64 = OWN | 1 << 62;

/// What the service keeps for a client: the descriptions it holds, its
/// long operations and how many wait, whether the session took the
/// descriptions Clone made it with, and the root of its chain of clones:
/// the label of init's client whose process forked or spawned it, or its
/// own label for such a client. The limits of pipes, waiting operations
/// and clones count by the root, so that one process tree cannot take
/// the service from the others.
#[derive(Default)]
struct Client {
    held: Held,
    long: LongSession,
    waiting: u16,
    claimed: bool,
    root: u64,
}

/// A clone that sent nothing yet: its label, its descriptions and the
/// root of its chain.
type Birth = (u64, Held, u64);

/// The tables of the sessions, births, clones and long operations, and
/// the pipes with their rings, in `.bss`: too big for the stack.
struct Tables {
    sessions: [Option<Session<Client, 0>>; SESSIONS],
    births: [Option<Birth>; BIRTHS],
    pipes: Pipes,
    ops: LongOps<OPERATIONS>,
    watches: watch::Pool<OPERATIONS>,
    roots: Roots<OPERATIONS>,
    clones: Clones<CLONES>,
}
struct Bss(UnsafeCell<Tables>);
// SAFETY: only the main thread reaches it, once (`main`).
unsafe impl Sync for Bss {}
static TABLES: Bss = Bss(UnsafeCell::new(Tables {
    sessions: [const { None }; SESSIONS],
    births: [None; BIRTHS],
    pipes: Pipes::new(),
    ops: LongOps::new(),
    watches: watch::Pool::new(),
    roots: Roots::new(),
    clones: Clones::new(),
}));

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let args = ServiceArgs::read(start.args()).ok();
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(1) else {
        return 2;
    };
    if rt::service::register(&start.parent, &channel).is_err() {
        return 3;
    }
    let Ok(step) = sys::handle_label(&channel, Rights::NOTIFY, STEP, level) else {
        return 5;
    };
    let config = Config {
        issued: 0,
        heartbeat: Some(Heartbeat {
            to: &start.parent,
            period_ns: args.map_or(0, |args| args.period_ns),
            priority: level,
        }),
    };
    // SAFETY: only the main thread reaches TABLES, here once.
    let tables = unsafe { &mut *TABLES.0.get() };
    let mut service = PipeService {
        pipes: &mut tables.pipes,
        ops: &mut tables.ops,
        watches: &mut tables.watches,
        roots: &mut tables.roots,
        channel: Handle::borrowed(channel.raw()),
        level,
        given: 0,
        births: &mut tables.births,
        clones: &mut tables.clones,
        step,
        step_told: false,
        step_due: false,
    };
    rt::println!("pipe: ready");
    #[cfg(feature = "steps")]
    rt::service::report_steps(4);
    #[cfg(feature = "quiet-steps")]
    rt::service::quiet_steps();
    let _ = rt::service::run_in(&channel, &mut service, config, &mut tables.sessions);
    4
}

struct PipeService {
    pipes: &'static mut Pipes,
    ops: &'static mut LongOps<OPERATIONS>,
    watches: &'static mut watch::Pool<OPERATIONS>,
    /// The operations that wait, for each root.
    roots: &'static mut Roots<OPERATIONS>,
    /// The service's channel, which its own sessions are copies of.
    channel: ManuallyDrop<Handle<Channel>>,
    level: u8,
    /// The sessions the service gave itself so far.
    given: u64,
    /// The descriptions of the sessions Clone made that sent nothing yet,
    /// by their labels: the session's first request takes them, and the
    /// end of its last copy lets go of them.
    births: &'static mut [Option<Birth>; BIRTHS],
    clones: &'static mut Clones<CLONES>,
    /// The copy of the service's channel with NOTIFY, label STEP, and
    /// whether a step was told and not taken.
    step: Handle<Channel>,
    step_told: bool,
    /// A step is due that no notification told: the next request or
    /// notification makes it and tries to tell again.
    step_due: bool,
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

impl PipeService {
    /// Tells each operation `wakes` names that its end changed.
    fn tell(&mut self, wakes: &Wakes) {
        for (label, key) in wakes.iter() {
            self.ops.tell(label, key);
        }
    }

    /// Tells the loop of a step of the descriptions that sessions which
    /// went let go of, unless one is told already. Were the notification
    /// refused, the step is due all the same: the next request or
    /// notification makes one and tells again (`due`), so no step grows.
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

    /// The step a refused notification left due, after a request or
    /// another notification.
    fn due(&mut self) {
        if self.step_due && !self.step_told {
            self.step_due = false;
            rt::service::step_own();
            let mut wakes = Wakes::default();
            let more = self.cleanup_step(&mut wakes);
            self.tell(&wakes);
            if more {
                self.kick();
            }
        }
    }

    /// One reverse subscription and one deferred description per step.
    fn cleanup_step(&mut self, wakes: &mut Wakes) -> bool {
        if let Some((label, key, end)) = self.watches.cleanup() {
            self.pipes.unwait(end, (label, key));
        }
        self.pipes.step(wakes) || self.watches.cleanup_due()
    }

    /// One operation of the session `s` is over (`finished`): it waits no
    /// more for its root.
    fn over(&mut self, s: &mut Session<Client, 0>, finished: bool) {
        if finished {
            s.data.waiting -= 1;
            self.roots.give(s.data.root, 1);
        }
    }

    /// Every operation of the session `s` goes (it went, or Abandon).
    fn abandon(&mut self, s: &mut Session<Client, 0>) {
        self.watches.retire(s.label());
        if self.watches.cleanup_due() {
            self.kick();
        }
        self.ops.gone(&mut s.data.long);
        self.roots
            .give(s.data.root, core::mem::take(&mut s.data.waiting));
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

    /// The operation `key` of `label` at `end` is over.
    fn finish(&mut self, s: &mut Session<Client, 0>, key: Option<u64>, end: u32) {
        if let Some(key) = key {
            let label = s.label();
            let finished = self.ops.finish(&mut s.data.long, label, key);
            self.over(s, finished);
            self.pipes.unwait(end, (label, key));
        }
    }

    /// A read or write that found nothing to do: a start makes the
    /// operation and has it wait at `end` (WAIT k); a take keeps the
    /// handle it brought (ARMED) or waits on with the one it has.
    fn wait(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
        key: Option<u64>,
        end: u32,
        notify: Option<Handle<Channel>>,
    ) -> Answer {
        let label = s.label();
        match key {
            None => {
                if let Err(code) = self.roots.take(s.data.root) {
                    return status(code);
                }
                let key = match self.ops.start(&mut s.data.long, label) {
                    Ok(key) => key,
                    Err(e) => {
                        self.roots.give(s.data.root, 1);
                        return Answer::Status(Status::Kernel(e));
                    }
                };
                s.data.waiting += 1;
                let ops = &self.ops;
                if let Err(code) = self.pipes.wait(end, (label, key), |(l, k)| ops.waits(l, k)) {
                    let finished = self.ops.finish(&mut s.data.long, label, key);
                    self.over(s, finished);
                    return status(code);
                }
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
                long_answer(r, long::Reply::Armed)
            }
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
        if let Some(key) = read.key
            && (!self.ops.waits(s.label(), key) || self.watches.get(s.label(), key).is_some())
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let mut out = [0; MAX_READ];
        let mut wakes = Wakes::default();
        let got = self.pipes.read(
            &s.data.held,
            read.end,
            &mut out[..read.count as usize],
            &mut wakes,
        );
        self.tell(&wakes);
        match got {
            Ok(Some(n)) => {
                self.finish(s, read.key, read.end);
                long_answer(r, long::Reply::Ready(&out[..n]))
            }
            Err(code) => {
                self.finish(s, read.key, read.end);
                status(code)
            }
            Ok(None) => self.wait(s, r, read.key, read.end, notify),
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
        if let Some(key) = write.key
            && (!self.ops.waits(s.label(), key) || self.watches.get(s.label(), key).is_some())
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let mut wakes = Wakes::default();
        let put = self
            .pipes
            .write(&s.data.held, write.end, write.bytes, &mut wakes);
        self.tell(&wakes);
        match put {
            Ok(Some(n)) => {
                self.finish(s, write.key, write.end);
                long_answer(r, long::Reply::Ready(&(n as u32).to_le_bytes()))
            }
            Err(code) => {
                self.finish(s, write.key, write.end);
                status(code)
            }
            Ok(None) => self.wait(s, r, write.key, write.end, notify),
        }
    }

    /// READ_CANCEL or WRITE_CANCEL: the operation goes, with no effect.
    fn cancel(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let cancel = match Cancel::parse(r.body()) {
            Ok(cancel) => cancel,
            Err(status) => return Answer::Status(status),
        };
        let label = s.label();
        if self.watches.get(label, cancel.key).is_some() {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        if !self.ops.finish(&mut s.data.long, label, cancel.key) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        self.over(s, true);
        // The end the operation waits at is the one its start named; a
        // cancel that names the other leaves no waiter behind either.
        self.pipes.unwait(cancel.end, (label, cancel.key));
        self.pipes.unwait(cancel.end ^ 1, (label, cancel.key));
        long_answer(r, long::Reply::Cancelled)
    }

    fn watch_ready(r: &mut Request<'_>, ready: watch::Ready) -> Answer {
        let mut body = proto_wire::Writer::new();
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
        let descriptions = match s
            .data
            .held
            .select(set.items[..set.len].iter().map(|item| item.description))
        {
            Ok(descriptions) => descriptions,
            Err(code) => return status(code),
        };
        rt::service::step_detail(set.len as u64);
        let ready = set.ready(|end| self.pipes.readiness(&s.data.held, end));
        if ready.any() {
            return Self::watch_ready(r, ready);
        }
        if let Err(code) = self.roots.take(s.data.root) {
            return status(code);
        }
        let label = s.label();
        let key = match self.ops.start(&mut s.data.long, label) {
            Ok(key) => key,
            Err(error) => {
                self.roots.give(s.data.root, 1);
                return Answer::Status(Status::Kernel(error));
            }
        };
        s.data.waiting += 1;
        let registered = self.watches.insert(label, key, set);
        let mut refusal = if registered {
            None
        } else {
            Some(proto_pipe::AGAIN)
        };
        if registered {
            for description in descriptions.descriptions() {
                let ops = &self.ops;
                if let Err(code) = self
                    .pipes
                    .wait_new(description, (label, key), |(l, k)| ops.waits(l, k))
                {
                    refusal = Some(code);
                    break;
                }
            }
        }
        if let Some(code) = refusal {
            for description in descriptions.descriptions() {
                self.pipes.unwait(description, (label, key));
            }
            self.watches.remove(label, key);
            let finished = self.ops.finish(&mut s.data.long, label, key);
            self.over(s, finished);
            return status(code);
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
            if r.handles.len() > 1 {
                return Answer::Status(Status::BadSize);
            }
            if !r.handles.is_empty()
                && !matches!(r.handles.info(0), Some((rt::abi::ObjectKind::Channel, rights)) if rights.contains(Rights::NOTIFY))
            {
                return Answer::Status(Status::BadSize);
            }
            let notify = match Self::notify_of(r, true) {
                Ok(notify) => notify,
                Err(answer) => return answer,
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
        let ready = set.ready(|end| self.pipes.readiness(&s.data.held, end));
        if cancel {
            for description in set.descriptions() {
                self.pipes.unwait(description, (label, key));
            }
            self.watches.remove(label, key);
            let finished = self.ops.finish(&mut s.data.long, label, key);
            self.over(s, finished);
            Self::watch_ready(r, ready)
        } else if ready.any() {
            Self::watch_ready(r, ready)
        } else {
            long_answer(r, long::Reply::Armed)
        }
    }

    /// CLONE with a list of the session's descriptions (count u32, then
    /// each u32): a session of the service's own label that holds them;
    /// BAD_FD for one it does not hold, LIMIT_REACHED with BIRTHS clones
    /// that sent nothing yet or the clones of its root at their most.
    fn clone_session(&mut self, held: &Held, root: u64, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let mut list = [0u32; HELD_MAX];
        let count = body.u32().unwrap_or(u32::MAX) as usize;
        if count > list.len() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        for d in &mut list[..count] {
            let Ok(n) = body.u32() else {
                return Answer::Status(Status::BadSize);
            };
            *d = n;
        }
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        let Some(free) = self.births.iter().position(Option::is_none) else {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        };
        if self.clones.room_within(root, ROOT_CLONES).is_err() {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        }
        let mut child = match self.pipes.clone_held(held, &list[..count]) {
            Ok(child) => child,
            Err(code) => return status(code),
        };
        self.given += 1;
        let label = OWN | self.given;
        let session = sys::handle_label(
            &self.channel,
            Rights::SEND | Rights::TRANSFER,
            label,
            self.level,
        );
        match session {
            Ok(session) if r.reply().u32(0).is_ok() => {
                self.births[free] = Some((label, child, root));
                let _ = self.clones.add_within(label, root, ROOT_CLONES);
                Answer::Reply([session.erase()].into())
            }
            other => {
                if self.pipes.gone(&mut child) {
                    self.kick();
                }
                match other {
                    Err(e) => Answer::Status(Status::Kernel(e)),
                    Ok(_) => Answer::Status(Status::BadSize),
                }
            }
        }
    }
}

/// The value of a reply: status 0 and `words`.
fn words(r: &mut Request<'_>, words: &[u32]) -> Answer {
    let w = r.reply();
    if w.u32(0).is_err() || words.iter().any(|&v| w.u32(v).is_err()) {
        return Answer::Status(Status::BadSize);
    }
    Answer::Reply(Outgoing::new())
}

/// The end of a request of one end alone (and a word for SET_FLAGS).
fn end_body(r: &Request<'_>, word: bool) -> Result<(u32, u32), Answer> {
    let mut body = r.body();
    let end = body.u32().map_err(Answer::Status)?;
    let value = if word {
        body.u32().map_err(Answer::Status)?
    } else {
        0
    };
    body.finish().map_err(Answer::Status)?;
    Ok((end, value))
}

impl Service<0> for PipeService {
    const VERSION: u16 = VERSION;
    const METHODS: &'static [u16] = {
        #[cfg(feature = "steps")]
        {
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
        }
        #[cfg(not(feature = "steps"))]
        {
            proto_pipe::METHODS
        }
    };
    type Data = Client;

    fn request(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        self.due();
        #[cfg(feature = "steps")]
        if r.method() == 17 {
            return rt::service::step_snapshot(r);
        }
        if !s.data.claimed {
            // The first request of a session Clone made takes its
            // descriptions and its root; init's client is its own root.
            let label = r.label();
            s.data.root = label;
            if let Some(birth) = self
                .births
                .iter_mut()
                .find(|b| b.is_some_and(|(l, ..)| l == label))
            {
                let (_, held, root) = birth.take().expect("a birth");
                s.data.held = held;
                s.data.root = root;
            }
            s.data.claimed = true;
        }
        match Method::from_number(r.method()) {
            Some(Method::Create) => {
                let (flags, _) = match end_body(r, false) {
                    Ok(body) => body,
                    Err(answer) => return answer,
                };
                match self
                    .pipes
                    .create(&mut s.data.held, r.label(), s.data.root, flags)
                {
                    Ok((read, write)) => words(r, &[read, write]),
                    Err(code) => status(code),
                }
            }
            Some(Method::WatchStart) => self.watch_start(s, r),
            Some(Method::WatchTake) => self.watch_keyed(s, r, false),
            Some(Method::WatchCancel) => self.watch_keyed(s, r, true),
            Some(Method::ReadStart) => self.read(s, r, false),
            Some(Method::ReadTake) => self.read(s, r, true),
            Some(Method::WriteStart) => self.write(s, r, false),
            Some(Method::WriteTake) => self.write(s, r, true),
            Some(Method::ReadCancel | Method::WriteCancel) => self.cancel(s, r),
            Some(Method::Close) => {
                let (end, _) = match end_body(r, false) {
                    Ok(body) => body,
                    Err(answer) => return answer,
                };
                let mut wakes = Wakes::default();
                let closed = self.pipes.close(&mut s.data.held, end, &mut wakes);
                self.tell(&wakes);
                match closed {
                    Ok(()) => Answer::Status(Status::Ok),
                    Err(code) => status(code),
                }
            }
            Some(Method::Clone) => {
                let (held, root) = (s.data.held, s.data.root);
                self.clone_session(&held, root, r)
            }
            Some(Method::GetFlags) => match end_body(r, false) {
                Ok((end, _)) => match self.pipes.flags(&s.data.held, end) {
                    Ok(flags) => words(r, &[flags]),
                    Err(code) => status(code),
                },
                Err(answer) => answer,
            },
            Some(Method::SetFlags) => match end_body(r, true) {
                Ok((end, flags)) => match self.pipes.set_flags(&s.data.held, end, flags) {
                    Ok(()) => Answer::Status(Status::Ok),
                    Err(code) => status(code),
                },
                Err(answer) => answer,
            },
            Some(Method::Stat) => match end_body(r, false) {
                Ok((end, _)) => match self.pipes.stat(&s.data.held, end) {
                    Ok((pipe, len)) => words(r, &[pipe, len]),
                    Err(code) => status(code),
                },
                Err(answer) => answer,
            },
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

    /// The client of `s` went: its operations go, and its descriptions
    /// are let go of in steps.
    fn gone(&mut self, s: &mut Session<Client, 0>) {
        rt::service::step_own();
        self.abandon(s);
        if self.pipes.gone(&mut s.data.held) {
            self.kick();
        }
    }

    /// The last copy of a session Clone made went before it sent anything:
    /// the descriptions it was born with are let go of in steps.
    fn closed(&mut self, label: u64) {
        rt::service::step_own();
        self.clones.gone(label);
        if let Some(birth) = self
            .births
            .iter_mut()
            .find(|b| b.is_some_and(|(l, ..)| l == label))
            && let Some((_, mut held, _)) = birth.take()
            && self.pipes.gone(&mut held)
        {
            self.kick();
        }
    }

    /// The step of the descriptions that sessions which went let go of
    /// (STEP): one description, the operations it wakes told.
    fn notification(&mut self, n: Notice) {
        if n.source != Source::Session || n.label != STEP {
            self.due();
            return;
        }
        self.step_told = false;
        let mut wakes = Wakes::default();
        let more = self.cleanup_step(&mut wakes);
        self.tell(&wakes);
        rt::service::step_own();
        rt::service::step_detail(u64::from(more));
        if more {
            self.kick();
        }
    }
}
