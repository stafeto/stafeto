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
use core::sync::atomic::{AtomicU64, Ordering};
use posix_credentials::known::Known;
use pipe::ipc::{Block, Flow, IPC_TAG, Out};
use pipe::{Held, Pipes, Roots, Wakes};
use proto_init::ServiceArgs;
use proto_pipe::ipc::{Call, NEED_ID, Who, op as ipc_op};
use proto_pipe::sock::{Addr, Received, Recv, SEND_MAX, Send};
use proto_pipe::{Cancel, HELD_MAX, MAX_READ, Method, OWN, Read, VERSION, Write};
use proto_wire::clones::Clones;
use proto_wire::{Status, long, watch};
use rt::abi::{Error, Rights, Source};
use rt::handle::{Channel, Handle, Memory, Outgoing, Process, Resource};
use rt::service::{
    Answer, Config, Heartbeat, LongOps, LongSession, Notice, Request, Service, Session,
};
use rt::sys;

mod named_open;
use pipe::admissions::Admissions;
use proto_pipe::Endpoint;

#[derive(Clone, Copy)]
struct IoCapture {
    key: u64,
    endpoint: Endpoint,
    queue: u32,
}
impl IoCapture {
    const EMPTY: Self = Self {
        key: 0,
        endpoint: Endpoint {
            id: 0,
            generation: 0,
        },
        queue: 0,
    };
}

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
    /// A copy of the identity session of the client's process, which the
    /// process service vouched for (IPC calls only), and the answer.
    identity: Option<Handle<Channel>>,
    known: Known,
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
    watches: pipe::watches::Pool<OPERATIONS>,
    roots: Roots<OPERATIONS>,
    clones: Clones<CLONES>,
    named: Admissions<Handle<Channel>>,
    io: [IoCapture; OPERATIONS],
}
struct Bss(UnsafeCell<Tables>);
// SAFETY: only the main thread reaches it, once (`main`).
unsafe impl Sync for Bss {}
static TABLES: Bss = Bss(UnsafeCell::new(Tables {
    sessions: [const { None }; SESSIONS],
    births: [None; BIRTHS],
    pipes: Pipes::new(),
    ops: LongOps::new(),
    watches: pipe::watches::Pool::new(),
    roots: Roots::new(),
    clones: Clones::new(),
    named: Admissions::new(),
    io: [IoCapture::EMPTY; OPERATIONS],
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
        births: &mut tables.births,
        clones: &mut tables.clones,
        named: &mut tables.named,
        io: &mut tables.io,
        step,
        process: Handle::borrowed(start.process.raw()),
        parent: Handle::borrowed(start.parent.raw()),
        notary: None,
        generations: None,
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
    watches: &'static mut pipe::watches::Pool<OPERATIONS>,
    /// The operations that wait, for each root.
    roots: &'static mut Roots<OPERATIONS>,
    /// The service's channel, which its own sessions are copies of.
    channel: ManuallyDrop<Handle<Channel>>,
    level: u8,
    /// The descriptions of the sessions Clone made that sent nothing yet,
    /// by their labels: the session's first request takes them, and the
    /// end of its last copy lets go of them.
    births: &'static mut [Option<Birth>; BIRTHS],
    clones: &'static mut Clones<CLONES>,
    named: &'static mut Admissions<Handle<Channel>>,
    io: &'static mut [IoCapture; OPERATIONS],
    /// The copy of the service's channel with NOTIFY, label STEP, and
    /// whether a step was told and not taken.
    step: Handle<Channel>,
    /// The service's own process, to map the page of the generations in,
    /// and its connection to init, which gives the notary session.
    process: ManuallyDrop<Handle<Process>>,
    parent: ManuallyDrop<Handle<Channel>>,
    /// The notary session with the process service (init's VOUCHERS), asked
    /// for at the first IPC call, and the page of the credentials
    /// generations through it.
    notary: Option<Handle<Channel>>,
    generations: Option<Handle<Memory>>,
    step_told: bool,
    /// A step is due that no notification told: the next request or
    /// notification makes it and tries to tell again.
    step_due: bool,
}

/// Where the service maps the process service's page of the credentials
/// generations, read-only.
const GENERATIONS_ADDRESS: usize = 0x0F00_0000;

/// The generation of the credentials of the record at `index`, read from
/// the page with no call (Acquire); the page is mapped.
fn generation(index: usize) -> u64 {
    // SAFETY: the page is mapped for reading at GENERATIONS_ADDRESS for the
    // service's life once `generations` is set, which every caller checked;
    // an index below RECORDS is a u64 word inside it.
    unsafe { &*((GENERATIONS_ADDRESS + index * 8) as *const AtomicU64) }.load(Ordering::Acquire)
}

/// Vouch through the notary session: what the process service says of the
/// client whose identity session `identity` is a copy of (none for a
/// channel of anyone else).
fn vouch(notary: &Handle<Channel>, identity: &Handle<Channel>) -> Option<proto_process::WhoReply> {
    let rights = Rights::NOTIFY | Rights::TRANSFER;
    let copy = sys::handle_duplicate(identity, rights).ok()?;
    let request = proto_process::Method::Vouch.header().bytes();
    let reply = sys::send_handles(notary, &request, [copy.erase()]).ok()?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    proto_process::WhoReply::read(reply.bytes(&mut buffer)).ok()
}

/// EACCES as the code of a refusal of the IPC calls.
const NOT_ALLOWED: u32 = proto_pipe::ipc::ERRNO + 13;

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
    /// The notary session (asked of init once) and the page of the
    /// generations mapped through it (Register), once.
    fn notary_ready(&mut self) -> bool {
        if self.notary.is_none() {
            self.notary = rt::service::connect(&self.parent, "posix").ok();
        }
        let Some(notary) = self.notary.as_ref() else {
            return false;
        };
        if self.generations.is_some() {
            return true;
        }
        let request = proto_process::Method::Register.header().bytes();
        let Ok(mut reply) = sys::send(notary, &request) else {
            return false;
        };
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        if proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() != Ok(0) {
            return false;
        }
        let Ok(memory) = reply.handles.take::<Memory>(0) else {
            return false;
        };
        let mapped = sys::mem_map(
            &self.process,
            &memory,
            0,
            4096,
            GENERATIONS_ADDRESS,
            rt::abi::Access::Read,
        );
        if mapped.is_err() {
            return false;
        }
        self.generations = Some(memory);
        true
    }

    /// Who the client of `s` is, by the process service: `offered` is the
    /// identity session a request brought, which the session keeps in place
    /// of the one before (an exec moved it to a new image). The answer is
    /// remembered with the generation of the credentials and asked again
    /// only when the page's word moved. NEED_ID for a session that never
    /// brought a copy.
    fn who(
        &mut self,
        s: &mut Session<Client, 0>,
        offered: Option<Handle<Channel>>,
    ) -> Result<Who, u32> {
        if let Some(channel) = offered {
            s.data.identity = Some(channel);
            s.data.known = Known::new();
        }
        if s.data.identity.is_none() {
            return Err(NEED_ID);
        }
        if !self.notary_ready() {
            return Err(NOT_ALLOWED);
        }
        let notary = self.notary.as_ref().expect("the notary session");
        let identity = s.data.identity.as_ref().expect("the identity session");
        let credentials = s
            .data
            .known
            .credentials(generation, || vouch(notary, identity))
            .ok_or(NOT_ALLOWED)?;
        Ok(Who {
            uid: credentials.euid,
            gid: credentials.egid,
            pid: s.data.known.pid().unwrap_or(0),
        })
    }

    /// Tells each operation `wakes` names that its end changed.
    fn tell(&mut self, wakes: &Wakes) {
        for (label, key) in wakes.iter() {
            if !self.named_tell(label, key) {
                self.ops.tell(label, key);
            }
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
        let named_due = self.named_cleanup();
        self.pipes.step(wakes) || self.watches.cleanup_due() || named_due
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
        self.named.retire(s.label());
        if self.named.cleanup_due() {
            self.kick();
        }
        self.watches.retire(s.label());
        if self.watches.cleanup_due() {
            self.kick();
        }
        self.ops.gone(&mut s.data.long);
        self.pipes.ipc_forget(s.label());
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
            self.pipes.ipc_wait_done(label, key);
            let capture = &mut self.io[((key & 0xffff_ffff) - 1) as usize];
            let queue = if capture.key == key {
                let queue = capture.queue;
                *capture = IoCapture::EMPTY;
                queue
            } else {
                end
            };
            self.pipes.unwait(queue, (label, key));
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
        endpoint: Endpoint,
        notify: Option<Handle<Channel>>,
        queue: Option<u32>,
    ) -> Answer {
        let label = s.label();
        let end = match queue.map_or_else(|| self.pipes.queue_end(endpoint), Ok) {
            Ok(end) => end,
            Err(code) => return status(code),
        };
        match key {
            None => {
                if !self.named_room() {
                    return status(proto_pipe::AGAIN);
                }
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
                self.io[((key & 0xffff_ffff) - 1) as usize] = IoCapture {
                    key,
                    endpoint,
                    queue: end,
                };
                let ops = &self.ops;
                let named = &self.named;
                if let Err(code) = self.pipes.wait(end, (label, key), |(l, k)| {
                    ops.waits(l, k) || named.alive(l, k)
                }) {
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
        let (read, endpoint) = match Read::parse_endpoint(r.body(), take) {
            Ok(read) => read,
            Err(status) => return Answer::Status(status),
        };
        let notify = match Self::notify_of(r, take) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if let Some(key) = read.key
            && (!self.ops.waits(s.label(), key)
                || self.watches.get(s.label(), key).is_some()
                || ((endpoint.is_named() || endpoint.is_sock())
                    && self.io[((key & 0xffff_ffff) - 1) as usize].endpoint != endpoint))
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let mut out = [0; MAX_READ];
        let mut wakes = Wakes::default();
        let got = self.pipes.read_endpoint(
            &s.data.held,
            endpoint,
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
            Ok(None) => self.wait(s, r, read.key, endpoint, notify, None),
        }
    }

    /// WRITE_START (`take` false) or WRITE_TAKE.
    fn write(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>, take: bool) -> Answer {
        let (write, endpoint) = match Write::parse_endpoint(r.body(), take) {
            Ok(write) => write,
            Err(status) => return Answer::Status(status),
        };
        let notify = match Self::notify_of(r, take) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if let Some(key) = write.key
            && (!self.ops.waits(s.label(), key)
                || self.watches.get(s.label(), key).is_some()
                || ((endpoint.is_named() || endpoint.is_sock())
                    && self.io[((key & 0xffff_ffff) - 1) as usize].endpoint != endpoint))
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let mut wakes = Wakes::default();
        let put = self
            .pipes
            .write_endpoint(&s.data.held, endpoint, write.bytes, &mut wakes);
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
            Ok(None) => self.wait(s, r, write.key, endpoint, notify, None),
        }
    }

    /// READ_CANCEL or WRITE_CANCEL: the operation goes, with no effect.
    fn cancel(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let (cancel, endpoint) = match Cancel::parse_endpoint(r.body()) {
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
        self.pipes.ipc_wait_done(label, cancel.key);
        // The end the operation waits at is the one its start named; a
        // cancel that names the other leaves no waiter behind either.
        let capture = &mut self.io[((cancel.key & 0xffff_ffff) - 1) as usize];
        let queue = if capture.key == cancel.key {
            let queue = capture.queue;
            *capture = IoCapture::EMPTY;
            queue
        } else {
            endpoint.id
        };
        self.pipes.unwait(queue, (label, cancel.key));
        self.pipes.unwait(queue ^ 1, (label, cancel.key));
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
        let set = match proto_pipe::WatchSet::parse(r.body()) {
            Ok(set) if r.handles.is_empty() => set,
            _ => return Answer::Status(Status::BadSize),
        };
        let mut queues = [0u8; watch::MAX];
        let mut ready = watch::Ready {
            len: set.len,
            events: [0; watch::MAX],
        };
        for (i, queue) in queues.iter_mut().enumerate().take(set.len) {
            let endpoint = set.endpoint(i);
            let (canonical, events) = match self.pipes.watch_endpoint(&s.data.held, endpoint) {
                Ok(value) => value,
                Err(code) => return status(code),
            };
            *queue = canonical as u8;
            ready.events[i] = events & (set.items[i].events | watch::ALWAYS);
        }
        rt::service::step_detail(set.len as u64);
        if ready.any() {
            return Self::watch_ready(r, ready);
        }
        if !self.named_room() {
            return status(proto_pipe::AGAIN);
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
        let registered = self.watches.insert(label, key, set, queues);
        let mut refusal = if registered {
            None
        } else {
            Some(proto_pipe::AGAIN)
        };
        if registered {
            for description in pipe::watches::unique_queues(&queues[..set.len]) {
                let ops = &self.ops;
                let named = &self.named;
                if let Err(code) = self.pipes.wait_new(description, (label, key), |(l, k)| {
                    ops.waits(l, k) || named.alive(l, k)
                }) {
                    refusal = Some(code);
                    break;
                }
            }
        }
        if let Some(code) = refusal {
            for &queue in &queues[..set.len] {
                self.pipes.unwait(u32::from(queue), (label, key));
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
        let ready = set.ready(|endpoint| self.pipes.readiness_endpoint(&s.data.held, endpoint));
        if cancel {
            let queues = *self.watches.queues(label, key).unwrap();
            for &queue in &queues[..set.len] {
                self.pipes.unwait(u32::from(queue), (label, key));
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

    /// IPC (`take` false) or IPC_TAKE: the message queues, semaphores and
    /// shared memory segments (proto_pipe::ipc).
    fn ipc(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>, take: bool) -> Answer {
        let call = match Call::parse(r.body(), take) {
            Ok(call) => call,
            Err(status) => return Answer::Status(status),
        };
        let long = ipc_op::is_long(call.op);
        rt::service::step_detail(u64::from(call.op));
        if take && !long {
            return Answer::Status(Status::BadSize);
        }
        let endpoint = Endpoint::anonymous(IPC_TAG | call.op);
        // The handles: the caller's identity session when the request says
        // so, then the labelled copy of a first take.
        let (offered, notify) = {
            let count = r.handles.len();
            let (identity, notify) = (usize::from(call.id), usize::from(take));
            if count > identity + notify || (count < identity) || (notify == 0 && count > identity)
            {
                return Answer::Status(Status::BadSize);
            }
            let first = |r: &mut Request<'_>, i: usize| {
                r.handles
                    .take::<Channel>(i)
                    .map_err(|e| Answer::Status(Status::Kernel(e)))
            };
            let offered = if call.id {
                match first(r, 0) {
                    Ok(h) => Some(h),
                    Err(a) => return a,
                }
            } else {
                None
            };
            let notify = if count > identity {
                match first(r, identity) {
                    Ok(h) => Some(h),
                    Err(a) => return a,
                }
            } else {
                None
            };
            (offered, notify)
        };
        if !self.take_ok(s, call.key, endpoint) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let who = match self.who(s, offered) {
            Ok(who) => who,
            Err(code) => {
                if long {
                    self.finish(s, call.key, endpoint.id);
                }
                return status(code);
            }
        };
        if call.op == ipc_op::MQ_OPEN
            && s.data.held.count() + self.named.reservations(s.label()) + 1 > HELD_MAX
        {
            return status(proto_pipe::MFILE);
        }
        let mut out = Out::new();
        let mut wakes = Wakes::default();
        let (label, root) = (r.label(), s.data.root);
        let flow = self
            .pipes
            .ipc_call(&mut s.data.held, label, root, &call, who, &mut out, &mut wakes);
        self.tell(&wakes);
        match flow {
            Ok(Flow::Done) => {
                if long {
                    self.finish(s, call.key, endpoint.id);
                    let mut w = proto_wire::Writer::new();
                    if out.answer().write(&mut w).is_err() {
                        return Answer::Status(Status::BadSize);
                    }
                    long_answer(r, long::Reply::Ready(w.as_bytes()))
                } else {
                    let w = r.reply();
                    if w.u32(0).is_err() || out.answer().write(w).is_err() {
                        return Answer::Status(Status::BadSize);
                    }
                    Answer::Reply(Outgoing::new())
                }
            }
            Ok(Flow::Wait { queue, block }) => {
                if !long {
                    return Answer::Status(Status::BadSize);
                }
                self.ipc_wait(s, r, call.key, endpoint, notify, queue, block)
            }
            Err(code) => {
                if long {
                    self.finish(s, call.key, endpoint.id);
                }
                status(code)
            }
        }
    }

    /// A call of the IPC methods that found it must wait: a start makes the
    /// operation and has it wait at `queue` (WAIT k); a take keeps the
    /// handle it brought (ARMED) or waits on with the one it has.
    #[allow(clippy::too_many_arguments)]
    fn ipc_wait(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
        key: Option<u64>,
        endpoint: Endpoint,
        notify: Option<Handle<Channel>>,
        queue: u32,
        block: Block,
    ) -> Answer {
        let label = s.label();
        match key {
            None => {
                if !self.named_room() {
                    return status(proto_pipe::AGAIN);
                }
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
                self.io[((key & 0xffff_ffff) - 1) as usize] = IoCapture {
                    key,
                    endpoint,
                    queue,
                };
                let ops = &self.ops;
                let named = &self.named;
                if let Err(code) = self.pipes.wait(queue, (label, key), |(l, k)| {
                    ops.waits(l, k) || named.alive(l, k)
                }) {
                    self.io[((key & 0xffff_ffff) - 1) as usize] = IoCapture::EMPTY;
                    let finished = self.ops.finish(&mut s.data.long, label, key);
                    self.over(s, finished);
                    return status(code);
                }
                self.pipes.ipc_note_wait(label, key, queue, block);
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

    /// IPC_CANCEL: the operation goes, with no effect.
    fn ipc_cancel(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>) -> Answer {
        let key = match proto_pipe::ipc::cancel_key(r.body()) {
            Ok(key) => key,
            Err(status) => return Answer::Status(status),
        };
        let label = s.label();
        // An operation that ended with an error is over already, and the
        // client's cancel after that error finds nothing to cancel: it is
        // answered all the same, and the client returns its error.
        if !self.ops.finish(&mut s.data.long, label, key) {
            return long_answer(r, long::Reply::Cancelled);
        }
        self.over(s, true);
        self.pipes.ipc_wait_done(label, key);
        let capture = &mut self.io[((key & 0xffff_ffff) - 1) as usize];
        if capture.key == key {
            let queue = capture.queue;
            *capture = IoCapture::EMPTY;
            self.pipes.unwait(queue, (label, key));
        }
        long_answer(r, long::Reply::Cancelled)
    }

    /// The socket calls that answer at once: the body after the socket.
    fn sock_call(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>, m: Method) -> Answer {
        let mut body = r.body();
        let label = r.label();
        let mut wakes = Wakes::default();
        let answer = (|| -> Result<Answer, Answer> {
            let held_room = s.data.held.count() + self.named.reservations(s.label());
            match m {
                Method::SockCreate | Method::SockPair => {
                    let domain = body.u32().map_err(Answer::Status)?;
                    let kind = body.u32().map_err(Answer::Status)?;
                    let flags = body.u32().map_err(Answer::Status)?;
                    body.finish().map_err(Answer::Status)?;
                    let pair = m == Method::SockPair;
                    if held_room + 1 + usize::from(pair) > HELD_MAX {
                        return Ok(status(proto_pipe::MFILE));
                    }
                    let root = s.data.root;
                    if pair {
                        match self.pipes.sock_pair(
                            &mut s.data.held,
                            label,
                            root,
                            domain,
                            kind,
                            flags,
                        ) {
                            Ok((a, b)) => Ok(words(r, &[a, b])),
                            Err(code) => Ok(status(code)),
                        }
                    } else {
                        match self.pipes.sock_create(
                            &mut s.data.held,
                            label,
                            root,
                            domain,
                            kind,
                            flags,
                        ) {
                            Ok(id) => Ok(words(r, &[id])),
                            Err(code) => Ok(status(code)),
                        }
                    }
                }
                _ => {
                    let end = Endpoint::parse(&mut body).map_err(Answer::Status)?;
                    let held = &s.data.held;
                    let result: Result<Option<u32>, u32> = match m {
                        Method::SockBind => {
                            let addr = Addr::read(&mut body).map_err(Answer::Status)?;
                            body.finish().map_err(Answer::Status)?;
                            self.pipes.sock_bind(held, end, addr).map(|()| None)
                        }
                        Method::SockListen => {
                            let backlog = body.u32().map_err(Answer::Status)?;
                            body.finish().map_err(Answer::Status)?;
                            self.pipes.sock_listen(held, end, backlog).map(|()| None)
                        }
                        Method::SockConnect => {
                            let addr = Addr::read(&mut body).map_err(Answer::Status)?;
                            body.finish().map_err(Answer::Status)?;
                            self.pipes
                                .sock_connect(held, end, addr, &mut wakes)
                                .map(|()| None)
                        }
                        Method::SockShutdown => {
                            let how = body.u32().map_err(Answer::Status)?;
                            body.finish().map_err(Answer::Status)?;
                            self.pipes
                                .sock_shutdown(held, end, how, &mut wakes)
                                .map(|()| None)
                        }
                        Method::SockName => {
                            let peer = body.u32().map_err(Answer::Status)?;
                            body.finish().map_err(Answer::Status)?;
                            return match self.pipes.sock_name(held, end, peer != 0) {
                                Ok(addr) => {
                                    let w = r.reply();
                                    if w.u32(0).is_err() || addr.write(w).is_err() {
                                        return Ok(Answer::Status(Status::BadSize));
                                    }
                                    Ok(Answer::Reply(Outgoing::new()))
                                }
                                Err(code) => Ok(status(code)),
                            };
                        }
                        _ => {
                            let option = body.u32().map_err(Answer::Status)?;
                            let set = body.u32().map_err(Answer::Status)?;
                            let value = body.u32().map_err(Answer::Status)?;
                            body.finish().map_err(Answer::Status)?;
                            self.pipes
                                .sock_option(held, end, option, set != 0, value)
                                .map(Some)
                        }
                    };
                    Ok(match result {
                        Ok(None) => Answer::Status(Status::Ok),
                        Ok(Some(value)) => words(r, &[value]),
                        Err(code) => status(code),
                    })
                }
            }
        })();
        self.tell(&wakes);
        answer.unwrap_or_else(|a| a)
    }

    /// The key of a take and the socket of a long socket call's body.
    fn sock_key(
        &mut self,
        s: &Session<Client, 0>,
        body: &mut proto_wire::Reader<'_>,
        take: bool,
    ) -> Result<(Option<u64>, Endpoint), Answer> {
        let key = if take {
            Some(body.u64().map_err(Answer::Status)?)
        } else {
            None
        };
        let _ = s;
        let end = Endpoint::parse(body).map_err(Answer::Status)?;
        Ok((key, end))
    }

    /// Whether a take names an operation this session waits in, at this end.
    fn take_ok(&self, s: &Session<Client, 0>, key: Option<u64>, endpoint: Endpoint) -> bool {
        match key {
            None => true,
            Some(key) => {
                self.ops.waits(s.label(), key)
                    && self.watches.get(s.label(), key).is_none()
                    && self.io[((key & 0xffff_ffff) - 1) as usize].endpoint == endpoint
            }
        }
    }

    /// SOCK_ACCEPT (`take` false) or SOCK_ACCEPT_TAKE.
    fn sock_accept(
        &mut self,
        s: &mut Session<Client, 0>,
        r: &mut Request<'_>,
        take: bool,
    ) -> Answer {
        let mut body = r.body();
        let (key, endpoint) = match self.sock_key(s, &mut body, take) {
            Ok(v) => v,
            Err(a) => return a,
        };
        if body.finish().is_err() || !endpoint.is_sock() {
            return Answer::Status(Status::BadSize);
        }
        let notify = match Self::notify_of(r, take) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if !self.take_ok(s, key, endpoint) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        if s.data.held.count() + self.named.reservations(s.label()) + 1 > HELD_MAX {
            self.finish(s, key, endpoint.id);
            return status(proto_pipe::MFILE);
        }
        let (label, root) = (r.label(), s.data.root);
        let got = self
            .pipes
            .sock_accept(&mut s.data.held, endpoint, label, root);
        match got {
            Ok(Some((id, addr))) => {
                self.finish(s, key, endpoint.id);
                let mut w = proto_wire::Writer::new();
                if w.u32(id).is_err() || addr.write(&mut w).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                long_answer(r, long::Reply::Ready(w.as_bytes()))
            }
            Err(code) => {
                self.finish(s, key, endpoint.id);
                status(code)
            }
            Ok(None) => self.wait(s, r, key, endpoint, notify, None),
        }
    }

    /// SOCK_SEND (`take` false) or SOCK_SEND_TAKE.
    fn sock_send(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>, take: bool) -> Answer {
        let send = match Send::parse(r.body(), take) {
            Ok(send) => send,
            Err(status) => return Answer::Status(status),
        };
        let endpoint = Endpoint::socket(send.end & !proto_pipe::sock::SOCK_END);
        if send.end & proto_pipe::sock::SOCK_END == 0
            || (send.end & !proto_pipe::sock::SOCK_END) as usize >= proto_pipe::sock::SOCKETS
        {
            return Answer::Status(Status::BadSize);
        }
        let notify = match Self::notify_of(r, take) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if !self.take_ok(s, send.key, endpoint) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let mut wakes = Wakes::default();
        let put = self.pipes.sock_send(
            &s.data.held,
            endpoint,
            send.flags,
            &send.fds[..send.nfds],
            &send.to,
            send.bytes,
            &mut wakes,
        );
        self.tell(&wakes);
        match put {
            Ok(Some(n)) => {
                self.finish(s, send.key, endpoint.id);
                long_answer(r, long::Reply::Ready(&(n as u32).to_le_bytes()))
            }
            Err(code) => {
                self.finish(s, send.key, endpoint.id);
                status(code)
            }
            Ok(None) => {
                let queue = self.pipes.send_queue(&s.data.held, endpoint, &send.to).ok();
                self.wait(s, r, send.key, endpoint, notify, queue)
            }
        }
    }

    /// SOCK_RECV (`take` false) or SOCK_RECV_TAKE.
    fn sock_recv(&mut self, s: &mut Session<Client, 0>, r: &mut Request<'_>, take: bool) -> Answer {
        let recv = match Recv::parse(r.body(), take) {
            Ok(recv) => recv,
            Err(status) => return Answer::Status(status),
        };
        if recv.end & proto_pipe::sock::SOCK_END == 0
            || (recv.end & !proto_pipe::sock::SOCK_END) as usize >= proto_pipe::sock::SOCKETS
        {
            return Answer::Status(Status::BadSize);
        }
        let endpoint = Endpoint::socket(recv.end & !proto_pipe::sock::SOCK_END);
        let notify = match Self::notify_of(r, take) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        if !self.take_ok(s, recv.key, endpoint) {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let mut out = [0; SEND_MAX];
        let mut wakes = Wakes::default();
        let got = self.pipes.sock_recv(
            &mut s.data.held,
            endpoint,
            recv.flags,
            &mut out[..recv.count as usize],
            recv.max_fds as usize,
            &mut wakes,
        );
        self.tell(&wakes);
        match got {
            Ok(Some(got)) => {
                self.finish(s, recv.key, endpoint.id);
                let mut w = proto_wire::Writer::new();
                let message = Received {
                    flags: got.flags,
                    fds: got.fds,
                    nfds: got.nfds,
                    from: got.from,
                    bytes: &out[..got.n],
                };
                if message.write(&mut w).is_err() {
                    return Answer::Status(Status::BadSize);
                }
                long_answer(r, long::Reply::Ready(w.as_bytes()))
            }
            Err(code) => {
                self.finish(s, recv.key, endpoint.id);
                status(code)
            }
            Ok(None) => self.wait(s, r, recv.key, endpoint, notify, None),
        }
    }

    /// CLONE with a list of the session's descriptions (count u32, then
    /// each u32): a session of the service's own label that holds them;
    /// BAD_FD for one it does not hold, LIMIT_REACHED with BIRTHS clones
    /// that sent nothing yet or the clones of its root at their most.
    fn clone_session(&mut self, held: &Held, root: u64, r: &mut Request<'_>) -> Answer {
        let mut body = r.body();
        let mut list = [Endpoint::default(); HELD_MAX];
        let count = body.u32().unwrap_or(u32::MAX) as usize;
        if count > list.len() || !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        for d in &mut list[..count] {
            let Ok(n) = Endpoint::parse(&mut body) else {
                return Answer::Status(Status::BadSize);
            };
            *d = n;
        }
        if body.finish().is_err() {
            return Answer::Status(Status::BadSize);
        }
        if self.clones.room_within(root, ROOT_CLONES).is_err()
            || !self.pipes.ipc_inherit_room(r.label())
        {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        }
        let mut child = match self.pipes.clone_endpoints(held, &list[..count]) {
            Ok(child) => child,
            Err(code) => return status(code),
        };
        // The room was just checked, so the label comes; its place is the
        // birth's.
        let Ok(label) = self.clones.give_within(OWN, root, ROOT_CLONES) else {
            if self.pipes.gone(&mut child) {
                self.kick();
            }
            return Answer::Status(Status::Kernel(Error::LimitReached));
        };
        let session = sys::handle_label(
            &self.channel,
            Rights::SEND | Rights::TRANSFER,
            label,
            self.level,
        );
        match session {
            Ok(session) if r.reply().u32(0).is_ok() => {
                // The child holds the segments and semaphores its parent does.
                self.pipes.ipc_inherit(r.label(), label);
                if let Some(place) = self.clones.place_of(label) {
                    self.births[place] = Some((label, child, root));
                }
                Answer::Reply([session.erase()].into())
            }
            other => {
                self.clones.gone(label);
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
fn end_body(r: &Request<'_>, word: bool) -> Result<(Endpoint, u32), Answer> {
    let mut body = r.body();
    let end = Endpoint::parse(&mut body).map_err(Answer::Status)?;
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
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
            ]
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
                .clones
                .place_of(label)
                .and_then(|place| self.births[place].take_if(|b| b.0 == label))
            {
                let (_, held, root) = birth;
                s.data.held = held;
                s.data.root = root;
            }
            s.data.claimed = true;
        }
        let answer = match Method::from_number(r.method()) {
            Some(Method::Create) => {
                let mut body = r.body();
                let flags = match body.u32() {
                    Ok(flags) if body.finish().is_ok() => flags,
                    _ => return Answer::Status(Status::BadSize),
                };
                if s.data.held.count() + self.named.reservations(s.label()) + 2 > HELD_MAX {
                    return status(proto_pipe::MFILE);
                }
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
                let closed = self.pipes.close_endpoint(&mut s.data.held, end, &mut wakes);
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
                Ok((end, _)) => match self.pipes.flags_endpoint(&s.data.held, end) {
                    Ok(flags) => words(r, &[flags]),
                    Err(code) => status(code),
                },
                Err(answer) => answer,
            },
            Some(Method::SetFlags) => match end_body(r, true) {
                Ok((end, flags)) => match self.pipes.set_flags_endpoint(&s.data.held, end, flags) {
                    Ok(()) => Answer::Status(Status::Ok),
                    Err(code) => status(code),
                },
                Err(answer) => answer,
            },
            Some(Method::Stat) => match end_body(r, false) {
                Ok((end, _)) => match self.pipes.stat_endpoint(&s.data.held, end) {
                    Ok((pipe, len)) => words(r, &[pipe, len]),
                    Err(code) => status(code),
                },
                Err(answer) => answer,
            },
            Some(
                m @ (Method::SockCreate
                | Method::SockPair
                | Method::SockBind
                | Method::SockListen
                | Method::SockConnect
                | Method::SockShutdown
                | Method::SockName
                | Method::SockOpt),
            ) => self.sock_call(s, r, m),
            Some(Method::SockAccept) => self.sock_accept(s, r, false),
            Some(Method::SockAcceptTake) => self.sock_accept(s, r, true),
            Some(Method::SockSend) => self.sock_send(s, r, false),
            Some(Method::SockSendTake) => self.sock_send(s, r, true),
            Some(Method::SockRecv) => self.sock_recv(s, r, false),
            Some(Method::SockRecvTake) => self.sock_recv(s, r, true),
            Some(Method::Ipc) => self.ipc(s, r, false),
            Some(Method::IpcTake) => self.ipc(s, r, true),
            Some(Method::IpcCancel) => self.ipc_cancel(s, r),
            Some(Method::Abandon) => {
                if r.body().finish().is_err() {
                    return Answer::Status(Status::BadSize);
                }
                self.abandon(s);
                // An exec: the old image's segments are detached with it.
                if self.pipes.ipc_exec(s.label()) {
                    self.kick();
                }
                Answer::Status(Status::Ok)
            }
            Some(
                method @ (Method::PayerWitness
                | Method::BrokerPrepare
                | Method::BrokerCancel
                | Method::NamedAttach
                | Method::NamedQuery
                | Method::NamedTake
                | Method::NamedCancel
                | Method::NamedAck),
            ) => self.named_request(s, r, method),
            None => Answer::Status(Status::UnknownMethod),
        };
        // What the call left to let go of (descriptions a message held, a
        // connection nobody accepted) goes in steps of its own.
        if self.pipes.work_due() {
            self.kick();
        }
        answer
    }

    /// The client of `s` went: its operations go, and its descriptions
    /// are let go of in steps.
    fn gone(&mut self, s: &mut Session<Client, 0>) {
        rt::service::step_own();
        self.abandon(s);
        self.pipes.ipc_gone(s.label());
        if self.pipes.gone(&mut s.data.held) {
            self.kick();
        }
    }

    /// The last copy of a session Clone made went before it sent anything:
    /// the descriptions it was born with are let go of in steps.
    fn closed(&mut self, label: u64) {
        rt::service::step_own();
        let birth = self
            .clones
            .place_of(label)
            .and_then(|place| self.births[place].take_if(|b| b.0 == label));
        self.clones.gone(label);
        if self.pipes.ipc_gone(label) {
            self.kick();
        }
        if let Some((_, mut held, _)) = birth
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
