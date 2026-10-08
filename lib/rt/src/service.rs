// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The loop of a service (spec 5.4, 13.2, 13.4): `run` takes what comes to
//! the service's channel in one thread and hands it to a `Service`, which
//! only writes the handlers. A client is the label of the handle its
//! requests come through (spec 5.3), and what the service holds for it
//! lives in its `Session`: up to K handles and deferred replies, and the
//! count of the objects the service gave it. The table of sessions has N
//! places on the loop's stack; a lookup goes through them in turn. Each
//! refusal goes to the client as a status (proto_wire) and the service
//! goes on. CLIENT_GONE of a label ends its session: what the session
//! held closes, and its deferred replies get PEER_CLOSED. The heartbeat
//! goes to init from the same thread, at absolute deadlines, so that a
//! handler that hangs stops it too. `register` gives init the service's
//! channel and takes its windows and bindings, `connect` asks init for a
//! session with a service by its name.

use crate::handle::{Any, Channel, Handle, Incoming, Kind, Outgoing, Timer};
use crate::msgbuf;
use crate::startup::TakeError;
use crate::sys::{self, Received, Refused, Token};
use crate::time;
use abi::time::next_release;
use abi::{CLIENT_GONE, Error, INLINE_MAX, MESSAGE_MAX, Rights, Source};
use proto_init::{Connect, Method, RegisterReply, START_NAMES};
use proto_wire::{HEADER_LEN, Header, Name, Reader, Status, Writer};

/// A service: the handlers `run` calls, with K handles and deferred
/// replies at most in each session.
pub trait Service<const K: usize> {
    /// The version of the service's protocol, the only one it takes
    /// (proto_wire): a request of another gets BAD_VERSION.
    const VERSION: u16;
    /// The numbers of its methods: a request of another gets
    /// UNKNOWN_METHOD.
    const METHODS: &'static [u16];
    /// What the service keeps for each client besides handles and
    /// deferred replies.
    type Data: Default;

    /// The places of the table before PLACED are those `place` gives; a
    /// label it gives none takes the first free place from PLACED on.
    const PLACED: usize = 0;

    /// The place in the table of the session of `label`, for a service
    /// that gives its clients' labels itself: a lookup in O(1), and the
    /// client goes to `gone` even when it never sent a request. None
    /// (the default) looks through the places from PLACED on. A place
    /// that holds the session of another label is the service's to give
    /// again: that session ends as if its client went (`gone`, then its
    /// handles close and its deferred replies get PEER_CLOSED), and the
    /// request of `label` takes the place. A place past the table refuses the request with
    /// LIMIT_REACHED.
    fn place(&self, label: u64) -> Option<usize> {
        let _ = label;
        None
    }

    /// Answers `r`, a request of the client of `s` with a header of this
    /// version and one of METHODS; the handler checks the body. What it
    /// returns goes to the client, unless the handler took the token
    /// (`Request::defer`, `Request::token`): then it answers itself and
    /// returns `Answer::Deferred`.
    fn request(&mut self, s: &mut Session<Self::Data, K>, r: &mut Request<'_>) -> Answer;

    /// The client of `s` went (CLIENT_GONE); the session ends right after,
    /// and what it holds closes. A client `place` names comes here with a
    /// new session when it had none.
    fn gone(&mut self, s: &mut Session<Self::Data, K>) {
        let _ = s;
    }

    /// CLIENT_GONE of `label`, whether or not it had a session: after
    /// `gone`, for a service that hears of the last copy of a handle it
    /// gave away, such as the start channel of a program.
    fn closed(&mut self, label: u64) {
        let _ = label;
    }

    /// One bounded maintenance step, including retained clients whose owner ended.
    /// Called after notifications; heartbeat notices also advance the cursor.
    fn maintenance(&mut self, sessions: &mut [Option<Session<Self::Data, K>>], notice: Notice) {
        let _ = (sessions, notice);
    }

    /// A scheduling handoff after a measured notification dispatch has ended.
    /// A service with a queue of own cursor notices may yield to FIFO peers here.
    fn between_notifications(&mut self, notice: Notice) {
        let _ = notice;
    }

    /// A notification other than CLIENT_GONE and the heartbeat's timer:
    /// an interrupt, the end of a child, a timer of the service, the bits
    /// of a client's notify.
    fn notification(&mut self, n: Notice) {
        let _ = n;
    }
}

/// A notification, as `receive` took it (spec 6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notice {
    pub source: Source,
    pub label: u64,
    pub bits: u64,
    pub count: u32,
}

/// What `run` sends a client for its request.
pub enum Answer {
    /// A reply that is its status alone (proto_wire::reply).
    Status(Status),
    /// A reply of the bytes the handler wrote (`Request::reply`), its
    /// status first, and these handles.
    Reply(Outgoing),
    /// The handler took the token: `run` sends nothing. Were the token
    /// still there, the client would get BAD_STATE.
    Deferred,
}

impl From<Result<(), Error>> for Answer {
    /// Status 0, or the error as the status.
    fn from(result: Result<(), Error>) -> Answer {
        Answer::Status(result.map_or_else(Status::Kernel, |()| Status::Ok))
    }
}

/// How `run` works.
pub struct Config<'a> {
    /// The objects the service gives each session at most
    /// (`Session::issue`).
    pub issued: u32,
    pub heartbeat: Option<Heartbeat<'a>>,
}

/// The heartbeat of a service (spec 13.4): a HEARTBEAT request of
/// proto_init through `to`, at the deadlines t0 + k * period_ns from the
/// start of `run`.
pub struct Heartbeat<'a> {
    /// For a service, its connection to init (Startup::parent).
    pub to: &'a Handle<Channel>,
    pub period_ns: u64,
    /// The priority of the slot of its timer: the base priority of the
    /// thread that runs the loop.
    pub priority: u8,
}

/// A request as the handler gets it: the label of its client, its
/// header, its bytes, the handles it brought and its token, and room for
/// the bytes of its reply.
pub struct Request<'a> {
    label: u64,
    header: Header,
    bytes: &'a [u8],
    /// The handles the request brought; those the handler does not take
    /// close with the request.
    pub handles: Incoming,
    token: Option<Token>,
    reply: Option<Writer>,
}

impl<'a> Request<'a> {
    /// The label of the handle the request came through.
    pub fn label(&self) -> u64 {
        self.label
    }

    pub fn method(&self) -> u16 {
        self.header.method
    }

    /// The whole request, its header first.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// A reader of the bytes after the header.
    pub fn body(&self) -> Reader<'a> {
        Reader::new(&self.bytes[HEADER_LEN..])
    }

    /// The reply, deferred: the handler answers later through the
    /// `Pending`, or a session holds it (`Session::hold`). None once the
    /// token went.
    pub fn defer(&mut self) -> Option<Pending> {
        let token = self.token.take()?;
        Some(Pending {
            label: self.label,
            token: Some(token),
        })
    }

    /// The token itself, for a handler that answers with another helper
    /// (rt::startup::Giver); None once it went.
    pub fn token(&mut self) -> Option<Token> {
        self.token.take()
    }

    /// The bytes of the reply, its status first, which `Answer::Reply`
    /// sends: empty until the handler writes them.
    pub fn reply(&mut self) -> &mut Writer {
        self.reply.get_or_insert_with(Writer::new)
    }
}

/// A reply the service owes (spec 6.1): its token and the label of its
/// client. `answer` sends it; a `Pending` that goes unanswered replies
/// PEER_CLOSED, so a client never waits for good for a reply its service
/// forgot, and one its session held goes when the client does.
pub struct Pending {
    label: u64,
    token: Option<Token>,
}

impl Pending {
    pub fn label(&self) -> u64 {
        self.label
    }

    /// Replies `bytes`, the status first, and `handles`, as
    /// Token::reply_handles; when the kernel refused the reply before it
    /// reached the request, the client gets the error as its status.
    pub fn answer(mut self, bytes: &[u8], handles: impl Into<Outgoing>) -> Result<(), Refused> {
        match self.token.take() {
            Some(token) => reply(token, bytes, handles.into()),
            None => Ok(()),
        }
    }
}

impl Drop for Pending {
    /// Replies PEER_CLOSED when nothing answered.
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            let _ = token.reply(&proto_wire::reply(Status::Kernel(Error::PeerClosed)));
        }
    }
}

/// A place of a session: a handle or a deferred reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot(usize);

/// What a place of a session holds.
enum Held {
    Free,
    Handle(Handle<Any>),
    Pending(Pending),
}

/// What a service holds for one client (spec 5.4): its data, up to K
/// handles and deferred replies, and the count of the objects the service
/// gave it. When the client goes, the handles close and the deferred
/// replies get PEER_CLOSED.
pub struct Session<T, const K: usize> {
    label: u64,
    pub data: T,
    held: [Held; K],
    issued: u32,
    issued_max: u32,
}

impl<T, const K: usize> Session<T, K> {
    fn new(label: u64, data: T, issued_max: u32) -> Session<T, K> {
        Session {
            label,
            data,
            held: [const { Held::Free }; K],
            issued: 0,
            issued_max,
        }
    }

    /// The label of the client.
    pub fn label(&self) -> u64 {
        self.label
    }

    /// A free place; LIMIT_REACHED when K are held.
    fn free(&self) -> Result<usize, Error> {
        self.held
            .iter()
            .position(|h| matches!(h, Held::Free))
            .ok_or(Error::LimitReached)
    }

    /// Keeps `h` until the client goes or `take` takes it; LIMIT_REACHED
    /// when K handles and deferred replies are held, and `h` closes.
    pub fn keep(&mut self, h: Handle<Any>) -> Result<Slot, Error> {
        let i = self.free()?;
        self.held[i] = Held::Handle(h);
        Ok(Slot(i))
    }

    /// Holds the deferred reply `p` until the client goes or `pending`
    /// takes it; LIMIT_REACHED when K are held, and `p` replies that
    /// status.
    pub fn hold(&mut self, p: Pending) -> Result<Slot, Error> {
        match self.free() {
            Ok(i) => {
                self.held[i] = Held::Pending(p);
                Ok(Slot(i))
            }
            Err(e) => {
                let _ = p.answer(&proto_wire::reply(Status::Kernel(e)), Outgoing::new());
                Err(e)
            }
        }
    }

    /// The handle kept at `slot`.
    pub fn handle(&self, slot: Slot) -> Option<&Handle<Any>> {
        match self.held.get(slot.0) {
            Some(Held::Handle(h)) => Some(h),
            _ => None,
        }
    }

    /// The handle kept at `slot`, which leaves the session.
    pub fn take(&mut self, slot: Slot) -> Option<Handle<Any>> {
        match self.held.get_mut(slot.0)? {
            held @ Held::Handle(_) => match core::mem::replace(held, Held::Free) {
                Held::Handle(h) => Some(h),
                _ => None,
            },
            _ => None,
        }
    }

    /// The deferred reply held at `slot`, which leaves the session.
    pub fn pending(&mut self, slot: Slot) -> Option<Pending> {
        match self.held.get_mut(slot.0)? {
            held @ Held::Pending(_) => match core::mem::replace(held, Held::Free) {
                Held::Pending(p) => Some(p),
                _ => None,
            },
            _ => None,
        }
    }

    /// One object more given to the client; LIMIT_REACHED at
    /// Config::issued. What counts as given, and when it comes back, the
    /// protocol of the service says.
    pub fn issue(&mut self) -> Result<(), Error> {
        if self.issued == self.issued_max {
            return Err(Error::LimitReached);
        }
        self.issued += 1;
        Ok(())
    }

    /// One object the client had came back.
    pub fn release(&mut self) {
        self.issued = self.issued.saturating_sub(1);
    }

    /// The objects the client has.
    pub fn issued(&self) -> u32 {
        self.issued
    }
}

/// Serves `channel`, a handle with RECEIVE and no label, in the calling
/// thread, the only one that receives on it, with a table of N sessions
/// (spec 5.4, 13.4). A request goes to `service` once its header has the
/// version and one of the methods of the service and its client has a
/// session, the first request of a label making one; else the client gets
/// BAD_SIZE, BAD_VERSION, UNKNOWN_METHOD or, with the table full,
/// LIMIT_REACHED. A reply the client could not take (PEER_CLOSED,
/// LIMIT_REACHED, NO_MEMORY) is no error of the service. With a heartbeat
/// the loop makes a timer on `channel` through that handle, so the service
/// makes no other timer through a handle without a label there. Returns
/// only on an error: receive's on `channel`, timer_create's or timer_set's
/// for the heartbeat, INVALID_ARGS for a period of 0. The session of label
/// 0, the clients through a handle without a label, gets no CLIENT_GONE
/// and lasts as long as the loop.
pub fn run<S: Service<K>, const N: usize, const K: usize>(
    channel: &Handle<Channel>,
    service: &mut S,
    config: Config<'_>,
) -> Error {
    let mut table: [Option<Session<S::Data, K>>; N] = core::array::from_fn(|_| None);
    run_in(channel, service, config, &mut table)
}

/// `run` with the table of sessions the caller gives, all of them free:
/// a service with a table too big for its stack keeps it in its `.bss`.
pub fn run_in<S: Service<K>, const K: usize>(
    channel: &Handle<Channel>,
    service: &mut S,
    config: Config<'_>,
    table: &mut [Option<Session<S::Data, K>>],
) -> Error {
    let mut beat = match config.heartbeat.map(|h| Beat::start(channel, h)) {
        None => None,
        Some(Ok(beat)) => Some(beat),
        Some(Err(e)) => return e,
    };
    // Zeroed once: a request reads only its first `len` bytes, and both
    // paths fill all `len` bytes, so no byte of an earlier client reaches
    // the next request.
    let mut buffer = [0; MESSAGE_MAX];
    loop {
        #[cfg(feature = "step-stats")]
        let (began, incoming) = sys::receive_measured(channel);
        #[cfg(not(feature = "step-stats"))]
        let incoming = sys::receive(channel);
        steps::restart();
        let notice = match incoming {
            Err(e) => return e,
            Ok(Received::Message {
                label,
                len,
                handles,
                token,
                words,
            }) => {
                let bytes = &mut buffer[..len.min(MESSAGE_MAX)];
                if len <= INLINE_MAX {
                    bytes.copy_from_slice(&abi::inline_bytes(&words)[..len]);
                } else {
                    msgbuf::read(0, bytes);
                }
                let kind = steps::kind_of(bytes);
                #[cfg(not(feature = "step-stats"))]
                let began = steps::begin();
                request(service, table, config.issued, label, bytes, handles, token);
                steps::end(began, kind);
                continue;
            }
            Ok(Received::Notification {
                source,
                label,
                bits,
                count,
            }) => Notice {
                source,
                label,
                bits,
                count,
            },
        };
        #[cfg(not(feature = "step-stats"))]
        let began = steps::begin();
        match (notice.source, notice.label, &mut beat) {
            (Source::Timer, 0, Some(beat)) => beat.expired(),
            (Source::Session, label, _) if notice.bits & CLIENT_GONE != 0 => {
                steps::gone();
                let bits = notice.bits & !CLIENT_GONE;
                if bits != 0 {
                    service.notification(Notice { bits, ..notice });
                }
                let placed = service.place(label);
                let found = match placed {
                    Some(i) => table
                        .get_mut(i)
                        .filter(|s| s.as_ref().is_none_or(|s| s.label == label)),
                    None => table
                        .iter_mut()
                        .skip(S::PLACED)
                        .find(|s| s.as_ref().is_some_and(|s| s.label == label)),
                };
                if let Some(slot) = found {
                    if placed.is_some() && slot.is_none() {
                        *slot = Some(Session::new(label, S::Data::default(), config.issued));
                    }
                    if let Some(s) = slot.as_mut() {
                        service.gone(s);
                    }
                    *slot = None;
                }
                service.closed(label);
            }
            _ => service.notification(notice),
        }
        service.maintenance(table, notice);
        steps::end(began, steps::NOTICE);
        service.between_notifications(notice);
    }
}

/// The longest step of the loop (feature `step-stats`, which only the
/// images of measurements and tests turn on): the ticks from the return of
/// the Receive SVC to the handler's end and its reply, including register
/// decode, message copying, header and session lookup, less the time the
/// step waited in `sys::send` for the answer of another service (its own
/// part). Kernel receive and idle before its return are outside the
/// interval. For each method of the protocol and for notifications. A new
/// longest own part of a kind goes to the console as a line
/// `service step: T kind K N ticks detail D` after the step, so that the
/// print does not count in it (`report_steps` turns it on and gives the tag
/// T); K is the method, or `NOTICE` (`OWN` for a notification `step_own`
/// marked, `GONE` for the departure of a session). A new longest wait of a
/// kind goes out as `service wait: T kind K W ticks of A`, W the wait and A
/// the whole step in which it happened.
#[cfg(feature = "step-stats")]
mod steps {
    use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

    /// The kinds: methods below this number, and the notifications.
    pub const NOTICE: usize = 64;
    /// The notifications a service counts apart (`super::step_own`).
    pub const OWN: usize = NOTICE + 1;
    /// The notifications of a departed session (CLIENT_GONE).
    pub const GONE: usize = OWN + 1;
    const KINDS: usize = GONE + 1;
    /// Whether the step in progress counts as `OWN`.
    static OWNED: AtomicBool = AtomicBool::new(false);
    /// Whether the step in progress is the departure of a session.
    static DEPARTED: AtomicBool = AtomicBool::new(false);
    /// The ticks the step in progress has waited in `sys::send`.
    static WAITED: AtomicU64 = AtomicU64::new(0);
    /// The message buffer of the thread that leads the step in progress
    /// (`msgbuf::address`, one per thread): only its sends count as the
    /// step's waits. The other threads of a service (the adoption thread of
    /// the process service, the supply thread of the entropy service) send
    /// from their own loops, and their waits are the preemption of the step,
    /// which stays in its own part.
    static LEADER: AtomicUsize = AtomicUsize::new(0);
    static WAITS: [AtomicU64; KINDS] = [const { AtomicU64::new(0) }; KINDS];
    static LONGEST: [AtomicU64; KINDS] = [const { AtomicU64::new(0) }; KINDS];
    static FULL: [AtomicU64; KINDS] = [const { AtomicU64::new(0) }; KINDS];
    /// The same for the steps of detail 16 (the terminal's Watch).
    static FULL_16: [AtomicU64; KINDS] = [const { AtomicU64::new(0) }; KINDS];
    static DETAILS: [AtomicU64; KINDS] = [const { AtomicU64::new(0) }; KINDS];
    static QUIET: AtomicBool = AtomicBool::new(false);
    /// A number the handler of the step gives (`super::step_detail`), for
    /// the line a new longest prints.
    static DETAIL: AtomicU64 = AtomicU64::new(0);
    /// The tag a new longest prints with: the service that asked (0: none).
    static REPORT: AtomicU8 = AtomicU8::new(0);

    pub fn report(tag: u8) {
        REPORT.store(tag, Ordering::Relaxed);
    }

    pub fn quiet() {
        QUIET.store(true, Ordering::Relaxed);
    }
    pub fn maximum(kind: usize) -> Option<(u64, u64)> {
        Some((
            LONGEST.get(kind)?.load(Ordering::Relaxed),
            DETAILS[kind].load(Ordering::Relaxed),
        ))
    }

    /// The longest step of `kind` whose detail was `detail` (32 or 16).
    pub fn full(kind: usize, detail: u64) -> Option<(u64, u64)> {
        let table = if detail == 16 { &FULL_16 } else { &FULL };
        Some((table.get(kind)?.load(Ordering::Relaxed), detail))
    }

    pub fn detail(value: u64) {
        DETAIL.store(value, Ordering::Relaxed);
    }

    /// The kind of a request: its method, or the last place for a request
    /// whose header is short or whose method is past the table.
    pub fn kind_of(bytes: &[u8]) -> usize {
        match super::Header::read(&mut super::Reader::new(bytes)) {
            Ok(header) if (header.method as usize) < NOTICE => header.method as usize,
            _ => NOTICE - 1,
        }
    }

    pub fn own() {
        OWNED.store(true, Ordering::Relaxed);
    }

    /// Starts the count of a step: what an earlier send of the loop
    /// (between steps) waited does not belong to it.
    pub fn restart() {
        WAITED.store(0, Ordering::Relaxed);
        LEADER.store(crate::msgbuf::address(), Ordering::Relaxed);
        DEPARTED.store(false, Ordering::Relaxed);
    }

    pub fn gone() {
        DEPARTED.store(true, Ordering::Relaxed);
    }

    pub fn waited(ticks: u64) {
        if crate::msgbuf::address() == LEADER.load(Ordering::Relaxed) {
            WAITED.fetch_add(ticks, Ordering::Relaxed);
        }
    }

    pub fn end(began: u64, kind: usize) {
        let whole = super::time::now().saturating_sub(began);
        let counted = WAITED.swap(0, Ordering::Relaxed);
        let waited = counted.min(whole);
        let took = whole - waited;
        let kind = if OWNED.swap(false, Ordering::Relaxed) {
            OWN
        } else if DEPARTED.swap(false, Ordering::Relaxed) {
            GONE
        } else {
            kind
        };
        let detail = DETAIL.swap(0, Ordering::Relaxed);
        if detail == 32 {
            FULL[kind].fetch_max(took, Ordering::Relaxed);
        } else if detail == 16 {
            FULL_16[kind].fetch_max(took, Ordering::Relaxed);
        }
        let tag = REPORT.load(Ordering::Relaxed);
        let printing = tag != 0 && !QUIET.load(Ordering::Relaxed);
        if counted > whole {
            // The sends of the leading thread cannot add up to more than
            // the step: the accounting is lost, and `xtask` fails the run.
            crate::println!("service wait cut: {tag} kind {kind} {counted} ticks of {whole}");
        }
        if took > LONGEST[kind].fetch_max(took, Ordering::Relaxed) {
            DETAILS[kind].store(detail, Ordering::Relaxed);
            if printing {
                crate::println!("service step: {tag} kind {kind} {took} ticks detail {detail}");
            }
        }
        if waited > WAITS[kind].fetch_max(waited, Ordering::Relaxed) && printing {
            crate::println!("service wait: {tag} kind {kind} {waited} ticks of {whole}");
        }
    }
}

#[cfg(not(feature = "step-stats"))]
mod steps {
    pub const NOTICE: usize = 0;
    pub fn kind_of(_: &[u8]) -> usize {
        0
    }
    pub fn begin() -> u64 {
        0
    }
    pub fn end(_: u64, _: usize) {}
    pub fn restart() {}
    pub fn gone() {}
    pub fn detail(_: u64) {}
    pub fn own() {}
    pub fn report(_: u8) {}
}

/// Makes the loop of this service print each new longest step (feature
/// `step-stats`; nothing without it): the images with several services
/// that count their steps get the lines of the one that asked.
pub fn report_steps(tag: u8) {
    steps::report(tag);
}

/// Records complete steps without printing between requests. Measurement
/// images read the bounded maxima after their workload, with the same clocks.
#[cfg(feature = "step-stats")]
pub fn quiet_steps() {
    steps::quiet();
}

/// One measurement maximum and its own detail, including notification kinds.
#[cfg(feature = "step-stats")]
pub fn step_maximum(kind: usize) -> Option<(u64, u64)> {
    steps::maximum(kind)
}

/// Measurement-only request: kind u32, optional detail u64 (32), then maximum.
#[cfg(feature = "step-stats")]
pub fn step_snapshot(r: &mut Request<'_>) -> Answer {
    let mut body = r.body();
    let kind = match body.u32() {
        Ok(kind) if r.handles.is_empty() => kind as usize,
        _ => return Answer::Status(Status::BadSize),
    };
    let maximum = if body.left() == 0 {
        step_maximum(kind)
    } else {
        match body.u64() {
            Ok(detail @ (16 | 32)) => steps::full(kind, detail),
            _ => None,
        }
    };
    let Some((ticks, detail)) = maximum.filter(|_| body.finish().is_ok()) else {
        return Answer::Status(Status::BadSize);
    };
    if r.reply()
        .u32(0)
        .and_then(|()| r.reply().u64(ticks))
        .and_then(|()| r.reply().u64(detail))
        .is_err()
    {
        return Answer::Status(Status::BadSize);
    }
    Answer::Reply(Outgoing::new())
}

/// Adds the ticks a send waited to the step in progress (feature
/// `step-stats`; `sys::send_with` calls it): the step's own part leaves them
/// out.
#[cfg(feature = "step-stats")]
pub(crate) fn waited(ticks: u64) {
    steps::waited(ticks);
}

/// Counts the notification step in progress apart from the others (feature
/// `step-stats`; nothing without it): a service's own work in steps, which
/// its own wake-ups start, is measured on its own, and the heartbeats and
/// the departures of sessions that come when the processes of higher levels
/// happen to run are not mixed into it.
pub fn step_own() {
    steps::own();
}

/// Tells the line of the longest step a number of this step, such as the
/// entries a handler took off a channel (feature `step-stats`; nothing
/// without it).
pub fn step_detail(value: u64) {
    steps::detail(value);
}

/// Hands the request in `bytes` of the client `label` to `service`, and
/// sends its answer. A request refused for its header makes no session.
fn request<S: Service<K>, const K: usize>(
    service: &mut S,
    table: &mut [Option<Session<S::Data, K>>],
    issued: u32,
    label: u64,
    bytes: &[u8],
    handles: Incoming,
    token: Token,
) {
    let header = match Header::read(&mut Reader::new(bytes)) {
        Ok(header) if header.version != S::VERSION => Err(Status::BadVersion),
        Ok(header) if !S::METHODS.contains(&header.method) => Err(Status::UnknownMethod),
        other => other,
    };
    let place = service.place(label);
    let (header, s) =
        match header.map(|h| (h, session::<S, K>(service, table, label, place, issued))) {
            Ok((header, Some(s))) => (header, s),
            Ok((_, None)) => return refuse(token, Status::Kernel(Error::LimitReached)),
            Err(status) => return refuse(token, status),
        };
    let mut r = Request {
        label,
        header,
        bytes,
        handles,
        token: Some(token),
        reply: None,
    };
    let answer = service.request(s, &mut r);
    let Some(token) = r.token.take() else {
        return;
    };
    // A reply the client could not take is no error of the service; one
    // the kernel refused for the service's own handles, the client gets
    // as its status.
    let _ = match answer {
        Answer::Status(status) => reply(token, &proto_wire::reply(status), Outgoing::new()),
        Answer::Reply(handles) => {
            let bytes = r.reply.as_ref().map_or(&[][..], Writer::as_bytes);
            reply(token, bytes, handles)
        }
        Answer::Deferred => reply(
            token,
            &proto_wire::reply(Status::Kernel(Error::BadState)),
            Outgoing::new(),
        ),
    };
}

/// Refuses a request with `status` alone.
fn refuse(token: Token, status: Status) {
    let _ = reply(token, &proto_wire::reply(status), Outgoing::new());
}

/// The session of `label`: at `place` when the service gives one
/// (Service::place), or else found from PLACED on; made in that place, or
/// in the first free one from PLACED on, when there is none; a session of
/// another label at the service's place ends first. None when the table
/// is full or the place lies past it.
fn session<'a, S: Service<K>, const K: usize>(
    service: &mut S,
    table: &'a mut [Option<Session<S::Data, K>>],
    label: u64,
    place: Option<usize>,
    issued: u32,
) -> Option<&'a mut Session<S::Data, K>> {
    let found = match place {
        Some(i) => {
            debug_assert!(i < S::PLACED, "a place past those Service::place gives");
            let s = table.get_mut(i)?;
            if s.as_ref().is_some_and(|s| s.label != label) {
                // A session of a label the service gave the place up for.
                if let Some(mut old) = s.take() {
                    service.gone(&mut old);
                }
            }
            i
        }
        None => match table
            .iter()
            .enumerate()
            .skip(S::PLACED)
            .find(|(_, s)| s.as_ref().is_some_and(|s| s.label == label))
        {
            Some((i, _)) => i,
            None => {
                table
                    .iter()
                    .enumerate()
                    .skip(S::PLACED)
                    .find(|(_, s)| s.is_none())?
                    .0
            }
        },
    };
    let slot = &mut table[found];
    if slot.is_none() {
        *slot = Some(Session::new(label, S::Data::default(), issued));
    }
    slot.as_mut()
}

/// Token::reply_handles; when the kernel refused the reply before it
/// reached the request (Refused::token), the client gets the error as its
/// status, so it never waits for good.
fn reply(token: Token, bytes: &[u8], handles: Outgoing) -> Result<(), Refused> {
    token.reply_handles(bytes, handles).map_err(|mut refused| {
        if let Some(token) = refused.token.take() {
            let _ = token.reply(&proto_wire::reply(Status::Kernel(refused.error)));
        }
        refused
    })
}

/// The heartbeat's timer and its deadlines, t0 + k * period.
struct Beat<'a> {
    to: &'a Handle<Channel>,
    timer: Handle<Timer>,
    t0: u64,
    period: u64,
    deadline: u64,
}

impl<'a> Beat<'a> {
    /// The timer on `channel`, armed at t0 + period, t0 now.
    fn start(channel: &Handle<Channel>, h: Heartbeat<'a>) -> Result<Beat<'a>, Error> {
        if h.period_ns == 0 {
            return Err(Error::InvalidArgs);
        }
        let t0 = time::ticks_to_ns(time::now());
        let timer = sys::timer_create(channel, h.priority)?;
        let mut beat = Beat {
            to: h.to,
            timer,
            t0,
            period: h.period_ns,
            deadline: t0,
        };
        beat.arm()?;
        Ok(beat)
    }

    /// Arms the timer at the first deadline after now: those that passed
    /// are not made up in a burst (spec 10, 13.4).
    fn arm(&mut self) -> Result<(), Error> {
        let now = time::ticks_to_ns(time::now());
        self.deadline = next_release(self.t0, self.period, now);
        sys::timer_set(&self.timer, self.deadline)
    }

    /// An expiry of the timer: a stale one, before the deadline, changes
    /// nothing; else HEARTBEAT goes, and the timer is armed again. Init
    /// answers HEARTBEAT at once; what it answers changes nothing here.
    fn expired(&mut self) {
        if !time::reached(self.deadline) {
            return;
        }
        let _ = sys::send(self.to, &Method::Heartbeat.header().bytes());
        // The loop's own timer: timer_set has no error to give.
        let _ = self.arm();
    }
}

/// The windows and bindings init gave a service in the reply to its
/// REGISTER (spec 13.4), each under its name from init's table; those the
/// service does not take close with it.
pub struct Registered {
    names: [Option<Name>; START_NAMES],
    handles: Incoming,
}

impl Registered {
    /// The handle that came under `name`, when its object is of kind `K`:
    /// it leaves the reply. WrongKind leaves it there.
    pub fn take<K: Kind>(&mut self, name: &str) -> Result<Handle<K>, TakeError> {
        let i = self
            .names
            .iter()
            .position(|n| n.is_some_and(|n| n.as_bytes() == name.as_bytes()))
            .ok_or(TakeError::Missing)?;
        match self.handles.take(i) {
            Ok(h) => Ok(h),
            Err(Error::WrongType) => Err(TakeError::WrongKind),
            Err(_) => Err(TakeError::Missing),
        }
    }
}

/// REGISTER through `parent`, the service's connection to init
/// (Startup::parent), with a copy of `channel`, a handle with no label, of
/// SEND, NOTIFY, DUPLICATE and TRANSFER (spec 13.4): init keeps the copy,
/// gives copies of it with SEND and TRANSFER to the clients that connect
/// by the service's name, and answers with the windows and bindings of
/// the service. A service registers before it connects to other services.
/// The errors: the copy's handle_duplicate and send as the status, init's
/// refusal (BAD_STATE for a client or a second REGISTER, ACCESS_DENIED for
/// other rights), and BAD_SIZE for a reply out of the layout of
/// proto_init::RegisterReply.
pub fn register(parent: &Handle<Channel>, channel: &Handle<Channel>) -> Result<Registered, Status> {
    let rights = Rights::SEND | Rights::NOTIFY | Rights::DUPLICATE | Rights::TRANSFER;
    let copy = sys::handle_duplicate(channel, rights)?;
    let request = Method::Register.header().bytes();
    let reply = sys::send_handles(parent, &request, [copy.erase()])
        .map_err(|refused| Status::Kernel(refused.error))?;
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    match Status::from_code(Reader::new(bytes).u32()?) {
        Status::Ok => {}
        status => return Err(status),
    }
    let names = RegisterReply::read(bytes, reply.handles.len())?.names;
    Ok(Registered {
        names,
        handles: reply.handles,
    })
}

/// CONNECT through `parent`, the program's connection to init
/// (Startup::parent): a session with the service `name` (spec 13.4), a
/// handle with SEND, TRANSFER and a label of its own. Init answers once
/// the service registered; a service that is starting again makes the
/// call wait. The errors: BAD_SIZE for a name that is no name or a reply
/// out of the layout, send's as the status, and init's refusal:
/// ACCESS_DENIED for a name init's table does not give the caller,
/// PEER_CLOSED for a service that broke or ended, LIMIT_REACHED when four
/// requests wait for it.
pub fn connect(parent: &Handle<Channel>, name: &str) -> Result<Handle<Channel>, Status> {
    let name = Name::new(name.as_bytes())?;
    let mut w = Writer::new();
    Connect { name }.write(&mut w)?;
    let mut reply = sys::send(parent, w.as_bytes())?;
    let mut buffer = [0; MESSAGE_MAX];
    match Status::from_code(Reader::new(reply.bytes(&mut buffer)).u32()?) {
        Status::Ok => reply.handles.take(0).map_err(|_| Status::BadSize),
        status => Err(status),
    }
}

/// CLONE of a service through `session`, the request `request` (its
/// header and the body its protocol gives): the new session (SEND, TRANSFER) the service made for a child of
/// the caller (spec 2, 3.7; 5c). A send that came back INTERRUPTED goes
/// again: the service never saw it. The errors: send's, the service's
/// status, BAD_SIZE for a reply without the session.
pub fn clone_session(session: &Handle<Channel>, request: &[u8]) -> Result<Handle<Channel>, Status> {
    let mut reply = loop {
        match sys::send(session, request) {
            Err(Error::Interrupted) => continue,
            other => break other?,
        }
    };
    let mut buffer = [0; MESSAGE_MAX];
    match Status::from_code(Reader::new(reply.bytes(&mut buffer)).u32()?) {
        Status::Ok => reply.handles.take(0).map_err(|_| Status::BadSize),
        status => Err(status),
    }
}

/// The most long operations of one session that wait (spec 2, 3.4).
pub const LONG_SESSION_MAX: usize = 16;

/// A long operation that waits: its client, the handle with NOTIFY that
/// tells the client once its result is ready, and its neighbours in the
/// list of its session's operations.
struct LongOp {
    label: u64,
    notify: Option<Handle<Channel>>,
    told: bool,
    previous: Option<u16>,
    next: Option<u16>,
}

/// What `LongOps` keeps for one session, in the session's data: the count
/// of its operations that wait and the first of them, so that a start
/// counts and a session that goes is taken back in O(LONG_SESSION_MAX).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LongSession {
    count: u8,
    head: Option<u16>,
}

/// The long operations of a service in two steps (proto_wire::long): N at
/// most, LONG_SESSION_MAX of each session; each under its key k, the
/// index of its place and the generation of the place, so that a key that
/// went is never taken for a new one. Starting and finding an operation
/// are O(1) (a list of free places), taking back a session's
/// O(LONG_SESSION_MAX) (the list of the session's operations, whose head
/// the session keeps: `LongSession`). An operation lives until "take k"
/// gives its result, "cancel k", or its session goes. The service keeps
/// the operation's state itself; this keeps who waits and the handle to
/// tell them.
pub struct LongOps<const N: usize> {
    ops: [Option<LongOp>; N],
    generations: [u32; N],
    /// The free places, the last freed on top.
    free: [u16; N],
    free_len: usize,
}

impl<const N: usize> Default for LongOps<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> LongOps<N> {
    pub const fn new() -> Self {
        assert!(N <= u16::MAX as usize, "places fit u16");
        let mut free = [0; N];
        let mut i = 0;
        while i < N {
            free[i] = (N - 1 - i) as u16;
            i += 1;
        }
        LongOps {
            ops: [const { None }; N],
            generations: [0; N],
            free,
            free_len: N,
        }
    }

    /// A new operation of the client `label`, whose session keeps
    /// `session`: its key; LIMIT_REACHED when the session or the service
    /// holds its most (the client gets EAGAIN). O(1).
    pub fn start(&mut self, session: &mut LongSession, label: u64) -> Result<u64, Error> {
        if usize::from(session.count) >= LONG_SESSION_MAX || self.free_len == 0 {
            return Err(Error::LimitReached);
        }
        self.free_len -= 1;
        let index = usize::from(self.free[self.free_len]);
        self.generations[index] = self.generations[index].wrapping_add(1).max(1);
        self.ops[index] = Some(LongOp {
            label,
            notify: None,
            told: false,
            previous: None,
            next: session.head,
        });
        if let Some(head) = session.head {
            self.ops[usize::from(head)]
                .as_mut()
                .expect("the head of a session")
                .previous = Some(index as u16);
        }
        session.head = Some(index as u16);
        session.count += 1;
        Ok((u64::from(self.generations[index]) << 32) | (index as u64 + 1))
    }

    /// The place of the operation `key` of the client `label`.
    fn place(&self, label: u64, key: u64) -> Option<usize> {
        let index = (key & 0xffff_ffff).checked_sub(1)? as usize;
        let op = self.ops.get(index)?.as_ref()?;
        (op.label == label && u64::from(self.generations[index]) == key >> 32).then_some(index)
    }

    /// The operation in `index` goes with its handle: out of its session's
    /// list and back to the free places. O(1).
    fn free_place(&mut self, session: &mut LongSession, index: usize) {
        let op = self.ops[index].take().expect("a live operation");
        match op.previous {
            Some(p) => self.ops[usize::from(p)].as_mut().expect("a neighbour").next = op.next,
            None => session.head = op.next,
        }
        if let Some(n) = op.next {
            self.ops[usize::from(n)]
                .as_mut()
                .expect("a neighbour")
                .previous = op.previous;
        }
        session.count -= 1;
        self.free[self.free_len] = index as u16;
        self.free_len += 1;
    }

    /// Whether the operation `key` of `label` waits.
    pub fn waits(&self, label: u64, key: u64) -> bool {
        self.place(label, key).is_some()
    }

    /// Keeps `notify`, which the client's "take" brought, for the operation;
    /// BAD_STATE for none.
    pub fn arm(&mut self, label: u64, key: u64, notify: Handle<Channel>) -> Result<(), Error> {
        let index = self.place(label, key).ok_or(Error::BadState)?;
        let op = self.ops[index].as_mut().expect("a placed operation");
        op.notify = Some(notify);
        op.told = false;
        Ok(())
    }

    /// Tells the client of the operation that its result is ready: bit 0
    /// through its handle, once; nothing before it armed.
    pub fn tell(&mut self, label: u64, key: u64) {
        let Some(index) = self.place(label, key) else {
            return;
        };
        let op = self.ops[index].as_mut().expect("a placed operation");
        if let Some(notify) = op.notify.as_ref()
            && !op.told
        {
            op.told = true;
            // A client that went closed its end: nothing to tell then.
            let _ = sys::notify(notify, 1);
        }
    }

    /// The client took after a tell and found nothing ready: the next
    /// `tell` tells again through the handle kept, as after `arm`.
    pub fn untell(&mut self, label: u64, key: u64) {
        if let Some(index) = self.place(label, key) {
            self.ops[index].as_mut().expect("a placed operation").told = false;
        }
    }

    /// The operation is over (taken or cancelled): it goes with its handle.
    pub fn finish(&mut self, session: &mut LongSession, label: u64, key: u64) -> bool {
        match self.place(label, key) {
            Some(index) => {
                self.free_place(session, index);
                true
            }
            None => false,
        }
    }

    /// The client of `session` went: its operations go with their handles.
    /// O(LONG_SESSION_MAX).
    pub fn gone(&mut self, session: &mut LongSession) {
        while let Some(head) = session.head {
            self.free_place(session, usize::from(head));
        }
    }

    /// The operations that wait, and the handles they hold.
    pub fn counts(&self) -> (usize, usize) {
        let live = self.ops.iter().flatten().count();
        let held = self
            .ops
            .iter()
            .flatten()
            .filter(|o| o.notify.is_some())
            .count();
        (live, held)
    }

    /// The labels and keys of the operations that wait, for a service that
    /// finishes them when their result comes.
    pub fn keys(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.ops.iter().enumerate().filter_map(|(index, op)| {
            op.as_ref().map(|op| {
                (
                    op.label,
                    (u64::from(self.generations[index]) << 32) | (index as u64 + 1),
                )
            })
        })
    }
}
