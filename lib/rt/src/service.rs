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
//! handler that hangs stops it too.

use crate::handle::{Any, Channel, Handle, Incoming, Outgoing, Timer};
use crate::msgbuf;
use crate::sys::{self, Received, Refused, Token};
use crate::time;
use abi::time::next_release;
use abi::{CLIENT_GONE, Error, INLINE_MAX, MESSAGE_MAX, Source};
use proto_init::Method;
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};

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

    /// Answers `r`, a request of the client of `s` with a header of this
    /// version and one of METHODS; the handler checks the body. What it
    /// returns goes to the client, unless the handler took the token
    /// (`Request::defer`, `Request::token`): then it answers itself and
    /// returns `Answer::Deferred`.
    fn request(&mut self, s: &mut Session<Self::Data, K>, r: &mut Request<'_>) -> Answer;

    /// The client of `s` went (CLIENT_GONE); the session ends right after,
    /// and what it holds closes.
    fn gone(&mut self, s: &mut Session<Self::Data, K>) {
        let _ = s;
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
    let mut beat = match config.heartbeat.map(|h| Beat::start(channel, h)) {
        None => None,
        Some(Ok(beat)) => Some(beat),
        Some(Err(e)) => return e,
    };
    let mut table: [Option<Session<S::Data, K>>; N] = core::array::from_fn(|_| None);
    loop {
        let notice = match sys::receive(channel) {
            Err(e) => return e,
            Ok(Received::Message {
                label,
                len,
                handles,
                token,
                words,
            }) => {
                let mut buffer = [0; MESSAGE_MAX];
                let bytes = &mut buffer[..len.min(MESSAGE_MAX)];
                if len <= INLINE_MAX {
                    bytes.copy_from_slice(&abi::inline_bytes(&words)[..len]);
                } else {
                    msgbuf::read(0, bytes);
                }
                request(
                    service,
                    &mut table,
                    config.issued,
                    label,
                    bytes,
                    handles,
                    token,
                );
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
        match (notice.source, notice.label, &mut beat) {
            (Source::Timer, 0, Some(beat)) => beat.expired(),
            (Source::Session, label, _) if notice.bits & CLIENT_GONE != 0 => {
                let bits = notice.bits & !CLIENT_GONE;
                if bits != 0 {
                    service.notification(Notice { bits, ..notice });
                }
                if let Some(slot) = table
                    .iter_mut()
                    .find(|s| s.as_ref().is_some_and(|s| s.label == label))
                {
                    if let Some(s) = slot.as_mut() {
                        service.gone(s);
                    }
                    *slot = None;
                }
            }
            _ => service.notification(notice),
        }
    }
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
    let (header, s) = match header.map(|h| (h, session(table, label, issued))) {
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

/// The session of `label`, made in the first free place when there is
/// none; None when the table is full.
fn session<T: Default, const K: usize>(
    table: &mut [Option<Session<T, K>>],
    label: u64,
    issued: u32,
) -> Option<&mut Session<T, K>> {
    let i = match table
        .iter()
        .position(|s| s.as_ref().is_some_and(|s| s.label == label))
    {
        Some(i) => i,
        None => {
            let i = table.iter().position(Option::is_none)?;
            table[i] = Some(Session::new(label, T::default(), issued));
            i
        }
    };
    table[i].as_mut()
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
