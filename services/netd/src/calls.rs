// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The sockets' methods of the protocol (proto_net::sockets). A request that
//! may wait is a long operation in two steps (proto_wire::long): the start
//! answers READY, an error, or WAIT k and keeps who waits; the take repeats
//! the operation by its key and answers READY or ARMED with the handle that
//! tells the client. The service takes nothing from a socket until it
//! answers READY, so a cancel loses nothing (spec 2, 3.4).
//!
//! A call changes the buffers of a smoltcp socket and asks the loop for a
//! step; the call itself never runs the stack, so its length does not grow
//! with the number of sockets.

use crate::net::{
    Birth, Client, Conn, Kind, Net, OPEN_MAX, OWN, OpInfo, ROOT_CLONES, SESSIONS, Sock, now_ns,
    op_index,
};
use crate::split;
use crate::stack::{GROUP, Stack, listen_endpoint};
use abi::{Error, MESSAGE_MAX, Rights};
use netd::births;
use netd::demux::Key;
use netd::passes::Passes;
use netd::places::{Held, State};
use netd::ports::{self, Binding, Proto};
use netd::profile::{self, Counter};
use netd::reuse::NO_GROUP;
use proto_net::sockets::{self, EpollReady, EpollRecord, Request as Call, epoll, opt};
use proto_net::{Address, DATA_MAX, INET, code};
use proto_wire::{Status, Writer, long, watch};
use rt::handle::{Channel, Handle, Outgoing};
use rt::service::{Answer, LongSession, Request, Session};
use rt::sys;
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Duration;
use smoltcp::wire::{IpAddress, IpEndpoint};

/// `n` bytes went between a socket's queue and a buffer of the caller (the
/// profile's count of copies).
#[inline(always)]
fn copied(n: usize) {
    profile::count(Counter::CopyN);
    profile::add(Counter::CopyBytes, n as u64);
}

type Sess = Session<Client, 0>;

fn refuse(c: u32) -> Answer {
    Answer::Status(code(c))
}

fn ok() -> Answer {
    Answer::Status(Status::Ok)
}

fn long_answer(r: &mut Request<'_>, reply: long::Reply<'_>) -> Answer {
    match reply.write(r.reply()) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}

fn word(r: &mut Request<'_>, value: u32) -> Answer {
    match sockets::write_word(r.reply(), value) {
        Ok(()) => Answer::Reply(Outgoing::new()),
        Err(status) => Answer::Status(status),
    }
}

/// The bytes of a SEND: in the message, or in a cell of the session's
/// shared buffer (its address and length).
#[derive(Clone, Copy)]
enum Out<'a> {
    Bytes(&'a [u8]),
    Cell(usize, usize),
}

/// Where the bytes of a RECV go: the reply, or a cell (its address and
/// the bytes asked).
#[derive(Clone, Copy)]
enum Into {
    Reply,
    Cell(usize, usize),
}

/// What an operation on a socket came to.
enum Io<T> {
    Ready(T),
    /// Nothing can be done yet.
    Block,
    Fail(u32),
}

/// The destination of a send or a connect, once the loopback is settled: the
/// wildcard means this host, and the loopback network has the one address
/// 127.0.0.1.
fn destination(address: &Address) -> Result<([u8; 4], u16), u32> {
    let ip = address.ipv4().ok_or(proto_net::NO_FAMILY)?;
    let port = u16::try_from(address.port).map_err(|_| proto_net::INVALID)?;
    let ip = if ip == [0; 4] { [127, 0, 0, 1] } else { ip };
    if ip[0] == 127 && ip != [127, 0, 0, 1] {
        return Err(proto_net::UNREACHABLE);
    }
    Ok((ip, port))
}

fn endpoint(ip: [u8; 4], port: u16) -> IpEndpoint {
    IpEndpoint::new(IpAddress::Ipv4(ip.into()), port)
}

fn peer_of(end: IpEndpoint) -> ([u8; 4], u16) {
    let IpAddress::Ipv4(a) = end.addr;
    (a.octets(), end.port)
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

impl Net {
    /// The session `s` takes the descriptions Clone made it with, at its
    /// first request; init's client is its own root.
    pub fn claim(&mut self, s: &mut Sess, label: u64) {
        if s.data.claimed {
            return;
        }
        s.data.root = label;
        if let Some((_, held, root, _)) = self
            .clones
            .place_of(label)
            .and_then(|place| self.births[place].take_if(|b| b.0 == label))
        {
            s.data.held = held;
            s.data.root = root;
        }
        s.data.claimed = true;
    }

    /// The last copy of a clone's session went before it sent anything: its
    /// descriptions go, and its label.
    pub fn unborn(&mut self, label: u64) -> Option<Held> {
        let birth: Option<Birth> = self
            .clones
            .place_of(label)
            .and_then(|place| self.births[place].take_if(|b| b.0 == label));
        self.clones.gone(label);
        birth.map(|(_, held, _, _)| held)
    }

    /// Up to `ABANDON_PORTION` operations of a session go (ABANDON, or a step
    /// of departure of a session that went): each leaves the place it waits
    /// on before its number is given to others. True when the session has more.
    pub fn release_ops(&mut self, long: &mut LongSession) -> bool {
        netd::ring::abandon_portion(|| {
            let Some(key) = self.ops.first(long) else {
                return false;
            };
            if let Some(idx) = op_index(key) {
                self.forget_op(idx);
            }
            self.ops.gone_some(long, 1);
            true
        });
        !long.is_empty()
    }

    /// The operation `key` of the session is over.
    fn finish_op(&mut self, s: &mut Sess, key: u64) {
        let label = s.label();
        if self.ops.finish(&mut s.data.long, label, key)
            && let Some(idx) = op_index(key)
        {
            self.forget_op(idx);
        }
    }

    /// Whether `key` is an operation of `kind` of the session, on place `place`.
    fn op_ok(&self, s: &Sess, key: u64, kind: Kind, place: usize) -> bool {
        // The key is a client's: the table is asked first, and the index
        // only of a key that names an operation.
        if !self.ops.waits(s.label(), key) {
            return false;
        }
        let Some(idx) = op_index(key) else {
            return false;
        };
        let info = self.info[idx];
        info.key == key && info.kind == kind && usize::from(info.place) == place
    }

    /// A start makes the operation and has it wait (WAIT k); a take keeps
    /// the handle it brought (ARMED) or waits on with the one it has.
    fn wait(
        &mut self,
        s: &mut Sess,
        r: &mut Request<'_>,
        key: Option<u64>,
        kind: Kind,
        place: usize,
        notify: Option<Handle<Channel>>,
    ) -> Answer {
        let label = s.label();
        match key {
            None => {
                let key = match self.ops.start(&mut s.data.long, label) {
                    Ok(key) => key,
                    Err(e) => return Answer::Status(Status::Kernel(e)),
                };
                let idx = op_index(key).expect("a key the table of operations gave");
                self.info[idx] = OpInfo {
                    key,
                    label,
                    kind,
                    place: place as u16,
                };
                self.told &= !(1 << idx);
                self.limit(idx, kind, place);
                if kind == Kind::Epoll {
                    self.interest.add_waiter(place, idx);
                } else {
                    self.socks[place].waiters |= 1 << idx;
                    self.attention.set(place);
                }
                long_answer(r, long::Reply::Wait(key))
            }
            Some(key) => {
                // The time limit of the operation ran out: it ends as a call
                // that would not wait does (EAGAIN; a connect goes on).
                let ran_out = op_index(key).is_some_and(|idx| self.expired >> idx & 1 != 0);
                if ran_out && kind != Kind::Linger {
                    let code = if kind == Kind::Connect {
                        proto_net::IN_PROGRESS
                    } else {
                        proto_net::AGAIN
                    };
                    return self.done(s, Some(key), refuse(code));
                }
                self.told &= !op_index(key).map_or(0, |idx| 1u128 << idx);
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

    /// The time limit of the new operation `idx` of `kind` on `place`:
    /// SO_RCVTIMEO for what receives, SO_SNDTIMEO for what sends, the linger
    /// time of a close.
    fn limit(&mut self, idx: usize, kind: Kind, place: usize) {
        let sock = &self.socks[place];
        let ns = match kind {
            Kind::Accept | Kind::Recv => u64::from(sock.rcvtimeo) * 1_000_000,
            Kind::Send | Kind::Connect => u64::from(sock.sndtimeo) * 1_000_000,
            Kind::Linger => u64::from(sock.linger & 0xFFFF) * 1_000_000_000,
            Kind::Watch | Kind::Epoll => 0,
        };
        let bit = 1u128 << idx;
        self.expired &= !bit;
        self.timed &= !bit;
        if ns != 0 {
            self.op_deadline[idx] = now_ns().saturating_add(ns);
            self.timed |= bit;
            self.deadline_new = true;
        }
    }

    /// The place a call names, or the answer that refuses it; a take on a
    /// description that closed meanwhile ends its operation.
    fn locate(&mut self, s: &mut Sess, d: u32, key: Option<u64>) -> Result<usize, Answer> {
        match self.find(&s.data.held, d) {
            Some(place) => Ok(place),
            None => {
                if let Some(key) = key {
                    self.finish_op(s, key);
                }
                Err(refuse(proto_net::BAD_FD))
            }
        }
    }

    /// Ends the operation of a start that was ready or failed at once, or
    /// of a take, and answers `answer`.
    fn done(&mut self, s: &mut Sess, key: Option<u64>, answer: Answer) -> Answer {
        if let Some(key) = key {
            self.finish_op(s, key);
        }
        self.step_due = true;
        answer
    }

    /// The call `call` of the session `s`.
    pub fn call(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        call: Call<'_>,
    ) -> Answer {
        let now = now_ns();
        // The group of the description has work for the next pass of sending.
        let touching = match call {
            Call::Listen { description, .. }
            | Call::Connect { description, .. }
            | Call::Accept { description, .. }
            | Call::Send { description, .. }
            | Call::Recv { description, .. }
            | Call::SendCell { description, .. }
            | Call::RecvCell { description, .. }
            | Call::Shutdown { description, .. }
            | Call::Close { description, .. }
            | Call::SetOpt { description, .. } => Some(description),
            _ => None,
        };
        let touched = touching.and_then(|d| self.find(&s.data.held, d));
        if let Some(place) = touched {
            self.touch(place);
        }
        #[cfg(feature = "probe")]
        {
            self.in_request = true;
        }
        let answer = self.dispatch(stack, s, r, call, now);
        #[cfg(feature = "probe")]
        {
            self.in_request = false;
        }
        // A request that changed a place with records brings what the service
        // knows of its events up to date: a read that took the last byte must
        // not leave the place reported readable.
        if let Some(place) = touched
            && self.interest.watched(place)
        {
            let ev = self.events(stack, place, now);
            self.interest.scan(place, ev);
            self.wake_wanted |= self.interest.due != 0;
        }
        answer
    }

    fn dispatch(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        call: Call<'_>,
        now: u64,
    ) -> Answer {
        match call {
            Call::Socket {
                family,
                kind,
                flags,
            } => self.socket(stack, s, r, family, kind, flags),
            Call::Bind {
                description,
                address,
            } => self.bind(stack, s, r, description, address),
            Call::Listen {
                description,
                backlog,
            } => self.listen(stack, s, description, backlog),
            Call::Connect {
                key,
                description,
                address,
            } => self.connect(stack, s, r, key, description, address, now),
            Call::Accept {
                key,
                description,
                flags,
            } => self.accept(stack, s, r, key, description, flags),
            Call::Send {
                key,
                description,
                flags,
                address,
                data,
            } => self.send(
                stack,
                s,
                r,
                key,
                description,
                flags,
                address,
                Out::Bytes(data),
                now,
            ),
            Call::Recv {
                key,
                description,
                flags,
                most,
            } => self.recv(
                stack,
                s,
                r,
                key,
                description,
                flags,
                most as usize,
                Into::Reply,
                now,
            ),
            Call::SendCell {
                key,
                description,
                flags,
                address,
                offset,
                len,
            } => match self.cell(s, offset, len) {
                Ok(at) => self.send(
                    stack,
                    s,
                    r,
                    key,
                    description,
                    flags,
                    address,
                    Out::Cell(at, len as usize),
                    now,
                ),
                Err(c) => self.done(s, key, refuse(c)),
            },
            Call::RecvCell {
                key,
                description,
                flags,
                most,
                offset,
            } => match self.cell(s, offset, most) {
                Ok(at) => self.recv(
                    stack,
                    s,
                    r,
                    key,
                    description,
                    flags,
                    most as usize,
                    Into::Cell(at, most as usize),
                    now,
                ),
                Err(c) => self.done(s, key, refuse(c)),
            },
            Call::Shutdown { description, how } => self.shutdown(stack, s, description, how, now),
            Call::Close {
                description,
                linger,
            } => self.close_call(stack, s, r, description, linger),
            Call::CloseTake(key) => self.close_take(stack, s, r, key),
            Call::Export { description } => self.export(s, r, description),
            Call::Adopt => self.adopt_pass(stack, s, r),
            Call::GetOpt { description, name } => {
                let Some(place) = self.find(&s.data.held, description) else {
                    return refuse(proto_net::BAD_FD);
                };
                if name == opt::NREAD {
                    return self.readable(stack, r, place);
                }
                if name == opt::HOME {
                    return word(r, u32::from(self.instance));
                }
                if name == opt::CALLS {
                    return word(r, self.counters.calls as u32);
                }
                if name == opt::BUFFERS || name == opt::BUFFERED {
                    #[cfg(any(feature = "profile", feature = "probe", feature = "trace"))]
                    if name == opt::BUFFERED {
                        self.profile_due = true;
                    }
                    return word(r, self.buffers_word(name));
                }
                match self.option(place, name) {
                    Some(value) => word(r, value),
                    None => refuse(proto_net::NO_OPTION),
                }
            }
            Call::SetOpt {
                description,
                name,
                value,
            } => self.set_option(stack, s, description, name, value),
            Call::Name { description, which } => {
                let Some(place) = self.find(&s.data.held, description) else {
                    return refuse(proto_net::BAD_FD);
                };
                let peer = match which {
                    sockets::OWN_NAME => false,
                    sockets::PEER_NAME => true,
                    _ => return refuse(proto_net::INVALID),
                };
                self.sync(stack, place, now);
                let sock = self.socks[place];
                let connected = sock.conn == Conn::Done || sock.peer.is_some();
                if peer && !connected {
                    return refuse(proto_net::NOT_CONNECTED);
                }
                match self.name(stack, place, peer) {
                    Some(address) => match sockets::write_name(r.reply(), &address) {
                        Ok(()) => Answer::Reply(Outgoing::new()),
                        Err(status) => Answer::Status(status),
                    },
                    None => refuse(proto_net::NOT_CONNECTED),
                }
            }
            Call::Watch(set) => self.watch_start(stack, s, r, set, now),
            Call::WatchTake(key) => self.watch_keyed(stack, s, r, key, false, now),
            Call::WatchCancel(key) => self.watch_keyed(stack, s, r, key, true, now),
            Call::EpollSet { set, list } => self.epoll_set(stack, s, r, set, list.as_slice(), now),
            Call::EpollDrop(set) => self.epoll_drop(s, set),
            Call::EpollWait {
                key,
                set,
                most,
                flags,
            } => self.epoll_wait(s, r, key, set, most as usize, flags),
            Call::Abandon => {
                // The sets go with the operations (an exec closes the
                // descriptors of epoll before it).
                if self.interest.sets_of(s.label()) != 0 {
                    self.interest.drop_sets_of(s.label());
                    self.cleanup_wanted = true;
                }
                self.release_ops(&mut s.data.long);
                // The new image starts without a shared buffer.
                self.drop_buffer(s);
                match sockets::write_abandoned(r.reply(), s.data.long.count() as u32) {
                    Ok(()) => Answer::Reply(Outgoing::new()),
                    Err(status) => Answer::Status(status),
                }
            }
            Call::Clone(list) => self.clone_session(s, r, list.as_slice()),
            Call::CloneMore { birth, list } => self.clone_more(s, birth, list.as_slice()),
            Call::Cancel(key) => {
                self.finish_op(s, key);
                long_answer(r, long::Reply::Cancelled)
            }
        }
    }

    // ----- CLOSE -----

    /// CLOSE: the session lets go of the description. With `CLOSE_MAY_WAIT`
    /// the reply is a long one: READY, or WAIT k when the session was the last
    /// to hold a stream with a linger time whose data is not acknowledged yet.
    fn close_call(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        description: u32,
        linger: u32,
    ) -> Answer {
        if linger > proto_net::sockets::CLOSE_MAY_WAIT {
            return refuse(proto_net::INVALID);
        }
        let Some(place) = self.find_any(&s.data.held, description) else {
            return refuse(proto_net::BAD_FD);
        };
        let waits = linger != 0 && self.close_may_linger(place);
        let hold = self.socks[place].hold;
        s.data.held.remove(place);
        if hold != 0 {
            // The session closed a description of a group: when it was the last of that group in
            // the session, its consumer leaves the group (the switch steers no more SYNs to it).
            let mut groups = (0..).scan(0, |at, _| {
                let p = s.data.held.next(*at)?;
                *at = p + 1;
                Some(self.socks[p].hold)
            });
            self.holds.closed_by(hold, s.data.consumer, &mut groups);
        }
        self.interest.drop_place(place, Some(s.label()));
        self.release(stack, place);
        self.step_due = true;
        if linger == 0 {
            return ok();
        }
        let unacknowledged = waits
            && self.places.state(place) == State::Orphan
            && self.socks[place].handle.is_some_and(|h| {
                !matches!(
                    stack.tcp(h).state(),
                    tcp::State::FinWait2 | tcp::State::TimeWait | tcp::State::Closed
                )
            })
            && !self.socks[place].rst_pending;
        if unacknowledged {
            return self.wait(s, r, None, Kind::Linger, place, None);
        }
        long_answer(r, long::Reply::Ready(&[]))
    }

    /// Whether a close of place `place` by its last holder waits for the data
    /// to go: a stream that blocks, with a linger time above 0.
    fn close_may_linger(&self, place: usize) -> bool {
        let sock = &self.socks[place];
        sock.proto == Proto::Tcp
            && !sock.nonblock
            && !sock.listening
            && sock.linger & opt::LINGER_ON != 0
            && sock.linger & 0xFFFF != 0
            && self.places.holders(place) == 1
    }

    /// CLOSE_TAKE: the wait of a close that answered WAIT k.
    fn close_take(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        key: u64,
    ) -> Answer {
        let notify = match notify_of(r, true) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        let Some(idx) = op_index(key).filter(|_| self.ops.waits(s.label(), key)) else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        let info = self.info[idx];
        if info.key != key || info.kind != Kind::Linger {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let place = usize::from(info.place);
        let bit = 1u128 << idx;
        let over = (self.lingered | self.expired) & bit != 0
            || self.socks[place].waiters & bit == 0
            || self.linger_done(stack, place);
        if over {
            return self.done(s, Some(key), long_answer(r, long::Reply::Ready(&[])));
        }
        self.wait(s, r, Some(key), Kind::Linger, place, notify)
    }

    // ----- EXPORT, ADOPT -----

    /// EXPORT: a pass for the description, a copy of the service's channel with
    /// a label of its own that carries TRANSFER alone (no DUPLICATE, so a holder
    /// cannot make copies that keep kernel places charged to the service after
    /// the pass is spent, and no SEND), so
    /// that whoever holds it can hand it on and can ask the service for nothing.
    /// The pass holds a reference of the place until ADOPT or the last copy goes.
    fn export(&mut self, s: &mut Sess, r: &mut Request<'_>, d: u32) -> Answer {
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let Some(place) = self.find_any(&s.data.held, d) else {
            return refuse(proto_net::BAD_FD);
        };
        let Ok(label) = self.passes.make(place, s.label()) else {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        };
        let pass = sys::handle_label(&self.channel, Rights::TRANSFER, label, self.level);
        match pass {
            Ok(pass) if r.reply().u32(Status::Ok.code()).is_ok() && self.places.hold(place) => {
                Answer::Reply([pass.erase()].into())
            }
            other => {
                self.passes.end(label);
                match other {
                    Err(e) => Answer::Status(Status::Kernel(e)),
                    Ok(_) => Answer::Status(Status::Kernel(Error::LimitReached)),
                }
            }
        }
    }

    /// ADOPT: the description a pass names becomes the session's (the pass is
    /// spent and its handle closes with the request). A handle that is no pass
    /// of this service is NOT_SOCKET; a pass that was spent is BAD_FD.
    fn adopt_pass(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
    ) -> Answer {
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let Ok(pass) = r.handles.take::<Channel>(0) else {
            return refuse(proto_net::NOT_SOCKET);
        };
        let Ok(label) = sys::copy_label(&self.channel, &pass) else {
            return refuse(proto_net::NOT_SOCKET);
        };
        if !Passes::is_pass(label) {
            return refuse(proto_net::NOT_SOCKET);
        }
        let Some(place) = self.passes.end(label) else {
            return refuse(proto_net::BAD_FD);
        };
        let kind = match self.socks[place].proto {
            Proto::Tcp => sockets::STREAM,
            Proto::Udp => sockets::DGRAM,
        };
        let name = self.places.name(place);
        if s.data.held.has(place) {
            // The session has the description: the reference of the pass goes.
            self.release(stack, place);
        } else if s.data.held.count() >= OPEN_MAX {
            self.release(stack, place);
            return refuse(proto_net::MFILE);
        } else {
            // The reference of the pass becomes the session's.
            s.data.held.add(place);
        }
        match sockets::write_adopted(r.reply(), name, kind) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }

    /// The last copy of the pass `label` went: its reference of the place goes
    /// (a label that names no pass in use is none of this).
    pub fn pass_gone(&mut self, stack: &mut Stack<'static>, label: u64) -> bool {
        match self.passes.end(label) {
            Some(place) => {
                self.release(stack, place);
                self.step_due = true;
                true
            }
            None => false,
        }
    }

    // ----- SOCKET, BIND, LISTEN -----

    fn socket(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        family: u32,
        kind: u32,
        flags: u32,
    ) -> Answer {
        if family != INET {
            return refuse(proto_net::NO_FAMILY);
        }
        if flags & !sockets::NONBLOCK != 0 {
            return refuse(proto_net::INVALID);
        }
        let proto = match kind {
            sockets::STREAM => Proto::Tcp,
            sockets::DGRAM => Proto::Udp,
            _ => return refuse(proto_net::BAD_TYPE),
        };
        if s.data.held.count() >= OPEN_MAX {
            return refuse(proto_net::MFILE);
        }
        let Some(place) = self.new_place(stack, State::Live, proto) else {
            return refuse(proto_net::NO_BUFFERS);
        };
        self.socks[place].nonblock = flags & sockets::NONBLOCK != 0;
        self.places.hold(place);
        s.data.held.add(place);
        word(r, self.places.name(place))
    }

    /// The effective user of the process whose identity session the request
    /// brought, as the process service vouches for it (spec 6, 3.6); None
    /// without a session or when the service refuses it.
    fn who(&mut self, r: &mut Request<'_>) -> Option<u32> {
        if r.handles.len() != 1 {
            return None;
        }
        let identity = r.handles.take::<Channel>(0).ok()?;
        self.vouch(identity)
    }

    /// The effective user of the process of the identity session
    /// `identity`, as the process service vouches for it; None when the
    /// service refuses it.
    pub fn vouch(&mut self, identity: Handle<Channel>) -> Option<u32> {
        let notary = self.notary()?;
        let request = proto_process::Method::Vouch.header().bytes();
        let reply = sys::send_handles(notary, &request, [identity.erase()]).ok()?;
        let mut buffer = [0; MESSAGE_MAX];
        proto_process::WhoReply::read(reply.bytes(&mut buffer))
            .ok()
            .map(|who| who.credentials.euid)
    }

    fn bind(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        d: u32,
        address: Address,
    ) -> Answer {
        let Some(place) = self.find(&s.data.held, d) else {
            return refuse(proto_net::BAD_FD);
        };
        let sock = self.socks[place];
        if sock.bound || sock.listening || sock.conn != Conn::None {
            return refuse(proto_net::INVALID);
        }
        let Some(ip) = address.ipv4() else {
            return refuse(proto_net::NO_FAMILY);
        };
        let Ok(port) = u16::try_from(address.port) else {
            return refuse(proto_net::INVALID);
        };
        if !self.own_address(ip) {
            return refuse(proto_net::NO_ADDRESS);
        }
        // The identity session of the request is vouched for once: a port
        // below 1024 needs the superuser, and a shared port a user to hold it.
        let low = (1..1024).contains(&port);
        let sharing = sock.reuseport && sock.proto == Proto::Tcp;
        let uid = if low || sharing { self.who(r) } else { None };
        if low && uid != Some(0) {
            return refuse(proto_net::NOT_ALLOWED);
        }
        if sharing && uid.is_none() {
            return refuse(proto_net::NOT_ALLOWED);
        }
        let port = if port == 0 {
            match self.ephemeral(sock.proto, ip, ([0; 4], 0)) {
                Some(port) => {
                    if sharing && !self.join_group(place, ip, port, uid.unwrap_or(0)) {
                        self.ports(sock.proto).release(port);
                        return refuse(proto_net::NO_BUFFERS);
                    }
                    port
                }
                None => return refuse(proto_net::NO_ADDRESS),
            }
        } else {
            let new = Binding {
                proto: sock.proto,
                address: ip,
                port,
                listening: false,
                connected: false,
                reuse: sock.reuse,
                share_uid: sharing.then_some(uid.unwrap_or(0)),
            };
            if ports::conflicts(&new, self.bindings(port, place, !sock.reuse)) {
                return refuse(proto_net::IN_USE);
            }
            // Another instance that holds the port refuses the bind (the one port space).
            if !self.ports(sock.proto).try_hold(port) {
                return refuse(proto_net::IN_USE);
            }
            if sharing && !self.join_group(place, ip, port, uid.unwrap_or(0)) {
                self.ports(sock.proto).release(port);
                return refuse(proto_net::IN_USE);
            }
            port
        };
        if let (Proto::Udp, Some(handle)) = (sock.proto, sock.handle)
            && stack.udp(handle).bind(listen_endpoint(ip, port)).is_err()
        {
            return refuse(proto_net::IN_USE);
        }
        let sock = &mut self.socks[place];
        sock.bound = true;
        sock.uid = uid.unwrap_or(0);
        sock.port_held = true;
        sock.address = ip;
        sock.port = port;
        self.chains.link(place, port);
        let sock = &self.socks[place];
        if sock.proto == Proto::Udp {
            self.register(
                place,
                Key::Bound {
                    tcp: false,
                    address: ip,
                    port,
                },
            );
        }
        ok()
    }

    /// Puts `place`, bound to `address` and `port` with SO_REUSEPORT, in the
    /// group of that port (made by the first); false when the group is another
    /// user's or full.
    fn join_group(&mut self, place: usize, address: [u8; 4], port: u16, uid: u32) -> bool {
        // The registry has let this binding through only when every binding
        // it overlaps was made with the option by the same user.
        match self.groups.join(address, port, uid, place) {
            Ok(k) => {
                self.socks[place].group = k as u8;
                true
            }
            Err(_) => false,
        }
    }

    fn listen(&mut self, stack: &mut Stack<'static>, s: &mut Sess, d: u32, backlog: u32) -> Answer {
        let Some(place) = self.find(&s.data.held, d) else {
            return refuse(proto_net::BAD_FD);
        };
        let sock = self.socks[place];
        if sock.proto != Proto::Tcp {
            return refuse(proto_net::NOT_SUPPORTED);
        }
        if sock.listening {
            // A second `listen` with a larger backlog builds the queue up to
            // it; a smaller one changes nothing.
            let wanted = backlog.clamp(1, crate::net::BACKLOG_MAX as u32) as usize;
            while usize::from(self.socks[place].member_count) < wanted {
                let own = self.socks[place].members;
                let count = usize::from(self.socks[place].member_count);
                let Some(m) = self.member(stack, &sock, place, own, count) else {
                    break;
                };
                let listener = &mut self.socks[place];
                listener.members[usize::from(listener.member_count)] = m as u16;
                listener.member_count += 1;
                listener.room = listener.room.saturating_add(1);
            }
            return ok();
        }
        if sock.conn != Conn::None {
            return refuse(proto_net::INVALID);
        }
        if !sock.bound {
            let Some(port) = self.ephemeral(Proto::Tcp, [0; 4], ([0; 4], 0)) else {
                return refuse(proto_net::NO_ADDRESS);
            };
            self.socks[place].bound = true;
            self.socks[place].port_held = true;
            self.socks[place].port = port;
            self.chains.link(place, port);
        }
        let sock = self.socks[place];
        let wanted = backlog.clamp(1, crate::net::BACKLOG_MAX as u32) as usize;
        let mut count = 0;
        let mut members = [0u16; crate::net::BACKLOG_MAX];
        for k in 0..wanted {
            let Some(m) = self.member(stack, &sock, place, members, count) else {
                break;
            };
            members[k] = m as u16;
            count += 1;
        }
        if count == 0 {
            return refuse(proto_net::NO_BUFFERS);
        }
        if let Some(handle) = sock.handle {
            stack.drop_socket(handle);
        }
        let sock = &mut self.socks[place];
        sock.handle = None;
        sock.listening = true;
        sock.members = members;
        sock.member_count = count as u8;
        sock.room = count as u8;
        let (address, port) = (sock.address, sock.port);
        self.register(
            place,
            Key::Bound {
                tcp: true,
                address,
                port,
            },
        );
        ok()
    }

    /// A new place of the queue of the listening `sock`, whose queue stands in
    /// `own[..count]` already: a smoltcp socket that listens on its port and
    /// has its options. The queue of a member of a group stands in sets no
    /// other member's queue stands in.
    fn member(
        &mut self,
        stack: &mut Stack<'static>,
        sock: &Sock,
        listener: usize,
        own: [u16; crate::net::BACKLOG_MAX],
        count: usize,
    ) -> Option<usize> {
        let grouped = sock.group != NO_GROUP;
        let m = self.place_for(
            stack,
            State::Member,
            Proto::Tcp,
            grouped.then_some((listener, own, count)),
        )?;
        let handle = self.socks[m].handle?;
        if stack
            .tcp(handle)
            .listen(listen_endpoint(sock.address, sock.port))
            .is_err()
        {
            self.release_place(stack, m);
            return None;
        }
        let member = &mut self.socks[m];
        member.bound = true;
        member.listener = listener as u16;
        if grouped {
            member.owns_set = true;
            self.owners.claim(m / GROUP, listener);
        }
        let member = &mut self.socks[m];
        member.address = sock.address;
        member.port = sock.port;
        self.chains.link(m, sock.port);
        let member = &mut self.socks[m];
        member.nodelay = sock.nodelay;
        member.keepalive = sock.keepalive;
        member.reuse = sock.reuse;
        // As on Linux, the connections a listening description took keep its
        // SO_REUSEPORT and user, so a later member of the group may bind.
        member.reuseport = sock.reuseport;
        member.uid = sock.uid;
        member.linger = sock.linger;
        member.rcvtimeo = sock.rcvtimeo;
        member.sndtimeo = sock.sndtimeo;
        self.apply_options(stack, m);
        Some(m)
    }

    // ----- CONNECT -----

    #[allow(clippy::too_many_arguments)]
    fn connect(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        key: Option<u64>,
        d: u32,
        address: Address,
        now: u64,
    ) -> Answer {
        let notify = match notify_of(r, key.is_some()) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        let place = match self.locate(s, d, key) {
            Ok(place) => place,
            Err(answer) => return answer,
        };
        if let Some(key) = key
            && !self.op_ok(s, key, Kind::Connect, place)
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        if self.socks[place].proto == Proto::Udp {
            return self.udp_connect(stack, s, r, place, address, key);
        }
        self.sync(stack, place, now);
        let sock = self.socks[place];
        if key.is_none() {
            if sock.listening {
                return refuse(proto_net::INVALID);
            }
            match sock.conn {
                Conn::Done => return refuse(proto_net::CONNECTED),
                Conn::Connecting(_) => return refuse(proto_net::ALREADY),
                Conn::None if sock.error != 0 => {
                    let error = core::mem::take(&mut self.socks[place].error);
                    return refuse(error);
                }
                Conn::None => {}
            }
            return match self.start_connect(stack, place, address, now) {
                Ok(()) if sock.nonblock => refuse(proto_net::IN_PROGRESS),
                Ok(()) => {
                    self.step_due = true;
                    self.wait(s, r, None, Kind::Connect, place, None)
                }
                Err(c) => refuse(c),
            };
        }
        match sock.conn {
            Conn::Done => self.done(s, key, long_answer(r, long::Reply::Ready(&[]))),
            Conn::Connecting(_) => self.wait(s, r, key, Kind::Connect, place, notify),
            Conn::None => {
                let error = core::mem::take(&mut self.socks[place].error);
                let c = if error != 0 {
                    error
                } else {
                    proto_net::NOT_CONNECTED
                };
                self.done(s, key, refuse(c))
            }
        }
    }

    /// Sends the SYN of a stream to `address`.
    fn start_connect(
        &mut self,
        stack: &mut Stack<'static>,
        place: usize,
        address: Address,
        now: u64,
    ) -> Result<(), u32> {
        let remote = destination(&address)?;
        if remote.1 == 0 {
            return Err(proto_net::REFUSED);
        }
        if !is_loopback_or_own(self, remote.0) && self.external.is_none() {
            return Err(proto_net::NET_DOWN);
        }
        self.implicit_bind(stack, place, remote)?;
        let sock = self.socks[place];
        let Some(handle) = sock.handle else {
            return Err(proto_net::INVALID);
        };
        stack
            .tcp_connect(handle, remote, (sock.address, sock.port))
            .map_err(|_| proto_net::UNREACHABLE)?;
        let t = stack.tcp(handle);
        if let (Some(local), Some(remote)) = (t.local_endpoint(), t.remote_endpoint()) {
            let (local, remote) = (peer_of(local), peer_of(remote));
            self.register(
                place,
                Key::Conn {
                    local: local.0,
                    local_port: local.1,
                    remote: remote.0,
                    remote_port: remote.1,
                },
            );
        }
        stack.tcp(handle).set_timeout(Some(Duration::from_secs(
            crate::net::CONNECT_NS / 1_000_000_000,
        )));
        self.socks[place].conn = Conn::Connecting(now);
        self.rechain(place);
        self.socks[place].peer = Some(remote);
        self.connecting.set(place);
        self.step_due = true;
        Ok(())
    }

    /// An unbound socket takes an ephemeral port for its first use.
    fn implicit_bind(
        &mut self,
        stack: &mut Stack<'static>,
        place: usize,
        remote: ([u8; 4], u16),
    ) -> Result<(), u32> {
        let sock = self.socks[place];
        if sock.bound {
            return Ok(());
        }
        let local = if remote.0[0] == 127 {
            [127, 0, 0, 1]
        } else {
            [0; 4]
        };
        let port = self
            .ephemeral(sock.proto, local, remote)
            .ok_or(proto_net::NO_ADDRESS)?;
        if let (Proto::Udp, Some(handle)) = (sock.proto, sock.handle)
            && stack
                .udp(handle)
                .bind(listen_endpoint([0; 4], port))
                .is_err()
        {
            return Err(proto_net::NO_ADDRESS);
        }
        let sock = &mut self.socks[place];
        sock.bound = true;
        sock.port_held = true;
        sock.address = [0; 4];
        sock.port = port;
        self.chains.link(place, port);
        let sock = &self.socks[place];
        if sock.proto == Proto::Udp {
            self.register(
                place,
                Key::Bound {
                    tcp: false,
                    address: [0; 4],
                    port,
                },
            );
        }
        Ok(())
    }

    fn udp_connect(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        place: usize,
        address: Address,
        key: Option<u64>,
    ) -> Answer {
        let result = (|| {
            if address.family == 0 {
                // A connect to no address dissolves the association.
                self.socks[place].peer = None;
                return Ok(());
            }
            let remote = destination(&address)?;
            if remote.1 == 0 {
                return Err(proto_net::INVALID);
            }
            self.implicit_bind(stack, place, remote)?;
            self.socks[place].peer = Some(remote);
            Ok(())
        })();
        // The caller of a long operation reads its end as a reply of `long`.
        let answer = match result {
            Ok(()) => long_answer(r, long::Reply::Ready(&[])),
            Err(c) => refuse(c),
        };
        self.done(s, key, answer)
    }

    // ----- ACCEPT -----

    fn accept(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        key: Option<u64>,
        d: u32,
        flags: u32,
    ) -> Answer {
        let notify = match notify_of(r, key.is_some()) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        let place = match self.locate(s, d, key) {
            Ok(place) => place,
            Err(answer) => return answer,
        };
        if let Some(key) = key
            && !self.op_ok(s, key, Kind::Accept, place)
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        if flags & !sockets::NONBLOCK != 0 {
            return self.done(s, key, refuse(proto_net::INVALID));
        }
        let sock = self.socks[place];
        if !sock.listening {
            return self.done(s, key, refuse(proto_net::INVALID));
        }
        if s.data.held.count() >= OPEN_MAX {
            return self.done(s, key, refuse(proto_net::MFILE));
        }
        let Some(k) = self.accept_ready(stack, place) else {
            return if key.is_none() && sock.nonblock {
                refuse(proto_net::AGAIN)
            } else {
                self.wait(s, r, key, Kind::Accept, place, notify)
            };
        };
        // The member becomes the new description; another listens in its
        // place.
        let m = usize::from(sock.members[k]);
        let Some(handle) = self.socks[m].handle else {
            return self.done(s, key, refuse(proto_net::INVALID));
        };
        let peer = stack
            .tcp(handle)
            .remote_endpoint()
            .map_or(Address::NONE, |e| {
                let (ip, port) = peer_of(e);
                Address::v4(ip, u32::from(port))
            });
        let local = stack.tcp(handle).local_endpoint().map(peer_of);
        self.places.set_state(m, State::Live);
        self.touch(m);
        // The accepted socket shares the port of the listening description
        // and keeps it after that one closes.
        let shared = self.socks[m].port;
        self.ports(Proto::Tcp).hold(shared);
        self.socks[m].port_held = true;
        self.places.hold(m);
        s.data.held.add(m);
        let accepted = &mut self.socks[m];
        accepted.conn = Conn::Done;
        self.rechain(m);
        self.leave_queue(m);
        let accepted = &mut self.socks[m];
        accepted.nonblock = flags & sockets::NONBLOCK != 0;
        accepted.peer = peer.ipv4().map(|ip| (ip, peer.port as u16));
        if let Some((ip, port)) = local {
            accepted.address = ip;
            accepted.port = port;
        }
        let own = sock.members;
        let count = usize::from(sock.member_count);
        match self.member(stack, &sock, place, own, count) {
            Some(fresh) => {
                self.socks[place].members[k] = fresh as u16;
                self.socks[place].room = self.socks[place].room.saturating_add(1);
            }
            None => {
                let listener = &mut self.socks[place];
                listener.members[k] = listener.members[usize::from(listener.member_count) - 1];
                listener.member_count -= 1;
                self.counters.listen_short += 1;
            }
        }
        let mut w = Writer::new();
        let name = self.places.name(m);
        let data = match sockets::write_accepted(&mut w, name, &peer) {
            Ok(()) => long_answer(r, long::Reply::Ready(w.as_bytes())),
            Err(status) => Answer::Status(status),
        };
        self.done(s, key, data)
    }

    // ----- SEND, RECV -----

    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        key: Option<u64>,
        d: u32,
        flags: u32,
        address: Address,
        data: Out<'_>,
        now: u64,
    ) -> Answer {
        let notify = match notify_of(r, key.is_some()) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        let place = match self.locate(s, d, key) {
            Ok(place) => place,
            Err(answer) => return answer,
        };
        if let Some(key) = key
            && !self.op_ok(s, key, Kind::Send, place)
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        if flags & !sockets::DONTWAIT != 0 {
            return self.done(s, key, refuse(proto_net::INVALID));
        }
        self.sync(stack, place, now);
        let io = match (self.socks[place].proto, data) {
            (Proto::Tcp, _) => self.tcp_send(stack, place, data),
            (Proto::Udp, Out::Bytes(data)) => self.udp_send(stack, place, &address, data),
            (Proto::Udp, Out::Cell(..)) => Io::Fail(proto_net::INVALID),
        };
        match io {
            Io::Ready(n) => {
                if let Out::Cell(..) = data {
                    self.buffered += n as u64;
                    #[cfg(feature = "probe")]
                    {
                        self.counters.largest_copy = self.counters.largest_copy.max(n as u64);
                    }
                }
                let bytes = (n as u32).to_le_bytes();
                self.done(s, key, long_answer(r, long::Reply::Ready(&bytes)))
            }
            Io::Fail(c) => self.done(s, key, refuse(c)),
            Io::Block => {
                if key.is_none() && (self.socks[place].nonblock || flags & sockets::DONTWAIT != 0) {
                    refuse(proto_net::AGAIN)
                } else {
                    self.step_due = true;
                    self.wait(s, r, key, Kind::Send, place, notify)
                }
            }
        }
    }

    fn tcp_send(&mut self, stack: &mut Stack<'static>, place: usize, data: Out<'_>) -> Io<usize> {
        // Whether the interface has an address: a stream from it has not,
        // once the lease is lost.
        let external = self.external.is_some();
        let sock = &mut self.socks[place];
        let Some(handle) = sock.handle else {
            return Io::Fail(proto_net::NOT_CONNECTED);
        };
        if sock.error != 0 {
            // The error is reported once; the stream is shut after it.
            sock.shut_wr = true;
            return Io::Fail(core::mem::take(&mut sock.error));
        }
        if sock.conn != Conn::Done {
            return Io::Fail(proto_net::NOT_CONNECTED);
        }
        if sock.shut_wr {
            return Io::Fail(proto_net::PIPE);
        }
        let t = stack.tcp(handle);
        if !t.may_send() {
            return if t.state() == tcp::State::Closed && !sock.saw_fin {
                sock.shut_wr = true;
                Io::Fail(proto_net::RESET)
            } else {
                Io::Fail(proto_net::PIPE)
            };
        }
        if !external && t.local_endpoint().is_some_and(|e| peer_of(e).0[0] != 127) {
            return Io::Fail(proto_net::NET_DOWN);
        }
        let data = match data {
            Out::Bytes(data) => data,
            Out::Cell(at, len) => {
                if !t.can_send() {
                    return Io::Block;
                }
                let began = split::now();
                // SAFETY: `cell` checked that the cell of `len` bytes lies in
                // the session's mapped buffer.
                let n = unsafe { crate::cells::cell_to_queue(t, at, len) };
                split::record(split::BUF_COPY_TX, split::now() - began);
                copied(n);
                return if n == 0 { Io::Block } else { Io::Ready(n) };
            }
        };
        if data.is_empty() {
            return Io::Ready(0);
        }
        if !t.can_send() {
            return Io::Block;
        }
        match t.send_slice(data) {
            Ok(0) => Io::Block,
            Ok(n) => {
                copied(n);
                Io::Ready(n)
            }
            Err(_) => Io::Fail(proto_net::PIPE),
        }
    }

    fn udp_send(
        &mut self,
        stack: &mut Stack<'static>,
        place: usize,
        address: &Address,
        data: &[u8],
    ) -> Io<usize> {
        let sock = self.socks[place];
        let Some(handle) = sock.handle else {
            return Io::Fail(proto_net::NOT_CONNECTED);
        };
        if sock.error != 0 {
            return Io::Fail(core::mem::take(&mut self.socks[place].error));
        }
        let remote = if address.family == 0 {
            match sock.peer {
                Some(peer) => peer,
                None => return Io::Fail(proto_net::NOT_CONNECTED),
            }
        } else {
            match destination(address) {
                Ok(remote) if remote.1 != 0 => remote,
                Ok(_) => return Io::Fail(proto_net::INVALID),
                Err(c) => return Io::Fail(c),
            }
        };
        if !is_loopback_or_own(self, remote.0) && self.external.is_none() {
            return Io::Fail(proto_net::NET_DOWN);
        }
        if remote.0 == [255; 4] && !sock.broadcast {
            return Io::Fail(proto_net::NOT_ALLOWED);
        }
        if let Err(c) = self.implicit_bind(stack, place, remote) {
            return Io::Fail(c);
        }
        let u = stack.udp(handle);
        if !u.can_send() {
            return Io::Block;
        }
        match u.send_slice(data, endpoint(remote.0, remote.1)) {
            Ok(()) => Io::Ready(data.len()),
            Err(udp::SendError::BufferFull) => Io::Block,
            Err(_) => Io::Fail(proto_net::UNREACHABLE),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recv(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        key: Option<u64>,
        d: u32,
        flags: u32,
        most: usize,
        into: Into,
        now: u64,
    ) -> Answer {
        let notify = match notify_of(r, key.is_some()) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        let place = match self.locate(s, d, key) {
            Ok(place) => place,
            Err(answer) => return answer,
        };
        if let Some(key) = key
            && !self.op_ok(s, key, Kind::Recv, place)
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        if flags & !(sockets::PEEK | sockets::DONTWAIT) != 0 {
            return self.done(s, key, refuse(proto_net::INVALID));
        }
        self.sync(stack, place, now);
        let peek = flags & sockets::PEEK != 0;
        let mut buffer = [0u8; DATA_MAX];
        let io = match (self.socks[place].proto, into) {
            (Proto::Tcp, Into::Reply) => {
                self.tcp_recv(stack, place, peek, into, &mut buffer[..most])
            }
            (Proto::Tcp, Into::Cell(..)) => self.tcp_recv(stack, place, peek, into, &mut []),
            (Proto::Udp, Into::Reply) => self.udp_recv(stack, place, peek, &mut buffer[..most]),
            (Proto::Udp, Into::Cell(..)) => Io::Fail(proto_net::INVALID),
        };
        match io {
            Io::Ready((n, truncated, from)) => {
                let mut w = Writer::new();
                let flags = if truncated { sockets::OUT_TRUNC } else { 0 };
                let written = match into {
                    Into::Reply => sockets::write_received(&mut w, flags, &from, &buffer[..n]),
                    Into::Cell(..) => {
                        self.buffered += n as u64;
                        #[cfg(feature = "probe")]
                        {
                            self.counters.largest_copy = self.counters.largest_copy.max(n as u64);
                        }
                        sockets::write_received_count(&mut w, flags, &from, n as u32)
                    }
                };
                let answer = match written {
                    Ok(()) => long_answer(r, long::Reply::Ready(w.as_bytes())),
                    Err(status) => Answer::Status(status),
                };
                self.done(s, key, answer)
            }
            Io::Fail(c) => self.done(s, key, refuse(c)),
            Io::Block => {
                if key.is_none() && (self.socks[place].nonblock || flags & sockets::DONTWAIT != 0) {
                    refuse(proto_net::AGAIN)
                } else {
                    self.wait(s, r, key, Kind::Recv, place, notify)
                }
            }
        }
    }

    /// Bytes of a stream: how many, whether the datagram was cut (never for a
    /// stream) and from whom.
    fn tcp_recv(
        &mut self,
        stack: &mut Stack<'static>,
        place: usize,
        peek: bool,
        into: Into,
        buffer: &mut [u8],
    ) -> Io<(usize, bool, Address)> {
        let sock = &mut self.socks[place];
        let Some(handle) = sock.handle else {
            return Io::Fail(proto_net::NOT_CONNECTED);
        };
        if sock.error != 0 {
            sock.saw_fin = true;
            return Io::Fail(core::mem::take(&mut sock.error));
        }
        if sock.conn != Conn::Done {
            return Io::Fail(proto_net::NOT_CONNECTED);
        }
        let from = sock
            .peer
            .map_or(Address::NONE, |(ip, port)| Address::v4(ip, u32::from(port)));
        if sock.shut_rd {
            return Io::Ready((0, false, from));
        }
        let t = stack.tcp(handle);
        if let (Into::Cell(at, most), true) = (into, t.can_recv()) {
            let began = split::now();
            // SAFETY: `cell` checked that the cell of `most` bytes lies in the
            // session's mapped buffer.
            let n = unsafe { crate::cells::queue_to_cell(t, at, most, peek) };
            split::record(split::BUF_COPY_RX, split::now() - began);
            copied(n);
            return Io::Ready((n, false, from));
        }
        if t.can_recv() {
            let n = if peek {
                t.peek_slice(buffer)
            } else {
                t.recv_slice(buffer)
            };
            return match n {
                Ok(n) => {
                    copied(n);
                    Io::Ready((n, false, from))
                }
                Err(_) => Io::Fail(proto_net::RESET),
            };
        }
        if t.may_recv() {
            return Io::Block;
        }
        // No bytes and no more to come: the end of the stream, or a reset
        // (a closed stream whose peer sent no FIN).
        if t.state() == tcp::State::Closed && !sock.saw_fin && !sock.shut_wr {
            sock.saw_fin = true;
            return Io::Fail(proto_net::RESET);
        }
        Io::Ready((0, false, from))
    }

    fn udp_recv(
        &mut self,
        stack: &mut Stack<'static>,
        place: usize,
        peek: bool,
        buffer: &mut [u8],
    ) -> Io<(usize, bool, Address)> {
        let sock = self.socks[place];
        let Some(handle) = sock.handle else {
            return Io::Fail(proto_net::NOT_CONNECTED);
        };
        if sock.error != 0 {
            return Io::Fail(core::mem::take(&mut self.socks[place].error));
        }
        if !sock.bound {
            return Io::Fail(proto_net::INVALID);
        }
        if sock.shut_rd {
            return Io::Ready((0, false, Address::NONE));
        }
        let u = stack.udp(handle);
        loop {
            // Datagrams from anyone but the peer of a connected socket are
            // discarded.
            let Ok((payload, meta)) = u.peek().map(|(p, m)| (p.len(), *m)) else {
                return Io::Block;
            };
            let from = peer_of(meta.endpoint);
            if sock.peer.is_some_and(|peer| peer != from) {
                let _ = u.recv();
                continue;
            }
            let n = payload.min(buffer.len());
            if peek {
                if let Ok((bytes, _)) = u.peek() {
                    buffer[..n].copy_from_slice(&bytes[..n]);
                }
            } else if let Ok((bytes, _)) = u.recv() {
                buffer[..n].copy_from_slice(&bytes[..n]);
            }
            return Io::Ready((n, payload > n, Address::v4(from.0, u32::from(from.1))));
        }
    }

    // ----- SHUTDOWN and the options -----

    fn shutdown(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        d: u32,
        how: u32,
        now: u64,
    ) -> Answer {
        let Some(place) = self.find(&s.data.held, d) else {
            return refuse(proto_net::BAD_FD);
        };
        if how > sockets::SHUT_BOTH {
            return refuse(proto_net::INVALID);
        }
        self.sync(stack, place, now);
        let sock = self.socks[place];
        let connected = match sock.proto {
            Proto::Tcp => sock.conn == Conn::Done,
            Proto::Udp => sock.peer.is_some(),
        };
        if !connected {
            return refuse(proto_net::NOT_CONNECTED);
        }
        if how != sockets::SHUT_READ {
            if let (Proto::Tcp, Some(handle)) = (sock.proto, sock.handle) {
                stack.tcp(handle).close();
            }
            self.socks[place].shut_wr = true;
        }
        if how != sockets::SHUT_WRITE {
            self.socks[place].shut_rd = true;
        }
        self.step_due = true;
        ok()
    }

    fn set_option(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        d: u32,
        name: u32,
        value: u32,
    ) -> Answer {
        let Some(place) = self.find(&s.data.held, d) else {
            return refuse(proto_net::BAD_FD);
        };
        let on = value != 0;
        let sock = &mut self.socks[place];
        match name {
            opt::REUSEADDR => sock.reuse = on,
            opt::KEEPALIVE => sock.keepalive = on,
            opt::BROADCAST => sock.broadcast = on,
            opt::NODELAY => sock.nodelay = on,
            opt::NONBLOCK => sock.nonblock = on,
            // Before BIND only: the group is made at BIND.
            opt::REUSEPORT if sock.proto == Proto::Tcp && (sock.bound || sock.listening) => {
                return refuse(proto_net::INVALID);
            }
            opt::REUSEPORT if sock.proto == Proto::Tcp => sock.reuseport = on,
            opt::LINGER => {
                if value != 0
                    && (value & opt::LINGER_ON == 0
                        || value & !opt::LINGER_ON > u32::from(u16::MAX))
                {
                    return refuse(proto_net::INVALID);
                }
                sock.linger = value;
            }
            opt::RCVTIMEO => sock.rcvtimeo = value,
            opt::SNDTIMEO => sock.sndtimeo = value,
            // The buffers have one size.
            opt::RCVBUF | opt::SNDBUF => {}
            _ => return refuse(proto_net::NO_OPTION),
        }
        // The options of a listening description are those of its queue.
        let sock = self.socks[place];
        if sock.listening {
            for k in 0..usize::from(sock.member_count) {
                let m = usize::from(sock.members[k]);
                let member = &mut self.socks[m];
                member.keepalive = sock.keepalive;
                member.nodelay = sock.nodelay;
                member.linger = sock.linger;
                member.rcvtimeo = sock.rcvtimeo;
                member.sndtimeo = sock.sndtimeo;
                self.apply_options(stack, m);
            }
        } else {
            self.apply_options(stack, place);
        }
        ok()
    }

    // ----- WATCH -----

    fn watch_ready_answer(r: &mut Request<'_>, ready: watch::Ready) -> Answer {
        let mut body = Writer::new();
        if let Err(status) = ready.write(&mut body) {
            return Answer::Status(status);
        }
        long_answer(r, long::Reply::Ready(body.as_bytes()))
    }

    fn watch_start(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        set: watch::Set,
        now: u64,
    ) -> Answer {
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let mut ready = watch::Ready {
            len: set.len,
            events: [0; watch::MAX],
        };
        for (i, item) in set.items[..set.len].iter().enumerate() {
            let Some(place) = self.find(&s.data.held, item.description) else {
                return refuse(proto_net::BAD_FD);
            };
            ready.events[i] = self.events(stack, place, now) & (item.events | watch::ALWAYS);
        }
        rt::service::step_detail(set.len as u64);
        if ready.any() {
            return Self::watch_ready_answer(r, ready);
        }
        let label = s.label();
        let key = match self.ops.start(&mut s.data.long, label) {
            Ok(key) => key,
            Err(e) => return Answer::Status(Status::Kernel(e)),
        };
        let idx = op_index(key).expect("a key the table of operations gave");
        self.told &= !(1 << idx);
        self.info[idx] = OpInfo {
            key,
            label,
            kind: Kind::Watch,
            place: 0,
        };
        self.watches[idx] = set;
        for item in &set.items[..set.len] {
            if let Some(place) = self.places.find(item.description) {
                self.socks[place].waiters |= 1 << idx;
                self.attention.set(place);
            }
        }
        long_answer(r, long::Reply::Wait(key))
    }

    fn watch_keyed(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        key: u64,
        cancel: bool,
        now: u64,
    ) -> Answer {
        let label = s.label();
        let valid = self.ops.waits(label, key)
            && op_index(key)
                .is_some_and(|idx| self.info[idx].key == key && self.info[idx].kind == Kind::Watch);
        let Some(idx) = op_index(key).filter(|_| valid) else {
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
                && !matches!(r.handles.info(0), Some((abi::ObjectKind::Channel, rights)) if rights.contains(Rights::NOTIFY))
            {
                return Answer::Status(Status::BadSize);
            }
            let notify = match notify_of(r, true) {
                Ok(notify) => notify,
                Err(answer) => return answer,
            };
            self.told &= !(1 << idx);
            match notify {
                Some(handle) => {
                    if let Err(e) = self.ops.arm(label, key, handle) {
                        return Answer::Status(Status::Kernel(e));
                    }
                }
                None => self.ops.untell(label, key),
            }
        }
        rt::service::step_detail(self.watches[idx].len as u64);
        let ready = self.watch_ready(stack, idx, now);
        if cancel {
            self.finish_op(s, key);
            Self::watch_ready_answer(r, ready)
        } else if ready.any() {
            Self::watch_ready_answer(r, ready)
        } else {
            long_answer(r, long::Reply::Armed)
        }
    }

    // ----- EPOLL -----

    /// NREAD (FIONREAD): the bytes of a stream waiting to be read, or the
    /// length of the next datagram.
    fn readable(
        &mut self,
        stack: &mut Stack<'static>,
        r: &mut Request<'_>,
        place: usize,
    ) -> Answer {
        let sock = self.socks[place];
        if sock.listening {
            return refuse(proto_net::INVALID);
        }
        let n = match (sock.proto, sock.handle) {
            (Proto::Tcp, Some(h)) => stack.tcp(h).recv_queue(),
            (Proto::Udp, Some(h)) => stack.udp(h).peek().map_or(0, |(p, _)| p.len()),
            _ => 0,
        };
        word(r, n as u32)
    }

    /// The code of a record's refusal.
    fn epoll_code(refused: netd::interest::Refused) -> u32 {
        use netd::interest::Refused;
        match refused {
            Refused::NoSpace => proto_net::NO_SPACE,
            Refused::Exists => proto_net::EXISTS,
            Refused::NoEntry => proto_net::NO_ENTRY,
        }
    }

    /// One record of EPOLL_SET: 0 or the code of its refusal.
    fn epoll_record(
        &mut self,
        stack: &mut Stack<'static>,
        s: &Sess,
        set: usize,
        record: &EpollRecord,
        now: u64,
    ) -> u32 {
        let Some(place) = self.find(&s.data.held, record.description) else {
            return proto_net::BAD_FD;
        };
        let result = match record.action {
            sockets::EPOLL_DEL => self.interest.delete(set, place),
            sockets::EPOLL_ADD | sockets::EPOLL_MOD => {
                // EPOLLEXCLUSIVE: ADD only, with the events Linux allows with it.
                let exclusive = record.events & epoll::EXCLUSIVE != 0;
                let allowed = epoll::IN | epoll::OUT | epoll::ERR | epoll::HUP | epoll::ET;
                let known = epoll::EVENTS | epoll::ET | epoll::ONESHOT | epoll::EXCLUSIVE;
                if record.events & !known != 0
                    || (exclusive
                        && (record.action != sockets::EPOLL_ADD
                            || record.events & !(allowed | epoll::EXCLUSIVE) != 0))
                {
                    return proto_net::INVALID;
                }
                let ev = self.events(stack, place, now);
                let done = if record.action == sockets::EPOLL_ADD {
                    self.interest
                        .add(set, place, record.events, record.label, ev)
                        .map(drop)
                } else {
                    self.interest
                        .modify(set, place, record.events, record.label, ev)
                };
                if done.is_ok() {
                    self.attention.set(place);
                }
                done
            }
            _ => return proto_net::INVALID,
        };
        result.err().map_or(0, Self::epoll_code)
    }

    /// EPOLL_SET: the records of a set of the session (a set of its own is
    /// made when `wire` is 0). The request wakes nobody: a set with ready
    /// records and waiting operations is left to the step of waking.
    fn epoll_set(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
        r: &mut Request<'_>,
        wire: u32,
        records: &[EpollRecord],
        now: u64,
    ) -> Answer {
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let label = s.label();
        let set = if wire == 0 {
            match self.interest.new_set(label) {
                Some(k) => k,
                None => return Answer::Status(Status::Kernel(Error::LimitReached)),
            }
        } else {
            match self.interest.find_set(label, wire) {
                Some(k) => k,
                None => return refuse(proto_net::BAD_FD),
            }
        };
        let mut statuses = [0u32; sockets::EPOLL_BATCH];
        for (status, record) in statuses.iter_mut().zip(records) {
            *status = self.epoll_record(stack, s, set, record, now);
        }
        rt::service::step_detail(records.len() as u64);
        self.wake_wanted |= self.interest.due != 0;
        let wire = self.interest.wire(set);
        match sockets::write_epoll_set(r.reply(), wire, &statuses[..records.len()]) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }

    /// EPOLL_DROP: the set goes (its records in steps); the operations that
    /// wait on it are told and find it gone.
    fn epoll_drop(&mut self, s: &mut Sess, wire: u32) -> Answer {
        let Some(set) = self.interest.find_set(s.label(), wire) else {
            return refuse(proto_net::BAD_FD);
        };
        self.closed_ops |= self.interest.drop_set(set);
        self.wake_wanted = true;
        self.cleanup_wanted = true;
        ok()
    }

    /// EPOLL_WAIT and its take: the ready records of the set, or a wait for
    /// them. Nothing leaves the lists until the answer is READY, so a
    /// cancel loses no event.
    fn epoll_wait(
        &mut self,
        s: &mut Sess,
        r: &mut Request<'_>,
        key: Option<u64>,
        wire: u32,
        most: usize,
        flags: u32,
    ) -> Answer {
        let notify = match notify_of(r, key.is_some()) {
            Ok(notify) => notify,
            Err(answer) => return answer,
        };
        let Some(set) = self.interest.find_set(s.label(), wire) else {
            if let Some(key) = key {
                self.finish_op(s, key);
            }
            return refuse(proto_net::BAD_FD);
        };
        if let Some(key) = key
            && !self.op_ok(s, key, Kind::Epoll, set)
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
        let mut ready = EpollReady::EMPTY;
        self.interest.take(set, most, &mut ready);
        rt::service::step_detail(ready.len as u64);
        if ready.len == 0 && (key.is_some() || flags & sockets::EPOLL_DONTWAIT == 0) {
            let answer = self.wait(s, r, key, Kind::Epoll, set, notify);
            // The look at the list was cut short (it is longer than the window
            // and the records seen reported nothing): records are left, and
            // nothing else would wake the wait for them.
            if self.interest.has_ready(set) {
                self.interest.due |= 1 << set;
                self.wake_wanted = true;
            }
            return answer;
        }
        let mut w = Writer::new();
        let answer = match ready.write(&mut w) {
            Ok(()) => long_answer(r, long::Reply::Ready(w.as_bytes())),
            Err(status) => Answer::Status(status),
        };
        self.done(s, key, answer)
    }

    // ----- CLONE -----

    /// CLONE: a new session of the service's own label that holds the
    /// descriptions in `list`, which the session must hold itself.
    fn clone_session(&mut self, s: &mut Sess, r: &mut Request<'_>, list: &[u32]) -> Answer {
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        let root = s.data.root;
        if self.clones.room_within(root, ROOT_CLONES).is_err() {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        }
        let mut child = Held::EMPTY;
        for &d in list {
            let Some(place) = self.find_any(&s.data.held, d) else {
                return refuse(proto_net::BAD_FD);
            };
            child.add(place);
        }
        // The room was just checked, so the label comes; its place is the
        // birth's.
        let Ok(label) = self.clones.give_within(OWN, root, ROOT_CLONES) else {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        };
        let session = sys::handle_label(
            &self.channel,
            Rights::SEND | Rights::TRANSFER,
            label,
            self.level,
        );
        let word =
            proto_net::sockets::birth_word(self.clones.place_of(label).unwrap_or(0), label >> 16);
        match session {
            Ok(session) if sockets::write_cloned(r.reply(), word).is_ok() => {
                let mut place = 0;
                while let Some(p) = child.next(place) {
                    place = p + 1;
                    self.places.hold(p);
                }
                if let Some(birth) = self.clones.place_of(label) {
                    self.births[birth] = Some((label, child, root, s.label()));
                }
                Answer::Reply([session.erase()].into())
            }
            other => {
                self.clones.gone(label);
                match other {
                    Err(e) => Answer::Status(Status::Kernel(e)),
                    Ok(_) => Answer::Status(Status::BadSize),
                }
            }
        }
    }

    /// HOME_MAKE: a new session of `root` with no descriptions, for a process whose home this
    /// instance is. Only an instance of the service sends it (the label of the handle it uses,
    /// `HOME_LABEL`, is the service's own); the session is counted with the root's clones.
    pub fn home_make(&mut self, s: &mut Sess, r: &mut Request<'_>) -> Answer {
        if s.label() != HOME_LABEL {
            return refuse(proto_net::NOT_ALLOWED);
        }
        let root = match proto_net::read_home_make(r.body()) {
            Ok(root) if r.handles.is_empty() => root,
            _ => return Answer::Status(Status::BadSize),
        };
        if self.clones.room_within(root, ROOT_CLONES).is_err() {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        }
        let Ok(label) = self.clones.give_within(OWN, root, ROOT_CLONES) else {
            return Answer::Status(Status::Kernel(Error::LimitReached));
        };
        let session = sys::handle_label(
            &self.channel,
            Rights::SEND | Rights::TRANSFER,
            label,
            self.level,
        );
        match session {
            Ok(session) => {
                // The session takes the root's name at its first request (`claim`), with
                // nothing in hand.
                if let Some(birth) = self.clones.place_of(label) {
                    self.births[birth] = Some((label, Held::EMPTY, root, s.label()));
                }
                self.counters.homed += 1;
                match sockets::write_cloned(r.reply(), 0) {
                    Ok(()) => Answer::Reply([session.erase()].into()),
                    Err(status) => Answer::Status(status),
                }
            }
            Err(e) => {
                self.clones.gone(label);
                Answer::Status(Status::Kernel(e))
            }
        }
    }

    /// CLONE_MORE: more descriptions for the birth `word` (CLONE's reply)
    /// that the calling session made and that sent nothing yet. All the
    /// descriptions are checked before the birth changes, and one the birth
    /// holds already is passed over (`netd::births`).
    fn clone_more(&mut self, s: &mut Sess, word: u32, list: &[u32]) -> Answer {
        let Ok((place, (label, mut held, root, parent))) =
            births::permitted(&self.births, word, s.label())
        else {
            return refuse(proto_net::BAD_FD);
        };
        let mut added = Held::EMPTY;
        for &d in list {
            let Some(p) = self.find_any(&s.data.held, d) else {
                return refuse(proto_net::BAD_FD);
            };
            added.add(p);
        }
        if births::fits(&held, &added, OPEN_MAX).is_err() {
            return refuse(proto_net::MFILE);
        }
        let mut at = 0;
        while let Some(p) = added.next(at) {
            at = p + 1;
            if held.add(p) {
                self.places.hold(p);
            }
        }
        self.births[place] = Some((label, held, root, parent));
        ok()
    }
}

/// Whether the address is the loopback's or the interface's own: a
/// destination that needs no route.
fn is_loopback_or_own(net: &Net, ip: [u8; 4]) -> bool {
    ip[0] == 127 || net.external == Some(ip)
}

const _: () = assert!(SESSIONS >= ROOT_CLONES);

/// The label of the handle with which an instance of the service sends HOME_MAKE to another.
pub const HOME_LABEL: u64 = 0x484F_4D45_0000_0001;
