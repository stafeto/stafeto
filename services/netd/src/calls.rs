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
use crate::stack::{Stack, listen_endpoint};
use abi::{Error, MESSAGE_MAX, Rights};
use netd::places::{Held, State};
use netd::ports::{self, Binding, Proto};
use proto_net::sockets::{self, Request as Call, opt};
use proto_net::{Address, DATA_MAX, INET, code};
use proto_wire::{Status, Writer, long, watch};
use rt::handle::{Channel, Handle, Outgoing};
use rt::service::{Answer, Request, Session};
use rt::sys;
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Duration;
use smoltcp::wire::{IpAddress, IpEndpoint};

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
        if let Some((_, held, root)) = self
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
        birth.map(|(_, held, _)| held)
    }

    /// The operations of a session go (it went, or ABANDON).
    pub fn abandon(&mut self, s: &mut Sess) {
        self.ops.gone(&mut s.data.long);
    }

    /// The operation `key` of the session is over.
    fn finish_op(&mut self, s: &mut Sess, key: u64) {
        let label = s.label();
        if self.ops.finish(&mut s.data.long, label, key) {
            self.forget_op(op_index(key));
        }
    }

    /// Whether `key` is an operation of `kind` of the session, on place `place`.
    fn op_ok(&self, s: &Sess, key: u64, kind: Kind, place: usize) -> bool {
        let info = self.info[op_index(key)];
        self.ops.waits(s.label(), key)
            && info.key == key
            && info.kind == kind
            && usize::from(info.place) == place
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
                self.info[op_index(key)] = OpInfo {
                    key,
                    label,
                    kind,
                    place: place as u16,
                };
                self.socks[place].waiters |= 1 << op_index(key);
                self.attention.set(place);
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
            } => self.send(stack, s, r, key, description, flags, address, data, now),
            Call::Recv {
                key,
                description,
                flags,
                most,
            } => self.recv(stack, s, r, key, description, flags, most as usize, now),
            Call::Shutdown { description, how } => self.shutdown(stack, s, description, how, now),
            Call::Close {
                description,
                linger,
            } => {
                if linger != 0 {
                    return refuse(proto_net::INVALID);
                }
                let Some(place) = self.find(&s.data.held, description) else {
                    return refuse(proto_net::BAD_FD);
                };
                s.data.held.remove(place);
                self.release(stack, place);
                self.step_due = true;
                ok()
            }
            Call::GetOpt { description, name } => {
                let Some(place) = self.find(&s.data.held, description) else {
                    return refuse(proto_net::BAD_FD);
                };
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
            Call::Abandon => {
                self.abandon(s);
                ok()
            }
            Call::Clone(list) => self.clone_session(s, r, list.as_slice()),
            Call::Cancel(key) => {
                self.finish_op(s, key);
                long_answer(r, long::Reply::Cancelled)
            }
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

    /// Whether the request brought the identity session of a process the
    /// process service vouches for as the superuser (spec 6, 3.6).
    fn vouched(&mut self, r: &mut Request<'_>) -> bool {
        if r.handles.len() != 1 {
            return false;
        }
        let Ok(identity) = r.handles.take::<Channel>(0) else {
            return false;
        };
        let Some(notary) = self.notary() else {
            return false;
        };
        let request = proto_process::Method::Vouch.header().bytes();
        let Ok(reply) = sys::send_handles(notary, &request, [identity.erase()]) else {
            return false;
        };
        let mut buffer = [0; MESSAGE_MAX];
        proto_process::WhoReply::read(reply.bytes(&mut buffer))
            .is_ok_and(|who| who.credentials.euid == 0)
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
        if (1..1024).contains(&port) && !self.vouched(r) {
            return refuse(proto_net::NOT_ALLOWED);
        }
        let port = if port == 0 {
            match self.ephemeral(sock.proto, ip, ([0; 4], 0)) {
                Some(port) => port,
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
            };
            if ports::conflicts(&new, self.bindings(place)) {
                return refuse(proto_net::IN_USE);
            }
            self.ports(sock.proto).hold(port);
            port
        };
        if let (Proto::Udp, Some(handle)) = (sock.proto, sock.handle)
            && stack.udp(handle).bind(listen_endpoint(ip, port)).is_err()
        {
            return refuse(proto_net::IN_USE);
        }
        let sock = &mut self.socks[place];
        sock.bound = true;
        sock.address = ip;
        sock.port = port;
        ok()
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
            self.socks[place].port = port;
        }
        let sock = self.socks[place];
        let wanted = backlog.clamp(1, crate::net::BACKLOG_MAX as u32) as usize;
        let mut count = 0;
        let mut members = [0u16; crate::net::BACKLOG_MAX];
        for member in members.iter_mut().take(wanted) {
            let Some(m) = self.member(stack, &sock) else {
                break;
            };
            *member = m as u16;
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
        ok()
    }

    /// A new place of the queue of the listening `sock`: a smoltcp socket
    /// that listens on its port and has its options.
    fn member(&mut self, stack: &mut Stack<'static>, sock: &Sock) -> Option<usize> {
        let m = self.new_place(stack, State::Member, Proto::Tcp)?;
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
        member.address = sock.address;
        member.port = sock.port;
        member.nodelay = sock.nodelay;
        member.keepalive = sock.keepalive;
        member.reuse = sock.reuse;
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
            return self.udp_connect(stack, s, place, address, key);
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
        stack.tcp(handle).set_timeout(Some(Duration::from_secs(
            crate::net::CONNECT_NS / 1_000_000_000,
        )));
        self.socks[place].conn = Conn::Connecting(now);
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
        sock.address = [0; 4];
        sock.port = port;
        Ok(())
    }

    fn udp_connect(
        &mut self,
        stack: &mut Stack<'static>,
        s: &mut Sess,
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
        let answer = match result {
            Ok(()) => ok(),
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
        self.places.hold(m);
        s.data.held.add(m);
        let accepted = &mut self.socks[m];
        accepted.conn = Conn::Done;
        accepted.nonblock = flags & sockets::NONBLOCK != 0;
        accepted.peer = peer.ipv4().map(|ip| (ip, peer.port as u16));
        if let Some((ip, port)) = local {
            accepted.address = ip;
            accepted.port = port;
        }
        match self.member(stack, &sock) {
            Some(fresh) => self.socks[place].members[k] = fresh as u16,
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
        data: &[u8],
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
        let io = match self.socks[place].proto {
            Proto::Tcp => self.tcp_send(stack, place, data),
            Proto::Udp => self.udp_send(stack, place, &address, data),
        };
        match io {
            Io::Ready(n) => {
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

    fn tcp_send(&mut self, stack: &mut Stack<'static>, place: usize, data: &[u8]) -> Io<usize> {
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
        if data.is_empty() {
            return Io::Ready(0);
        }
        if !t.can_send() {
            return Io::Block;
        }
        match t.send_slice(data) {
            Ok(0) => Io::Block,
            Ok(n) => Io::Ready(n),
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
        let io = match self.socks[place].proto {
            Proto::Tcp => self.tcp_recv(stack, place, peek, &mut buffer[..most]),
            Proto::Udp => self.udp_recv(stack, place, peek, &mut buffer[..most]),
        };
        match io {
            Io::Ready((n, truncated, from)) => {
                let mut w = Writer::new();
                let flags = if truncated { sockets::OUT_TRUNC } else { 0 };
                let written = sockets::write_received(&mut w, flags, &from, &buffer[..n]);
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
        if t.can_recv() {
            let n = if peek {
                t.peek_slice(buffer)
            } else {
                t.recv_slice(buffer)
            };
            return match n {
                Ok(n) => Io::Ready((n, false, from)),
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
        let idx = op_index(key);
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
        let idx = op_index(key);
        if !self.ops.waits(label, key)
            || self.info[idx].key != key
            || self.info[idx].kind != Kind::Watch
        {
            return Answer::Status(Status::Kernel(Error::BadState));
        }
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
            let Some(place) = self.find(&s.data.held, d) else {
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
        match session {
            Ok(session) if r.reply().u32(0).is_ok() => {
                let mut place = 0;
                while let Some(p) = child.next(place) {
                    place = p + 1;
                    self.places.hold(p);
                }
                if let Some(birth) = self.clones.place_of(label) {
                    self.births[birth] = Some((label, child, root));
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
}

/// Whether the address is the loopback's or the interface's own: a
/// destination that needs no route.
fn is_loopback_or_own(net: &Net, ip: [u8; 4]) -> bool {
    ip[0] == 127 || net.external == Some(ip)
}

const _: () = assert!(SESSIONS >= ROOT_CLONES);
