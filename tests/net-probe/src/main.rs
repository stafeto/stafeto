// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guest probe of the network service (`net`, services/netd, built
//! with the feature `probe`). A client of init whose roles the bytes of
//! its own arguments name, run in this order in one process:
//!
//! - `c`: CONFIG, asked again every 10 ms while the service says NET_DOWN
//!   (the lease takes a moment), at most 20 s; the line with the address,
//!   the gateway, the name server and the MAC; then 300 PINGs of the
//!   gateway, one after another, each of which must be answered (the ring
//!   of receiving holds 256 buffers, so a buffer that is never given back
//!   shows before the end), and the longest and the median round trip.
//! - `k`: CRASH of the service (no reply: the channel closes), a new
//!   session from init asked for every 10 ms until it opens, CONFIG until
//!   it answers, 10 PINGs.
//! - `b`: the registry of ports and the sessions: BIND of a port below 1024
//!   without the identity session is refused, a port taken is taken, CLONE
//!   of no descriptions gives a session, the name of a closed description
//!   is dead.
//! - `sN` (the digits are N): N places of the table at once, half of them
//!   sockets of TCP connections on the loopback that each send 64 KiB to
//!   the other end, then 50 PINGs of the gateway.
//! - `e`: the rates of the loopback through the service, 5 s each: UDP
//!   datagrams of 64 bytes, and a TCP stream in pieces of 800 bytes.
//!
//! Each check prints its line, and the last says `net-probe: ok`; xtask
//! reads them.

#![no_std]
#![no_main]

use abi::{Error, MESSAGE_MAX};
use proto_init::ServiceArgs;
use proto_net::sockets::{self, Request};
use proto_net::text::{Ip, Mac};
use proto_net::{Address, Config, Method, NET_DOWN, code};
use proto_wire::{Status, Writer, long};
use rt::handle::{Channel, Resource};
use rt::wait::Waiter;
use rt::{Handle, sys, time};

rt::entry!(main);

const RETRY_NS: u64 = 10_000_000;
const WAIT_NS: u64 = 20_000_000_000;
/// The pings of the first role, which must exceed the 256 buffers of the
/// ring of receiving, and of the role after the restart.
const PINGS: usize = 300;
const PINGS_AFTER: usize = 10;

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let own = ServiceArgs::read(start.args()).map_or(&[][..], |a| a.own);
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(level) else {
        return 1;
    };
    let Ok(waiter) = Waiter::new(&channel, 0, level) else {
        return 1;
    };
    let probe = Probe {
        parent: &start.parent,
        channel,
        waiter,
        level,
    };
    let mut result = Ok(());
    let mut session = None;
    let mut at = 0;
    while at < own.len() {
        let role = own[at];
        at += 1;
        // The digits after a role are its number.
        let mut number = 0;
        while let Some(digit) = own.get(at).filter(|b| b.is_ascii_digit()) {
            number = number * 10 + usize::from(digit - b'0');
            at += 1;
        }
        result = match role {
            b'c' => probe.configured(&mut session),
            b'k' => probe.restarted(&mut session),
            b'b' => probe.bound(),
            b's' => probe.sockets(number, &mut session),
            b'e' => probe.rates(),
            b'f' => probe.full_batch(&mut session),
            b'a' => probe.all_groups(&mut session),
            b'w' => probe.wakes(&mut session),
            _ => Err("an unknown role"),
        };
        if result.is_err() {
            break;
        }
    }
    match result {
        Ok(()) => {
            rt::println!("net-probe: ok");
            0
        }
        Err(reason) => {
            rt::println!("net-probe: failed: {reason}");
            2
        }
    }
}

struct Probe<'a> {
    parent: &'a Handle<Channel>,
    channel: Handle<Channel>,
    waiter: Waiter,
    /// The level of the probe's thread, for the handles it makes.
    level: u8,
}

/// What a request to the service came to.
#[derive(Debug, PartialEq, Eq)]
enum Fail {
    Status(Status),
    Kernel(Error),
    Bad(&'static str),
}

/// One request: the reply's bytes in `buffer`, or the refusal.
fn call<'b>(
    session: &Handle<Channel>,
    request: &[u8],
    buffer: &'b mut [u8; MESSAGE_MAX],
) -> Result<&'b [u8], Fail> {
    let reply = sys::send(session, request).map_err(Fail::Kernel)?;
    let bytes = reply.bytes(buffer);
    let word = bytes.get(..4).ok_or(Fail::Bad("a short reply"))?;
    match Status::from_code(u32::from_le_bytes([word[0], word[1], word[2], word[3]])) {
        Status::Ok => Ok(bytes),
        status => Err(Fail::Status(status)),
    }
}

fn config(session: &Handle<Channel>) -> Result<Config, Fail> {
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = call(session, &Method::Config.header().bytes(), &mut buffer)?;
    Config::read(bytes).map_err(|_| Fail::Bad("CONFIG's reply"))
}

/// PING of `target`: the round-trip time in nanoseconds.
fn ping(session: &Handle<Channel>, target: [u8; 4]) -> Result<u64, Fail> {
    let mut w = Writer::new();
    proto_net::write_ping(&Address::v4(target, 0), &mut w).map_err(Fail::Status)?;
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = call(session, w.as_bytes(), &mut buffer)?;
    proto_net::read_ping_reply(bytes).map_err(|_| Fail::Bad("PING's reply"))
}

/// One request of the sockets' methods: the reply's bytes in `buffer`.
fn socket_call<'b>(
    session: &Handle<Channel>,
    request: &Request<'_>,
    buffer: &'b mut [u8; MESSAGE_MAX],
) -> Result<&'b [u8], Fail> {
    let mut w = Writer::new();
    request.write(&mut w).map_err(Fail::Status)?;
    call(session, w.as_bytes(), buffer)
}

/// The data of a READY reply.
fn ready(reply: &[u8]) -> Result<&[u8], Fail> {
    match long::Reply::read(reply) {
        Ok(long::Reply::Ready(data)) => Ok(data),
        _ => Err(Fail::Bad("a reply that is not READY")),
    }
}

fn is(fail: &Fail, c: u32) -> bool {
    matches!(fail, Fail::Status(s) if *s == code(c))
}

/// The ends of one connection through the loopback: the sessions and
/// descriptions of its client and of the socket the listener accepted, and
/// the bytes each has sent and taken.
#[derive(Clone, Copy, Default)]
struct Link {
    session: [usize; 2],
    description: [u32; 2],
    sent: [u32; 2],
    got: [u32; 2],
}

/// The connections of a role and the sessions that hold them.
struct Pairs {
    sessions: [Option<Handle<Channel>>; SESSIONS_MAX],
    held: [usize; SESSIONS_MAX],
    links: [Link; PAIRS_MAX],
    listeners: [(usize, u32); PAIRS_MAX],
    count: usize,
}

/// The most places the role `s` fills, in the pairs of 4 places.
const PAIRS_MAX: usize = 64;
/// The sessions the role may need: 3 descriptions a pair, 64 a session.
const SESSIONS_MAX: usize = 8;
/// The bytes each end of a connection sends in the role `s`.
const STREAM: u32 = 64 * 1024;
const PIECE: usize = 800;
const PINGS_ROLE_S: usize = 50;
/// The pause after an answer AGAIN: a millisecond (under -icount it costs
/// no time of the host), none in the rates, which spin.
const PAUSE_NS: u64 = 1_000_000;

/// The byte at `offset` of the stream in direction `dir`.
fn pattern(dir: usize, offset: u32) -> u8 {
    (offset as u8).wrapping_mul(7).wrapping_add(dir as u8 * 91)
}

impl Probe<'_> {
    /// `f` again while it answers AGAIN, with a pause of `pause` ns between.
    fn nonblocking<T>(
        &self,
        pause: u64,
        mut f: impl FnMut() -> Result<T, Fail>,
    ) -> Result<T, Fail> {
        loop {
            match f() {
                Err(fail) if is(&fail, proto_net::AGAIN) => self.sleep(pause),
                other => return other,
            }
        }
    }

    fn sleep(&self, ns: u64) {
        let deadline = time::ticks_to_ns(time::now()).saturating_add(ns);
        while let Ok(rt::wait::Waited::Got(_)) = self.waiter.receive_until(&self.channel, deadline)
        {
        }
    }

    fn now(&self) -> u64 {
        time::ticks_to_ns(time::now())
    }

    /// A session with the service, asked for until init gives one.
    fn connect(&self) -> Result<Handle<Channel>, &'static str> {
        let end = self.now().saturating_add(WAIT_NS);
        loop {
            match rt::service::connect(self.parent, "net") {
                Ok(session) => return Ok(session),
                Err(_) if self.now() < end => self.sleep(RETRY_NS),
                Err(_) => return Err("connect to net"),
            }
        }
    }

    /// CONFIG until the service has an address.
    fn address(&self, session: &Handle<Channel>) -> Result<Config, &'static str> {
        let end = self.now().saturating_add(WAIT_NS);
        loop {
            match config(session) {
                Ok(config) => return Ok(config),
                Err(Fail::Status(status)) if status == code(NET_DOWN) && self.now() < end => {
                    self.sleep(RETRY_NS)
                }
                Err(Fail::Status(status)) if status == code(NET_DOWN) => {
                    return Err("no address in 20 s");
                }
                Err(_) => return Err("CONFIG refused"),
            }
        }
    }

    fn print_config(&self, prefix: &str, c: &Config) {
        let gateway = c.gateway.unwrap_or([0; 4]);
        let dns = c.dns.unwrap_or([0; 4]);
        rt::println!(
            "net-probe: {prefix}config {}/{} gw {} dns {} mac {}",
            Ip(c.address),
            c.prefix,
            Ip(gateway),
            Ip(dns),
            Mac(c.mac)
        );
    }

    /// Role `c`.
    fn configured(&self, session: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        let net = self.connect()?;
        let c = self.address(&net)?;
        self.print_config("", &c);
        let gateway = c.gateway.ok_or("the lease has no gateway")?;
        let mut rtts = [0u64; PINGS];
        for rtt in &mut rtts {
            *rtt = ping(&net, gateway).map_err(|_| "a PING of the gateway failed")?;
        }
        rt::println!("net-probe: ping {} ok {PINGS}", Ip(gateway));
        let max = rtts.iter().copied().max().unwrap_or(0);
        rtts.sort_unstable();
        rt::println!(
            "net-probe: ping rtt max {} us median {} us",
            max / 1000,
            rtts[PINGS / 2] / 1000
        );
        *session = Some(net);
        Ok(())
    }

    /// Role `k`.
    fn restarted(&self, session: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        let old = match session.take() {
            Some(old) => old,
            None => self.connect()?,
        };
        // The service ends with a fault and answers nothing.
        match sys::send(&old, &Method::Crash.header().bytes()) {
            Err(Error::PeerClosed) => {}
            _ => return Err("CRASH was answered"),
        }
        rt::println!("net-probe: the service was killed");
        // The old session leads to a closed channel.
        match config(&old) {
            Err(Fail::Kernel(Error::PeerClosed)) => {}
            _ => return Err("the old session still answers"),
        }
        drop(old);
        let net = self.connect()?;
        let c = self.address(&net)?;
        self.print_config("after restart ", &c);
        let gateway = c.gateway.ok_or("the lease has no gateway")?;
        for _ in 0..PINGS_AFTER {
            ping(&net, gateway).map_err(|_| "a PING after the restart failed")?;
        }
        rt::println!(
            "net-probe: after restart ping {} ok {PINGS_AFTER}",
            Ip(gateway)
        );
        *session = Some(net);
        Ok(())
    }
}

/// The sockets' side of the probe: every description is nonblocking, and an
/// answer AGAIN is met with a pause of a millisecond.
impl Probe<'_> {
    fn new_socket(&self, net: &Handle<Channel>, kind: u32) -> Result<u32, Fail> {
        let mut buffer = [0; MESSAGE_MAX];
        let request = Request::Socket {
            family: proto_net::INET,
            kind,
            flags: sockets::NONBLOCK,
        };
        let reply = socket_call(net, &request, &mut buffer)?;
        sockets::read_word(reply).map_err(Fail::Status)
    }

    fn plain(&self, net: &Handle<Channel>, request: Request<'_>) -> Result<(), Fail> {
        let mut buffer = [0; MESSAGE_MAX];
        socket_call(net, &request, &mut buffer).map(|_| ())
    }

    fn bind(&self, net: &Handle<Channel>, d: u32, ip: [u8; 4], port: u32) -> Result<(), Fail> {
        self.plain(
            net,
            Request::Bind {
                description: d,
                address: Address::v4(ip, port),
            },
        )
    }

    fn close(&self, net: &Handle<Channel>, d: u32) -> Result<(), Fail> {
        self.plain(
            net,
            Request::Close {
                description: d,
                linger: 0,
            },
        )
    }

    /// A new session of the service with no descriptions.
    fn clone_empty(&self, net: &Handle<Channel>) -> Result<Handle<Channel>, Fail> {
        self.clone_with(net, &[])
    }

    /// A new session that holds the descriptions in `list`.
    fn clone_with(&self, net: &Handle<Channel>, list: &[u32]) -> Result<Handle<Channel>, Fail> {
        let request = Request::Clone(sockets::List::new(list).ok_or(Fail::Bad("a list"))?);
        let mut w = Writer::new();
        request.write(&mut w).map_err(Fail::Status)?;
        let mut reply = sys::send(net, w.as_bytes()).map_err(Fail::Kernel)?;
        let mut buffer = [0; MESSAGE_MAX];
        let bytes = reply.bytes(&mut buffer);
        match bytes.get(..4) {
            Some(word) if word == [0; 4] => {}
            _ => return Err(Fail::Bad("CLONE refused")),
        }
        reply
            .handles
            .take::<Channel>(0)
            .map_err(|_| Fail::Bad("CLONE gave no session"))
    }

    /// Role `b`.
    fn bound(&self) -> Result<(), &'static str> {
        let net = self.connect()?;
        let tcp = |net: &Handle<Channel>| {
            self.new_socket(net, sockets::STREAM)
                .map_err(|_| "SOCKET failed")
        };
        let first = tcp(&net)?;
        match self.bind(&net, first, [0; 4], 80) {
            Err(fail) if is(&fail, proto_net::NOT_ALLOWED) => {}
            _ => return Err("BIND of port 80 without the identity session was not refused"),
        }
        self.bind(&net, first, [0; 4], 8080)
            .map_err(|_| "BIND of port 8080 failed")?;
        let second = tcp(&net)?;
        match self.bind(&net, second, [0; 4], 8080) {
            Err(fail) if is(&fail, proto_net::IN_USE) => {}
            _ => return Err("the second BIND of port 8080 was not refused"),
        }
        // 127.0.0.1 meets 0.0.0.0 on the same port.
        match self.bind(&net, second, [127, 0, 0, 1], 8080) {
            Err(fail) if is(&fail, proto_net::IN_USE) => {}
            _ => return Err("BIND of 127.0.0.1:8080 next to 0.0.0.0:8080 was not refused"),
        }
        // A session of CLONE has its own descriptions, none of the first's.
        let child = self.clone_empty(&net).map_err(|_| "CLONE failed")?;
        let child_socket = tcp(&child)?;
        match self.close(&child, first) {
            Err(fail) if is(&fail, proto_net::BAD_FD) => {}
            _ => return Err("a session closed a description it never held"),
        }
        self.close(&child, child_socket)
            .map_err(|_| "CLOSE in the new session failed")?;
        // A name of another generation, and a name closed twice.
        let other_generation = first ^ (1 << sockets::SLOT_BITS);
        match self.close(&net, other_generation) {
            Err(fail) if is(&fail, proto_net::BAD_FD) => {}
            _ => return Err("CLOSE of another generation was not refused"),
        }
        self.close(&net, first).map_err(|_| "CLOSE failed")?;
        match self.close(&net, first) {
            Err(fail) if is(&fail, proto_net::BAD_FD) => {}
            _ => return Err("CLOSE of a closed description was not refused"),
        }
        self.close(&net, second).map_err(|_| "CLOSE failed")?;
        // The port is free again.
        let third = tcp(&net)?;
        self.bind(&net, third, [0; 4], 8080)
            .map_err(|_| "BIND of a port after its holder closed failed")?;
        self.close(&net, third).map_err(|_| "CLOSE failed")?;
        // The first connection on the loopback after the start, which asks
        // the neighbour (ARP) through the loop: the time of its CONNECT.
        let listener = tcp(&net)?;
        self.bind(&net, listener, [127, 0, 0, 1], 8081)
            .map_err(|_| "BIND failed")?;
        self.plain(
            &net,
            Request::Listen {
                description: listener,
                backlog: 1,
            },
        )
        .map_err(|_| "LISTEN failed")?;
        let client = tcp(&net)?;
        let began = self.now();
        self.connect_wait(&net, client, Address::v4([127, 0, 0, 1], 8081))?;
        let took = self.now() - began;
        rt::println!("net-probe: loopback connect {} us", took / 1000);
        // The server end closes first, so that the stream that waits for its
        // end is in TIME-WAIT (the table may take its place back), not in a
        // state that holds it for a minute.
        let mut buffer = [0; MESSAGE_MAX];
        let len = self
            .nonblocking(PAUSE_NS, || {
                socket_call(
                    &net,
                    &Request::Accept {
                        key: None,
                        description: listener,
                        flags: sockets::NONBLOCK,
                    },
                    &mut buffer,
                )
                .map(|b| b.len())
            })
            .map_err(|_| "ACCEPT failed")?;
        let (server, _) =
            sockets::read_accepted(ready(&buffer[..len]).map_err(|_| "ACCEPT's reply")?)
                .map_err(|_| "ACCEPT's data")?;
        self.close(&net, server).map_err(|_| "CLOSE failed")?;
        self.sleep(50_000_000);
        self.close(&net, client).map_err(|_| "CLOSE failed")?;
        self.close(&net, listener).map_err(|_| "CLOSE failed")?;
        // A datagram to an address beyond the gateway leaves with the
        // external address as its source; the counters of the next CONFIG
        // would show a frame of 127.0.0.0/8 the wire refused.
        let datagram = self
            .new_socket(&net, sockets::DGRAM)
            .map_err(|_| "SOCKET failed")?;
        let send = Request::Send {
            key: None,
            description: datagram,
            flags: 0,
            address: Address::v4([192, 0, 2, 1], 9),
            data: b"beyond",
        };
        let mut buffer = [0; MESSAGE_MAX];
        socket_call(&net, &send, &mut buffer).map_err(|_| "UDP SEND beyond the gateway failed")?;
        self.sleep(50_000_000);
        self.close(&net, datagram).map_err(|_| "CLOSE failed")?;
        config(&net).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: bind ok");
        Ok(())
    }

    /// The session `n` of the role `s`, made when the one before holds 64
    /// descriptions.
    fn session_of(
        &self,
        sessions: &mut [Option<Handle<Channel>>; SESSIONS_MAX],
        held: &mut [usize; SESSIONS_MAX],
        root: &Handle<Channel>,
    ) -> Result<usize, &'static str> {
        let current = held.iter().position(|&h| h < 64).unwrap_or(SESSIONS_MAX);
        if current == SESSIONS_MAX {
            return Err("the role needs more sessions than it has");
        }
        if sessions[current].is_none() {
            sessions[current] = Some(self.clone_empty(root).map_err(|_| "CLONE failed")?);
        }
        held[current] += 1;
        Ok(current)
    }

    /// `pairs` connections on the loopback: each a listening description
    /// with a queue of one, a client and the socket it accepted, 4 places of
    /// the table. The sessions that hold them are made as they are needed.
    fn open_pairs(&self, root: &Handle<Channel>, pairs: usize) -> Result<Pairs, &'static str> {
        let mut p = Pairs {
            sessions: [const { None }; SESSIONS_MAX],
            held: [0; SESSIONS_MAX],
            links: [Link::default(); PAIRS_MAX],
            listeners: [(0, 0); PAIRS_MAX],
            count: pairs,
        };
        // The listeners, each with a queue of one: 2 places each.
        for i in 0..pairs {
            let session = self.session_of(&mut p.sessions, &mut p.held, root)?;
            // The place of the accepted socket in this session.
            p.held[session] += 1;
            let net = p.sessions[session].as_ref().ok_or("no session")?;
            let d = self
                .new_socket(net, sockets::STREAM)
                .map_err(|_| "SOCKET failed")?;
            self.bind(net, d, [127, 0, 0, 1], 9000 + i as u32)
                .map_err(|_| "BIND failed")?;
            self.plain(
                net,
                Request::Listen {
                    description: d,
                    backlog: 1,
                },
            )
            .map_err(|_| "LISTEN failed")?;
            p.listeners[i] = (session, d);
        }
        // The clients.
        for i in 0..pairs {
            let session = self.session_of(&mut p.sessions, &mut p.held, root)?;
            let net = p.sessions[session].as_ref().ok_or("no session")?;
            let d = self
                .new_socket(net, sockets::STREAM)
                .map_err(|_| "SOCKET failed")?;
            p.links[i].session[0] = session;
            p.links[i].description[0] = d;
            let address = Address::v4([127, 0, 0, 1], 9000 + i as u32);
            self.connect_wait(net, d, address)?;
        }
        // The accepted ends take the places of the queues; others listen in
        // their place.
        for i in 0..pairs {
            let (lsession, listener) = p.listeners[i];
            let net = p.sessions[lsession].as_ref().ok_or("no session")?;
            let mut buffer = [0; MESSAGE_MAX];
            let len = self
                .nonblocking(PAUSE_NS, || {
                    socket_call(
                        net,
                        &Request::Accept {
                            key: None,
                            description: listener,
                            flags: sockets::NONBLOCK,
                        },
                        &mut buffer,
                    )
                    .map(|b| b.len())
                })
                .map_err(|_| "ACCEPT failed")?;
            let reply = ready(&buffer[..len]).map_err(|_| "ACCEPT's reply")?;
            let (d, _) = sockets::read_accepted(reply).map_err(|_| "ACCEPT's data")?;
            p.links[i].session[1] = lsession;
            p.links[i].description[1] = d;
        }
        Ok(p)
    }

    /// Everything of `p` closes.
    fn close_pairs(&self, p: &Pairs) -> Result<(), &'static str> {
        for link in p.links.iter().take(p.count) {
            for end in 0..2 {
                let net = p.sessions[link.session[end]].as_ref().ok_or("no session")?;
                self.close(net, link.description[end])
                    .map_err(|_| "CLOSE failed")?;
            }
        }
        for &(session, d) in p.listeners.iter().take(p.count) {
            let net = p.sessions[session].as_ref().ok_or("no session")?;
            self.close(net, d).map_err(|_| "CLOSE failed")?;
        }
        Ok(())
    }

    /// HOLD of the service (the probe build): see proto_net.
    fn hold(&self, net: &Handle<Channel>, value: u32) -> Result<(), &'static str> {
        let mut w = Writer::new();
        proto_net::write_hold(value, &mut w).map_err(|_| "HOLD's request")?;
        let mut buffer = [0; MESSAGE_MAX];
        call(net, w.as_bytes(), &mut buffer)
            .map(|_| ())
            .map_err(|_| "HOLD refused")
    }

    /// Role `sN`: N places of the table, half of them the sockets of
    /// connections that carry data, then 50 PINGs.
    fn sockets(
        &self,
        places: usize,
        keep: &mut Option<Handle<Channel>>,
    ) -> Result<(), &'static str> {
        let pairs = places / 4;
        if pairs == 0 || pairs > PAIRS_MAX {
            return Err("the role s takes 4 to 256 places");
        }
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        let ok = self.config_ready(&root)?;
        if places >= 16 {
            self.full_clone(&root, places.min(64))?;
        }
        let mut p = self.open_pairs(&root, pairs)?;
        // Data in both directions on every connection at once.
        let mut idle_passes = 0;
        loop {
            let mut moved = false;
            let mut open = false;
            for link in p.links.iter_mut().take(pairs) {
                for end in 0..2 {
                    let net = p.sessions[link.session[end]].as_ref().ok_or("no session")?;
                    if link.sent[end] < STREAM {
                        moved |= self.push_piece(net, link, end)?;
                    }
                    if link.got[1 - end] < STREAM {
                        moved |= self.pull_piece(net, link, end)?;
                    }
                }
                open |=
                    link.sent.iter().any(|&n| n < STREAM) || link.got.iter().any(|&n| n < STREAM);
            }
            if !open {
                break;
            }
            if moved {
                idle_passes = 0;
            } else {
                idle_passes += 1;
                if idle_passes > 20_000 {
                    return Err("the connections stopped moving");
                }
                self.sleep(1_000_000);
            }
        }
        self.close_pairs(&p)?;
        for _ in 0..PINGS_ROLE_S {
            ping(&root, ok).map_err(|_| "a PING of the gateway failed")?;
        }
        // The counters of the service go to the console with CONFIG.
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: sockets {places} ok");
        *keep = Some(root);
        Ok(())
    }

    /// Role `f`: the first steps after the service lets go find the full
    /// share of sending and the full ring of the loopback. 64 connections
    /// (all 256 places), NODELAY, HOLD, 800 bytes into each, release.
    fn full_batch(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        self.config_ready(&root)?;
        let mut p = self.open_pairs(&root, PAIRS_MAX)?;
        for link in p.links.iter().take(PAIRS_MAX) {
            let net = p.sessions[link.session[0]].as_ref().ok_or("no session")?;
            self.plain(
                net,
                Request::SetOpt {
                    description: link.description[0],
                    name: sockets::opt::NODELAY,
                    value: 1,
                },
            )
            .map_err(|_| "SETOPT failed")?;
        }
        self.hold(&root, proto_net::HOLD_ON)?;
        for link in p.links.iter_mut().take(PAIRS_MAX) {
            let net = p.sessions[link.session[0]].as_ref().ok_or("no session")?;
            if !self.push_piece(net, link, 0)? {
                return Err("a SEND was not taken");
            }
        }
        self.hold(&root, proto_net::HOLD_OFF)?;
        // Every connection delivers its piece.
        let mut idle_passes = 0;
        while p
            .links
            .iter()
            .take(PAIRS_MAX)
            .any(|l| l.got[0] < PIECE as u32)
        {
            let mut moved = false;
            for link in p.links.iter_mut().take(PAIRS_MAX) {
                if link.got[0] < PIECE as u32 {
                    let net = p.sessions[link.session[1]].as_ref().ok_or("no session")?;
                    moved |= self.pull_piece(net, link, 1)?;
                }
            }
            if !moved {
                idle_passes += 1;
                if idle_passes > 20_000 {
                    return Err("the pieces did not arrive");
                }
                self.sleep(1_000_000);
            }
        }
        self.close_pairs(&p)?;
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: full batch ok");
        *keep = Some(root);
        Ok(())
    }

    /// Role `a`: every group of sockets has work at once (the effect of a
    /// change of the address or of an ARP frame), with 64 connections; the
    /// connections go on working after.
    fn all_groups(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        self.config_ready(&root)?;
        let mut p = self.open_pairs(&root, PAIRS_MAX)?;
        self.hold(&root, proto_net::HOLD_ADDRESS)?;
        self.sleep(100_000_000);
        // A piece into every connection and out of it.
        for link in p.links.iter_mut().take(PAIRS_MAX) {
            let net = p.sessions[link.session[0]].as_ref().ok_or("no session")?;
            if !self.push_piece(net, link, 0)? {
                return Err("a SEND was not taken");
            }
        }
        let mut idle_passes = 0;
        while p
            .links
            .iter()
            .take(PAIRS_MAX)
            .any(|l| l.got[0] < PIECE as u32)
        {
            let mut moved = false;
            for link in p.links.iter_mut().take(PAIRS_MAX) {
                if link.got[0] < PIECE as u32 {
                    let net = p.sessions[link.session[1]].as_ref().ok_or("no session")?;
                    moved |= self.pull_piece(net, link, 1)?;
                }
            }
            if !moved {
                idle_passes += 1;
                if idle_passes > 20_000 {
                    return Err("the pieces did not arrive");
                }
                self.sleep(1_000_000);
            }
        }
        self.close_pairs(&p)?;
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: all groups ok");
        *keep = Some(root);
        Ok(())
    }

    /// Role `w`: 16 operations wait for a datagram on one socket, armed with
    /// the handles that tell their client; one datagram arrives and the step
    /// of waking tells them in portions. All 16 are told.
    fn wakes(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        const WAITING: usize = 16;
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        self.config_ready(&root)?;
        let receiver = {
            let mut buffer = [0; MESSAGE_MAX];
            let request = Request::Socket {
                family: proto_net::INET,
                kind: sockets::DGRAM,
                flags: 0,
            };
            let reply = socket_call(&root, &request, &mut buffer).map_err(|_| "SOCKET failed")?;
            sockets::read_word(reply).map_err(|_| "SOCKET's reply")?
        };
        self.bind(&root, receiver, [127, 0, 0, 1], 9200)
            .map_err(|_| "BIND failed")?;
        let mut keys = [0u64; WAITING];
        for key in keys.iter_mut() {
            let mut buffer = [0; MESSAGE_MAX];
            let start = Request::Recv {
                key: None,
                description: receiver,
                flags: 0,
                most: PIECE as u32,
            };
            let reply = socket_call(&root, &start, &mut buffer).map_err(|_| "RECV failed")?;
            match long::Reply::read(reply) {
                Ok(long::Reply::Wait(k)) => *key = k,
                _ => return Err("RECV did not wait"),
            }
        }
        // Arm each with a handle that notifies this probe under its own label.
        for (i, key) in keys.iter().enumerate() {
            let notify = sys::handle_label(
                &self.channel,
                abi::Rights::NOTIFY | abi::Rights::TRANSFER,
                0x100 + i as u64,
                self.level,
            )
            .map_err(|_| "handle_label failed")?;
            let take = Request::Recv {
                key: Some(*key),
                description: receiver,
                flags: 0,
                most: PIECE as u32,
            };
            let mut w = Writer::new();
            take.write(&mut w).map_err(|_| "RECV's request")?;
            let reply = sys::send_handles(&root, w.as_bytes(), [notify.erase()])
                .map_err(|_| "RECV's take failed")?;
            let mut buffer = [0; MESSAGE_MAX];
            match long::Reply::read(reply.bytes(&mut buffer)) {
                Ok(long::Reply::Armed) => {}
                _ => return Err("RECV was not armed"),
            }
        }
        // The datagram.
        let sender = self
            .new_socket(&root, sockets::DGRAM)
            .map_err(|_| "SOCKET failed")?;
        let mut buffer = [0; MESSAGE_MAX];
        let send = Request::Send {
            key: None,
            description: sender,
            flags: 0,
            address: Address::v4([127, 0, 0, 1], 9200),
            data: b"wake",
        };
        socket_call(&root, &send, &mut buffer).map_err(|_| "SEND failed")?;
        // All 16 are told.
        let mut told = 0u32;
        let end = self.now() + 5_000_000_000;
        while told.count_ones() < WAITING as u32 {
            match self.waiter.receive_until(&self.channel, end) {
                Ok(rt::wait::Waited::Got(sys::Received::Notification {
                    source: abi::Source::Session,
                    label,
                    bits,
                    ..
                })) if bits & 1 != 0 && (0x100..0x100 + WAITING as u64).contains(&label) => {
                    told |= 1 << (label - 0x100);
                }
                Ok(rt::wait::Waited::Got(_)) => {}
                _ => return Err("not all the operations were told"),
            }
        }
        for key in keys {
            let mut w = Writer::new();
            Request::Cancel(key)
                .write(&mut w)
                .map_err(|_| "CANCEL's request")?;
            let mut buffer = [0; MESSAGE_MAX];
            call(&root, w.as_bytes(), &mut buffer).map_err(|_| "CANCEL failed")?;
        }
        self.close(&root, sender).map_err(|_| "CLOSE failed")?;
        self.close(&root, receiver).map_err(|_| "CLOSE failed")?;
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: wakes ok {WAITING}");
        *keep = Some(root);
        Ok(())
    }

    /// CLONE of a session that holds `count` descriptions, 64 the most it
    /// may: the child holds them as the parent does and lets go of them in
    /// steps when it ends. The longest step of the method (kind 19) is this
    /// one, at 64.
    fn full_clone(&self, net: &Handle<Channel>, count: usize) -> Result<(), &'static str> {
        let mut all = [0u32; 64];
        for d in &mut all[..count] {
            *d = self
                .new_socket(net, sockets::DGRAM)
                .map_err(|_| "SOCKET failed")?;
        }
        let list = &all[..count];
        let child = self.clone_with(net, list).map_err(|_| "CLONE failed")?;
        // The child's first request takes its descriptions.
        let mut buffer = [0; MESSAGE_MAX];
        let name = Request::Name {
            description: list[count - 1],
            which: sockets::OWN_NAME,
        };
        socket_call(&child, &name, &mut buffer)
            .map_err(|_| "the clone does not hold its descriptions")?;
        for &d in list {
            self.close(net, d).map_err(|_| "CLOSE failed")?;
        }
        // The child's end lets go of the rest in steps; the places come back.
        drop(child);
        self.sleep(200_000_000);
        Ok(())
    }

    /// The gateway of the lease, waited for.
    fn config_ready(&self, net: &Handle<Channel>) -> Result<[u8; 4], &'static str> {
        let c = self.address(net)?;
        c.gateway.ok_or("the lease has no gateway")
    }

    /// CONNECT of a nonblocking socket, repeated until it is done.
    fn connect_wait(
        &self,
        net: &Handle<Channel>,
        d: u32,
        address: Address,
    ) -> Result<(), &'static str> {
        let mut passes = 0;
        loop {
            let mut buffer = [0; MESSAGE_MAX];
            let request = Request::Connect {
                key: None,
                description: d,
                address,
            };
            match socket_call(net, &request, &mut buffer) {
                Err(fail) if is(&fail, proto_net::CONNECTED) => return Ok(()),
                Err(fail) if is(&fail, proto_net::IN_PROGRESS) || is(&fail, proto_net::ALREADY) => {
                    passes += 1;
                    if passes > 20_000 {
                        return Err("CONNECT did not finish");
                    }
                    self.sleep(1_000_000);
                }
                _ => return Err("CONNECT failed"),
            }
        }
    }

    /// Sends the next piece of the end's stream; true when bytes went.
    fn push_piece(
        &self,
        net: &Handle<Channel>,
        link: &mut Link,
        end: usize,
    ) -> Result<bool, &'static str> {
        let mut data = [0u8; PIECE];
        let n = (STREAM - link.sent[end]).min(PIECE as u32) as usize;
        for (i, byte) in data[..n].iter_mut().enumerate() {
            *byte = pattern(end, link.sent[end] + i as u32);
        }
        let mut buffer = [0; MESSAGE_MAX];
        let request = Request::Send {
            key: None,
            description: link.description[end],
            flags: 0,
            address: Address::NONE,
            data: &data[..n],
        };
        match socket_call(net, &request, &mut buffer) {
            Ok(reply) => {
                let taken = sockets::read_sent(ready(reply).map_err(|_| "SEND's reply")?)
                    .map_err(|_| "SEND's data")?;
                link.sent[end] += taken;
                Ok(taken > 0)
            }
            Err(fail) if is(&fail, proto_net::AGAIN) => Ok(false),
            Err(_) => Err("SEND failed"),
        }
    }

    /// Takes the next piece the other end sent to this end; true when bytes
    /// came, and they are the bytes that were sent.
    fn pull_piece(
        &self,
        net: &Handle<Channel>,
        link: &mut Link,
        end: usize,
    ) -> Result<bool, &'static str> {
        let from = 1 - end;
        let mut buffer = [0; MESSAGE_MAX];
        let request = Request::Recv {
            key: None,
            description: link.description[end],
            flags: 0,
            most: PIECE as u32,
        };
        match socket_call(net, &request, &mut buffer) {
            Ok(reply) => {
                let data = ready(reply).map_err(|_| "RECV's reply")?;
                let (_, _, bytes) = sockets::read_received(data).map_err(|_| "RECV's data")?;
                for (i, &byte) in bytes.iter().enumerate() {
                    if byte != pattern(from, link.got[from] + i as u32) {
                        return Err("a byte of a stream is not the byte that was sent");
                    }
                }
                link.got[from] += bytes.len() as u32;
                Ok(!bytes.is_empty())
            }
            Err(fail) if is(&fail, proto_net::AGAIN) => Ok(false),
            Err(_) => Err("RECV failed"),
        }
    }

    /// Role `e`: the rates of the loopback through the service.
    fn rates(&self) -> Result<(), &'static str> {
        let net = self.connect()?;
        let seconds = 5;
        // UDP: a datagram of 64 bytes to a bound socket, and its receipt.
        let receiver = self
            .new_socket(&net, sockets::DGRAM)
            .map_err(|_| "SOCKET failed")?;
        self.bind(&net, receiver, [127, 0, 0, 1], 9100)
            .map_err(|_| "BIND failed")?;
        let sender = self
            .new_socket(&net, sockets::DGRAM)
            .map_err(|_| "SOCKET failed")?;
        let data = [0xA5u8; 64];
        let end = self.now() + seconds * 1_000_000_000;
        let mut count = 0u64;
        while self.now() < end {
            let mut buffer = [0; MESSAGE_MAX];
            let send = Request::Send {
                key: None,
                description: sender,
                flags: 0,
                address: Address::v4([127, 0, 0, 1], 9100),
                data: &data,
            };
            socket_call(&net, &send, &mut buffer).map_err(|_| "UDP SEND failed")?;
            let recv = Request::Recv {
                key: None,
                description: receiver,
                flags: 0,
                most: 64,
            };
            let got = self.nonblocking(0, || {
                let mut buffer = [0; MESSAGE_MAX];
                socket_call(&net, &recv, &mut buffer).map(|b| b.len())
            });
            got.map_err(|_| "UDP RECV failed")?;
            count += 1;
        }
        rt::println!("net-probe: echo udp {} pps", count / seconds);
        self.close(&net, sender).map_err(|_| "CLOSE failed")?;
        self.close(&net, receiver).map_err(|_| "CLOSE failed")?;
        // TCP: one connection, pieces of 800 bytes one way.
        let listener = self
            .new_socket(&net, sockets::STREAM)
            .map_err(|_| "SOCKET failed")?;
        self.bind(&net, listener, [127, 0, 0, 1], 9101)
            .map_err(|_| "BIND failed")?;
        self.plain(
            &net,
            Request::Listen {
                description: listener,
                backlog: 1,
            },
        )
        .map_err(|_| "LISTEN failed")?;
        let client = self
            .new_socket(&net, sockets::STREAM)
            .map_err(|_| "SOCKET failed")?;
        self.connect_wait(&net, client, Address::v4([127, 0, 0, 1], 9101))?;
        let mut buffer = [0; MESSAGE_MAX];
        let len = self
            .nonblocking(PAUSE_NS, || {
                socket_call(
                    &net,
                    &Request::Accept {
                        key: None,
                        description: listener,
                        flags: sockets::NONBLOCK,
                    },
                    &mut buffer,
                )
                .map(|b| b.len())
            })
            .map_err(|_| "ACCEPT failed")?;
        let (server, _) =
            sockets::read_accepted(ready(&buffer[..len]).map_err(|_| "ACCEPT's reply")?)
                .map_err(|_| "ACCEPT's data")?;
        let data = [0x5Au8; PIECE];
        let end = self.now() + seconds * 1_000_000_000;
        let mut bytes = 0u64;
        while self.now() < end {
            let mut buffer = [0; MESSAGE_MAX];
            let send = Request::Send {
                key: None,
                description: client,
                flags: 0,
                address: Address::NONE,
                data: &data,
            };
            match socket_call(&net, &send, &mut buffer) {
                Ok(_) => {}
                Err(fail) if is(&fail, proto_net::AGAIN) => {}
                Err(_) => return Err("TCP SEND failed"),
            }
            let recv = Request::Recv {
                key: None,
                description: server,
                flags: 0,
                most: PIECE as u32,
            };
            let mut buffer = [0; MESSAGE_MAX];
            match socket_call(&net, &recv, &mut buffer) {
                Ok(reply) => {
                    let data = ready(reply).map_err(|_| "RECV's reply")?;
                    let (_, _, got) = sockets::read_received(data).map_err(|_| "RECV's data")?;
                    bytes += got.len() as u64;
                }
                Err(fail) if is(&fail, proto_net::AGAIN) => {}
                Err(_) => return Err("TCP RECV failed"),
            }
        }
        rt::println!(
            "net-probe: echo tcp {}.{} MB/s",
            bytes / seconds / 1_000_000,
            bytes / seconds / 100_000 % 10
        );
        Ok(())
    }
}
