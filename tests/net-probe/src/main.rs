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
//! - `i`: the service idles for 150 s (five renewals of the neighbours) and
//!   must not have ended.
//! - `l`: blocking ACCEPT and WATCH on a listening description with a queue
//!   of 16, woken by connections that land in sockets of other groups; a
//!   listening description closed with a connection in its queue resets it;
//!   eight sessions with queues of 16 go at once.
//! - `u`: 150 echo requests of 1 472 bytes to the gateway, frames of the wire
//!   at full size in both directions, for the cost of a frame of the wire.
//! - `W`: a UDP socket on port 7000 echoes 2 000 datagrams that the host
//!   sends through a forwarded port, at 1 472 bytes each (frames of 1 514
//!   bytes on the wire); the first 800 bytes of each come back. The cost of
//!   the frames of the wire, for the choice of the portions of the steps.
//! - `C`: 1 000 datagram sockets in one session, CLONE of the first 64 and
//!   CLONE_MORE of the rest in portions of 64 (16 steps of the service, none of
//!   them longer than a portion); the new session uses the last description
//!   and a CLONE_MORE of a session that did not make the birth is refused.
//! - `A`: 16 operations wait in one session, which asks ABANDON until none is
//!   left: the service lets go of four in each answer.
//! - `r`: the timers: a PING that nobody answers ends in TIMEOUT, and a frame
//!   of the loopback that is dropped is sent again by the retransmission
//!   timer.
//!
//! Each check prints its line, and the last says `net-probe: ok`; xtask
//! reads them.

#![no_std]
#![no_main]

use abi::{Error, MESSAGE_MAX};
use proto_init::ServiceArgs;
use proto_net::sockets::{self, EpollList, EpollReady, EpollRecord, Request};
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
        told: core::cell::Cell::new(0),
        crowd: core::cell::Cell::new(0),
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
            b'i' => probe.idle(&mut session),
            b'l' => probe.listeners(&mut session),
            b'r' => probe.timers(&mut session),
            b'u' => probe.wire(&mut session),
            b'W' => probe.wire_echo(&mut session),
            b'C' => probe.clone_many(&mut session),
            b'A' => probe.abandon_many(&mut session),
            b'E' => probe.epoll_sets(&mut session),
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
    /// The labels (from TOLD_BASE) of the operations the service told.
    told: core::cell::Cell<u128>,
    /// The same for the crowd of role `w`.
    crowd: core::cell::Cell<u128>,
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

/// PING_WIRE of `target`: an echo request that fills a frame (probe builds).
fn ping_wire(session: &Handle<Channel>, target: [u8; 4]) -> Result<u64, Fail> {
    let mut w = Writer::new();
    proto_net::write_ping_wire(&Address::v4(target, 0), &mut w).map_err(Fail::Status)?;
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = call(session, w.as_bytes(), &mut buffer)?;
    proto_net::read_ping_reply(bytes).map_err(|_| Fail::Bad("PING_WIRE's reply"))
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

/// The first label of the handles that tell this probe of an operation.
const TOLD_BASE: u64 = 0x100;
/// The first label of the 128 operations that wait on one socket (role `w`).
const CROWD_BASE: u64 = 0x400;
/// The operations the crowd has: the whole table of the service.
const CROWD: usize = 128;

/// The most places the role `s` fills, in the pairs of 4 places (all 1 280).
const PAIRS_MAX: usize = 320;
/// The pairs of the roles that fill 256 places (`f`, `a`).
const PAIRS_256: usize = 64;
/// The descriptions a session of the role holds: a process holds 1 024 at
/// most, and the role spreads the connections over sessions of 64, so that
/// CLONE and the clones' labels are tried.
const SESSION_SHARE: usize = 64;
/// The sessions the role may need: 3 descriptions a pair.
const SESSIONS_MAX: usize = 16;
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
        while let Ok(rt::wait::Waited::Got(got)) =
            self.waiter.receive_until(&self.channel, deadline)
        {
            self.note(&got);
        }
    }

    /// Remembers a notification of one of the handles the probe armed
    /// operations with (labels 0x100 to 0x17f).
    fn note(&self, got: &sys::Received) {
        if let sys::Received::Notification {
            source: abi::Source::Session,
            label,
            bits,
            ..
        } = got
            && bits & 1 != 0
            && (TOLD_BASE..TOLD_BASE + 128).contains(label)
        {
            self.told.set(self.told.get() | 1 << (label - TOLD_BASE));
        }
        if let sys::Received::Notification {
            source: abi::Source::Session,
            label,
            bits,
            ..
        } = got
            && bits & 1 != 0
            && (CROWD_BASE..CROWD_BASE + CROWD as u64).contains(label)
        {
            self.crowd.set(self.crowd.get() | 1 << (label - CROWD_BASE));
        }
    }

    /// Waits up to `seconds` of the guest's time for the notification under
    /// `label`; true when it came (it may have come before).
    fn told_within(&self, label: u64, seconds: u64) -> bool {
        let end = self.now() + seconds * 1_000_000_000;
        let bit = 1u128 << (label - TOLD_BASE);
        while self.told.get() & bit == 0 {
            match self.waiter.receive_until(&self.channel, end) {
                Ok(rt::wait::Waited::Got(got)) => self.note(&got),
                _ => return false,
            }
        }
        true
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
        // A key of a long operation that no operation has, in every take: the
        // service refuses it and goes on (an index past the table once ended it).
        for key in [129u64, (5 << 32) | 200, 1 << 32, u64::MAX] {
            let takes = [
                Request::Recv {
                    key: Some(key),
                    description: first,
                    flags: 0,
                    most: 1,
                },
                Request::Send {
                    key: Some(key),
                    description: first,
                    flags: 0,
                    address: Address::NONE,
                    data: b"x",
                },
                Request::Accept {
                    key: Some(key),
                    description: first,
                    flags: 0,
                },
                Request::Connect {
                    key: Some(key),
                    description: first,
                    address: Address::v4([127, 0, 0, 1], 9),
                },
                Request::WatchTake(key),
                Request::WatchCancel(key),
            ];
            for take in &takes {
                let mut buffer = [0; MESSAGE_MAX];
                match socket_call(&net, take, &mut buffer) {
                    Err(Fail::Status(_)) => {}
                    _ => return Err("a take with a key nobody has was not refused"),
                }
            }
        }
        config(&net).map_err(|_| "the service ended at a key nobody has")?;
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
        // end is in TIME-WAIT, where the table may take its place back (a
        // stream in another state holds it for a minute).
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

    /// The session `n` of the role `s`, made when the one before holds
    /// `SESSION_SHARE` descriptions.
    fn session_of(
        &self,
        sessions: &mut [Option<Handle<Channel>>; SESSIONS_MAX],
        held: &mut [usize; SESSIONS_MAX],
        root: &Handle<Channel>,
    ) -> Result<usize, &'static str> {
        let current = held
            .iter()
            .position(|&h| h < SESSION_SHARE)
            .unwrap_or(SESSIONS_MAX);
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
            return Err("the role s takes 4 to 1280 places");
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
        let mut p = self.open_pairs(&root, PAIRS_256)?;
        for link in p.links.iter().take(PAIRS_256) {
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
        for link in p.links.iter_mut().take(PAIRS_256) {
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
            .take(PAIRS_256)
            .any(|l| l.got[0] < PIECE as u32)
        {
            let mut moved = false;
            for link in p.links.iter_mut().take(PAIRS_256) {
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
        let mut p = self.open_pairs(&root, PAIRS_256)?;
        self.hold(&root, proto_net::HOLD_ADDRESS)?;
        self.sleep(100_000_000);
        // A piece into every connection and out of it.
        for link in p.links.iter_mut().take(PAIRS_256) {
            let net = p.sessions[link.session[0]].as_ref().ok_or("no session")?;
            if !self.push_piece(net, link, 0)? {
                return Err("a SEND was not taken");
            }
        }
        let mut idle_passes = 0;
        while p
            .links
            .iter()
            .take(PAIRS_256)
            .any(|l| l.got[0] < PIECE as u32)
        {
            let mut moved = false;
            for link in p.links.iter_mut().take(PAIRS_256) {
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
        // 128 operations wait on one socket (eight sessions of 16, the whole
        // table of the service): one datagram tells them all, eight at most in
        // a step.
        let crowd = self.new_blocking(&root, sockets::DGRAM)?;
        self.bind(&root, crowd, [127, 0, 0, 1], 9203)
            .map_err(|_| "BIND failed")?;
        let mut crowd_sessions: [Option<Handle<Channel>>; 8] = [const { None }; 8];
        for (n, slot) in crowd_sessions.iter_mut().enumerate() {
            let session = self
                .clone_with(&root, &[crowd])
                .map_err(|_| "CLONE failed")?;
            for k in 0..16u64 {
                let label = CROWD_BASE + n as u64 * 16 + k;
                let start = Request::Recv {
                    key: None,
                    description: crowd,
                    flags: 0,
                    most: PIECE as u32,
                };
                let key = self.start_wait(&session, &start)?;
                let take = Request::Recv {
                    key: Some(key),
                    description: crowd,
                    flags: 0,
                    most: PIECE as u32,
                };
                self.take_armed(&session, &take, label)?;
            }
            *slot = Some(session);
        }
        let to_crowd = Request::Send {
            key: None,
            description: sender,
            flags: 0,
            address: Address::v4([127, 0, 0, 1], 9203),
            data: b"crowd",
        };
        let mut buffer = [0; MESSAGE_MAX];
        socket_call(&root, &to_crowd, &mut buffer).map_err(|_| "SEND failed")?;
        let end = self.now() + 10_000_000_000;
        while self.crowd.get() != u128::MAX {
            match self.waiter.receive_until(&self.channel, end) {
                Ok(rt::wait::Waited::Got(got)) => self.note(&got),
                _ => return Err("not all 128 operations on one socket were told"),
            }
        }
        drop(crowd_sessions);
        self.close(&root, crowd).map_err(|_| "CLOSE failed")?;
        // The operations of a session that goes leave the places they wait
        // on: a new operation with the same number is not told for them.
        let held = self.new_blocking(&root, sockets::DGRAM)?;
        self.bind(&root, held, [127, 0, 0, 1], 9201)
            .map_err(|_| "BIND failed")?;
        let child = self
            .clone_with(&root, &[held])
            .map_err(|_| "CLONE failed")?;
        let waiting = Request::Recv {
            key: None,
            description: held,
            flags: 0,
            most: PIECE as u32,
        };
        let stale = self.start_wait(&child, &waiting)?;
        let take = Request::Recv {
            key: Some(stale),
            description: held,
            flags: 0,
            most: PIECE as u32,
        };
        self.take_armed(&child, &take, TOLD_BASE + 0x10)?;
        drop(child);
        self.sleep(100_000_000);
        let other = self.new_blocking(&root, sockets::DGRAM)?;
        self.bind(&root, other, [127, 0, 0, 1], 9202)
            .map_err(|_| "BIND failed")?;
        let fresh = Request::Recv {
            key: None,
            description: other,
            flags: 0,
            most: PIECE as u32,
        };
        let fresh_key = self.start_wait(&root, &fresh)?;
        let fresh_take = Request::Recv {
            key: Some(fresh_key),
            description: other,
            flags: 0,
            most: PIECE as u32,
        };
        self.take_armed(&root, &fresh_take, TOLD_BASE + 0x11)?;
        let mut buffer = [0; MESSAGE_MAX];
        let to_held = Request::Send {
            key: None,
            description: sender,
            flags: 0,
            address: Address::v4([127, 0, 0, 1], 9201),
            data: b"stale",
        };
        socket_call(&root, &to_held, &mut buffer).map_err(|_| "SEND failed")?;
        self.sleep(300_000_000);
        if self.told.get() & (1 << 0x11) != 0 {
            return Err("an operation was told for the place of a session that went");
        }
        // The datagram did arrive where the old operation waited.
        let mut got = [0; MESSAGE_MAX];
        let peek = Request::Recv {
            key: None,
            description: held,
            flags: sockets::DONTWAIT,
            most: PIECE as u32,
        };
        let reply = socket_call(&root, &peek, &mut got).map_err(|f| {
            rt::println!("net-probe: stale recv {f:?}");
            "the datagram for the old place did not arrive"
        })?;
        let data = ready(reply).map_err(|_| "RECV's reply")?;
        let (_, _, bytes) = sockets::read_received(data).map_err(|_| "RECV's data")?;
        if bytes != b"stale" {
            return Err("the datagram for the old place arrived changed");
        }
        let mut w = Writer::new();
        Request::Cancel(fresh_key)
            .write(&mut w)
            .map_err(|_| "CANCEL's request")?;
        call(&root, w.as_bytes(), &mut buffer).map_err(|_| "CANCEL failed")?;
        self.close(&root, held).map_err(|_| "CLOSE failed")?;
        self.close(&root, other).map_err(|_| "CLOSE failed")?;
        self.close(&root, sender).map_err(|_| "CLOSE failed")?;
        self.close(&root, receiver).map_err(|_| "CLOSE failed")?;
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: wakes ok {WAITING} and {CROWD}");
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

/// The roles `i`, `l` and `r`, and the checks that the other roles share.
impl Probe<'_> {
    /// A socket that waits (no NONBLOCK).
    fn new_blocking(&self, net: &Handle<Channel>, kind: u32) -> Result<u32, &'static str> {
        let mut buffer = [0; MESSAGE_MAX];
        let request = Request::Socket {
            family: proto_net::INET,
            kind,
            flags: 0,
        };
        let reply = socket_call(net, &request, &mut buffer).map_err(|_| "SOCKET failed")?;
        sockets::read_word(reply).map_err(|_| "SOCKET's reply")
    }

    /// The long operation `request` (a start) of a blocking description:
    /// its key, WAIT k.
    fn start_wait(
        &self,
        net: &Handle<Channel>,
        request: &Request<'_>,
    ) -> Result<u64, &'static str> {
        let mut buffer = [0; MESSAGE_MAX];
        let reply = socket_call(net, request, &mut buffer).map_err(|fail| {
            rt::println!("net-probe: a start: {fail:?}");
            "a start failed"
        })?;
        match long::Reply::read(reply) {
            Ok(long::Reply::Wait(key)) => Ok(key),
            _ => Err("a start did not wait"),
        }
    }

    /// The take `request` of an operation with a handle that tells this probe
    /// under `label`: true when the service armed it, false when the result
    /// was ready at once.
    fn take_armed(
        &self,
        net: &Handle<Channel>,
        request: &Request<'_>,
        label: u64,
    ) -> Result<bool, &'static str> {
        let notify = sys::handle_label(
            &self.channel,
            abi::Rights::NOTIFY | abi::Rights::TRANSFER,
            label,
            self.level,
        )
        .map_err(|_| "handle_label failed")?;
        let mut w = Writer::new();
        request.write(&mut w).map_err(|_| "a take's request")?;
        let reply =
            sys::send_handles(net, w.as_bytes(), [notify.erase()]).map_err(|_| "a take failed")?;
        let mut buffer = [0; MESSAGE_MAX];
        match long::Reply::read(reply.bytes(&mut buffer)) {
            Ok(long::Reply::Armed) => Ok(true),
            Ok(long::Reply::Ready(_)) => Ok(false),
            _ => Err("a take was neither armed nor ready"),
        }
    }

    /// A take with no handle: the data of READY.
    fn take_ready(
        &self,
        net: &Handle<Channel>,
        request: &Request<'_>,
    ) -> Result<u32, &'static str> {
        let mut buffer = [0; MESSAGE_MAX];
        let reply = socket_call(net, request, &mut buffer).map_err(|_| "a take failed")?;
        let data = ready(reply).map_err(|_| "a take was not ready")?;
        // ACCEPT's data begins with the new description.
        Ok(data
            .get(..4)
            .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }

    /// Role `i`: 150 s of idle, in which the service renews its neighbours
    /// five times; it must answer CONFIG after and must not have restarted
    /// (the verdict counts the restarts).
    fn idle(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        self.config_ready(&root)?;
        self.sleep(150_000_000_000);
        self.config_ready(&root)?;
        rt::println!("net-probe: idle ok");
        *keep = Some(root);
        Ok(())
    }

    /// Role `l`.
    fn listeners(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        const BASE: u64 = TOLD_BASE + 0x20;
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        self.config_ready(&root)?;
        // A listening description with a queue of 16: its sockets lie in
        // several groups of the table, and the description in one of them.
        let listener = self.new_blocking(&root, sockets::STREAM)?;
        self.bind(&root, listener, [127, 0, 0, 1], 9300)
            .map_err(|_| "BIND failed")?;
        self.plain(
            &root,
            Request::Listen {
                description: listener,
                backlog: 16,
            },
        )
        .map_err(|_| "LISTEN failed")?;
        for round in 0..20u64 {
            let accept = Request::Accept {
                key: None,
                description: listener,
                flags: 0,
            };
            let key = self.start_wait(&root, &accept)?;
            let take = Request::Accept {
                key: Some(key),
                description: listener,
                flags: 0,
            };
            if !self.take_armed(&root, &take, BASE + round)? {
                return Err("ACCEPT was ready before a connection");
            }
            let client = self
                .new_socket(&root, sockets::STREAM)
                .map_err(|_| "SOCKET failed")?;
            self.plain(
                &root,
                Request::Connect {
                    key: None,
                    description: client,
                    address: Address::v4([127, 0, 0, 1], 9300),
                },
            )
            .err()
            .filter(|f| !is(f, proto_net::IN_PROGRESS))
            .map_or(Ok(()), |_| Err("CONNECT failed"))?;
            if !self.told_within(BASE + round, 5) {
                return Err("a blocking ACCEPT was not woken by a connection");
            }
            let accepted = self.take_ready(&root, &take)?;
            self.close(&root, accepted).map_err(|_| "CLOSE failed")?;
            self.close(&root, client).map_err(|_| "CLOSE failed")?;
        }
        // The same with WATCH.
        let mut set = proto_wire::watch::Set::new();
        set.len = 1;
        set.items[0] = proto_wire::watch::Item {
            description: listener,
            events: proto_wire::watch::IN,
        };
        let key = self.start_wait(&root, &Request::Watch(set))?;
        if !self.take_armed(&root, &Request::WatchTake(key), BASE + 30)? {
            return Err("WATCH was ready before a connection");
        }
        let client = self
            .new_socket(&root, sockets::STREAM)
            .map_err(|_| "SOCKET failed")?;
        let _ = self.plain(
            &root,
            Request::Connect {
                key: None,
                description: client,
                address: Address::v4([127, 0, 0, 1], 9300),
            },
        );
        if !self.told_within(BASE + 30, 5) {
            return Err("a WATCH of a listening description was not woken");
        }
        let mut w = Writer::new();
        Request::WatchCancel(key)
            .write(&mut w)
            .map_err(|_| "WATCH's request")?;
        let mut buffer = [0; MESSAGE_MAX];
        call(&root, w.as_bytes(), &mut buffer).map_err(|_| "WATCH_CANCEL failed")?;
        self.close(&root, client).map_err(|_| "CLOSE failed")?;
        // The connections in the queue are reset when the description closes:
        // each client's end hears RESET. Eight wait.
        let mut waiting = [0u32; 8];
        for w in &mut waiting {
            *w = self
                .new_socket(&root, sockets::STREAM)
                .map_err(|_| "SOCKET failed")?;
            self.connect_wait(&root, *w, Address::v4([127, 0, 0, 1], 9300))?;
        }
        self.close(&root, listener).map_err(|_| "CLOSE failed")?;
        let end = self.now() + 5_000_000_000;
        for &w in &waiting {
            loop {
                let mut buffer = [0; MESSAGE_MAX];
                let request = Request::Recv {
                    key: None,
                    description: w,
                    flags: 0,
                    most: 1,
                };
                match socket_call(&root, &request, &mut buffer) {
                    Err(fail) if is(&fail, proto_net::RESET) => break,
                    Err(fail) if is(&fail, proto_net::AGAIN) && self.now() < end => {
                        self.sleep(1_000_000)
                    }
                    _ => return Err("a client of a closed listening description was not reset"),
                }
            }
            self.close(&root, w).map_err(|_| "CLOSE failed")?;
        }
        // Eight sessions go at once, each holding eight listening descriptions
        // with a connected stream in the queue and the client's end: the
        // places come back in portions of steps, the streams with the work of
        // the table of destinations, the port and smoltcp.
        let mut sessions: [Option<Handle<Channel>>; 8] = [const { None }; 8];
        for (i, slot) in sessions.iter_mut().enumerate() {
            let session = self.clone_empty(&root).map_err(|_| "CLONE failed")?;
            for j in 0..8u32 {
                let port = 9500 + i as u32 * 8 + j;
                let d = self
                    .new_socket(&session, sockets::STREAM)
                    .map_err(|_| "SOCKET failed")?;
                self.bind(&session, d, [127, 0, 0, 1], port)
                    .map_err(|_| "BIND failed")?;
                self.plain(
                    &session,
                    Request::Listen {
                        description: d,
                        backlog: 1,
                    },
                )
                .map_err(|_| "LISTEN failed")?;
                let c = self
                    .new_socket(&session, sockets::STREAM)
                    .map_err(|_| "SOCKET failed")?;
                self.connect_wait(&session, c, Address::v4([127, 0, 0, 1], port))?;
            }
            *slot = Some(session);
        }
        drop(sessions);
        self.sleep(500_000_000);
        // The ports are free again.
        let again = self
            .new_socket(&root, sockets::STREAM)
            .map_err(|_| "SOCKET failed")?;
        self.bind(&root, again, [127, 0, 0, 1], 9500)
            .map_err(|_| "a port of a session that went is still held")?;
        self.close(&root, again).map_err(|_| "CLOSE failed")?;
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: listeners ok");
        *keep = Some(root);
        Ok(())
    }

    /// Role `r`.
    fn timers(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        self.config_ready(&root)?;
        // A PING of an address nobody answers ends by its timer, after about a
        // second.
        let began = self.now();
        match ping(&root, [10, 0, 2, 99]) {
            Err(fail) if is(&fail, proto_net::TIMEOUT) => {}
            _ => return Err("a PING of an address nobody answers did not end in TIMEOUT"),
        }
        let took = self.now() - began;
        if !(900_000_000..3_000_000_000).contains(&took) {
            return Err("a PING that nobody answers took another time than a second");
        }
        // A frame of the loopback that is dropped: the segment is sent again
        // by the retransmission timer (smoltcp waits a second at least).
        let mut p = self.open_pairs(&root, 1)?;
        self.sleep(200_000_000);
        self.hold(&root, proto_net::HOLD_DROP)?;
        let net = p.sessions[p.links[0].session[0]]
            .as_ref()
            .ok_or("no session")?;
        if !self.push_piece(net, &mut p.links[0], 0)? {
            return Err("a SEND was not taken");
        }
        let began = self.now();
        let end = began + 4_000_000_000;
        while p.links[0].got[0] < PIECE as u32 {
            let net = p.sessions[p.links[0].session[1]]
                .as_ref()
                .ok_or("no session")?;
            if !self.pull_piece(net, &mut p.links[0], 1)? {
                if self.now() > end {
                    return Err("a dropped segment was never sent again");
                }
                self.sleep(1_000_000);
            }
        }
        let after = (self.now() - began) / 1_000_000;
        self.close_pairs(&p)?;
        // One datagram on a quiet service, between sockets of two groups: the
        // blocking RECV is woken within 50 ms. Nothing else touches the group
        // of the sender, so the SEND itself must ask for its pass.
        let receiver = self.new_blocking(&root, sockets::DGRAM)?;
        self.bind(&root, receiver, [127, 0, 0, 1], 9210)
            .map_err(|_| "BIND failed")?;
        let mut spare = [0u32; 8];
        let mut sender = self
            .new_socket(&root, sockets::DGRAM)
            .map_err(|_| "SOCKET failed")?;
        let mut used = 0;
        while sockets::slot(sender) / 4 == sockets::slot(receiver) / 4 && used < spare.len() {
            spare[used] = sender;
            used += 1;
            sender = self
                .new_socket(&root, sockets::DGRAM)
                .map_err(|_| "SOCKET failed")?;
        }
        for &d in &spare[..used] {
            self.close(&root, d).map_err(|_| "CLOSE failed")?;
        }
        let waiting = Request::Recv {
            key: None,
            description: receiver,
            flags: 0,
            most: PIECE as u32,
        };
        let key = self.start_wait(&root, &waiting)?;
        let take = Request::Recv {
            key: Some(key),
            description: receiver,
            flags: 0,
            most: PIECE as u32,
        };
        self.take_armed(&root, &take, TOLD_BASE + 0x20)?;
        self.sleep(200_000_000);
        let began = self.now();
        let quiet = Request::Send {
            key: None,
            description: sender,
            flags: 0,
            address: Address::v4([127, 0, 0, 1], 9210),
            data: b"quiet",
        };
        let mut buffer = [0; MESSAGE_MAX];
        socket_call(&root, &quiet, &mut buffer).map_err(|_| "SEND failed")?;
        if !self.told_within(TOLD_BASE + 0x20, 1) || self.now() - began > 50_000_000 {
            return Err("a datagram on a quiet service did not wake its RECV within 50 ms");
        }
        self.take_ready(&root, &take)?;
        self.close(&root, sender).map_err(|_| "CLOSE failed")?;
        self.close(&root, receiver).map_err(|_| "CLOSE failed")?;
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: timers ok (a segment sent again after {after} ms)");
        *keep = Some(root);
        Ok(())
    }
}

/// The sockets role `C` makes.
const CLONE_SOCKETS: usize = 1000;

/// The port of the echo of role `W` and the datagrams it takes.
const WIRE_ECHO_PORT: u32 = 7000;
const WIRE_ECHO_COUNT: usize = 2_000;

impl Probe<'_> {
    /// Role `C`: CLONE and CLONE_MORE with 1 000 descriptions.
    fn clone_many(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        self.config_ready(&root)?;
        let mut all = [0u32; CLONE_SOCKETS];
        for d in all.iter_mut() {
            *d = self
                .new_socket(&root, sockets::DGRAM)
                .map_err(|_| "SOCKET failed")?;
        }
        // CLONE of the first portion: the birth and the session.
        let first = sockets::List::new(&all[..sockets::CLONE_MAX]).ok_or("a list")?;
        let mut w = Writer::new();
        Request::Clone(first)
            .write(&mut w)
            .map_err(|_| "CLONE's request")?;
        let mut reply = sys::send(&root, w.as_bytes()).map_err(|_| "CLONE failed")?;
        let mut buffer = [0; MESSAGE_MAX];
        let birth = sockets::read_word(reply.bytes(&mut buffer)).map_err(|_| "CLONE's reply")?;
        let child = reply
            .handles
            .take::<Channel>(0)
            .map_err(|_| "CLONE gave no session")?;
        // A session that did not make the birth may not add to it.
        let other = self.clone_empty(&root).map_err(|_| "CLONE failed")?;
        let mut portions = 1;
        for chunk in all[sockets::CLONE_MAX..].chunks(sockets::CLONE_MAX) {
            let list = sockets::List::new(chunk).ok_or("a list")?;
            if portions == 1 {
                let mut buffer = [0; MESSAGE_MAX];
                match socket_call(&other, &Request::CloneMore { birth, list }, &mut buffer) {
                    Err(fail) if is(&fail, proto_net::BAD_FD) => {}
                    other => {
                        rt::println!("net-probe: CLONE_MORE of another session's birth: {other:?}");
                        return Err("CLONE_MORE of another session's birth was not refused");
                    }
                }
            }
            self.plain(&root, Request::CloneMore { birth, list })
                .map_err(|_| "CLONE_MORE failed")?;
            portions += 1;
        }
        // The same portion again is passed over; a description the session
        // does not hold is refused and changes nothing.
        let again = sockets::List::new(&all[..4]).ok_or("a list")?;
        self.plain(&root, Request::CloneMore { birth, list: again })
            .map_err(|_| "CLONE_MORE of held descriptions failed")?;
        let stale = sockets::List::new(&[all[0] ^ (1 << sockets::SLOT_BITS)]).ok_or("a list")?;
        let mut buffer = [0; MESSAGE_MAX];
        match socket_call(
            &root,
            &Request::CloneMore { birth, list: stale },
            &mut buffer,
        ) {
            Err(fail) if is(&fail, proto_net::BAD_FD) => {}
            _ => return Err("CLONE_MORE of a description nobody holds was not refused"),
        }
        // The child uses the first and the last description.
        for d in [all[0], all[CLONE_SOCKETS - 1]] {
            self.close(&child, d)
                .map_err(|_| "the child does not hold a description")?;
        }
        drop(child);
        drop(other);
        for d in all {
            self.close(&root, d).map_err(|_| "CLOSE failed")?;
        }
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: clone ok {CLONE_SOCKETS} in {portions} portions");
        *keep = Some(root);
        Ok(())
    }

    /// Role `A`: 16 operations wait, ABANDON until none is left.
    fn abandon_many(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        const WAITING: usize = 16;
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        self.config_ready(&root)?;
        let session = self.clone_empty(&root).map_err(|_| "CLONE failed")?;
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
        self.bind(&root, receiver, [127, 0, 0, 1], 9300)
            .map_err(|_| "BIND failed")?;
        let child = self
            .clone_with(&root, &[receiver])
            .map_err(|_| "CLONE failed")?;
        for k in 0..WAITING {
            let start = Request::Recv {
                key: None,
                description: receiver,
                flags: 0,
                most: PIECE as u32,
            };
            if let Err(e) = self.start_wait(&child, &start) {
                rt::println!("net-probe: start {k} failed");
                return Err(e);
            }
        }
        let mut asked = 0;
        loop {
            let mut buffer = [0; MESSAGE_MAX];
            let reply = call(&child, &Method::Abandon.header().bytes(), &mut buffer)
                .map_err(|_| "ABANDON failed")?;
            asked += 1;
            let left = sockets::read_abandoned(reply).map_err(|_| "ABANDON's reply")?;
            if left == 0 {
                break;
            }
            if asked > WAITING {
                return Err("ABANDON does not end");
            }
        }
        if asked != WAITING / 4 {
            return Err("ABANDON did not let go of four operations in each answer");
        }
        drop(session);
        drop(child);
        self.close(&root, receiver).map_err(|_| "CLOSE failed")?;
        // A session that goes with 16 operations waiting and 8 descriptions:
        // the step of departure lets go of the operations a portion at a time,
        // then of the places.
        let mut held = [0u32; 8];
        for (i, d) in held.iter_mut().enumerate() {
            *d = self
                .new_socket(&root, sockets::DGRAM)
                .map_err(|_| "SOCKET failed")?;
            self.bind(&root, *d, [127, 0, 0, 1], 9310 + i as u32)
                .map_err(|_| "BIND failed")?;
            // new_socket makes a nonblocking socket; the operations need a
            // blocking one, which SOCKET with flags 0 gives.
        }
        let _ = held;
        let mut blocking = [0u32; 8];
        for (i, d) in blocking.iter_mut().enumerate() {
            let mut buffer = [0; MESSAGE_MAX];
            let request = Request::Socket {
                family: proto_net::INET,
                kind: sockets::DGRAM,
                flags: 0,
            };
            let reply = socket_call(&root, &request, &mut buffer).map_err(|_| "SOCKET failed")?;
            *d = sockets::read_word(reply).map_err(|_| "SOCKET's reply")?;
            self.bind(&root, *d, [127, 0, 0, 1], 9330 + i as u32)
                .map_err(|_| "BIND failed")?;
        }
        let leaving = self
            .clone_with(&root, &blocking)
            .map_err(|_| "CLONE failed")?;
        for d in blocking {
            for _ in 0..2 {
                let start = Request::Recv {
                    key: None,
                    description: d,
                    flags: 0,
                    most: PIECE as u32,
                };
                self.start_wait(&leaving, &start)?;
            }
        }
        drop(leaving);
        self.sleep(100_000_000);
        for d in blocking.iter().chain(held.iter()) {
            self.close(&root, *d).map_err(|_| "CLOSE failed")?;
        }
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: abandon ok {WAITING} in {asked} asks");
        *keep = Some(root);
        Ok(())
    }

    /// One EPOLL_SET of `records` in `set` (0 makes a set): the set.
    fn epoll_set(
        &self,
        net: &Handle<Channel>,
        set: u32,
        records: &[EpollRecord],
    ) -> Result<u32, &'static str> {
        let list = EpollList::new(records).ok_or("an epoll list")?;
        let mut buffer = [0; MESSAGE_MAX];
        let reply = socket_call(net, &Request::EpollSet { set, list }, &mut buffer)
            .map_err(|_| "EPOLL_SET refused")?;
        let mut statuses = [0u32; sockets::EPOLL_BATCH];
        let set = sockets::read_epoll_set(reply, records.len(), &mut statuses)
            .map_err(|_| "EPOLL_SET's reply")?;
        if statuses[..records.len()].iter().any(|&s| s != 0) {
            rt::println!(
                "net-probe: EPOLL_SET statuses {:?}",
                &statuses[..records.len()]
            );
            return Err("an EPOLL_SET record was refused");
        }
        Ok(set)
    }

    /// EPOLL_WAIT of `set` with `most` pairs: the pairs (a start that waits
    /// gives the key instead).
    fn epoll_wait_now(
        &self,
        net: &Handle<Channel>,
        set: u32,
        most: u32,
    ) -> Result<EpollReady, &'static str> {
        let mut buffer = [0; MESSAGE_MAX];
        let request = Request::EpollWait {
            key: None,
            set,
            most,
            flags: sockets::EPOLL_DONTWAIT,
        };
        let reply = socket_call(net, &request, &mut buffer).map_err(|_| "EPOLL_WAIT failed")?;
        EpollReady::parse(ready(reply).map_err(|_| "EPOLL_WAIT was not ready")?)
            .map_err(|_| "EPOLL_WAIT's pairs")
    }

    /// Role `E`: epoll in the service. The sets and records of sixteen
    /// places that fifteen other sessions watch (EPOLL_SET with a batch on
    /// places with fifteen records), a wait of 64 pairs after 64 stale
    /// records, the step of waking over places with records and sets with
    /// waiting operations, the drop of a set of 1 000 records and the
    /// departure of sessions with sets (the steps of CLEANUP).
    fn epoll_sets(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        const PLACES: usize = sockets::EPOLL_BATCH;
        const WATCHERS: usize = 15;
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        self.config_ready(&root)?;
        let rec = |action: u32, description: u32, events: u32, label: u32| EpollRecord {
            action,
            description,
            events,
            label,
        };
        let mut places = [0u32; PLACES];
        for (i, d) in places.iter_mut().enumerate() {
            *d = self
                .new_socket(&root, sockets::DGRAM)
                .map_err(|_| "SOCKET failed")?;
            self.bind(&root, *d, [127, 0, 0, 1], 9400 + i as u32)
                .map_err(|_| "BIND failed")?;
        }
        // Fifteen sessions, each with a set that watches every place for IN,
        // and a wait of its own that is armed.
        let mut watchers: [Option<(Handle<Channel>, u32, u64)>; WATCHERS] =
            [const { None }; WATCHERS];
        for (k, slot) in watchers.iter_mut().enumerate() {
            let session = self
                .clone_with(&root, &places)
                .map_err(|_| "CLONE failed")?;
            let mut records = [EpollRecord::default(); PLACES];
            for (i, r) in records.iter_mut().enumerate() {
                *r = rec(
                    sockets::EPOLL_ADD,
                    places[i],
                    proto_net::sockets::epoll::IN,
                    i as u32,
                );
            }
            // One record at a time, as the layer's epoll_ctl does: the
            // steps of the batches that are measured below come after these
            // and are each the longest of their kind so far.
            let mut set = 0;
            for batch in records.chunks(1) {
                set = self.epoll_set(&session, set, batch)?;
            }
            let request = Request::EpollWait {
                key: None,
                set,
                most: 64,
                flags: 0,
            };
            let key = self.start_wait(&session, &request)?;
            let take = Request::EpollWait {
                key: Some(key),
                set,
                most: 64,
                flags: 0,
            };
            if !self.take_armed(&session, &take, 700 + k as u64)? {
                return Err("a wait of a set was ready with nothing to report");
            }
            *slot = Some((session, set, key));
        }
        // The batches of 4, 8 and 16 records on places that hold fifteen
        // records each: the steps of EPOLL_SET the batch is chosen by.
        for size in [4usize, 8, 16] {
            let mut records = [EpollRecord::default(); PLACES];
            for (i, r) in records[..size].iter_mut().enumerate() {
                *r = rec(
                    sockets::EPOLL_ADD,
                    places[i],
                    proto_net::sockets::epoll::OUT,
                    i as u32,
                );
            }
            let set = self.epoll_set(&root, 0, &records[..size])?;
            for r in records[..size].iter_mut() {
                r.action = sockets::EPOLL_DEL;
            }
            self.epoll_set(&root, set, &records[..size])?;
            let mut buffer = [0; MESSAGE_MAX];
            let mut w = Writer::new();
            Request::EpollDrop(set)
                .write(&mut w)
                .map_err(|_| "EPOLL_DROP's request")?;
            call(&root, w.as_bytes(), &mut buffer).map_err(|_| "EPOLL_DROP failed")?;
            rt::println!("net-probe: epoll batch {size} ok");
        }
        // The step of waking: a datagram to each place tells the fifteen
        // waits (the set of each lists the place's record and is due).
        let sender = self
            .new_socket(&root, sockets::DGRAM)
            .map_err(|_| "SOCKET failed")?;
        self.bind(&root, sender, [127, 0, 0, 1], 9390)
            .map_err(|_| "BIND failed")?;
        for i in 0..PLACES {
            let request = Request::Send {
                key: None,
                description: sender,
                flags: 0,
                address: Address::v4([127, 0, 0, 1], 9400 + i as u32),
                data: b"e",
            };
            self.plain(&root, request).map_err(|_| "SEND failed")?;
        }
        self.sleep(200_000_000);
        for (k, slot) in watchers.iter().enumerate() {
            let Some((session, set, key)) = slot else {
                return Err("a watcher is missing");
            };
            let take = Request::EpollWait {
                key: Some(*key),
                set: *set,
                most: 64,
                flags: 0,
            };
            let mut buffer = [0; MESSAGE_MAX];
            let reply = socket_call(session, &take, &mut buffer).map_err(|_| "a take failed")?;
            let pairs = EpollReady::parse(ready(reply).map_err(|_| "a take was not ready")?)
                .map_err(|_| "a take's pairs")?;
            if pairs.len != PLACES {
                rt::println!("net-probe: watcher {k} got {} pairs", pairs.len);
                return Err("a watcher did not get a pair for each place");
            }
        }
        rt::println!("net-probe: epoll wake ok {WATCHERS}");
        // A wait of 64 pairs behind 64 records that report nothing now: 128
        // records looked at.
        let stale: [u32; 64] = core::array::from_fn(|_| 0);
        let mut stale = stale;
        let mut valid = [0u32; 64];
        for (i, d) in stale.iter_mut().enumerate() {
            *d = self
                .new_socket(&root, sockets::DGRAM)
                .map_err(|_| "SOCKET failed")?;
            self.bind(&root, *d, [127, 0, 0, 1], 9500 + i as u32)
                .map_err(|_| "BIND failed")?;
            let request = Request::Send {
                key: None,
                description: sender,
                flags: 0,
                address: Address::v4([127, 0, 0, 1], 9500 + i as u32),
                data: b"s",
            };
            self.plain(&root, request).map_err(|_| "SEND failed")?;
        }
        for (i, d) in valid.iter_mut().enumerate() {
            *d = self
                .new_socket(&root, sockets::DGRAM)
                .map_err(|_| "SOCKET failed")?;
            self.bind(&root, *d, [127, 0, 0, 1], 9600 + i as u32)
                .map_err(|_| "BIND failed")?;
        }
        self.sleep(200_000_000);
        let mut set = 0;
        for chunk in 0..4 {
            let mut records = [EpollRecord::default(); PLACES];
            for (i, r) in records.iter_mut().enumerate() {
                *r = rec(
                    sockets::EPOLL_ADD,
                    stale[chunk * PLACES + i],
                    proto_net::sockets::epoll::IN,
                    (chunk * PLACES + i) as u32,
                );
            }
            set = self.epoll_set(&root, set, &records)?;
        }
        for d in stale {
            let request = Request::Recv {
                key: None,
                description: d,
                flags: sockets::DONTWAIT,
                most: PIECE as u32,
            };
            self.plain(&root, request).map_err(|_| "RECV failed")?;
        }
        for chunk in 0..4 {
            let mut records = [EpollRecord::default(); PLACES];
            for (i, r) in records.iter_mut().enumerate() {
                *r = rec(
                    sockets::EPOLL_ADD,
                    valid[chunk * PLACES + i],
                    proto_net::sockets::epoll::OUT,
                    (100 + chunk * PLACES + i) as u32,
                );
            }
            set = self.epoll_set(&root, set, &records)?;
        }
        let pairs = self.epoll_wait_now(&root, set, 64)?;
        if pairs.len != 64 {
            rt::println!("net-probe: {} pairs", pairs.len);
            return Err("the wait did not give 64 pairs");
        }
        rt::println!("net-probe: epoll wait ok 64 after 64 stale");
        // A request that changes a place with records brings what the service
        // knows of its events up to date: a datagram taken while the steps of
        // the stack are held (no step of waking follows) leaves no stale report.
        {
            let d = self
                .new_socket(&root, sockets::DGRAM)
                .map_err(|_| "SOCKET failed")?;
            self.bind(&root, d, [127, 0, 0, 1], 9700)
                .map_err(|_| "BIND failed")?;
            let set = self.epoll_set(
                &root,
                0,
                &[rec(sockets::EPOLL_ADD, d, proto_net::sockets::epoll::IN, 1)],
            )?;
            let request = Request::Send {
                key: None,
                description: sender,
                flags: 0,
                address: Address::v4([127, 0, 0, 1], 9700),
                data: b"r",
            };
            self.plain(&root, request).map_err(|_| "SEND failed")?;
            self.sleep(100_000_000);
            self.hold(&root, proto_net::HOLD_ON)?;
            let take = Request::Recv {
                key: None,
                description: d,
                flags: sockets::DONTWAIT,
                most: PIECE as u32,
            };
            self.plain(&root, take).map_err(|_| "RECV failed")?;
            let pairs = self.epoll_wait_now(&root, set, 64);
            self.hold(&root, proto_net::HOLD_OFF)?;
            if pairs?.len != 0 {
                return Err("a place that was read was still reported");
            }
            let mut buffer = [0; MESSAGE_MAX];
            let mut w = Writer::new();
            Request::EpollDrop(set)
                .write(&mut w)
                .map_err(|_| "EPOLL_DROP's request")?;
            call(&root, w.as_bytes(), &mut buffer).map_err(|_| "EPOLL_DROP failed")?;
            self.close(&root, d).map_err(|_| "CLOSE failed")?;
        }
        // A session that lets go of a description takes its records off the
        // place, which another session still holds: 17 rounds of 64 places
        // through one set (it takes 1 024 records) never fill it.
        {
            let set = self.epoll_set(&root, 0, &[])?;
            // The holders stay until the end: the places are held all the time.
            let mut holders: [Option<Handle<Channel>>; 17] = [const { None }; 17];
            for holder in holders.iter_mut() {
                let mut group = [0u32; 64];
                for d in group.iter_mut() {
                    *d = self
                        .new_socket(&root, sockets::DGRAM)
                        .map_err(|_| "SOCKET failed")?;
                }
                *holder = Some(self.clone_with(&root, &group).map_err(|_| "CLONE failed")?);
                for chunk in group.chunks(PLACES) {
                    let mut records = [EpollRecord::default(); PLACES];
                    for (r, &d) in records.iter_mut().zip(chunk) {
                        *r = rec(sockets::EPOLL_ADD, d, proto_net::sockets::epoll::IN, 0);
                    }
                    self.epoll_set(&root, set, &records[..chunk.len()])?;
                }
                for &d in &group {
                    self.close(&root, d).map_err(|_| "CLOSE failed")?;
                }
            }
            drop(holders);
            let mut buffer = [0; MESSAGE_MAX];
            let mut w = Writer::new();
            Request::EpollDrop(set)
                .write(&mut w)
                .map_err(|_| "EPOLL_DROP's request")?;
            call(&root, w.as_bytes(), &mut buffer).map_err(|_| "EPOLL_DROP failed")?;
            rt::println!("net-probe: epoll close ok");
        }
        // A request that makes a set ready wakes nobody itself: sixteen waits
        // of one set are told by the step of waking, eight at a time, and the
        // EPOLL_SET step stays short.
        {
            let u = self
                .new_socket(&root, sockets::DGRAM)
                .map_err(|_| "SOCKET failed")?;
            let session = self.clone_with(&root, &[u]).map_err(|_| "CLONE failed")?;
            let set = self.epoll_set(&session, 0, &[])?;
            let mut keys = [0u64; 16];
            for (k, key) in keys.iter_mut().enumerate() {
                let start = Request::EpollWait {
                    key: None,
                    set,
                    most: 64,
                    flags: 0,
                };
                *key = self.start_wait(&session, &start)?;
                let take = Request::EpollWait {
                    key: Some(*key),
                    set,
                    most: 64,
                    flags: 0,
                };
                if !self.take_armed(&session, &take, 900 + k as u64)? {
                    return Err("a wait of an empty set was ready");
                }
            }
            self.epoll_set(
                &session,
                set,
                &[rec(
                    sockets::EPOLL_ADD,
                    u,
                    proto_net::sockets::epoll::OUT,
                    5,
                )],
            )?;
            self.sleep(100_000_000);
            for (k, key) in keys.iter().enumerate() {
                let take = Request::EpollWait {
                    key: Some(*key),
                    set,
                    most: 64,
                    flags: 0,
                };
                let mut buffer = [0; MESSAGE_MAX];
                let reply =
                    socket_call(&session, &take, &mut buffer).map_err(|_| "a take failed")?;
                let ready = EpollReady::parse(ready(reply).map_err(|_| "a take was not ready")?)
                    .map_err(|_| "a take's pairs")?;
                // The first take has the record; the others find it listed
                // again (by level) and report it as well.
                if ready.len == 0 {
                    rt::println!("net-probe: wait {k} of the set was told and found nothing");
                    return Err("a wait of a ready set found nothing");
                }
            }
            drop(session);
            self.close(&root, u).map_err(|_| "CLOSE failed")?;
        }
        // A set of 800 records dropped, then the sessions that watch.
        let mut big = [0u32; 800];
        let mut made = 0;
        while made < big.len() {
            let d = self
                .new_socket(&root, sockets::DGRAM)
                .map_err(|_| "SOCKET failed")?;
            big[made] = d;
            made += 1;
        }
        let mut big_set = 0;
        for chunk in big.chunks(PLACES) {
            let mut records = [EpollRecord::default(); PLACES];
            for (i, r) in records[..chunk.len()].iter_mut().enumerate() {
                *r = rec(
                    sockets::EPOLL_ADD,
                    chunk[i],
                    proto_net::sockets::epoll::OUT,
                    i as u32,
                );
            }
            big_set = self.epoll_set(&root, big_set, &records[..chunk.len()])?;
        }
        let mut buffer = [0; MESSAGE_MAX];
        let mut w = Writer::new();
        Request::EpollDrop(big_set)
            .write(&mut w)
            .map_err(|_| "EPOLL_DROP's request")?;
        call(&root, w.as_bytes(), &mut buffer).map_err(|_| "EPOLL_DROP failed")?;
        let request = Request::EpollSet {
            set: big_set,
            list: EpollList::new(&[]).ok_or("a list")?,
        };
        match socket_call(&root, &request, &mut buffer) {
            Err(fail) if is(&fail, proto_net::BAD_FD) => {}
            _ => return Err("a dropped set answered"),
        }
        for d in big {
            self.close(&root, d).map_err(|_| "CLOSE failed")?;
        }
        // The fifteen sessions go with their sets and the waits armed.
        for slot in watchers.iter_mut() {
            drop(slot.take());
        }
        self.sleep(300_000_000);
        // The sets of the sessions that went are free again: fifteen new
        // sessions make four sets each, and the root three more (it has one
        // still), which fills the 64 sets of the service and no more.
        let mut sessions: [Option<Handle<Channel>>; WATCHERS] = [const { None }; WATCHERS];
        for slot in sessions.iter_mut() {
            let session = self.clone_empty(&root).map_err(|_| "CLONE failed")?;
            for _ in 0..4 {
                self.epoll_set(&session, 0, &[])?;
            }
            *slot = Some(session);
        }
        for _ in 0..3 {
            self.epoll_set(&root, 0, &[])?;
        }
        match self.epoll_set(&root, 0, &[]) {
            Err(_) => {}
            Ok(_) => return Err("the service made a set past its 64"),
        }
        drop(sessions);
        for d in stale.iter().chain(valid.iter()).chain(places.iter()) {
            self.close(&root, *d).map_err(|_| "CLOSE failed")?;
        }
        self.close(&root, sender).map_err(|_| "CLOSE failed")?;
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: epoll ok");
        *keep = Some(root);
        Ok(())
    }

    /// Role `W`: the host's datagrams of full frames, echoed.
    fn wire_echo(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        self.config_ready(&root)?;
        let socket = self
            .new_socket(&root, sockets::DGRAM)
            .map_err(|_| "SOCKET failed")?;
        self.bind(&root, socket, [0, 0, 0, 0], WIRE_ECHO_PORT)
            .map_err(|_| "BIND failed")?;
        rt::println!("net-probe: wire echo ready {WIRE_ECHO_PORT}");
        let recv = Request::Recv {
            key: None,
            description: socket,
            flags: 0,
            most: proto_net::DATA_MAX as u32,
        };
        for _ in 0..WIRE_ECHO_COUNT {
            let end = self.now() + WAIT_NS;
            let mut buffer = [0; MESSAGE_MAX];
            let len = loop {
                match socket_call(&root, &recv, &mut buffer).map(|b| b.len()) {
                    Ok(len) => break len,
                    Err(fail) if is(&fail, proto_net::AGAIN) && self.now() < end => {
                        self.sleep(PAUSE_NS / 10)
                    }
                    Err(_) => return Err("RECV of a datagram of the host failed"),
                }
            };
            let data = ready(&buffer[..len]).map_err(|_| "RECV's reply")?;
            let (_, from, bytes) = sockets::read_received(data).map_err(|_| "RECV's data")?;
            let mut reply = [0; MESSAGE_MAX];
            let send = Request::Send {
                key: None,
                description: socket,
                flags: 0,
                address: from,
                data: bytes,
            };
            socket_call(&root, &send, &mut reply).map_err(|_| "SEND of the echo failed")?;
        }
        self.close(&root, socket).map_err(|_| "CLOSE failed")?;
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: wire echo ok {WIRE_ECHO_COUNT}");
        *keep = Some(root);
        Ok(())
    }

    /// Role `u`.
    fn wire(&self, keep: &mut Option<Handle<Channel>>) -> Result<(), &'static str> {
        let root = match keep.take() {
            Some(session) => session,
            None => self.connect()?,
        };
        let gateway = self.config_ready(&root)?;
        let mut longest = 0;
        for _ in 0..150 {
            let took =
                ping_wire(&root, gateway).map_err(|_| "a PING_WIRE of the gateway failed")?;
            longest = longest.max(took);
        }
        config(&root).map_err(|_| "CONFIG refused")?;
        rt::println!("net-probe: wire ok 150 (longest {} us)", longest / 1000);
        *keep = Some(root);
        Ok(())
    }
}
