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
//!
//! Each check prints its line, and the last says `net-probe: ok`; xtask
//! reads them.

#![no_std]
#![no_main]

use abi::{Error, MESSAGE_MAX};
use proto_init::ServiceArgs;
use proto_net::text::{Ip, Mac};
use proto_net::{Address, Config, Method, NET_DOWN, code};
use proto_wire::{Status, Writer};
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
    };
    let mut result = Ok(());
    let mut session = None;
    for role in own {
        result = match role {
            b'c' => probe.configured(&mut session),
            b'k' => probe.restarted(&mut session),
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

impl Probe<'_> {
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
