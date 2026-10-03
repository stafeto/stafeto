// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guest probe of the source of entropy: the entropy device's driver
//! (`rng`, services/virtio-rng) and the entropy service (`entropy`,
//! services/entropy). A client of init, whose roles the bytes of its own
//! arguments name, done in their order:
//!
//! - `s`: a SEED, which waits for the device's first bytes when they did
//!   not come yet; the key's line; 16 SEED with NONBLOCK, all answered at
//!   once and all distinct; a SEED with an unknown flag is refused.
//! - `f`: two fills of 64 bytes through `rng`: they differ and neither is
//!   all zero.
//! - `c`: CRASH of the driver; 32 SEED with NONBLOCK while init restarts
//!   it, all answered at once (after `s`); a new session with the driver,
//!   and a fill.
//! - `w`: a wait of 61 s, past the service's reseed, then a SEED with
//!   NONBLOCK.
//! - `p`: WAITERS SEED at once before the device's first bytes (the
//!   service's build `slow-start` delays them), each WAIT k, each armed
//!   with a labelled copy; the service tells them all once the bytes come,
//!   and each SEED_TAKE gives a key.
//!
//! Each operation goes in two steps (proto_entropy, proto_wire::long).
//! Each check prints its line, and the last says `entropy-probe: ok`;
//! xtask reads them.

#![no_std]
#![no_main]

use abi::{Error, MESSAGE_MAX, Rights, Source};
use proto_entropy::{Fill, Key, Method, NONBLOCK, NOT_READY, SEED_LEN, Seed};
use proto_init::ServiceArgs;
use proto_wire::{Status, Writer, long};
use rt::handle::{Channel, Resource};
use rt::wait::Waiter;
use rt::{Handle, sys, time};

rt::entry!(main);

/// The bytes of each fill.
const N: usize = 64;
/// The seeds at once after the first, and while the driver restarts.
const AT_ONCE: usize = 16;
const DURING_RESTART: usize = 32;
/// The seeds of `p` that wait at once.
const WAITERS: usize = 16;
/// The wait of `w`: past the service's period of 60 s.
const WAIT_NS: u64 = 61_000_000_000;

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
    let mut probe = Probe {
        parent: &start.parent,
        channel,
        level,
        rng: None,
        entropy: None,
        seen: [[0; SEED_LEN]; 1 + AT_ONCE + DURING_RESTART + 1 + WAITERS],
        seen_len: 0,
    };
    let mut result = if own.is_empty() {
        Err("no role")
    } else {
        Ok(())
    };
    for &role in own {
        if result.is_err() {
            break;
        }
        result = match role {
            b's' => probe.seeds(),
            b'f' => probe.fills().map(drop),
            b'c' => probe.crash(),
            b'w' => probe.later(),
            b'p' => probe.waiters(),
            _ => Err("an unknown role"),
        };
    }
    match result {
        Ok(()) => {
            rt::println!("entropy-probe: ok");
            0
        }
        Err(reason) => {
            rt::println!("entropy-probe: failed: {reason}");
            2
        }
    }
}

struct Probe<'a> {
    parent: &'a Handle<Channel>,
    /// The probe's own channel, which the services notify through a copy.
    channel: Handle<Channel>,
    level: u8,
    rng: Option<Handle<Channel>>,
    entropy: Option<Handle<Channel>>,
    /// The keys the service gave so far.
    seen: [[u8; SEED_LEN]; 1 + AT_ONCE + DURING_RESTART + 1 + WAITERS],
    seen_len: usize,
}

/// The first 8 bytes of `bytes` as a number, for the lines.
fn head(bytes: &[u8]) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(word)
}

fn zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&x| x == 0)
}

impl Probe<'_> {
    fn rng(&mut self) -> Result<&Handle<Channel>, &'static str> {
        if self.rng.is_none() {
            let rng = rt::service::connect(self.parent, "rng").map_err(|_| "connect to rng")?;
            self.rng = Some(rng);
        }
        self.rng.as_ref().ok_or("no rng")
    }

    /// A key of the service, waiting for it unless `nonblock`; it must
    /// differ from every key before it.
    fn seed(&mut self, nonblock: bool) -> Result<[u8; SEED_LEN], &'static str> {
        if self.entropy.is_none() {
            let entropy =
                rt::service::connect(self.parent, "entropy").map_err(|_| "connect to entropy")?;
            self.entropy = Some(entropy);
        }
        let service = self.entropy.as_ref().ok_or("no entropy")?;
        let flags = if nonblock { NONBLOCK } else { 0 };
        let mut w = Writer::new();
        Seed { flags }.write(&mut w).map_err(|_| "seed request")?;
        let mut key = [0; SEED_LEN];
        self.long(service, w.as_bytes(), Method::SeedTake, &mut key)?;
        if zero(&key) || self.seen[..self.seen_len].contains(&key) {
            return Err("a key all zero or given before");
        }
        if self.seen_len < self.seen.len() {
            self.seen[self.seen_len] = key;
            self.seen_len += 1;
        }
        Ok(key)
    }

    /// Role `s`.
    fn seeds(&mut self) -> Result<(), &'static str> {
        let key = self.seed(false)?;
        // The whole key, which xtask compares with another client's.
        let mut text = [0u8; 2 * SEED_LEN];
        for (i, b) in key.iter().enumerate() {
            let digits = b"0123456789abcdef";
            text[2 * i] = digits[usize::from(b >> 4)];
            text[2 * i + 1] = digits[usize::from(b & 15)];
        }
        let text = core::str::from_utf8(&text).map_err(|_| "hex")?;
        rt::println!("entropy-probe: key {text}");
        for _ in 0..AT_ONCE {
            self.seed(true)?;
        }
        rt::println!("entropy-probe: {AT_ONCE} seeds at once, all distinct");
        let service = self.entropy.as_ref().ok_or("no entropy")?;
        let mut w = Writer::new();
        Method::Seed.header().write(&mut w).map_err(|_| "header")?;
        w.u32(2).map_err(|_| "flags")?;
        w.u32(0).map_err(|_| "zero")?;
        let mut key = [0; SEED_LEN];
        match call(service, w.as_bytes(), None, &mut key) {
            Err(Status::Kernel(Error::InvalidArgs)) => {}
            _ => return Err("a seed with an unknown flag was not refused"),
        }
        rt::println!("entropy-probe: an unknown flag is refused");
        Ok(())
    }

    /// Role `f`: two fills that differ, none all zero.
    fn fills(&mut self) -> Result<[[u8; N]; 2], &'static str> {
        let (mut a, mut b) = ([0; N], [0; N]);
        self.fill(&mut a)?;
        self.fill(&mut b)?;
        if a == b || zero(&a) || zero(&b) {
            return Err("two fills alike or all zero");
        }
        rt::println!(
            "entropy-probe: two fills of {N} bytes differ, none all zero ({:016x}, {:016x})",
            head(&a),
            head(&b)
        );
        Ok([a, b])
    }

    /// Role `c`: CRASH, seeds while the driver restarts, a fill from the
    /// new instance.
    fn crash(&mut self) -> Result<(), &'static str> {
        rt::println!("entropy-probe: crashing rng");
        let request = Method::Crash.header().bytes();
        // The driver never replies: its end gives PEER_CLOSED.
        if sys::send(self.rng()?, &request).is_ok() {
            return Err("CRASH answered");
        }
        self.rng = None;
        if self.entropy.is_some() {
            for _ in 0..DURING_RESTART {
                self.seed(true)?;
            }
            rt::println!("entropy-probe: {DURING_RESTART} seeds while the driver restarts");
        }
        let mut c = [0; N];
        self.fill(&mut c)?;
        if zero(&c) {
            return Err("the fill after the restart");
        }
        rt::println!(
            "entropy-probe: a fill after the restart ({:016x})",
            head(&c)
        );
        Ok(())
    }

    /// Role `p`: WAITERS seeds started before the first bytes, all armed,
    /// all told, all taken; each key differs from every other.
    fn waiters(&mut self) -> Result<(), &'static str> {
        let entropy =
            rt::service::connect(self.parent, "entropy").map_err(|_| "connect to entropy")?;
        let mut keys = [0u64; WAITERS];
        let mut w = Writer::new();
        Seed { flags: 0 }
            .write(&mut w)
            .map_err(|_| "seed request")?;
        let mut key = [0; SEED_LEN];
        for k in keys.iter_mut() {
            match call(&entropy, w.as_bytes(), None, &mut key) {
                Ok(Got::Wait(waits)) => *k = waits,
                Ok(Got::Ready) => return Err("a seed was ready before the first bytes"),
                _ => return Err("a refusal of a waiting seed"),
            }
        }
        let mut armed = 0;
        for &k in &keys {
            let mut take = Writer::new();
            Key { key: k }
                .write(Method::SeedTake, &mut take)
                .map_err(|_| "take request")?;
            let copy = sys::handle_label(
                &self.channel,
                Rights::NOTIFY | Rights::TRANSFER,
                k,
                self.level,
            )
            .map_err(|_| "labelled copy")?;
            match call(&entropy, take.as_bytes(), Some(copy), &mut key) {
                Ok(Got::Armed) => armed += 1,
                Ok(Got::Ready) => self.keep(key)?,
                _ => return Err("a refusal of a take"),
            }
        }
        let mut told = 0;
        while told < armed {
            match sys::receive(&self.channel) {
                Ok(sys::Received::Notification {
                    source: Source::Session,
                    label,
                    bits,
                    ..
                }) if keys.contains(&label) && bits & 1 != 0 => {
                    let mut take = Writer::new();
                    Key { key: label }
                        .write(Method::SeedTake, &mut take)
                        .map_err(|_| "take request")?;
                    match call(&entropy, take.as_bytes(), None, &mut key) {
                        Ok(Got::Ready) => self.keep(key)?,
                        _ => return Err("a told seed gave no key"),
                    }
                    told += 1;
                }
                Ok(_) => {}
                Err(_) => return Err("receive"),
            }
        }
        rt::println!("entropy-probe: {WAITERS} seeds waited for the first bytes, {armed} told");
        Ok(())
    }

    /// Keeps `key` among those seen: it must be new and not all zero.
    fn keep(&mut self, key: [u8; SEED_LEN]) -> Result<(), &'static str> {
        if zero(&key) || self.seen[..self.seen_len].contains(&key) {
            return Err("a key all zero or given before");
        }
        if self.seen_len < self.seen.len() {
            self.seen[self.seen_len] = key;
            self.seen_len += 1;
        }
        Ok(())
    }

    /// Role `w`: a seed with NONBLOCK after WAIT_NS.
    fn later(&mut self) -> Result<(), &'static str> {
        let timer = Waiter::new(&self.channel, 0, self.level).map_err(|_| "timer")?;
        let deadline = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        while let Ok(rt::wait::Waited::Got(_)) = timer.receive_until(&self.channel, deadline) {}
        self.seed(true)?;
        rt::println!("entropy-probe: a seed after 61 s");
        Ok(())
    }

    /// A fill of `out.len()` bytes through `rng`.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), &'static str> {
        let mut w = Writer::new();
        Fill {
            n: out.len() as u32,
        }
        .write(&mut w)
        .map_err(|_| "fill request")?;
        let rng = self.rng()?;
        let rng = Handle::<Channel>::borrowed(rng.raw());
        self.long(&rng, w.as_bytes(), Method::FillTake, out)
    }

    /// A long operation of `service` (proto_wire::long): `start` gives
    /// READY or WAIT k; then `take` with a copy of the probe's channel
    /// labelled k, and, once bit 0 came in that slot, `take` again.
    fn long(
        &self,
        service: &Handle<Channel>,
        start: &[u8],
        take: Method,
        out: &mut [u8],
    ) -> Result<(), &'static str> {
        let key = match call(service, start, None, out) {
            Ok(Got::Ready) => return Ok(()),
            Ok(Got::Wait(key)) => key,
            Ok(Got::Armed) => return Err("ARMED to a start"),
            Err(status) if status == NOT_READY => return Err("NOT_READY"),
            Err(Status::Kernel(Error::LimitReached)) => return Err("LIMIT_REACHED"),
            Err(_) => return Err("a refusal of a start"),
        };
        let mut w = Writer::new();
        Key { key }
            .write(take, &mut w)
            .map_err(|_| "take request")?;
        // The first take brings the labelled copy, which the service keeps
        // while the operation waits.
        let mut notify = Some(
            sys::handle_label(
                &self.channel,
                Rights::NOTIFY | Rights::TRANSFER,
                key,
                self.level,
            )
            .map_err(|_| "labelled copy")?,
        );
        loop {
            match call(service, w.as_bytes(), notify.take(), out) {
                Ok(Got::Ready) => return Ok(()),
                Ok(Got::Armed) => {}
                Ok(Got::Wait(_)) => return Err("WAIT to a take"),
                Err(_) => return Err("a refusal of a take"),
            }
            loop {
                match sys::receive(&self.channel) {
                    Ok(sys::Received::Notification {
                        source: Source::Session,
                        label,
                        bits,
                        ..
                    }) if label == key && bits & 1 != 0 => break,
                    Ok(_) => {}
                    Err(_) => return Err("receive"),
                }
            }
        }
    }
}

/// What a request of a long operation gave.
enum Got {
    Ready,
    Wait(u64),
    Armed,
}

/// One request to `service`, with `notify` when there is one, and its long
/// reply; READY bytes go into `out`, all of them; a refusal as its status.
fn call(
    service: &Handle<Channel>,
    request: &[u8],
    notify: Option<Handle<Channel>>,
    out: &mut [u8],
) -> Result<Got, Status> {
    let reply = match notify {
        None => sys::send(service, request)?,
        Some(n) => sys::send_handles(service, request, [n.erase()]).map_err(|r| r.error)?,
    };
    let mut buffer = [0; MESSAGE_MAX];
    match long::Reply::read(reply.bytes(&mut buffer))? {
        long::Reply::Ready(bytes) if bytes.len() == out.len() => {
            out.copy_from_slice(bytes);
            Ok(Got::Ready)
        }
        long::Reply::Ready(_) | long::Reply::Cancelled => Err(Status::BadSize),
        long::Reply::Wait(key) => Ok(Got::Wait(key)),
        long::Reply::Armed => Ok(Got::Armed),
    }
}
