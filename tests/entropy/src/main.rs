// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guest probe of the entropy device's driver (services/virtio-rng):
//! a client of init, whose role the first byte of its own arguments names.
//! `f`: two fills of 64 bytes through `rng`, each in two steps
//! (proto_entropy): they differ and neither is all zero; with `c` as the
//! second byte the probe then sends CRASH, connects again once init
//! restarted the driver, and fills once more. Each check prints its line,
//! and the last says `entropy-probe: ok`; xtask reads them.

#![no_std]
#![no_main]

use abi::{Error, MESSAGE_MAX, Rights, Source};
use proto_entropy::{Fill, Key, Method};
use proto_init::ServiceArgs;
use proto_wire::{Status, Writer, long};
use rt::handle::{Channel, Resource};
use rt::{Handle, sys};

rt::entry!(main);

/// The bytes of each fill.
const N: usize = 64;

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let own = ServiceArgs::read(start.args()).map_or(&[][..], |a| a.own);
    let (role, then) = (own.first().copied(), own.get(1).copied());
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(level) else {
        return 1;
    };
    let probe = Probe {
        parent: &start.parent,
        channel,
        level,
    };
    let result = match role {
        Some(b'f') => probe.fills(then == Some(b'c')),
        _ => Err("no role"),
    };
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
    /// The probe's own channel, which the driver notifies through a copy.
    channel: Handle<Channel>,
    level: u8,
}

/// The first 8 bytes of `bytes` as a number, for the lines.
fn head(bytes: &[u8]) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(word)
}

impl Probe<'_> {
    /// Role `f`: two fills that differ, none all zero; with `crash`, CRASH,
    /// a new session once init restarted the driver, and a third fill.
    fn fills(&self, crash: bool) -> Result<(), &'static str> {
        let rng = rt::service::connect(self.parent, "rng").map_err(|_| "connect to rng")?;
        let (mut a, mut b) = ([0; N], [0; N]);
        self.fill(&rng, &mut a)?;
        self.fill(&rng, &mut b)?;
        let zero = |bytes: &[u8]| bytes.iter().all(|&x| x == 0);
        if a == b || zero(&a) || zero(&b) {
            return Err("two fills alike or all zero");
        }
        rt::println!(
            "entropy-probe: two fills of {N} bytes differ, none all zero ({:016x}, {:016x})",
            head(&a),
            head(&b)
        );
        if !crash {
            return Ok(());
        }
        rt::println!("entropy-probe: crashing rng");
        let request = Method::Crash.header().bytes();
        // The driver never replies: its end gives PEER_CLOSED.
        if sys::send(&rng, &request).is_ok() {
            return Err("CRASH answered");
        }
        drop(rng);
        let rng = rt::service::connect(self.parent, "rng").map_err(|_| "connect again")?;
        let mut c = [0; N];
        self.fill(&rng, &mut c)?;
        if zero(&c) || c == a || c == b {
            return Err("the fill after the restart");
        }
        rt::println!(
            "entropy-probe: a fill after the restart ({:016x})",
            head(&c)
        );
        Ok(())
    }

    /// A fill of `out.len()` bytes through `rng` in two steps: FILL_START
    /// gives WAIT k; FILL_TAKE with a copy of the probe's channel labelled
    /// k, then, once bit 0 came in that slot, FILL_TAKE again.
    fn fill(&self, rng: &Handle<Channel>, out: &mut [u8]) -> Result<(), &'static str> {
        let mut w = Writer::new();
        Fill {
            n: out.len() as u32,
        }
        .write(&mut w)
        .map_err(|_| "fill request")?;
        let key = match call(rng, w.as_bytes(), None, out)? {
            Got::Wait(key) => key,
            _ => return Err("FILL_START gave no WAIT"),
        };
        let mut take = Writer::new();
        Key { key }
            .write(Method::FillTake, &mut take)
            .map_err(|_| "take request")?;
        // The first FILL_TAKE brings the labelled copy, which the driver
        // keeps while the fill waits.
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
            match call(rng, take.as_bytes(), notify.take(), out)? {
                Got::Ready => return Ok(()),
                Got::Armed => {}
                Got::Wait(_) => return Err("FILL_TAKE gave WAIT"),
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

/// What a request of a fill gave.
enum Got {
    Ready,
    Wait(u64),
    Armed,
}

/// One request to `rng`, with `notify` when there is one, and its long
/// reply; READY bytes go into `out`, all of them.
fn call(
    rng: &Handle<Channel>,
    request: &[u8],
    notify: Option<Handle<Channel>>,
    out: &mut [u8],
) -> Result<Got, &'static str> {
    let reply = match notify {
        None => sys::send(rng, request).map_err(|_| "send")?,
        Some(n) => {
            sys::send_handles(rng, request, [n.erase()]).map_err(|_| "send with a handle")?
        }
    };
    let mut buffer = [0; MESSAGE_MAX];
    match long::Reply::read(reply.bytes(&mut buffer)) {
        Ok(long::Reply::Ready(bytes)) if bytes.len() == out.len() => {
            out.copy_from_slice(bytes);
            Ok(Got::Ready)
        }
        Ok(long::Reply::Ready(_)) => Err("READY of another length"),
        Ok(long::Reply::Wait(key)) => Ok(Got::Wait(key)),
        Ok(long::Reply::Armed) => Ok(Got::Armed),
        Ok(long::Reply::Cancelled) => Err("CANCELLED"),
        Err(Status::Kernel(Error::LimitReached)) => Err("LIMIT_REACHED"),
        Err(_) => Err("a refusal"),
    }
}
