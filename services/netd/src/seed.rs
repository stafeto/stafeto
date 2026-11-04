// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The key the stack takes its secrets from (RFC 6528 sequence numbers, RFC
//! 6056 ports in the stages that need them): 32 bytes from the entropy
//! service. SEED with no flags either answers at once or gives a key `k`;
//! SEED_TAKE with a copy of the service's own channel labelled `k` arms
//! the wait, and the notification of bit 0 in that slot brings the second
//! SEED_TAKE that returns the key (proto_entropy, proto_wire::long). The
//! service runs this before it registers with init, so nothing else
//! reaches its channel.

use abi::{CLIENT_GONE, MESSAGE_MAX, Rights, Source};
use proto_entropy::{Key, Method, SEED_LEN, Seed};
use proto_wire::{Status, Writer, long};
use rt::Handle;
use rt::handle::Channel;
use rt::sys;

/// What a request of the long operation gave.
enum Got {
    Ready,
    Wait(u64),
    Armed,
}

fn call(
    service: &Handle<Channel>,
    request: &[u8],
    notify: Option<Handle<Channel>>,
    out: &mut [u8; SEED_LEN],
) -> Result<Got, Status> {
    let reply = match notify {
        None => sys::send(service, request)?,
        Some(n) => sys::send_handles(service, request, [n.erase()]).map_err(|r| r.error)?,
    };
    let mut buffer = [0; MESSAGE_MAX];
    match long::Reply::read(reply.bytes(&mut buffer))? {
        long::Reply::Ready(bytes) if bytes.len() == SEED_LEN => {
            out.copy_from_slice(bytes);
            Ok(Got::Ready)
        }
        long::Reply::Ready(_) | long::Reply::Cancelled => Err(Status::BadSize),
        long::Reply::Wait(key) => Ok(Got::Wait(key)),
        long::Reply::Armed => Ok(Got::Armed),
    }
}

/// Why no key came.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// The service refused or broke the protocol.
    Refused(Status),
    /// The entropy service ended with the copy of the handle that was to
    /// bring the key (CLIENT_GONE).
    Gone,
    /// KEY_WAIT_NS passed.
    Timeout,
}

impl From<Status> for Failure {
    fn from(status: Status) -> Failure {
        Failure::Refused(status)
    }
}

/// How long the service waits for the key, in nanoseconds of the guest's
/// time: init restarts a service that ends, and declares one that keeps
/// failing broken, which a wait without end would hide.
pub const KEY_WAIT_NS: u64 = 10_000_000_000;

/// The key from the service of the session `entropy`, waiting for it when
/// the service is not ready. `channel` is the service's own channel, whose
/// notifications of `level` bring the answer; the timer of label `timer`
/// ends the wait after KEY_WAIT_NS.
pub fn take(
    entropy: &Handle<Channel>,
    channel: &Handle<Channel>,
    level: u8,
    timer: (&Handle<rt::handle::Timer>, u64),
) -> Result<[u8; SEED_LEN], Failure> {
    let mut start = Writer::new();
    Seed { flags: 0 }.write(&mut start)?;
    let mut key = [0; SEED_LEN];
    let k = match call(entropy, start.as_bytes(), None, &mut key)? {
        Got::Ready => return Ok(key),
        Got::Wait(k) => k,
        Got::Armed => return Err(Status::BadSize.into()),
    };
    let mut take = Writer::new();
    Key { key: k }.write(Method::SeedTake, &mut take)?;
    let copy = sys::handle_label(channel, Rights::NOTIFY | Rights::TRANSFER, k, level)
        .map_err(Status::Kernel)?;
    match call(entropy, take.as_bytes(), Some(copy), &mut key)? {
        Got::Ready => return Ok(key),
        Got::Armed => {}
        Got::Wait(_) => return Err(Status::BadSize.into()),
    }
    let (timer, timer_label) = timer;
    let deadline = rt::time::ticks_to_ns(rt::time::now()).saturating_add(KEY_WAIT_NS);
    sys::timer_set(timer, deadline).map_err(Status::Kernel)?;
    loop {
        match sys::receive(channel).map_err(Status::Kernel)? {
            sys::Received::Notification {
                source: Source::Session,
                label,
                bits,
                ..
            } if label == k => {
                if bits & CLIENT_GONE != 0 {
                    return Err(Failure::Gone);
                }
                if bits & 1 != 0 {
                    break;
                }
            }
            sys::Received::Notification {
                source: Source::Timer,
                label,
                ..
            } if label == timer_label => return Err(Failure::Timeout),
            _ => {}
        }
    }
    match call(entropy, take.as_bytes(), None, &mut key)? {
        Got::Ready => Ok(key),
        _ => Err(Status::BadSize.into()),
    }
}
