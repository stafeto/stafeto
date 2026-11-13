// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The root of a service for the loaders: the channel service, the network
//! service and the entropy service send a root of their own to the process
//! service with Register (through the notary session init gives them, whose
//! label has the mark of the service), and a loader sends that root
//! VerifySession for the session of a set-ID program.
//!
//! `register` is one such Register. `keep` is the body of a thread that makes
//! it for a service whose loop must not wait for the process service (a
//! connection to it waits in init until it has started): the thread tries
//! until the root is registered, with a growing pause and a line for the
//! first failure and every second one after (`proto_process::retry`), then
//! ends.

use crate::abi::{Error, MESSAGE_MAX, Rights};
use crate::handle::{Channel, Handle};
use crate::wait::{Waited, Waiter};
use crate::{service, sys, time};
use proto_process::retry::{Attempt, Retry};

/// Register with `channel`'s root of the label `label` (SEND, DUPLICATE and
/// TRANSFER) through `notary`. BAD_STATE for a refusal.
pub fn register(
    notary: &Handle<Channel>,
    channel: &Handle<Channel>,
    label: u64,
    level: u8,
) -> Result<(), Error> {
    let root = sys::handle_label(
        channel,
        Rights::SEND | Rights::DUPLICATE | Rights::TRANSFER,
        label,
        level,
    )?;
    let request = proto_process::Method::Register.header().bytes();
    let reply =
        sys::send_handles(notary, &request, [root.erase()]).map_err(|refused| refused.error)?;
    let mut buffer = [0; MESSAGE_MAX];
    match proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() {
        Ok(0) => Ok(()),
        _ => Err(Error::BadState),
    }
}

/// A connection to the process service for a registration.
pub enum Notary {
    /// The notary session.
    Session(Handle<Channel>),
    /// Init's table has no process service for this service to connect to
    /// (ACCESS_DENIED): the image has no loader to give a root to, and trying
    /// again changes nothing.
    Absent,
    /// Any other refusal; the process service may come.
    Failed,
}

/// The notary session with the process service, asked of init through
/// `parent`; the call waits until the process service has registered.
pub fn notary(parent: &Handle<Channel>) -> Notary {
    match service::connect(parent, "posix") {
        Ok(session) => Notary::Session(session),
        Err(proto_wire::Status::Kernel(Error::AccessDenied)) => Notary::Absent,
        Err(_) => Notary::Failed,
    }
}

/// The attempts of a registration through the connection to init `parent`,
/// until one succeeds; `who` names the service in the lines. A thread's body:
/// it ends the thread once the root is registered.
pub fn keep(
    parent: &Handle<Channel>,
    channel: &Handle<Channel>,
    label: u64,
    level: u8,
    who: &str,
) -> ! {
    let waits = sys::channel_create(level)
        .and_then(|own| Waiter::new(&own, 0, level).map(|timer| (own, timer)));
    let mut retry = Retry::new();
    loop {
        let ok = match notary(parent) {
            Notary::Session(notary) => register(&notary, channel, label, level).is_ok(),
            // No process service in the image: nothing to register with.
            Notary::Absent => sys::thread_exit(),
            Notary::Failed => false,
        };
        match retry.record(time::ticks_to_ns(time::now()), ok) {
            Attempt::Registered { failures } => {
                if failures > 0 {
                    crate::println!("{who}: root registered after {failures} failed attempts");
                }
                sys::thread_exit()
            }
            Attempt::Failed {
                count,
                wait_ns,
                report,
            } => {
                if report {
                    crate::println!(
                        "{who}: registering the root failed ({count} so far), trying again in {} s",
                        wait_ns / 1_000_000_000
                    );
                }
                let Ok((own, timer)) = waits.as_ref() else {
                    // No timer to wait with: the service runs on without a root.
                    sys::thread_exit()
                };
                let deadline = time::ticks_to_ns(time::now()).saturating_add(wait_ns);
                while let Ok(Waited::Got(_)) = timer.receive_until(own, deadline) {}
            }
        }
    }
}
