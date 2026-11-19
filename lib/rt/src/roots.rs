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
    register_status(notary, channel, label, level).map_err(|status| match status {
        proto_wire::Status::Kernel(error) => error,
        _ => Error::BadState,
    })
}

/// `register`, with the status the process service refused with.
pub fn register_status(
    notary: &Handle<Channel>,
    channel: &Handle<Channel>,
    label: u64,
    level: u8,
) -> Result<(), proto_wire::Status> {
    let root = sys::handle_label(
        channel,
        Rights::SEND | Rights::DUPLICATE | Rights::TRANSFER,
        label,
        level,
    )
    .map_err(proto_wire::Status::Kernel)?;
    let request = proto_process::Method::Register.header().bytes();
    let reply = sys::send_handles(notary, &request, [root.erase()])
        .map_err(|refused| proto_wire::Status::Kernel(refused.error))?;
    let mut buffer = [0; MESSAGE_MAX];
    match proto_wire::Reader::new(reply.bytes(&mut buffer)).u32() {
        Ok(0) => Ok(()),
        Ok(code) => Err(proto_wire::Status::from_code(code)),
        Err(status) => Err(status),
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
    let mut why = proto_wire::Status::Ok;
    loop {
        let ok = match notary(parent) {
            Notary::Session(notary) => match register_status(&notary, channel, label, level) {
                Ok(()) => true,
                Err(status) => {
                    why = status;
                    false
                }
            },
            // No process service in the image: nothing to register with.
            Notary::Absent => {
                crate::println!(
                    "{who}: no notary session with the process service (ACCESS_DENIED): the root is not registered"
                );
                sys::thread_exit()
            }
            Notary::Failed => {
                why = proto_wire::Status::Kernel(Error::BadState);
                false
            }
        };
        match retry.record(time::ticks_to_ns(time::now()), ok) {
            Attempt::Registered { failures } => {
                if failures > 0 {
                    crate::println!("{who}: root registered after {failures} failed attempts");
                } else {
                    crate::println!("{who}: root registered with the process service");
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
                        "{who}: registering the root failed ({count} so far, status {}), trying again in {} s",
                        why.code(),
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
