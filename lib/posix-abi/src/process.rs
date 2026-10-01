// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Numeric process identity. Startup publishes the native process handle before
//! C entry. Queries allocate nothing and do not touch errno or application TLS.
use crate::allocation;
use core::cell::UnsafeCell;
use process_client::Client;
use proto_process::Change;
use proto_wire::Status;
use rt::handle::{Channel, Handle, Process};

struct State(UnsafeCell<Option<Client>>);
// SAFETY: startup publishes once before threads; Client methods only borrow it.
unsafe impl Sync for State {}
static STATE: State = State(UnsafeCell::new(None));

/// # Safety
/// Call exactly once during single-threaded startup, before credential calls.
pub unsafe fn init(parent: &Handle<Channel>, own: &Handle<Process>) -> Result<(), Status> {
    // SAFETY: startup has exclusive access until it publishes the client.
    let state = unsafe { &mut *STATE.0.get() };
    if state.is_some() {
        return Err(Status::Kernel(rt::abi::Error::BadState));
    }
    let client = Client::connect(parent)?;
    let registered = client.enroll(own)?;
    if registered.identity != rt::sys::process_identity(own)? {
        return Err(Status::BadSize);
    }
    *state = Some(client);
    Ok(())
}

fn client() -> &'static Client {
    // SAFETY: startup finished publishing before C entry and application threads.
    unsafe { &*STATE.0.get() }
        .as_ref()
        .expect("process service initialized")
}

fn credentials() -> proto_process::Credentials {
    client()
        .query()
        .expect("live critical process service")
        .credentials
}

#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn getuid() -> u32 {
    credentials().uid
}
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn geteuid() -> u32 {
    credentials().euid
}
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn getgid() -> u32 {
    credentials().gid
}
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn getegid() -> u32 {
    credentials().egid
}

fn change(operation: Change, id: u32) -> i32 {
    client().change(operation, id).map_or_else(
        |error| {
            let code = match error.code() {
                proto_process::INVALID => crate::constants::EINVAL,
                proto_process::PERMISSION => crate::constants::EPERM,
                proto_process::FULL => crate::constants::ENOMEM,
                _ => crate::constants::EIO,
            };
            crate::fail(code) as i32
        },
        |()| 0,
    )
}
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn setuid(id: u32) -> i32 {
    change(Change::Uid, id)
}
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn seteuid(id: u32) -> i32 {
    change(Change::EffectiveUid, id)
}
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn setgid(id: u32) -> i32 {
    change(Change::Gid, id)
}
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn setegid(id: u32) -> i32 {
    change(Change::EffectiveGid, id)
}

#[cfg(feature = "transport-probe")]
pub fn probe_interrupt(
    thread: &Handle<rt::handle::Thread>,
    method: proto_process::Method,
) -> Result<(), Status> {
    client().interrupt(thread, method)
}

fn identity() -> rt::abi::ProcessIdentity {
    rt::sys::process_identity(allocation::process()).expect("live process identity")
}

#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn getpid() -> i32 {
    i32::try_from(identity().id).expect("positive signed process namespace")
}

#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn getppid() -> i32 {
    i32::try_from(identity().parent).expect("signed parent process namespace")
}
