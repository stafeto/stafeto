// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process identity and credentials through the process service (spec 2,
//! section 3.1). Startup takes the session of the process's record from the
//! start data (`posix`), asks the service once for its snapshot and keeps
//! the PID, which never changes; PPID and credentials are queries. Queries
//! allocate nothing and do not touch errno or application TLS.
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};
use process_client::Client;
pub use process_client::START_NAME;
use proto_process::Change;
use proto_wire::Status;
use rt::handle::{Channel, Handle};

struct State(UnsafeCell<Option<Client>>);
// SAFETY: startup publishes once before threads; Client methods only borrow it.
unsafe impl Sync for State {}
static STATE: State = State(UnsafeCell::new(None));
/// The PID of the snapshot at startup.
static PID: AtomicU32 = AtomicU32::new(0);

/// Takes `session`, the session of the process's record (start data
/// `posix`), and the PID of its snapshot.
///
/// # Safety
/// Call exactly once during single-threaded startup, before credential calls.
pub unsafe fn init(session: Handle<Channel>) -> Result<(), Status> {
    // SAFETY: startup has exclusive access until it publishes the client.
    let state = unsafe { &mut *STATE.0.get() };
    if state.is_some() {
        return Err(Status::Kernel(rt::abi::Error::BadState));
    }
    let client = Client::new(session);
    let snapshot = client.query()?;
    PID.store(snapshot.pid, Ordering::Release);
    *state = Some(client);
    Ok(())
}

/// The client of the process's record, which startup published.
pub fn client() -> &'static Client {
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

#[unsafe(no_mangle)]
pub extern "C" fn getuid() -> u32 {
    credentials().uid
}
#[unsafe(no_mangle)]
pub extern "C" fn geteuid() -> u32 {
    credentials().euid
}
#[unsafe(no_mangle)]
pub extern "C" fn getgid() -> u32 {
    credentials().gid
}
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub extern "C" fn setuid(id: u32) -> i32 {
    change(Change::Uid, id)
}
#[unsafe(no_mangle)]
pub extern "C" fn seteuid(id: u32) -> i32 {
    change(Change::EffectiveUid, id)
}
#[unsafe(no_mangle)]
pub extern "C" fn setgid(id: u32) -> i32 {
    change(Change::Gid, id)
}
#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
pub extern "C" fn getpid() -> i32 {
    i32::try_from(PID.load(Ordering::Acquire)).expect("positive signed process namespace")
}

#[unsafe(no_mangle)]
pub extern "C" fn getppid() -> i32 {
    let parent = client()
        .query()
        .expect("live critical process service")
        .parent;
    i32::try_from(parent).expect("signed parent process namespace")
}
