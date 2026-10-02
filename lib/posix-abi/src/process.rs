// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process identity and credentials through the process service (spec 2,
//! section 3.1). Startup takes the session of the process's record from the
//! start data (`posix`), asks the service once for its snapshot and keeps
//! the PID and the PPID, so `getpid` and `getppid` always succeed;
//! credentials are queries. Queries allocate nothing and do not touch
//! errno or application TLS.
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};
use process_client::Client;
pub use process_client::START_NAME;
use proto_process::{Change, Spawn};
use proto_wire::Status;
use rt::handle::{Channel, Handle};

struct State(UnsafeCell<Option<Client>>);
// SAFETY: startup publishes once before threads; Client methods only borrow it.
unsafe impl Sync for State {}
static STATE: State = State(UnsafeCell::new(None));
/// The PID and the PPID of the snapshot at startup: neither changes until
/// the service moves children to a new parent (stage 5b).
static PID: AtomicU32 = AtomicU32::new(0);
static PPID: AtomicU32 = AtomicU32::new(0);

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
    PPID.store(snapshot.parent, Ordering::Release);
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

pub fn getuid() -> u32 {
    credentials().uid
}
pub fn geteuid() -> u32 {
    credentials().euid
}
pub fn getgid() -> u32 {
    credentials().gid
}
pub fn getegid() -> u32 {
    credentials().egid
}

fn change(operation: Change, id: u32) -> Result<(), i32> {
    client()
        .change(operation, id)
        .map_err(|error| match error.code() {
            proto_process::INVALID => crate::constants::EINVAL,
            proto_process::PERMISSION => crate::constants::EPERM,
            proto_process::FULL => crate::constants::ENOMEM,
            _ => crate::constants::EIO,
        })
}
pub fn setuid(id: u32) -> Result<(), i32> {
    change(Change::Uid, id)
}
pub fn seteuid(id: u32) -> Result<(), i32> {
    change(Change::EffectiveUid, id)
}
pub fn setgid(id: u32) -> Result<(), i32> {
    change(Change::Gid, id)
}
pub fn setegid(id: u32) -> Result<(), i32> {
    change(Change::EffectiveGid, id)
}

pub fn getpid() -> i32 {
    i32::try_from(PID.load(Ordering::Acquire)).expect("positive signed process namespace")
}

pub fn getppid() -> i32 {
    i32::try_from(PPID.load(Ordering::Acquire)).expect("signed parent process namespace")
}

/// posix_spawn of the program at `path` with the spawn-flags `flags` and
/// the process group `pgroup` (5b, until the loader of 5c): `path` names a
/// record of init's table that starts on demand, `/boot/<name>`, whose
/// program and arguments the child gets. ENOENT for another path or no
/// such record; EINVAL for a flag other than POSIX_SPAWN_SETPGROUP and
/// POSIX_SPAWN_SETSID or a negative group; EAGAIN past the children of a
/// process, while the record's child lives, or with the service's records
/// taken; ENOMEM when the child could not be loaded. The error comes
/// before posix_spawn returns: the child got no PID then.
pub fn spawn(path: &[u8], flags: i32, pgroup: i32) -> Result<i32, i32> {
    use crate::constants::{EAGAIN, EINVAL, ENOENT, ENOMEM, EPERM};
    let name = path
        .strip_prefix(b"/boot/")
        .filter(|name| !name.contains(&b'/'))
        .and_then(|name| proto_wire::Name::new(name).ok())
        .ok_or(ENOENT)?;
    let allowed = proto_process::SPAWN_SETPGROUP | proto_process::SPAWN_SETSID;
    let flags = u32::try_from(flags).map_err(|_| EINVAL)?;
    let pgroup = u32::try_from(pgroup).map_err(|_| EINVAL)?;
    if flags & !allowed != 0 {
        return Err(EINVAL);
    }
    // The copy of the child's program runs at least at the caller's level.
    let level = crate::threads::own_block()
        .base_level
        .load(core::sync::atomic::Ordering::Relaxed) as u8;
    let spawn = Spawn {
        name,
        flags,
        pgroup,
        level,
    };
    let pid = client().spawn(&spawn).map_err(|status| match status {
        Status::Kernel(rt::abi::Error::NoMemory) => ENOMEM,
        status => match status.code() {
            proto_process::NOT_FOUND => ENOENT,
            proto_process::INVALID => EINVAL,
            proto_process::PERMISSION => EPERM,
            _ => EAGAIN,
        },
    })?;
    i32::try_from(pid).map_err(|_| EAGAIN)
}
