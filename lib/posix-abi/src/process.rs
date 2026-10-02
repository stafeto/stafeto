// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process identity and credentials through the process service (spec 2,
//! section 3.1). Startup takes the session of the process's record from the
//! start data (`posix`), asks the service once for its snapshot and keeps
//! the PID; the PPID is on the record's page, which the service maps at
//! proto_process::PAGE_ADDRESS and changes when the parent goes, so
//! `getpid` and `getppid` always succeed with no call; credentials are
//! queries. Queries allocate nothing and do not touch errno or
//! application TLS. waitpid and waitid wait in two steps (long.rs).
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};
use process_client::Client;
pub use process_client::START_NAME;
use proto_process::{Change, Spawn};
use proto_wire::{Status, Writer};
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
    crate::signals::publish_initial();
    Ok(())
}

/// kill of the process `pid` (> 0, the caller's own among them) with
/// `signal` through the process service (0 checks alone): ESRCH, EPERM,
/// EINVAL from the service. A signal to the caller's own process comes to
/// a thread of it before the return, the caller when its mask lets it
/// through ([P24-KILL]).
pub fn kill(pid: i32, signal: i32) -> Result<(), i32> {
    use crate::constants::{EINVAL, EIO, EPERM, ESRCH};
    let pid = u32::try_from(pid).ok().filter(|&p| p != 0).ok_or(EINVAL)?;
    let signal = u32::try_from(signal).map_err(|_| EINVAL)?;
    let mut w = Writer::new();
    proto_process::Method::Kill
        .header()
        .write(&mut w)
        .map_err(|_| EIO)?;
    w.u32(pid).map_err(|_| EIO)?;
    w.u32(signal).map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let status = loop {
        match rt::sys::send(client().session(), w.as_bytes()) {
            Err(rt::abi::Error::Interrupted) => continue,
            Err(_) => return Err(EIO),
            Ok(reply) => {
                let bytes = reply.bytes(&mut buffer);
                break proto_wire::Reader::new(bytes).u32().map_err(|_| EIO)?;
            }
        }
    };
    match status {
        0 => {}
        proto_process::NO_PROCESS => return Err(ESRCH),
        proto_process::PERMISSION => return Err(EPERM),
        proto_process::INVALID => return Err(EINVAL),
        _ => return Err(EIO),
    }
    if pid == PID.load(Ordering::Acquire) && signal != 0 {
        crate::signals::route();
        crate::signals::deliver_now();
    }
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

/// The page of the process's record, which the service mapped before the
/// process started.
pub fn page() -> &'static proto_process::Page {
    // SAFETY: the service maps the record's page at PAGE_ADDRESS, read and
    // write, before the first thread runs, for as long as the process
    // lives; its fields are atomics the service writes too.
    unsafe { &*(proto_process::PAGE_ADDRESS as *const proto_process::Page) }
}

pub fn getppid() -> i32 {
    i32::try_from(page().ppid.load(Ordering::Acquire)).expect("signed parent process namespace")
}

/// What a wait found: the child's PID, how it ended and its real UID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Waited {
    pub pid: i32,
    pub end: Option<proto_process::End>,
    pub uid: u32,
}

/// A wait for a child of `selector` with the service's `options`
/// (proto_process::WaitStart) in two steps: what it found, PID 0 for
/// WNOHANG with none; ECHILD with no such child, EINTR when a signal
/// without SA_RESTART ended it, EINVAL for a selector of no child.
pub fn wait(selector: proto_process::Selector, options: u32) -> Result<Waited, i32> {
    use crate::constants::{ECHILD, EIO};
    use proto_process::{Method, WaitResult, WaitStart};
    let mut start = Writer::new();
    Method::WaitStart
        .header()
        .write(&mut start)
        .map_err(|_| EIO)?;
    WaitStart { selector, options }
        .write(&mut start)
        .map_err(|_| EIO)?;
    let keyed = |cancel: bool, key: u64, w: &mut Writer| {
        let method = if cancel {
            Method::WaitCancel
        } else {
            Method::WaitTake
        };
        method.header().write(w)?;
        w.u64(key)
    };
    let mut out = [0; 16];
    let n = crate::long::run(client().session(), start.as_bytes(), keyed, &mut out)?;
    match WaitResult::read(&out[..n]) {
        Ok(WaitResult::Ended { pid, end, uid }) => Ok(Waited {
            pid: i32::try_from(pid).map_err(|_| EIO)?,
            end: Some(end),
            uid,
        }),
        Ok(WaitResult::Nothing) => Ok(Waited {
            pid: 0,
            end: None,
            uid: 0,
        }),
        Ok(WaitResult::NoChild) => Err(ECHILD),
        Err(_) => Err(EIO),
    }
}

/// waitpid: the child of `pid` (waitpid's -1, 0, > 0, < -1) that ended,
/// with `options` (WNOHANG; WUNTRACED and WCONTINUED take nothing until
/// stops come in 5e).
pub fn waitpid(pid: i32, options: i32) -> Result<Waited, i32> {
    use proto_process::{WCONTINUED, WEXITED, WNOHANG, WSTOPPED};
    let options = u32::try_from(options).map_err(|_| crate::constants::EINVAL)?;
    if options & !(WNOHANG | WSTOPPED | WCONTINUED) != 0 {
        return Err(crate::constants::EINVAL);
    }
    let own = page().pgid.load(Ordering::Relaxed);
    wait(proto_process::Selector::of(pid, own), options | WEXITED)
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
