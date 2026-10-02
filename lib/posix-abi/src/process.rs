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
pub use process_client::{IDENTITY_NAME, START_NAME};
use proto_process::{Change, Spawn};
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Handle};

struct State(UnsafeCell<Option<Client>>);
// SAFETY: startup publishes once before threads; Client methods only borrow it.
unsafe impl Sync for State {}
static STATE: State = State(UnsafeCell::new(None));
struct Identity(UnsafeCell<Option<Handle<Channel>>>);
// SAFETY: startup publishes once before threads; afterwards only shared reads.
unsafe impl Sync for Identity {}
/// The process's identity session (start data `posix-id`), whose copies
/// the process gives to the services that ask who it is.
static IDENTITY: Identity = Identity(UnsafeCell::new(None));
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

/// The service's answer to a request through the session of the process's
/// record: the number its reply carries (0 for a status alone), or the
/// errno of its status. A send that came back INTERRUPTED was never seen
/// by the service and goes again; an accepted request that waits for its
/// reply (a walk of a group) is not taken back by a signal.
fn ask(w: &Writer) -> Result<u32, i32> {
    use crate::constants::{EACCES, EAGAIN, EINVAL, EIO, EPERM, ESRCH};
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let (status, value) = loop {
        match rt::sys::send(client().session(), w.as_bytes()) {
            Err(rt::abi::Error::Interrupted) => continue,
            Err(_) => return Err(EIO),
            Ok(reply) => {
                let mut bytes = proto_wire::Reader::new(reply.bytes(&mut buffer));
                let status = bytes.u32().map_err(|_| EIO)?;
                break (status, bytes.u32().unwrap_or(0));
            }
        }
    };
    match status {
        0 => Ok(value),
        proto_process::NO_PROCESS => Err(ESRCH),
        proto_process::PERMISSION => Err(EPERM),
        proto_process::INVALID => Err(EINVAL),
        proto_process::ACCESS => Err(EACCES),
        proto_process::AGAIN => Err(EAGAIN),
        _ => Err(EIO),
    }
}

/// A request of `method` with the numbers `words` as its body.
fn request(method: proto_process::Method, words: &[u32]) -> Result<Writer, i32> {
    let mut w = Writer::new();
    method
        .header()
        .write(&mut w)
        .map_err(|_| crate::constants::EIO)?;
    for &word in words {
        w.u32(word).map_err(|_| crate::constants::EIO)?;
    }
    Ok(w)
}

/// Takes `session`, the process's identity session.
///
/// # Safety
/// Call at most once during single-threaded startup, after `init`.
pub unsafe fn set_identity(session: Handle<Channel>) {
    // SAFETY: startup has exclusive access until threads start.
    unsafe { *IDENTITY.0.get() = Some(session) };
}

/// The process's identity session, which startup published; None when its
/// start data had none.
pub fn identity() -> Option<&'static Handle<Channel>> {
    // SAFETY: startup finished publishing before application threads.
    unsafe { &*IDENTITY.0.get() }.as_ref()
}

/// Router: the service asks for the entry of `thread`, a thread of the
/// process, once it set a signal on the page (spec 2, 3.3): the main
/// thread at the start, the next live one when the router leaves
/// (relibc::leaving).
pub fn register_router(thread: &Handle<rt::handle::Thread>) -> Result<(), i32> {
    use crate::constants::EIO;
    use rt::abi::Rights;
    let copy =
        rt::sys::handle_duplicate(thread, Rights::MANAGE | Rights::TRANSFER).map_err(|_| EIO)?;
    let request = proto_process::Method::Router.header().bytes();
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let reply =
        rt::sys::send_handles(client().session(), &request, [copy.erase()]).map_err(|_| EIO)?;
    if reply.bytes(&mut buffer) != proto_wire::reply(Status::Ok) {
        return Err(EIO);
    }
    Ok(())
}

/// kill of `pid` with `signal` through the process service (0 checks
/// alone): a process for `pid` above 0, the caller's group for 0, every
/// process but the caller's for -1, the group -`pid` below; ESRCH, EPERM,
/// EINVAL from the service, EAGAIN while another walk of the process's
/// groups is on. A signal to the caller's own process or group comes to a
/// thread of it before the return, the caller when its mask lets it
/// through ([P24-KILL]).
pub fn kill(pid: i32, signal: i32) -> Result<(), i32> {
    let signal = u32::try_from(signal).map_err(|_| crate::constants::EINVAL)?;
    ask(&request(
        proto_process::Method::Kill,
        &[pid as u32, signal],
    )?)?;
    if signal != 0 && (pid == getpid() || (pid <= 0 && pid != -1)) {
        crate::signals::route();
        crate::signals::deliver_now();
    }
    Ok(())
}

/// killpg of group `pgrp`: 0 is the caller's own, one or below is EINVAL
/// (no group 1 exists: PID 1 is the service).
pub fn killpg(pgrp: i32, signal: i32) -> Result<(), i32> {
    if pgrp < 0 || pgrp == 1 {
        return Err(crate::constants::EINVAL);
    }
    kill(-pgrp, signal)
}

/// setpgid ([P24-SETPGID]) through the service: EINVAL for a negative
/// number; ESRCH, EPERM, EACCES from it.
pub fn setpgid(pid: i32, pgid: i32) -> Result<(), i32> {
    let (Ok(pid), Ok(pgid)) = (u32::try_from(pid), u32::try_from(pgid)) else {
        return Err(crate::constants::EINVAL);
    };
    ask(&request(proto_process::Method::SetPgid, &[pid, pgid])?).map(drop)
}

/// setsid ([P24-SETSID]): the new session's number; EPERM for a leader of
/// a group. The page takes the new numbers before the reply.
pub fn setsid() -> Result<i32, i32> {
    let sid = ask(&request(proto_process::Method::SetSid, &[])?)?;
    i32::try_from(sid).map_err(|_| crate::constants::EIO)
}

/// getpgid of `pid`: the caller's own group from its page with no call.
pub fn getpgid(pid: i32) -> Result<i32, i32> {
    let pid = u32::try_from(pid).map_err(|_| crate::constants::EINVAL)?;
    if pid == 0 || pid == getpid() as u32 {
        return i32::try_from(page().pgid.load(Ordering::Acquire))
            .map_err(|_| crate::constants::EIO);
    }
    let pgid = ask(&request(proto_process::Method::GetPgid, &[pid])?)?;
    i32::try_from(pgid).map_err(|_| crate::constants::EIO)
}

/// getsid of `pid`: the caller's own session from its page with no call.
pub fn getsid(pid: i32) -> Result<i32, i32> {
    let pid = u32::try_from(pid).map_err(|_| crate::constants::EINVAL)?;
    if pid == 0 || pid == getpid() as u32 {
        return i32::try_from(page().sid.load(Ordering::Acquire))
            .map_err(|_| crate::constants::EIO);
    }
    let sid = ask(&request(proto_process::Method::GetSid, &[pid])?)?;
    i32::try_from(sid).map_err(|_| crate::constants::EIO)
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
    // The child's main thread starts with the caller's mask.
    let mask = crate::threads::own_block()
        .mask
        .load(core::sync::atomic::Ordering::SeqCst);
    let spawn = Spawn {
        name,
        flags,
        pgroup,
        level,
        mask,
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

/// The window where the layer writes the block of a spawn (5c); one
/// spawn of the process writes there at a time (SPAWN_LOCK).
const SPAWN_WINDOW: usize = 0x3000_0000;
static SPAWN_LOCK: posix_sync::LayerLock = posix_sync::LayerLock::raising();

/// What posix_spawn of a file takes beyond the path and the strings: the
/// spawn-flags and the process group (proto_process::SPAWN_FLAGS), the
/// mask of POSIX_SPAWN_SETSIGMASK (None: the caller's), the signals of
/// POSIX_SPAWN_SETSIGDEF and the caller's umask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpawnAttributes {
    pub flags: u32,
    pub pgroup: u32,
    pub mask: Option<u64>,
    pub default: u64,
    pub umask: u32,
}

/// The errno of a refusal of SpawnStart.
fn start_errno(status: Status) -> i32 {
    use crate::constants::{EAGAIN, EINVAL, ENOENT, ENOMEM, EPERM};
    match status {
        Status::Kernel(rt::abi::Error::NoMemory) => ENOMEM,
        status => match status.code() {
            proto_process::NOT_FOUND => ENOENT,
            proto_process::INVALID => EINVAL,
            proto_process::PERMISSION => EPERM,
            _ => EAGAIN,
        },
    }
}

/// The errno of a loader's answer to Go other than "the image is ready".
fn load_errno(code: u32) -> i32 {
    use crate::constants::*;
    match code {
        proto_loader::NO_ENTRY => ENOENT,
        proto_loader::ACCESS => EACCES,
        proto_loader::NOT_EXEC => ENOEXEC,
        proto_loader::NO_MEMORY => ENOMEM,
        proto_loader::TOO_BIG => E2BIG,
        proto_loader::NAME_TOO_LONG => ENAMETOOLONG,
        proto_loader::PERMISSION => EPERM,
        proto_loader::NOT_DIRECTORY => ENOTDIR,
        _ => EIO,
    }
}

/// A request through C, sent again while it comes back INTERRUPTED (the
/// loader never saw it): its status.
fn ask_loader(c: &Handle<Channel>, w: &Writer, handles: Option<rt::handle::Outgoing>) -> u32 {
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut handles = handles;
    loop {
        let sent = match handles.take() {
            Some(h) => rt::sys::send_handles(c, w.as_bytes(), h).map_err(|refused| {
                handles = refused.back;
                refused.error
            }),
            None => rt::sys::send(c, w.as_bytes()),
        };
        match sent {
            Err(rt::abi::Error::Interrupted) => continue,
            Err(_) => return proto_loader::IO,
            Ok(reply) => {
                return proto_wire::Reader::new(reply.bytes(&mut buffer))
                    .u32()
                    .unwrap_or(proto_loader::IO);
            }
        }
    }
}

/// The block of a spawn of `path` in a new object of the caller's: its
/// length and the object (5c, spec 2, 3.2). E2BIG past {ARG_MAX},
/// ENAMETOOLONG for a path past the limit, ENOMEM.
fn block<'s>(
    path: &[u8],
    argv: impl Iterator<Item = &'s [u8]> + Clone,
    envp: impl Iterator<Item = &'s [u8]> + Clone,
    umask: u32,
) -> Result<(usize, Handle<rt::handle::Memory>), i32> {
    use crate::constants::{E2BIG, EINVAL, ENAMETOOLONG, ENOMEM};
    use proto_loader::{Block, BlockError};
    let mut cwd = [0; proto_loader::PATH_MAX];
    let cwd_len = crate::shared::with_files(|files| {
        let own = files.cwd();
        let n = own.len().min(cwd.len());
        cwd[..n].copy_from_slice(&own[..n]);
        Ok(n)
    })?;
    let strings: usize = argv.clone().chain(envp.clone()).map(|s| s.len() + 1).sum();
    let len = Block::len(path.len(), cwd_len, strings);
    let pages = (len.min(proto_loader::BLOCK_MAX) as u64).next_multiple_of(4096);
    let object = rt::sys::mem_create(pages).map_err(|_| ENOMEM)?;
    let _guard = SPAWN_LOCK.lock();
    let process = crate::allocation::process();
    rt::sys::mem_map(
        process,
        &object,
        0,
        pages,
        SPAWN_WINDOW,
        rt::abi::Access::ReadWrite,
    )
    .map_err(|_| ENOMEM)?;
    // SAFETY: the window maps `pages` bytes of the new object, which only
    // this call uses under SPAWN_LOCK.
    let out = unsafe { core::slice::from_raw_parts_mut(SPAWN_WINDOW as *mut u8, pages as usize) };
    let written = Block::write(out, path, &cwd[..cwd_len], umask, argv, envp);
    // SAFETY: the mapping made above, which nothing uses after the write.
    let _ = unsafe { rt::sys::mem_unmap(process, SPAWN_WINDOW, pages) };
    match written {
        Ok(len) => Ok((len, object)),
        Err(BlockError::TooBig) => Err(E2BIG),
        Err(BlockError::NameTooLong) => Err(ENAMETOOLONG),
        Err(BlockError::Malformed) => Err(EINVAL),
    }
}

/// posix_spawn of the program in the file at `path` (5c, spec 2, 3.2):
/// the block of `argv` and `envp` goes to a new process's loader, which
/// opens the file through the session of the loaders and answers whether
/// the image is ready; the child gets clones of the caller's sessions
/// with the RAM files, the clock and the console's input, and lives once
/// the service commits it. Every error comes before the return, the child
/// gone: ENOENT, EACCES, ENOEXEC, ENOMEM, E2BIG, ENAMETOOLONG, ENOTDIR,
/// EPERM, EINVAL for a flag the service does not take, EAGAIN past its
/// limits.
pub fn spawn_file<'s>(
    path: &[u8],
    argv: impl Iterator<Item = &'s [u8]> + Clone,
    envp: impl Iterator<Item = &'s [u8]> + Clone,
    attributes: SpawnAttributes,
) -> Result<i32, i32> {
    use crate::constants::{EAGAIN, EINVAL, EIO, ENOENT};
    use proto_process::{Method, SpawnStart};
    if path.is_empty() {
        return Err(ENOENT);
    }
    let pgroup = attributes.pgroup;
    if pgroup > i32::MAX as u32 || attributes.flags & !proto_process::SPAWN_FLAGS != 0 {
        return Err(EINVAL);
    }
    let (len, object) = block(path, argv, envp, attributes.umask)?;
    let block = &crate::threads::own_block;
    let level = block().base_level.load(Ordering::Relaxed) as u8;
    let mask = attributes
        .mask
        .unwrap_or_else(|| block().mask.load(Ordering::SeqCst));
    let start = SpawnStart {
        flags: attributes.flags,
        pgroup,
        level,
        mask,
        default: attributes.default,
    };
    let mut w = Writer::new();
    Method::SpawnStart.header().write(&mut w).map_err(|_| EIO)?;
    start.write(&mut w).map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut reply = loop {
        match rt::sys::send(client().session(), w.as_bytes()) {
            Err(rt::abi::Error::Interrupted) => continue,
            Err(_) => return Err(EAGAIN),
            Ok(reply) => break reply,
        }
    };
    let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
    let status = Status::from_code(r.u32().map_err(|_| EIO)?);
    if status != Status::Ok {
        return Err(start_errno(status));
    }
    let pid = r.u32().map_err(|_| EIO)?;
    let c = reply.handles.take::<Channel>(0).map_err(|_| EIO)?;
    let pid = i32::try_from(pid).map_err(|_| EIO)?;
    let finished = commit(&c, pid, len, object);
    if finished.is_err() {
        let _ = ask(&request(Method::SpawnAbort, &[pid as u32])?);
    }
    finished.map(|()| pid)
}

/// The parent's side of the loader's protocol for the child `pid`: Start
/// with the block, Go, Handles with clones of the caller's sessions, then
/// SpawnCommit.
fn commit(
    c: &Handle<Channel>,
    pid: i32,
    len: usize,
    object: Handle<rt::handle::Memory>,
) -> Result<(), i32> {
    use crate::constants::{EIO, ENOMEM};
    use proto_loader::{Method, Slot};
    let rights = rt::abi::Rights::MAP_READ | rt::abi::Rights::TRANSFER;
    let copy = rt::sys::handle_duplicate(&object, rights).map_err(|_| ENOMEM)?;
    let mut w = Writer::new();
    Method::Start.header().write(&mut w).map_err(|_| EIO)?;
    w.u32(len as u32).map_err(|_| EIO)?;
    if ask_loader(c, &w, Some([copy.erase()].into())) != 0 {
        return Err(EIO);
    }
    drop(object);
    let mut w = Writer::new();
    Method::Go.header().write(&mut w).map_err(|_| EIO)?;
    let code = ask_loader(c, &w, None);
    if code != 0 {
        return Err(load_errno(code));
    }
    // The child's own sessions: clones of the caller's.
    let clock = crate::clock::session().ok_or(EIO)?;
    let clock =
        rt::service::clone_session(clock, proto_clock::Method::Clone.header()).map_err(|_| EIO)?;
    let (files, uart) = crate::shared::with_files(|fs| {
        let (files, uart) = fs.sessions();
        let files =
            rt::service::clone_session(files, proto_fs::Method::Clone.header()).map_err(|_| EIO)?;
        let uart = match uart {
            Some(u) => Some(
                rt::service::clone_session(u, proto_uart::Method::Clone.header())
                    .map_err(|_| EIO)?,
            ),
            None => None,
        };
        Ok((files, uart))
    })?;
    let mut w = Writer::new();
    Method::Handles.header().write(&mut w).map_err(|_| EIO)?;
    let mut handles = rt::handle::Outgoing::new();
    for (slot, session) in [
        (Slot::Files, Some(files)),
        (Slot::Clock, Some(clock)),
        (Slot::Uart, uart),
    ] {
        if let Some(session) = session {
            w.u32(slot as u32).map_err(|_| EIO)?;
            handles.push(session.erase()).map_err(|_| EIO)?;
        }
    }
    if ask_loader(c, &w, Some(handles)) != 0 {
        return Err(EIO);
    }
    ask(&request(proto_process::Method::SpawnCommit, &[pid as u32])?).map(drop)
}

/// OPEN_EXEC of `path` through the process's own session with the RAM
/// file service, with a copy of its identity: what a process that is no
/// loader gets (5c, the probe of condition O1). 0 when an image session came back,
/// EPERM for the refusal, EIO for anything else.
pub fn probe_open_exec(path: &[u8]) -> i32 {
    use crate::constants::{EIO, EPERM};
    let Some(own) = identity() else {
        return EIO;
    };
    let rights = rt::abi::Rights::NOTIFY | rt::abi::Rights::TRANSFER;
    let Ok(copy) = rt::sys::handle_duplicate(own, rights) else {
        return EIO;
    };
    let mut w = Writer::new();
    if proto_fs::Method::OpenExec.header().write(&mut w).is_err() || w.bytes(path).is_err() {
        return EIO;
    }
    let sent = crate::shared::with_files(|files| {
        let (session, _) = files.sessions();
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let reply =
            rt::sys::send_handles(session, w.as_bytes(), [copy.erase()]).map_err(|_| EIO)?;
        proto_wire::Reader::new(reply.bytes(&mut buffer))
            .u32()
            .map_err(|_| EIO)
    });
    match sent {
        Ok(0) => 0,
        Ok(proto_fs::PERMISSION) => EPERM,
        _ => EIO,
    }
}
