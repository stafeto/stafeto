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
use proto_process::Change;
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

/// The probe of condition O2 (5c): with it set, Start carries a second
/// handle, a copy of a channel whose receiver the caller closed, which an
/// honest loader never sends through.
static DECOY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Sets the probe of condition O2.
pub fn probe_decoy(on: bool) {
    DECOY.store(on, Ordering::Relaxed);
}

/// The window where the layer writes the block of a spawn (5c); one
/// spawn of the process writes there at a time (SPAWN_LOCK).
const SPAWN_WINDOW: usize = 0x3000_0000;
static SPAWN_LOCK: posix_sync::LayerLock = posix_sync::LayerLock::raising();

/// A file action of posix_spawn (spawn.h): open `path` with `flags` at
/// `fd`, close `fd`, dup2, chdir and fchdir.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAction<'a> {
    Open { fd: u32, path: &'a [u8], flags: i32 },
    Close(u32),
    Dup2(u32, u32),
    Chdir(&'a [u8]),
    Fchdir(u32),
}

/// The child's descriptors and current directory as the file actions
/// shape them (5c, decision 8): a shadow of the caller's table, whose
/// files of the service the caller holds until the child's session shares
/// them, and the descriptors the actions opened in the caller, which close
/// after the spawn.
struct Shadow {
    entries: [Option<(posix_fs::Target, bool)>; posix_fs::OPEN_MAX],
    held: [Option<posix_fs::Target>; posix_fs::OPEN_MAX],
    opened: [Option<u32>; posix_fs::OPEN_MAX],
    cwd: [u8; proto_loader::PATH_MAX],
    cwd_len: usize,
}

impl Shadow {
    /// The caller's table and current directory, its files held.
    fn take() -> Result<Shadow, i32> {
        let mut shadow = Shadow {
            entries: [None; posix_fs::OPEN_MAX],
            held: [None; posix_fs::OPEN_MAX],
            opened: [None; posix_fs::OPEN_MAX],
            cwd: [0; proto_loader::PATH_MAX],
            cwd_len: 0,
        };
        crate::shared::with_files(|files| {
            let mut open = [None; posix_fs::OPEN_MAX];
            for (fd, target, flags) in files.descriptors() {
                open[fd as usize] = Some((target, flags.close_on_exec));
            }
            for (fd, entry) in open.iter().enumerate() {
                if let Some((_, close_on_exec)) = entry {
                    let target = files.hold(fd as u32).map_err(crate::error)?;
                    shadow.held[fd] = Some(target);
                    shadow.entries[fd] = Some((target, *close_on_exec));
                }
            }
            let own = files.cwd();
            let n = own.len().min(shadow.cwd.len());
            shadow.cwd[..n].copy_from_slice(&own[..n]);
            shadow.cwd_len = n;
            Ok(())
        })?;
        Ok(shadow)
    }

    fn cwd(&self) -> &[u8] {
        &self.cwd[..self.cwd_len]
    }

    /// `path` against the shadow's current directory, into `out`.
    fn absolute<'o>(
        &self,
        path: &[u8],
        out: &'o mut [u8; proto_loader::PATH_MAX],
    ) -> Result<&'o [u8], i32> {
        use crate::constants::{ENAMETOOLONG, ENOENT};
        if path.is_empty() {
            return Err(ENOENT);
        }
        let parts: [&[u8]; 3] = if path[0] == b'/' {
            [path, b"", b""]
        } else if self.cwd().ends_with(b"/") {
            [self.cwd(), path, b""]
        } else {
            [self.cwd(), b"/", path]
        };
        let len: usize = parts.iter().map(|p| p.len()).sum();
        if len > out.len() {
            return Err(ENAMETOOLONG);
        }
        let mut at = 0;
        for p in parts {
            out[at..at + p.len()].copy_from_slice(p);
            at += p.len();
        }
        Ok(&out[..len])
    }

    /// One file action, in order ([P24-SPAWN]).
    fn apply(&mut self, action: FileAction<'_>) -> Result<(), i32> {
        use crate::constants::{EBADF, ENOSYS, ENOTDIR};
        let slot = |fd: u32| -> Result<usize, i32> {
            ((fd as usize) < posix_fs::OPEN_MAX)
                .then_some(fd as usize)
                .ok_or(EBADF)
        };
        match action {
            FileAction::Close(fd) => {
                self.entries[slot(fd)?] = None;
            }
            FileAction::Dup2(fd, new) => {
                let (target, _) = self.entries[slot(fd)?].ok_or(EBADF)?;
                // The copy has no FD_CLOEXEC, and so has the descriptor
                // dup2 names twice ([P24-SPAWN]).
                self.entries[slot(new)?] = Some((target, false));
            }
            FileAction::Open { fd, path, flags } => {
                let place = slot(fd)?;
                let mut full = [0; proto_loader::PATH_MAX];
                let full = self.absolute(path, &mut full)?;
                let own = crate::open(full, flags & !crate::constants::O_CLOEXEC)?;
                let own = own as u32;
                let target =
                    crate::shared::with_files(|files| files.target(own).map_err(crate::error));
                let Some(free) = self.opened.iter_mut().find(|o| o.is_none()) else {
                    let _ = crate::close(own as i32);
                    return Err(crate::constants::EMFILE);
                };
                *free = Some(own);
                self.entries[place] = Some((target?, flags & crate::constants::O_CLOEXEC != 0));
            }
            FileAction::Chdir(path) => {
                let mut full = [0; proto_loader::PATH_MAX];
                let full = self.absolute(path, &mut full)?;
                let directory = crate::shared::resolved(full, |transport, path| {
                    Ok(transport.stat(path).map_err(crate::error)?.kind
                        == posix_fs::FileKind::Directory)
                })?;
                if !directory {
                    return Err(ENOTDIR);
                }
                let len = full.len();
                let mut copy = [0; proto_loader::PATH_MAX];
                copy[..len].copy_from_slice(full);
                self.cwd = copy;
                self.cwd_len = len;
            }
            // The layer keeps no path of a descriptor yet.
            FileAction::Fchdir(_) => return Err(ENOSYS),
        }
        Ok(())
    }

    /// The descriptors the child starts with: those without FD_CLOEXEC.
    fn descriptors(&self) -> ([proto_loader::Descriptor; proto_loader::DESCRIPTORS], usize) {
        use proto_loader::{Descriptor, Names};
        let mut out = [Descriptor {
            fd: 0,
            names: Names::Input,
        }; proto_loader::DESCRIPTORS];
        let mut count = 0;
        for (fd, entry) in self.entries.iter().enumerate() {
            let Some((target, false)) = entry else {
                continue;
            };
            let names = match *target {
                posix_fs::Target::Input => Names::Input,
                posix_fs::Target::Output => Names::Output,
                posix_fs::Target::Error => Names::Error,
                posix_fs::Target::Ram(n) => Names::File(n),
            };
            out[count] = Descriptor {
                fd: fd as u32,
                names,
            };
            count += 1;
        }
        (out, count)
    }

    /// The service's descriptions the child's session shares, each once.
    fn shared(&self) -> impl Iterator<Item = u32> + Clone + '_ {
        let (list, count) = self.descriptors();
        (0..count).filter_map(move |i| match list[i].names {
            proto_loader::Names::File(n)
                if !list[..i]
                    .iter()
                    .any(|d| d.names == proto_loader::Names::File(n)) =>
            {
                Some(n)
            }
            _ => None,
        })
    }

    /// The caller lets go: its holds end and the descriptors the actions
    /// opened close (the child's session keeps the descriptions it shares).
    fn finish(&mut self) {
        for target in self.held.iter_mut().filter_map(Option::take) {
            let release = crate::shared::with_files(|files| Ok(files.unhold(target)));
            if let Ok(Some(posix_fs::Target::Ram(n))) = release {
                let _ = crate::shared::release(n);
            }
        }
        for fd in self.opened.iter_mut().filter_map(Option::take) {
            let _ = crate::close(fd as i32);
        }
    }
}

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
    shadow: &Shadow,
    carried: proto_loader::Carried,
) -> Result<(usize, Handle<rt::handle::Memory>), i32> {
    use crate::constants::{E2BIG, EINVAL, ENAMETOOLONG, ENOMEM};
    use proto_loader::{Block, BlockError};
    let cwd = shadow.cwd();
    let (descriptors, count) = shadow.descriptors();
    let strings: usize = argv.clone().chain(envp.clone()).map(|s| s.len() + 1).sum();
    let len = Block::len(path.len(), cwd.len(), strings) + proto_loader::DESCRIPTOR * count;
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
    let written = Block::write_with(out, path, cwd, umask, argv, envp, &descriptors[..count])
        .and_then(|len| Block::carry(&mut out[..len], carried).map(|()| len));
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
pub fn spawn_file<'s, 'a>(
    path: &[u8],
    argv: impl Iterator<Item = &'s [u8]> + Clone,
    envp: impl Iterator<Item = &'s [u8]> + Clone,
    attributes: SpawnAttributes,
    actions: impl Iterator<Item = FileAction<'a>>,
) -> Result<i32, i32> {
    use crate::constants::{EINVAL, ENOENT};
    if path.is_empty() {
        return Err(ENOENT);
    }
    let pgroup = attributes.pgroup;
    if pgroup > i32::MAX as u32 || attributes.flags & !proto_process::SPAWN_FLAGS != 0 {
        return Err(EINVAL);
    }
    let mut shadow = Shadow::take()?;
    let spawned = actions
        .into_iter()
        .try_for_each(|action| shadow.apply(action))
        .and_then(|()| spawn_shadowed(path, argv, envp, attributes, &shadow));
    shadow.finish();
    spawned
}

/// spawn_file once the file actions shaped the child's descriptors and
/// current directory in `shadow`.
fn spawn_shadowed<'s>(
    path: &[u8],
    argv: impl Iterator<Item = &'s [u8]> + Clone,
    envp: impl Iterator<Item = &'s [u8]> + Clone,
    attributes: SpawnAttributes,
    shadow: &Shadow,
) -> Result<i32, i32> {
    use crate::constants::{EAGAIN, EIO};
    use proto_process::{Method, SpawnStart};
    let pgroup = attributes.pgroup;
    let (len, object) = block(
        path,
        argv,
        envp,
        attributes.umask,
        shadow,
        proto_loader::Carried::default(),
    )?;
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
    let finished = commit(&c, pid, len, object, shadow);
    if finished.is_err() {
        let _ = ask(&request(Method::SpawnAbort, &[pid as u32])?);
    }
    finished.map(|()| pid)
}

/// execve of the program in the file at `path` with `argv` and `envp`
/// (5c, spec 2, 3.2): the other threads stop and every signal of the
/// caller is held (step 1); the service makes the new process with the
/// loader for this record (ExecStart) and the loader opens and loads the
/// file (step 2); on "the image is ready" (step 3) the descriptors with
/// FD_CLOEXEC close and the sessions move to the loader as they are, the
/// descriptions, offsets and labels with them (step 4); ExecCommit moves
/// the record (step 5) and the service kills this process (step 7) while the loader
/// jumps (step 6). An error before step 4 comes back with every thread
/// and descriptor as it was: ENOENT, EACCES, ENOEXEC, ENOMEM, E2BIG,
/// ENAMETOOLONG, ENOTDIR, EPERM, EAGAIN.
pub fn exec<'s>(
    path: &[u8],
    argv: impl Iterator<Item = &'s [u8]> + Clone,
    envp: impl Iterator<Item = &'s [u8]> + Clone,
    umask: u32,
) -> Result<core::convert::Infallible, i32> {
    use crate::constants::ENOENT;
    if path.is_empty() {
        return Err(ENOENT);
    }
    let block = crate::threads::own_block();
    // Step 1: every signal of the caller held, the others stopped.
    let mask = block.mask.swap(!0, Ordering::SeqCst);
    let pending = block.pending.load(Ordering::SeqCst);
    let stopped = crate::signals::stop_others();
    let result =
        stopped.and_then(|()| exec_stopped(path, argv, envp, umask, mask, pending, Probe::None));
    // Back from an exec that failed before step 4: all as it was.
    crate::signals::resume_others();
    block.mask.store(mask, Ordering::SeqCst);
    crate::signals::deliver_now();
    result
}

/// exec once the process stopped (steps 2 to 7).
fn exec_stopped<'s>(
    path: &[u8],
    argv: impl Iterator<Item = &'s [u8]> + Clone,
    envp: impl Iterator<Item = &'s [u8]> + Clone,
    umask: u32,
    mask: u64,
    pending: u64,
    probe: Probe,
) -> Result<core::convert::Infallible, i32> {
    use crate::constants::{EAGAIN, EIO};
    use proto_process::{Method, SpawnStart};
    let mut shadow = Shadow::take()?;
    let carried = proto_loader::Carried {
        pending,
        timers: 0,
        alarm: 0,
    };
    let built = block(path, argv, envp, umask, &shadow, carried);
    shadow.finish();
    let (len, object) = built?;
    let level = crate::threads::own_block()
        .base_level
        .load(Ordering::Relaxed) as u8;
    let start = SpawnStart {
        flags: 0,
        pgroup: 0,
        level,
        mask,
        default: 0,
    };
    let mut w = Writer::new();
    Method::ExecStart.header().write(&mut w).map_err(|_| EIO)?;
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
    let c = reply.handles.take::<Channel>(0).map_err(|_| EIO)?;
    let ready = image_ready(&c, len, object);
    if let Err(errno) = ready {
        let _ = ask(&request(Method::ExecAbort, &[])?);
        return Err(errno);
    }
    // The probes of the window: the old image ends before ExecCommit.
    match probe {
        Probe::None | Probe::Outlive => {}
        Probe::Exit(code) => rt::sys::process_exit(code),
        Probe::Kill => {
            let pid = page().pid.load(Ordering::Acquire) as i32;
            let _ = kill(pid, crate::constants::SIGKILL);
            rt::sys::process_exit(1);
        }
    }
    // The probe of an old image that outlives its ExecCommit keeps a clone
    // of its clock session to ask with afterwards.
    let kept = match probe {
        Probe::Outlive => crate::clock::session().and_then(|clock| {
            rt::service::clone_session(clock, &proto_clock::Method::Clone.header().bytes()).ok()
        }),
        _ => None,
    };
    // Step 4: past this point the old image gives its sessions away, and
    // a failure ends it.
    move_files(&c);
    if ask(&request(Method::ExecCommit, &[])?).is_err() {
        rt::sys::process_exit(127);
    }
    if let Some(clock) = kept {
        outlived(clock);
    }
    // Step 7: the service killed this process at ExecCommit (for a record
    // of init's table, once init took the new one); the loader of the new
    // image jumps once the record is ready. An exit here ends it all the
    // same.
    rt::sys::process_exit(0)
}

/// What a probe of the window of exec makes of the old image once the
/// new one is ready: nothing; it ends with a code, or by its own SIGKILL,
/// before ExecCommit; or it asks the clock service to set the time after
/// ExecCommit's reply, should it get one.
#[derive(Clone, Copy)]
enum Probe {
    None,
    Exit(u64),
    Kill,
    Outlive,
}

/// The old image of the probe `Probe::Outlive` after ExecCommit: the
/// service should have killed it (sp5.K1). It says so on the console and
/// asks the clock service to set the time with its own identity through
/// the clone of the clock session it kept; then it ends.
fn outlived(clock: Handle<Channel>) -> ! {
    rt::println!("posix-procs: the old image lived past ExecCommit");
    let client = posix_clock::Client::from_session(clock);
    let now = posix_time::Time {
        seconds: 1_800_000_000,
        nanos: 0,
    };
    if client.set(now, identity()).is_ok() {
        rt::println!("posix-procs: the old image set the clock");
    }
    rt::sys::process_exit(3)
}

/// The probes of the window of exec (5c): ExecCommit with no exec (the
/// service's status as an errno), an exec whose old image ends with
/// `code` once the new one is ready, before ExecCommit (by its own
/// SIGKILL for a code of 137), and an exec whose old image tries to set
/// the clock after ExecCommit.
pub fn probe_exec_commit() -> i32 {
    match request(proto_process::Method::ExecCommit, &[]).and_then(|w| ask(&w)) {
        Ok(_) => 0,
        Err(errno) => errno,
    }
}

pub fn probe_exec_then_exit<'s>(
    path: &[u8],
    argv: impl Iterator<Item = &'s [u8]> + Clone,
    code: u64,
) -> i32 {
    let probe = match code {
        137 => Probe::Kill,
        code => Probe::Exit(code),
    };
    probe_exec(path, argv, probe)
}

pub fn probe_exec_outlive<'s>(path: &[u8], argv: impl Iterator<Item = &'s [u8]> + Clone) -> i32 {
    probe_exec(path, argv, Probe::Outlive)
}

fn probe_exec<'s>(path: &[u8], argv: impl Iterator<Item = &'s [u8]> + Clone, probe: Probe) -> i32 {
    let block = crate::threads::own_block();
    let mask = block.mask.swap(!0, Ordering::SeqCst);
    let result = crate::signals::stop_others()
        .and_then(|()| exec_stopped(path, argv, [].into_iter(), 0o022, mask, 0, probe));
    crate::signals::resume_others();
    block.mask.store(mask, Ordering::SeqCst);
    match result {
        Ok(never) => match never {},
        Err(errno) => errno,
    }
}

/// Start with the block and Go: Ok once the loader said "the image is
/// ready", else the errno of its answer.
fn image_ready(
    c: &Handle<Channel>,
    len: usize,
    object: Handle<rt::handle::Memory>,
) -> Result<(), i32> {
    use crate::constants::{EIO, ENOMEM};
    use proto_loader::Method;
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
    match ask_loader(c, &w, None) {
        0 => Ok(()),
        code => Err(load_errno(code)),
    }
}

/// Step 4 of exec: the descriptors with FD_CLOEXEC close (their
/// descriptions with the last of them), then the process's own sessions
/// with the RAM files, the clock and the console's input move to the
/// loader (Handles): the new image keeps the descriptions, offsets and
/// labels. Nothing of this image uses them afterwards.
fn move_files(c: &Handle<Channel>) {
    use proto_loader::{Method, Slot};
    for fd in 0..posix_fs::OPEN_MAX as u32 {
        let close_on_exec = crate::shared::with_files(|files| {
            Ok(files
                .descriptor_flags(fd)
                .is_ok_and(|flags| flags.close_on_exec))
        });
        if close_on_exec == Ok(true) {
            let _ = crate::close(fd as i32);
        }
    }
    // A stopped thread never ends the request it holds a description
    // for: a description whose last descriptor went meanwhile closes
    // here, or the new image would keep it in the service with no
    // descriptor (sp5.V3).
    crate::shared::abandon_holds();
    let sessions = crate::shared::with_files(|files| {
        let (files, uart) = files.sessions();
        Ok((files.raw(), uart.map(Handle::raw)))
    });
    let clock = crate::clock::session().map(Handle::raw);
    let Ok((files, uart)) = sessions else {
        return;
    };
    let mut w = Writer::new();
    if Method::Handles.header().write(&mut w).is_err() {
        return;
    }
    let mut handles = rt::handle::Outgoing::new();
    for (slot, session) in [
        (Slot::Files, Some(files)),
        (Slot::Clock, clock),
        (Slot::Uart, uart),
    ] {
        if let Some(raw) = session
            && w.u32(slot as u32).is_ok()
        {
            // The handle moves: this image's owner never uses it again.
            let _ = handles.push(Handle::<Channel>::from_raw(raw).erase());
        }
    }
    let _ = ask_loader(c, &w, Some(handles));
}

/// The errno of a refused Clone: EAGAIN for a service at its limit of
/// clones or sessions (a limit of the moment), ENOMEM, EIO otherwise.
fn clone_errno(status: Status) -> i32 {
    use crate::constants::{EAGAIN, EIO, ENOMEM};
    match status {
        Status::Kernel(rt::abi::Error::LimitReached) => EAGAIN,
        Status::Kernel(rt::abi::Error::NoMemory) => ENOMEM,
        _ => EIO,
    }
}

/// The parent's side of the loader's protocol for the child `pid`: Start
/// with the block, Go, Handles with clones of the caller's sessions, then
/// SpawnCommit.
fn commit(
    c: &Handle<Channel>,
    pid: i32,
    len: usize,
    object: Handle<rt::handle::Memory>,
    shadow: &Shadow,
) -> Result<(), i32> {
    use crate::constants::{EIO, ENOMEM};
    use proto_loader::{Method, Slot};
    let rights = rt::abi::Rights::MAP_READ | rt::abi::Rights::TRANSFER;
    let copy = rt::sys::handle_duplicate(&object, rights).map_err(|_| ENOMEM)?;
    let mut w = Writer::new();
    Method::Start.header().write(&mut w).map_err(|_| EIO)?;
    w.u32(len as u32).map_err(|_| EIO)?;
    let mut start = rt::handle::Outgoing::new();
    start.push(copy.erase()).map_err(|_| EIO)?;
    if DECOY.load(Ordering::Relaxed) {
        // A loader that sent through it would get PEER_CLOSED, and the
        // spawn would fail.
        let decoy = rt::sys::channel_create(1).map_err(|_| ENOMEM)?;
        let rights = rt::abi::Rights::SEND | rt::abi::Rights::TRANSFER;
        let copy = rt::sys::handle_duplicate(&decoy, rights).map_err(|_| ENOMEM)?;
        drop(decoy);
        start.push(copy.erase()).map_err(|_| EIO)?;
    }
    if ask_loader(c, &w, Some(start)) != 0 {
        return Err(EIO);
    }
    drop(object);
    let mut w = Writer::new();
    Method::Go.header().write(&mut w).map_err(|_| EIO)?;
    let code = ask_loader(c, &w, None);
    if code != 0 {
        return Err(load_errno(code));
    }
    // The child's own sessions: clones of the caller's, the one of the
    // RAM files sharing the descriptions the child starts with.
    let clock = crate::clock::session().ok_or(EIO)?;
    let clock = rt::service::clone_session(clock, &proto_clock::Method::Clone.header().bytes())
        .map_err(clone_errno)?;
    let (files, uart) = crate::shared::with_files(|fs| {
        let (files, uart) = fs.sessions();
        Ok((files.raw(), uart.map(Handle::raw)))
    })?;
    let mut w = Writer::new();
    proto_fs::Method::Clone
        .header()
        .write(&mut w)
        .map_err(|_| EIO)?;
    let shared = shadow.shared();
    w.u32(shared.clone().count() as u32).map_err(|_| EIO)?;
    for fd in shared {
        w.u32(fd).map_err(|_| EIO)?;
    }
    // The sessions live as long as the process's files.
    let files = rt::service::clone_session(&Handle::<Channel>::borrowed(files), w.as_bytes())
        .map_err(clone_errno)?;
    let uart = match uart {
        Some(u) => Some(
            rt::service::clone_session(
                &Handle::<Channel>::borrowed(u),
                &proto_uart::Method::Clone.header().bytes(),
            )
            .map_err(clone_errno)?,
        ),
        None => None,
    };
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

/// A SpawnStart whose loader never gets a block, for the probes: the
/// child's PID and the parent's copy of C, or the errno of the refusal.
fn start_bare() -> Result<(u32, Handle<Channel>), i32> {
    use crate::constants::EIO;
    use proto_process::{Method, SpawnStart};
    let level = crate::threads::own_block()
        .base_level
        .load(Ordering::Relaxed) as u8;
    let start = SpawnStart {
        flags: 0,
        pgroup: 0,
        level,
        mask: 0,
        default: 0,
    };
    let mut w = Writer::new();
    Method::SpawnStart.header().write(&mut w).map_err(|_| EIO)?;
    start.write(&mut w).map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut reply = rt::sys::send(client().session(), w.as_bytes()).map_err(|_| EIO)?;
    let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
    let status = Status::from_code(r.u32().map_err(|_| EIO)?);
    if status != Status::Ok {
        return Err(start_errno(status));
    }
    let pid = r.u32().map_err(|_| EIO)?;
    let c = reply.handles.take::<Channel>(0).map_err(|_| EIO)?;
    Ok((pid, c))
}

/// The probe of a commit before the loader's image is ready (sp5.V1): a
/// SpawnStart whose loader never gets a block, SpawnCommit at once, then
/// SpawnAbort; the child's PID in `pid`, and the errno SpawnCommit came
/// back with (0 had it been taken).
pub fn probe_commit_early(pid: &mut i32) -> i32 {
    use proto_process::Method;
    let (child, _c) = match start_bare() {
        Ok(started) => started,
        Err(errno) => return errno,
    };
    *pid = child as i32;
    let committed = request(Method::SpawnCommit, &[child]).and_then(|w| ask(&w));
    let _ = request(Method::SpawnAbort, &[child]).and_then(|w| ask(&w));
    committed.err().unwrap_or(0)
}

/// The probe of the loads a record may have at once (sp5.V2): up to
/// three SpawnStarts that wait together, then SpawnAbort of each; how
/// many the service took (LOADERS_OF_PARENT, 2, when no load of the
/// record was left behind).
pub fn probe_loads() -> i32 {
    use proto_process::Method;
    let mut started = [None, None, None];
    for slot in &mut started {
        match start_bare() {
            Ok(load) => *slot = Some(load),
            Err(_) => break,
        }
    }
    let mut count = 0;
    for (pid, _c) in started.into_iter().flatten() {
        count += 1;
        let _ = request(Method::SpawnAbort, &[pid]).and_then(|w| ask(&w));
    }
    count
}

/// The bytes of the service's quota left for children (Pool), for the
/// probe that the ends of loads give theirs back; 0 on an error.
pub fn probe_pool() -> u64 {
    let Ok(w) = request(proto_process::Method::Pool, &[]) else {
        return 0;
    };
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let Ok(reply) = rt::sys::send(client().session(), w.as_bytes()) else {
        return 0;
    };
    let mut r = proto_wire::Reader::new(reply.bytes(&mut buffer));
    match (r.u32(), r.u64()) {
        (Ok(0), Ok(pool)) => pool,
        _ => 0,
    }
}

/// Arms the notification of the process's identity session in the process
/// service's channel of identity sessions, as a process that wants a
/// Vouch to take one more entry does (the probe of the longest Vouch). 0,
/// or EIO when the process has no identity session.
pub fn probe_notify_identity() -> i32 {
    match identity() {
        Some(own) if rt::sys::notify(own, 1).is_ok() => 0,
        _ => crate::constants::EIO,
    }
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
    let Ok(session) = crate::shared::with_files(|files| Ok(files.sessions().0.raw())) else {
        return EIO;
    };
    // The session lives as long as the process's files.
    let session = Handle::<Channel>::borrowed(session);
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let sent = rt::sys::send_handles(&session, w.as_bytes(), [copy.erase()])
        .map_err(|_| EIO)
        .and_then(|reply| {
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
