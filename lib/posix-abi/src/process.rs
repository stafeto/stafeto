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

/// The record of a forked child (spec 2, 3.2): its own session `session`
/// and identity session `identity`, which its loader took (Take), in place
/// of the parent's, which name nothing of the child's and go without a
/// close; its PID from the service. The page's classes of signals are
/// the service's from ForkStart, and the actions the copy of the parent's.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(
    session: Handle<Channel>,
    identity: Option<Handle<Channel>>,
) -> Result<(), Status> {
    // SAFETY: the caller's promise gives these borrows alone.
    let (state, own) = unsafe { (&mut *STATE.0.get(), &mut *IDENTITY.0.get()) };
    if let Some(parent) = state.replace(Client::new(session)) {
        core::mem::forget(parent);
    }
    if let Some(parent) = core::mem::replace(own, identity) {
        core::mem::forget(parent);
    }
    let snapshot = client().query()?;
    PID.store(snapshot.pid, Ordering::Release);
    Ok(())
}

/// The service's answer to a request through the session of the process's
/// record: the number its reply carries (0 for a status alone), or the
/// errno of its status. A send that came back INTERRUPTED was never seen
/// by the service and goes again; an accepted request that waits for its
/// reply (a walk of a group) is not taken back by a signal.
pub(crate) fn ask(w: &Writer) -> Result<u32, i32> {
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
pub(crate) fn request(method: proto_process::Method, words: &[u32]) -> Result<Writer, i32> {
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

/// Obtain the service's authoritative epoch for a directed job signal.
pub(crate) fn signal_generation(signal: i32) -> Result<u64, i32> {
    let w = request(proto_process::Method::SignalGeneration, &[signal as u32])?;
    let mut bytes = [0; rt::abi::MESSAGE_MAX];
    loop {
        match rt::sys::send(client().session(), w.as_bytes()) {
            Err(rt::abi::Error::Interrupted) => continue,
            Err(_) => return Err(crate::constants::EIO),
            Ok(reply) => {
                let mut r = proto_wire::Reader::new(reply.bytes(&mut bytes));
                let status = r.u32().map_err(|_| crate::constants::EIO)?;
                if status == proto_process::AGAIN {
                    return Err(crate::constants::EAGAIN);
                }
                if status != 0 {
                    return Err(crate::constants::EIO);
                }
                return r.u64().map_err(|_| crate::constants::EIO);
            }
        }
    }
}

pub(crate) fn stop_self(signal: i32, ticket: u64) -> Result<(), i32> {
    let mut w = request(proto_process::Method::StopSelf, &[signal as u32])?;
    w.u64(ticket).map_err(|_| crate::constants::EIO)?;
    ask(&w).map(|_| ())
}

static PROBE_RETURN_FAILURE: AtomicU32 = AtomicU32::new(0);
pub(crate) fn probe_return_failure() {
    PROBE_RETURN_FAILURE.store(1, Ordering::Release);
}

/// Return process information through its single publisher. Interrupted sends
/// were not accepted and repeat; a stale ticket is acknowledged harmlessly.
pub(crate) fn return_signal(
    signal: i32,
    ticket: u64,
    info: &posix_types::SigInfo,
) -> Result<(), i32> {
    if PROBE_RETURN_FAILURE.swap(0, Ordering::AcqRel) != 0 {
        return Err(crate::constants::EIO);
    }
    let mut w = request(proto_process::Method::ReturnSignal, &[signal as u32])?;
    w.u64(ticket)
        .and_then(|()| w.u32(info.si_code as u32))
        .and_then(|()| w.u32(info.si_pid as u32))
        .and_then(|()| w.u32(info.si_uid))
        .and_then(|()| w.u32(info.si_status as u32))
        .map_err(|_| crate::constants::EIO)?;
    ask(&w).map(|_| ())
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
    send_router(router_copy(thread)?)
}

/// The copy of `thread` the service keeps as the router: MANAGE and
/// TRANSFER, made from a handle with DUPLICATE.
pub(crate) fn router_copy(
    thread: &Handle<rt::handle::Thread>,
) -> Result<Handle<rt::handle::Thread>, i32> {
    use crate::constants::EIO;
    use rt::abi::Rights;
    rt::sys::handle_duplicate(thread, Rights::MANAGE | Rights::TRANSFER).map_err(|_| EIO)
}

/// Tells the service that the thread of `copy` routes the process's
/// signals. Never under the table lock of the threads: the service may
/// take long to answer.
pub(crate) fn send_router(copy: Handle<rt::handle::Thread>) -> Result<(), i32> {
    use crate::constants::EIO;
    #[cfg(feature = "thread-probe")]
    assert!(
        !crate::relibc::probe_table_held_by_caller(),
        "the router is named to the service under the table lock"
    );
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
    pub stopped: Option<u8>,
    pub continued: bool,
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
            stopped: None,
            continued: false,
            uid,
        }),
        Ok(WaitResult::Stopped { pid, signal, uid }) => Ok(Waited {
            pid: i32::try_from(pid).map_err(|_| EIO)?,
            end: None,
            stopped: Some(signal),
            continued: false,
            uid,
        }),
        Ok(WaitResult::Continued { pid, uid }) => Ok(Waited {
            pid: i32::try_from(pid).map_err(|_| EIO)?,
            end: None,
            stopped: None,
            continued: true,
            uid,
        }),
        Ok(WaitResult::Nothing) => Ok(Waited {
            pid: 0,
            end: None,
            stopped: None,
            continued: false,
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

/// Malformed own-loader packets for the terminal C probe. No foreign
/// endpoint or credential participates in these refusal paths.
static TERMINAL_PACKET_PROBE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static TERMINAL_PACKET_RESULT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub fn probe_terminal_packet_result() -> u64 {
    TERMINAL_PACKET_RESULT.load(Ordering::Acquire)
}
pub fn probe_terminal_packet(mode: u32) {
    TERMINAL_PACKET_PROBE.store(mode, Ordering::Release);
}

/// A live counterfeit terminal endpoint used by the C terminal probe.
static FAKE_TERMINAL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn probe_terminal_fake_start() -> i32 {
    match rt::sys::channel_create(1) {
        Ok(channel) => {
            FAKE_TERMINAL.store(channel.into_raw().0, Ordering::Release);
            0
        }
        Err(_) => crate::constants::EIO,
    }
}

pub fn probe_terminal_fake_control() -> i32 {
    let fake = Handle::<Channel>::borrowed(rt::abi::Handle(FAKE_TERMINAL.load(Ordering::Acquire)));
    let Some(identity) = identity().and_then(|identity| {
        rt::sys::handle_duplicate(
            identity,
            rt::abi::Rights::NOTIFY | rt::abi::Rights::TRANSFER,
        )
        .ok()
    }) else {
        return crate::constants::EIO;
    };
    if rt::sys::send_handles(
        &fake,
        &proto_tty::Method::Controlling.header().bytes(),
        [identity.erase()],
    )
    .is_ok()
    {
        0
    } else {
        crate::constants::EIO
    }
}

pub fn probe_terminal_fake_listen() -> u32 {
    let fake = Handle::<Channel>::borrowed(rt::abi::Handle(FAKE_TERMINAL.load(Ordering::Acquire)));
    let mut identities = 0;
    loop {
        let Ok(received) = rt::sys::receive(&fake) else {
            return u32::MAX;
        };
        if let rt::sys::Received::Message {
            token,
            words,
            handles,
            ..
        } = received
        {
            let stop = u16::from_le_bytes(rt::abi::inline_bytes(&words)[..2].try_into().unwrap())
                == u16::MAX;
            for i in 0..handles.len() {
                if matches!(handles.info(i), Some((rt::abi::ObjectKind::Channel, rights)) if rights.contains(rt::abi::Rights::NOTIFY))
                {
                    identities += 1;
                }
            }
            let _ = token.reply(&proto_wire::reply(proto_wire::Status::Ok));
            if stop {
                return identities;
            }
        }
    }
}

pub fn probe_terminal_fake_stop() -> i32 {
    let fake = Handle::<Channel>::borrowed(rt::abi::Handle(FAKE_TERMINAL.load(Ordering::Acquire)));
    let request = proto_wire::Header::new(u16::MAX, proto_tty::VERSION).bytes();
    if rt::sys::send(&fake, &request).is_ok() {
        0
    } else {
        crate::constants::EIO
    }
}

pub fn probe_terminal_fake_close() {
    let raw = FAKE_TERMINAL.swap(0, Ordering::AcqRel);
    if raw != 0 {
        drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
    }
}

/// The probe of the loader's refusal of the end of a pipe with no session
/// of the pipe service to give (5e): with it set, a spawn's Handles brings
/// no Pipes session.
static NO_PIPES_SESSION: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Sets the probe of the loader's refusal of a pipe's end with no session.
pub fn probe_no_pipes_session(on: bool) {
    NO_PIPES_SESSION.store(on, Ordering::Relaxed);
}

/// The window where the layer writes the block of a spawn (5c); one
/// spawn of the process writes there at a time (SPAWN_LOCK).
const SPAWN_WINDOW: usize = 0x3000_0000;
static SPAWN_LOCK: posix_sync::LayerLock = posix_sync::LayerLock::raising();

/// A file action of posix_spawn (spawn.h): open `path` with `flags` (and
/// `mode` when it creates the file) at `fd`, close `fd`, dup2, chdir and
/// fchdir.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAction<'a> {
    Open {
        fd: u32,
        path: &'a [u8],
        flags: i32,
        mode: u32,
    },
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
    /// The creation mask the child starts with: the mode of a file an Open
    /// action creates is cut by it.
    umask: u32,
    terminal_opens: [proto_loader::TerminalAction; proto_loader::TERMINAL_ACTIONS],
    terminal_count: usize,
    terminal_open_count: usize,
    pending: [Option<u32>; posix_fs::OPEN_MAX],
    /// POSIX_SPAWN_RESETIDS with effective IDs that differ from the real
    /// ones: the child runs under the real IDs, and the actions of files and
    /// the search of PATH, which run here under the effective ones, check
    /// the permissions with the real ones first (a temporary check until
    /// issue #176 moves the actions into the child, which has the IDs after
    /// the reset: this window between the check and the use stays, issue
    /// #150).
    real_ids: bool,
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
            umask: 0,
            terminal_opens: [proto_loader::TerminalAction::default();
                proto_loader::TERMINAL_ACTIONS],
            terminal_count: 0,
            terminal_open_count: 0,
            pending: [None; posix_fs::OPEN_MAX],
            real_ids: false,
        };
        let numbers = core::array::from_fn::<_, { posix_fs::OPEN_MAX }, _>(|fd| fd as u32);
        crate::shared::with_descriptors(&numbers, |files| {
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

    /// The child starts in the directory with this canonical path.
    fn set_cwd(&mut self, canonical: &[u8]) {
        let mut copy = [0; proto_loader::PATH_MAX];
        copy[..canonical.len()].copy_from_slice(canonical);
        self.cwd = copy;
        self.cwd_len = canonical.len();
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

    /// The final alias of a temporary open closes at this point in the
    /// action sequence, before any following Open takes effect.
    fn replace_entry(
        &mut self,
        fd: usize,
        entry: Option<(posix_fs::Target, bool)>,
        pending: Option<u32>,
    ) -> Result<(), i32> {
        if let Some(token) = self.pending[fd]
            && pending != Some(token)
            && !self
                .pending
                .iter()
                .enumerate()
                .any(|(i, &p)| i != fd && p == Some(token))
        {
            if self.terminal_count == proto_loader::TERMINAL_ACTIONS {
                return Err(crate::constants::EMFILE);
            }
            self.terminal_opens[self.terminal_count] = proto_loader::TerminalAction {
                token,
                kind: proto_loader::TERMINAL_CLOSE,
                number: 0,
                flags: 0,
            };
            self.terminal_count += 1;
        }
        self.entries[fd] = entry;
        self.pending[fd] = pending;
        Ok(())
    }

    /// One file action, in order ([P24-SPAWN]).
    fn apply(&mut self, action: FileAction<'_>) -> Result<(), i32> {
        use crate::constants::{EBADF, ENOTDIR};
        let slot = |fd: u32| -> Result<usize, i32> {
            ((fd as usize) < posix_fs::OPEN_MAX)
                .then_some(fd as usize)
                .ok_or(EBADF)
        };
        match action {
            FileAction::Close(fd) => {
                self.replace_entry(slot(fd)?, None, None)?;
            }
            FileAction::Dup2(fd, new) => {
                let (target, _) = self.entries[slot(fd)?].ok_or(EBADF)?;
                // The copy has no FD_CLOEXEC, and so has the descriptor
                // dup2 names twice ([P24-SPAWN]).
                self.replace_entry(slot(new)?, Some((target, false)), self.pending[slot(fd)?])?;
            }
            FileAction::Open {
                fd,
                path,
                flags,
                mode,
            } => {
                let place = slot(fd)?;
                let mut full = [0; proto_loader::PATH_MAX];
                let full = self.absolute(path, &mut full)?;
                use crate::constants::{
                    EINVAL, EMFILE, O_ACCMODE, O_APPEND, O_CHANGES, O_CLOEXEC, O_CLOFORK, O_CREAT,
                    O_DIRECTORY, O_EXCL, O_NOCTTY, O_NONBLOCK, O_TRUNC,
                };
                if flags
                    & !(O_ACCMODE
                        | O_DIRECTORY
                        | O_CLOEXEC
                        | O_CLOFORK
                        | O_CHANGES
                        | O_NOCTTY
                        | O_NONBLOCK
                        | O_CREAT
                        | O_EXCL
                        | O_TRUNC
                        | O_APPEND)
                    != 0
                    || flags & O_ACCMODE == O_ACCMODE
                {
                    return Err(EINVAL);
                }
                let terminal = crate::shared::resolved(full, |transport, path| {
                    if transport.terminal().is_none() {
                        return Ok(None);
                    }
                    transport.terminal_open(path).map_err(crate::error)
                })?;
                if let Some((kind, number)) = terminal {
                    if flags & O_DIRECTORY != 0 {
                        return Err(ENOTDIR);
                    }
                    if self.terminal_open_count == proto_loader::TERMINAL_OPENS
                        || self.terminal_count == proto_loader::TERMINAL_ACTIONS
                    {
                        return Err(EMFILE);
                    }
                    self.replace_entry(place, None, None)?;
                    let token = self.terminal_open_count as u32;
                    self.terminal_opens[self.terminal_count] = proto_loader::TerminalAction {
                        token,
                        kind,
                        number,
                        flags: (flags & (O_ACCMODE | O_NONBLOCK | O_NOCTTY)) as u32,
                    };
                    self.terminal_count += 1;
                    self.terminal_open_count += 1;
                    self.entries[place] = Some((posix_fs::Target::Tty(0), flags & O_CLOEXEC != 0));
                    self.pending[place] = Some(token);
                    return Ok(());
                }
                self.replace_entry(place, None, None)?;
                if self.real_ids {
                    self.real_open_allowed(full, flags)?;
                }
                // The caller's own descriptor lives only for the spawn: with
                // FD_CLOEXEC, so that an exec or spawn of another thread in
                // the meantime does not inherit it. The child's flag is the
                // action's.
                let own = crate::open_policy(
                    full,
                    flags | crate::constants::O_CLOEXEC,
                    mode,
                    self.umask,
                )?;
                let own = own as u32;
                let target =
                    crate::shared::with_fd(own, |files| files.target(own).map_err(crate::error));
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
                if self.real_ids {
                    real_access(full, X_OK)?;
                }
                // The child starts in the canonical path of the directory.
                let mut canonical = [0; crate::names::MAX_PATH + 1];
                let len = crate::names::directory_path(full, &mut canonical)?;
                self.set_cwd(&canonical[..len]);
            }
            FileAction::Fchdir(fd) => {
                let (target, _) = self.entries[slot(fd)?].ok_or(EBADF)?;
                // The directory the descriptor names now, by the path the
                // service gives it; a descriptor of another service is ENOTDIR.
                let mut canonical = [0; crate::names::MAX_PATH + 1];
                let len = crate::names::descriptor_path(target, &mut canonical)?;
                if self.real_ids {
                    real_access(&canonical[..len], X_OK)?;
                }
                self.set_cwd(&canonical[..len]);
            }
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
            let names = if let Some(token) = self.pending[fd] {
                Names::PendingTerminal(token)
            } else {
                match *target {
                    posix_fs::Target::Input => Names::Input,
                    posix_fs::Target::Output => Names::Output,
                    posix_fs::Target::Error => Names::Error,
                    posix_fs::Target::Ram(n) => Names::File(n.fd()),
                    posix_fs::Target::Pipe(n) => Names::Pipe(n),
                    posix_fs::Target::Tty(n) => Names::Terminal(n),
                    posix_fs::Target::Random(n) => Names::Random(n.fd()),
                }
            };
            out[count] = Descriptor {
                fd: fd as u32,
                names,
            };
            count += 1;
        }
        (out, count)
    }

    fn shared_terminals(&self) -> ([u32; posix_fs::OPEN_MAX], usize) {
        let (list, count) = self.descriptors();
        let mut ids = [0; posix_fs::OPEN_MAX];
        let mut n = 0;
        for descriptor in &list[..count] {
            if let proto_loader::Names::Terminal(id) = descriptor.names
                && id != 0
                && !ids[..n].contains(&id)
            {
                ids[n] = id;
                n += 1;
            }
        }
        (ids, n)
    }

    /// The service's descriptions the child's session shares, each once.
    fn shared(&self) -> impl Iterator<Item = rt::fs::PreparedOpen> + Clone + '_ {
        (0..self.entries.len()).filter_map(move |index| {
            let Some((posix_fs::Target::Ram(target) | posix_fs::Target::Random(target), false)) = self.entries[index] else { return None; };
            let captured = target.prepared();
            let duplicate = self.entries[..index].iter().any(|entry| {
                matches!(entry, Some((posix_fs::Target::Ram(old) | posix_fs::Target::Random(old), false)) if old.prepared() == captured)
            });
            (!duplicate).then_some(captured)
        })
    }

    /// The ends of pipes the child's session shares, each once.
    fn shared_pipes(&self) -> ([u32; posix_fs::OPEN_MAX], usize) {
        let (list, count) = self.descriptors();
        let mut ends = [0; posix_fs::OPEN_MAX];
        let mut found = 0;
        for d in &list[..count] {
            if let proto_loader::Names::Pipe(n) = d.names
                && !ends[..found].contains(&n)
            {
                ends[found] = n;
                found += 1;
            }
        }
        (ends, found)
    }

    /// The caller lets go: its holds end and the descriptors the actions
    /// opened close (the child's session keeps the descriptions it shares).
    fn finish(&mut self) {
        for target in self.held.iter_mut().filter_map(Option::take) {
            let release = crate::shared::with_files(|files| Ok(files.unhold(target)));
            if let Ok(Some(target)) = release {
                let _ = crate::shared::release_target(target);
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
pub(crate) fn start_errno(status: Status) -> i32 {
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
pub(crate) fn load_errno(code: u32) -> i32 {
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
        proto_loader::NO_CONTROLLING => ENXIO,
        _ => EIO,
    }
}

/// A Loader request and its status. Non-repeatable capability transfers mask
/// thread entries until the reply has been copied: an interrupted send consumes
/// the outgoing handles even when the Loader never received them.
pub(crate) fn ask_loader(
    c: &Handle<Channel>,
    w: &Writer,
    handles: Option<rt::handle::Outgoing>,
) -> u32 {
    struct TransferMask(bool);
    impl Drop for TransferMask {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: restore the entry state that this thread already enabled.
                // The reply and all outgoing resources have ended before this guard.
                unsafe { rt::upcall::enable() }.expect("restore Loader transfer entry state");
            }
        }
    }
    let _mask = if handles.is_some() {
        match rt::upcall::mask() {
            Ok(was_masked) => TransferMask(!was_masked),
            Err(_) => return proto_loader::IO,
        }
    } else {
        TransferMask(false)
    };
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
                let status = proto_wire::Reader::new(reply.bytes(&mut buffer))
                    .u32()
                    .unwrap_or(proto_loader::IO);
                if TERMINAL_PACKET_PROBE.load(Ordering::Relaxed) != 0 {
                    let method =
                        proto_wire::Header::read(&mut proto_wire::Reader::new(w.as_bytes()))
                            .map_or(0, |h| h.method);
                    TERMINAL_PACKET_RESULT
                        .store((method as u64) << 32 | status as u64, Ordering::Release);
                }
                return status;
            }
        }
    }
}

/// Handles of the sessions `sessions` that are there, by their slots, to
/// the loader `c`: abi::MESSAGE_HANDLES of them a message, so further ones go
/// in a second Handles. The sessions move whatever comes of it; the
/// loader's code of the first message that failed, 0 once all went.
pub(crate) fn give_sessions<const N: usize>(
    c: &Handle<Channel>,
    sessions: [(proto_loader::Slot, Option<Handle<Channel>>); N],
) -> u32 {
    use proto_loader::Method;
    let sessions = match crate::loader_probe::bundle(sessions) {
        Ok(sessions) => sessions,
        Err(_) => return proto_loader::IO,
    };
    let mut left = sessions
        .into_iter()
        .filter_map(|(slot, s)| s.map(|s| (slot, s)));
    loop {
        let mut w = Writer::new();
        if Method::Handles.header().write(&mut w).is_err() {
            return proto_loader::IO;
        }
        let mut handles = rt::handle::Outgoing::new();
        for (slot, session) in left.by_ref().take(rt::abi::MESSAGE_HANDLES) {
            let session = match crate::loader_probe::replace(slot, session) {
                Ok(session) => session,
                Err(_) => return proto_loader::IO,
            };
            if w.u32(slot as u32).is_err() || handles.push(session.erase()).is_err() {
                return proto_loader::IO;
            }
        }
        if handles.is_empty() {
            if crate::loader_probe::omit_completion() {
                return 0;
            }
            let mut done = Writer::new();
            if Method::HandlesDone.header().write(&mut done).is_err() {
                return proto_loader::IO;
            }
            let code = ask_loader(c, &done, None);
            if code == 0 && crate::loader_probe::repeat_bundle() {
                let expected = Status::Kernel(rt::abi::Error::BadState).code();
                if ask_loader(c, &done, None) != expected {
                    return proto_loader::IO;
                }
                let mut late = Writer::new();
                if Method::Handles.header().write(&mut late).is_err()
                    || ask_loader(c, &late, None) != expected
                {
                    return proto_loader::IO;
                }
            }
            return code;
        }
        let code = ask_loader(c, &w, Some(handles));
        if code != 0 {
            return code;
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
    spawn_search(path, None, argv, envp, attributes, actions)
}

/// posix_spawnp: `file` is a name with no slash, searched in the
/// directories of `search` (the value of PATH, `None` for the plain
/// posix_spawn of `file` as a path). The search comes after the file
/// actions, as an execvp in the child would make it: in the directory the
/// actions left as the current one, with the descriptors they made. A
/// directory that is empty stands for the current directory. The first file
/// the caller may execute is the program (a regular file, by the effective
/// IDs); ENOENT when none exists, EACCES when one exists that the caller may
/// not execute (a directory of that name counts).
pub fn spawn_search<'s, 'a>(
    file: &[u8],
    search: Option<&[u8]>,
    argv: impl Iterator<Item = &'s [u8]> + Clone,
    envp: impl Iterator<Item = &'s [u8]> + Clone,
    attributes: SpawnAttributes,
    actions: impl Iterator<Item = FileAction<'a>>,
) -> Result<i32, i32> {
    use crate::constants::{EINVAL, ENOENT};
    if file.is_empty() {
        return Err(ENOENT);
    }
    let pgroup = attributes.pgroup;
    if pgroup > i32::MAX as u32 || attributes.flags & !proto_process::SPAWN_FLAGS != 0 {
        return Err(EINVAL);
    }
    let mut shadow = Shadow::take()?;
    shadow.umask = attributes.umask;
    shadow.real_ids = attributes.flags & proto_process::SPAWN_RESETIDS != 0
        && (geteuid() != getuid() || getegid() != getgid());
    let spawned = actions
        .into_iter()
        .try_for_each(|action| shadow.apply(action))
        .and_then(|()| match search {
            None => spawn_shadowed(file, argv, envp, attributes, &shadow),
            Some(search) => {
                let mut program = [0; proto_loader::PATH_MAX];
                let program = shadow.find_program(file, search, &mut program)?;
                spawn_shadowed(program, argv, envp, attributes, &shadow)
            }
        });
    shadow.finish();
    spawned
}

/// X_OK of faccessat.
const X_OK: i32 = 1;

/// Whether the real IDs of the caller have the access `bits` (R_OK 4, W_OK 2,
/// X_OK 1) to `path`: EACCES or the error of the lookup.
fn real_access(path: &[u8], bits: i32) -> Result<(), i32> {
    crate::names::faccessat(crate::names::AT_FDCWD, path, bits, 0)
}

impl Shadow {
    /// An Open action under RESETIDS with differing IDs: what the real IDs
    /// may do to the file. An existing file needs the bits of the access
    /// mode (and write for O_TRUNC); a name to create needs write and search
    /// in its directory.
    fn real_open_allowed(&self, full: &[u8], flags: i32) -> Result<(), i32> {
        use crate::constants::{ENOENT, O_ACCMODE, O_CREAT, O_RDWR, O_TRUNC, O_WRONLY};
        match crate::names::fstatat(crate::names::AT_FDCWD, Some(full), 0) {
            Ok(_) => {
                let mut bits = match flags & O_ACCMODE {
                    O_WRONLY => 2,
                    O_RDWR => 6,
                    _ => 4,
                };
                if flags & O_TRUNC != 0 {
                    bits |= 2;
                }
                real_access(full, bits)
            }
            Err(ENOENT) if flags & O_CREAT != 0 => {
                let slash = full.iter().rposition(|&byte| byte == b'/').unwrap_or(0);
                let parent: &[u8] = if slash == 0 { b"/" } else { &full[..slash] };
                real_access(parent, 2 | X_OK)
            }
            // A lookup that fails otherwise (a missing directory above, no
            // search permission) is the answer of the open that follows.
            Err(_) => Ok(()),
        }
    }

    /// The first directory of `search` with a file `file` the caller may
    /// execute, as an absolute path against the shadow's current directory.
    fn find_program<'o>(
        &self,
        file: &[u8],
        search: &[u8],
        out: &'o mut [u8; proto_loader::PATH_MAX],
    ) -> Result<&'o [u8], i32> {
        use crate::constants::{EACCES, ENOENT};
        let mut denied = false;
        for directory in search.split(|&byte| byte == b':') {
            let directory: &[u8] = if directory.is_empty() {
                b"."
            } else {
                directory
            };
            let mut candidate = [0; proto_loader::PATH_MAX];
            let length = directory.len() + 1 + file.len();
            if length > candidate.len() {
                continue;
            }
            candidate[..directory.len()].copy_from_slice(directory);
            candidate[directory.len()] = b'/';
            candidate[directory.len() + 1..length].copy_from_slice(file);
            let mut full = [0; proto_loader::PATH_MAX];
            let Ok(full) = self.absolute(&candidate[..length], &mut full) else {
                continue;
            };
            // A candidate that execve would refuse is passed over, as execvp
            // passes it: a directory has the search permission for X_OK and
            // is no program (execve answers EACCES, which execvp remembers
            // and reports when no later directory has the program). The
            // permission is that of the effective IDs, as execve checks it.
            match crate::names::fstatat(crate::names::AT_FDCWD, Some(full), 0) {
                Ok(info) if info.kind == 2 => {}
                Ok(_) => {
                    denied = true;
                    continue;
                }
                Err(_) => continue,
            }
            // With RESETIDS and differing IDs the child runs under the real
            // ones: they decide.
            let how = if self.real_ids {
                0
            } else {
                crate::names::AT_EACCESS
            };
            match crate::names::faccessat(crate::names::AT_FDCWD, full, X_OK, how) {
                Ok(()) => {
                    out[..full.len()].copy_from_slice(full);
                    return Ok(&out[..full.len()]);
                }
                Err(EACCES) => denied = true,
                Err(_) => {}
            }
        }
        Err(if denied { EACCES } else { ENOENT })
    }
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
    if let Err(error) = crate::signals::prepare_exec_jobs() {
        block.mask.store(mask, Ordering::SeqCst);
        crate::signals::deliver_now();
        return Err(error);
    }
    let pending = block.pending.load(Ordering::SeqCst) & !proto_process::job::MASK;
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
    if !move_files(&c) {
        // The loader refused the sessions (a pipe's end without the
        // session of the pipe service): the new image may not start with
        // descriptors it cannot use, and this one gave its sessions away.
        rt::sys::process_exit(127);
    }
    if ask(&request(Method::ExecCommit, &[])?).is_err() {
        // A distinct probe status witnesses refusal while this image still runs.
        if crate::loader_probe::omit_completion() {
            rt::sys::process_exit(126);
        }
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
/// service should have killed it. It says so on the console and
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
/// descriptions with the last of them), then a fresh RAM session sharing
/// retained descriptions and the clock and console sessions go to the Loader.
/// The new image keeps descriptions and offsets under its authenticated binding.
/// Whether the Loader took them.
fn move_files(c: &Handle<Channel>) -> bool {
    use proto_loader::Slot;
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
    // descriptor.
    if !crate::relibc::detach_for_exec() {
        return false;
    }
    crate::shared::abandon_holds();
    let mut kept = [rt::fs::PreparedOpen {
        fd: 0,
        slot: 0,
        generation: 0,
        random: false,
    }; posix_fs::OPEN_MAX];
    let sessions = crate::shared::with_files(|files| {
        let count = files.kept_by_exec(&mut kept);
        let (channel, uart) = files.sessions();
        Ok((channel.raw(), uart.map(Handle::raw), count))
    });
    let clock = crate::clock::session().map(Handle::raw);
    let Ok((files, uart, count)) = sessions else {
        return false;
    };
    // The old image's session remains tied to its authority. The new image
    // receives a true unclaimed clone whose Pending binding the Loader authenticates.
    let Ok(files) =
        rt::fs::Files::clone_exact_on(&Handle::<Channel>::borrowed(files), &kept[..count])
    else {
        return false;
    };
    // The session with the pipe service moves as it is, with the ends of
    // the descriptors that stay. The operations that wait in it for the
    // threads of this image go first, or they would wait on in the new
    // image's session, and count against its limits: the stopped threads
    // never end them. The sessions of the RAM files and the clock keep no
    // waiting operation, so a general Abandon of long operations has
    // nothing else to do here.
    let (pipes, terminal) = crate::shared::with_files(|files| {
        Ok((
            files.pipes().map(Handle::raw),
            files.terminal().map(Handle::raw),
        ))
    })
    .unwrap_or((None, None));
    if let Some(pipes) = pipes {
        crate::pipes::abandon(pipes);
    }
    // The terminal's session moves too, its waiting operations gone.
    if let Some(terminal) = terminal {
        crate::terminal::abandon(terminal);
    }
    // The handles move: this image's owner never uses them again.
    let moved = |raw: Option<rt::abi::Handle>| raw.map(Handle::<Channel>::from_raw);
    give_sessions(
        c,
        [
            (Slot::Files, Some(files)),
            (Slot::Clock, moved(clock)),
            (Slot::Driver, moved(uart)),
            (Slot::Pipes, moved(pipes)),
            (Slot::Terminal, moved(terminal)),
            (Slot::Entropy, moved(crate::random::session())),
        ],
    ) == 0
}

/// The errno of a refused Clone: EAGAIN for a service at its limit of
/// clones or sessions (a limit of the moment), ENOMEM, EIO otherwise.
pub(crate) fn clone_errno(status: Status) -> i32 {
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
    // The child's own sessions: clones of the caller's, the one of the
    // RAM files sharing the descriptions the child starts with.
    let clock = crate::clock::session().ok_or(EIO)?;
    let clock = rt::service::clone_session(clock, &proto_clock::Method::Clone.header().bytes())
        .map_err(clone_errno)?;
    let (files, uart) = crate::shared::with_files(|fs| {
        let (files, uart) = fs.sessions();
        Ok((files.raw(), uart.map(Handle::raw)))
    })?;
    let mut kept = [rt::fs::PreparedOpen {
        fd: 0,
        slot: 0,
        generation: 0,
        random: false,
    }; posix_fs::OPEN_MAX];
    let mut count = 0;
    for held in shadow.shared() {
        kept[count] = held;
        count += 1;
    }
    let files = rt::fs::Files::clone_exact_on(&Handle::<Channel>::borrowed(files), &kept[..count])
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
    // The child's session with the pipe service: a clone of the caller's
    // that holds the ends the child starts with (none the probe of the
    // loader's refusal gives).
    let pipes = match crate::shared::with_files(|fs| Ok(fs.pipes().map(Handle::raw)))? {
        Some(_) if NO_PIPES_SESSION.load(Ordering::Relaxed) => None,
        Some(pipes) => {
            let (ends, count) = shadow.shared_pipes();
            Some(crate::fork::pipes_clone(pipes, &ends[..count])?)
        }
        None => None,
    };
    // The child's session with the terminal service: a clone of the
    // caller's.
    let terminal = match crate::shared::with_files(|fs| Ok(fs.terminal().map(Handle::raw)))? {
        Some(terminal) => {
            let (ids, count) = shadow.shared_terminals();
            Some(crate::terminal::clone_kept(terminal, Some(&ids[..count]))?)
        }
        None => None,
    };
    let fake = FAKE_TERMINAL.load(Ordering::Acquire);
    let terminal = if fake != 0 {
        Some(
            rt::sys::handle_duplicate(
                &Handle::<Channel>::borrowed(rt::abi::Handle(fake)),
                rt::abi::Rights::SEND | rt::abi::Rights::TRANSFER,
            )
            .map_err(|_| EIO)?,
        )
    } else {
        terminal
    };
    let entropy = crate::fork::entropy_clone();
    let sessions = [
        (Slot::Files, Some(files)),
        (Slot::Clock, Some(clock)),
        (Slot::Driver, uart),
        (Slot::Pipes, pipes),
        (Slot::Terminal, terminal),
        (Slot::Entropy, entropy),
    ];
    if give_sessions(c, sessions) != 0 {
        return Err(EIO);
    }
    let packet_probe = TERMINAL_PACKET_PROBE.load(Ordering::Acquire);
    for (packet_index, packet) in shadow.terminal_opens[..shadow.terminal_count]
        .chunks(proto_loader::TERMINAL_PACKET)
        .enumerate()
    {
        if packet_probe == 4 {
            break;
        }
        let mut w = Writer::new();
        Method::TerminalActions
            .header()
            .write(&mut w)
            .map_err(|_| EIO)?;
        w.u32(packet.len() as u32).map_err(|_| EIO)?;
        for (i, &action) in packet.iter().enumerate() {
            let action = if packet_probe == 1 && packet_index == 0 && i == 1 {
                packet[0]
            } else if packet_probe == 2 && packet_index == 1 && i == 0 {
                proto_loader::TerminalAction {
                    flags: u32::MAX,
                    ..action
                }
            } else {
                action
            };
            action.write(&mut w).map_err(|_| EIO)?;
        }
        let code = ask_loader(c, &w, None);
        if code != 0 {
            return Err(load_errno(code));
        }
    }
    if packet_probe == 3 {
        let mut w = Writer::new();
        Method::TerminalActions
            .header()
            .write(&mut w)
            .map_err(|_| EIO)?;
        w.u32(1).map_err(|_| EIO)?;
        proto_loader::TerminalAction::default()
            .write(&mut w)
            .map_err(|_| EIO)?;
        let code = ask_loader(c, &w, None);
        if code != 0 {
            return Err(load_errno(code));
        }
    }
    let mut w = Writer::new();
    Method::Go.header().write(&mut w).map_err(|_| EIO)?;
    let code = ask_loader(c, &w, None);
    if code != 0 {
        return Err(load_errno(code));
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

/// The probe of a commit before the loader's image is ready: a
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

/// The probe of the loads a record may have at once: up to
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
/// TtySignal of `signal` to the group `pgid` through the process's own
/// session, for the probe that the process service takes it from the
/// notary session of the terminal service alone: the errno of the
/// refusal, 0 when it was taken.
pub fn probe_tty_signal(pgid: u32, signal: u32) -> i32 {
    match request(proto_process::Method::TtySignal, &[0, pgid, signal]).and_then(|w| ask(&w)) {
        Ok(_) => 0,
        Err(errno) => errno,
    }
}

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

/// The probe of `addopen`: the descriptor an open action makes in the
/// caller's table while the spawn goes on has FD_CLOEXEC whatever the
/// action's flags say. 1 when it does, 0 when it does not, the negated
/// errno of a failure.
pub fn probe_addopen_cloexec(path: &[u8]) -> i32 {
    let Ok(mut shadow) = Shadow::take() else {
        return -crate::constants::EIO;
    };
    let result = match shadow.apply(FileAction::Open {
        fd: 20,
        path,
        flags: 0,
        mode: 0,
    }) {
        Ok(()) => {
            let own = shadow.opened.iter().flatten().next().copied();
            let seen = crate::shared::with_files(|files| {
                Ok(own.map(|own| {
                    files
                        .descriptors()
                        .any(|(fd, _, flags)| fd == own && flags.close_on_exec)
                }))
            });
            match seen {
                Ok(Some(found)) => i32::from(found),
                _ => -crate::constants::EIO,
            }
        }
        Err(errno) => -errno,
    };
    shadow.finish();
    result
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

/// OPEN_EXEC through the process's bound RAM session, using a live paid
/// pathname proof and the current wire. A normal process receives EPERM.
/// A returned image gives 0; malformed replies and transport errors give EIO.
pub fn probe_open_exec(path: &[u8]) -> i32 {
    use crate::constants::{EIO, EPERM};
    let Ok(session) = crate::shared::with_files(|files| Ok(files.sessions().0.raw())) else {
        return EIO;
    };
    // The process keeps its session alive; this borrowed view closes no handle.
    // The paid request and its Proof cleanup execute outside the files lock.
    let files = core::mem::ManuallyDrop::new(rt::fs::Files::from_sessions(
        Handle::from_raw(session),
        None,
    ));
    match files.open_exec_bound(path) {
        Ok(image) => {
            drop(image);
            0
        }
        Err(proto_wire::Status::Unknown(proto_fs::PERMISSION)) => EPERM,
        Err(_) => EIO,
    }
}
