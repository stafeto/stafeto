// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The data file service at `/data` (`proto_data`, services/datafs): the process's session with it
//! and the paths and descriptions of the volume it serves.
//!
//! * A path belongs to `/data` by its absolute form (the current directory, the dots and the
//!   slashes applied first, as for `/proc`): `/data` and everything below it, never `/datax`
//!   (`posix_fs::data::volume_path`). The service gets the path below `/data`, absolute from the
//!   root of the volume, with no dots. `..` is resolved by the dots rule of the layer with no
//!   question to the service, so `a/ghost/..` names `a` and does not fail for the missing `ghost`;
//!   `/data/..` is `/`, a path of the RAM file service.
//! * The session comes when it is first needed: TakeRoot asks the process service for the root of
//!   the service, SESSION with a copy of the process's identity session gives a session that is
//!   bound to the process. A path under `/data` never goes to the RAM file service: while the
//!   process service has no root (UNREGISTERED: the service has not registered it yet at boot, or
//!   it is marked broken) the layer asks again every millisecond for a second, then answers EIO. An
//!   image that has no data service gets EIO after that second for a path under `/data`; its files
//!   are never below `/data` (xtask refuses them). A session that arrived in the slot
//!   Data (a fork, a spawn or an exec) is unbound or has lapsed: the first call that needs an
//!   identity answers NOT_BOUND, and the layer sends BIND with a copy of the identity session and
//!   asks once more. What a description holds is read without a binding.
//! * A call the service answers WouldBlock (every job in use) is repeated every millisecond for a
//!   second, then EIO. A service that went (PEER_CLOSED) drops the session, the description of the
//!   current directory and the listings: the descriptions of the old instance answer EIO (the
//!   service says STALE to the handles of an earlier instance), `close` of one succeeds with no
//!   call, and the next path call takes a session of the new instance and opens the current
//!   directory again from its string.
//! * Waits. The retries sleep with a timed wait (`pause`, clock_nanosleep: a thread of any level
//!   lets the service's worker run, and a signal ends it with EINTR). The session is taken under a
//!   lock (`TAKE`) that blocks its waiters; the lock is held for one round trip at a time, never
//!   across a sleep. A holder is in a critical section of the layer, so a signal handler cannot run
//!   on its thread while it holds the lock: a handler that calls `open` finds the lock free or held
//!   by another thread and never waits for itself. The listings have their own short lock, held
//!   for memory work alone.
//! * The current directory under `/data` holds a description of the directory opened for search
//!   only, so that the service refuses to rename or remove it (EBUSY) and the string of the layer
//!   stays true. A forked child shares it; an exec or a spawn opens it again at the first path call.
//! * Writes. `open` takes O_CREAT, O_EXCL, O_TRUNC, O_APPEND and O_SYNC (`posix_fs::data::open_plan`:
//!   an open for reading with O_TRUNC is an open for writing of its own that truncates and closes,
//!   then the reading open), the creation mode has the umask applied here. `write` and `pwrite` go
//!   in messages of at most 1,012 bytes, each one atomic against the other writers and readers of
//!   the file, and the end of an O_APPEND file is taken for each message: a write of more than one
//!   message can have another writer's bytes between its messages (the service has no longer
//!   atomic unit). The result is the sum of the messages that went; a failure after some (ENOSPC,
//!   EFBIG, EINTR) is that sum, the next call meets the error again, and the first message alone
//!   fails with the error (the limit of the file size gives SIGXFSZ then). `rename` takes two
//!   names of the volume (EXDEV across the mount), `link` of a file is EMLINK (a name of the volume
//!   has one), `symlink`, `mkfifo` and `mknod` are EPERM, `unlink` of a directory is EISDIR, and
//!   record locks are ENOLCK. A program is never run from the volume (EACCES).
//! * Limits. At most 32 descriptions a session holds (EMFILE), a clone refused for its tree's clones
//!   or the table (EAGAIN), at most 2,048 metadata pairs a volume and 1,024 directories (ENOSPC for
//!   MKDIR, the creation of a file and a RENAME into another directory; removal, writes, truncation
//!   and changes of mode and times are never refused by these caps), no inline data (a file takes
//!   4 KiB at least), and a reserve of 64 blocks that refuses writes, creation, rename and changes
//!   of attributes to users other than root (ENOSPC), never removal.

use crate::constants::*;

/// A line that says why a call of the data volume failed, in a layer built with the feature
/// `trace` (the measurement build of libc.so): the step and the status or error behind an errno.
#[cfg(feature = "trace")]
macro_rules! why {
    ($($arg:tt)*) => {
        rt::println!("posix-abi: data: {}", format_args!($($arg)*))
    };
}
#[cfg(not(feature = "trace"))]
macro_rules! why {
    // Checked and then dropped: the variables the lines name stay in use.
    ($($arg:tt)*) => {
        if false {
            let _ = format_args!($($arg)*);
        }
    };
}
use core::ffi::c_int;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use posix_fs::data::{self as pure, errno_of};
use posix_fs::{DataTarget, Target};
use proto_data as p;
use proto_wire::{Reader, Status, Writer};
use rt::abi::{Error, MESSAGE_MAX, Rights};
use rt::handle::{Channel, Handle};

// The flags the volume's rules (posix-fs) name are the layer's.
const _: () = {
    use posix_fs::data::oflag as o;
    assert!(o::ACCMODE == O_ACCMODE && o::WRONLY == O_WRONLY && o::RDWR == O_RDWR);
    assert!(o::CREAT == O_CREAT && o::EXCL == O_EXCL && o::TRUNC == O_TRUNC);
    assert!(o::APPEND == O_APPEND && o::DIRECTORY == O_DIRECTORY && o::SYNC == O_SYNC);
};

/// A path of the volume with the slash of its end noted: what the service takes.
pub struct Vol {
    bytes: [u8; crate::names::MAX_PATH + 1],
    len: usize,
    /// The path named a directory with a slash at its end.
    pub trailing_slash: bool,
}

impl Vol {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn from(volume: &[u8], trailing_slash: bool) -> Option<Vol> {
        let mut out = Vol {
            bytes: [0; crate::names::MAX_PATH + 1],
            len: volume.len(),
            trailing_slash,
        };
        out.bytes.get_mut(..volume.len())?.copy_from_slice(volume);
        (volume.len() <= p::MAX_PATH).then_some(out)
    }
}

// ---------------------------------------------------------------- the session

/// The session with the data file service, 0 for none.
static SESSION: AtomicU64 = AtomicU64::new(0);

/// The process's session with the data file service, which the start gives in the slot Data.
///
/// # Safety
/// Startup, on the only thread.
pub unsafe fn init(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
    posix_fs::set_data_release(close_description);
    // The image's current directory has no description of its own yet.
    CWD_HANDLE.store(NONE, Ordering::Release);
    CWD_CHECKED.store(false, Ordering::Release);
}

/// A forked child: `session`, the clone the parent made (or none), takes the place of the parent's
/// value, which names nothing of the child's. The description of the current directory is the same
/// number in the clone.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
    // The child's session is the clone: the parent's failed close is not its own.
    CLOSE_FAILED.store(false, Ordering::Release);
    if SESSION.load(Ordering::Acquire) == 0 {
        CWD_HANDLE.store(NONE, Ordering::Release);
        CWD_CHECKED.store(false, Ordering::Release);
    }
    LISTINGS.forget_all();
}

/// The session with the data file service, if the process has one: for the requests that need no
/// session of their own (the clones a child gets, the exec's move).
pub fn session() -> Option<rt::abi::Handle> {
    match SESSION.load(Ordering::Acquire) {
        0 => None,
        raw => Some(rt::abi::Handle(raw)),
    }
}

/// Why a try to take the session did not end it.
enum Attempt {
    /// Not yet: the process service has no root (UNREGISTERED) or the service is busy.
    Retry,
    /// The errno of the failure.
    Failed(i32),
}

/// The root of the service from the process service (TakeRoot).
fn take_root() -> Result<Handle<Channel>, Attempt> {
    let mut request = Writer::new();
    proto_process::take_root(proto_process::ROOT_DATA, &mut request)
        .map_err(|_| Attempt::Failed(EIO))?;
    let mut reply = crate::process::send_again(&request).map_err(|error| {
        why!("TakeRoot not sent: {error:?}");
        Attempt::Failed(EIO)
    })?;
    let mut buffer = [0; MESSAGE_MAX];
    match Reader::new(reply.bytes(&mut buffer)).u32() {
        Ok(0) => reply.handles.take::<Channel>(0).map_err(|error| {
            why!("TakeRoot gave no root handle: {error:?}");
            Attempt::Failed(EIO)
        }),
        Ok(proto_process::UNREGISTERED) => {
            why!("TakeRoot: UNREGISTERED, no root yet");
            Err(Attempt::Retry)
        }
        other => {
            why!("TakeRoot refused: {other:?}");
            Err(Attempt::Failed(EIO))
        }
    }
}

/// A copy of the identity session for a request of the service to carry (it moves with the call).
fn identity_copy() -> Result<rt::handle::Handle<rt::handle::Any>, i32> {
    let Some(identity) = crate::process::identity() else {
        why!("no identity session in the start data of this process");
        return Err(EIO);
    };
    // DUPLICATE as well: the service copies the handle it keeps for each Vouch (the kernel copies
    // only a handle that has the right).
    rt::sys::handle_duplicate(
        identity,
        Rights::NOTIFY | Rights::TRANSFER | Rights::DUPLICATE,
    )
    .map(Handle::erase)
    .map_err(|error| {
        why!("copy of the identity session refused: {error:?}");
        EIO
    })
}

/// A session from the root: SESSION with a copy of the identity session, which the service vouches
/// for before it answers. One try.
fn take_session(root: &Handle<Channel>) -> Result<Handle<Channel>, Attempt> {
    let request = p::Method::Session.header().bytes();
    let copy = identity_copy().map_err(Attempt::Failed)?;
    let mut reply = match rt::sys::send_handles(root, &request, [copy]) {
        Ok(reply) => reply,
        Err(refused) if refused.error == Error::Interrupted => return Err(Attempt::Retry),
        Err(refused) => {
            why!("SESSION not sent to the root: {:?}", refused.error);
            return Err(Attempt::Failed(EIO));
        }
    };
    let mut buffer = [0; MESSAGE_MAX];
    match Reader::new(reply.bytes(&mut buffer)).u32() {
        Ok(0) => reply.handles.take::<Channel>(0).map_err(|error| {
            why!("SESSION gave no session handle: {error:?}");
            Attempt::Failed(EIO)
        }),
        Ok(status) if status == busy_code() => Err(Attempt::Retry),
        Ok(status) => {
            why!("SESSION refused with status {status}");
            Err(Attempt::Failed(errno_of(status)))
        }
        Err(_) => Err(Attempt::Failed(EIO)),
    }
}

/// The lock of the taking of the session: its waiters block (a futex), and its holder is in a
/// critical section for one round trip.
static TAKE: posix_sync::LayerLock = posix_sync::LayerLock::new();

/// The session of the process: the one it has, or one taken now. The taker holds `TAKE`, so the
/// others block until the session is there; a try that must wait (no root yet, a busy service)
/// ends, lets the lock go and sleeps outside it, for a second at most (then EIO). The raw handle
/// stays valid while the process runs: a session that died is parked and never closed, so that a thread
/// that read it before never sends to another channel under its number.
fn ensure() -> Result<rt::abi::Handle, i32> {
    let mut tries = 0;
    loop {
        if let Some(session) = session() {
            return Ok(session);
        }
        let attempt = {
            let _held = TAKE.lock();
            if let Some(session) = session() {
                return Ok(session);
            }
            match take_root().and_then(|root| take_session(&root)) {
                Ok(session) => {
                    let raw = session.into_raw();
                    SESSION.store(raw.0, Ordering::Release);
                    return Ok(raw);
                }
                Err(attempt) => attempt,
            }
        };
        match attempt {
            Attempt::Retry if tries < BUSY_TRIES => {
                tries += 1;
                pause()?;
            }
            Attempt::Retry => {
                why!("no session after a second of tries");
                return Err(EIO);
            }
            Attempt::Failed(errno) => return Err(errno),
        }
    }
}

/// The session died with its instance: a later call takes a session of the new one.
fn forget(raw: rt::abi::Handle) {
    // The handle is parked, never closed (see `ensure`).
    if SESSION
        .compare_exchange(raw.0, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // What the old instance held is gone with it: the description of the current directory
        // (the next path call opens it again from the string) and the listings.
        CWD_HANDLE.store(NONE, Ordering::Release);
        CWD_CHECKED.store(false, Ordering::Release);
        // A close that failed was a call on the session that is gone.
        CLOSE_FAILED.store(false, Ordering::Release);
        LISTINGS.forget_all();
    }
}

// ---------------------------------------------------------------- the calls

/// The status of a reply for a request the service has no job for (WouldBlock).
fn busy_code() -> u32 {
    Status::Kernel(Error::WouldBlock).code()
}

/// The calls repeated for a busy service, a millisecond apart: one second.
const BUSY_TRIES: u32 = 1000;

/// Waits a millisecond with a timed sleep: the thread leaves the processor whatever its level (the
/// worker of the service runs), and a signal that is caught ends the wait with EINTR.
fn pause() -> Result<(), i32> {
    crate::threads::sleep::clock_nanosleep(
        crate::clock::CLOCK_MONOTONIC,
        0,
        posix_types::Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        },
    )
    .map_err(|(errno, _)| errno)
}

/// A reply: its bytes after the status (in `bytes`, `len` of them) and the handle it brought.
pub struct Answer {
    bytes: [u8; MESSAGE_MAX],
    len: usize,
}

impl Answer {
    fn reader(&self) -> Reader<'_> {
        Reader::new(&self.bytes[..self.len])
    }
}

/// BIND with a copy of the identity session: INVALID for a session that is bound already (a thread
/// of the process was first) counts as done.
fn bind(session: rt::abi::Handle) -> Result<(), i32> {
    let request = p::Method::Bind.header().bytes();
    let channel = Handle::<Channel>::borrowed(session);
    let mut tries = 0;
    loop {
        let copy = identity_copy()?;
        let reply = match rt::sys::send_handles(&channel, &request, [copy]) {
            Ok(reply) => reply,
            Err(refused) if refused.error == Error::Interrupted => continue,
            Err(_) => return Err(EIO),
        };
        let mut buffer = [0; MESSAGE_MAX];
        match Reader::new(reply.bytes(&mut buffer)).u32() {
            Ok(0) => return Ok(()),
            Ok(p::INVALID) => return Ok(()),
            Ok(status) if status == busy_code() && tries < BUSY_TRIES => {
                tries += 1;
                pause()?;
            }
            Ok(status) => return Err(errno_of(status)),
            Err(_) => return Err(EIO),
        }
    }
}

/// One request to the session, and its reply: NOT_BOUND binds and asks once more, a busy service is
/// asked again for a second, a service that went drops the session (EIO).
fn call(request: &[u8]) -> Result<Answer, i32> {
    call_with(request, true)
}

/// `call`; with `take` false a process with no session fails with EIO at once and takes none (the
/// close of a description needs none).
fn call_with(request: &[u8], take: bool) -> Result<Answer, i32> {
    let mut bound = false;
    let mut reborn = false;
    let mut tries = 0;
    loop {
        let session = if take {
            ensure()?
        } else {
            session().ok_or(EIO)?
        };
        let channel = Handle::<Channel>::borrowed(session);
        let reply = match rt::sys::send(&channel, request) {
            Ok(reply) => reply,
            Err(Error::Interrupted) => continue,
            Err(Error::PeerClosed) => {
                why!("the session closed: the service went");
                forget(session);
                // A path call goes on at once with a session of the new instance; a call on a
                // description of the old one is told STALE there (EIO).
                if take && !reborn {
                    reborn = true;
                    continue;
                }
                return Err(EIO);
            }
            Err(error) => {
                why!("request not sent to the session: {error:?}");
                return Err(EIO);
            }
        };
        let mut buffer = [0; MESSAGE_MAX];
        let bytes = reply.bytes(&mut buffer);
        let mut r = Reader::new(bytes);
        let status = r.u32().map_err(|_| EIO)?;
        if status == 0 {
            let mut answer = Answer {
                bytes: [0; MESSAGE_MAX],
                len: bytes.len() - 4,
            };
            answer.bytes[..bytes.len() - 4].copy_from_slice(&bytes[4..]);
            return Ok(answer);
        }
        if status != 0 {
            why!("call answered with status {status}");
        }
        if status == p::NOT_BOUND && !bound {
            bound = true;
            bind(session)?;
            continue;
        }
        if status == busy_code() && tries < BUSY_TRIES {
            tries += 1;
            pause()?;
            continue;
        }
        // The limit of the process's file size: the layer sends SIGXFSZ for it once the locks are
        // let go (`finish_file_size` of the call that asked).
        if status == p::FILE_SIZE_LIMIT {
            return Err(crate::FILE_SIZE_REFUSAL);
        }
        return Err(errno_of(status));
    }
}

/// Builds a request with `build` and calls it.
fn ask(build: impl FnOnce(&mut Writer) -> Result<(), Status>) -> Result<Answer, i32> {
    let mut w = Writer::new();
    build(&mut w).map_err(|_| EIO)?;
    call(w.as_bytes())
}

// ---------------------------------------------------------------- paths

/// The path of `path` of the layer as a path of the volume, when it is under `/data` and the
/// service serves it: `path` against the current directory (`AT_FDCWD` or an absolute path), or
/// against the directory `dirfd` when that is a description of the service (WHERE gives where it
/// is). None for any other path, in a table with no service too.
pub fn route(dirfd: c_int, path: &[u8]) -> Result<Option<Vol>, i32> {
    if path.is_empty() || path.len() > crate::names::MAX_PATH {
        return Ok(None);
    }
    let mut absolute = [0u8; crate::names::MAX_PATH + 1];
    let length = if path[0] == b'/' || dirfd == crate::names::AT_FDCWD {
        let resolved =
            crate::shared::with_files(|files| files.resolve(path).map_err(crate::error))?;
        posix_path::simplify(resolved.as_bytes(), &mut absolute)
    } else {
        let Some(handle) = directory_handle(dirfd) else {
            return Ok(None);
        };
        let base = where_is(handle)?;
        let mut joined = [0u8; crate::names::MAX_PATH + 1];
        let mut at = 0;
        for part in [pure::MOUNT, base.bytes(), b"/", path] {
            let end = at + part.len();
            joined
                .get_mut(at..end)
                .ok_or(ENAMETOOLONG)?
                .copy_from_slice(part);
            at = end;
        }
        posix_path::simplify(&joined[..at], &mut absolute)
    };
    let absolute = &absolute[..length];
    let Some(volume) = pure::volume_path(absolute) else {
        return Ok(None);
    };
    ensure_cwd()?;
    Ok(Vol::from(volume, path.last() == Some(&b'/')))
}

/// The handle of the description of the service that `fd` names, when it is a directory of it.
fn directory_handle(fd: c_int) -> Option<u32> {
    let fd = u32::try_from(fd).ok()?;
    match crate::shared::with_fd(fd, |files| files.target(fd).map_err(crate::error)) {
        Ok(Target::Data(d)) if d.directory => Some(d.handle),
        _ => None,
    }
}

/// The canonical path of the description `handle` below `/data` (WHERE), as a Vol.
fn where_is(handle: u32) -> Result<Vol, i32> {
    let answer = ask(|w| p::handle_call(p::Method::Where, handle, w))?;
    let mut r = answer.reader();
    let path = r.bytes(r.left()).map_err(|_| EIO)?;
    Vol::from(path, false).ok_or(EIO)
}

/// The path `/data/...` of the description `target` (a descriptor of the service), for `fchdir` and
/// `realpath` of a descriptor.
pub fn descriptor_path(
    target: DataTarget,
    out: &mut [u8; crate::names::MAX_PATH + 1],
) -> Result<usize, i32> {
    let volume = where_is(target.handle)?;
    join(volume.bytes(), out)
}

/// `/data` and the path `volume` below it into `out`: the length.
fn join(volume: &[u8], out: &mut [u8; crate::names::MAX_PATH + 1]) -> Result<usize, i32> {
    let rest = if volume == b"/" { &[][..] } else { volume };
    let mut at = 0;
    for part in [pure::MOUNT, rest] {
        let end = at + part.len();
        out.get_mut(at..end)
            .ok_or(ENAMETOOLONG)?
            .copy_from_slice(part);
        at = end;
    }
    Ok(at)
}

/// stat of a path of the volume: `follow` makes no difference (the volume has no links).
pub fn stat(vol: &Vol) -> Result<proto_fs::NodeInfo, i32> {
    let answer = ask(|w| p::path_call(p::Method::Stat, vol.bytes(), w))?;
    let stat = p::Stat::from_bytes(&answer.bytes[..answer.len]).map_err(|_| EIO)?;
    if vol.trailing_slash && stat.kind != p::KIND_DIRECTORY {
        return Err(ENOTDIR);
    }
    Ok(pure::node_info(&stat))
}

/// access of a path of the volume: `bits` as `R_OK`, `W_OK` and `X_OK` (0 for `F_OK`), with the
/// real identifiers unless `effective`. The service's answer is the answer, except that a regular
/// file is never executable here (a program is not run from the volume): X_OK on one is EACCES.
pub fn access(vol: &Vol, bits: c_int, effective: bool) -> Result<(), i32> {
    let flags = if effective { 0 } else { p::ACCESS_REAL };
    ask(|w| p::access(vol.bytes(), bits as u32 & 7, flags, w))?;
    if bits & 1 != 0 && stat(vol)?.kind != 1 {
        return Err(EACCES);
    }
    Ok(())
}

/// statvfs of the volume: relibc's eleven words.
pub fn statvfs() -> Result<[u64; 11], i32> {
    let answer = ask(p::statfs)?;
    let mut r = answer.reader();
    let blocks = r.u64().map_err(|_| EIO)?;
    let free = r.u64().map_err(|_| EIO)?;
    let avail = r.u64().map_err(|_| EIO)?;
    let block = u64::from(r.u32().map_err(|_| EIO)?);
    const ST_NOSUID: u64 = 2;
    Ok([
        block,
        block,
        blocks,
        free,
        avail,
        blocks,
        free,
        avail,
        2,
        ST_NOSUID,
        p::NAME_MAX as u64,
    ])
}

/// The canonical path of the volume's `vol` below `/data` (realpath): the path must exist and be
/// searchable (STAT answers), and the answer is the path the layer made.
pub fn realpath(vol: &Vol, out: &mut [u8; crate::names::MAX_PATH + 1]) -> Result<usize, i32> {
    stat(vol)?;
    join(vol.bytes(), out)
}

// ---------------------------------------------------------------- the current directory

const NONE: u32 = u32::MAX;
/// The description of the current directory under `/data` (opened for search only), `NONE` for
/// none.
static CWD_HANDLE: AtomicU32 = AtomicU32::new(NONE);
/// The current directory of the image was looked at: when it is under `/data` its description is
/// open.
static CWD_CHECKED: AtomicBool = AtomicBool::new(false);

/// The canonical path `/data/...` of the directory `vol` names, which the caller may search (an
/// OPEN for search only, closed again): ENOTDIR for a file. The current directory is not changed.
pub fn directory(vol: &Vol, out: &mut [u8; crate::names::MAX_PATH + 1]) -> Result<usize, i32> {
    let handle = open_search(vol.bytes())?;
    close_description(handle);
    join(vol.bytes(), out)
}

/// The current directory became `absolute` (the layer's string is set): under `/data` its
/// description is opened for search only (the service then refuses to rename or remove the
/// directory), anywhere else the description of the one before is closed.
pub fn sync_cwd(absolute: &[u8]) -> Result<(), i32> {
    let Some(volume) = pure::volume_path(absolute) else {
        left();
        return Ok(());
    };
    let handle = open_search(volume)?;
    let old = CWD_HANDLE.swap(handle, Ordering::AcqRel);
    CWD_CHECKED.store(true, Ordering::Release);
    if old != NONE {
        close_description(old);
    }
    Ok(())
}

/// The current directory left `/data` (a chdir elsewhere): its description closes.
pub fn left() {
    let old = CWD_HANDLE.swap(NONE, Ordering::AcqRel);
    CWD_CHECKED.store(true, Ordering::Release);
    if old != NONE {
        close_description(old);
    }
}

/// The description of the current directory, if one is open: a forked child carries it.
pub fn cwd_handle() -> Option<u32> {
    match CWD_HANDLE.load(Ordering::Acquire) {
        NONE => None,
        handle => Some(handle),
    }
}

/// The image has not looked at its current directory yet (a new image after exec or spawn): when it
/// is under `/data` the description is opened now.
fn ensure_cwd() -> Result<(), i32> {
    if CWD_CHECKED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    let cwd = crate::shared::with_files(|files| {
        let mut copy = [0u8; crate::names::MAX_PATH + 1];
        let cwd = files.cwd();
        copy[..cwd.len()].copy_from_slice(cwd);
        Ok((copy, cwd.len()))
    })?;
    let Some(volume) = pure::volume_path(&cwd.0[..cwd.1]) else {
        return Ok(());
    };
    match open_search(volume) {
        Ok(handle) => CWD_HANDLE.store(handle, Ordering::Release),
        // The service could not be asked (it is gone or not back yet): the next path call tries
        // again. Any other answer (the directory is gone) stands: relative paths fail there.
        Err(EIO) => CWD_CHECKED.store(false, Ordering::Release),
        Err(_) => {}
    }
    Ok(())
}

/// A CLOSE of a description failed while the session was there.
static CLOSE_FAILED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------- descriptions

/// OPEN of a directory with no access bits: the service holds its path and no place of the volume.
fn open_search(path: &[u8]) -> Result<u32, i32> {
    let answer = ask(|w| p::open(path, p::DIRECTORY, 0, w))?;
    answer.reader().u32().map_err(|_| EIO)
}

/// The requests of an OPEN: the path, the protocol's flags and mode. The answer is the handle and
/// whether it names a directory. A directory opened for reading with no O_DIRECTORY gets
/// IS_DIRECTORY from the service for a file open: the layer asks again for a listing.
fn open_raw(vol: &Vol, flags: u32, mode: u32) -> Result<(u32, bool), i32> {
    let (answer, listing) = match ask(|w| p::open(vol.bytes(), flags, mode, w)) {
        Ok(answer) => (answer, flags & p::DIRECTORY != 0),
        Err(EISDIR) if flags & (p::WRITE | p::DIRECTORY) == 0 => (
            ask(|w| p::open(vol.bytes(), flags | p::DIRECTORY, mode, w))?,
            true,
        ),
        Err(errno) => return Err(errno),
    };
    let mut r = answer.reader();
    let handle = r.u32().map_err(|_| EIO)?;
    let kind = r.u32().map_err(|_| EIO)?;
    Ok((handle, listing || kind == p::KIND_DIRECTORY))
}

/// open of a path of the volume: `flags` are the layer's, the mode and the creation mask are the
/// caller's (`posix_fs::data::open_plan` translates them). The descriptor is the lowest free one.
pub fn open(vol: &Vol, flags: c_int, mode: u32, umask: u32) -> Result<c_int, i32> {
    // The flags the file service takes, and no others.
    let known = O_ACCMODE
        | O_DIRECTORY
        | O_CLOEXEC
        | O_CLOFORK
        | O_CHANGES
        | O_NOCTTY
        | O_NONBLOCK
        | O_CREAT
        | O_EXCL
        | O_TRUNC
        | O_APPEND
        | O_NOFOLLOW
        | O_SYNC;
    if flags & !known != 0 {
        return Err(EINVAL);
    }
    let mut plan = pure::open_plan(flags, mode, umask)?;
    // A name that ends in a slash is a directory: no file is made or opened for it.
    if vol.trailing_slash && flags & O_CREAT != 0 {
        return Err(EISDIR);
    }
    if plan.truncate_first {
        // The truncation (and the creation) is an open for writing of its own, which closes at
        // once; the caller's description is the reading one that follows.
        let first = pure::truncating_open(plan);
        let (handle, _) = open_raw(vol, first.flags, first.mode)?;
        close_description(handle);
        plan = pure::reading_open(plan);
    }
    let (handle, directory) = open_raw(vol, plan.flags, plan.mode)?;
    if vol.trailing_slash && !directory {
        close_description(handle);
        return Err(ENOTDIR);
    }
    let target = DataTarget { handle, directory };
    let flags_of = crate::descriptor_flags(flags);
    let inserted = crate::shared::growing(|files| {
        files
            .insert(Target::Data(target), flags_of)
            .map_err(crate::shared::page_error)
    });
    match inserted {
        Ok(fd) => Ok(fd as c_int),
        Err(errno) => {
            close_description(handle);
            Err(errno)
        }
    }
}

/// CLOSE of the description `handle`: the last descriptor of it went. The answer matters to no one:
/// a service that went has closed what the session held.
pub fn close_description(handle: u32) {
    LISTINGS.forget(handle);
    // A process with no session (the old one died with its instance) holds nothing the service
    // knows: the close succeeds with no call, and no session is taken for it.
    let mut w = Writer::new();
    if p::handle_call(p::Method::Close, handle, &mut w).is_ok()
        && session().is_some()
        && call_with(w.as_bytes(), false).is_err()
    {
        // The description stays in the session: an exec must not hand the session to an image that
        // could read it by guessing the handle (`session_for_exec`).
        CLOSE_FAILED.store(true, Ordering::Release);
    }
}

/// read of the description at its position: the bytes, 0 at the end of the file.
pub fn read(handle: u32, out: &mut [u8]) -> Result<usize, i32> {
    let count = out.len().min(p::MAX_READ) as u32;
    let answer = ask(|w| p::read(handle, count, w))?;
    copy_bytes(&answer, out)
}

/// pread at `offset`, the position of the description untouched.
pub fn pread(handle: u32, offset: u64, out: &mut [u8]) -> Result<usize, i32> {
    let count = out.len().min(p::MAX_READ) as u32;
    let answer = ask(|w| p::pread(handle, count, offset, w))?;
    copy_bytes(&answer, out)
}

/// The bytes after the count of a read reply.
fn copy_bytes(answer: &Answer, out: &mut [u8]) -> Result<usize, i32> {
    let mut r = answer.reader();
    let count = r.u32().map_err(|_| EIO)? as usize;
    let bytes = r.bytes(count).map_err(|_| EIO)?;
    let n = bytes.len().min(out.len());
    out[..n].copy_from_slice(&bytes[..n]);
    Ok(n)
}

/// lseek: the new position. A directory takes a position the listing counts (SEEK_SET with the
/// number of entries given before, 0 for `rewinddir`, or SEEK_CUR 0 to read it).
pub fn seek(target: DataTarget, offset: i64, whence: i32) -> Result<u64, i32> {
    if target.directory {
        let handle = target.handle;
        return match (whence, offset) {
            (0, at) if at >= 0 => {
                position_listing(handle, at.cast_unsigned())?;
                Ok(at.cast_unsigned())
            }
            (1, 0) => Ok(LISTINGS
                .with(|slots| slot_of(slots, handle).map(|l| l.index()))
                .unwrap_or(0)),
            _ => Err(EINVAL),
        };
    }
    let whence = match whence {
        0 => p::SEEK_SET,
        1 => p::SEEK_CUR,
        2 => p::SEEK_END,
        _ => return Err(EINVAL),
    };
    let answer = ask(|w| p::seek(target.handle, offset, whence, w))?;
    answer.reader().u64().map_err(|_| EIO)
}

/// fstat of the description.
pub fn fstat(handle: u32) -> Result<proto_fs::NodeInfo, i32> {
    let answer = ask(|w| p::handle_call(p::Method::Fstat, handle, w))?;
    let stat = p::Stat::from_bytes(&answer.bytes[..answer.len]).map_err(|_| EIO)?;
    Ok(pure::node_info(&stat))
}

// ---------------------------------------------------------------- writes

/// write to the description at its position, in messages of the service's largest size: the bytes
/// written. A message the service took short ends the write; a failure after some messages is
/// their sum (the next call meets it again: ENOSPC, EFBIG), and the error of the first alone when
/// none went (FILE_SIZE_REFUSAL is the layer's mark for SIGXFSZ). Each message is atomic against
/// other writers of the file (and the end of an O_APPEND write is taken per message); a write of
/// more than one message can have another writer's bytes between its messages.
pub fn write(handle: u32, bytes: &[u8]) -> Result<usize, i32> {
    let mut split = pure::Splitter::new(bytes.len(), p::MAX_WRITE);
    while let Some(n) = split.next_len() {
        let at = split.at();
        let sent = ask(|w| p::write(handle, &bytes[at..at + n], w))
            .and_then(|answer| answer.reader().u32().map_err(|_| EIO));
        match sent {
            Ok(wrote) => {
                if !split.took(n, wrote as usize) {
                    break;
                }
            }
            Err(errno) => return split.failed(errno),
        }
    }
    Ok(split.written())
}

/// pwrite at `offset`, the position of the description untouched, in messages as `write`.
pub fn pwrite(handle: u32, offset: u64, bytes: &[u8]) -> Result<usize, i32> {
    let mut split = pure::Splitter::new(bytes.len(), p::MAX_WRITE);
    while let Some(n) = split.next_len() {
        let at = split.at();
        let sent = ask(|w| p::pwrite(handle, offset + at as u64, &bytes[at..at + n], w))
            .and_then(|answer| answer.reader().u32().map_err(|_| EIO));
        match sent {
            Ok(wrote) => {
                if !split.took(n, wrote as usize) {
                    break;
                }
            }
            Err(errno) => return split.failed(errno),
        }
    }
    Ok(split.written())
}

/// ftruncate of the description: the file is `size` bytes, grown with zeros.
pub fn truncate(handle: u32, size: u64) -> Result<(), i32> {
    ask(|w| p::truncate(handle, size, w)).map(drop)
}

/// fsync and fdatasync: the bytes, the size, the name and the times of the file are durable when
/// it returns. A directory has nothing to do (its operations are durable when they answer).
pub fn fsync(target: DataTarget) -> Result<(), i32> {
    if target.directory {
        return Ok(());
    }
    ask(|w| p::handle_call(p::Method::Fsync, target.handle, w)).map(drop)
}

/// The data descriptor `fd` names, if it names one.
pub fn data_target(fd: c_int) -> Option<DataTarget> {
    let fd = u32::try_from(fd).ok()?;
    match crate::shared::with_fd(fd, |files| files.target(fd).map_err(crate::error)) {
        Ok(Target::Data(d)) => Some(d),
        _ => None,
    }
}

/// The status flags of the platform: O_APPEND and the layer's durability bit (O_DSYNC and
/// O_SYNC), as relibc has them.
const NATIVE_APPEND: c_int = 0o2000;
const NATIVE_SYNC: c_int = 0o4010000;

/// F_GETFL (`set` None) and F_SETFL of a descriptor of the volume: None for any other descriptor.
/// F_GETFL says the access mode of the description and O_APPEND and O_SYNC when it has them;
/// F_SETFL changes those two (the service keeps them in the description, which a duplicate and a
/// child share) and takes the rest for what it is, a flag that means nothing for a regular file.
pub fn status_flags(fd: c_int, set: Option<c_int>) -> Result<Option<c_int>, i32> {
    let Some(target) = data_target(fd) else {
        return Ok(None);
    };
    match set {
        None => {
            let answer = ask(|w| p::handle_call(p::Method::GetFlags, target.handle, w))?;
            let flags = answer.reader().u32().map_err(|_| EIO)?;
            let mut out = match (flags & p::READ != 0, flags & p::WRITE != 0) {
                (true, true) => 2,
                (false, true) => 1,
                _ => 0,
            };
            if flags & p::APPEND != 0 {
                out |= NATIVE_APPEND;
            }
            if flags & p::SYNC != 0 {
                out |= NATIVE_SYNC;
            }
            Ok(Some(out))
        }
        Some(argument) => {
            let mut bits = 0;
            if argument & NATIVE_APPEND != 0 {
                bits |= p::APPEND;
            }
            if argument & NATIVE_SYNC != 0 {
                bits |= p::SYNC;
            }
            ask(|w| p::set_flags(target.handle, bits, w))?;
            Ok(Some(0))
        }
    }
}

/// A name that is the root of the volume cannot be made, removed or moved.
fn is_root(vol: &Vol) -> bool {
    vol.bytes() == b"/"
}

/// mkdir: the mode with the creation mask applied.
pub fn mkdir(vol: &Vol, mode: u32, umask: u32) -> Result<(), i32> {
    if is_root(vol) {
        return Err(EEXIST);
    }
    let mode = mode & p::MODE_MASK & !(umask & 0o777);
    ask(|w| p::mkdir(vol.bytes(), mode, w)).map(drop)
}

/// unlink and rmdir (`directory`): a directory under unlink is EISDIR, as the RAM file service
/// and Linux have it (XSH allows EPERM).
pub fn unlink(vol: &Vol, directory: bool) -> Result<(), i32> {
    if is_root(vol) {
        return Err(if directory { EBUSY } else { EISDIR });
    }
    let method = if directory {
        p::Method::Rmdir
    } else {
        p::Method::Unlink
    };
    ask(|w| p::path_call(method, vol.bytes(), w)).map(drop)
}

/// rename inside the volume.
pub fn rename(from: &Vol, to: &Vol) -> Result<(), i32> {
    if is_root(from) || is_root(to) {
        return Err(EBUSY);
    }
    ask(|w| p::rename(from.bytes(), to.bytes(), w)).map(drop)
}

/// What a `rename` or `link` of two paths needs: the routes of both (None for a path elsewhere).
/// EXDEV when only one is the volume's.
pub fn pair(
    old_dirfd: c_int,
    old: &[u8],
    new_dirfd: c_int,
    new: &[u8],
) -> Result<Option<(Vol, Vol)>, i32> {
    let first = route(old_dirfd, old)?;
    let second = route(new_dirfd, new)?;
    match (first, second) {
        (None, None) => Ok(None),
        (Some(a), Some(b)) => Ok(Some((a, b))),
        (a, b) => {
            debug_assert!(pure::route_of(a.is_some(), b.is_some()) == pure::Route::Across);
            Err(EXDEV)
        }
    }
}

/// link of two names of the volume: it has one name for a file (EMLINK, the first name's file must
/// be there) and none for a directory (EPERM).
pub fn link(old: &Vol) -> Result<(), i32> {
    let info = stat(old)?;
    Err(pure::link_errno(info.kind == 1))
}

/// chmod, chown and utimensat of a path of the volume, or with AT_EMPTY_PATH of the description
/// `dirfd` names: `args` are the layer's (`names::metadata`). Ok(false) when the target is not the
/// volume's.
pub fn change(
    op: proto_fs::ChangeOp,
    dirfd: c_int,
    path: &[u8],
    args: [u64; 4],
) -> Result<bool, i32> {
    use proto_fs::ChangeOp as C;
    if path.is_empty() {
        let Some(target) = data_target(dirfd) else {
            return Ok(false);
        };
        let h = target.handle;
        match op {
            C::Chmod => ask(|w| p::fchmod(h, args[0] as u32, w))?,
            C::Chown => ask(|w| p::fchown(h, args[0] as u32, args[1] as u32, w))?,
            C::Times => ask(|w| {
                p::futimens(
                    h,
                    pure::time_spec(args[0], args[1]),
                    pure::time_spec(args[2], args[3]),
                    w,
                )
            })?,
            _ => return Err(EINVAL),
        };
        return Ok(true);
    }
    let Some(vol) = route(dirfd, path)? else {
        return Ok(false);
    };
    let at = vol.bytes();
    match op {
        C::Chmod => ask(|w| p::chmod(at, args[0] as u32, w))?,
        C::Chown => ask(|w| p::chown(at, args[0] as u32, args[1] as u32, w))?,
        C::Times => ask(|w| {
            p::utimens(
                at,
                pure::time_spec(args[0], args[1]),
                pure::time_spec(args[2], args[3]),
                w,
            )
        })?,
        _ => return Err(EINVAL),
    };
    Ok(true)
}

// ---------------------------------------------------------------- passes (SCM_RIGHTS)

/// EXPORT of the description `handle`: a pass for it (a channel that can only be handed on) to
/// send in an SCM_RIGHTS message; the service holds one reference for it until it is adopted.
pub fn export(handle: u32) -> Result<Handle<Channel>, i32> {
    let mut w = Writer::new();
    p::handle_call(p::Method::Export, handle, &mut w).map_err(|_| EIO)?;
    let session = ensure()?;
    let channel = Handle::<Channel>::borrowed(session);
    let mut tries = 0;
    loop {
        let mut reply = match rt::sys::send(&channel, w.as_bytes()) {
            Ok(reply) => reply,
            Err(Error::Interrupted) => continue,
            Err(Error::PeerClosed) => {
                forget(session);
                return Err(EIO);
            }
            Err(_) => return Err(EIO),
        };
        let mut buffer = [0; MESSAGE_MAX];
        let status = Reader::new(reply.bytes(&mut buffer))
            .u32()
            .map_err(|_| EIO)?;
        match status {
            0 => return reply.handles.take::<Channel>(0).map_err(|_| EIO),
            s if s == busy_code() && tries < BUSY_TRIES => {
                tries += 1;
                pause()?;
            }
            p::TABLE_FULL | p::TOO_MANY_OPEN => return Err(EMFILE),
            _ => return Err(errno_of(status)),
        }
    }
}

/// ADOPT of a pass of the data file service received in an SCM_RIGHTS message: the description
/// becomes a descriptor of this process (the lowest free one), with its rights as they were. The
/// pass is spent, or closes with the error.
pub fn adopt(pass: Handle<Channel>, cloexec: bool) -> Result<c_int, i32> {
    let mut w = Writer::new();
    p::adopt(&mut w).map_err(|_| EIO)?;
    let session = ensure()?;
    let channel = Handle::<Channel>::borrowed(session);
    let mut pass = pass;
    let mut tries = 0;
    let answer = loop {
        let mut reply = match rt::sys::send_handles(&channel, w.as_bytes(), [pass.erase()]) {
            Ok(reply) => reply,
            Err(refused) => {
                if refused.error == Error::PeerClosed {
                    forget(session);
                }
                return Err(EIO);
            }
        };
        let mut buffer = [0; MESSAGE_MAX];
        let bytes = reply.bytes(&mut buffer);
        let mut r = Reader::new(bytes);
        let status = r.u32().map_err(|_| EIO)?;
        if status == 0 {
            let handle = r.u32().map_err(|_| EIO)?;
            let kind = r.u32().map_err(|_| EIO)?;
            break (handle, kind);
        }
        // A refusal for a limit the caller can lift gives the pass back in the reply.
        let back = reply.handles.take::<Channel>(0);
        match back {
            Ok(back) if status == busy_code() && tries < BUSY_TRIES => {
                tries += 1;
                pass = back;
                pause()?;
            }
            _ => {
                return Err(match status {
                    p::TABLE_FULL | p::TOO_MANY_OPEN => EMFILE,
                    _ => errno_of(status),
                });
            }
        }
    };
    let target = DataTarget {
        handle: answer.0,
        directory: answer.1 == p::KIND_DIRECTORY,
    };
    let flags = crate::descriptor_flags(if cloexec { O_CLOEXEC } else { 0 });
    let inserted = crate::shared::growing(|files| {
        files
            .insert(Target::Data(target), flags)
            .map_err(crate::shared::page_error)
    });
    match inserted {
        Ok(fd) => Ok(fd as c_int),
        Err(errno) => {
            close_description(answer.0);
            Err(errno)
        }
    }
}

// ---------------------------------------------------------------- listings

/// The listings of the directory descriptions that have been read: one buffer for each (a batch of
/// the service and where the next entry is), by the handle of the description.
struct Listings {
    lock: posix_sync::LayerLock,
    slots: core::cell::UnsafeCell<[Option<(u32, pure::Listing)>; LISTING_SLOTS]>,
}

// SAFETY: every access takes `lock`.
unsafe impl Sync for Listings {}

/// The directories one process reads at once (the service holds 16 listings at most).
const LISTING_SLOTS: usize = 16;

static LISTINGS: Listings = Listings {
    lock: posix_sync::LayerLock::raising(),
    slots: core::cell::UnsafeCell::new([const { None }; LISTING_SLOTS]),
};

impl Listings {
    /// Runs `run` on the slots under the lock, which blocks its waiters and is held for memory work
    /// alone (no call to the service inside), in a critical section: a signal handler never runs
    /// on the holder's thread.
    fn with<R>(
        &self,
        run: impl FnOnce(&mut [Option<(u32, pure::Listing)>; LISTING_SLOTS]) -> R,
    ) -> R {
        let _held = self.lock.lock();
        // SAFETY: the lock is held.
        run(unsafe { &mut *self.slots.get() })
    }

    fn forget(&self, handle: u32) {
        self.with(|slots| {
            for slot in slots.iter_mut() {
                if slot.as_ref().is_some_and(|(h, _)| *h == handle) {
                    *slot = None;
                }
            }
        });
    }

    fn forget_all(&self) {
        self.with(|slots| slots.iter_mut().for_each(|slot| *slot = None));
    }
}

/// The records of the directory `handle` in Linux's dirent64 layout from `position` (the number of
/// entries read before, as `telldir` counts them), as many as `out` holds: the bytes, 0 at the end.
/// The position of the stream is the listing's own: a position other than where it stands starts
/// the listing again (REWIND) and reads on to it. The first entry that does not fit is put back.
pub fn entries(handle: u32, out: &mut [u8], position: Option<u64>) -> Result<usize, i32> {
    let standing = LISTINGS.with(|slots| slot_of(slots, handle).map(|l| l.index()));
    position_listing(handle, position.or(standing).unwrap_or(0))?;
    posix_change::dirent::fill(
        out,
        |name| {
            let before = LISTINGS
                .with(|slots| slot_of(slots, handle).map(|l| l.index()))
                .unwrap_or(0);
            let Some(entry) = next_entry(handle)? else {
                return Ok(None);
            };
            name[..entry.name().len()].copy_from_slice(entry.name());
            Ok(Some(posix_change::dirent::Item {
                inode: entry.ino,
                kind: entry.d_type(),
                name_len: entry.name().len(),
                before: before.cast_signed(),
                after: before.cast_signed() + 1,
            }))
        },
        |_| {
            LISTINGS.with(|slots| {
                if let Some(l) = slot_of(slots, handle) {
                    l.put_back();
                }
            });
            Ok(())
        },
    )
}

/// The listing of `handle` stands at entry `want`: as it is when it stands there already, or
/// started over (REWIND) and read on to the entry.
fn position_listing(handle: u32, want: u64) -> Result<(), i32> {
    let standing = LISTINGS.with(|slots| slot_of(slots, handle).map(|l| l.index()));
    if standing == Some(want) {
        return Ok(());
    }
    if standing.is_some() || want != 0 {
        ask(|w| p::handle_call(p::Method::Rewind, handle, w))?;
    }
    LISTINGS.with(|slots| {
        for slot in slots.iter_mut() {
            if slot.as_ref().is_some_and(|(h, _)| *h == handle) {
                *slot = None;
            }
        }
    });
    ensure_slot(handle);
    for _ in 0..want {
        if next_entry(handle)?.is_none() {
            break;
        }
    }
    Ok(())
}

fn slot_of(
    slots: &mut [Option<(u32, pure::Listing)>; LISTING_SLOTS],
    handle: u32,
) -> Option<&mut pure::Listing> {
    slots
        .iter_mut()
        .flatten()
        .find(|(h, _)| *h == handle)
        .map(|(_, l)| l)
}

fn ensure_slot(handle: u32) {
    LISTINGS.with(|slots| {
        if slot_of(slots, handle).is_none()
            && let Some(free) = slots.iter_mut().find(|s| s.is_none())
        {
            *free = Some((handle, pure::Listing::new()));
        }
    });
}

/// The next entry of the listing of `handle`: from its buffer, or from the next batch.
fn next_entry(handle: u32) -> Result<Option<pure::Entry>, i32> {
    loop {
        let (entry, needs) = LISTINGS.with(|slots| match slot_of(slots, handle) {
            Some(l) => (l.take(), l.needs_batch()),
            None => (None, true),
        });
        if entry.is_some() {
            return Ok(entry);
        }
        if !needs {
            return Ok(None);
        }
        let answer = ask(|w| p::handle_call(p::Method::Readdir, handle, w))?;
        let loaded = LISTINGS.with(|slots| {
            if slot_of(slots, handle).is_none()
                && let Some(free) = slots.iter_mut().find(|s| s.is_none())
            {
                *free = Some((handle, pure::Listing::new()));
            }
            slot_of(slots, handle).map(|l| l.load(&answer.bytes[..answer.len]))
        });
        match loaded {
            Some(Ok(())) => {}
            Some(Err(errno)) => return Err(errno),
            None => return Err(EMFILE),
        }
    }
}

// ---------------------------------------------------------------- fork, spawn, exec

/// A clone of the session for a child (CLONE) holding the descriptions in `handles`, and the
/// current directory's when `with_cwd`: None when the process has no session or there is nothing to
/// carry (the child takes a session when it first uses `/data`). A refusal is EAGAIN or ENFILE as
/// the code says.
pub fn clone_for_child(
    held: impl IntoIterator<Item = pure::Held>,
    with_cwd: bool,
) -> Result<Option<Handle<Channel>>, i32> {
    if session().is_none() {
        return Ok(None);
    }
    let cwd = if with_cwd { cwd_handle() } else { None };
    let plan = pure::clone_plan(held, cwd);
    if !plan.needed() {
        return Ok(None);
    }
    let session = session().ok_or(EIO)?;
    let channel = Handle::<Channel>::borrowed(session);
    let mut messages = plan.messages();
    let first = messages.next().ok_or(EIO)?;
    let mut w = Writer::new();
    p::clone(first, &mut w).map_err(|_| EIO)?;
    let (child, birth) = send_clone(&channel, w.as_bytes())?;
    let child = child.ok_or(EIO)?;
    // The rest of the descriptions join the clone before the child sends anything.
    for more in messages {
        let mut w = Writer::new();
        p::clone_more(birth, more, &mut w).map_err(|_| EIO)?;
        if let Err(errno) = send_clone(&channel, w.as_bytes()) {
            drop(child);
            return Err(errno);
        }
    }
    Ok(Some(child))
}

/// One CLONE or CLONE_MORE: for CLONE the new session and its birth number, for CLONE_MORE the
/// no session.
fn send_clone(
    channel: &Handle<Channel>,
    request: &[u8],
) -> Result<(Option<Handle<Channel>>, u32), i32> {
    let mut tries = 0;
    loop {
        let mut reply = match rt::sys::send(channel, request) {
            Ok(reply) => reply,
            Err(Error::Interrupted) => continue,
            Err(_) => return Err(EIO),
        };
        let mut buffer = [0; MESSAGE_MAX];
        let mut r = Reader::new(reply.bytes(&mut buffer));
        let status = r.u32().map_err(|_| EIO)?;
        match status {
            0 => {
                let birth = r.u32().unwrap_or(0);
                if reply.handles.is_empty() {
                    return Ok((None, birth));
                }
                let session = reply.handles.take::<Channel>(0).map_err(|_| EIO)?;
                return Ok((Some(session), birth));
            }
            s if s == busy_code() && tries < BUSY_TRIES => {
                tries += 1;
                pause()?;
            }
            // The service has no place left for the clone (the tree's clones, descriptions or the
            // table): a limit of the moment.
            p::TABLE_FULL | p::TOO_MANY_OPEN => return Err(EAGAIN),
            _ => return Err(errno_of(status)),
        }
    }
}

/// A clone of the session for a forked child: it holds the descriptions of the descriptors without
/// FD_CLOFORK and the current directory's. None when there is nothing to carry.
pub fn clone_for_fork() -> Result<Option<Handle<Channel>>, i32> {
    if session().is_none() {
        return Ok(None);
    }
    // Another thread may close a description between the collection and the CLONE: the service
    // says BAD_HANDLE (EBADF), and the descriptions are collected again, three times at most.
    let mut tries = 0;
    loop {
        let mut held = [pure::Held {
            handle: 0,
            clofork: true,
        }; pure::PLAN_MAX];
        let mut count = 0;
        crate::shared::with_files(|files| {
            for (_, target, flags) in files.descriptors() {
                if let Target::Data(d) = target
                    && count < held.len()
                    && !flags.close_on_fork
                    && !held[..count].iter().any(|h| h.handle == d.handle)
                {
                    held[count] = pure::Held {
                        handle: d.handle,
                        clofork: false,
                    };
                    count += 1;
                }
            }
            Ok(())
        })?;
        match clone_for_child(held[..count].iter().copied(), true) {
            Err(EBADF) if tries < 3 => tries += 1,
            other => return other,
        }
    }
}

/// The session as the new image of an exec gets it (None when there is none): the description of
/// the current directory closes first, and the new image opens it again at its first path call.
pub fn session_for_exec() -> Option<rt::abi::Handle> {
    let raw = session()?;
    let old = CWD_HANDLE.swap(NONE, Ordering::AcqRel);
    CWD_CHECKED.store(false, Ordering::Release);
    if old != NONE {
        close_description(old);
    }
    // A close that failed left a description in the session with no descriptor: the new image
    // takes a session of its own.
    if CLOSE_FAILED.swap(false, Ordering::AcqRel) {
        return None;
    }
    Some(raw)
}
