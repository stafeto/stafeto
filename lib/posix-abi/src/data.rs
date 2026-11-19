// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The data file service at `/data` (`proto_data`, services/datafs): the process's session with it
//! and the paths and descriptions of the volume it serves.
//!
//! * A path belongs to `/data` by its absolute form (the current directory, the dots and the
//!   slashes applied first, as for `/proc`): `/data` and everything below it, never `/datax`
//!   (`posix_fs::data::volume_path`). The service gets the path below `/data`, absolute from the
//!   root of the volume, with no dots. `..` is resolved by the dots rule of the layer, not by
//!   asking the service, so `a/ghost/..` names `a` and does not fail for the missing `ghost`;
//!   `/data/..` is `/`, a path of the RAM file service.
//! * The session comes when it is first needed: TakeRoot asks the process service for the root of
//!   the service, SESSION with a copy of the process's identity session gives a session that is
//!   bound to the process. A process the process service has no root for (an image without the
//!   service) finds `/data` in the RAM file service as before. A session that arrived in the slot
//!   Data (a fork, a spawn or an exec) is unbound or has lapsed: the first call that needs an
//!   identity answers NOT_BOUND, and the layer sends BIND with a copy of the identity session and
//!   asks once more. What a description holds is read without a binding.
//! * A call the service answers WouldBlock (every job in use) is repeated every millisecond for a
//!   second, then EIO. A service that went (PEER_CLOSED) drops the session: the descriptions of the
//!   old instance answer EIO (the service says STALE to the handles of an earlier instance), and the
//!   next path call takes a session of the new one.
//! * The current directory under `/data` holds a description of the directory opened for search
//!   only, so that the service refuses to rename or remove it (EBUSY) and the string of the layer
//!   stays true. A forked child shares it; an exec or a spawn opens it again at the first path call.
//! * Everything that changes the volume is EROFS in this part of the layer. The limits the service
//!   keeps show as these errnos: at most 32 descriptions a session holds (EMFILE), a clone refused
//!   for its tree's clones or the table (EAGAIN), and at most 2,048 metadata pairs on a volume (a
//!   later part's MKDIR over it answers ENOSPC).

use crate::constants::*;
use core::ffi::c_int;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use posix_fs::data::{self as pure, errno_of};
use posix_fs::{DataTarget, Target};
use proto_data as p;
use proto_wire::{Reader, Status, Writer};
use rt::abi::{Error, MESSAGE_MAX, Rights};
use rt::handle::{Channel, Handle};

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
/// A thread is taking a session.
static TAKING: AtomicBool = AtomicBool::new(false);

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
    TAKING.store(false, Ordering::Release);
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

/// Why a session could not be had.
enum Missing {
    /// No service in the image: the path is the RAM file service's.
    Absent,
    /// The service is there and the session failed: the errno.
    Failed(i32),
}

/// The root of the service from the process service (TakeRoot).
fn take_root() -> Result<Handle<Channel>, Missing> {
    let mut request = Writer::new();
    proto_process::Method::TakeRoot
        .header()
        .write(&mut request)
        .and_then(|()| {
            proto_process::LoaderRoot {
                root: proto_process::ROOT_DATA,
            }
            .write(&mut request)
        })
        .map_err(|_| Missing::Failed(EIO))?;
    let mut reply = crate::process::send_again(&request).map_err(|_| Missing::Failed(EIO))?;
    let mut buffer = [0; MESSAGE_MAX];
    match Reader::new(reply.bytes(&mut buffer)).u32() {
        Ok(0) => reply
            .handles
            .take::<Channel>(0)
            .map_err(|_| Missing::Failed(EIO)),
        Ok(proto_process::UNREGISTERED) => Err(Missing::Absent),
        _ => Err(Missing::Failed(EIO)),
    }
}

/// A copy of the identity session for a request of the service to carry (it moves with the call).
fn identity_copy() -> Result<rt::handle::Handle<rt::handle::Any>, i32> {
    let identity = crate::process::identity().ok_or(EIO)?;
    rt::sys::handle_duplicate(identity, Rights::NOTIFY | Rights::TRANSFER)
        .map(Handle::erase)
        .map_err(|_| EIO)
}

/// A session from the root: SESSION with a copy of the identity session, which the service vouches
/// for before it answers.
fn take_session(root: &Handle<Channel>) -> Result<Handle<Channel>, Missing> {
    let request = p::Method::Session.header().bytes();
    let mut tries = 0;
    loop {
        let copy = identity_copy().map_err(Missing::Failed)?;
        let mut reply = match rt::sys::send_handles(root, &request, [copy]) {
            Ok(reply) => reply,
            Err(refused) if refused.error == Error::Interrupted => continue,
            Err(_) => return Err(Missing::Failed(EIO)),
        };
        let mut buffer = [0; MESSAGE_MAX];
        match Reader::new(reply.bytes(&mut buffer)).u32() {
            Ok(0) => {
                return reply
                    .handles
                    .take::<Channel>(0)
                    .map_err(|_| Missing::Failed(EIO));
            }
            Ok(status) if status == busy_code() && tries < BUSY_TRIES => {
                tries += 1;
                pause();
            }
            Ok(status) => return Err(Missing::Failed(errno_of(status))),
            Err(_) => return Err(Missing::Failed(EIO)),
        }
    }
}

/// The session of the process: the one it has, or one taken now (one thread takes it, the others
/// wait). The raw handle stays valid while the process runs: a session that died is parked, not
/// closed, so that a thread that read it before never sends to another channel under its number.
fn ensure() -> Result<rt::abi::Handle, Missing> {
    loop {
        if let Some(session) = session() {
            return Ok(session);
        }
        if TAKING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let made = take_root().and_then(|root| take_session(&root));
            let result = match made {
                Ok(session) => {
                    let raw = session.into_raw();
                    SESSION.store(raw.0, Ordering::Release);
                    Ok(raw)
                }
                Err(missing) => Err(missing),
            };
            TAKING.store(false, Ordering::Release);
            return result;
        }
        let _ = rt::sys::yield_now();
    }
}

/// The session died with its instance: a later call takes a session of the new one.
fn forget(raw: rt::abi::Handle) {
    // The handle is parked, never closed (see `ensure`).
    let _ = SESSION.compare_exchange(raw.0, 0, Ordering::AcqRel, Ordering::Acquire);
}

// ---------------------------------------------------------------- the calls

/// The status of a reply for a request the service has no job for (WouldBlock).
fn busy_code() -> u32 {
    Status::Kernel(Error::WouldBlock).code()
}

/// The calls repeated for a busy service, a millisecond apart: one second.
const BUSY_TRIES: u32 = 1000;

/// Waits about a millisecond.
fn pause() {
    let until = rt::time::now().saturating_add(rt::time::ns_to_ticks(1_000_000));
    while rt::time::now() < until {
        let _ = rt::sys::yield_now();
    }
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
                pause();
            }
            Ok(status) => return Err(errno_of(status)),
            Err(_) => return Err(EIO),
        }
    }
}

/// One request to the session, and its reply: NOT_BOUND binds and asks once more, a busy service is
/// asked again for a second, a service that went drops the session (EIO).
fn call(request: &[u8]) -> Result<Answer, i32> {
    let mut bound = false;
    let mut tries = 0;
    loop {
        let session = ensure().map_err(|missing| match missing {
            Missing::Absent => EIO,
            Missing::Failed(errno) => errno,
        })?;
        let channel = Handle::<Channel>::borrowed(session);
        let reply = match rt::sys::send(&channel, request) {
            Ok(reply) => reply,
            Err(Error::Interrupted) => continue,
            Err(Error::PeerClosed) => {
                forget(session);
                return Err(EIO);
            }
            Err(_) => return Err(EIO),
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
        if status == p::NOT_BOUND && !bound {
            bound = true;
            bind(session)?;
            continue;
        }
        if status == busy_code() && tries < BUSY_TRIES {
            tries += 1;
            pause();
            continue;
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

/// Whether `/data` is served: a session exists or can be had. False in an image with no data
/// service; an error when it is there and no session could be made.
fn served() -> Result<bool, i32> {
    match ensure() {
        Ok(_) => Ok(true),
        Err(Missing::Absent) => Ok(false),
        Err(Missing::Failed(errno)) => Err(errno),
    }
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
    if !served()? {
        return Ok(None);
    }
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

/// Refuses a change of a path of the service: EROFS. The paths elsewhere pass.
pub fn refuse_change(dirfd: c_int, path: &[u8]) -> Result<(), i32> {
    match route(dirfd, path)? {
        Some(_) => Err(EROFS),
        None => Ok(()),
    }
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
/// real identifiers unless `effective`. Write permission on a volume the layer cannot write to is
/// EROFS for a path that exists (XSH access()).
pub fn access(vol: &Vol, bits: c_int, effective: bool) -> Result<(), i32> {
    let flags = if effective { 0 } else { p::ACCESS_REAL };
    ask(|w| p::access(vol.bytes(), bits as u32 & 7, flags, w))?;
    if bits & 2 != 0 {
        return Err(EROFS);
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
    if !served()? {
        left();
        return Ok(());
    }
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
    if let Ok(handle) = open_search(volume) {
        CWD_HANDLE.store(handle, Ordering::Release);
    }
    Ok(())
}

// ---------------------------------------------------------------- descriptions

/// OPEN of a directory with no access bits: the service holds its path and no place of the volume.
fn open_search(path: &[u8]) -> Result<u32, i32> {
    let answer = ask(|w| p::open(path, p::DIRECTORY, 0, w))?;
    answer.reader().u32().map_err(|_| EIO)
}

/// open of a path of the volume for reading: `flags` are the C flags. A write, a create or a
/// truncate is EROFS. The descriptor is the lowest free one.
pub fn open(vol: &Vol, flags: c_int) -> Result<c_int, i32> {
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
        | O_NOFOLLOW;
    if flags & !known != 0 || flags & O_ACCMODE == O_ACCMODE {
        return Err(EINVAL);
    }
    // Reading is all the volume gives in this part of the layer.
    if flags & O_ACCMODE != 0 || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0 {
        return Err(EROFS);
    }
    let mut asked = p::READ;
    if flags & O_DIRECTORY != 0 {
        asked |= p::DIRECTORY;
    }
    // A directory opened with O_RDONLY and no O_DIRECTORY: the service says IS_DIRECTORY for a file
    // open, and the layer asks for a listing.
    let (answer, directory) = match ask(|w| p::open(vol.bytes(), asked, 0, w)) {
        Ok(answer) => (answer, flags & O_DIRECTORY != 0),
        Err(EISDIR) if flags & O_DIRECTORY == 0 => (
            ask(|w| p::open(vol.bytes(), asked | p::DIRECTORY, 0, w))?,
            true,
        ),
        Err(errno) => return Err(errno),
    };
    let mut r = answer.reader();
    let handle = r.u32().map_err(|_| EIO)?;
    let kind = r.u32().map_err(|_| EIO)?;
    let directory = directory || kind == p::KIND_DIRECTORY;
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
    let _ = ask(|w| p::handle_call(p::Method::Close, handle, w));
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

// ---------------------------------------------------------------- listings

/// The listings of the directory descriptions that have been read: one buffer for each (a batch of
/// the service and where the next entry is), by the handle of the description.
struct Listings {
    lock: AtomicBool,
    slots: core::cell::UnsafeCell<[Option<(u32, pure::Listing)>; LISTING_SLOTS]>,
}

// SAFETY: every access takes `lock`.
unsafe impl Sync for Listings {}

/// The directories one process reads at once (the service holds 16 listings at most).
const LISTING_SLOTS: usize = 16;

static LISTINGS: Listings = Listings {
    lock: AtomicBool::new(false),
    slots: core::cell::UnsafeCell::new([const { None }; LISTING_SLOTS]),
};

impl Listings {
    fn with<R>(
        &self,
        run: impl FnOnce(&mut [Option<(u32, pure::Listing)>; LISTING_SLOTS]) -> R,
    ) -> R {
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            let _ = rt::sys::yield_now();
        }
        // SAFETY: the lock is held.
        let result = run(unsafe { &mut *self.slots.get() });
        self.lock.store(false, Ordering::Release);
        result
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
        // The child's own thread, before anything else runs: the lock was copied as it stood.
        self.lock.store(false, Ordering::Release);
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
    let request = {
        let mut w = Writer::new();
        p::clone(plan.handles(), &mut w).map_err(|_| EIO)?;
        w
    };
    let session = session().ok_or(EIO)?;
    let channel = Handle::<Channel>::borrowed(session);
    let mut tries = 0;
    loop {
        let mut reply = rt::sys::send(&channel, request.as_bytes()).map_err(|_| EIO)?;
        let mut buffer = [0; MESSAGE_MAX];
        let status = Reader::new(reply.bytes(&mut buffer))
            .u32()
            .map_err(|_| EIO)?;
        match status {
            0 => return reply.handles.take::<Channel>(0).map(Some).map_err(|_| EIO),
            s if s == busy_code() && tries < BUSY_TRIES => {
                tries += 1;
                pause();
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
    let mut held = [pure::Held {
        handle: 0,
        clofork: true,
    }; p::HELD_MAX];
    let mut count = 0;
    crate::shared::with_files(|files| {
        for (_, target, flags) in files.descriptors() {
            if let Target::Data(d) = target
                && count < held.len()
            {
                held[count] = pure::Held {
                    handle: d.handle,
                    clofork: flags.close_on_fork,
                };
                count += 1;
            }
        }
        Ok(())
    })?;
    clone_for_child(held[..count].iter().copied(), true)
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
    Some(raw)
}
