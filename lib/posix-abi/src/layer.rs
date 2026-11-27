// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The layer service (`proto_fs::names`, services/layerd): the process's session with it and the
//! paths and descriptions of the layered root it decides. The feature `layer` is on in an image
//! whose init table has the service; a build without it has no code of this module (`layer_off.rs`).
//!
//! * A path belongs to the layered root by its absolute form (the current directory, the dots and
//!   the slashes applied first, as for `/data`): every path but the pass-through names of the root
//!   (`/data`, `/proc`, `/dev`, `/tmp`, `/run` and what lies below them), which their own services
//!   answer (`posix_fs::layer::belongs`). A relative path against a directory descriptor joins the
//!   absolute path of the descriptor: the path of a description of the layer service is kept here
//!   (the service has no WHERE), that of a directory of the file service comes from its PATH query.
//!   A path against a descriptor of any other service is not this layer's.
//! * The session comes when it is first needed: TakeRoot asks the process service for the root of
//!   the service, SESSION with a copy of the process's identity session gives a session that is
//!   bound to the process. While the service has no root (UNREGISTERED), or says STARTING (it builds
//!   its index), the layer asks again every millisecond for a few seconds, then answers EIO. A
//!   session that arrived in the slot Layer (a fork, a spawn or an exec) is unbound or has lapsed:
//!   the first call that needs an identity answers AUTHENTICATING, and the layer sends BIND with a
//!   copy of the identity session and asks once more.
//! * What OPEN answers. REDIRECT to the file service: the path is opened there with the process's
//!   own session (`open_image`), so the rights of the process's identity are checked against the
//!   lower attributes, and the description is marked so that its `fstat` reports the layered
//!   device. REDIRECT to the data file service: the path goes to `posix_abi::data`. A pass of a
//!   description of a file of a layer of the user: ADOPT in the session with the data file service
//!   (`data::adopt`). A directory description of the service (a directory that has a name in a
//!   layer of the user, its listing merged): a `Target::Layer` with the path kept here. A directory
//!   of the lower set alone is a REDIRECT, and the file service lists it.
//! * `stat`, `lstat`, `fstatat`, `access`, `readlink`, `chdir` and `realpath` of a path of the
//!   root ask the service (STAT, ACCESS, READLINK); a REDIRECT sends the path to the file service's
//!   own call, and the `st_dev` of every answer is the root's one number. A program is never run
//!   from a layer of the user (EACCES, as for `/data`): the path of an exec or a spawn is asked
//!   with STAT first, so that a name the layers delete is ENOENT.
//! * Changes. `unlink`, `rmdir`, `mkdir`, `symlink`, `rename`, `link`, `chmod`, `chown` and
//!   `utimensat` of a path of the root are CHANGE requests to the service (`change`); an open that
//!   creates sends its mode (the creation mask applied) in the flags. A file opened for writing is a
//!   pass of a writable description of the data file service, which `ADOPT` takes, so the writes are
//!   the data file service's. A name of the lower set is EROFS until the copy up: the service says it.
//!   The directory part of a path of a change is canonical: a link of a layer of the user in it is a
//!   redirect that routes by the path (followed here), and a link of the lower set is resolved here
//!   first (`canonical_leaf`). A path a link led out of the root goes on at the service that owns it.
//! * Redirects that route by the path. The service answers a link of a layer of the user with one, and
//!   the RAM file service of a layered image answers every link and every `..` of the walk of a
//!   POSIX session with one: the path they carry is routed again, from the start (`run`), and the
//!   redirects and links of one call are at most `LINKS_MAX` (ELOOP past it). The path of an
//!   `exec` is made canonical first (`check_exec`), because the loader does not follow a redirect.
//! * Listings. A directory description of the service lists through batches of READ_DIR kept here
//!   (`posix_fs::layer::Listing`); a reply with `more` and no entry is read over and the call asks
//!   again. The position of the stream (`telldir`) counts the entries given, and a position other
//!   than where the stream stands starts it again (REWIND) and reads on to it.
//! * Fork, spawn and exec. A forked child gets a CLONE of the session that shares the descriptions
//!   of the descriptors without FD_CLOFORK (a description is one, as POSIX says: its position is
//!   shared by the processes), and binds it at its first call. A spawned child gets one for the
//!   descriptions its descriptors name. An exec moves the session to the new image, which binds it
//!   again. The path a description stands for does not cross an exec: a relative path against such
//!   a descriptor, and `fchdir` of it, are EOPNOTSUPP in the new image.
//! * Waits. The retries sleep with a timed wait (`threads::sleep::pause`); the session is taken
//!   under a lock held for one round trip at a time, never across a sleep.

// The loop of a path (`run`) carries the next path in its error: a path is 512 bytes on the stack
// of the one call, and the layer has no heap to box it in.
#![allow(clippy::result_large_err)]

use crate::constants::*;
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use posix_fs::layer as pure;
use posix_fs::layer::errno_of;
use posix_fs::{LayerTarget, Target};
use proto_fs::names::{self as n, NameMethod};
use proto_wire::{Reader, Writer};
use rt::abi::{Error, MESSAGE_MAX};
use rt::handle::{Channel, Handle};

/// A line that says why a call of the layer service failed, in a layer built with the feature
/// `trace`: the step and the status or error behind an errno.
#[cfg(feature = "trace")]
macro_rules! why {
    ($($arg:tt)*) => {
        rt::println!("posix-abi: layer: {}", format_args!($($arg)*))
    };
}
#[cfg(not(feature = "trace"))]
macro_rules! why {
    ($($arg:tt)*) => {
        if false {
            let _ = format_args!($($arg)*);
        }
    };
}

// The flags the rules of the layer service (posix-fs) name are the layer's.
const _: () = {
    use posix_fs::layer::oflag as o;
    assert!(o::ACCMODE == O_ACCMODE && o::CREAT == O_CREAT && o::EXCL == O_EXCL);
    assert!(o::TRUNC == O_TRUNC && o::APPEND == O_APPEND && o::DIRECTORY == O_DIRECTORY);
    assert!(o::NOFOLLOW == O_NOFOLLOW);
};

const WIDE: usize = crate::names::MAX_PATH + 1;

/// An absolute path of the layered root made plain, with the slash of its end noted: what the
/// service gets.
#[derive(Clone)]
pub struct Abs {
    bytes: [u8; WIDE],
    len: usize,
    /// The path named a directory with a slash at its end.
    pub trailing_slash: bool,
}

impl Abs {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn from(path: &[u8], trailing_slash: bool) -> Option<Abs> {
        if path.is_empty() || path.len() > proto_fs::MAX_PATH {
            return None;
        }
        let mut out = Abs {
            bytes: [0; WIDE],
            len: path.len(),
            trailing_slash,
        };
        out.bytes[..path.len()].copy_from_slice(path);
        Some(out)
    }

    /// The path of a redirect for the file service: the slash of the end comes back when the
    /// program's path had one, so that the service refuses a file there (ENOTDIR).
    fn redirected(path: &[u8], trailing_slash: bool) -> Option<Abs> {
        let slash = trailing_slash && path.last() != Some(&b'/') && path.len() < proto_fs::MAX_PATH;
        let mut out = Abs::from(path, trailing_slash)?;
        if slash {
            out.bytes[out.len] = b'/';
            out.len += 1;
        }
        Some(out)
    }
}

// ---------------------------------------------------------------- the session

/// The session with the layer service, 0 for none.
static SESSION: AtomicU64 = AtomicU64::new(0);

/// The process's session with the layer service, which the start gives in the slot Layer.
///
/// # Safety
/// Startup, on the only thread.
pub unsafe fn init(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
    posix_fs::set_layer_release(close_description);
}

/// A forked child: `session`, the clone the parent made (or none), takes the place of the
/// parent's value, which names nothing of the child's.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(session: Option<Handle<Channel>>) {
    SESSION.store(session.map_or(0, |s| s.into_raw().0), Ordering::Release);
    CLOSE_FAILED.store(false, Ordering::Release);
    // The description of a directory is the parent's too, and its position is shared: what the
    // parent had read ahead into its buffer is the parent's.
    DIRS.with(|cells| {
        for dir in cells.iter_mut().flatten() {
            dir.listing.restart();
        }
    });
}

/// The session with the layer service, if the process has one: for the requests that need no
/// session of their own (the clones a child gets, the exec's move).
pub fn session() -> Option<rt::abi::Handle> {
    match SESSION.load(Ordering::Acquire) {
        0 => None,
        raw => Some(rt::abi::Handle(raw)),
    }
}

/// The process service had no root of the layer service for the whole wait: the image has none, and
/// no path of this process goes to the service again (a program built with the layer in an image
/// without `layerd` waits once).
static NEVER: AtomicBool = AtomicBool::new(false);

/// Why a try to take the session did not end it.
enum Attempt {
    /// The process service has no root (UNREGISTERED) yet.
    NoRoot,
    /// Not yet: the service is busy or starting.
    Retry,
    /// The errno of the failure.
    Failed(i32),
}

/// The root of the service from the process service (TakeRoot).
fn take_root() -> Result<Handle<Channel>, Attempt> {
    let mut request = Writer::new();
    proto_process::take_root(proto_process::ROOT_LAYER, &mut request)
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
            Err(Attempt::NoRoot)
        }
        other => {
            why!("TakeRoot refused: {other:?}");
            Err(Attempt::Failed(EIO))
        }
    }
}

/// Whether a status asks the caller to ask again: the service has no job free, or it builds its
/// index.
fn is_busy(status: u32) -> bool {
    status == crate::data::busy_code() || status == pure::STARTING
}

/// A session from the root: SESSION with a copy of the identity session, which the service vouches
/// for before it answers. One try.
fn take_session(root: &Handle<Channel>) -> Result<Handle<Channel>, Attempt> {
    let request = NameMethod::Session.header().bytes();
    let copy = crate::data::identity_copy().map_err(Attempt::Failed)?;
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
        Ok(status) if is_busy(status) => Err(Attempt::Retry),
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

/// The calls repeated for a service that is busy or builds its index, a millisecond apart: a
/// second for a busy service, five for the first requests of a service that starts.
const BUSY_TRIES: u32 = 5000;

/// Waits a millisecond with a timed sleep that is no point of cancellation, as `data` does.
fn pause() -> Result<(), i32> {
    crate::threads::sleep::pause(1_000_000)
}

/// The session of the process: the one it has, or one taken now.
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
            Attempt::Retry | Attempt::NoRoot if tries < BUSY_TRIES => {
                tries += 1;
                pause()?;
            }
            Attempt::NoRoot => {
                why!("no root of the layer service after the tries: none in this image");
                NEVER.store(true, Ordering::Release);
                return Err(EIO);
            }
            Attempt::Retry => {
                why!("no session after the tries");
                return Err(EIO);
            }
            Attempt::Failed(errno) => return Err(errno),
        }
    }
}

/// The session died with its instance: a later call takes a session of the new one. The handle is
/// parked, never closed, so that a thread that read it before never sends to another channel under
/// its number.
fn forget(raw: rt::abi::Handle) {
    if SESSION
        .compare_exchange(raw.0, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        CLOSE_FAILED.store(false, Ordering::Release);
        DIRS.with(|cells| {
            for dir in cells.iter_mut().flatten() {
                dir.listing.restart();
            }
        });
    }
}

// ---------------------------------------------------------------- the calls

/// A reply whole, its status word first.
pub struct Raw {
    bytes: [u8; MESSAGE_MAX],
    len: usize,
}

impl Raw {
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// What a call brought: the reply and the handle it carried (the pass of a file).
struct Got {
    raw: Raw,
    handle: Option<Handle<Channel>>,
}

/// BIND with a copy of the identity session: INVALID_ARGUMENT for a session that is bound already
/// (a thread of the process was first) counts as done.
fn bind(session: rt::abi::Handle) -> Result<(), i32> {
    let request = NameMethod::Bind.header().bytes();
    let channel = Handle::<Channel>::borrowed(session);
    let mut tries = 0;
    loop {
        let copy = crate::data::identity_copy()?;
        let reply = match rt::sys::send_handles(&channel, &request, [copy]) {
            Ok(reply) => reply,
            Err(refused) if refused.error == Error::Interrupted => continue,
            Err(_) => return Err(EIO),
        };
        let mut buffer = [0; MESSAGE_MAX];
        match Reader::new(reply.bytes(&mut buffer)).u32() {
            Ok(0) => return Ok(()),
            Ok(proto_fs::INVALID_ARGUMENT) => return Ok(()),
            Ok(status) if is_busy(status) && tries < BUSY_TRIES => {
                tries += 1;
                pause()?;
            }
            Ok(status) => return Err(errno_of(status)),
            Err(_) => return Err(EIO),
        }
    }
}

/// One request to the session, and its reply: AUTHENTICATING binds and asks once more, a busy or
/// starting service is asked again, a service that went drops the session (EIO). A reply of status
/// 0 or REDIRECT comes back whole; any other status is its errno.
fn call(request: &[u8]) -> Result<Got, i32> {
    call_with(request, true)
}

/// `call`; with `take` false a process with no session fails with EIO at once and takes none (the
/// close of a description needs none).
fn call_with(request: &[u8], take: bool) -> Result<Got, i32> {
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
        let mut reply = match rt::sys::send(&channel, request) {
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
        let mut raw = Raw {
            bytes: [0; MESSAGE_MAX],
            len: 0,
        };
        let bytes = reply.bytes(&mut raw.bytes);
        raw.len = bytes.len();
        let Ok(status) = Reader::new(raw.bytes()).u32() else {
            return Err(EIO);
        };
        if status == 0 || status == proto_fs::REDIRECT {
            let handle = if reply.handles.is_empty() {
                None
            } else {
                reply.handles.take::<Channel>(0).ok()
            };
            return Ok(Got { raw, handle });
        }
        why!("call answered with status {status}");
        if status == proto_fs::AUTHENTICATING && !bound {
            bound = true;
            bind(session)?;
            continue;
        }
        if is_busy(status) && tries < BUSY_TRIES {
            tries += 1;
            pause()?;
            continue;
        }
        return Err(errno_of(status));
    }
}

fn write_failed<T>(_: T) -> i32 {
    ENAMETOOLONG
}

// ---------------------------------------------------------------- paths

/// The absolute path of `dirfd` when a relative path against it belongs to the layered root: a
/// description of the service (its kept path), or a directory of the file service (its PATH
/// query). None for a descriptor of any other service. EOPNOTSUPP for a description of the layer
/// service that crossed an exec (its path is not known).
fn base_path(dirfd: c_int) -> Result<Option<pure::DirPath>, i32> {
    let fd = u32::try_from(dirfd).map_err(|_| EBADF)?;
    let target = crate::shared::with_fd(fd, |files| files.target(fd).map_err(crate::error))?;
    match target {
        Target::Layer(layer) => match DIRS.path_of(layer.handle) {
            Some(path) => Ok(Some(path)),
            None => Err(EOPNOTSUPP),
        },
        Target::Ram(ram) if ram.kind() == Ok(posix_fs::FileKind::Directory) => {
            let mut out = [0u8; WIDE];
            let len = crate::names::descriptor_path(target, &mut out)?;
            // The path is joined first and then tested (`route`): a `..` out of a directory below a
            // pass-through name reaches the layered root.
            Ok(pure::DirPath::new(&out[..len]))
        }
        _ => Ok(None),
    }
}

/// The path of `path` of the layer as a path of the layered root, when it belongs there: `path`
/// against the current directory (`AT_FDCWD` or an absolute path), or against the directory
/// `dirfd` when that is a description of the service or a directory of the file service outside
/// the pass-through names. None for any other path, in a build with no layer service too.
pub fn route(dirfd: c_int, path: &[u8]) -> Result<Option<Abs>, i32> {
    // The break: no path goes to the layer service, and the file service answers them all as it
    // would in an image with no layers (`cargo xtask layer-posix breaks`).
    if cfg!(feature = "break-layer-route") || NEVER.load(Ordering::Acquire) {
        return Ok(None);
    }
    if path.is_empty() || path.len() > crate::names::MAX_PATH {
        return Ok(None);
    }
    let mut absolute = [0u8; WIDE];
    let length = if path[0] == b'/' || dirfd == crate::names::AT_FDCWD {
        let resolved =
            crate::shared::with_files(|files| files.resolve(path).map_err(crate::error))?;
        posix_path::simplify(resolved.as_bytes(), &mut absolute)
    } else {
        let Some(base) = base_path(dirfd)? else {
            return Ok(None);
        };
        let mut joined = [0u8; WIDE];
        let at = pure::join(base.bytes(), path, &mut joined).ok_or(ENAMETOOLONG)?;
        posix_path::simplify(&joined[..at], &mut absolute)
    };
    let absolute = &absolute[..length];
    if !pure::belongs(absolute) {
        return Ok(None);
    }
    let abs = Abs::from(absolute, path.last() == Some(&b'/')).ok_or(ENAMETOOLONG)?;
    Ok(Some(abs))
}

/// The canonical path of the description `target` (a path kept at its open).
pub fn descriptor_path(target: LayerTarget, out: &mut [u8; WIDE]) -> Result<usize, i32> {
    let path = DIRS.path_of(target.handle).ok_or(EOPNOTSUPP)?;
    let bytes = path.bytes();
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}

/// What a request with a path answered. The two forms live on the caller's stack for one call (the
/// layer has no heap to box them in), so the difference in size costs nothing a box would save.
#[allow(clippy::large_enum_variant)]
enum Answered {
    /// The service decided: the reply, with the handle it carried.
    Done(Got),
    /// The name lies in the lower set (or belongs to a pass-through service): the call goes on
    /// there, with this path.
    Redirect { target: u32, path: Abs },
}

/// Why an attempt on a path did not end the call. The layer has no heap to box the path in, and the
/// value lives for one step of a loop.
#[allow(clippy::large_enum_variant)]
enum Next {
    /// The errno of the failure.
    Errno(i32),
    /// The path goes on as this one, after the links the redirect says it had expanded: a link of
    /// a layer of the user.
    Again(Abs, u32),
    /// A call to the RAM file service ended its walk in a redirect that routes by the path (a
    /// link of the lower set, or a `..`): the redirect is asked for.
    Ram,
}

impl From<i32> for Next {
    fn from(errno: i32) -> Next {
        Next::Errno(errno)
    }
}

/// The failure of a call to the RAM file service as the next move of the loop.
fn ram(errno: i32) -> Next {
    if errno == crate::EREDIRECT {
        Next::Ram
    } else {
        Next::Errno(errno)
    }
}

/// The path a redirect that routes by the path names, as the paths of the layer are: simple.
fn rerouted(path: &[u8], trailing_slash: bool) -> Result<Abs, i32> {
    if path.is_empty() || path.len() > proto_fs::MAX_PATH {
        return Err(EIO);
    }
    let mut plain = [0u8; WIDE];
    let len = posix_path::simplify(path, &mut plain);
    Abs::from(&plain[..len], trailing_slash || path.last() == Some(&b'/')).ok_or(ENAMETOOLONG)
}

/// Runs `attempt` on `abs`, and again on the path a redirect that routes by the path gives (from
/// the layer service for a link of a layer of the user, from the RAM file service for a link of the
/// lower set or a `..`), until the call ends. A redirect counts as the links it expanded and one more;
/// the sum is at most `LINKS_MAX` (ELOOP past it). `follow` says whether the call follows a link at
/// the end of its path, as the RAM file service's walk did.
fn run<T>(
    abs: &Abs,
    follow: bool,
    mut attempt: impl FnMut(&Abs) -> Result<T, Next>,
) -> Result<T, i32> {
    let mut at = abs.clone();
    let mut used = 0u32;
    loop {
        let (path, links) = match attempt(&at) {
            Ok(done) => return Ok(done),
            Err(Next::Errno(errno)) => return Err(errno),
            Err(Next::Again(path, links)) => (path, links),
            Err(Next::Ram) => {
                let mut found = [0u8; proto_fs::MAX_PATH];
                let asked = crate::shared::with_files(|files| Ok(files.transport()))?
                    .files()
                    .redirect_of(None, at.bytes(), follow, &mut found)
                    .map_err(|status| match status {
                        proto_wire::Status::Kernel(Error::Interrupted) => EINTR,
                        _ => EIO,
                    })?;
                match asked {
                    Some(redirect)
                        if redirect.index == 0
                            && redirect.target == proto_fs::REDIRECT_BY_PATH
                            && redirect.length > 0 =>
                    {
                        let path = rerouted(&found[..redirect.length], at.trailing_slash)?;
                        (path, redirect.links)
                    }
                    _ => return Err(EIO),
                }
            }
        };
        used = used.saturating_add(1 + links);
        if used > proto_fs::LINKS_MAX {
            return Err(ELOOP);
        }
        at = path;
    }
}

/// Where a path that is not the layered root's goes: the data file service for a name below
/// `/data`, the RAM file service for the others.
fn elsewhere(path: &Abs) -> u32 {
    let first = path.bytes().strip_prefix(b"/").unwrap_or(path.bytes());
    if first.split(|&b| b == b'/').next() == Some(&b"data"[..]) {
        proto_fs::REDIRECT_DATA
    } else {
        proto_fs::REDIRECT_RAM
    }
}

/// Asks the service about `abs` (the request `build` writes): a path that is no longer the root's
/// (a link of the layer led out of it) is a redirect to the service that owns it; a reply that
/// routes by the path is the next move of the loop.
fn ask(
    abs: &Abs,
    build: impl FnOnce(&Abs, &mut Writer) -> Result<(), i32>,
) -> Result<Answered, Next> {
    if !pure::belongs(abs.bytes()) {
        return Ok(Answered::Redirect {
            target: elsewhere(abs),
            path: abs.clone(),
        });
    }
    let mut w = Writer::new();
    build(abs, &mut w)?;
    let got = call(w.as_bytes())?;
    match proto_fs::Redirect::read_reply(got.raw.bytes()) {
        None => Ok(Answered::Done(got)),
        Some(Ok(redirect)) if redirect.index == 0 => {
            if redirect.target == proto_fs::REDIRECT_BY_PATH {
                let path = rerouted(redirect.path, abs.trailing_slash)?;
                return Err(Next::Again(path, redirect.links));
            }
            let path = Abs::redirected(redirect.path, abs.trailing_slash).ok_or(EIO)?;
            Ok(Answered::Redirect {
                target: redirect.target,
                path,
            })
        }
        Some(_) => Err(Next::Errno(EIO)),
    }
}

/// The data file service's volume path of a redirect to it.
fn volume_of(path: &Abs) -> Result<crate::data::Vol, i32> {
    crate::data::route(crate::names::AT_FDCWD, path.bytes())?.ok_or(EIO)
}

/// stat of a path of the root. A name of a layer of the user is answered by the service with the
/// attributes the data file service keeps; a lower name by the file service, the links followed
/// as `follow` says. The device is the root's.
pub fn stat(abs: &Abs, follow: bool) -> Result<proto_fs::NodeInfo, i32> {
    run(abs, follow, |at| {
        let flags = if follow { 0 } else { n::STAT_NO_FOLLOW };
        match ask(at, |a, w| {
            n::write_stat(flags, a.bytes(), w).map_err(write_failed)
        })? {
            Answered::Done(got) => {
                let info = n::read_info(got.raw.bytes()).map_err(|_| EIO)?;
                if at.trailing_slash && info.kind != 1 {
                    return Err(ENOTDIR.into());
                }
                Ok(pure::stamp(info))
            }
            Answered::Redirect { target, path } => {
                let flags = if follow {
                    0
                } else {
                    crate::names::AT_SYMLINK_NOFOLLOW
                };
                let info = match target {
                    proto_fs::REDIRECT_RAM => {
                        crate::names::fstatat_ram(crate::names::AT_FDCWD, path.bytes(), flags)
                            .map_err(ram)?
                    }
                    proto_fs::REDIRECT_DATA => crate::data::stat(&volume_of(&path)?)?,
                    _ => return Err(EIO.into()),
                };
                Ok(pure::stamp(info))
            }
        }
    })
}

/// access of a path of the root: `bits` as `R_OK`, `W_OK` and `X_OK` (0 for `F_OK`), with the real
/// identifiers unless `effective`.
pub fn access(abs: &Abs, bits: c_int, effective: bool) -> Result<(), i32> {
    run(abs, true, |at| {
        let flags = if effective {
            0
        } else {
            proto_data::ACCESS_REAL
        };
        match ask(at, |a, w| {
            n::write_access(bits as u32 & 7, flags, a.bytes(), w).map_err(write_failed)
        })? {
            Answered::Done(_) => {
                // A regular file of a layer of the user is never executable here: no program runs
                // from a layer of the user.
                if bits & 1 != 0 && stat(at, true)?.kind != 1 {
                    return Err(EACCES.into());
                }
                Ok(())
            }
            Answered::Redirect { target, path } => match target {
                proto_fs::REDIRECT_RAM => crate::names::faccessat_ram(
                    crate::names::AT_FDCWD,
                    path.bytes(),
                    bits,
                    if effective {
                        crate::names::AT_EACCESS
                    } else {
                        0
                    },
                )
                .map_err(ram),
                proto_fs::REDIRECT_DATA => {
                    Ok(crate::data::access(&volume_of(&path)?, bits, effective)?)
                }
                _ => Err(EIO.into()),
            },
        }
    })
}

/// readlink of a path of the root: the text of a link of a layer of the user, EINVAL for a name of
/// a layer that is no link, and a lower name is the file service's.
pub fn readlink(abs: &Abs, out: &mut [u8]) -> Result<usize, i32> {
    run(abs, false, |at| {
        match ask(at, |a, w| {
            n::write_readlink(a.bytes(), w).map_err(write_failed)
        })? {
            Answered::Done(got) => {
                let mut reader = Reader::new(got.raw.bytes());
                reader.u32().map_err(|_| EIO)?;
                let text = reader.bytes(reader.left()).map_err(|_| EIO)?;
                let length = text.len().min(out.len());
                out[..length].copy_from_slice(&text[..length]);
                Ok(length)
            }
            Answered::Redirect { target, path } => match target {
                proto_fs::REDIRECT_RAM => {
                    crate::names::readlinkat_ram(crate::names::AT_FDCWD, path.bytes(), out)
                        .map_err(ram)
                }
                proto_fs::REDIRECT_DATA => {
                    Err(crate::data::stat(&volume_of(&path)?).and(Err(EINVAL))?)
                }
                _ => Err(EIO.into()),
            },
        }
    })
}

/// The canonical path of a directory of the root the caller may search, with the links resolved: a
/// link of a layer of the user by the service, a link of the lower set by the file service. ENOTDIR
/// for a file, ENOENT for a name the layers delete.
pub fn directory(abs: &Abs, out: &mut [u8; WIDE]) -> Result<usize, i32> {
    run(abs, true, |at| {
        match ask(at, |a, w| {
            n::write_stat(0, a.bytes(), w).map_err(write_failed)
        })? {
            Answered::Done(got) => {
                let info = n::read_info(got.raw.bytes()).map_err(|_| EIO)?;
                if info.kind != 1 {
                    return Err(ENOTDIR.into());
                }
                access(at, 1, true)?;
                Ok(plain(at, out)?)
            }
            Answered::Redirect { target, path } => match target {
                proto_fs::REDIRECT_RAM => {
                    crate::names::directory_path_ram(path.bytes(), out).map_err(ram)
                }
                proto_fs::REDIRECT_DATA => Ok(crate::data::directory(&volume_of(&path)?, out)?),
                _ => Err(EIO.into()),
            },
        }
    })
}

/// The canonical path of a path of the root (realpath): the path must exist and be searchable. A
/// directory of the layer of the user is the path itself; a path through links of any layer is the
/// path they lead to.
pub fn realpath(abs: &Abs, out: &mut [u8; WIDE]) -> Result<usize, i32> {
    run(abs, true, |at| {
        match ask(at, |a, w| {
            n::write_stat(0, a.bytes(), w).map_err(write_failed)
        })? {
            Answered::Done(got) => {
                let info = n::read_info(got.raw.bytes()).map_err(|_| EIO)?;
                if at.trailing_slash && info.kind != 1 {
                    return Err(ENOTDIR.into());
                }
                Ok(plain(at, out)?)
            }
            Answered::Redirect { target, path } => match target {
                proto_fs::REDIRECT_RAM => {
                    crate::names::realpath_ram(path.bytes(), out).map_err(ram)
                }
                proto_fs::REDIRECT_DATA => Ok(crate::data::realpath(&volume_of(&path)?, out)?),
                _ => Err(EIO.into()),
            },
        }
    })
}

/// The path without its slash at the end, in `out`.
fn plain(abs: &Abs, out: &mut [u8; WIDE]) -> Result<usize, i32> {
    let path = pure::DirPath::new(abs.bytes()).ok_or(ENAMETOOLONG)?;
    let bytes = path.bytes();
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}

/// Whether the program at `abs` may be run: a name of the lower set is the loader's to open (the
/// path it opens has no link: the loader's session does not follow a redirect that routes by the
/// path); a name of a layer of the user is never run (EACCES, as for `/data`); a name the layers
/// delete or never had is ENOENT, and a directory of the path that is closed is EACCES.
pub fn check_exec(abs: &Abs) -> Result<Abs, i32> {
    run(abs, true, |at| {
        match ask(at, |a, w| {
            n::write_stat(0, a.bytes(), w).map_err(write_failed)
        })? {
            Answered::Done(_) => Err(EACCES.into()),
            Answered::Redirect {
                target: proto_fs::REDIRECT_RAM,
                path,
            } => {
                let mut canonical = [0u8; WIDE];
                let len = crate::names::realpath_ram(path.bytes(), &mut canonical).map_err(ram)?;
                Abs::from(&canonical[..len], false).ok_or(Next::Errno(ENAMETOOLONG))
            }
            Answered::Redirect { .. } => Err(EACCES.into()),
        }
    })
}

// ---------------------------------------------------------------- changes

/// What a change of a path of the root came to. The path lives on the stack of the one call.
#[allow(clippy::large_enum_variant)]
pub enum Changed {
    Done,
    /// A link led the path out of the layered root: the call goes on at the service that owns
    /// this path (the caller runs it again with it).
    Elsewhere(Abs),
}

/// The path `abs` made canonical in its directory part: the parent directory resolved by
/// `directory` (every link, of the layers and of the lower set), the name last, not followed. The
/// path of the root itself stays.
fn canonical_leaf(abs: &Abs) -> Result<Abs, i32> {
    let bytes = abs.bytes();
    let trimmed = if bytes.len() > 1 && bytes.ends_with(b"/") {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };
    let at = trimmed.iter().rposition(|&b| b == b'/').unwrap_or(0);
    if at == 0 {
        return Ok(abs.clone());
    }
    let parent = Abs::from(&trimmed[..at], false).ok_or(ENAMETOOLONG)?;
    let mut dir = [0u8; WIDE];
    let len = directory(&parent, &mut dir)?;
    let leaf = &trimmed[at + 1..];
    if len + 1 + leaf.len() > proto_fs::MAX_PATH {
        return Err(ENAMETOOLONG);
    }
    let mut joined = [0u8; WIDE];
    joined[..len].copy_from_slice(&dir[..len]);
    let mut total = len;
    if len > 1 || dir[0] != b'/' {
        joined[total] = b'/';
        total += 1;
    }
    joined[total..total + leaf.len()].copy_from_slice(leaf);
    total += leaf.len();
    if abs.trailing_slash && total < proto_fs::MAX_PATH {
        joined[total] = b'/';
        total += 1;
    }
    Abs::from(&joined[..total], abs.trailing_slash).ok_or(ENAMETOOLONG)
}

/// One CHANGE for the paths `first` and `second` (the text of a symbolic link rides in `text`): the
/// redirects of the service, which says which path (`index`) they are for, are followed here. A
/// path that a link of a layer led out of the root ends the call with `Elsewhere` (for the first
/// path; a rename that leaves the root is EXDEV).
fn change(
    op: n::ChangeOp,
    a: u64,
    b: u64,
    first: &Abs,
    second: Option<&Abs>,
    text: Option<&[u8]>,
) -> Result<Changed, i32> {
    let mut paths = [first.clone(), second.unwrap_or(first).clone()];
    let mut used = 0u32;
    loop {
        if !pure::belongs(paths[0].bytes()) {
            return Ok(Changed::Elsewhere(paths[0].clone()));
        }
        if second.is_some() && !pure::belongs(paths[1].bytes()) {
            return Err(EXDEV);
        }
        let mut w = Writer::new();
        n::Change {
            op,
            a,
            b,
            first: paths[0].bytes(),
            second: match (text, second) {
                (Some(text), _) => text,
                (None, Some(_)) => paths[1].bytes(),
                (None, None) => b"",
            },
        }
        .write(&mut w)
        .map_err(write_failed)?;
        let got = call(w.as_bytes())?;
        let redirect = match proto_fs::Redirect::read_reply(got.raw.bytes()) {
            None => return Ok(Changed::Done),
            Some(Ok(redirect)) => redirect,
            Some(Err(_)) => return Err(EIO),
        };
        let which = redirect.index as usize;
        if which > 1 || (which == 1 && second.is_none()) {
            return Err(EIO);
        }
        paths[which] = match redirect.target {
            // A link of a layer of the user in the directory part.
            proto_fs::REDIRECT_BY_PATH => {
                used = used.saturating_add(1 + redirect.links);
                rerouted(redirect.path, paths[which].trailing_slash)?
            }
            // A link of the lower set in the directory part: the directory is resolved here.
            proto_fs::REDIRECT_RAM => {
                used = used.saturating_add(1);
                let canonical = canonical_leaf(&paths[which])?;
                if canonical.bytes() == paths[which].bytes() {
                    return Err(ELOOP);
                }
                canonical
            }
            _ => return Err(EIO),
        };
        if used > proto_fs::LINKS_MAX {
            return Err(ELOOP);
        }
    }
}

/// `unlink` (`directory` false) and `rmdir` of a path of the root.
pub fn unlink(abs: &Abs, directory: bool) -> Result<Changed, i32> {
    let op = if directory {
        n::ChangeOp::Rmdir
    } else {
        n::ChangeOp::Unlink
    };
    change(op, 0, 0, abs, None, None)
}

/// `mkdir` of a path of the root with the mode the creation mask has been applied to.
pub fn mkdir(abs: &Abs, mode: u32) -> Result<Changed, i32> {
    change(
        n::ChangeOp::Mkdir,
        u64::from(mode & 0o7777),
        0,
        abs,
        None,
        None,
    )
}

/// `symlink`: the link `abs` with the text `target`.
pub fn symlink(target: &[u8], abs: &Abs) -> Result<Changed, i32> {
    change(n::ChangeOp::Symlink, 0, 0, abs, None, Some(target))
}

/// `rename` of a path of the root to another one: a name of the lower set and a name that a link
/// leads out of the root are EXDEV.
pub fn rename(from: &Abs, to: &Abs) -> Result<(), i32> {
    match change(n::ChangeOp::Rename, 0, 0, from, Some(to), None)? {
        Changed::Done => Ok(()),
        Changed::Elsewhere(_) => Err(EXDEV),
    }
}

/// `link` of paths of the root: the volume of the layers has no links (EMLINK).
pub fn link(from: &Abs, to: &Abs) -> Result<(), i32> {
    match change(n::ChangeOp::Link, 0, 0, from, Some(to), None)? {
        Changed::Done => Ok(()),
        Changed::Elsewhere(_) => Err(EXDEV),
    }
}

/// `chmod`, `chown` and `utimensat` of a path of the root (a name of the lower set is EROFS until
/// the copy up): `args` are the layer's (`names::metadata`). The links of the path are resolved
/// here (the last one too, unless `follow` is false: `lchown`, `AT_SYMLINK_NOFOLLOW`).
pub fn attributes(
    op: proto_fs::ChangeOp,
    abs: &Abs,
    follow: bool,
    args: [u64; 4],
) -> Result<Changed, i32> {
    let (op, a, b) = match op {
        proto_fs::ChangeOp::Chmod => (n::ChangeOp::Chmod, args[0], 0),
        proto_fs::ChangeOp::Chown => (n::ChangeOp::Chown, args[0], args[1]),
        proto_fs::ChangeOp::Times => (
            n::ChangeOp::Utimens,
            posix_fs::data::time_spec(args[0], args[1]).word() as u64,
            posix_fs::data::time_spec(args[2], args[3]).word() as u64,
        ),
        _ => return Err(EINVAL),
    };
    // The last name is looked through when the call follows links: the path of its target.
    let target = if follow {
        let mut resolved = [0u8; WIDE];
        let len = realpath(abs, &mut resolved)?;
        Abs::from(&resolved[..len], false).ok_or(ENAMETOOLONG)?
    } else {
        abs.clone()
    };
    change(op, a, b, &target, None, None)
}

// ---------------------------------------------------------------- descriptions

/// What an attempt to open a path came to: a descriptor of another service (the RAM file service,
/// the data file service), or the reply of the layer service and the path it was given.
#[allow(clippy::large_enum_variant)]
enum Opened {
    Fd(c_int),
    Reply(Got, Abs),
}

/// open of a path of the root: `flags` are the layer's, the mode and the creation mask are the
/// caller's. The descriptor is the lowest free one.
pub fn open(abs: &Abs, flags: c_int, mode: u32, umask: u32) -> Result<c_int, i32> {
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
        | O_SYNC
        | O_SEARCH;
    if flags & !known != 0 {
        return Err(EINVAL);
    }
    let mut wire = pure::open_flags(flags & !(O_SYNC | O_SEARCH))?;
    // The mode of a file the service creates goes with the flags, the creation mask applied.
    if flags & O_CREAT != 0 {
        wire = n::with_permissions(wire, mode & !umask & 0o7777);
    }
    let follow = flags & O_NOFOLLOW == 0 && flags & (O_CREAT | O_EXCL) != O_CREAT | O_EXCL;
    let opened = run(abs, follow, |at| {
        match ask(at, |a, w| {
            n::write_open(wire, a.bytes(), w).map_err(write_failed)
        })? {
            Answered::Done(got) => Ok(Opened::Reply(got, at.clone())),
            Answered::Redirect { target, path } => match target {
                proto_fs::REDIRECT_RAM => {
                    let fd =
                        crate::open_image(path.bytes(), flags & !(O_SYNC | O_SEARCH), mode, umask)
                            .map_err(ram)?;
                    mark(fd);
                    Ok(Opened::Fd(fd))
                }
                // A name the layered root passes through to the data file service.
                proto_fs::REDIRECT_DATA => Ok(Opened::Fd(crate::data::open(
                    &volume_of(&path)?,
                    flags,
                    mode,
                    umask,
                )?)),
                _ => Err(EIO.into()),
            },
        }
    })?;
    let (got, abs) = match opened {
        Opened::Fd(fd) => return Ok(fd),
        Opened::Reply(got, abs) => (got, abs),
    };
    match n::OpenAnswer::read(got.raw.bytes()).map_err(|_| EIO)? {
        n::OpenAnswer::Pass => {
            let pass = got.handle.ok_or(EIO)?;
            let fd = crate::data::adopt(pass, flags & O_CLOEXEC != 0, flags & O_CLOFORK != 0)?;
            // The file is of the root's device (`fstat` of it says so, as `stat` of its path).
            if let Some(data) = crate::data::data_target(fd) {
                pure::mark_data(data.handle);
            }
            Ok(fd)
        }
        n::OpenAnswer::Directory { handle } => {
            let target = LayerTarget { handle };
            if !DIRS.insert(handle, pure::DirPath::new(abs.bytes())) {
                close_description(handle);
                return Err(EMFILE);
            }
            insert_description(target, flags)
        }
        n::OpenAnswer::Redirect(_) => Err(EIO),
    }
}

/// The description of the file service that `fd` names is the layered root's: its `fstat` reports
/// the root's device.
fn mark(fd: c_int) {
    let Ok(fd) = u32::try_from(fd) else {
        return;
    };
    if let Ok(Target::Ram(ram) | Target::Random(ram)) =
        crate::shared::with_fd(fd, |files| files.target(fd).map_err(crate::error))
    {
        pure::mark_ram(ram.fd(), ram.generation());
    }
}

/// A new image's descriptors `fds` came with the mark of the layered root (the word of
/// `Names::File`): the descriptions they name are marked, with the generation they have here.
pub fn mark_inherited(fds: &[u32]) {
    for &fd in fds {
        mark(fd as c_int);
    }
}

/// The lowest free descriptor for the description `target`, with the close-on-exec and
/// close-on-fork bits of `flags`; the description closes when no descriptor can be made.
fn insert_description(target: LayerTarget, flags: c_int) -> Result<c_int, i32> {
    let flags_of = crate::descriptor_flags(flags);
    let inserted = crate::shared::growing(|files| {
        files
            .insert(Target::Layer(target), flags_of)
            .map_err(crate::shared::page_error)
    });
    match inserted {
        Ok(fd) => Ok(fd as c_int),
        Err(errno) => {
            close_description(target.handle);
            Err(errno)
        }
    }
}

/// A CLOSE of a description failed while the session was there.
static CLOSE_FAILED: AtomicBool = AtomicBool::new(false);

/// CLOSE of the description `handle`: the last descriptor of it went. The answer matters to no one:
/// a service that went has closed what the session held.
pub fn close_description(handle: u32) {
    DIRS.remove(handle);
    let mut w = Writer::new();
    if n::write_handle(NameMethod::Close, handle, &mut w).is_ok()
        && session().is_some()
        && call_with(w.as_bytes(), false).is_err()
    {
        // The description stays in the session: an exec must not hand the session to an image that
        // could read it by guessing the handle (`session_for_exec`).
        CLOSE_FAILED.store(true, Ordering::Release);
    }
}

/// fstat of the description: the attributes of its directory, the device the root's.
pub fn fstat(handle: u32) -> Result<proto_fs::NodeInfo, i32> {
    let mut w = Writer::new();
    n::write_handle(NameMethod::Fstat, handle, &mut w).map_err(write_failed)?;
    let got = call(w.as_bytes())?;
    Ok(pure::stamp(n::read_info(got.raw.bytes()).map_err(|_| EIO)?))
}

/// lseek of a description (every one is a directory): a position the listing counts (SEEK_SET with
/// the number of entries given before, 0 for `rewinddir`, or SEEK_CUR 0 to read it).
pub fn seek(target: LayerTarget, offset: i64, whence: i32) -> Result<u64, i32> {
    match (whence, offset) {
        // An explicit seek (`rewinddir`, `seekdir`) asks the service even when the layer's count
        // stands where it is told to go: the position is the description's, which another holder
        // of it may have moved.
        (0, at) if at >= 0 => {
            position_listing(target.handle, at.cast_unsigned(), true)?;
            Ok(at.cast_unsigned())
        }
        (1, 0) => Ok(DIRS.index_of(target.handle).unwrap_or(0)),
        _ => Err(EINVAL),
    }
}

/// The layer's table of the descriptions of the service: the path each stands for and the listing
/// of each that has been read.
struct Dir {
    handle: u32,
    path: Option<pure::DirPath>,
    listing: pure::Listing,
}

struct Dirs {
    lock: posix_sync::LayerLock,
    cells: UnsafeCell<[Option<Dir>; DIR_SLOTS]>,
}

// SAFETY: every access takes `lock`.
unsafe impl Sync for Dirs {}

/// The descriptions one process keeps at once (the service holds 16 for a session).
const DIR_SLOTS: usize = 24;

static DIRS: Dirs = Dirs {
    lock: posix_sync::LayerLock::raising(),
    cells: UnsafeCell::new([const { None }; DIR_SLOTS]),
};

impl Dirs {
    /// Runs `run` on the cells under the lock, which blocks its waiters and is held for memory
    /// work alone (no call to the service inside), in a critical section: a signal handler never
    /// runs on the holder's thread.
    fn with<R>(&self, run: impl FnOnce(&mut [Option<Dir>; DIR_SLOTS]) -> R) -> R {
        let _held = self.lock.lock();
        // SAFETY: the lock is held.
        run(unsafe { &mut *self.cells.get() })
    }

    /// Notes the description `handle` with its path; false when no cell is free.
    fn insert(&self, handle: u32, path: Option<pure::DirPath>) -> bool {
        self.with(|cells| {
            if let Some(old) = cells.iter_mut().flatten().find(|d| d.handle == handle) {
                old.path = path;
                old.listing.restart();
                return true;
            }
            match cells.iter_mut().find(|c| c.is_none()) {
                Some(free) => {
                    *free = Some(Dir {
                        handle,
                        path,
                        listing: pure::Listing::new(),
                    });
                    true
                }
                None => false,
            }
        })
    }

    fn remove(&self, handle: u32) {
        self.with(|cells| {
            for cell in cells.iter_mut() {
                if cell.as_ref().is_some_and(|d| d.handle == handle) {
                    *cell = None;
                }
            }
        });
    }

    fn path_of(&self, handle: u32) -> Option<pure::DirPath> {
        self.with(|cells| {
            cells
                .iter()
                .flatten()
                .find(|d| d.handle == handle)
                .and_then(|d| d.path)
        })
    }

    fn index_of(&self, handle: u32) -> Option<u64> {
        self.with(|cells| {
            cells
                .iter()
                .flatten()
                .find(|d| d.handle == handle)
                .map(|d| d.listing.index())
        })
    }

    /// The listing of `handle`, made when a description came from an exec (it has no path).
    fn listing<R>(&self, handle: u32, run: impl FnOnce(&mut pure::Listing) -> R) -> Option<R> {
        self.with(|cells| {
            if !cells.iter().flatten().any(|d| d.handle == handle)
                && let Some(free) = cells.iter_mut().find(|c| c.is_none())
            {
                *free = Some(Dir {
                    handle,
                    path: None,
                    listing: pure::Listing::new(),
                });
            }
            cells
                .iter_mut()
                .flatten()
                .find(|d| d.handle == handle)
                .map(|d| run(&mut d.listing))
        })
    }
}

/// The records of the directory `handle` in Linux's dirent64 layout from `position` (the number of
/// entries read before, as `telldir` counts them), as many as `out` holds: the bytes, 0 at the end.
/// The position of the stream is the listing's own: a position other than where it stands starts
/// the listing again (REWIND) and reads on to it. The first entry that does not fit is put back.
pub fn entries(handle: u32, out: &mut [u8], position: Option<u64>) -> Result<usize, i32> {
    let standing = DIRS.index_of(handle);
    position_listing(handle, position.or(standing).unwrap_or(0), false)?;
    posix_change::dirent::fill(
        out,
        |name| {
            let before = DIRS.index_of(handle).unwrap_or(0);
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
            DIRS.listing(handle, pure::Listing::put_back);
            Ok(())
        },
    )
}

/// The listing of `handle` stands at entry `want`: as it is when it stands there already (unless
/// `force`), or started over (REWIND) and read on to the entry.
fn position_listing(handle: u32, want: u64, force: bool) -> Result<(), i32> {
    let standing = DIRS.index_of(handle);
    if !force && (standing == Some(want) || (standing.is_none() && want == 0)) {
        return Ok(());
    }
    let mut w = Writer::new();
    n::write_handle(NameMethod::Rewind, handle, &mut w).map_err(write_failed)?;
    call(w.as_bytes())?;
    DIRS.listing(handle, pure::Listing::restart);
    for _ in 0..want {
        if next_entry(handle)?.is_none() {
            break;
        }
    }
    Ok(())
}

/// The next entry of the listing of `handle`: from its buffer, or from the next reply. A reply with
/// `more` and no entry is read over by asking again.
fn next_entry(handle: u32) -> Result<Option<pure::Entry>, i32> {
    loop {
        let (entry, needs) = DIRS
            .listing(handle, |l| (l.take(), l.needs_batch()))
            .ok_or(ENFILE)?;
        if entry.is_some() {
            return Ok(entry);
        }
        if !needs {
            return Ok(None);
        }
        let mut w = Writer::new();
        n::write_handle(NameMethod::ReadDir, handle, &mut w).map_err(write_failed)?;
        let got = call(w.as_bytes())?;
        DIRS.listing(handle, |l| l.load(got.raw.bytes()))
            .ok_or(ENFILE)??;
    }
}

// ---------------------------------------------------------------- fork, spawn, exec

/// A clone of the session for a child (CLONE) that shares the descriptions in `held`: None when the
/// process has no session or there is nothing to carry (the child takes a session when it first
/// uses the layered root). A refusal is EAGAIN or ENFILE as the code says.
pub fn clone_for_child(
    held: impl IntoIterator<Item = pure::Held>,
) -> Result<Option<Handle<Channel>>, i32> {
    // The break: a child gets no session, so the descriptions it inherits answer nothing.
    if session().is_none() || cfg!(feature = "break-layer-clone") {
        return Ok(None);
    }
    let plan = pure::clone_plan(held);
    if !plan.needed() {
        return Ok(None);
    }
    let mut w = Writer::new();
    n::write_clone(plan.handles(), &mut w).map_err(write_failed)?;
    let channel = Handle::<Channel>::borrowed(session().ok_or(EIO)?);
    let mut tries = 0;
    loop {
        let mut reply = match rt::sys::send(&channel, w.as_bytes()) {
            Ok(reply) => reply,
            Err(Error::Interrupted) => continue,
            Err(_) => return Err(EIO),
        };
        let mut buffer = [0; MESSAGE_MAX];
        let bytes = reply.bytes(&mut buffer);
        let status = Reader::new(bytes).u32().map_err(|_| EIO)?;
        match status {
            0 => {
                n::read_clone_reply(bytes).map_err(|_| EIO)?;
                let session = reply.handles.take::<Channel>(0).map_err(|_| EIO)?;
                return Ok(Some(session));
            }
            s if is_busy(s) && tries < BUSY_TRIES => {
                tries += 1;
                pause()?;
            }
            // The service has no place left for the clone (the sessions of the process or of the
            // service): a limit of the moment.
            proto_fs::TOO_MANY_FILES_IN_SYSTEM | proto_fs::TOO_MANY_OPEN_FILES => {
                return Err(EAGAIN);
            }
            other => return Err(errno_of(other)),
        }
    }
}

/// A clone of the session for a forked child: it shares the descriptions of the descriptors
/// without FD_CLOFORK. None when there is nothing to carry.
pub fn clone_for_fork() -> Result<Option<Handle<Channel>>, i32> {
    if session().is_none() {
        return Ok(None);
    }
    // Another thread may close a description between the collection and the CLONE: the service
    // says BAD_FD (EBADF), and the descriptions are collected again, three times at most.
    let mut tries = 0;
    loop {
        let mut held = [pure::Held {
            handle: 0,
            clofork: true,
        }; pure::PLAN_MAX + 1];
        let mut count = 0;
        crate::shared::with_files(|files| {
            for (_, target, flags) in files.descriptors() {
                if let Target::Layer(l) = target
                    && count < held.len()
                    && !flags.close_on_fork
                    && !held[..count].iter().any(|h| h.handle == l.handle)
                {
                    held[count] = pure::Held {
                        handle: l.handle,
                        clofork: false,
                    };
                    count += 1;
                }
            }
            Ok(())
        })?;
        match clone_for_child(held[..count].iter().copied()) {
            Err(EBADF) if tries < 3 => tries += 1,
            other => return other,
        }
    }
}

/// The session as the new image of an exec gets it (None when there is none): a close that failed
/// left a description in the session with no descriptor, so the new image takes a session of its
/// own.
pub fn session_for_exec() -> Option<rt::abi::Handle> {
    let raw = session()?;
    if CLOSE_FAILED.swap(false, Ordering::AcqRel) {
        return None;
    }
    Some(raw)
}
