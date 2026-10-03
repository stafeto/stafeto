// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's file state under a lock of the layer (spec 2, 3.4): the
//! calling thread performs its request itself, its holder at the ceiling
//! of the process (LayerLock::raising). No helper thread. The lock covers
//! the table of descriptors and the current directory alone: a request
//! snapshots what a descriptor names and holds it, or resolves its path,
//! lets go of the lock, and only then sends to the service (5c, the end
//! of the exception of 5a); a close meanwhile releases the service's
//! description after the last request that holds it.

use crate::constants::*;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use posix_fs::{PosixFs, Resolved, Target, Transport};
use posix_request::{MESSAGE_MAX, Reply, Request};
use posix_sync::LayerLock;
use proto_wire::Writer;

struct State {
    files: Option<PosixFs>,
}
struct Cell(UnsafeCell<State>);
// SAFETY: startup installs the files once; afterwards only `process_state`
// borrows the state, under FILES_LOCK.
unsafe impl Sync for Cell {}
static STATE: Cell = Cell(UnsafeCell::new(State { files: None }));
static READY: AtomicBool = AtomicBool::new(false);
static FILES_LOCK: LayerLock = LayerLock::raising();
/// Runs `run` holding the lock of the process's files, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_hold(run: impl FnOnce()) {
    let _guard = FILES_LOCK.lock();
    run();
}

/// # Safety
/// Startup has exclusive access, before any client thread uses the files.
pub unsafe fn init(files: PosixFs) -> Result<(), rt::abi::Error> {
    if READY.load(Ordering::Acquire) {
        return Err(rt::abi::Error::BadState);
    }
    // SAFETY: startup has exclusive access; no client exists yet.
    unsafe { (*STATE.0.get()).files = Some(files) };
    READY.store(true, Ordering::Release);
    Ok(())
}

/// Runs `f` on the process's files under their lock.
fn process_state<R>(f: impl FnOnce(&mut PosixFs) -> Result<R, i32>) -> Result<R, i32> {
    if !READY.load(Ordering::Acquire) {
        return Err(ENOSYS);
    }
    let _guard = FILES_LOCK.lock();
    // SAFETY: the lock gives this borrow alone; READY published the state.
    let state = unsafe { &mut *STATE.0.get() };
    let files = state.files.as_mut().ok_or(ENOSYS)?;
    f(files)
}

/// The hook a thread probe runs in each request outside the lock, between
/// its snapshot and its request to the service: a request under the lock
/// would hold the lock through the hook.
#[cfg(feature = "thread-probe")]
static WINDOW: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Sets the hook of the requests outside the lock (None for none).
#[cfg(feature = "thread-probe")]
pub fn probe_window(hook: Option<fn()>) {
    WINDOW.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

fn window() {
    #[cfg(feature = "thread-probe")]
    {
        let hook = WINDOW.load(Ordering::Acquire);
        if hook != 0 {
            // SAFETY: only probe_window stores a value, a `fn()`.
            let hook: fn() = unsafe { core::mem::transmute::<usize, fn()>(hook) };
            hook();
        }
    }
}

/// Runs `run` with the transports and what `fd` names, held: outside the
/// lock, and a close meanwhile releases the service's description once
/// `run` is over.
pub fn held<R>(fd: u32, run: impl FnOnce(Transport, Target) -> Result<R, i32>) -> Result<R, i32> {
    let (transport, target) =
        process_state(|files| Ok((files.transport(), files.hold(fd).map_err(crate::error)?)))?;
    window();
    let result = run(transport, target);
    let release = process_state(|files| Ok(files.unhold(target)))?;
    let _ = transport.release(release);
    result
}

/// Runs `run` with the transports and `path` resolved against the
/// current directory, outside the lock.
pub fn resolved<R>(
    path: &[u8],
    run: impl FnOnce(Transport, &Resolved) -> Result<R, i32>,
) -> Result<R, i32> {
    let (transport, resolved) = process_state(|files| {
        Ok((
            files.transport(),
            files.resolve(path).map_err(crate::error)?,
        ))
    })?;
    window();
    run(transport, &resolved)
}

/// Runs `change` on the table under the lock, then releases what it
/// handed back outside it.
fn releasing<R>(
    change: impl FnOnce(&mut PosixFs) -> Result<(R, Option<Target>), i32>,
) -> Result<R, i32> {
    let (value, transport, release) = process_state(|files| {
        let (value, release) = change(files)?;
        Ok((value, files.transport(), release))
    })?;
    transport.release(release).map_err(crate::error)?;
    Ok(value)
}

/// The holds of the threads an exec stopped go, and the descriptions
/// whose last descriptor went while one was held close in the service.
pub fn abandon_holds() {
    while let Ok(Some((transport, target))) =
        process_state(|files| Ok(files.abandon_hold().map(|t| (files.transport(), t))))
    {
        let _ = transport.release(Some(target));
    }
}

/// Close of the service's open description `fd`, which the table handed
/// back to release, outside the lock.
pub fn release(fd: u32) -> Result<(), i32> {
    let transport = process_state(|files| Ok(files.transport()))?;
    transport
        .release(Some(Target::Ram(fd)))
        .map_err(crate::error)
}

// Keep read buffers out of the frames of the other requests.
#[inline(never)]
fn read_reply(fd: u32, count: u32, out: &mut Writer) -> Result<(), i32> {
    let read = held(fd, |transport, target| {
        transport
            .prepare_read(target, count as usize)
            .map_err(crate::error)
    })?;
    if let Some((input, extent)) = read.input() {
        Reply::Input {
            uart: input.uart().map(|h| h.0),
            extent: extent as u32,
        }
        .write(out)
        .map_err(|_| EIO)
    } else {
        let (length, bytes) = read.complete().map_err(crate::error)?;
        Reply::Bytes(&bytes[..length]).write(out).map_err(|_| EIO)
    }
}

/// Open: the path resolved under the lock, the service's open outside it,
/// then the descriptor under it again.
fn open(path: &[u8], flags: i32) -> Result<u64, i32> {
    if flags & !(O_ACCMODE | O_DIRECTORY | O_CLOEXEC | O_CLOFORK) != 0
        || flags & O_ACCMODE == O_ACCMODE
    {
        return Err(EINVAL);
    }
    let directory = if flags & O_DIRECTORY != 0 {
        posix_fs::DIRECTORY_ONLY
    } else {
        0
    };
    let (transport, opened) = resolved(path, |transport, path| {
        if path.trailing_slash
            && transport.stat(path).map_err(crate::error)?.kind == posix_fs::FileKind::Regular
        {
            return Err(ENOTDIR);
        }
        let name = path.as_str().map_err(crate::error)?;
        let opened = transport
            .open(name, (flags & O_ACCMODE) as u32 | directory)
            .map_err(crate::error)?;
        Ok((transport, opened))
    })?;
    let inserted = process_state(|files| {
        files
            .insert(opened, crate::descriptor_flags(flags))
            .map_err(crate::error)
    });
    if inserted.is_err() {
        let _ = transport.release(Some(Target::Ram(opened)));
    }
    inserted.map(u64::from)
}

fn number_operation(request: Request<'_>) -> Result<u64, i32> {
    use Request::*;
    match request {
        Open { path, flags } => open(path, flags as i32),
        Write { fd, bytes } => held(fd, |transport, target| match target {
            Target::Output | Target::Error => transport
                .input()
                .write(bytes)
                .map(|n| n as u64)
                .map_err(|status| crate::error(posix_fs::FsError::from(status))),
            target => transport
                .write(target, bytes)
                .map(|n| n as u64)
                .map_err(crate::error),
        }),
        Seek { fd, offset, origin } => held(fd, |transport, target| {
            transport
                .lseek(target, offset, origin)
                .map(|value| value as u64)
                .map_err(crate::error)
        }),
        Dup { fd } => process_state(|files| {
            files
                .dup(fd)
                .map(|value| value as u64)
                .map_err(crate::error)
        }),
        Dup2 { source, target } => releasing(|files| {
            files
                .take_dup3(source, target, None)
                .map(|(fd, release)| (fd as u64, release))
                .map_err(crate::error)
        }),
        Dup3 {
            source,
            target,
            flags,
        } => {
            if flags & !((O_CLOEXEC | O_CLOFORK) as u32) != 0 {
                return Err(EINVAL);
            }
            let flags = crate::descriptor_flags(flags as i32);
            releasing(|files| {
                files
                    .take_dup3(source, target, Some(flags))
                    .map(|(fd, release)| (fd as u64, release))
                    .map_err(crate::error)
            })
        }
        // Directory streams are relibc's (getdents on a descriptor).
        _ => Err(ENOSYS),
    }
}

fn perform(request: Request<'_>, out: &mut Writer) -> Result<(), i32> {
    use Request::*;
    let write = |reply: Reply<'_>, out: &mut Writer| reply.write(out).map_err(|_| EIO);
    match request {
        Close { fd } => {
            releasing(|files| {
                files
                    .take_close(fd)
                    .map(|release| ((), release))
                    .map_err(crate::error)
            })?;
            write(Reply::Unit, out)
        }
        Read { fd, count } => read_reply(fd, count, out),
        Chdir { path } => {
            let directory = resolved(path, |transport, path| {
                Ok(transport.stat(path).map_err(crate::error)?.kind
                    == posix_fs::FileKind::Directory)
            })?;
            if !directory {
                return Err(ENOTDIR);
            }
            process_state(|files| files.set_cwd(path).map_err(crate::error))?;
            write(Reply::Unit, out)
        }
        Cwd => {
            let mut cwd = [0u8; posix_fs::MAX_CWD];
            let len = process_state(|files| {
                let own = files.cwd();
                cwd[..own.len()].copy_from_slice(own);
                Ok(own.len())
            })?;
            write(Reply::Bytes(&cwd[..len]), out)
        }
        Stat { path } => write(
            Reply::Info(resolved(path, |transport, path| {
                transport.stat_information(path).map_err(crate::error)
            })?),
            out,
        ),
        Fstat { fd } => write(
            Reply::Info(held(fd, |transport, target| {
                transport
                    .descriptor_information(target)
                    .map_err(crate::error)
            })?),
            out,
        ),
        Cleanup => {
            for fd in 0..posix_fs::OPEN_MAX as u32 {
                let closed = releasing(|files| match files.take_close(fd) {
                    Ok(release) => Ok(((), release)),
                    Err(posix_fs::FsError::BadFileDescriptor) => Ok(((), None)),
                    Err(error) => Err(crate::error(error)),
                });
                closed?;
            }
            write(Reply::Unit, out)
        }
        number => write(Reply::Number(number_operation(number)?), out),
    }
}

#[cfg(feature = "thread-probe")]
fn error_reply(code: i32) -> Writer {
    let mut out = Writer::new();
    Reply::Error(code)
        .write(&mut out)
        .expect("bounded errno reply");
    out
}

#[cfg(feature = "thread-probe")]
fn request_error(error: proto_wire::Status) -> i32 {
    match error {
        proto_wire::Status::UnknownMethod | proto_wire::Status::BadVersion => ENOSYS,
        _ => EINVAL,
    }
}

/// Runs `f` on the process's files under their lock: the table and the
/// current directory; a request to a service goes through `held` or
/// `resolved` outside it.
pub fn with_files<R>(f: impl FnOnce(&mut PosixFs) -> Result<R, i32>) -> Result<R, i32> {
    process_state(f)
}

pub(crate) fn dispatch<'a>(
    request: Request<'_>,
    buffer: &'a mut [u8; MESSAGE_MAX],
) -> Result<Reply<'a>, i32> {
    let mut encoded = Writer::new();
    perform(request, &mut encoded)?;
    let bytes = encoded.as_bytes();
    buffer[..bytes.len()].copy_from_slice(bytes);
    match Reply::read(&buffer[..bytes.len()]).map_err(|_| EIO)? {
        Reply::Error(code) => Err(code),
        value => Ok(value),
    }
}

pub(crate) fn number(request: Request<'_>) -> Result<u64, i32> {
    if !READY.load(Ordering::Acquire) {
        return Err(ENOSYS);
    }
    number_operation(request)
}

pub(crate) fn unit(request: Request<'_>) -> Result<(), i32> {
    match dispatch(request, &mut [0; MESSAGE_MAX])? {
        Reply::Unit => Ok(()),
        _ => Err(EIO),
    }
}

/// Close the process's descriptors after every client has stopped using them.
/// Callers must arrange quiescence.
pub fn cleanup() -> Result<(), i32> {
    unit(Request::Cleanup)
}

/// A request as the probe wrote it, performed on the process's files: the
/// probes of malformed requests. The reply's bytes go to `buffer`.
#[cfg(feature = "thread-probe")]
pub fn probe(request: &[u8], buffer: &mut [u8; MESSAGE_MAX]) -> Result<usize, rt::abi::Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(rt::abi::Error::BadState);
    }
    let mut encoded = Writer::new();
    let result = Request::read(request)
        .map_err(request_error)
        .and_then(|request| perform(request, &mut encoded));
    if let Err(code) = result {
        encoded = error_reply(code);
    }
    let bytes = encoded.as_bytes();
    buffer[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}
