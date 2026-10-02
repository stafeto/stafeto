// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's file and directory state under a lock of the layer (spec
//! 2, 3.4): the calling thread performs its request itself, its holder at
//! the ceiling of the process (LayerLock::raising). No helper thread. The
//! lock is held through the request to the file service, since the state
//! of a descriptor and its session go together in posix-fs.

use crate::{constants::*, directory::Streams, tls};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use posix_fs::PosixFs;
use posix_request::{MESSAGE_MAX, Reply, Request};
use posix_sync::LayerLock;
use proto_wire::Writer;
#[cfg(feature = "thread-probe")]
use rt::{handle::Handle, sys};

struct State {
    files: Option<PosixFs>,
    streams: Streams,
}
struct Cell(UnsafeCell<State>);
// SAFETY: startup installs the files once; afterwards only `process_state`
// borrows the state, under FILES_LOCK.
unsafe impl Sync for Cell {}
static STATE: Cell = Cell(UnsafeCell::new(State {
    files: None,
    streams: Streams::new(),
}));
static READY: AtomicBool = AtomicBool::new(false);
static FILES_LOCK: LayerLock = LayerLock::raising();
#[cfg(feature = "thread-probe")]
static PROBE_LOCAL_KIND: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "thread-probe")]
static PROBE_LOCAL_TARGET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "thread-probe")]
static PROBE_LOCAL_LIVE: AtomicBool = AtomicBool::new(false);

/// Runs `run` holding the lock of the process's files, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_hold(run: impl FnOnce()) {
    let _guard = FILES_LOCK.lock();
    run();
}

/// Request entry while the next local operation holds its file references.
/// kind 1 selects operations with a reply, kind 2 numeric operations. The target
/// handle must stay live until that call returns; only one probe may be armed.
#[cfg(feature = "thread-probe")]
pub fn probe_local_borrow(kind: u64, target: &Handle<rt::handle::Thread>) {
    assert!(kind == 1 || kind == 2);
    PROBE_LOCAL_TARGET.store(target.raw().0, Ordering::Relaxed);
    PROBE_LOCAL_KIND.store(kind, Ordering::Release);
}

#[cfg(feature = "thread-probe")]
pub fn probe_local_borrow_live() -> bool {
    PROBE_LOCAL_LIVE.load(Ordering::Acquire)
}

#[cfg(feature = "thread-probe")]
struct BorrowProbe(bool);
#[cfg(feature = "thread-probe")]
impl BorrowProbe {
    fn enter(kind: u64) -> Self {
        let armed = PROBE_LOCAL_KIND
            .compare_exchange(kind, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if armed {
            PROBE_LOCAL_LIVE.store(true, Ordering::Release);
            let target = Handle::<rt::handle::Thread>::borrowed(rt::abi::Handle(
                PROBE_LOCAL_TARGET.load(Ordering::Acquire),
            ));
            sys::thread_upcall_request(&target).unwrap();
        }
        Self(armed)
    }
}
#[cfg(feature = "thread-probe")]
impl Drop for BorrowProbe {
    fn drop(&mut self) {
        if self.0 {
            PROBE_LOCAL_LIVE.store(false, Ordering::Release);
        }
    }
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

/// Runs `f` on the process's streams and files under their lock.
fn process_state<R>(f: impl FnOnce(&Streams, &mut PosixFs) -> Result<R, i32>) -> Result<R, i32> {
    if !READY.load(Ordering::Acquire) {
        return Err(ENOSYS);
    }
    let _guard = FILES_LOCK.lock();
    // SAFETY: the lock gives this borrow alone; READY published the state.
    let state = unsafe { &mut *STATE.0.get() };
    let files = state.files.as_mut().ok_or(ENOSYS)?;
    f(&state.streams, files)
}

// Keep read buffers out of metadata/directory dispatch stack frames. Local
// scopes already carry a directory registry on their caller's fixed stack.
#[inline(never)]
fn read_reply(files: &mut PosixFs, fd: u32, count: u32, out: &mut Writer) -> Result<(), i32> {
    let read = files
        .prepare_read(fd, count as usize)
        .map_err(crate::error)?;
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

// Separate transport-sized write buffers from other numeric operations.
#[inline(never)]
fn write_number(files: &PosixFs, fd: u32, bytes: &[u8]) -> Result<u64, i32> {
    files
        .write(fd, bytes)
        .map(|value| value as u64)
        .map_err(crate::error)
}

fn number_operation(
    request: Request<'_>,
    streams: &Streams,
    files: &mut PosixFs,
) -> Result<u64, i32> {
    use Request::*;
    match request {
        Open { path, flags } => {
            let flags = flags as i32;
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
            let fd = files
                .open(path, (flags & O_ACCMODE) as u32 | directory)
                .map_err(crate::error)?;
            files
                .set_descriptor_flags(fd, crate::descriptor_flags(flags))
                .map_err(crate::error)?;
            Ok(fd as u64)
        }
        Write { fd, bytes } => write_number(files, fd, bytes),
        Seek { fd, offset, origin } => files
            .lseek(fd, offset, origin)
            .map(|value| value as u64)
            .map_err(crate::error),
        Dup { fd } => files
            .dup(fd)
            .map(|value| value as u64)
            .map_err(crate::error),
        Dup2 { source, target } => files
            .dup2(source, target)
            .map(|value| value as u64)
            .map_err(crate::error),
        Dup3 {
            source,
            target,
            flags,
        } => {
            if flags & !((O_CLOEXEC | O_CLOFORK) as u32) != 0 {
                return Err(EINVAL);
            }
            files
                .dup3(source, target, crate::descriptor_flags(flags as i32))
                .map(|value| value as u64)
                .map_err(crate::error)
        }
        directory => streams.perform(directory, files),
    }
}

fn perform(
    request: Request<'_>,
    streams: &Streams,
    files: &mut PosixFs,
    out: &mut Writer,
) -> Result<(), i32> {
    use Request::*;
    let write = |reply: Reply<'_>, out: &mut Writer| reply.write(out).map_err(|_| EIO);
    match request {
        Close { fd } => {
            files.close(fd).map_err(crate::error)?;
            write(Reply::Unit, out)
        }
        Read { fd, count } => read_reply(files, fd, count, out),
        Chdir { path } => {
            files.chdir(path).map_err(crate::error)?;
            write(Reply::Unit, out)
        }
        Cwd => write(Reply::Bytes(files.cwd()), out),
        Stat { path } => write(
            Reply::Info(files.stat_information(path).map_err(crate::error)?),
            out,
        ),
        Fstat { fd } => write(
            Reply::Info(files.descriptor_information(fd).map_err(crate::error)?),
            out,
        ),
        Cleanup => {
            streams.close_all(files);
            for fd in 0..posix_fs::OPEN_MAX as u32 {
                match files.close(fd) {
                    Ok(()) | Err(posix_fs::FsError::BadFileDescriptor) => (),
                    Err(error) => return Err(crate::error(error)),
                }
            }
            write(Reply::Unit, out)
        }
        number => write(
            Reply::Number(number_operation(number, streams, files)?),
            out,
        ),
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

// Keep every local reference inside the guard, including error exits. The
// callback may return owned data or a reply borrowing its caller's buffer,
// but its result cannot borrow these operation-local file references.
fn local<R>(
    kind: u64,
    run: impl FnOnce(&Streams, &mut PosixFs) -> Result<R, i32>,
) -> Result<R, i32> {
    let _guard = rt::upcall::defer_entries().map_err(|_| EIO)?;
    let streams = tls::directories();
    let files = tls::files();
    if streams.is_null() || files.is_null() {
        return Err(ENOSYS);
    }
    // SAFETY: the TLS scope owns both objects; deferred entries cannot reborrow
    // them until this operation ends and all exclusive references are gone.
    let (streams, files) = unsafe { (&*streams, &mut *files) };
    #[cfg(feature = "thread-probe")]
    let _probe = BorrowProbe::enter(kind);
    #[cfg(not(feature = "thread-probe"))]
    let _ = kind;
    run(streams, files)
}

/// Runs `f` on the process's files under their lock (relibc's platform:
/// every thread of a program on relibc uses the process's files).
pub fn with_files<R>(f: impl FnOnce(&mut PosixFs) -> Result<R, i32>) -> Result<R, i32> {
    process_state(|_, files| f(files))
}

pub(crate) fn dispatch<'a>(
    request: Request<'_>,
    buffer: &'a mut [u8; MESSAGE_MAX],
) -> Result<Reply<'a>, i32> {
    let mut encoded = Writer::new();
    if tls::process_files() {
        process_state(|streams, files| perform(request, streams, files, &mut encoded))?;
    } else {
        local(1, |streams, files| {
            perform(request, streams, files, &mut encoded)
        })?;
    }
    let bytes = encoded.as_bytes();
    buffer[..bytes.len()].copy_from_slice(bytes);
    match Reply::read(&buffer[..bytes.len()]).map_err(|_| EIO)? {
        Reply::Error(code) => Err(code),
        value => Ok(value),
    }
}

pub(crate) fn number(request: Request<'_>) -> Result<u64, i32> {
    if tls::process_files() {
        // A write to the console leaves the section: the driver answers a
        // write into a full ring only once it drained.
        if let Request::Write { fd, bytes } = request
            && let Some(console) =
                process_state(|_, files| files.console_route(fd).map_err(crate::error))?
        {
            return console
                .write(bytes)
                .map(|n| n as u64)
                .map_err(|status| crate::error(posix_fs::FsError::from(status)));
        }
        return process_state(|streams, files| number_operation(request, streams, files));
    }
    local(2, |streams, files| {
        number_operation(request, streams, files)
    })
}

pub(crate) fn unit(request: Request<'_>) -> Result<(), i32> {
    match dispatch(request, &mut [0; MESSAGE_MAX])? {
        Reply::Unit => Ok(()),
        _ => Err(EIO),
    }
}

pub(crate) fn information(request: Request<'_>) -> Result<posix_fs::NodeInfo, i32> {
    match dispatch(request, &mut [0; MESSAGE_MAX])? {
        Reply::Info(info) => Ok(info),
        _ => Err(EIO),
    }
}

/// Close process descriptors and streams after every client has stopped using them.
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
        .and_then(|request| {
            process_state(|streams, files| perform(request, streams, files, &mut encoded))
        });
    if let Err(code) = result {
        encoded = error_reply(code);
    }
    let bytes = encoded.as_bytes();
    buffer[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}
