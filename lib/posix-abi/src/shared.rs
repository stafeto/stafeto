// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Private in-process owner of file and directory state, a worker at the
//! process ceiling. Explicit value messages own their payload in message
//! pages; the worker never borrows a caller job or invokes an address
//! supplied in a request.

use crate::{constants::*, directory::Streams, tls};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use posix_fs::PosixFs;
use posix_request::{MESSAGE_MAX, Reply, Request, exchange::Exchange};
mod replies;
use proto_wire::Writer;
use replies::Journal;
use rt::{
    Stack,
    abi::Policy,
    handle::{Channel, Handle, Process},
    sys,
};

struct Cell<T>(UnsafeCell<Option<T>>);
// SAFETY: startup installs once; the channel stays immutable and the initial
// file state is consumed exactly once by its sole worker. Publication is atomic.
unsafe impl<T: Send> Sync for Cell<T> {}
static CHANNEL: Cell<Handle<Channel>> = Cell(UnsafeCell::new(None));
static FILES: Cell<PosixFs> = Cell(UnsafeCell::new(None));
static PROCESS: AtomicU64 = AtomicU64::new(0);
static READY: AtomicBool = AtomicBool::new(false);
static NEXT: AtomicU64 = AtomicU64::new(1);
static STACK: Stack<32768> = Stack::new();
#[cfg(feature = "thread-probe")]
static PROBE_LOCAL_KIND: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "thread-probe")]
static PROBE_LOCAL_TARGET: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "thread-probe")]
static PROBE_LOCAL_LIVE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "thread-probe")]
static PROBE_WORKER: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "thread-probe")]
static PROBE_START: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// The base priority of the live file worker.
#[cfg(feature = "thread-probe")]
pub fn probe_worker_base() -> u8 {
    let raw = rt::abi::Handle(PROBE_WORKER.load(Ordering::Acquire));
    let thread = Handle::<rt::handle::Thread>::borrowed(raw);
    sys::thread_info(&thread).expect("file worker info").base
}

/// Create the file worker at `priority` instead of the ceiling. A probe
/// calls it before init to queue requests while the worker, below main,
/// has not yet reached its receive.
#[cfg(feature = "thread-probe")]
pub fn probe_start_priority(priority: u8) {
    PROBE_START.store(priority, Ordering::Release);
}

/// Request entry while the next local operation holds its file references.
/// kind 1 selects value replies, kind 2 selects numeric replies. The target
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

fn channel() -> &'static Handle<Channel> {
    // SAFETY: initialization or READY establishes an immutable installed handle.
    unsafe { (*CHANNEL.0.get()).as_ref().expect("file owner initialized") }
}

/// # Safety
/// Startup has exclusive access, before any client thread uses the file owner.
/// The worker stack is used once and its message page at 0xb00000 is unused.
/// Reply storage reserves 0x20000000..0x28000000 independently of malloc.
/// process must remain open until process exit (normally owned by allocation::init).
pub unsafe fn init(process: &Handle<Process>, files: PosixFs) -> Result<(), rt::abi::Error> {
    if READY.load(Ordering::Acquire) {
        return Err(rt::abi::Error::BadState);
    }
    let channel = sys::channel_create(1)?;
    unsafe {
        *CHANNEL.0.get() = Some(channel);
        *FILES.0.get() = Some(files);
    }
    PROCESS.store(process.raw().0, Ordering::Relaxed);
    let started = (|| {
        let level = crate::ceiling()?;
        #[cfg(feature = "thread-probe")]
        let level = match PROBE_START.load(Ordering::Acquire) {
            0 => level,
            probe => probe,
        };
        let thread = unsafe {
            sys::thread_create(
                process,
                worker,
                STACK.top(),
                0,
                level,
                Policy::Fifo,
                0xb00000,
            )
        }?;
        // Publish initialization before the worker can run. Startup excludes clients.
        READY.store(true, Ordering::Release);
        sys::thread_start(&thread)?;
        #[cfg(feature = "thread-probe")]
        PROBE_WORKER.store(thread.into_raw().0, Ordering::Release);
        Ok(())
    })();
    if started.is_err() {
        READY.store(false, Ordering::Release);
        // SAFETY: a failed create/start left no worker able to consume this state.
        unsafe {
            *FILES.0.get() = None;
            *CHANNEL.0.get() = None;
        }
        PROCESS.store(0, Ordering::Relaxed);
        return started;
    }
    Ok(())
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

fn error_reply(code: i32) -> Writer {
    let mut out = Writer::new();
    Reply::Error(code)
        .write(&mut out)
        .expect("bounded errno reply");
    out
}

fn request_error(error: proto_wire::Status) -> i32 {
    match error {
        proto_wire::Status::UnknownMethod | proto_wire::Status::BadVersion => ENOSYS,
        _ => EINVAL,
    }
}

extern "C" fn worker(_: u64) -> ! {
    assert!(READY.load(Ordering::Acquire), "published file owner");
    // SAFETY: startup handed this state exclusively to this worker.
    let mut files = unsafe { (*FILES.0.get()).take().expect("initial file state") };
    tls::with_files(&mut files, || {
        // Startup keeps this process capability alive for the worker's full lifetime.
        let process = Handle::<Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Relaxed)));
        let mut journal = Journal::new(&process);
        loop {
            let Ok(sys::Received::Message {
                len,
                words,
                token,
                handles,
                ..
            }) = sys::receive(channel())
            else {
                continue;
            };
            let unexpected_handles = !handles.is_empty();
            drop(handles);
            // Copy before any nested service call overwrites this thread's message page.
            let mut input = [0; MESSAGE_MAX];
            let mut output = Writer::new();
            let result = if unexpected_handles || len > input.len() {
                Err(EINVAL)
            } else {
                let inline = len.min(rt::abi::INLINE_MAX);
                input[..inline].copy_from_slice(&rt::abi::inline_bytes(&words)[..inline]);
                if len > inline {
                    rt::msgbuf::read(inline, &mut input[inline..len]);
                }
                Exchange::read(&input[..len])
                    .map_err(request_error)
                    .and_then(|exchange| match exchange {
                        Exchange::Fetch(nonce) => output
                            .bytes(journal.reply(nonce).ok_or(EINTR)?)
                            .map_err(|_| EIO),
                        Exchange::Ack(nonce) => {
                            journal.ack(nonce);
                            Reply::Unit.write(&mut output).map_err(|_| EIO)
                        }
                        Exchange::Execute { nonce, request } => {
                            if journal.reply(nonce).is_none() {
                                journal.reserve(nonce)?;
                                let result = Request::read(request)
                                    .map_err(request_error)
                                    .and_then(|request| {
                                        // SAFETY: this thread uniquely owns the local file scope.
                                        perform(
                                            request,
                                            unsafe { &*tls::directories() },
                                            unsafe { &mut *tls::files() },
                                            journal.output(nonce),
                                        )
                                    });
                                if let Err(code) = result {
                                    *journal.output(nonce) = error_reply(code);
                                }
                            }
                            output
                                .bytes(journal.reply(nonce).expect("committed file reply"))
                                .map_err(|_| EIO)
                        }
                    })
            };
            if let Err(code) = result {
                output = error_reply(code);
            }
            let _ = token.reply(output.as_bytes());
        }
    })
}

fn send_copy(request: &[u8], buffer: &mut [u8; MESSAGE_MAX]) -> Result<usize, rt::abi::Error> {
    let reply = sys::send(channel(), request)?;
    if !reply.handles.is_empty() {
        return Err(rt::abi::Error::BadState);
    }
    Ok(reply.bytes(buffer).len())
}
fn retry(request: &[u8], buffer: &mut [u8; MESSAGE_MAX]) -> Result<usize, i32> {
    loop {
        match send_copy(request, buffer) {
            Err(rt::abi::Error::Interrupted) => continue,
            value => return value.map_err(|_| EIO),
        }
    }
}
fn execute(request: &[u8], buffer: &mut [u8; MESSAGE_MAX]) -> Result<usize, i32> {
    let nonce = NEXT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
        .map_err(|_| EOVERFLOW)?;
    let mut wire = Writer::new();
    Exchange::Execute { nonce, request }
        .write(&mut wire)
        .map_err(request_error)?;
    let length = match send_copy(wire.as_bytes(), buffer) {
        Err(rt::abi::Error::Interrupted) => {
            wire = Writer::new();
            Exchange::Fetch(nonce)
                .write(&mut wire)
                .map_err(request_error)?;
            retry(wire.as_bytes(), buffer)?
        }
        value => value.map_err(|_| EIO)?,
    };
    // The reply has been copied to the caller's own stack before Ack overwrites IPC.
    wire = Writer::new();
    Exchange::Ack(nonce)
        .write(&mut wire)
        .map_err(request_error)?;
    let mut response = [0; MESSAGE_MAX];
    let size = retry(wire.as_bytes(), &mut response)?;
    if !matches!(Reply::read(&response[..size]), Ok(Reply::Unit)) {
        return Err(EIO);
    }
    Ok(length)
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

pub(crate) fn dispatch<'a>(
    request: Request<'_>,
    buffer: &'a mut [u8; MESSAGE_MAX],
) -> Result<Reply<'a>, i32> {
    let bytes = if tls::process_files() {
        if !READY.load(Ordering::Acquire) {
            return Err(ENOSYS);
        }
        let mut encoded = Writer::new();
        request.write(&mut encoded).map_err(request_error)?;
        let length = execute(encoded.as_bytes(), buffer)?;
        &buffer[..length]
    } else {
        let mut encoded = Writer::new();
        local(1, |streams, files| {
            perform(request, streams, files, &mut encoded)
        })?;
        let bytes = encoded.as_bytes();
        buffer[..bytes.len()].copy_from_slice(bytes);
        &buffer[..bytes.len()]
    };
    match Reply::read(bytes).map_err(|_| EIO)? {
        Reply::Error(code) => Err(code),
        value => Ok(value),
    }
}

#[inline(never)]
fn remote_number(request: Request<'_>) -> Result<u64, i32> {
    match dispatch(request, &mut [0; MESSAGE_MAX])? {
        Reply::Number(value) => Ok(value),
        _ => Err(EIO),
    }
}

pub(crate) fn number(request: Request<'_>) -> Result<u64, i32> {
    if tls::process_files() {
        return remote_number(request);
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
/// The worker remains alive until process exit. Callers must arrange quiescence.
pub fn cleanup() -> Result<(), i32> {
    unit(Request::Cleanup)
}

/// A request as the probe wrote it, through the whole exchange with the
/// worker: the probes of malformed requests.
#[cfg(feature = "thread-probe")]
pub fn probe(request: &[u8], buffer: &mut [u8; MESSAGE_MAX]) -> Result<usize, rt::abi::Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(rt::abi::Error::BadState);
    }
    execute(request, buffer).map_err(|code| match code {
        EINTR => rt::abi::Error::Interrupted,
        ENOMEM => rt::abi::Error::NoMemory,
        _ => rt::abi::Error::InvalidArgs,
    })
}
