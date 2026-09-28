// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Private in-process owner of file and directory state. Explicit value
//! messages own their payload in message pages; the worker never borrows a
//! caller job or invokes an address supplied in a request.

use crate::{constants::*, directory::Streams, tls};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use posix_fs::PosixFs;
use posix_request::{MESSAGE_MAX, Reply, Request};
use proto_wire::Writer;
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
static READY: AtomicBool = AtomicBool::new(false);
static STACK: Stack<32768> = Stack::new();

fn channel() -> &'static Handle<Channel> {
    // SAFETY: initialization or READY establishes an immutable installed handle.
    unsafe { (*CHANNEL.0.get()).as_ref().expect("file owner initialized") }
}

/// # Safety
/// Startup has exclusive access, before any client thread uses the file owner.
/// The worker stack is used once and its message page at 0xb00000 is unused.
pub unsafe fn init(process: &Handle<Process>, files: PosixFs) -> Result<(), rt::abi::Error> {
    if READY.load(Ordering::Acquire) {
        return Err(rt::abi::Error::BadState);
    }
    let channel = sys::channel_create(1)?;
    unsafe {
        *CHANNEL.0.get() = Some(channel);
        *FILES.0.get() = Some(files);
    }
    let started = (|| {
        let thread = unsafe {
            sys::thread_create(process, worker, STACK.top(), 0, 1, Policy::Fifo, 0xb00000)
        }?;
        // Publish initialization before the worker can run. Startup excludes clients.
        READY.store(true, Ordering::Release);
        sys::thread_start(&thread)
    })();
    if started.is_err() {
        READY.store(false, Ordering::Release);
        // SAFETY: a failed create/start left no worker able to consume this state.
        unsafe {
            *FILES.0.get() = None;
            *CHANNEL.0.get() = None;
        }
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
                Request::read(&input[..len])
                    .map_err(request_error)
                    .and_then(|request| {
                        // SAFETY: this thread uniquely owns the local file scope.
                        perform(
                            request,
                            unsafe { &*tls::directories() },
                            unsafe { &mut *tls::files() },
                            &mut output,
                        )
                    })
            };
            if let Err(code) = result {
                output = error_reply(code);
            }
            // A departed client cannot invalidate input or output owned by this worker.
            let _ = token.reply(output.as_bytes());
        }
    })
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
        let reply = sys::send(channel(), encoded.as_bytes()).map_err(|error| match error {
            rt::abi::Error::Interrupted => EINTR,
            _ => EIO,
        })?;
        if !reply.handles.is_empty() {
            return Err(EIO);
        }
        reply.bytes(buffer)
    } else {
        let streams = tls::directories();
        let files = tls::files();
        if streams.is_null() || files.is_null() {
            return Err(ENOSYS);
        }
        let mut encoded = Writer::new();
        // SAFETY: the local scope uniquely borrows files and owns its registry.
        perform(
            request,
            unsafe { &*streams },
            unsafe { &mut *files },
            &mut encoded,
        )?;
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
    let streams = tls::directories();
    let files = tls::files();
    if streams.is_null() || files.is_null() {
        return Err(ENOSYS);
    }
    // SAFETY: the unique local owner executes the same operation without IPC buffers.
    number_operation(request, unsafe { &*streams }, unsafe { &mut *files })
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

#[cfg(feature = "transport-probe")]
pub fn probe(request: &[u8], buffer: &mut [u8; MESSAGE_MAX]) -> Result<usize, rt::abi::Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(rt::abi::Error::BadState);
    }
    let reply = sys::send(channel(), request)?;
    Ok(reply.bytes(buffer).len())
}
