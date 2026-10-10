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
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
};
use posix_fs::{Inherited, PosixFs, Resolved, StartupFiles, Target, Transport};
use posix_request::{MESSAGE_MAX, Reply, Request};
use posix_sync::LayerLock;
use proto_wire::Writer;
use rt::handle::Handle;

struct State {
    files: MaybeUninit<PosixFs>,
}
struct Cell(UnsafeCell<State>);
// SAFETY: startup installs the files once; afterwards only `process_state`
// borrows the state, under FILES_LOCK.
unsafe impl Sync for Cell {}
static STATE: Cell = Cell(UnsafeCell::new(State {
    files: MaybeUninit::uninit(),
}));
static STARTED: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static FILES_LOCK: LayerLock = LayerLock::raising();
pub fn terminals_kept_by_fork(out: &mut [u32; posix_fs::OPEN_MAX]) -> Result<usize, i32> {
    process_state(|files| Ok(files.terminals_kept_by_fork(out)))
}

/// Runs `run` holding the lock of the process's files, for the guest probes.
#[cfg(feature = "thread-probe")]
pub fn probe_hold(run: impl FnOnce()) {
    let _guard = FILES_LOCK.lock();
    run();
}

/// A recursive recovery probe checks the critical depth and raised priority balance.
#[cfg(feature = "thread-probe")]
pub fn probe_recovery_busy_balanced() -> bool {
    let block = crate::threads::own_block();
    let before = block.flags.load(Ordering::SeqCst);
    let mask = block.mask.load(Ordering::SeqCst);
    let busy = try_with_files(|_| Ok(())).is_err();
    busy && block.flags.load(Ordering::SeqCst) == before
        && block.mask.load(Ordering::SeqCst) == mask
}

/// # Safety
/// Startup has exclusive access, before any client thread uses the files.
pub unsafe fn init(
    startup: StartupFiles,
    cwd: &[u8],
    inherited: Option<&[Inherited]>,
    secure: bool,
    identity: Option<&Handle<rt::handle::Channel>>,
) -> Result<(), rt::abi::Error> {
    if STARTED.swap(true, Ordering::AcqRel) {
        return Err(rt::abi::Error::BadState);
    }
    if let Some(identity) = identity {
        startup
            .bind(identity)
            .map_err(|_| rt::abi::Error::BadState)?;
    }
    // SAFETY: startup has exclusive access; no client exists yet.
    unsafe {
        PosixFs::initialize_at(
            (*STATE.0.get()).files.as_mut_ptr(),
            startup,
            cwd,
            inherited,
            secure,
        )
    }
    .map_err(|_| rt::abi::Error::BadState)?;
    crate::relibc::configure_open_lifetime(detach_open_owner, help_open_recovery);
    READY.store(true, Ordering::Release);
    Ok(())
}

/// The files of a forked child (posix_fs::PosixFs::after_fork): its own
/// sessions `files`, `uart`, `pipes` and `terminal`.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork(
    files: Handle<rt::handle::Channel>,
    uart: Option<Handle<rt::handle::Channel>>,
    pipes: Option<Handle<rt::handle::Channel>>,
    terminal: Option<Handle<rt::handle::Channel>>,
) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: the caller's promise gives this borrow alone.
    {
        // SAFETY: READY witnesses complete in-place initialization.
        let own = unsafe { (*STATE.0.get()).files.assume_init_mut() };
        own.after_fork(files, uart, pipes, terminal);
        if let Some(identity) = crate::process::identity() {
            let _ = own.bind(identity);
        }
    }
}

/// The descriptions of the RAM file service a forked child's session
/// shares (posix_fs::PosixFs::kept_by_fork), into `out`; how many.
pub fn kept_by_fork(out: &mut [rt::fs::PreparedOpen; posix_fs::OPEN_MAX]) -> Result<usize, i32> {
    process_state(|files| Ok(files.kept_by_fork(out)))
}

/// The ends of pipes a forked child's session shares
/// (posix_fs::PosixFs::pipes_kept_by_fork), into `out`; how many.
pub fn pipes_kept_by_fork(out: &mut [u32; posix_fs::OPEN_MAX]) -> Result<usize, i32> {
    process_state(|files| Ok(files.pipes_kept_by_fork(out)))
}

/// Runs `run` holding the lock of the process's files, for the probes of
/// a fork while another thread holds it.
pub(crate) fn hold(run: impl FnOnce()) {
    let _guard = FILES_LOCK.lock();
    run();
}

/// Runs `f` on the process's files under their lock.
fn process_state<R>(f: impl FnOnce(&mut PosixFs) -> Result<R, i32>) -> Result<R, i32> {
    if !READY.load(Ordering::Acquire) {
        return Err(ENOSYS);
    }
    let _guard = FILES_LOCK.lock();
    // SAFETY: the lock gives this borrow alone; READY published the state.
    let state = unsafe { &mut *STATE.0.get() };
    // SAFETY: READY witnesses complete initialization and the lock is exclusive.
    let files = unsafe { state.files.assume_init_mut() };
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

/// Runs `run` with the transports and what `fd` names, outside the lock.
/// RAM and pipe close waits until `run` is over. Terminal last-fd close
/// releases the real hold immediately; armed I/O retains a service pin.
pub fn held<R>(fd: u32, run: impl FnOnce(Transport, Target) -> Result<R, i32>) -> Result<R, i32> {
    let (transport, target) = with_fd(fd, |files| {
        Ok((files.transport(), files.hold(fd).map_err(crate::error)?))
    })?;
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

/// The holds of the threads an exec stopped go, and the descriptions
/// whose last descriptor went while one was held close in the service.
pub fn abandon_holds() {
    while let Ok(Some((transport, target))) =
        process_state(|files| Ok(files.abandon_hold().map(|t| (files.transport(), t))))
    {
        let _ = transport.release(Some(target));
    }
}

/// The assembly longjmp keeps kernel entries deferred until its restored SP.
/// Preparation also prevents synchronous delivery from FILES_LOCK's unlock.
pub fn jump_mark(target_sp: u64) {
    // SAFETY: a published current Block lives through this callback.
    let Some(block) = (unsafe { posix_thread::block().as_ref() }) else {
        return;
    };
    let preparation = posix_sync::DeliveryPreparation::begin(block);
    if let Some(owner) =
        crate::relibc::jump_owner().and_then(|owner| posix_fs::change::OwnerToken::new(owner).ok())
    {
        let _ = process_state(|files| {
            files.mark_control_jump(owner, entries::Frame::main(target_sp));
            Ok(())
        });
    }
    // Unlock cannot consume this local marker. Give it a real pending entry
    // before assembly resumes, even when no kernel entry was already pending.
    if block.flags.load(Ordering::SeqCst) & posix_thread::flag::ENTRY_DEFERRED != 0 {
        let thread = Handle::<rt::handle::Thread>::borrowed(rt::abi::Handle(
            block.thread.load(Ordering::Relaxed),
        ));
        rt::sys::thread_upcall_request(&thread).expect("jump deferred delivery owner");
    }
    drop(preparation);
}

/// Close of the service's open description `fd`, which the table handed
/// back to release, outside the lock.
pub fn release(fd: posix_fs::RamTarget) -> Result<(), i32> {
    release_target(Target::Ram(fd))
}

/// Close of what `target` names in its service (a file's description, a
/// pipe's end), which the table handed back to release, outside the lock.
pub fn release_target(target: Target) -> Result<(), i32> {
    let transport = process_state(|files| Ok(files.transport()))?;
    transport.release(Some(target)).map_err(crate::error)
}

/// The reply of a read of a file or the console: its bytes, or the
/// console's route for a read of input in two steps.
// Keep read buffers out of the frames of the other requests.
#[inline(never)]
fn file_reply(
    transport: Transport,
    target: Target,
    count: u32,
    out: &mut Writer,
) -> Result<(), i32> {
    let read = transport
        .prepare_read(target, count as usize)
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

/// The reply of a read of a random device: bytes of the layer's generator,
/// no request to a service (the generator waits for its first key, and a
/// signal handler without SA_RESTART ends that wait with EINTR).
#[inline(never)]
fn random_reply(count: u32, out: &mut Writer) -> Result<(), i32> {
    let mut bytes = [0; posix_fs::MAX_READ];
    let extent = (count as usize).min(bytes.len());
    crate::random::fill(&mut bytes[..extent], false)?;
    let reply = Reply::Bytes(&bytes[..extent]).write(out).map_err(|_| EIO);
    posix_random::erase(&mut bytes[..extent]);
    reply
}

/// The reply of a read of a pipe's read end, its bytes once they came.
#[inline(never)]
fn pipe_reply(transport: Transport, end: u32, count: u32, out: &mut Writer) -> Result<(), i32> {
    let mut bytes = [0; posix_fs::MAX_READ];
    let extent = (count as usize).min(bytes.len());
    let n = crate::pipes::read(transport, end, &mut bytes[..extent])?;
    Reply::Bytes(&bytes[..n]).write(out).map_err(|_| EIO)
}

/// The reply of a read of the console through the terminal service (5f),
/// its bytes once they came.
#[inline(never)]
fn terminal_reply(
    transport: Transport,
    number: u32,
    count: u32,
    out: &mut Writer,
) -> Result<(), i32> {
    let mut bytes = [0; posix_fs::MAX_READ];
    let extent = (count as usize).min(bytes.len());
    let n = crate::terminal::read(transport, number, &mut bytes[..extent])?;
    Reply::Bytes(&bytes[..n]).write(out).map_err(|_| EIO)
}

/// A read of `fd`: what it names held, outside the lock; the read of a
/// pipe or of the terminal waits here. Each kind has its own frame: the
/// reads of files stay as deep as they were (threads with small stacks
/// read files).
fn read_reply(fd: u32, count: u32, out: &mut Writer) -> Result<(), i32> {
    held(fd, |transport, target| match target {
        Target::Pipe(end) => pipe_reply(transport, end, count, &mut *out),
        Target::Input if transport.terminal().is_some() => {
            terminal_reply(transport, proto_tty::CONSOLE, count, &mut *out)
        }
        Target::Tty(number) => terminal_reply(transport, number, count, &mut *out),
        Target::Random(_) => random_reply(count, &mut *out),
        target => file_reply(transport, target, count, &mut *out),
    })
}

/// What an open of a name gave: a description of the RAM file service, or
/// a terminal of the terminal service.
#[derive(Clone, Copy)]
enum Opened {
    Resident(u32),
    /// A terminal, and whether it was opened as /dev/tty.
    Terminal(u32, bool),
}

/// Open: the path resolved under the lock, the service's open outside it,
/// then the descriptor under it again.
fn open(path: &[u8], flags: i32, mode: u32, umask: u32) -> Result<u64, i32> {
    open_from(None, path, flags, mode, umask)
}

/// Open of a path that starts at a descriptor of the session (`base`: its
/// number and the generation of its description), or against the current
/// directory when there is none.
pub(crate) fn open_from(
    base: Option<(u32, u64)>,
    path: &[u8],
    flags: i32,
    mode: u32,
    umask: u32,
) -> Result<u64, i32> {
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
            | O_APPEND
            | O_NOFOLLOW)
        != 0
        || flags & O_ACCMODE == O_ACCMODE
    {
        return Err(EINVAL);
    }
    let mut policy = (flags & O_ACCMODE) as u32;
    for (local, backend) in [
        (O_DIRECTORY, posix_fs::DIRECTORY_ONLY),
        (O_CHANGES, posix_fs::CHANGES),
        (O_CREAT, posix_fs::CREATE),
        (O_EXCL, posix_fs::EXCLUSIVE),
        (O_TRUNC, posix_fs::TRUNCATE),
        (O_APPEND, posix_fs::APPEND),
        (O_NOFOLLOW, posix_fs::NO_FOLLOW),
    ] {
        if flags & local != 0 {
            policy |= backend;
        }
    }
    // What an open does with a resolved path once the layer knows whether it
    // is a regular file with a slash after it (ENOTDIR) and whether it names a
    // terminal of the terminal service.
    let finish =
        |transport: Transport, bytes: &[u8], trailing_slash: bool, terminal: Option<(u32, u32)>| {
            if let Some((kind, number)) = terminal {
                if flags & O_DIRECTORY != 0 || trailing_slash {
                    return Err(ENOTDIR);
                }
                let id = crate::terminal::open(
                    transport,
                    kind,
                    (flags & (O_ACCMODE | O_NONBLOCK)) as u32,
                    number,
                )?;
                return Ok((
                    transport,
                    Opened::Terminal(
                        id,
                        kind == proto_tty::OPEN_CONTROLLING || kind == proto_tty::OPEN_MASTER,
                    ),
                ));
            }
            let fd = crate::open_driver::open(
                transport,
                base,
                bytes,
                policy,
                mode,
                umask,
                crate::descriptor_flags(flags),
            )?;
            Ok((transport, Opened::Resident(fd)))
        };
    let (transport, opened) = match base {
        None => resolved(path, |transport, path| {
            if path.trailing_slash
                && transport.stat(path).map_err(crate::error)?.kind == posix_fs::FileKind::Regular
            {
                return Err(ENOTDIR);
            }
            let terminal = transport.terminal_open(path).map_err(crate::error)?;
            finish(transport, path.as_bytes(), path.trailing_slash, terminal)
        })?,
        Some(_) => {
            let transport = process_state(|files| Ok(files.transport()))?;
            let trailing_slash = path.last() == Some(&b'/');
            if trailing_slash {
                let info = transport
                    .files()
                    .node_information_from(base, path, true)
                    .map_err(|status| crate::error(posix_fs::FsError::from(status)))?;
                if info.kind == 2 {
                    return Err(ENOTDIR);
                }
            }
            let terminal = transport
                .terminal_leaf(base, path, false)
                .map_err(crate::error)?;
            finish(transport, path, trailing_slash, terminal)?
        }
    };
    let inserted = process_state(|files| {
        let flags = crate::descriptor_flags(flags);
        match opened {
            Opened::Resident(fd) => return Ok(fd),
            Opened::Terminal(number, _) => files.insert_terminal(number, flags),
        }
        .map_err(crate::error)
    });
    // A session leader that opens a terminal without O_NOCTTY takes it as
    // its controlling terminal when its session has none and the terminal
    // is no other session's (XBD 11.1.3); the open stands either way.
    if inserted.is_ok()
        && let Opened::Terminal(number, false) = opened
        && flags & O_NOCTTY == 0
        && crate::process::getsid(0) == Ok(crate::process::getpid())
    {
        let _ = crate::terminal::job(transport, number, proto_tty::Method::Acquire, None);
    }
    if inserted.is_err() {
        let target = match opened {
            Opened::Resident(_) => return inserted.map(u64::from),
            Opened::Terminal(id, _) => Target::Tty(id),
        };
        let _ = transport.release(Some(target));
    }
    inserted.map(u64::from)
}

fn number_operation(request: Request<'_>) -> Result<u64, i32> {
    use Request::*;
    match request {
        Open {
            path,
            flags,
            mode,
            umask,
        } => open(path, flags as i32, mode, umask),
        Write { fd, bytes } => held(fd, |transport, target| {
            // A file or the console takes at most one message of it.
            let extent = &bytes[..bytes.len().min(posix_request::MAX_WRITE)];
            match target {
                // The write of the terminal waits here, outside the lock.
                Target::Output | Target::Error if transport.terminal().is_some() => {
                    crate::terminal::write(transport, proto_tty::CONSOLE, bytes).map(|n| n as u64)
                }
                Target::Tty(number) => {
                    crate::terminal::write(transport, number, bytes).map(|n| n as u64)
                }
                Target::Output | Target::Error => transport
                    .input()
                    .write(extent)
                    .map(|n| n as u64)
                    .map_err(|status| crate::error(posix_fs::FsError::from(status))),
                // The write of a pipe waits here, outside the lock.
                Target::Pipe(end) => crate::pipes::write(transport, end, bytes).map(|n| n as u64),
                target => transport
                    .write(target, extent)
                    .map(|n| n as u64)
                    .map_err(crate::error),
            }
        }),
        Seek { fd, offset, origin } => held(fd, |transport, target| {
            transport
                .lseek(target, offset, origin)
                .map(|value| value as u64)
                .map_err(crate::error)
        }),
        Dup { fd } => with_fd(fd, |files| {
            files
                .dup(fd)
                .map(|value| value as u64)
                .map_err(crate::error)
        }),
        Dup2 { source, target } => duplicate_replacing(source, target, None),
        Dup3 {
            source,
            target,
            flags,
        } => {
            if flags & !((O_CLOEXEC | O_CLOFORK) as u32) != 0 {
                return Err(EINVAL);
            }
            duplicate_replacing(source, target, Some(crate::descriptor_flags(flags as i32)))
        }
        // Directory streams are relibc's (getdents on a descriptor).
        _ => Err(ENOSYS),
    }
}

/// A tentative numeric target keeps its operation alive while the caller waits unlocked.
fn duplicate_replacing(
    source: u32,
    target: u32,
    flags: Option<posix_fs::DescriptorFlags>,
) -> Result<u64, i32> {
    crate::close_driver::replace(source, target, flags).map(u64::from)
}

fn perform(request: Request<'_>, out: &mut Writer) -> Result<(), i32> {
    use Request::*;
    let write = |reply: Reply<'_>, out: &mut Writer| reply.write(out).map_err(|_| EIO);
    match request {
        Close { fd } => {
            crate::close_driver::close(fd)?;
            write(Reply::Unit, out)
        }
        Read { fd, count } => read_reply(fd, count, out),
        Chdir { path } => {
            // The service names the directory by its canonical path, without
            // links, `.` and `..`: the current directory is a place.
            let mut canonical = [0; crate::names::MAX_PATH + 1];
            let length = crate::names::directory_path(path, &mut canonical)?;
            process_state(|files| files.set_cwd(&canonical[..length]).map_err(crate::error))?;
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
                match crate::close_driver::close(fd) {
                    Ok(()) | Err(EBADF) => {}
                    Err(error) => return Err(error),
                }
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
/// Recovery borrows the resident state only when its lock is immediately available.
pub(crate) fn try_with_files<R>(f: impl FnOnce(&mut PosixFs) -> Result<R, i32>) -> Result<R, i32> {
    if !READY.load(Ordering::Acquire) {
        return Err(ENOSYS);
    }
    let _guard = FILES_LOCK.try_lock().ok_or(crate::EAGAIN)?;
    // SAFETY: READY published the state and the successful guard is exclusive.
    let files = unsafe { (&mut *STATE.0.get()).files.assume_init_mut() };
    f(files)
}

/// Inspect competing Closing records under the same lock as the fd operation.
/// The original closure runs once, after every exact event is confirmed unlocked.
pub fn with_fd<R>(fd: u32, f: impl FnOnce(&mut PosixFs) -> Result<R, i32>) -> Result<R, i32> {
    with_descriptors(&[fd], f)
}

pub fn with_descriptors<R>(
    fds: &[u32],
    f: impl FnOnce(&mut PosixFs) -> Result<R, i32>,
) -> Result<R, i32> {
    enum Step<R> {
        Close(posix_fs::closing::CloseToken),
        Done(Result<R, i32>),
    }
    let mut f = Some(f);
    loop {
        let step = process_state(|files| {
            if let Some(token) = fds.iter().find_map(|&fd| files.closing(fd)) {
                return Ok(Step::Close(token));
            }
            Ok(Step::Done(f.take().expect("one fd operation")(files)))
        })?;
        match step {
            Step::Close(token) => crate::close_driver::settle_token(token)?,
            Step::Done(result) => return result,
        }
    }
}

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

/// Final lifetime callbacks perform local transitions and retain remote ownership.
pub fn detach_open_owner(owner: u64) -> bool {
    let opens = crate::open_driver::detach(owner);
    // Every resident Control family loses this exact native lifetime.
    let changes = crate::change::detach(owner);
    let closes = crate::close_driver::detach(owner);
    let drains = crate::drain_driver::detach(owner);
    opens && changes && closes && drains
}
/// A surviving caller or collector pays one cleanup phase outside the layer locks.
pub fn help_open_recovery() {
    crate::open_driver::help();
    crate::change::help();
    crate::close_driver::help();
    crate::drain_driver::help();
}
