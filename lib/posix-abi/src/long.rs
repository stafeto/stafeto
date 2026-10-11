// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Long operations of services in two steps (spec 2, 3.4; design of 5a,
//! 1.7, 1.8; proto_wire::long), from the calling thread. "Start" goes
//! without a handle: a ready result comes in its reply, one round trip.
//! Otherwise the service answers WAIT k; the thread sends "take k" with a
//! copy of its own channel labelled k (NOTIFY) and waits in `receive` on
//! its channel until bit 0 comes in that slot, then takes the result. A
//! signal entry ends the wait with "cancel k" unless every handler that ran
//! had SA_RESTART: then it waits on, the operation still alive in the
//! service. A request of cancellation (bit CANCEL or an entry) cancels too,
//! and the caller's point takes it. A result that was ready when the cancel
//! came is returned: nothing is lost.
use crate::constants::*;
use core::sync::atomic::Ordering;
use posix_thread::flag;
use proto_wire::{Status, Writer, long};
use rt::abi::{Error, MESSAGE_MAX, Rights, Source};
use rt::handle::{Channel, Handle, Timer};
use rt::sys;

/// The errno of a refusal of the service's own, which `run_with` takes;
/// None leaves the refusal to the kernel's errors (EIO for the rest).
type Refusal<'a> = &'a dyn Fn(Status) -> Option<i32>;

/// Paid tcdrain record receives accepted keys/results before delivery opens.
pub(crate) trait Custody {
    fn record(&self, kind: u32, key: u64) -> Result<(), i32>;
}
struct Mode<'a> {
    point: bool,
    authenticated: bool,
    custody: Option<&'a dyn Custody>,
}
impl Mode<'_> {
    fn plain(point: bool, authenticated: bool) -> Self {
        Self {
            point,
            authenticated,
            custody: None,
        }
    }
}

/// A short custody transition closes kernel and synchronous unlock delivery.
/// It covers one RPC at most; never the long receive or admission pause.
pub(crate) struct ShortScope {
    local: Option<posix_sync::DeliveryPreparation<'static>>,
    kernel: Option<rt::upcall::DeferredEntry>,
}
impl ShortScope {
    pub(crate) fn enter(enabled: bool) -> Result<Self, i32> {
        if !enabled {
            return Ok(Self {
                local: None,
                kernel: None,
            });
        }
        // Lifetime help can run before any TCB is published on a raw worker.
        // Such a caller cannot take local preparation and must not admit one.
        let block = unsafe { posix_thread::block().as_ref() }.ok_or(EIO)?;
        let kernel = rt::upcall::defer_entries().map_err(|_| EIO)?;
        let local = posix_sync::DeliveryPreparation::begin(block);
        Ok(Self {
            local: Some(local),
            kernel: Some(kernel),
        })
    }
}
impl Drop for ShortScope {
    fn drop(&mut self) {
        if self.local.is_some() {
            let block = crate::threads::own_block();
            if block.flags.load(Ordering::SeqCst) & flag::ENTRY_DEFERRED != 0 {
                let thread = Handle::<rt::handle::Thread>::borrowed(rt::abi::Handle(
                    block.thread.load(Ordering::Relaxed),
                ));
                sys::thread_upcall_request(&thread).expect("short custody delivery owner");
            }
        }
        drop(self.local.take());
        drop(self.kernel.take());
    }
}

/// One request to `service` and its long reply, copied into `out`: the
/// kind and, for READY, the length. EINTR when the kernel interrupted the
/// request before its reply; a refusal as `refusal` says.
fn call(
    service: &Handle<Channel>,
    request: &[u8],
    handle: Option<Handle<Channel>>,
    out: &mut [u8],
    refusal: Refusal<'_>,
    authenticated: bool,
    custody: Option<&dyn Custody>,
) -> Result<(u32, usize, u64), i32> {
    let _scope = ShortScope::enter(custody.is_some())?;
    let identity = authenticated
        .then(|| {
            crate::process::identity()
                .and_then(|identity| {
                    sys::handle_duplicate(identity, Rights::NOTIFY | Rights::TRANSFER).ok()
                })
                .ok_or(EIO)
        })
        .transpose()?;
    let reply = match (identity, handle) {
        (Some(identity), Some(handle)) => {
            sys::send_handles(service, request, [identity.erase(), handle.erase()])
                .map_err(|refused| refused.error.into_errno())?
        }
        (Some(identity), None) => sys::send_handles(service, request, [identity.erase()])
            .map_err(|refused| refused.error.into_errno())?,
        (None, None) => sys::send(service, request).map_err(|e| e.into_errno())?,
        (None, Some(handle)) => sys::send_handles(service, request, [handle.erase()])
            .map_err(|refused| refused.error.into_errno())?,
    };
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    let len = bytes.len();
    let result = match long::Reply::read(bytes) {
        Ok(long::Reply::Ready(result)) => {
            let n = result.len().min(out.len());
            out[..n].copy_from_slice(&result[..n]);
            Ok((long::READY, n, 0))
        }
        Ok(long::Reply::Wait(key)) => Ok((long::WAIT, 0, key)),
        Ok(long::Reply::Armed) => Ok((long::ARMED, 0, 0)),
        Ok(long::Reply::Cancelled) => Ok((long::CANCELLED, 0, 0)),
        Err(status) if refusal(status).is_some() => Err(refusal(status).unwrap_or(EIO)),
        Err(Status::Kernel(Error::LimitReached)) => Err(EAGAIN),
        Err(Status::Kernel(error)) => Err(error.into_errno()),
        Err(_) => Err(EIO),
    };
    // The reply's copy on the stack goes (a key of the entropy service
    // among them), and a child of fork finds none of it.
    posix_random::erase(&mut buffer[..len]);
    if let (Some(custody), Ok((kind, _, key))) = (custody, result)
        && matches!(kind, long::WAIT | long::READY | long::CANCELLED)
        && custody.record(kind, key).is_err()
    {
        // Accepted server state must never escape without its resident owner.
        sys::process_exit(127);
    }
    result
}

trait Errno {
    fn into_errno(self) -> i32;
}
impl Errno for Error {
    fn into_errno(self) -> i32 {
        match self {
            Error::Interrupted => EINTR,
            Error::LimitReached => EAGAIN,
            Error::BadState => EBUSY,
            _ => EIO,
        }
    }
}

/// Keeps the caller's NO_RESTART across a nested long operation: a
/// handler without SA_RESTART that ran while the outer one waited stays
/// seen by it, whatever the inner one clears (a handler may read too).
pub(crate) struct OuterRestart(u32);

impl OuterRestart {
    pub(crate) fn enter(flags: &core::sync::atomic::AtomicU32) -> OuterRestart {
        OuterRestart(flags.fetch_and(!flag::NO_RESTART, Ordering::SeqCst) & flag::NO_RESTART)
    }
}

impl Drop for OuterRestart {
    fn drop(&mut self) {
        crate::threads::own_block()
            .flags
            .fetch_or(self.0, Ordering::SeqCst);
    }
}

/// Whether the wait of the operation ends with "cancel k": a request of
/// cancellation when the operation is a point of cancellation (`point`),
/// or a handler without SA_RESTART ran since it started.
pub(crate) fn ending(flags: &core::sync::atomic::AtomicU32, point: bool) -> bool {
    (point && crate::threads::cancel::requested())
        || flags.load(Ordering::SeqCst) & flag::NO_RESTART != 0
}

/// Runs a long operation on `service`: `start` is its first request,
/// `keyed(cancel, k)` writes "take k" or "cancel k". The result goes into
/// `out`; its length, or EINTR when a signal or cancellation ended it with
/// no effect. Once the service answered WAIT k, every way out of here
/// goes through a "take k" that brings the result or a "cancel k": a
/// "take" that the kernel took back from the queue (EINTR), or a labelled
/// copy that could not be made, ends as an entry in the wait does. The
/// service keeps the operation until then, or until the client's session
/// goes: a thread that leaves between the two steps past this function
/// (siglongjmp, asynchronous cancellation, thread_exit) leaves it there
/// until the session goes.
pub fn run(
    service: &Handle<Channel>,
    start: &[u8],
    keyed: impl Fn(bool, u64, &mut Writer) -> Result<(), Status>,
    out: &mut [u8],
) -> Result<usize, i32> {
    run_with(service, start, keyed, out, &|_| None)
}

/// `run` with the errnos of the service's own refusals, `refusal`: those
/// of the start, of a take and of a cancel alike.
pub fn run_with(
    service: &Handle<Channel>,
    start: &[u8],
    keyed: impl Fn(bool, u64, &mut Writer) -> Result<(), Status>,
    out: &mut [u8],
    refusal: Refusal<'_>,
) -> Result<usize, i32> {
    run_in(
        service,
        Start::Once(start),
        keyed,
        out,
        refusal,
        Mode::plain(true, false),
    )
}

/// `run_with` for an operation that is no point of cancellation
/// (getentropy, getrandom, arc4random; XSH 2.9.5 allows no new points): a
/// request of cancellation leaves the wait alone and stays for the next
/// point; a handler without SA_RESTART still ends it with EINTR.
pub fn run_no_point(
    service: &Handle<Channel>,
    start: &[u8],
    keyed: impl Fn(bool, u64, &mut Writer) -> Result<(), Status>,
    out: &mut [u8],
    refusal: Refusal<'_>,
) -> Result<usize, i32> {
    run_in(
        service,
        Start::Once(start),
        keyed,
        out,
        refusal,
        Mode::plain(false, false),
    )
}

/// A terminal operation authenticates every actual request. The identity
/// precedes the optional notification handle; cancellation still only
/// removes the operation and does not check foreground access.
pub fn run_with_identity(
    service: &Handle<Channel>,
    start: &[u8],
    keyed: impl Fn(bool, u64, &mut Writer) -> Result<(), Status>,
    out: &mut [u8],
    refusal: Refusal<'_>,
) -> Result<usize, i32> {
    run_in(
        service,
        Start::Once(start),
        keyed,
        out,
        refusal,
        Mode::plain(true, true),
    )
}

/// Terminal slave requests authenticate; master requests use their owning
/// service session and a notification in slot zero.
pub(crate) fn run_terminal(
    master: bool,
    service: &Handle<Channel>,
    start: &[u8],
    keyed: impl Fn(bool, u64, &mut Writer) -> Result<(), Status>,
    out: &mut [u8],
    refusal: Refusal<'_>,
) -> Result<usize, i32> {
    run_in(
        service,
        Start::Once(start),
        keyed,
        out,
        refusal,
        Mode::plain(true, !master),
    )
}

// Private sentinel: only a decoded service START refusal produces it.
const ADMISSION_LIMIT: i32 = -31002;

enum Start<'a> {
    Once(&'a [u8]),
    Admission(&'a dyn Fn() -> Result<Writer, Status>),
}

/// Physical tcdrain waits for existing paid capacity before it captures a
/// prefix. Every retry refreshes job-control arguments. TAKE and CANCEL
/// retain their original identity and never retry as a new START.
pub(crate) fn run_drain(
    service: &Handle<Channel>,
    start: impl Fn() -> Result<Writer, Status>,
    keyed: impl Fn(bool, u64, &mut Writer) -> Result<(), Status>,
    refusal: Refusal<'_>,
    custody: Option<&dyn Custody>,
) -> Result<(), i32> {
    run_in(
        service,
        Start::Admission(&start),
        keyed,
        &mut [],
        refusal,
        Mode {
            point: true,
            authenticated: true,
            custody,
        },
    )
    .map(drop)
}

/// No server state is retained yet. Use the thread's already paid timer;
/// signal deferral closes the race between the flags check and receive.
pub(crate) fn admission_pause() -> Result<(), i32> {
    let block = crate::threads::own_block();
    let channel =
        Handle::<Channel>::borrowed(rt::abi::Handle(block.channel.load(Ordering::Relaxed)));
    let timer = Handle::<Timer>::borrowed(rt::abi::Handle(block.timer.load(Ordering::Relaxed)));
    let deadline = rt::time::ticks_to_ns(rt::time::now()).saturating_add(1_000_000);
    let result = loop {
        let guard = match rt::upcall::defer_entries() {
            Ok(guard) => guard,
            Err(_) => break Err(EIO),
        };
        if ending(&block.flags, true) {
            drop(guard);
            break Err(EINTR);
        }
        if rt::time::reached(deadline) {
            drop(guard);
            break Ok(());
        }
        if sys::timer_set(&timer, deadline).is_err() {
            drop(guard);
            break Err(EIO);
        }
        let got = sys::receive(&channel);
        drop(guard);
        match got {
            Ok(_) | Err(Error::Interrupted) => {}
            Err(_) => break Err(EIO),
        }
    };
    let _ = sys::timer_cancel(&timer);
    result
}

fn run_in(
    service: &Handle<Channel>,
    start: Start<'_>,
    keyed: impl Fn(bool, u64, &mut Writer) -> Result<(), Status>,
    out: &mut [u8],
    refusal: Refusal<'_>,
    mode: Mode<'_>,
) -> Result<usize, i32> {
    let Mode {
        point,
        authenticated,
        custody,
    } = mode;
    // From before the first request: a handler that ran on the way back
    // from a reply, outside `receive`, leaves its mark for the wait.
    let block = crate::threads::own_block();
    let _outer = OuterRestart::enter(&block.flags);
    let admission = matches!(start, Start::Admission(_));
    let start_refusal = |status| {
        if admission && status == Status::Kernel(Error::LimitReached) {
            Some(ADMISSION_LIMIT)
        } else {
            refusal(status)
        }
    };
    let key = loop {
        if admission && ending(&block.flags, point) {
            return Err(EINTR);
        }
        let reply = match &start {
            Start::Once(bytes) => call(
                service,
                bytes,
                None,
                out,
                &start_refusal,
                authenticated,
                custody,
            ),
            Start::Admission(build) => {
                let request = build().map_err(|_| EIO)?;
                call(
                    service,
                    request.as_bytes(),
                    None,
                    out,
                    &start_refusal,
                    authenticated,
                    custody,
                )
            }
        };
        match reply {
            Ok((long::READY, n, _)) => return Ok(n),
            Ok((long::WAIT, _, key)) => break key,
            Err(ADMISSION_LIMIT) => admission_pause()?,
            Err(EINTR) if admission && !ending(&block.flags, point) => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(EIO),
        }
    };
    let request = |cancel: bool| {
        let mut w = Writer::new();
        keyed(cancel, key, &mut w).map(|()| w)
    };
    let channel =
        Handle::<Channel>::borrowed(rt::abi::Handle(block.channel.load(Ordering::Relaxed)));
    let level = block.base_level.load(Ordering::Relaxed) as u8;
    // The first take brings the labelled copy: the service keeps it while
    // the operation waits. A take the kernel took back left the service
    // without it, and the next one brings a new copy.
    let mut armed = false;
    // The handlers that had run when the operation was last looked at: a
    // handler's own long operation on this thread receives from the same
    // channel and may take this one's notification, so once a handler ran
    // the wait asks again ("take k" with no handle) before it blocks.
    let mut handled = block.handled.load(Ordering::SeqCst);
    let cancel = 'wait: loop {
        if armed && block.handled.load(Ordering::SeqCst) != handled {
            handled = block.handled.load(Ordering::SeqCst);
            match call(
                service,
                request(false).map_err(|_| EIO)?.as_bytes(),
                None,
                out,
                refusal,
                authenticated,
                custody,
            ) {
                Ok((long::READY, n, _)) => return Ok(n),
                Ok((long::ARMED, _, _)) => {}
                Ok(_) => break 'wait Some(EIO),
                Err(EINTR) if ending(&block.flags, point) => break 'wait None,
                Err(EINTR) => armed = false,
                Err(error) => break 'wait Some(error),
            }
            continue;
        }
        if !armed {
            handled = block.handled.load(Ordering::SeqCst);
            // No user entry may abandon a newly created transfer clone before
            // the request has either transferred it or closed the refusal.
            let clone_guard = if custody.is_some() {
                Some(rt::upcall::defer_entries().map_err(|_| EIO)?)
            } else {
                None
            };
            let Ok(labelled) =
                sys::handle_label(&channel, Rights::NOTIFY | Rights::TRANSFER, key, level)
            else {
                break 'wait Some(EAGAIN);
            };
            let reply = call(
                service,
                request(false).map_err(|_| EIO)?.as_bytes(),
                Some(labelled),
                out,
                refusal,
                authenticated,
                custody,
            );
            drop(clone_guard);
            match reply {
                Ok((long::READY, n, _)) => return Ok(n),
                Ok((long::ARMED, _, _)) => armed = true,
                Ok(_) => break 'wait Some(EIO),
                Err(EINTR) if ending(&block.flags, point) => break 'wait None,
                Err(EINTR) => continue,
                Err(error) => break 'wait Some(error),
            }
        }
        // An entry that came outside `receive` ends the wait before it
        // blocks; one that comes from here on stays pending and makes
        // `receive` return at once.
        let guard = rt::upcall::defer_entries().map_err(|_| EIO)?;
        if ending(&block.flags, point) {
            drop(guard);
            break 'wait None;
        }
        // A handler that ran since the look above: look again first.
        if block.handled.load(Ordering::SeqCst) != handled {
            drop(guard);
            continue;
        }
        let got = sys::receive(&channel);
        drop(guard);
        match got {
            Ok(sys::Received::Notification {
                source: Source::Session,
                label,
                bits,
                ..
            }) if label == key && bits & 1 != 0 => {
                match call(
                    service,
                    request(false).map_err(|_| EIO)?.as_bytes(),
                    None,
                    out,
                    refusal,
                    authenticated,
                    custody,
                ) {
                    Ok((long::READY, n, _)) => return Ok(n),
                    Ok((long::ARMED, _, _)) => {}
                    Ok(_) => break 'wait Some(EIO),
                    Err(EINTR) if ending(&block.flags, point) => break 'wait None,
                    // The service told once and keeps the result for the
                    // next "take"; it tells no second time, so the take
                    // goes again with a new copy and does not wait.
                    Err(EINTR) => armed = false,
                    Err(error) => break 'wait Some(error),
                }
            }
            Ok(sys::Received::Notification {
                source: Source::Unlabeled,
                bits,
                ..
            }) if point
                && bits & posix_sync::bit::CANCEL != 0
                && crate::threads::cancel::requested() =>
            {
                break 'wait None;
            }
            Ok(_) => {}
            Err(Error::Interrupted) => {
                if ending(&block.flags, point) {
                    break 'wait None;
                }
                // Every handler that ran had SA_RESTART: wait on.
            }
            Err(error) => panic!("long operation receive: {error:?}"),
        }
    };
    // "Cancel k": the result if it was ready, nothing otherwise; the
    // error of the way out, EINTR for an entry or a cancellation.
    let request = request(true).map_err(|_| EIO)?;
    loop {
        match call(
            service,
            request.as_bytes(),
            None,
            out,
            refusal,
            authenticated,
            custody,
        ) {
            Ok((long::READY, n, _)) => return Ok(n),
            Ok((long::CANCELLED, _, _)) => return Err(cancel.unwrap_or(EINTR)),
            Err(EINTR) => {}
            Ok(_) => return Err(EIO),
            Err(error) => return Err(error),
        }
    }
}
