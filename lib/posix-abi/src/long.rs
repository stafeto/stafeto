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
use rt::handle::{Channel, Handle};
use rt::sys;

/// The errno of a refusal of the service's own, which `run_with` takes;
/// None leaves the refusal to the kernel's errors (EIO for the rest).
type Refusal<'a> = &'a dyn Fn(Status) -> Option<i32>;

/// One request to `service` and its long reply, copied into `out`: the
/// kind and, for READY, the length. EINTR when the kernel interrupted the
/// request before its reply; a refusal as `refusal` says.
fn call(
    service: &Handle<Channel>,
    request: &[u8],
    handle: Option<Handle<Channel>>,
    out: &mut [u8],
    refusal: Refusal<'_>,
) -> Result<(u32, usize, u64), i32> {
    let reply = match handle {
        None => sys::send(service, request).map_err(|e| e.into_errno())?,
        Some(handle) => sys::send_handles(service, request, [handle.erase()])
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
struct OuterRestart(u32);

impl OuterRestart {
    fn enter(flags: &core::sync::atomic::AtomicU32) -> OuterRestart {
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
/// cancellation, or a handler without SA_RESTART ran since it started.
fn ending(flags: &core::sync::atomic::AtomicU32) -> bool {
    crate::threads::cancel::requested() || flags.load(Ordering::SeqCst) & flag::NO_RESTART != 0
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
    // From before the first request: a handler that ran on the way back
    // from a reply, outside `receive`, leaves its mark for the wait.
    let block = crate::threads::own_block();
    let _outer = OuterRestart::enter(&block.flags);
    let key = match call(service, start, None, out, refusal)? {
        (long::READY, n, _) => return Ok(n),
        (long::WAIT, _, key) => key,
        _ => return Err(EIO),
    };
    let request = |cancel: bool| {
        let mut w = Writer::new();
        keyed(cancel, key, &mut w).map(|()| w)
    };
    let take = request(false).map_err(|_| EIO)?;
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
            match call(service, take.as_bytes(), None, out, refusal) {
                Ok((long::READY, n, _)) => return Ok(n),
                Ok((long::ARMED, _, _)) => {}
                Ok(_) => break 'wait Some(EIO),
                Err(EINTR) if ending(&block.flags) => break 'wait None,
                Err(EINTR) => armed = false,
                Err(error) => break 'wait Some(error),
            }
            continue;
        }
        if !armed {
            handled = block.handled.load(Ordering::SeqCst);
            let Ok(labelled) =
                sys::handle_label(&channel, Rights::NOTIFY | Rights::TRANSFER, key, level)
            else {
                break 'wait Some(EAGAIN);
            };
            match call(service, take.as_bytes(), Some(labelled), out, refusal) {
                Ok((long::READY, n, _)) => return Ok(n),
                Ok((long::ARMED, _, _)) => armed = true,
                Ok(_) => break 'wait Some(EIO),
                Err(EINTR) if ending(&block.flags) => break 'wait None,
                Err(EINTR) => continue,
                Err(error) => break 'wait Some(error),
            }
        }
        // An entry that came outside `receive` ends the wait before it
        // blocks; one that comes from here on stays pending and makes
        // `receive` return at once.
        let guard = rt::upcall::defer_entries().map_err(|_| EIO)?;
        if ending(&block.flags) {
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
                match call(service, take.as_bytes(), None, out, refusal) {
                    Ok((long::READY, n, _)) => return Ok(n),
                    Ok((long::ARMED, _, _)) => {}
                    Ok(_) => break 'wait Some(EIO),
                    Err(EINTR) if ending(&block.flags) => break 'wait None,
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
            }) if bits & posix_sync::bit::CANCEL != 0 && crate::threads::cancel::requested() => {
                break 'wait None;
            }
            Ok(_) => {}
            Err(Error::Interrupted) => {
                if ending(&block.flags) {
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
        match call(service, request.as_bytes(), None, out, refusal) {
            Ok((long::READY, n, _)) => return Ok(n),
            Ok((long::CANCELLED, _, _)) => return Err(cancel.unwrap_or(EINTR)),
            Err(EINTR) => {}
            Ok(_) => return Err(EIO),
            Err(error) => return Err(error),
        }
    }
}
