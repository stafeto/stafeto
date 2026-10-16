// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! F_SETLKW and F_OFD_SETLKW. The service queues the request and tells the
//! client when to arm a notification channel, sleep on it and ask again.
//!
//! The thread blocks every signal for the whole operation and opens the mask
//! only inside the sleep, in the manner of pselect. A handler therefore never
//! runs while a registration exists: a signal that ends the sleep is held,
//! the registration is cancelled and released, and the handler runs after
//! that, with the mask restored. A handler that jumps or ends the thread
//! leaves nothing behind in the service, and the client keeps no record.

use crate::constants::{EDEADLK, EINTR, EIO, ENOLCK};
use ::core::sync::atomic::{AtomicU64, Ordering};
use posix_fs::Transport;
use proto_fs::{
    DataDescription, LockKind, Method, WaitKey, WaitMode, WaitPhase, WaitReply, WaitStart,
};
use proto_wire::{Reader, Status, Writer};
use rt::abi::{Error, Rights};
use rt::handle::{Channel, Handle};
use rt::sys;

/// What the caller wants locked, copied from the flock fields.
#[derive(Clone, Copy)]
pub(crate) struct Input {
    pub mode: WaitMode,
    pub kind: LockKind,
    pub whence: u32,
    pub start: i64,
    pub length: i64,
    pub pid: i32,
}

#[cfg(feature = "wait-probe")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Probe {
    /// The thread is about to sleep on its channel.
    Receive,
    /// The service reported a final result.
    Complete,
}
#[cfg(feature = "wait-probe")]
static HOOK: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "wait-probe")]
pub fn probe_hook(hook: Option<fn(Probe, WaitKey) -> bool>) {
    HOOK.store(
        hook.map_or(0, |hook| hook as usize as u64),
        Ordering::Release,
    );
}
#[cfg(feature = "wait-probe")]
fn probed(phase: Probe, key: WaitKey) {
    let raw = HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: probe_hook stores only functions of this exact type.
        let hook =
            unsafe { ::core::mem::transmute::<usize, fn(Probe, WaitKey) -> bool>(raw as usize) };
        hook(phase, key);
    }
}

/// A call that did not end the operation.
enum Failure {
    /// A stray entry ended the call, or the service is binding: send again.
    Again,
    /// The key's place in the service is taken by another wait.
    Busy,
    Rejected(u32),
    Fatal(i32),
}

enum Ended {
    Done(Result<(), i32>),
    /// A signal or a cancellation request ended the wait; nothing is
    /// registered any more.
    Signalled,
}

/// Keys are unique and rising within the process, across exec as well,
/// because they come from the counter of the machine.
static LAST: AtomicU64 = AtomicU64::new(0);
fn generation() -> u64 {
    let now = rt::time::now();
    let mut next = 1;
    let _ = LAST.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |last| {
        next = last.wrapping_add(1).max(now).max(1);
        Some(next)
    });
    next
}

struct Wait {
    transport: Transport,
    channel: Handle<Channel>,
    key: WaitKey,
    /// Saved mask of the caller: what the sleep opens.
    outer: u64,
}
impl Wait {
    fn call(&self, request: &Writer) -> Result<WaitReply, Failure> {
        let files = self.transport.files();
        let response = match rt::fs::Files::send_on(files.sessions().0, request.as_bytes()) {
            Ok(response) => response,
            Err(Status::Kernel(Error::Interrupted)) => return Err(Failure::Again),
            Err(_) => return Err(Failure::Fatal(EIO)),
        };
        self.decode(&response)
    }
    fn decode(&self, response: &sys::Reply) -> Result<WaitReply, Failure> {
        if !response.handles.is_empty() || response.len > rt::abi::INLINE_MAX {
            return Err(Failure::Fatal(EIO));
        }
        let bytes = rt::abi::inline_bytes(&response.words);
        match WaitReply::read(Reader::new(&bytes[..response.len])) {
            Ok(reply) => Ok(reply),
            Err(Status::Unknown(proto_fs::RESOLVING)) => Err(Failure::Again),
            Err(Status::Unknown(proto_fs::JOBS_FULL | proto_fs::OPEN_RETIRED)) => {
                Err(Failure::Busy)
            }
            Err(Status::Unknown(code)) => Err(Failure::Rejected(code)),
            Err(_) => Err(Failure::Fatal(EIO)),
        }
    }
    fn keyed(&self, method: Method) -> Result<Writer, Failure> {
        let mut request = Writer::new();
        proto_fs::write_wait_key(method, self.key, &mut request)
            .map_err(|_| Failure::Fatal(EIO))?;
        Ok(request)
    }
    /// Send again after a stray entry, until the service answers.
    fn answer(&self, request: &Writer) -> Result<WaitReply, Failure> {
        loop {
            match self.call(request) {
                Err(Failure::Again) => {
                    let _ = sys::yield_now();
                }
                other => return other,
            }
        }
    }
    fn arm(&self) -> Result<WaitReply, Failure> {
        let request = self.keyed(Method::WaitArm)?;
        loop {
            let copy = sys::handle_duplicate(&self.channel, Rights::NOTIFY | Rights::TRANSFER)
                .map_err(|_| Failure::Fatal(EIO))?;
            let files = self.transport.files();
            match sys::send_handles(files.sessions().0, request.as_bytes(), [copy.erase()]) {
                Ok(response) => match self.decode(&response) {
                    Err(Failure::Again) => {
                        let _ = sys::yield_now();
                    }
                    other => return other,
                },
                Err(refused) if refused.error == Error::Interrupted => {
                    drop(refused.back);
                    let _ = sys::yield_now();
                }
                Err(_) => return Err(Failure::Fatal(EIO)),
            }
        }
    }
    /// Release the registration for good: cancel until the service has a
    /// final result, then release the place. The result tells whether the
    /// lock was granted before the cancellation reached the service.
    fn withdraw(&self) -> Option<WaitReply> {
        let cancel = self.keyed(Method::WaitCancel).ok()?;
        let mut last = None;
        for turn in 0u32.. {
            match self.answer(&cancel) {
                Ok(reply) if reply.phase == WaitPhase::Complete => {
                    last = Some(reply);
                    break;
                }
                Ok(_) => {
                    let _ = sys::yield_now();
                }
                Err(_) => break,
            }
            let _ = turn;
        }
        self.release();
        last
    }
    fn release(&self) {
        let Ok(request) = self.keyed(Method::WaitRelease) else {
            return;
        };
        let files = self.transport.files();
        loop {
            match rt::fs::Files::send_on(files.sessions().0, request.as_bytes()) {
                Ok(response) if response.words[0] as u32 == proto_fs::RESOLVING => {
                    let _ = sys::yield_now();
                }
                Err(Status::Kernel(Error::Interrupted)) => {
                    let _ = sys::yield_now();
                }
                _ => return,
            }
        }
    }
    /// A signal this thread would take, or a request of cancellation.
    fn signalled(&self) -> bool {
        crate::signals::pending_beyond(self.outer) || crate::threads::cancel::requested()
    }
    /// Sleep on the channel with the caller's mask. Pending signals are
    /// checked after the mask opens, and the mask closes again before the
    /// deferral ends, so that no handler runs here.
    fn sleep(&self) -> bool {
        #[cfg(feature = "wait-probe")]
        probed(Probe::Receive, self.key);
        let Ok(guard) = rt::upcall::defer_entries() else {
            return false;
        };
        crate::signals::swap_mask(self.outer);
        if !self.signalled() {
            let _ = sys::receive(&self.channel);
        }
        crate::signals::swap_mask(u64::MAX);
        drop(guard);
        self.signalled()
    }
}

/// Results of the service for a wait that ended.
fn outcome(reply: WaitReply) -> Result<(), i32> {
    match reply.result {
        0 => Ok(()),
        proto_fs::LOCK_CANCELLED => Err(EINTR),
        proto_fs::LOCK_DEADLOCK => Err(EDEADLK),
        code => Err(crate::lock_fields::refusal(code)),
    }
}

fn run(transport: Transport, description: DataDescription, input: Input, outer: u64) -> Ended {
    let level = (crate::threads::own_block()
        .base_level
        .load(Ordering::Relaxed) as u8)
        .max(1);
    let channel = match sys::channel_create(level) {
        Ok(channel) => channel,
        Err(Error::NoMemory | Error::LimitReached) => return Ended::Done(Err(ENOLCK)),
        Err(_) => return Ended::Done(Err(EIO)),
    };
    let mut wait = Wait {
        transport,
        channel,
        key: WaitKey {
            slot: 0,
            generation: 1,
        },
        outer,
    };
    // The first place to try differs by thread, so that two waiters of one
    // process rarely meet at the same one.
    let mut slot =
        (crate::threads::own_block().thread_id % proto_fs::WAIT_KEY_PLACES as u64) as u32;
    let mut tried = 0u32;
    if wait.signalled() {
        return Ended::Signalled;
    }
    let mut reply = loop {
        wait.key = WaitKey {
            slot,
            generation: generation(),
        };
        let mut request = Writer::new();
        let start = WaitStart {
            key: wait.key,
            description,
            mode: input.mode,
            kind: input.kind,
            whence: input.whence,
            start: input.start,
            length: input.length,
            pid: input.pid,
        };
        if start.write(&mut request).is_err() {
            return Ended::Done(Err(crate::constants::EINVAL));
        }
        // After a lost reply the same key goes again: the service takes a
        // repeated Start of the same key and answers with the state.
        match wait.answer(&request) {
            Ok(reply) => break reply,
            Err(Failure::Busy) => {
                slot = (slot + 1) % proto_fs::WAIT_KEY_PLACES as u32;
                tried += 1;
                if tried.is_multiple_of(proto_fs::WAIT_KEY_PLACES as u32) {
                    let _ = crate::threads::sleep::pause(posix_change::room_pause_ns(
                        tried / proto_fs::WAIT_KEY_PLACES as u32,
                    ));
                }
                if wait.signalled() {
                    return Ended::Signalled;
                }
            }
            Err(Failure::Rejected(code)) => {
                return Ended::Done(Err(crate::lock_fields::refusal(code)));
            }
            Err(_) => return Ended::Done(Err(EIO)),
        }
    };
    let mut last = Last::Start;
    loop {
        if reply.phase == WaitPhase::Complete {
            #[cfg(feature = "wait-probe")]
            probed(Probe::Complete, wait.key);
            wait.release();
            return Ended::Done(outcome(reply));
        }
        if wait.signalled() {
            return match wait.withdraw() {
                Some(reply) if reply.result == 0 => Ended::Done(Ok(())),
                _ => Ended::Signalled,
            };
        }
        let query = |wait: &Wait| wait.keyed(Method::WaitQuery).and_then(|q| wait.answer(&q));
        let next = match reply.phase {
            WaitPhase::NeedsArm => {
                last = Last::Arm;
                wait.arm()
            }
            WaitPhase::Sleeping if last == Last::Query => {
                // The Query after the Arm found the wait asleep: sleep on
                // the channel, then ask again.
                if wait.sleep() {
                    continue;
                }
                query(&wait)
            }
            WaitPhase::Queued => {
                let _ = sys::yield_now();
                last = Last::Query;
                query(&wait)
            }
            _ => {
                last = Last::Query;
                query(&wait)
            }
        };
        match next {
            Ok(next) => reply = next,
            Err(Failure::Fatal(error)) => {
                wait.withdraw();
                return Ended::Done(Err(error));
            }
            Err(_) => {
                wait.withdraw();
                return Ended::Done(Err(EIO));
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Last {
    Start,
    Arm,
    Query,
}

/// Block until the lock is set, a signal ends the wait, or an error comes.
pub(crate) fn operation(fd: u32, input: Input) -> Result<(), i32> {
    let _outer = OuterRestart::enter();
    loop {
        let saved = crate::signals::swap_mask(u64::MAX);
        let ended = (|| {
            let (description, transport) = crate::shared::with_fd(fd, |files| {
                let description = files.lock_begins(fd).map_err(crate::error)?;
                Ok((description, files.transport()))
            })?;
            let ended = run(transport, description, input, saved);
            let _ = crate::shared::with_files(|files| {
                files.lock_ends();
                Ok(())
            });
            Ok::<_, i32>(ended)
        })();
        crate::signals::swap_mask(saved);
        if crate::signals::pending_unblocked() {
            crate::signals::deliver_now();
        }
        match ended {
            Err(error) => return Err(error),
            Ok(Ended::Done(result)) => return result,
            Ok(Ended::Signalled) => {
                if ending() || crate::threads::cancel::requested() {
                    return Err(EINTR);
                }
            }
        }
    }
}

/// Keeps the caller's NO_RESTART across this operation: a handler without
/// SA_RESTART that runs inside it sets the flag, and the flag ends the wait.
struct OuterRestart(u32);
impl OuterRestart {
    fn enter() -> Self {
        Self(
            crate::threads::own_block()
                .flags
                .fetch_and(!posix_thread::flag::NO_RESTART, Ordering::SeqCst)
                & posix_thread::flag::NO_RESTART,
        )
    }
}
impl Drop for OuterRestart {
    fn drop(&mut self) {
        crate::threads::own_block()
            .flags
            .fetch_or(self.0, Ordering::SeqCst);
    }
}
fn ending() -> bool {
    crate::threads::own_block().flags.load(Ordering::SeqCst) & posix_thread::flag::NO_RESTART != 0
}
