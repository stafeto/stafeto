// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's OpenWF Composition devices over the scene session of the
//! composition service (`proto_comp`; the rules are the crate `wfc`, the C
//! functions `<WF/wfc.h>` in `posix_crt`'s `wfc_c.rs`). The module is behind
//! the feature `wfc`: a statically linked program turns it on, and `libc.so`
//! leaves it off, so its exports and the series 0.6 of the ABI stay as they
//! were.
//!
//! The process's `Display` session is the scene session when init gave it the
//! mark `SCENE_MARK`; a plain session is refused by MANAGE, so
//! `wfcCreateDevice` answers no device (ENODEV) for it. The first device
//! opens the transport: the library's own channel and timer, and SUBSCRIBE on
//! the session with a duplicate of the channel, on which the service sends the
//! scene's bits (COMMITTED, COMPOSED, and EVENTS for the ring of the scene).
//! The last device closes it. Devices are `wfc::Wfc` values in a table of
//! four; each has a lock of its own, which a call holds for its whole length
//! (a `wfcCommit` that waits holds its device's lock and no other's), so every
//! function is thread safe (specification 2.13) and a waiting thread blocks
//! the calls on its own device only. The bits are shared by all devices; a
//! wait looks at them again every 100 milliseconds, so a bit a thread of
//! another device took off the channel is found.
//!
//! `fork`: the child has no device. Its Display session is a clone, which
//! never has the mark, so the service would refuse it anyway; its table, its
//! locks (a parent's thread may have held one) and its handles of the channel
//! and the timer, which name nothing of the child's table, are reset and the
//! handles forgotten, never closed (as the window of G4 and the display
//! device). `exec` closes the channel and the timer and drops every device
//! (`release_for_exec`); the Display session stays with the new image (the
//! scene session moves, plan 5.1), and so does the scene the old image
//! committed, until the new image commits its own.
//!
//! Signals: the lock of a device is a plain futex mutex (no critical section
//! of the layer), so a signal's handler runs while a call waits. A request
//! that comes back INTERRUPTED goes again (the service never saw it). A wait
//! or a pause that is interrupted runs the handler and returns
//! `Kernel(Interrupted)` to the rules, which wait again without counting it,
//! as a call restarted under SA_RESTART; the 16 tries of the rules are for
//! BUSY answers and would-block refusals only. The functions are not
//! async-signal-safe (XSH 2.4.3): calling one from a handler that interrupted
//! another call of the library, or jumping out of a call with `siglongjmp`,
//! is undefined (the device lock stays held).
//!
//! Sleeping: one thread at a time blocks in `receive` on the channel with the
//! library's one timer; any other waiting thread sleeps in steps of 10
//! milliseconds on its own thread's timer and looks at the bits again, so no
//! thread moves or cancels another's timer.

use crate::constants::*;
use crate::threads;
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use posix_sync::{CLOCK_MONOTONIC, futex_wait, futex_wake};
use proto_comp::{COMMITTED_BIT, COMPOSED_BIT, EVENTS_BIT, Method, manage};
use proto_wire::{Status, Writer};
use rt::abi::{Error, MESSAGE_MAX, Rights, Source};
use rt::handle::{Channel, Handle, Outgoing, Timer};
use rt::sys::{self, Received};
use wfc::consts::*;
use wfc::{FORMAT_UNKNOWN, Service, Setup, StreamInfo, Wfc};

/// The most devices a process holds.
pub const MAX_DEVICES: usize = 4;

/// How long a wait sleeps before it looks at the bits and at the service
/// again, and the one frame a pause lasts (at 60 hertz).
const POLL_NS: u64 = 100_000_000;
const FRAME_NS: u64 = 17_000_000;

/// A plain futex mutex. It is no `LayerLock`: its holder is in no critical
/// section, so a signal's handler runs while a call that holds it waits (a
/// critical section would keep the signal pending, and every wait would end
/// at once, interrupted). It is held for a whole call, a wait included, so it
/// serializes the calls on one device; the child of a fork makes it new (the
/// thread of the parent that held it is not there). A handler that jumps out
/// of a call leaves it held: the functions are not async-signal-safe.
struct Lock(AtomicU32);

struct Held<'a>(&'a Lock);

impl Lock {
    const fn new() -> Lock {
        Lock(AtomicU32::new(0))
    }

    fn lock(&self) -> Held<'_> {
        if self
            .0
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.0.swap(2, Ordering::Acquire) != 0 {
                if futex_wait(&self.0, 2, CLOCK_MONOTONIC, None) == Err(EINVAL) {
                    let _ = sys::yield_now();
                }
            }
        }
        Held(self)
    }

    fn reset(&self) {
        self.0.store(0, Ordering::Release);
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if self.0.0.swap(0, Ordering::Release) == 2 {
            futex_wake(&self.0.0, 1);
        }
    }
}

struct Slot {
    lock: Lock,
    /// The device's handle, 0 for a free slot (outside the lock, so a thread
    /// finds its slot without waiting for another device's call).
    handle: AtomicU32,
    wfc: UnsafeCell<Option<Wfc>>,
}
// SAFETY: `wfc` is touched under `lock` (and by `after_fork`).
unsafe impl Sync for Slot {}

impl Slot {
    const fn new() -> Slot {
        Slot {
            lock: Lock::new(),
            handle: AtomicU32::new(0),
            wfc: UnsafeCell::new(None),
        }
    }
}

static SLOTS: [Slot; MAX_DEVICES] = [const { Slot::new() }; MAX_DEVICES];
/// Makes and destroys devices and the transport; never held across a wait for
/// the service's bits.
static REGISTRY: Lock = Lock::new();
/// The devices made, under REGISTRY.
static DEVICES: AtomicU32 = AtomicU32::new(0);
/// The library's own channel and timer (raw handles, 0 for none).
static CHANNEL: AtomicU64 = AtomicU64::new(0);
static TIMER: AtomicU64 = AtomicU64::new(0);
/// The service's bits seen and not yet cleared.
static BITS: AtomicU64 = AtomicU64::new(0);
/// The one screen is claimed by a device.
static SCREEN: AtomicBool = AtomicBool::new(false);
/// A thread waits for a new stream.
static NEXT_WAITING: AtomicBool = AtomicBool::new(false);
/// One thread at a time sleeps in `receive` on the channel (the one timer is
/// its own); the others sleep on their thread's timer and look at the bits
/// again, every `LOOK_NS`.
static SLEEPER: AtomicBool = AtomicBool::new(false);
/// The transport is being closed: waiters leave.
static CLOSING: AtomicBool = AtomicBool::new(false);
/// The bit that wakes the sleeper: outside the service's bits.
const WAKE: u64 = 1 << 32;
/// The step a thread that is not the sleeper looks at the bits again.
const LOOK_NS: u64 = 10_000_000;

/// The numbers of the windows the scene's ring said were made and no
/// `wfcNextStreamSTAFETO` took yet.
const CREATED_MAX: usize = 32;
struct Created(UnsafeCell<([u32; CREATED_MAX], usize, usize)>);
// SAFETY: touched only by the thread that holds NEXT_WAITING (and by the
// closing of the transport, when none waits).
unsafe impl Sync for Created {}
static CREATED: Created = Created(UnsafeCell::new(([0; CREATED_MAX], 0, 0)));

fn level() -> u8 {
    (threads::own_block().base_level.load(Ordering::Relaxed) as u8).max(1)
}

fn channel() -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(CHANNEL.load(Ordering::Acquire)))
}

/// One request with `handles` and its reply; a send that came back
/// INTERRUPTED goes again, with the handles it gave back.
fn call(channel: &Handle<Channel>, request: &[u8], handles: Outgoing) -> Result<sys::Reply, Error> {
    let mut handles = Some(handles);
    loop {
        let Some(sending) = handles.take() else {
            return Err(Error::BadState);
        };
        match sys::send_handles(channel, request, sending) {
            Ok(reply) => return Ok(reply),
            Err(refused) if refused.error == Error::Interrupted => handles = refused.back,
            Err(refused) => return Err(refused.error),
        }
    }
}

fn status_of(reply: &sys::Reply) -> Status {
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    match bytes.get(..4) {
        Some(w) => Status::from_code(u32::from_le_bytes([w[0], w[1], w[2], w[3]])),
        None => Status::BadSize,
    }
}

/// A request on the process's session: its reply, the status as the error.
fn ask(request: &[u8], handles: Outgoing) -> Result<sys::Reply, Status> {
    let session = crate::display::session().ok_or(Status::Kernel(Error::PeerClosed))?;
    let reply =
        call(&Handle::<Channel>::borrowed(session), request, handles).map_err(Status::Kernel)?;
    match status_of(&reply) {
        Status::Ok => Ok(reply),
        status => Err(status),
    }
}

/// What the channel brought: the service's bits are kept; the timer's
/// expiries and anything else are passed over.
fn absorb(got: &Received) {
    if let Received::Notification {
        source: Source::Unlabeled,
        bits,
        ..
    } = got
    {
        BITS.fetch_or(
            bits & (COMMITTED_BIT | COMPOSED_BIT | EVENTS_BIT),
            Ordering::AcqRel,
        );
    }
}

/// Takes what waits on the channel without blocking.
fn drain() -> Result<(), Status> {
    let own = channel();
    loop {
        match sys::try_receive(&own) {
            Ok(got) => absorb(&got),
            Err(Error::WouldBlock) => return Ok(()),
            Err(Error::Interrupted) => {
                crate::signals::deliver_now();
                return Err(Status::Kernel(Error::Interrupted));
            }
            Err(e) => return Err(Status::Kernel(e)),
        }
    }
}

/// Sleeps until something comes or `limit_ns` pass, and takes what the channel
/// has. One thread (the sleeper) blocks in `receive` on the channel with the
/// library's timer; another that waits at the same time sleeps `LOOK_NS` on its
/// thread's timer, so the shared timer is never moved or cancelled by two
/// threads. A signal's handler runs and `Kernel(Interrupted)` comes back.
fn sleep(limit_ns: u64) -> Result<(), Status> {
    if SLEEPER.swap(true, Ordering::AcqRel) {
        let step = limit_ns.min(LOOK_NS);
        let slept = crate::threads::sleep::pause(step as i64);
        return match slept {
            Err(EINTR) => {
                crate::signals::deliver_now();
                Err(Status::Kernel(Error::Interrupted))
            }
            _ => drain(),
        };
    }
    let result = sleep_on_channel(limit_ns);
    SLEEPER.store(false, Ordering::Release);
    result
}

fn sleep_on_channel(limit_ns: u64) -> Result<(), Status> {
    let own = channel();
    let timer = Handle::<Timer>::borrowed(rt::abi::Handle(TIMER.load(Ordering::Acquire)));
    let block = threads::own_block();
    let handled = block.handled.load(Ordering::SeqCst);
    if crate::signals::pending_unblocked() {
        crate::signals::deliver_now();
        return Err(Status::Kernel(Error::Interrupted));
    }
    let until = crate::wait::now().saturating_add(limit_ns);
    sys::timer_set(&timer, until).map_err(Status::Kernel)?;
    let guard = rt::upcall::defer_entries().map_err(Status::Kernel)?;
    if block.handled.load(Ordering::SeqCst) != handled || crate::signals::pending_unblocked() {
        drop(guard);
        let _ = sys::timer_cancel(&timer);
        crate::signals::deliver_now();
        return Err(Status::Kernel(Error::Interrupted));
    }
    let got = sys::receive(&own);
    drop(guard);
    let _ = sys::timer_cancel(&timer);
    match got {
        Ok(got) => {
            absorb(&got);
            Ok(())
        }
        Err(Error::Interrupted) => {
            crate::signals::deliver_now();
            Err(Status::Kernel(Error::Interrupted))
        }
        Err(e) => Err(Status::Kernel(e)),
    }
}

/// A DESCRIBE, to find out whether the service is still there: only a
/// service that ended (PEER_CLOSED) is an error.
fn alive() -> Result<(), Status> {
    match ask(&Method::Describe.header().bytes(), Outgoing::new()) {
        Err(Status::Kernel(Error::PeerClosed)) => Err(Status::Kernel(Error::PeerClosed)),
        _ => Ok(()),
    }
}

/// The service the rules talk to: the process's scene session and the
/// library's channel of bits.
pub struct Transport;

impl Service for Transport {
    fn scene_commit(&mut self, commit: &proto_comp::SceneCommit) -> Result<(), Status> {
        let mut request = Writer::new();
        commit.write(&mut request)?;
        ask(request.as_bytes(), Outgoing::new()).map(|_| ())
    }

    fn scene_compose(&mut self, flags: u32) -> Result<(), Status> {
        let mut request = Writer::new();
        proto_comp::write_scene_compose(flags, &mut request)?;
        ask(request.as_bytes(), Outgoing::new()).map(|_| ())
    }

    fn wait(&mut self, bit: u64) -> Result<(), Status> {
        let mut polls = 0;
        loop {
            drain()?;
            if BITS.load(Ordering::Acquire) & bit != 0 {
                return Ok(());
            }
            sleep(POLL_NS)?;
            polls += 1;
            if polls % 5 == 0 {
                alive()?;
            }
        }
    }

    fn clear(&mut self, bit: u64) {
        BITS.fetch_and(!bit, Ordering::AcqRel);
    }

    fn pause(&mut self) -> Result<(), Status> {
        drain()?;
        sleep(FRAME_NS)?;
        alive()
    }

    fn claim_screen(&mut self) -> bool {
        !SCREEN.swap(true, Ordering::AcqRel)
    }

    fn release_screen(&mut self) {
        SCREEN.store(false, Ordering::Release);
    }
}

/// Runs `f` on the device `dev` under its lock; None when there is none.
pub fn with<R>(dev: u32, f: impl FnOnce(&mut Wfc, &mut Transport) -> R) -> Option<R> {
    if dev == 0 {
        return None;
    }
    let slot = SLOTS
        .iter()
        .find(|s| s.handle.load(Ordering::Acquire) == dev)?;
    let _guard = slot.lock.lock();
    if slot.handle.load(Ordering::Acquire) != dev {
        return None;
    }
    // SAFETY: the lock gives this borrow alone.
    let wfc = unsafe { &mut *slot.wfc.get() }.as_mut()?;
    Some(f(wfc, &mut Transport))
}

/// Whether a device can be made at all: the process has a `Display` session.
pub fn available() -> bool {
    crate::display::session().is_some()
}

/// `wfcCreateDevice`: the device's handle, or the errno it was not made for
/// (ENODEV: no session or not the scene's; EBUSY: the screen of the first
/// revision is open, a manager has the service or the table is full).
pub fn create() -> Result<u32, i32> {
    if crate::display::session().is_none() {
        return Err(ENODEV);
    }
    if crate::display::screen_open() {
        return Err(EBUSY);
    }
    let _registry = REGISTRY.lock();
    let slot = SLOTS
        .iter()
        .find(|s| s.handle.load(Ordering::Acquire) == 0)
        .ok_or(EBUSY)?;
    let mut setup = Setup::VIRTIO;
    if DEVICES.load(Ordering::Acquire) == 0 {
        open_transport(&mut setup)?;
    }
    let wfc = Wfc::create_device(0, &[], setup).ok_or(ENOMEM);
    let wfc = match wfc {
        Ok(w) => w,
        Err(e) => {
            if DEVICES.load(Ordering::Acquire) == 0 {
                close_transport_now();
            }
            return Err(e);
        }
    };
    let handle = wfc.device();
    {
        let _guard = slot.lock.lock();
        // SAFETY: the lock gives this borrow alone.
        unsafe { *slot.wfc.get() = Some(wfc) };
        slot.handle.store(handle, Ordering::Release);
    }
    DEVICES.fetch_add(1, Ordering::AcqRel);
    Ok(handle)
}

/// The channel, the timer and SUBSCRIBE on the session; the screen's size.
fn open_transport(setup: &mut Setup) -> Result<(), i32> {
    BITS.store(0, Ordering::Release);
    let own = sys::channel_create_wait(level()).map_err(|_| ENOMEM)?;
    let timer = sys::timer_create(&own, level()).map_err(|_| ENOMEM)?;
    let notify =
        sys::handle_duplicate(&own, Rights::NOTIFY | Rights::TRANSFER).map_err(|_| ENOMEM)?;
    CHANNEL.store(own.into_raw().0, Ordering::Release);
    TIMER.store(timer.into_raw().0, Ordering::Release);
    let mut request = Writer::new();
    let made = proto_comp::write_manage(manage::SUBSCRIBE, 0, 0, 0, &mut request)
        .map_err(|_| EINVAL)
        .and_then(|()| {
            ask(request.as_bytes(), [notify.erase()].into()).map_err(|s| match s {
                // A plain session is no scene's; a manager holds the service.
                s if s == proto_comp::code(proto_comp::BUSY) => EBUSY,
                Status::Kernel(Error::LimitReached | Error::NoMemory) => ENOMEM,
                _ => ENODEV,
            })
        });
    if let Err(e) = made {
        // No other thread has the transport yet.
        close_transport_now();
        return Err(e);
    }
    if let Ok(reply) = ask(&Method::Describe.header().bytes(), Outgoing::new()) {
        let mut buffer = [0; MESSAGE_MAX];
        if let Ok(d) = proto_comp::Description::read(reply.bytes(&mut buffer))
            && d.width > 0
            && d.height > 0
        {
            setup.width = d.width;
            setup.height = d.height;
        }
    }
    Ok(())
}

/// Closes the channel and the timer and forgets the bits and the streams,
/// when no thread uses them: a transport that failed to open, or `exec`.
fn close_transport_now() {
    for (cell, is_timer) in [(&TIMER, true), (&CHANNEL, false)] {
        let raw = cell.swap(0, Ordering::AcqRel);
        if raw == 0 {
            continue;
        }
        if is_timer {
            drop(Handle::<Timer>::from_raw(rt::abi::Handle(raw)));
        } else {
            drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
        }
    }
    BITS.store(0, Ordering::Release);
    SCREEN.store(false, Ordering::Release);
    // SAFETY: the callers say no thread waits for a stream.
    unsafe { *CREATED.0.get() = ([0; CREATED_MAX], 0, 0) };
}

/// The last device is gone: the threads that still use the channel and the
/// timer (a `wfcNextStreamSTAFETO` that waits has no device lock, and the
/// thread that sleeps in `receive`) are woken and leave, and then the
/// transport closes. They find the device gone and return. The wait is
/// bounded (3 seconds) so that a thread that does not leave cannot hold the
/// destroy.
fn close_transport() {
    CLOSING.store(true, Ordering::Release);
    if CHANNEL.load(Ordering::Acquire) != 0 {
        let _ = sys::notify(&channel(), WAKE);
    }
    for _ in 0..3000 {
        if !NEXT_WAITING.load(Ordering::Acquire) && !SLEEPER.load(Ordering::Acquire) {
            break;
        }
        let _ = crate::threads::sleep::pause(1_000_000);
    }
    close_transport_now();
    CLOSING.store(false, Ordering::Release);
}

/// Whether `dev` is a device of the table.
fn exists(dev: u32) -> bool {
    dev != 0
        && SLOTS
            .iter()
            .any(|s| s.handle.load(Ordering::Acquire) == dev)
}

/// `wfcDestroyDevice`: the result of the call; BAD_DEVICE for a handle that
/// is no device. The last device closes the transport.
pub fn destroy(dev: u32) -> i32 {
    if dev == 0 {
        return ERROR_BAD_DEVICE;
    }
    let Some(slot) = SLOTS
        .iter()
        .find(|s| s.handle.load(Ordering::Acquire) == dev)
    else {
        return ERROR_BAD_DEVICE;
    };
    let result = {
        let _guard = slot.lock.lock();
        if slot.handle.load(Ordering::Acquire) != dev {
            return ERROR_BAD_DEVICE;
        }
        // SAFETY: the lock gives this borrow alone.
        let cell = unsafe { &mut *slot.wfc.get() };
        let result = cell
            .as_mut()
            .map_or(ERROR_BAD_DEVICE, |w| w.destroy_device(dev, &mut Transport));
        if result == ERROR_NONE {
            *cell = None;
            slot.handle.store(0, Ordering::Release);
        }
        result
    };
    if result == ERROR_NONE {
        let _registry = REGISTRY.lock();
        if DEVICES.fetch_sub(1, Ordering::AcqRel) == 1 {
            close_transport();
        }
    }
    result
}

/// What the service knows of the stream `id` (a window): its size from LIST.
/// The format is not in LIST, so it is `FORMAT_UNKNOWN` and the service
/// checks the kind of the window at the commit. None for a window that is
/// not there, a transport that is not open or a service that refuses.
pub fn stream_info(id: u32) -> Option<StreamInfo> {
    if CHANNEL.load(Ordering::Acquire) == 0 {
        return None;
    }
    let mut request = Writer::new();
    proto_comp::write_manage(manage::LIST, 0, 0, 0, &mut request).ok()?;
    let reply = ask(request.as_bytes(), Outgoing::new()).ok()?;
    let mut buffer = [0; MESSAGE_MAX];
    let mut found = None;
    proto_comp::read_list(reply.bytes(&mut buffer), |r| {
        if r.id == id {
            found = Some(StreamInfo {
                id,
                width: r.w,
                height: r.h,
                format: FORMAT_UNKNOWN,
            });
        }
    })
    .ok()?;
    found
}

fn pop_created() -> Option<u32> {
    // SAFETY: the caller holds NEXT_WAITING.
    let (ring, head, len) = unsafe { &mut *CREATED.0.get() };
    if *len == 0 {
        return None;
    }
    let id = ring[*head];
    *head = (*head + 1) % CREATED_MAX;
    *len -= 1;
    Some(id)
}

fn push_created(id: u32) {
    // SAFETY: the caller holds NEXT_WAITING.
    let (ring, head, len) = unsafe { &mut *CREATED.0.get() };
    if *len < CREATED_MAX {
        ring[(*head + *len) % CREATED_MAX] = id;
        *len += 1;
    }
}

/// The ring of the scene read once: the numbers of windows made go to
/// CREATED, the other events (the pointer's among them) are dropped.
fn read_ring() -> Result<(), Status> {
    BITS.fetch_and(!EVENTS_BIT, Ordering::AcqRel);
    let reply = ask(&Method::Events.header().bytes(), Outgoing::new())?;
    let mut buffer = [0; MESSAGE_MAX];
    proto_comp::read_events(reply.bytes(&mut buffer), |event| {
        if event.kind == proto_comp::CREATE {
            push_created(event.value as u32);
        }
    })?;
    Ok(())
}

/// The counters the probe of the demo reads from the service: the frames shown,
/// of which direct, the late ones, the starts of a period that took nothing, the
/// frames the device failed and the periods the cap put bands off (STATS), and
/// the frames shown straight from a window's buffer and the bands put together
/// (DESCRIBE). None when the service does not answer.
pub fn counters() -> Option<[u32; 8]> {
    let reply = ask(&Method::Describe.header().bytes(), Outgoing::new()).ok()?;
    let mut buffer = [0; MESSAGE_MAX];
    let d = proto_comp::Description::read(reply.bytes(&mut buffer)).ok()?;
    let mut request = Writer::new();
    proto_comp::write_stats(0, &mut request).ok()?;
    let reply = ask(request.as_bytes(), Outgoing::new()).ok()?;
    let mut buffer = [0; MESSAGE_MAX];
    let s = proto_comp::StatsReply::read(reply.bytes(&mut buffer))
        .ok()?
        .stats;
    Some([
        s.frames, s.direct, s.late, s.skipped, s.failed, s.capped, d.bypassed, d.bands,
    ])
}

/// `wfcNextStreamSTAFETO`: 1 and the window's number when a window was made
/// (now or within `timeout_ms`), 0 when the time ran out or a signal ended
/// the wait, -1 when the device is gone or another thread waits (the error
/// is the device's).
pub fn next_stream(dev: u32, timeout_ms: i32, out: &mut u32) -> i32 {
    if with(dev, |w, _| w.stream_allowed(dev)) != Some(true) {
        return -1;
    }
    if NEXT_WAITING.swap(true, Ordering::AcqRel) {
        with(dev, |w, _| w.refuse(dev, ERROR_BUSY));
        return -1;
    }
    let result = next_stream_waiting(dev, timeout_ms, out);
    NEXT_WAITING.store(false, Ordering::Release);
    result
}

fn next_stream_waiting(dev: u32, timeout_ms: i32, out: &mut u32) -> i32 {
    let until = crate::wait::now().saturating_add(timeout_ms.max(0) as u64 * 1_000_000);
    let mut polls = 0;
    loop {
        if CLOSING.load(Ordering::Acquire) || !exists(dev) {
            return -1;
        }
        if let Some(id) = pop_created() {
            *out = id;
            return 1;
        }
        if let Err(s) = read_ring() {
            with(dev, |w, _| w.refuse(dev, wfc::translate(s)));
            return -1;
        }
        if let Some(id) = pop_created() {
            *out = id;
            return 1;
        }
        let now = crate::wait::now();
        if now >= until {
            return 0;
        }
        match drain() {
            Ok(()) => {}
            Err(_) => return 0,
        }
        if BITS.load(Ordering::Acquire) & EVENTS_BIT != 0 {
            continue;
        }
        match sleep((until - now).min(POLL_NS)) {
            Ok(()) => {}
            // A signal ends the wait.
            Err(Status::Kernel(Error::Interrupted)) => return 0,
            Err(s) => {
                with(dev, |w, _| w.refuse(dev, wfc::translate(s)));
                return -1;
            }
        }
        polls += 1;
        if polls % 5 == 0
            && let Err(s) = alive()
        {
            with(dev, |w, _| w.refuse(dev, wfc::translate(s)));
            return -1;
        }
    }
}

/// A forked child has no device: its table, its locks and its handles are
/// the parent's and are reset or forgotten, never closed.
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork() {
    for cell in [&CHANNEL, &TIMER] {
        cell.store(0, Ordering::Release);
    }
    BITS.store(0, Ordering::Release);
    SCREEN.store(false, Ordering::Release);
    NEXT_WAITING.store(false, Ordering::Release);
    DEVICES.store(0, Ordering::Release);
    SLEEPER.store(false, Ordering::Release);
    CLOSING.store(false, Ordering::Release);
    REGISTRY.reset();
    // SAFETY: the child's only thread.
    unsafe {
        for slot in &SLOTS {
            slot.lock.reset();
            slot.handle.store(0, Ordering::Release);
            *slot.wfc.get() = None;
        }
        *CREATED.0.get() = ([0; CREATED_MAX], 0, 0);
    }
}

/// `exec` takes the devices back with the old image: the channel and the
/// timer close, the rules' state goes. The session stays, and so does the
/// scene the service has.
pub(crate) fn release_for_exec() {
    if DEVICES.swap(0, Ordering::AcqRel) == 0 && CHANNEL.load(Ordering::Acquire) == 0 {
        return;
    }
    for slot in &SLOTS {
        slot.handle.store(0, Ordering::Release);
        // SAFETY: exec has stopped the other threads.
        unsafe { *slot.wfc.get() = None };
    }
    close_transport_now();
}
