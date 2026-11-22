// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's OpenWF Display device over the display service
//! (`proto_gpu` revision 3; the rules are the crate `wfd`, the C functions
//! `<WF/wfd.h>` in `posix_crt`'s `wfd_c.rs`). The module is behind the feature
//! `wfd`: a statically linked program turns it on, and `libc.so` leaves it
//! off, so its exports and the series 0.6 of the ABI stay as they were.
//!
//! The device is the screen's owner. `create` takes the process's `Display`
//! session (the driver's own in an image with no composition service), makes
//! OPEN, gives the driver the library's own channel (SUBSCRIBE: its bits are
//! the frame's `FRAME_SHOWN` and `FRAME_FAILED`), asks for the pipelines
//! (PIPELINES) and builds the rules' device from the answers. What the
//! program draws in lives in three sources of the driver, which the process
//! maps as pieces of its map: the compositing target (the buffer OPEN gives,
//! the display piece), the pool and the cursor picture (SOURCE; pieces of the
//! kind `posix_map::Kind::Source`). A commit is one LAYERS request, which
//! the driver answers at once; the frame's bit completes the bindings.
//!
//! A forked child has no device (its state is reset, the handles are the
//! parent's alone); `exec` and `wfdDestroyDevice` give the screen back.

use crate::constants::*;
use crate::plain_lock::Lock;
use crate::threads;
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use posix_sync::LayerLock;
use proto_gpu::{Method, Pipelines, SourceInfo};
use proto_wire::{Status, Writer};
use rt::abi::{Error, MESSAGE_MAX, Rights, Source};
use rt::handle::{Channel, Handle, Memory, Outgoing, Timer};
use rt::sys::{self, Received};
use wfd::consts::*;
use wfd::{Commit, Poll, Setup, Wfd};

const CLOSED: u32 = 0;
const OPENING: u32 = 1;
const OPEN: u32 = 2;

/// The longest OPEN is asked again after CLEARING, and its pause.
const CLEARING_TRIES: u32 = 50;
const CLEARING_PAUSE_NS: i64 = 10_000_000;
/// The longest a commit waits for the frame the last one made.
const FRAME_WAIT_NS: u64 = 10_000_000_000;
const PAGE: u64 = 4096;
/// The refresh rate of the one mode: the device tells none (the image's
/// setting says, and on QEMU's virtio-gpu it is 60 hertz).
const REFRESH_HZ: u32 = 60;
/// The bit the library sends its own channel to wake a wait that sleeps in
/// another thread: outside the driver's bits.
const WAKE: u64 = 1 << 32;

static STATE: AtomicU32 = AtomicU32::new(CLOSED);
/// The owner's session, the library's own channel and its timer (raw
/// handles, 0 for none).
static OWNER: AtomicU64 = AtomicU64::new(0);
static CHANNEL: AtomicU64 = AtomicU64::new(0);
static TIMER: AtomicU64 = AtomicU64::new(0);
/// OPEN's flags: the client cleans the cache before it shows.
static FLAGS: AtomicU32 = AtomicU32::new(0);
/// The device mapped the display piece itself (a first-revision screen of the
/// process maps the same kind of piece, which the device never takes out).
static MAPPED: AtomicBool = AtomicBool::new(false);
/// A thread waits for events.
static WAITING: AtomicBool = AtomicBool::new(false);

/// The rules' device, under `LIB_LOCK`.
struct Lib(UnsafeCell<Option<Wfd>>);
// SAFETY: touched only under LIB_LOCK (and by `after_fork`, in the child's
// only thread).
unsafe impl Sync for Lib {}
static LIB: Lib = Lib(UnsafeCell::new(None));
static LIB_LOCK: LayerLock = LayerLock::new();
/// One thread at a time commits or destroys the device. A plain futex mutex
/// (no critical section of the layer): a commit holds it across the wait for
/// the last frame, and a critical section would keep a signal pending, so the
/// wait would end at once.
static COMMIT_LOCK: Lock = Lock::new();
/// One thread at a time makes a source of the driver.
static STREAM_LOCK: LayerLock = LayerLock::new();

/// A stream the driver makes sources of, as `struct stafeto_wfd_stream` of
/// `<WF/wfdext_stafeto.h>` has it.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Stream {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
    pub reserved: u32,
    pub pixels: usize,
}

/// The streams of the driver: the target and the sources the map holds as pieces.
const STREAM_COUNT: usize = 3;
const _: () = assert!(STREAM_COUNT - 1 == crate::allocation::SOURCE_PIECES);

const NO_STREAM: Stream = Stream {
    id: 0,
    width: 0,
    height: 0,
    stride: 0,
    format: 0,
    reserved: 0,
    pixels: 0,
};

struct Streams(UnsafeCell<[Stream; STREAM_COUNT]>);
// SAFETY: a descriptor is written once under STREAM_LOCK before its address
// is given out, and read after that.
unsafe impl Sync for Streams {}
static STREAMS: Streams = Streams(UnsafeCell::new([NO_STREAM; STREAM_COUNT]));

fn level() -> u8 {
    (threads::own_block().base_level.load(Ordering::Relaxed) as u8).max(1)
}

fn channel() -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(CHANNEL.load(Ordering::Acquire)))
}

fn owner() -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(OWNER.load(Ordering::Acquire)))
}

/// Runs `f` on the device under its lock; None when the process has none.
pub fn with<R>(f: impl FnOnce(&mut Wfd) -> R) -> Option<R> {
    let _guard = LIB_LOCK.lock();
    // SAFETY: the lock gives this borrow alone.
    let lib = unsafe { &mut *LIB.0.get() };
    lib.as_mut().map(f)
}

/// The handle of the device, 0 for none.
pub fn device() -> u32 {
    with(|w| w.device()).unwrap_or(0)
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

/// The status at the head of a reply.
fn status_of(reply: &sys::Reply) -> Status {
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    match bytes.get(..4) {
        Some(w) => Status::from_code(u32::from_le_bytes([w[0], w[1], w[2], w[3]])),
        None => Status::BadSize,
    }
}

/// The error of the specification for a refusal of the driver on a request
/// that was not refused for its form: the screen went away (REVOKED, a
/// service that ended) is BAD_DEVICE, a device that is at work BUSY, the
/// rest a configuration it cannot take.
fn driver_error(status: Status) -> i32 {
    use proto_gpu::{BUSY, NO_DEVICE, REVOKED};
    match status {
        Status::Kernel(Error::PeerClosed) => ERROR_BAD_DEVICE,
        Status::Kernel(Error::LimitReached) => ERROR_BUSY,
        s if s == proto_gpu::code(REVOKED) || s == proto_gpu::code(NO_DEVICE) => ERROR_BAD_DEVICE,
        s if s == proto_gpu::code(BUSY) => ERROR_BUSY,
        _ => ERROR_NOT_SUPPORTED,
    }
}

/// What took a device's making down: the screen could not be had.
fn open_errno(status: Status) -> i32 {
    use proto_gpu::{BUSY, CLEARING, NO_DEVICE};
    match status {
        s if s == proto_gpu::code(BUSY) || s == proto_gpu::code(CLEARING) => EBUSY,
        s if s == proto_gpu::code(NO_DEVICE) => ENODEV,
        Status::Kernel(Error::PeerClosed) => ENODEV,
        _ => EIO,
    }
}

/// Whether the process's `Display` session leads to the composition service,
/// which answers DESCRIBE (the driver does not): the screen is the service's
/// then and no device can take it.
fn composition_present(session: &Handle<Channel>) -> bool {
    let Ok(reply) = call(
        session,
        &proto_comp::Method::Describe.header().bytes(),
        Outgoing::new(),
    ) else {
        return false;
    };
    let mut buffer = [0; MESSAGE_MAX];
    proto_comp::Description::read(reply.bytes(&mut buffer)).is_ok()
}

/// Whether a device can be made: the process has a `Display` session and it
/// leads to the driver (the composition service answers DESCRIBE and refuses).
pub fn available() -> bool {
    match crate::display::session() {
        Some(session) => !composition_present(&Handle::<Channel>::borrowed(session)),
        None => false,
    }
}

/// `wfdCreateDevice`: the device's handle, or the errno it was not made for.
/// A screen of the first revision that the process has open (EBUSY) and the
/// composition service (ENODEV) refuse it before any OPEN.
pub fn create() -> Result<u32, i32> {
    let session = crate::display::session().ok_or(ENODEV)?;
    if crate::display::screen_open() {
        return Err(EBUSY);
    }
    if composition_present(&Handle::<Channel>::borrowed(session)) {
        return Err(ENODEV);
    }
    if STATE
        .compare_exchange(CLOSED, OPENING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(EBUSY);
    }
    let result = make(&Handle::<Channel>::borrowed(session));
    if result.is_err() {
        release();
    }
    STATE.store(
        if result.is_ok() { OPEN } else { CLOSED },
        Ordering::Release,
    );
    result
}

fn make(display: &Handle<Channel>) -> Result<u32, i32> {
    use proto_gpu::{CLEARING, FORMAT_XRGB8888, NO_INPUT, Screen};
    WAITING.store(false, Ordering::Release);
    let own = sys::channel_create_wait(level()).map_err(|_| ENOMEM)?;
    let timer = sys::timer_create(&own, level()).map_err(|_| ENOMEM)?;
    CHANNEL.store(own.into_raw().0, Ordering::Release);
    TIMER.store(timer.into_raw().0, Ordering::Release);

    // OPEN, again while the driver is clearing the last owner's buffer.
    let request = Method::Open.header().bytes();
    let mut tries = 0;
    let mut reply = loop {
        let reply = call(display, &request, Outgoing::new()).map_err(|_| ENODEV)?;
        let status = status_of(&reply);
        if status == Status::Ok || status == proto_gpu::code(NO_INPUT) {
            break reply;
        }
        if status == proto_gpu::code(CLEARING) && tries < CLEARING_TRIES {
            tries += 1;
            crate::threads::sleep::pause(CLEARING_PAUSE_NS)?;
            continue;
        }
        return Err(open_errno(status));
    };
    let mut buffer = [0; MESSAGE_MAX];
    let (_, screen) = Screen::read(reply.bytes(&mut buffer)).map_err(|_| EIO)?;
    let memory = reply.handles.take::<Memory>(0).map_err(|_| EIO)?;
    let session = reply.handles.take::<Channel>(1).map_err(|_| EIO)?;
    // The focus session, if the driver had one, is of no use here.
    drop(reply);
    if screen.format != FORMAT_XRGB8888 || !screen.fits() || screen.width == 0 || screen.height == 0
    {
        return Err(EIO);
    }
    OWNER.store(session.into_raw().0, Ordering::Release);
    FLAGS.store(screen.flags, Ordering::Release);

    // The target is the display piece of the map.
    let bytes = u64::from(screen.stride) * u64::from(screen.height);
    let pixels = crate::display::map_buffer(memory, bytes.div_ceil(PAGE) as usize)?;
    MAPPED.store(true, Ordering::Release);
    // SAFETY: no other thread knows the device yet (STATE is OPENING).
    unsafe {
        (*STREAMS.0.get())[0] = Stream {
            id: proto_gpu::SOURCE_TARGET,
            width: screen.width,
            height: screen.height,
            stride: screen.stride,
            format: screen.format,
            reserved: 0,
            pixels,
        };
    }

    // The driver tells the frames on the library's own channel.
    let notify =
        sys::handle_duplicate(&channel(), Rights::NOTIFY | Rights::TRANSFER).map_err(|_| ENOMEM)?;
    let reply = call(
        &owner(),
        &Method::Subscribe.header().bytes(),
        [notify.erase()].into(),
    )
    .map_err(|_| ENODEV)?;
    if status_of(&reply) != Status::Ok {
        return Err(EIO);
    }

    // The hardware the driver has.
    let mut request = Writer::new();
    Pipelines::write_request(&mut request).map_err(|_| EIO)?;
    let reply = call(&owner(), request.as_bytes(), Outgoing::new()).map_err(|_| ENODEV)?;
    let mut buffer = [0; MESSAGE_MAX];
    let pipelines = Pipelines::read(reply.bytes(&mut buffer)).map_err(|_| EIO)?;
    let setup = Setup {
        width: screen.width,
        height: screen.height,
        refresh_hz: REFRESH_HZ,
        pipelines,
        sources: SourceInfo::VIRTIO,
    };
    let _guard = LIB_LOCK.lock();
    // SAFETY: the lock gives this borrow alone.
    let lib = unsafe { &mut *LIB.0.get() };
    let made = lib.insert(Wfd::new(setup));
    Ok(made.device())
}

/// The stream of `kind` (0 the target, 1 the pool, 2 the cursor picture) for
/// the device `dev`, made on the first call: its address, null for a device
/// that is none or a source the driver does not give. The descriptor stays
/// until the device is destroyed.
pub fn stream(dev: u32, kind: i32) -> Option<&'static Stream> {
    if with(|w| w.device()) != Some(dev) || !(0..=2).contains(&kind) {
        return None;
    }
    let _make = STREAM_LOCK.lock();
    let at = kind as usize;
    // SAFETY: written under STREAM_LOCK, which this holds.
    let descs = unsafe { &mut *STREAMS.0.get() };
    if descs[at].id == 0 {
        let info = ask_source(kind as u32).ok()?;
        descs[at] = info;
        with(|w| w.make_available(info.id));
    }
    Some(&descs[at])
}

/// SOURCE for `kind` (1 pool, 2 cursor... the numbers of the stream kinds
/// 1 and 2 are the driver's own): the source mapped as a piece of the map.
fn ask_source(kind: u32) -> Result<Stream, i32> {
    let mut request = Writer::new();
    SourceInfo::write_request(kind, &mut request).map_err(|_| EINVAL)?;
    let mut reply = call(&owner(), request.as_bytes(), Outgoing::new()).map_err(|_| ENODEV)?;
    let mut buffer = [0; MESSAGE_MAX];
    let info = SourceInfo::read(reply.bytes(&mut buffer)).map_err(|_| EIO)?;
    let memory = reply.handles.take::<Memory>(0).map_err(|_| EIO)?;
    let bytes = u64::from(info.stride) * u64::from(info.height);
    let pixels =
        crate::allocation::heap(|state| state.map_source(memory, bytes.div_ceil(PAGE) as usize))?;
    Ok(Stream {
        id: info.id,
        width: info.width,
        height: info.height,
        stride: info.stride,
        format: info.format,
        reserved: 0,
        pixels,
    })
}

/// The id of the driver's source a `stream` descriptor names, 0 for a pointer
/// that is none of the three.
pub fn stream_id(stream: *const Stream) -> u32 {
    // SAFETY: only the address is compared.
    let descs = unsafe { &*STREAMS.0.get() };
    descs
        .iter()
        .find(|d| core::ptr::eq(*d, stream) && d.id != 0)
        .map_or(0, |d| d.id)
}

/// What the channel brought: the frame's bits complete the bindings of the
/// commit that waits; the timer's expiry, the wake and anything else are
/// passed over. Whether a bit of the frame came.
fn absorb(got: &Received) -> bool {
    if let Received::Notification {
        source: Source::Unlabeled,
        bits,
        ..
    } = got
        && bits & (proto_gpu::FRAME_SHOWN | proto_gpu::FRAME_FAILED) != 0
    {
        with(|w| w.frame_done());
        return true;
    }
    false
}

/// Takes what waits on the channel without blocking.
fn drain() {
    let own = channel();
    while let Ok(got) = sys::try_receive(&own) {
        absorb(&got);
    }
}

/// How a wait ended.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    Timeout,
    Signal,
    Failed,
}

/// Waits on the channel until `ready` says so or `until` (a time of
/// `wait::now`) passes: the wait of `window::wait`, a try without waiting,
/// the signals, the entries deferred, a receive with a timer for the bound.
fn block_until(until: u64, ready: impl Fn() -> bool) -> Result<(), Ended> {
    let own = channel();
    let timer = Handle::<Timer>::borrowed(rt::abi::Handle(TIMER.load(Ordering::Acquire)));
    let block = threads::own_block();
    loop {
        loop {
            match sys::try_receive(&own) {
                Ok(got) => {
                    absorb(&got);
                }
                Err(Error::WouldBlock) => break,
                Err(Error::Interrupted) => {
                    crate::signals::deliver_now();
                    return Err(Ended::Signal);
                }
                Err(_) => return Err(Ended::Failed),
            }
        }
        if ready() {
            return Ok(());
        }
        if crate::wait::now() >= until {
            return Err(Ended::Timeout);
        }
        let handled = block.handled.load(Ordering::SeqCst);
        if crate::signals::pending_unblocked() {
            crate::signals::deliver_now();
            return Err(Ended::Signal);
        }
        sys::timer_set(&timer, until).map_err(|_| Ended::Failed)?;
        let guard = rt::upcall::defer_entries().map_err(|_| Ended::Failed)?;
        if block.handled.load(Ordering::SeqCst) != handled || crate::signals::pending_unblocked() {
            drop(guard);
            let _ = sys::timer_cancel(&timer);
            crate::signals::deliver_now();
            return Err(Ended::Signal);
        }
        let got = sys::receive(&own);
        drop(guard);
        match got {
            Ok(got) => {
                absorb(&got);
                let _ = sys::timer_cancel(&timer);
            }
            Err(Error::Interrupted) => {
                let _ = sys::timer_cancel(&timer);
                crate::signals::deliver_now();
                return Err(Ended::Signal);
            }
            Err(_) => return Err(Ended::Failed),
        }
    }
}

/// Runs `wait` again each time a signal ended it (its handler has run by
/// then), as a call restarted under SA_RESTART. The wait's own bound ends the
/// loop.
fn wait_restarting(mut wait: impl FnMut() -> Result<(), Ended>) -> Result<(), Ended> {
    loop {
        match wait() {
            Err(Ended::Signal) => {}
            other => return other,
        }
    }
}

/// `wfdDeviceCommit`: the rules decide what to ask the driver, the driver is
/// asked, the rules are told how it went.
pub fn commit(dev: u32, kind: i32, handle: u32) {
    let _commit = COMMIT_LOCK.lock();
    let Some(Some(plan)) = with(|w| w.commit(dev, kind, handle)) else {
        return;
    };
    let result = send(&plan);
    with(|w| w.finish_commit(&plan, result));
}

fn send(plan: &Commit) -> Result<(), i32> {
    let Some(layers) = plan.layers else {
        return Ok(());
    };
    if STATE.load(Ordering::Acquire) != OPEN {
        return Err(ERROR_BAD_DEVICE);
    }
    if plan.frame {
        // The driver takes one frame's work at a time: wait for the last
        // one's bit (the rules know whether one is out).
        drain();
        let until = crate::wait::now().saturating_add(FRAME_WAIT_NS);
        let ready = || with(|w| !w.frame_pending()).unwrap_or(true);
        wait_restarting(|| block_until(until, ready)).map_err(|_| ERROR_BUSY)?;
    }
    if FLAGS.load(Ordering::Acquire) & proto_gpu::CLEAN_BEFORE_FLUSH != 0 {
        clean(&layers);
    }
    let mut request = Writer::new();
    layers
        .write(&mut request)
        .map_err(|_| ERROR_NOT_SUPPORTED)?;
    let reply = call(&owner(), request.as_bytes(), Outgoing::new()).map_err(|e| {
        if e == Error::PeerClosed {
            ERROR_BAD_DEVICE
        } else {
            ERROR_BUSY
        }
    })?;
    match status_of(&reply) {
        Status::Ok => Ok(()),
        status => Err(driver_error(status)),
    }
}

/// The lines of the changed areas go to the device through the cache of the
/// processor: written back before the driver reads them.
fn clean(layers: &proto_gpu::Layers) {
    // SAFETY: read only after the device is open.
    let descs = unsafe { &*STREAMS.0.get() };
    for row in layers.rows() {
        let (Some(area), Some(d)) = (
            row.area(),
            descs.iter().find(|d| d.id == row.source && d.id != 0),
        ) else {
            continue;
        };
        for y in area.y..area.y + area.h {
            let at = d.pixels + y as usize * d.stride as usize + area.x as usize * 4;
            rt::dma::clean(at, area.w as usize * 4);
        }
    }
}

/// `wfdDeviceEventWait`: the type of the event, `EVENT_NONE` when the time
/// ran out or a signal ended the wait, `EVENT_DESTROYED` when the container
/// or the device went, `EVENT_INVALID` for a failure the rules stored.
pub fn event_wait(dev: u32, event: u32, timeout_ns: u64) -> i32 {
    if with(|w| w.begin_wait(dev, event)) != Some(true) {
        return EVENT_INVALID;
    }
    if WAITING.swap(true, Ordering::AcqRel) {
        with(|w| {
            w.end_wait(event);
        });
        return EVENT_NONE;
    }
    let until = crate::wait::now().saturating_add(timeout_ns);
    let kind = loop {
        match with(|w| w.event_poll(event)) {
            None | Some(Poll::Gone) => break EVENT_DESTROYED,
            Some(Poll::Event(kind)) => break kind,
            Some(Poll::Empty) => {}
        }
        if timeout_ns == 0 {
            break EVENT_NONE;
        }
        let ready = || with(|w| w.event_ready(event)).unwrap_or(true);
        match block_until(until, ready) {
            Ok(()) => {}
            Err(_) => {
                with(|w| w.event_timed_out(event));
                break EVENT_NONE;
            }
        }
    };
    WAITING.store(false, Ordering::Release);
    with(|w| w.end_wait(event));
    kind
}

/// Wakes a wait that sleeps in another thread, after a container was
/// destroyed.
pub fn wake() {
    if CHANNEL.load(Ordering::Acquire) != 0 {
        let _ = sys::notify(&channel(), WAKE);
    }
}

/// `wfdDestroyDevice`: the screen goes back and the device's resources go.
pub fn destroy(dev: u32) {
    let _commit = COMMIT_LOCK.lock();
    if device() != dev
        || STATE
            .compare_exchange(OPEN, OPENING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return;
    }
    // The owner's CLOSE gives the screen back at once.
    let _ = call(&owner(), &Method::Close.header().bytes(), Outgoing::new());
    release();
    STATE.store(CLOSED, Ordering::Release);
}

/// Lets the device go: the rules' state, the sources and the target leave
/// the map, the sessions, the timer and the channel close. Safe on a state
/// that is part made.
fn release() {
    {
        let _guard = LIB_LOCK.lock();
        // SAFETY: the lock gives this borrow alone.
        unsafe { *LIB.0.get() = None };
    }
    wake();
    let _ = crate::allocation::heap(|state| state.unmap_sources());
    if MAPPED.swap(false, Ordering::AcqRel) {
        let _ = crate::display::unmap_buffer();
    }
    {
        let _make = STREAM_LOCK.lock();
        // SAFETY: written under STREAM_LOCK.
        unsafe { *STREAMS.0.get() = [NO_STREAM; STREAM_COUNT] };
    }
    for (cell, is_timer) in [(&OWNER, false), (&TIMER, true), (&CHANNEL, false)] {
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
}

/// A forked child has no device: the parent's handles name nothing of its
/// table and are forgotten, never closed, and its pieces were left out of the
/// child's map (`allocation::after_fork`).
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork() {
    for cell in [&OWNER, &CHANNEL, &TIMER] {
        cell.store(0, Ordering::Release);
    }
    WAITING.store(false, Ordering::Release);
    MAPPED.store(false, Ordering::Release);
    COMMIT_LOCK.reset();
    // SAFETY: the child's only thread.
    unsafe {
        *LIB.0.get() = None;
        *STREAMS.0.get() = [NO_STREAM; STREAM_COUNT];
    }
    STATE.store(CLOSED, Ordering::Release);
}

/// `exec` takes the device back with the old image.
pub(crate) fn release_for_exec() {
    if STATE.swap(CLOSED, Ordering::AcqRel) == OPEN {
        release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signal_in_the_wait_runs_the_wait_again() {
        let mut calls = 0;
        let got = wait_restarting(|| {
            calls += 1;
            if calls < 3 {
                Err(Ended::Signal)
            } else {
                Ok(())
            }
        });
        assert_eq!(got, Ok(()));
        assert_eq!(calls, 3);
    }

    #[test]
    fn a_timeout_or_a_failure_ends_the_wait() {
        let mut calls = 0;
        let got = wait_restarting(|| {
            calls += 1;
            Err(Ended::Timeout)
        });
        assert_eq!(got, Err(Ended::Timeout));
        assert_eq!(calls, 1);
        assert_eq!(wait_restarting(|| Err(Ended::Failed)), Err(Ended::Failed));
    }
}
