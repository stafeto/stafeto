// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's window of the composition service (`proto_comp`, the
//! second revision of the display interface; the C functions are
//! `<stafeto/window.h>`, in `posix_crt`'s `window_c.rs`). The module is
//! behind the feature `window`: a statically linked program turns it on,
//! and `libc.so` leaves it off, so the series 0.5 of the ABI is as it was.
//! The logic that needs no kernel (the account of buffers, the merging of
//! rectangles, the event layouts, the refusals as errno) is the crate
//! `comp-client`.
//!
//! The process has one window (its number is 0). It owns:
//!
//! * a channel of its own, with a timer on it, that the service notifies:
//!   bit k says buffer k is free, bit 3 says the ring of events holds
//!   something (`proto_comp::EVENTS_BIT`). The channel is a wait channel
//!   like a thread's, apart from the thread's channel, so that the bits of
//!   the service never mix with the bits of other services and need no
//!   bank of labels;
//! * the window's session (WINDOW_CREATE's reply): POST, EVENTS and ATTACH
//!   go on it, and closing it ends the window;
//! * one to three buffers, memory objects of the process mapped as pieces
//!   of the map of the kind `posix_map::Kind::Window`: a forked child gets
//!   none, `munmap`, `mprotect` and `MAP_FIXED` on them give EINVAL, and
//!   `exec`, `close` and the end of the process take them. The service has
//!   its own copies of the objects' handles (MAP_READ and TRANSFER, no
//!   more) and maps them for reading.
//!
//! A forked child has no window: the state is reset in `after_fork`, and
//! the handles above are the parent's alone (the layer carries only its
//! own session records into a child). `exec` closes the window as it
//! closes the screen of the first revision (`release_for_exec`).
//!
//! One thread at a time waits (`wait`) and one takes events (`events`);
//! another that comes meanwhile gets EBUSY. The account of the buffers is
//! one atomic word, so POST needs no lock; it takes its buffer out of the
//! free ones before the request goes and gives it back if the service
//! refuses (`comp_client::account`).

use crate::constants::*;
use crate::threads;
use comp_client::account::Buffers;
use comp_client::damage;
use comp_client::errno;
use comp_client::events::Taker;
use comp_client::layout::{self, Screen, Window, WindowEvent};
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use proto_comp::{Attach, Create, Description, Method, Post};
use proto_wire::{Status, Writer};
use rt::abi::{Error, MESSAGE_MAX, Rights, Source};
use rt::handle::{Channel, Handle, Memory, Outgoing, Timer};
use rt::sys::{self, Received};

const _: () = {
    // The errno numbers of comp-client are the layer's.
    assert!(errno::EINTR == EINTR && errno::EIO == EIO && errno::EBADF == EBADF);
    assert!(errno::EAGAIN == EAGAIN && errno::ENOMEM == ENOMEM && errno::EBUSY == EBUSY);
    assert!(errno::ENODEV == ENODEV && errno::EINVAL == EINVAL && errno::ETIMEDOUT == ETIMEDOUT);
};

const CLOSED: u32 = 0;
const OPENING: u32 = 1;
const OPEN: u32 = 2;

/// The longest the display's setting up (CLEARING) is waited for, and the
/// pause of that wait; the longest a busy ATTACH is asked again (another
/// client's buffers are being mapped) and its pause; the pause of `shown`'s
/// looks.
const CLEARING_TRIES: u32 = 50;
const CLEARING_PAUSE_NS: i64 = 10_000_000;
const ATTACH_TRIES: u32 = 50;
const ATTACH_PAUSE_NS: i64 = 10_000_000;
const SHOWN_PAUSE_NS: i64 = 2_000_000;
const PAGE: u64 = 4096;

static STATE: AtomicU32 = AtomicU32::new(CLOSED);
/// The window's session, the window's own channel and its timer (raw
/// handles, 0 for none).
static SESSION: AtomicU64 = AtomicU64::new(0);
static CHANNEL: AtomicU64 = AtomicU64::new(0);
static TIMER: AtomicU64 = AtomicU64::new(0);
/// What the window is: width, height, stride, format, buffers.
static SHAPE: [AtomicU32; 5] = [const { AtomicU32::new(0) }; 5];
static PIXELS: [AtomicU64; layout::BUFFERS_MAX] = [const { AtomicU64::new(0) }; 3];
/// The account of the buffers (`Buffers::raw`; 0 when there is no window).
static ACCOUNT: AtomicU32 = AtomicU32::new(0);
/// The service ended or took the window away.
static GONE: AtomicBool = AtomicBool::new(false);
/// A thread waits on the channel; a thread takes events.
static WAITING: AtomicBool = AtomicBool::new(false);
static TAKING: AtomicBool = AtomicBool::new(false);
/// The frames the service had shown when `shown` last looked, and whether a
/// POST came since.
static FRAMES: AtomicU32 = AtomicU32::new(0);
static DIRTY: AtomicBool = AtomicBool::new(false);
/// The failure of an unmap was told once.
static UNMAP_TOLD: AtomicBool = AtomicBool::new(false);

/// The events a call had no room for and what the last reply was; the thread
/// that holds `TAKING` owns it.
struct Held(UnsafeCell<Taker>);
// SAFETY: touched only by the thread that holds TAKING.
unsafe impl Sync for Held {}
static STASH: Held = Held(UnsafeCell::new(Taker::new()));

/// Clears a flag at the end of the scope.
struct Flag(&'static AtomicBool);

impl Flag {
    /// Takes the flag; None when another thread has it.
    fn take(flag: &'static AtomicBool) -> Option<Flag> {
        (!flag.swap(true, Ordering::AcqRel)).then_some(Flag(flag))
    }
}

impl Drop for Flag {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn level() -> u8 {
    (threads::own_block().base_level.load(Ordering::Relaxed) as u8).max(1)
}

fn channel() -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(CHANNEL.load(Ordering::Acquire)))
}

fn session() -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(SESSION.load(Ordering::Acquire)))
}

/// The errno of a refusal of the kernel on the window's session; a service
/// that is gone marks the window gone for every later call.
fn refused(error: Error) -> i32 {
    if error == Error::PeerClosed {
        GONE.store(true, Ordering::Release);
    }
    errno::kernel(error)
}

/// The errno of a status a request of the window came back with; REVOKED
/// and NO_DEVICE mark the window gone.
fn refusal(status: Status) -> i32 {
    let errno = errno::status(status);
    if errno == ENODEV {
        GONE.store(true, Ordering::Release);
    }
    errno
}

/// One request with `handles` and its reply; a send that came back
/// INTERRUPTED goes again, with the handles it gave back: the service never
/// saw it.
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

/// The memory object calls' errno: out of memory and out of places are
/// ENOMEM.
fn memory_errno(error: Error) -> i32 {
    match error {
        Error::NoMemory | Error::LimitReached => ENOMEM,
        other => errno::kernel(other),
    }
}

/// DESCRIBE on the process's `Display` session, again up to 50 times 10 ms
/// apart while the service says CLEARING (the driver is being set up).
fn describe(display: &Handle<Channel>) -> Result<Description, i32> {
    let request = Method::Describe.header().bytes();
    let mut tries = 0;
    loop {
        let reply = call(display, &request, Outgoing::new()).map_err(errno::kernel)?;
        let mut buffer = [0; MESSAGE_MAX];
        match Description::read(reply.bytes(&mut buffer)) {
            Ok(d) => return Ok(d),
            Err(status)
                if status == proto_gpu::code(proto_gpu::CLEARING) && tries < CLEARING_TRIES =>
            {
                tries += 1;
                crate::threads::sleep::pause(CLEARING_PAUSE_NS)?;
            }
            Err(status) => return Err(errno::status(status)),
        }
    }
}

/// `stafeto_screen_describe`.
pub fn screen() -> Result<Screen, i32> {
    let display = crate::display::session().ok_or(ENODEV)?;
    let d = describe(&Handle::<Channel>::borrowed(display))?;
    Ok(Screen {
        width: d.width,
        height: d.height,
        format: d.format,
        flags: 0,
        reserved: [0; 4],
    })
}

/// `stafeto_window_open`: the window of (`w`, `h`) points at (`x`, `y`),
/// `buffers` buffers of `format`. The errno are those the header lists.
pub fn open(
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    format: u32,
    buffers: u32,
    flags: u32,
) -> Result<Window, i32> {
    if flags != 0 {
        return Err(EINVAL);
    }
    let display = crate::display::session().ok_or(ENODEV)?;
    if STATE
        .compare_exchange(CLOSED, OPENING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(EBUSY);
    }
    let result = open_window(
        &Handle::<Channel>::borrowed(display),
        (x, y, w, h),
        format,
        buffers,
    );
    if result.is_err() {
        release();
    }
    STATE.store(
        if result.is_ok() { OPEN } else { CLOSED },
        Ordering::Release,
    );
    result
}

fn open_window(
    display: &Handle<Channel>,
    (x, y, w, h): (i32, i32, i32, i32),
    format: u32,
    buffers: u32,
) -> Result<Window, i32> {
    let (Ok(x), Ok(y), Ok(w), Ok(h)) = (
        u32::try_from(x),
        u32::try_from(y),
        u32::try_from(w),
        u32::try_from(h),
    ) else {
        return Err(EINVAL);
    };
    if (format != layout::XRGB8888 && format != layout::ARGB8888 && format != layout::A8)
        || !(1..=layout::BUFFERS_MAX as u32).contains(&buffers)
    {
        return Err(EINVAL);
    }
    let create = Create {
        x,
        y,
        w,
        h,
        format,
        flags: 0,
    };
    let screen = describe(display)?;
    if !create.fits(screen.width, screen.height) {
        return Err(EINVAL);
    }
    let stride = layout::line_bytes(format, w).ok_or(EINVAL)?;
    let len = (u64::from(stride) * u64::from(h)).div_ceil(PAGE) * PAGE;
    if len > proto_comp::BUFFER_MAX {
        return Err(EINVAL);
    }
    GONE.store(false, Ordering::Release);
    WAITING.store(false, Ordering::Release);
    TAKING.store(false, Ordering::Release);

    // The window's channel and its timer.
    let own = sys::channel_create_wait(level()).map_err(memory_errno)?;
    let timer = sys::timer_create(&own, level()).map_err(memory_errno)?;
    CHANNEL.store(own.into_raw().0, Ordering::Release);
    TIMER.store(timer.into_raw().0, Ordering::Release);

    // The buffers: the process keeps each object mapped, and a spare handle
    // of it that ATTACH copies from (a busy service asks for the copies
    // again).
    let mut spares: [Option<Handle<Memory>>; layout::BUFFERS_MAX] = Default::default();
    let mut pixels = [0usize; layout::BUFFERS_MAX];
    for k in 0..buffers as usize {
        let object = sys::mem_create(len).map_err(memory_errno)?;
        spares[k] = Some(
            sys::handle_duplicate(
                &object,
                Rights::MAP_READ | Rights::TRANSFER | Rights::DUPLICATE,
            )
            .map_err(memory_errno)?,
        );
        let at = crate::allocation::heap(|state| state.map_window(object, (len / PAGE) as usize))?;
        PIXELS[k].store(at as u64, Ordering::Release);
        pixels[k] = at;
    }

    // WINDOW_CREATE with a copy of the channel that may notify and be
    // handed on.
    let mut tries = 0;
    let mut reply = loop {
        let notify = sys::handle_duplicate(&channel(), Rights::NOTIFY | Rights::TRANSFER)
            .map_err(memory_errno)?;
        let mut request = Writer::new();
        create.write(&mut request).map_err(|_| EIO)?;
        let reply =
            call(display, request.as_bytes(), [notify.erase()].into()).map_err(errno::kernel)?;
        match status_of(&reply) {
            Status::Ok => break reply,
            status if status == proto_gpu::code(proto_gpu::CLEARING) && tries < CLEARING_TRIES => {
                tries += 1;
                crate::threads::sleep::pause(CLEARING_PAUSE_NS)?;
            }
            status => return Err(errno::status(status)),
        }
    };
    let made = reply.handles.take::<Channel>(0).map_err(|_| EIO)?;
    SESSION.store(made.into_raw().0, Ordering::Release);

    // ATTACH with copies of the objects, MAP_READ and TRANSFER alone.
    let attach = Attach {
        count: buffers,
        stride,
        format,
    };
    let mut tries = 0;
    loop {
        let mut copies = Outgoing::new();
        for spare in spares.iter().flatten() {
            let copy = sys::handle_duplicate(spare, Rights::MAP_READ | Rights::TRANSFER)
                .map_err(memory_errno)?;
            copies.push(copy.erase()).map_err(|_| EIO)?;
        }
        let mut request = Writer::new();
        attach.write(&mut request).map_err(|_| EIO)?;
        let reply = call(&session(), request.as_bytes(), copies).map_err(errno::kernel)?;
        match status_of(&reply) {
            Status::Ok => break,
            status if status == proto_comp::code(proto_comp::BUSY) && tries < ATTACH_TRIES => {
                tries += 1;
                crate::threads::sleep::pause(ATTACH_PAUSE_NS)?;
            }
            status => return Err(errno::status(status)),
        }
    }
    drop(spares);

    // The frames shown so far are the baseline of `shown`.
    let frames = describe(display).map_or(screen.frames, |d| d.frames);
    FRAMES.store(frames, Ordering::Release);
    DIRTY.store(false, Ordering::Release);
    for (cell, value) in SHAPE.iter().zip([w, h, stride, format, buffers]) {
        cell.store(value, Ordering::Release);
    }
    // SAFETY: no thread but this one knows the window yet (TAKING is clear).
    unsafe { *STASH.0.get() = Taker::new() };
    ACCOUNT.store(Buffers::new(buffers as usize).raw(), Ordering::Release);
    Ok(Window {
        width: w,
        height: h,
        stride,
        format,
        buffers,
        reserved: 0,
        pixels: [pixels[0], pixels[1], pixels[2]],
    })
}

/// `win` is the window's number and the window is open.
fn opened(win: i32) -> Result<(), i32> {
    if win != 0 || STATE.load(Ordering::Acquire) != OPEN {
        return Err(EBADF);
    }
    Ok(())
}

fn alive() -> Result<(), i32> {
    if GONE.load(Ordering::Acquire) {
        Err(ENODEV)
    } else {
        Ok(())
    }
}

/// Updates the account in one compare-and-swap loop; None without a window.
fn account<R>(f: impl Fn(&mut Buffers) -> R) -> Option<R> {
    let mut word = ACCOUNT.load(Ordering::Acquire);
    loop {
        let mut buffers = Buffers::from_raw(word)?;
        let result = f(&mut buffers);
        match ACCOUNT.compare_exchange_weak(
            word,
            buffers.raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(result),
            Err(now) => word = now,
        }
    }
}

/// The bit the library sends its own channel to wake a `wait` that sleeps
/// in another thread when `post` took bits: outside the service's bits, so
/// that the account drops it and no bit comes twice.
const WAKE: u64 = 1 << 32;

/// What the channel brought: the service's bits go to the account (and wait
/// there for `wait`); the timer's expiries, the wake and anything else are
/// passed over. Whether service bits came.
fn absorb(got: &Received) -> bool {
    if let Received::Notification {
        source: Source::Unlabeled,
        bits,
        ..
    } = got
        && bits & u64::from(layout::BITS) != 0
    {
        account(|buffers| buffers.bits(*bits));
        return true;
    }
    false
}

/// Takes what waits on the channel without blocking. Service bits stay in
/// the account for the next `wait`. A `wait` in another thread may have set
/// its timer or be about to block on exactly what was taken (the timer's
/// expiry, an earlier wake, a bit), so when anything at all was taken and a
/// thread waits, one wake goes after the loop: the waiter looks again at the
/// account and at its time (`comp_client::account::should_wake`).
fn drain() {
    let own = channel();
    let mut taken = 0;
    while let Ok(got) = sys::try_receive(&own) {
        absorb(&got);
        taken += 1;
    }
    if comp_client::account::should_wake(taken, WAITING.load(Ordering::Acquire)) {
        let _ = sys::notify(&own, WAKE);
    }
}

/// `stafeto_window_info`: the window as `open` described it (its size, the
/// bytes of a line, the format, the number of buffers and where each lies in
/// the process); EBADF for a number that is no open window. The values are
/// those of the open window, so a window closed and opened again shows as
/// another description to a caller that kept the first.
pub fn info(win: i32) -> Result<Window, i32> {
    opened(win)?;
    let shape = |k: usize| SHAPE[k].load(Ordering::Acquire);
    let pixel = |k: usize| PIXELS[k].load(Ordering::Acquire) as usize;
    let window = Window {
        width: shape(0),
        height: shape(1),
        stride: shape(2),
        format: shape(3),
        buffers: shape(4),
        reserved: 0,
        pixels: [pixel(0), pixel(1), pixel(2)],
    };
    // A window closed while the description was read has no pixels left.
    opened(win)?;
    Ok(window)
}

/// `stafeto_window_free`: the free buffers by the account; 0 for a window
/// that is not open.
pub fn free(win: i32) -> u32 {
    if opened(win).is_err() {
        return 0;
    }
    account(|buffers| buffers.free()).unwrap_or(0)
}

/// `stafeto_window_post`: POST of `buffer` with `rects`.
pub fn post(win: i32, buffer: u32, rects: &[layout::Rect]) -> Result<(), i32> {
    opened(win)?;
    alive()?;
    let width = SHAPE[0].load(Ordering::Acquire);
    let height = SHAPE[1].load(Ordering::Acquire);
    let merged = damage::merge(rects, width, height)?;
    // Bits that already wait free the buffers they name.
    drain();
    account(|buffers| buffers.take(buffer)).ok_or(EBADF)??;
    let sent = send_post(buffer, merged.as_slice());
    // The service sends the bit of a buffer the post replaced before it
    // replies, so the account sees "free again at once" when the call
    // returns.
    drain();
    if sent.is_err() {
        account(|buffers| buffers.give_back(buffer));
    } else {
        DIRTY.store(true, Ordering::Release);
    }
    sent
}

fn send_post(buffer: u32, rects: &[layout::Rect]) -> Result<(), i32> {
    let mut list = [proto_comp::Rect {
        x: 0,
        y: 0,
        w: 0,
        h: 0,
    }; layout::RECTS_MAX];
    for (to, from) in list.iter_mut().zip(rects) {
        *to = proto_comp::Rect {
            x: from.x as u32,
            y: from.y as u32,
            w: from.w as u32,
            h: from.h as u32,
        };
    }
    let mut request = Writer::new();
    Post::new(buffer, &list[..rects.len()])
        .and_then(|post| post.write(&mut request))
        .map_err(|_| EINVAL)?;
    let reply = call(&session(), request.as_bytes(), Outgoing::new()).map_err(refused)?;
    match status_of(&reply) {
        Status::Ok => Ok(()),
        status => Err(refusal(status)),
    }
}

/// `stafeto_window_wait`: the bits that came on the window's channel, as
/// the header says. The wait is `fast::wait`'s: a try without waiting, the
/// signals, the entries deferred, a receive with a timer for the bound.
pub fn wait(win: i32, timeout_ns: u64) -> Result<u32, i32> {
    opened(win)?;
    alive()?;
    let Some(_waiting) = Flag::take(&WAITING) else {
        return Err(EBUSY);
    };
    let own = channel();
    let timer = Handle::<Timer>::borrowed(rt::abi::Handle(TIMER.load(Ordering::Acquire)));
    let until = crate::wait::now().saturating_add(timeout_ns);
    let block = threads::own_block();
    loop {
        // Whatever waits on the channel, without blocking.
        loop {
            match sys::try_receive(&own) {
                Ok(got) => {
                    absorb(&got);
                }
                Err(Error::WouldBlock) => break,
                Err(Error::Interrupted) => {
                    crate::signals::deliver_now();
                    return Err(EINTR);
                }
                Err(_) => return Err(EIO),
            }
        }
        if let Some(bits) = account(|buffers| buffers.take_pending())
            && bits != 0
        {
            return Ok(bits);
        }
        if crate::wait::now() >= until {
            return Err(ETIMEDOUT);
        }
        let handled = block.handled.load(Ordering::SeqCst);
        if crate::signals::pending_unblocked() {
            crate::signals::deliver_now();
            return Err(EINTR);
        }
        sys::timer_set(&timer, until).map_err(|_| EIO)?;
        let guard = rt::upcall::defer_entries().map_err(|_| EIO)?;
        if block.handled.load(Ordering::SeqCst) != handled || crate::signals::pending_unblocked() {
            drop(guard);
            let _ = sys::timer_cancel(&timer);
            crate::signals::deliver_now();
            return Err(EINTR);
        }
        let got = sys::receive(&own);
        drop(guard);
        match got {
            Ok(got) => {
                absorb(&got);
                // The timer is armed no more once something else came.
                let _ = sys::timer_cancel(&timer);
            }
            Err(Error::Interrupted) => {
                let _ = sys::timer_cancel(&timer);
                crate::signals::deliver_now();
                return Err(EINTR);
            }
            Err(_) => return Err(EIO),
        }
    }
}

/// `stafeto_window_events`: up to `out.len()` events of the ring and the
/// flags, and fewer only when the ring is empty (`comp_client::events::Taker`
/// asks the service again while its replies are full). Events the service
/// gave beyond `out` wait for the next call.
pub fn events(win: i32, out: &mut [WindowEvent]) -> Result<(usize, u32), i32> {
    opened(win)?;
    if out.is_empty() {
        return Err(EINVAL);
    }
    let Some(_taking) = Flag::take(&TAKING) else {
        return Err(EBUSY);
    };
    // SAFETY: TAKING is held.
    let taker = unsafe { &mut *STASH.0.get() };
    taker.take(out, |list| {
        alive()?;
        let reply = call(
            &session(),
            &Method::Events.header().bytes(),
            Outgoing::new(),
        )
        .map_err(refused)?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut n = 0;
        let flags = proto_comp::read_events(reply.bytes(&mut buffer), |event| {
            if n < list.len() {
                list[n] = event.into();
                n += 1;
            }
        })
        .map_err(refusal)?;
        Ok((n, flags & proto_comp::LOST != 0))
    })
}

/// `stafeto_window_shown`: until the service has shown a frame since the
/// last POST and makes none.
pub fn shown(win: i32, timeout_ns: u64) -> Result<(), i32> {
    opened(win)?;
    alive()?;
    let display = crate::display::session().ok_or(ENODEV)?;
    let display = Handle::<Channel>::borrowed(display);
    let until = crate::wait::now().saturating_add(timeout_ns);
    loop {
        let d = describe(&display)?;
        let grown = d.frames.wrapping_sub(FRAMES.load(Ordering::Acquire)) as i32 > 0;
        if d.busy == 0 && (grown || !DIRTY.load(Ordering::Acquire)) {
            FRAMES.store(d.frames, Ordering::Release);
            DIRTY.store(false, Ordering::Release);
            return Ok(());
        }
        if crate::wait::now() >= until {
            return Err(ETIMEDOUT);
        }
        // A signal that ends the pause has run its handler; the look goes on.
        let _ = crate::threads::sleep::pause(SHOWN_PAUSE_NS);
    }
}

/// Lets the window go: the session closes (the service forgets the window),
/// the buffers leave the map and the process, the timer and the channel
/// close. Safe on a state that is part made.
fn release() {
    if let Err(errno) = crate::allocation::heap(|state| state.unmap_windows()) {
        // Once: a program that closes windows in a loop would repeat it.
        if !UNMAP_TOLD.swap(true, Ordering::AcqRel) {
            rt::println!("posix: a buffer of the window could not be unmapped (errno {errno})");
        }
    }
    let raw = SESSION.swap(0, Ordering::AcqRel);
    if raw != 0 {
        drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
    }
    let raw = TIMER.swap(0, Ordering::AcqRel);
    if raw != 0 {
        drop(Handle::<Timer>::from_raw(rt::abi::Handle(raw)));
    }
    let raw = CHANNEL.swap(0, Ordering::AcqRel);
    if raw != 0 {
        drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
    }
    ACCOUNT.store(0, Ordering::Release);
    for cell in &PIXELS {
        cell.store(0, Ordering::Release);
    }
}

/// `stafeto_window_close`: EBADF for a number that is no open window.
pub fn close(win: i32) -> Result<(), i32> {
    if win != 0
        || STATE
            .compare_exchange(OPEN, OPENING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return Err(EBADF);
    }
    release();
    STATE.store(CLOSED, Ordering::Release);
    Ok(())
}

/// A forked child has no window: the parent's handles name nothing of its
/// table and are forgotten, never closed, and its buffers were left out of
/// the child's map (`allocation::after_fork`).
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork() {
    for cell in [&SESSION, &CHANNEL, &TIMER] {
        cell.store(0, Ordering::Release);
    }
    ACCOUNT.store(0, Ordering::Release);
    for cell in &PIXELS {
        cell.store(0, Ordering::Release);
    }
    for flag in [&GONE, &WAITING, &TAKING, &DIRTY] {
        flag.store(false, Ordering::Release);
    }
    // SAFETY: the child's only thread.
    unsafe { *STASH.0.get() = Taker::new() };
    STATE.store(CLOSED, Ordering::Release);
}

/// `exec` takes the window back with the old image.
pub(crate) fn release_for_exec() {
    if STATE.swap(CLOSED, Ordering::AcqRel) == OPEN {
        release();
    }
}
