// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The process's windows of the composition service (`proto_comp`, the
//! second revision of the display interface; the C functions are
//! `<stafeto/window.h>`, in `posix_crt`'s `window_c.rs`). The module is
//! behind the feature `window`: a statically linked program turns it on,
//! and `libc.so` leaves it off, so the series 0.5 of the ABI is as it was.
//! The logic that needs no kernel (the account of buffers, the merging of
//! rectangles, the event layouts, the refusals as errno, the labels and
//! numbers of the windows) is the crate `comp-client`.
//!
//! The process has up to `WINDOWS_MAX` (8) windows, numbered from 0 (a new
//! window takes the lowest free number). They share:
//!
//! * a channel with a timer on it, that the service notifies: bit k says
//!   buffer k of a window is free, bit 3 says the window's ring of events
//!   holds something (`proto_comp::EVENTS_BIT`). The service holds a copy of
//!   the channel for each window, and the copy's label names the window
//!   (`comp_client::table::label`), so the bits of the windows never mix
//!   and need no bank of labels beyond that. The channel is a wait channel
//!   like a thread's, apart from the thread's channel, so that the bits of
//!   the service never mix with the bits of other services. It is made with
//!   the first window and goes with the last.
//!
//! Each window owns:
//!
//! * the window's session (WINDOW_CREATE's reply): POST, EVENTS, ATTACH,
//!   SET_TEXT and SIZE go on it, and closing it ends the window;
//! * one to three buffers, memory objects of the process mapped as pieces
//!   of the map of the kind `posix_map::Kind::Window`: a forked child gets
//!   none, `munmap`, `mprotect` and `MAP_FIXED` on them give EINVAL, and
//!   `exec`, `close` and the end of the process take them. The service has
//!   its own copies of the objects' handles (MAP_READ and TRANSFER, no
//!   more) and maps them for reading. A window made `RESIZABLE` has buffers
//!   of the capacity of the whole screen (capped at `BUFFER_MAX`), and
//!   `resize` changes its size inside the capacity.
//!
//! A process the init table gives the manager's mark (the program `desk`) is
//! also the window manager: `manager` holds its calls (`<stafeto/manager.h>`).
//! Its subscription is one more labelled copy of the shared channel, whose
//! label (`table::manager_label`) names no window; the service's bit for the
//! manager's ring is the bit 30 of the mask `wait_all` returns.
//!
//! A forked child has no windows: the state is reset in `after_fork`, and
//! the handles above are the parent's alone (the layer carries only its
//! own session records into a child). `exec` closes every window as it
//! closes the screen of the first revision (`release_for_exec`).
//!
//! One thread at a time waits (`wait`, `wait_all`) and one takes the events
//! of a window (`events`); another that comes meanwhile gets EBUSY. The
//! account of a window's buffers is one atomic word, so POST needs no lock;
//! it takes its buffer out of the free ones before the request goes and
//! gives it back if the service refuses (`comp_client::account`).

use crate::constants::*;
use crate::threads;
use comp_client::account::Buffers;
use comp_client::damage;
use comp_client::errno;
use comp_client::events::Taker;
use comp_client::flag::Flag;
use comp_client::layout::{self, Screen, Window, WindowEvent};
use comp_client::table::{self, WINDOWS_MAX};
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use proto_comp::{Attach, Create, Description, Method, Post, SetText, Size};

mod manager;
pub use manager::{
    close as manager_close, configure, events as manager_events, focus, info as manager_info, link,
    list as manager_list, move_to, raise, subscribe, visible, window_id,
};
use proto_wire::{Status, Writer};
use rt::abi::{Error, MESSAGE_MAX, Rights, Source};
use rt::handle::{Channel, Handle, Memory, Outgoing, Timer};
use rt::sys::{self, Received};

const _: () = {
    // The errno numbers of comp-client are the layer's.
    assert!(errno::EINTR == EINTR && errno::EIO == EIO && errno::EBADF == EBADF);
    assert!(errno::EAGAIN == EAGAIN && errno::ENOMEM == ENOMEM && errno::EBUSY == EBUSY);
    assert!(errno::ENODEV == ENODEV && errno::EINVAL == EINVAL && errno::ETIMEDOUT == ETIMEDOUT);
    assert!(WINDOWS_MAX <= 16);
    assert!(WINDOWS_MAX * layout::BUFFERS_MAX == crate::allocation::WINDOW_PIECES);
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

/// The events a call had no room for and what the last reply was; the thread
/// that holds `taking` of the window owns it.
struct Held(UnsafeCell<Taker>);
// SAFETY: touched only by the thread that holds the window's `taking`.
unsafe impl Sync for Held {}

/// One window of the process.
struct Win {
    /// CLOSED, OPENING or OPEN; changed only under `LOCK` (open, close) or by
    /// `after_fork` and `release_for_exec`.
    state: AtomicU32,
    /// Raised by each successful open and given to the caller in
    /// `struct stafeto_window.generation`: a description tells which window it
    /// is the description of, so a window closed and opened again under the same
    /// number is another one.
    generation: AtomicU32,
    /// The label of the copy of the process's channel the service holds for
    /// this window (0 before the service took one). Each try of WINDOW_CREATE
    /// has a label of its own (`table::label`), so that the end of a copy the
    /// service refused (CLIENT_GONE, which the kernel posts when the last copy
    /// of a labelled handle goes) is told from the end of the copy the service
    /// kept, and the end of a closed window's copy from the next window's.
    label: AtomicU64,
    /// The window's session (a raw handle, 0 for none).
    session: AtomicU64,
    /// The service's number of the window (`proto_comp::window_id`), which the
    /// manager's events and MANAGE name it by; 0 when there is no window.
    id: AtomicU32,
    /// What the window is: width, height, stride, format, buffers.
    shape: [AtomicU32; 5],
    /// The capacity: the most width and height `resize` takes.
    cap: [AtomicU32; 2],
    pixels: [AtomicU64; layout::BUFFERS_MAX],
    /// The account of the buffers (`Buffers::raw`; 0 when there is no window).
    account: AtomicU32,
    /// The service ended or took the window away.
    gone: AtomicBool,
    /// A thread takes events.
    taking: AtomicBool,
    /// The frames the service had shown when `shown` last looked, and whether a
    /// POST came since.
    frames: AtomicU32,
    dirty: AtomicBool,
    stash: Held,
}

impl Win {
    const fn new() -> Win {
        Win {
            state: AtomicU32::new(CLOSED),
            generation: AtomicU32::new(0),
            label: AtomicU64::new(0),
            session: AtomicU64::new(0),
            id: AtomicU32::new(0),
            shape: [const { AtomicU32::new(0) }; 5],
            cap: [const { AtomicU32::new(0) }; 2],
            pixels: [const { AtomicU64::new(0) }; layout::BUFFERS_MAX],
            account: AtomicU32::new(0),
            gone: AtomicBool::new(false),
            taking: AtomicBool::new(false),
            frames: AtomicU32::new(0),
            dirty: AtomicBool::new(false),
            stash: Held(UnsafeCell::new(Taker::new())),
        }
    }

    fn shape(&self, k: usize) -> u32 {
        self.shape[k].load(Ordering::Acquire)
    }

    fn session(&self) -> ManuallyDrop<Handle<Channel>> {
        Handle::borrowed(rt::abi::Handle(self.session.load(Ordering::Acquire)))
    }
}

static WINS: [Win; WINDOWS_MAX] = [const { Win::new() }; WINDOWS_MAX];
static GENERATION: AtomicU32 = AtomicU32::new(0);
/// The sequence number of the next copy of the channel handed to the service.
static LABEL_SEQUENCE: AtomicU32 = AtomicU32::new(0);
/// The channel the windows share and its timer (raw handles, 0 for none).
static CHANNEL: AtomicU64 = AtomicU64::new(0);
static TIMER: AtomicU64 = AtomicU64::new(0);
/// Held by `open` and `close` for their length.
static LOCK: AtomicBool = AtomicBool::new(false);
/// A thread waits on the channel.
static WAITING: AtomicBool = AtomicBool::new(false);
/// The failure of an unmap was told once.
static UNMAP_TOLD: AtomicBool = AtomicBool::new(false);
/// The label of the copy of the channel the service holds for the manager's
/// ring (0 before `subscribe`), whether its bit came since a wait took it, and
/// whether the service's copy went.
static MANAGER_LABEL: AtomicU64 = AtomicU64::new(0);
static MANAGER_PENDING: AtomicBool = AtomicBool::new(false);
static MANAGER_GONE: AtomicBool = AtomicBool::new(false);

fn level() -> u8 {
    (threads::own_block().base_level.load(Ordering::Relaxed) as u8).max(1)
}

fn channel() -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(CHANNEL.load(Ordering::Acquire)))
}

/// The errno of a refusal of the kernel on the window's session; a service
/// that is gone marks the window gone for every later call.
fn refused(w: &Win, error: Error) -> i32 {
    if error == Error::PeerClosed {
        w.gone.store(true, Ordering::Release);
    }
    errno::kernel(error)
}

/// The errno of a status a request of the window came back with; REVOKED
/// and NO_DEVICE mark the window gone.
fn refusal(w: &Win, status: Status) -> i32 {
    let errno = errno::status(status);
    if errno == ENODEV {
        w.gone.store(true, Ordering::Release);
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
/// `buffers` buffers of `format`; `flags` is 0 or `RESIZABLE`. The window's
/// number (the lowest free one) and its description. The errno are those the
/// header lists.
pub fn open(
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    format: u32,
    buffers: u32,
    flags: u32,
) -> Result<(i32, Window), i32> {
    if flags & !layout::RESIZABLE != 0 {
        return Err(EINVAL);
    }
    let display = crate::display::session().ok_or(ENODEV)?;
    let _lock = lock();
    let used = (0..WINDOWS_MAX)
        .filter(|&k| WINS[k].state.load(Ordering::Acquire) != CLOSED)
        .fold(0u32, |mask, k| mask | 1 << k);
    let slot = table::free_slot(used)?;
    let win = &WINS[slot];
    win.state.store(OPENING, Ordering::Release);
    let result = open_window(
        win,
        slot,
        &Handle::<Channel>::borrowed(display),
        (x, y, w, h),
        format,
        buffers,
        flags & layout::RESIZABLE != 0,
    );
    if result.is_err() {
        release_window(win);
    }
    win.state.store(
        if result.is_ok() { OPEN } else { CLOSED },
        Ordering::Release,
    );
    if result.is_err() {
        drop_channel_if_unused();
    }
    result.map(|window| (slot as i32, window))
}

/// Takes `LOCK`, waiting for the thread that holds it.
fn lock() -> Flag {
    loop {
        if let Some(held) = Flag::take(&LOCK) {
            return held;
        }
        let _ = crate::threads::sleep::pause(1_000_000);
    }
}

/// The shared channel and its timer, made with the first window (or the
/// manager's subscription, whichever comes first). Called under `LOCK`.
fn ensure_channel() -> Result<(), i32> {
    if CHANNEL.load(Ordering::Acquire) == 0 {
        let own = sys::channel_create_wait(level()).map_err(memory_errno)?;
        let timer = sys::timer_create(&own, level()).map_err(memory_errno)?;
        CHANNEL.store(own.into_raw().0, Ordering::Release);
        TIMER.store(timer.into_raw().0, Ordering::Release);
    }
    Ok(())
}

fn open_window(
    win: &'static Win,
    slot: usize,
    display: &Handle<Channel>,
    (x, y, w, h): (i32, i32, i32, i32),
    format: u32,
    buffers: u32,
    resizable: bool,
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
    // A window that may be resized has buffers that hold the whole screen
    // (the most the service takes); the others hold their own lines.
    let (stride, len) = if resizable {
        let stride = layout::line_bytes(format, screen.width).ok_or(EINVAL)?;
        let len = (u64::from(stride) * u64::from(screen.height))
            .div_ceil(PAGE)
            .saturating_mul(PAGE)
            .min(proto_comp::BUFFER_MAX);
        (stride, len)
    } else {
        let stride = layout::line_bytes(format, w).ok_or(EINVAL)?;
        (
            stride,
            (u64::from(stride) * u64::from(h)).div_ceil(PAGE) * PAGE,
        )
    };
    if len > proto_comp::BUFFER_MAX || len < u64::from(stride) * u64::from(h) {
        return Err(EINVAL);
    }
    win.gone.store(false, Ordering::Release);
    win.taking.store(false, Ordering::Release);

    // The shared channel and its timer, made with the first window.
    ensure_channel()?;

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
        win.pixels[k].store(at as u64, Ordering::Release);
        pixels[k] = at;
    }

    // The account exists before the service can notify: a bit that comes
    // while another thread waits (the labelled copy is live from WINDOW_CREATE)
    // finds it, and nothing is dropped. A window still opening is not reported
    // by a wait across the windows (only OPEN windows are).
    win.account
        .store(Buffers::new(buffers as usize).raw(), Ordering::Release);

    // WINDOW_CREATE with a copy of the channel that may notify and be
    // handed on.
    let mut tries = 0;
    let mut reply = loop {
        // A labelled copy: the kernel tells the channel (CLIENT_GONE, from
        // this session's slot) when the service's last copy goes, so a
        // compositor that ends is known to the waits.
        let label = table::label(LABEL_SEQUENCE.fetch_add(1, Ordering::AcqRel), slot);
        let notify = sys::handle_label(
            &channel(),
            Rights::NOTIFY | Rights::TRANSFER,
            label,
            level(),
        )
        .map_err(memory_errno)?;
        let mut request = Writer::new();
        create.write(&mut request).map_err(|_| EIO)?;
        let reply =
            call(display, request.as_bytes(), [notify.erase()].into()).map_err(errno::kernel)?;
        match status_of(&reply) {
            Status::Ok => {
                win.label.store(label, Ordering::Release);
                break reply;
            }
            status if status == proto_gpu::code(proto_gpu::CLEARING) && tries < CLEARING_TRIES => {
                tries += 1;
                crate::threads::sleep::pause(CLEARING_PAUSE_NS)?;
            }
            status => return Err(errno::status(status)),
        }
    };
    let made = reply.handles.take::<Channel>(0).map_err(|_| EIO)?;
    win.session.store(made.into_raw().0, Ordering::Release);
    // The reply is the status and the window's number.
    let mut buffer = [0; MESSAGE_MAX];
    let id = match reply.bytes(&mut buffer).get(4..8) {
        Some(w) => u32::from_le_bytes([w[0], w[1], w[2], w[3]]),
        None => return Err(EIO),
    };
    win.id.store(id, Ordering::Release);

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
        let reply = call(&win.session(), request.as_bytes(), copies).map_err(errno::kernel)?;
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
    win.frames.store(frames, Ordering::Release);
    win.dirty.store(false, Ordering::Release);
    for (cell, value) in win.shape.iter().zip([w, h, stride, format, buffers]) {
        cell.store(value, Ordering::Release);
    }
    let (cap_w, cap_h) = table::capacity(format, stride, len);
    win.cap[0].store(cap_w, Ordering::Release);
    win.cap[1].store(cap_h, Ordering::Release);
    // SAFETY: no thread but this one knows the window yet (`taking` is clear).
    unsafe { *win.stash.0.get() = Taker::new() };
    let generation = GENERATION.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
    win.generation.store(generation, Ordering::Release);
    Ok(Window {
        width: w,
        height: h,
        stride,
        format,
        buffers,
        generation,
        pixels: [pixels[0], pixels[1], pixels[2]],
    })
}

/// The window `win` is open: its record.
fn opened(win: i32) -> Result<&'static Win, i32> {
    let w = usize::try_from(win)
        .ok()
        .and_then(|k| WINS.get(k))
        .ok_or(EBADF)?;
    if w.state.load(Ordering::Acquire) != OPEN {
        return Err(EBADF);
    }
    Ok(w)
}

/// The process subscribed as the window manager (`exec` is refused then).
pub(crate) fn manager_subscribed() -> bool {
    MANAGER_LABEL.load(Ordering::Acquire) != 0
}

/// Some window is open.
fn any_open() -> Result<(), i32> {
    if MANAGER_LABEL.load(Ordering::Acquire) != 0
        || WINS.iter().any(|w| w.state.load(Ordering::Acquire) == OPEN)
    {
        Ok(())
    } else {
        Err(EBADF)
    }
}

fn alive(w: &Win) -> Result<(), i32> {
    if w.gone.load(Ordering::Acquire) {
        Err(ENODEV)
    } else {
        Ok(())
    }
}

/// Updates the account in one compare-and-swap loop; None without a window.
fn account<R>(w: &Win, f: impl Fn(&mut Buffers) -> R) -> Option<R> {
    let mut word = w.account.load(Ordering::Acquire);
    loop {
        let mut buffers = Buffers::from_raw(word)?;
        let result = f(&mut buffers);
        match w.account.compare_exchange_weak(
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

/// What the channel brought: the service's bits go to the account of the
/// window the label names (and wait there for `wait`); CLIENT_GONE of the
/// service's copy of the channel marks that window gone; the timer's
/// expiries, the wake and anything else are passed over. Whether service
/// bits came.
fn absorb(got: &Received) -> bool {
    if let Received::Notification {
        source: Source::Session,
        label,
        bits,
        ..
    } = got
        && table::is_manager_label(*label)
        && MANAGER_LABEL.load(Ordering::Acquire) == *label
    {
        if bits & rt::abi::CLIENT_GONE != 0 {
            MANAGER_GONE.store(true, Ordering::Release);
        }
        if bits & proto_comp::EVENTS_BIT != 0 {
            MANAGER_PENDING.store(true, Ordering::Release);
            return true;
        }
        return false;
    }
    if let Received::Notification {
        source: Source::Session,
        label,
        bits,
        ..
    } = got
        && let Some(slot) = table::slot_of(*label)
        && WINS[slot].label.load(Ordering::Acquire) == *label
    {
        let w = &WINS[slot];
        if bits & rt::abi::CLIENT_GONE != 0 {
            w.gone.store(true, Ordering::Release);
        }
        if bits & u64::from(layout::BITS) != 0 {
            account(w, |buffers| buffers.bits(*bits));
            return true;
        }
    }
    false
}

/// Takes what waits on the channel without blocking. Service bits stay in
/// the accounts for the next `wait`. A `wait` in another thread may have set
/// its timer or be about to block on exactly what was taken (the timer's
/// expiry, an earlier wake, a bit), so when anything at all was taken and a
/// thread waits, one wake goes after the loop: the waiter looks again at the
/// accounts and at its time (`comp_client::account::should_wake`).
fn drain() {
    let own = channel();
    let mut taken = 0;
    while let Ok(got) = sys::try_receive(&own) {
        // What a waiter may sit on: the service's notifications and a timer's
        // expiry. A wake of another thread is not echoed.
        let matters = matches!(
            got,
            Received::Notification {
                source: Source::Session | Source::Timer,
                ..
            }
        );
        absorb(&got);
        if matters {
            taken += 1;
        }
    }
    if comp_client::account::should_wake(taken, WAITING.load(Ordering::Acquire)) {
        let _ = sys::notify(&own, WAKE);
    }
}

/// `stafeto_window_info`: the window as `open` described it (its size, the
/// bytes of a line, the format, the number of buffers and where each lies in
/// the process) and its generation; EBADF for a number that is no open window.
/// The values are those of the open window, and a window closed and opened
/// again has another generation. The size is the size of the last `resize`.
pub fn info(win: i32) -> Result<Window, i32> {
    let w = opened(win)?;
    let before = w.generation.load(Ordering::Acquire);
    let pixel = |k: usize| w.pixels[k].load(Ordering::Acquire) as usize;
    let window = Window {
        width: w.shape(0),
        height: w.shape(1),
        stride: w.shape(2),
        format: w.shape(3),
        buffers: w.shape(4),
        generation: before,
        pixels: [pixel(0), pixel(1), pixel(2)],
    };
    // A window closed, or closed and opened again, while the description was
    // read has another generation or none.
    opened(win)?;
    if w.generation.load(Ordering::Acquire) != before {
        return Err(EBADF);
    }
    Ok(window)
}

/// `stafeto_window_capacity`: the most width and height `resize` takes.
pub fn capacity(win: i32) -> Result<(u32, u32), i32> {
    let w = opened(win)?;
    if w.shape(3) == layout::A8 {
        return Ok((0, 0));
    }
    Ok((
        w.cap[0].load(Ordering::Acquire),
        w.cap[1].load(Ordering::Acquire),
    ))
}

/// `stafeto_window_free_buffers`: the free buffers by the account; 0 for a
/// window that is not open.
pub fn free(win: i32) -> u32 {
    let Ok(w) = opened(win) else {
        return 0;
    };
    account(w, |buffers| buffers.free()).unwrap_or(0)
}

/// `stafeto_window_post`: POST of `buffer` with `rects`.
pub fn post(win: i32, buffer: u32, rects: &[layout::Rect]) -> Result<(), i32> {
    let w = opened(win)?;
    alive(w)?;
    let width = w.shape(0);
    let height = w.shape(1);
    let merged = damage::merge(rects, width, height)?;
    // Bits that already wait free the buffers they name.
    drain();
    account(w, |buffers| buffers.take(buffer)).ok_or(EBADF)??;
    let sent = send_post(w, buffer, merged.as_slice());
    // The service sends the bit of a buffer the post replaced before it
    // replies, so the account sees "free again at once" when the call
    // returns.
    drain();
    if sent.is_err() {
        account(w, |buffers| buffers.give_back(buffer));
    } else {
        w.dirty.store(true, Ordering::Release);
    }
    sent
}

fn send_post(w: &Win, buffer: u32, rects: &[layout::Rect]) -> Result<(), i32> {
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
    let reply =
        call(&w.session(), request.as_bytes(), Outgoing::new()).map_err(|e| refused(w, e))?;
    match status_of(&reply) {
        Status::Ok => Ok(()),
        status => Err(refusal(w, status)),
    }
}

/// `stafeto_window_set_title` and `_set_app_id`: SET_TEXT of `which` with
/// `text`. EINVAL for more than `TEXT_MAX` bytes or a zero byte; the service
/// judges the rest (UTF-8).
pub fn set_text(win: i32, which: u32, text: &[u8]) -> Result<(), i32> {
    let w = opened(win)?;
    alive(w)?;
    if text.len() > proto_comp::TEXT_MAX || text.contains(&0) {
        return Err(EINVAL);
    }
    let mut bytes = [0; proto_comp::TEXT_MAX];
    bytes[..text.len()].copy_from_slice(text);
    let set = SetText {
        which,
        len: text.len(),
        bytes,
    };
    let mut request = Writer::new();
    set.write(&mut request).map_err(|_| EINVAL)?;
    let reply =
        call(&w.session(), request.as_bytes(), Outgoing::new()).map_err(|e| refused(w, e))?;
    match status_of(&reply) {
        Status::Ok => Ok(()),
        status => Err(refusal(w, status)),
    }
}

/// `stafeto_window_resize`: SIZE of `width` by `height` (the size of the next
/// POST, with `serial` of the CONFIGURE it answers or 0). EINVAL for an empty
/// size or one past the capacity, without asking the service; the service may
/// refuse a size that takes the window out of the screen (EINVAL). The size
/// `info` and the rectangles of POST use is the new one once the service took
/// the request.
pub fn resize(win: i32, width: u32, height: u32, serial: u32) -> Result<(), i32> {
    let w = opened(win)?;
    alive(w)?;
    // A mask has no size of its own to change.
    if w.shape(3) == layout::A8 {
        return Err(EINVAL);
    }
    let cap = (
        w.cap[0].load(Ordering::Acquire),
        w.cap[1].load(Ordering::Acquire),
    );
    table::resize_ok(width, height, cap)?;
    let mut request = Writer::new();
    Size {
        w: width,
        h: height,
        serial,
    }
    .write(&mut request)
    .map_err(|_| EINVAL)?;
    let reply =
        call(&w.session(), request.as_bytes(), Outgoing::new()).map_err(|e| refused(w, e))?;
    match status_of(&reply) {
        Status::Ok => {
            w.shape[0].store(width, Ordering::Release);
            w.shape[1].store(height, Ordering::Release);
            Ok(())
        }
        status if status == proto_comp::code(proto_comp::NOT_ALLOWED) => Err(EPERM),
        status => Err(refusal(w, status)),
    }
}

/// What a wait is for: the bits of a window (`stafeto_window_wait`), a free
/// buffer of a mask of a window (`stafeto_window_wait_free`) or the bits of
/// any window (`stafeto_windows_wait`).
#[derive(Clone, Copy)]
enum Goal {
    Bits(usize),
    Free(usize, u32),
    Any,
}

impl Goal {
    /// The goal's windows are open.
    fn open(self) -> Result<(), i32> {
        match self {
            Goal::Bits(k) | Goal::Free(k, _) => opened(k as i32).map(|_| ()),
            Goal::Any => any_open(),
        }
    }

    /// The service has not taken the goal's window away (a wait for any window
    /// reports a gone window with `GONE` in its bits).
    fn alive(self) -> Result<(), i32> {
        match self {
            Goal::Bits(k) | Goal::Free(k, _) => alive(&WINS[k]),
            Goal::Any => Ok(()),
        }
    }

    /// What changes when the goal's windows are closed and opened again: the
    /// window's generation, or the shared channel.
    fn epoch(self) -> u64 {
        match self {
            Goal::Bits(k) | Goal::Free(k, _) => {
                u64::from(WINS[k].generation.load(Ordering::Acquire))
            }
            Goal::Any => CHANNEL.load(Ordering::Acquire),
        }
    }
}

/// Whether the goal is reached: the bits it takes (the pending ones, once) or
/// the free buffers of the mask (the bits stay for the program's wait). For a
/// wait across the windows `out` gets the bits of each window.
fn reached(goal: Goal, out: &mut [u32; WINDOWS_MAX]) -> Option<u32> {
    let got = match goal {
        Goal::Bits(k) => account(&WINS[k], |buffers| buffers.take_pending()),
        Goal::Free(k, mask) => account(&WINS[k], |buffers| buffers.free() & mask),
        Goal::Any => {
            let mask = table::report(
                WINS.iter().map(|w| {
                    (w.state.load(Ordering::Acquire) == OPEN).then(|| {
                        (
                            account(w, |buffers| buffers.take_pending()).unwrap_or(0),
                            w.gone.load(Ordering::Acquire),
                        )
                    })
                }),
                out,
            );
            // The manager's ring is one more thing a wait across the windows
            // tells of, once for each time its bit came; a service that went
            // is told until the process ends.
            let pending = MANAGER_LABEL.load(Ordering::Acquire) != 0
                && MANAGER_PENDING.swap(false, Ordering::AcqRel);
            let gone =
                MANAGER_LABEL.load(Ordering::Acquire) != 0 && MANAGER_GONE.load(Ordering::Acquire);
            Some(table::with_manager(mask, pending, gone))
        }
    };
    got.filter(|&bits| bits != 0)
}

/// `stafeto_window_wait`: the bits that came on the window's channel, as
/// the header says. The wait is `fast::wait`'s: a try without waiting, the
/// signals, the entries deferred, a receive with a timer for the bound.
pub fn wait(win: i32, timeout_ns: u64) -> Result<u32, i32> {
    opened(win)?;
    wait_for(timeout_ns, Goal::Bits(win as usize), &mut [0; WINDOWS_MAX])
}

/// `stafeto_windows_wait`: waits until any window has bits (or has gone) and
/// returns the mask of those windows; `bits` gets each window's bits (0 for
/// the others). EBADF when no window is open.
pub fn wait_all(timeout_ns: u64, bits: &mut [u32; WINDOWS_MAX]) -> Result<u32, i32> {
    wait_for(timeout_ns, Goal::Any, bits)
}

/// `stafeto_window_wait_free`: waits until a buffer of `mask` is free by the
/// account and returns the free ones among them. The bits the service sent
/// stay for `wait` (events among them). While another thread holds the wait
/// it takes what waits on the channel without blocking and pauses, so it does
/// not depend on that thread running. EINVAL for a mask that is empty or names
/// a bit that is no buffer of the window. The program's own wait looks beside
/// it in the same way while it holds the wait, so it gets no EBUSY from it.
pub fn wait_free(win: i32, mask: u32, timeout_ns: u64) -> Result<u32, i32> {
    let w = opened(win)?;
    if !comp_client::account::mask_ok(mask, w.shape(4)) {
        return Err(EINVAL);
    }
    wait_for(
        timeout_ns,
        Goal::Free(win as usize, mask),
        &mut [0; WINDOWS_MAX],
    )
}

/// A free-buffer wait holds `WAITING`.
static FREE_HELD: AtomicBool = AtomicBool::new(false);

struct FreeHeld;

impl FreeHeld {
    fn set() -> FreeHeld {
        FREE_HELD.store(true, Ordering::Release);
        FreeHeld
    }
}

impl Drop for FreeHeld {
    fn drop(&mut self) {
        FREE_HELD.store(false, Ordering::Release);
    }
}

/// The errno of a refusal of the kernel on the channel: a window closed
/// meanwhile (by another thread) is EBADF.
fn channel_errno(goal: Goal) -> i32 {
    if goal.open().is_err() { EBADF } else { EIO }
}

/// The pause of a wait beside another waiter.
const BESIDE_PAUSE_NS: i64 = 1_000_000;

fn wait_for(timeout_ns: u64, goal: Goal, out: &mut [u32; WINDOWS_MAX]) -> Result<u32, i32> {
    goal.open()?;
    goal.alive()?;
    let until = crate::wait::now().saturating_add(timeout_ns);
    let Some(_waiting) = Flag::take(&WAITING) else {
        // A free-buffer wait (a swap) holds the wait: the program's wait looks
        // beside it as the swap looks beside the program's, so a poll never
        // gets EBUSY from a swap. Another wait of the program still does.
        return match goal {
            Goal::Bits(_) | Goal::Any if !FREE_HELD.load(Ordering::Acquire) => Err(EBUSY),
            _ => wait_beside(until, goal, out),
        };
    };
    // Held by a free-buffer wait until this call ends.
    let _free_held = matches!(goal, Goal::Free(..)).then(FreeHeld::set);
    let own = channel();
    let timer = Handle::<Timer>::borrowed(rt::abi::Handle(TIMER.load(Ordering::Acquire)));
    let block = threads::own_block();
    let epoch = goal.epoch();
    // No limit (UINT64_MAX): no timer is set, the receive waits for a bit.
    let unlimited = timeout_ns == u64::MAX;
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
                Err(_) => return Err(channel_errno(goal)),
            }
        }
        // A window closed meanwhile (by another thread) ends the wait.
        goal.open()?;
        if goal.epoch() != epoch {
            return Err(EBADF);
        }
        goal.alive()?;
        if let Some(bits) = reached(goal, out) {
            return Ok(bits);
        }
        if !unlimited && crate::wait::now() >= until {
            return Err(ETIMEDOUT);
        }
        let handled = block.handled.load(Ordering::SeqCst);
        if crate::signals::pending_unblocked() {
            crate::signals::deliver_now();
            return Err(EINTR);
        }
        if !unlimited {
            sys::timer_set(&timer, until).map_err(|_| EIO)?;
        }
        let cancel = || {
            if !unlimited {
                let _ = sys::timer_cancel(&timer);
            }
        };
        let guard = rt::upcall::defer_entries().map_err(|_| EIO)?;
        if block.handled.load(Ordering::SeqCst) != handled || crate::signals::pending_unblocked() {
            drop(guard);
            cancel();
            crate::signals::deliver_now();
            return Err(EINTR);
        }
        let got = sys::receive(&own);
        drop(guard);
        match got {
            Ok(got) => {
                absorb(&got);
                // The timer is armed no more once something else came.
                cancel();
            }
            Err(Error::Interrupted) => {
                cancel();
                crate::signals::deliver_now();
                return Err(EINTR);
            }
            Err(_) => return Err(channel_errno(goal)),
        }
    }
}

/// The wait for a free buffer while another thread holds the wait: what
/// waits on the channel is taken without blocking (`drain` wakes the other
/// waiter, which looks again), and a short pause follows.
fn wait_beside(until: u64, goal: Goal, out: &mut [u32; WINDOWS_MAX]) -> Result<u32, i32> {
    let epoch = goal.epoch();
    loop {
        goal.open()?;
        if goal.epoch() != epoch {
            return Err(EBADF);
        }
        drain();
        goal.alive()?;
        if let Some(bits) = reached(goal, out) {
            return Ok(bits);
        }
        if crate::wait::now() >= until {
            return Err(ETIMEDOUT);
        }
        if crate::signals::pending_unblocked() {
            crate::signals::deliver_now();
            return Err(EINTR);
        }
        if let Err(errno) = crate::threads::sleep::pause(BESIDE_PAUSE_NS)
            && errno == EINTR
        {
            return Err(EINTR);
        }
    }
}

/// `stafeto_window_events`: up to `out.len()` events of the ring and the
/// flags, and fewer only when the ring is empty (`comp_client::events::Taker`
/// asks the service again while its replies are full). Events the service
/// gave beyond `out` wait for the next call.
pub fn events(win: i32, out: &mut [WindowEvent]) -> Result<(usize, u32), i32> {
    let w = opened(win)?;
    if out.is_empty() {
        return Err(EINVAL);
    }
    let Some(_taking) = Flag::take(&w.taking) else {
        return Err(EBUSY);
    };
    // SAFETY: `taking` is held.
    let taker = unsafe { &mut *w.stash.0.get() };
    taker.take(out, |list| {
        alive(w)?;
        let reply = call(
            &w.session(),
            &Method::Events.header().bytes(),
            Outgoing::new(),
        )
        .map_err(|e| refused(w, e))?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut n = 0;
        let flags = proto_comp::read_events(reply.bytes(&mut buffer), |event| {
            if n < list.len() {
                list[n] = event.into();
                n += 1;
            }
        })
        .map_err(|s| refusal(w, s))?;
        Ok((n, flags & proto_comp::LOST != 0))
    })
}

/// `stafeto_window_shown`: until the service has shown a frame since the
/// last POST and makes none.
pub fn shown(win: i32, timeout_ns: u64) -> Result<(), i32> {
    let w = opened(win)?;
    alive(w)?;
    let display = crate::display::session().ok_or(ENODEV)?;
    let display = Handle::<Channel>::borrowed(display);
    let until = crate::wait::now().saturating_add(timeout_ns);
    loop {
        let d = describe(&display)?;
        let grown = d.frames.wrapping_sub(w.frames.load(Ordering::Acquire)) as i32 > 0;
        if d.busy == 0 && (grown || !w.dirty.load(Ordering::Acquire)) {
            w.frames.store(d.frames, Ordering::Release);
            w.dirty.store(false, Ordering::Release);
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
/// its buffers leave the map and the process. Safe on a state that is part
/// made.
fn release_window(w: &Win) {
    for cell in &w.pixels {
        let at = cell.swap(0, Ordering::AcqRel);
        if at == 0 {
            continue;
        }
        if let Err(errno) = crate::allocation::heap(|state| state.unmap_window_piece(at as usize))
            // Once: a program that closes windows in a loop would repeat it.
            && !UNMAP_TOLD.swap(true, Ordering::AcqRel)
        {
            rt::println!("posix: a buffer of the window could not be unmapped (errno {errno})");
        }
    }
    let raw = w.session.swap(0, Ordering::AcqRel);
    if raw != 0 {
        drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
    }
    w.account.store(0, Ordering::Release);
    w.label.store(0, Ordering::Release);
    w.id.store(0, Ordering::Release);
}

/// The timer and the channel close, when no window is open or being made.
fn drop_channel_if_unused() {
    if MANAGER_LABEL.load(Ordering::Acquire) != 0
        || WINS
            .iter()
            .any(|w| w.state.load(Ordering::Acquire) != CLOSED)
    {
        return;
    }
    drop_channel();
}

fn drop_channel() {
    let raw = TIMER.swap(0, Ordering::AcqRel);
    if raw != 0 {
        drop(Handle::<Timer>::from_raw(rt::abi::Handle(raw)));
    }
    let raw = CHANNEL.swap(0, Ordering::AcqRel);
    if raw != 0 {
        drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
    }
}

/// `stafeto_window_close`: EBADF for a number that is no open window.
pub fn close(win: i32) -> Result<(), i32> {
    let _lock = lock();
    let Some(w) = usize::try_from(win).ok().and_then(|k| WINS.get(k)) else {
        return Err(EBADF);
    };
    if w.state
        .compare_exchange(OPEN, OPENING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(EBADF);
    }
    release_window(w);
    w.state.store(CLOSED, Ordering::Release);
    // A thread that waits on the window (or on all of them) looks again and
    // finds it gone.
    if WAITING.load(Ordering::Acquire) {
        let _ = sys::notify(&channel(), WAKE);
    }
    drop_channel_if_unused();
    Ok(())
}

/// A forked child has no windows: the parent's handles name nothing of its
/// table and are forgotten, never closed, and its buffers were left out of
/// the child's map (`allocation::after_fork`).
///
/// # Safety
/// The child's only thread, before anything else of the layer runs.
pub unsafe fn after_fork() {
    for cell in [&CHANNEL, &TIMER, &MANAGER_LABEL] {
        cell.store(0, Ordering::Release);
    }
    for flag in [&MANAGER_PENDING, &MANAGER_GONE] {
        flag.store(false, Ordering::Release);
    }
    manager::after_fork();
    for w in &WINS {
        w.session.store(0, Ordering::Release);
        w.id.store(0, Ordering::Release);
        w.account.store(0, Ordering::Release);
        w.label.store(0, Ordering::Release);
        for cell in &w.pixels {
            cell.store(0, Ordering::Release);
        }
        for flag in [&w.gone, &w.taking, &w.dirty] {
            flag.store(false, Ordering::Release);
        }
        // SAFETY: the child's only thread.
        unsafe { *w.stash.0.get() = Taker::new() };
        w.state.store(CLOSED, Ordering::Release);
    }
    for flag in [&WAITING, &FREE_HELD, &LOCK] {
        flag.store(false, Ordering::Release);
    }
}

/// `exec` takes the windows back with the old image.
pub(crate) fn release_for_exec() {
    for w in &WINS {
        if w.state.swap(CLOSED, Ordering::AcqRel) == OPEN {
            release_window(w);
        }
    }
    MANAGER_LABEL.store(0, Ordering::Release);
    MANAGER_PENDING.store(false, Ordering::Release);
    MANAGER_GONE.store(false, Ordering::Release);
    drop_channel_if_unused();
}
