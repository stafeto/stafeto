// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guest probe of focus and composition of two clients (`gpu` in the
//! image of `focus::TABLE`, services/compositor, stage G2). Four programs of
//! init, whose roles the byte of their own arguments names:
//!
//! - `a`, a client with an opaque window of 240 by 180 at (40, 40): its events
//!   (FOCUS_IN and FOCUS_OUT, the keys that came while it had the focus, the
//!   click of the injected pointer and of the tablet) must be exactly the
//!   list it expects, and it lives on after the second client ends.
//! - `b`, a client with a window of 240 by 180 at (160, 100) whose points
//!   have an alpha (a half, opaque, none), over the first window: it must see
//!   the keys of the time it had the focus and no other, and no pointer.
//! - `m`, the manager: it hears the Super keys alone (the windows see none),
//!   and on Super and Tab it gives the focus and the top place to the window
//!   that has neither.
//! - `i`, the input: it injects the keys and the pointer of the scene and prints
//!   the CRC-32 of the screen as it should look after each step (the overlap
//!   with its transparency, a click that raises the first window, the
//!   manager's switch, the screen after the second client ended), which xtask
//!   compares with QEMU's screenshot. The service puts the pointer on the
//!   display's cursor pipeline (DESCRIBE's CURSOR_PLANE, which this role
//!   requires), so no CRC has the pointer's picture: the screenshot never
//!   holds the cursor, and a service that drew it into the frame would
//!   differ. That the cursor reached the device is the trace of QEMU's
//!   display, which xtask reads.
//!
//! The image of the window manager (`focus::WM_TABLE`, the second run of
//! xtask's focus-probe) has the program `wm` (apps/wm) as the manager, with a
//! keyboard's driver in the image, and three roles of this program:
//!
//! - `p`, a native client with a window of 240 by 180 at (40, 40): the focus
//!   the manager gives it when it is made, the focus it loses when the window
//!   of the first revision is made, the chord that brings it back, the key
//!   it gets while it has the focus, and the focus the compositor's own rule
//!   gives it when the other client ends, must be exactly its list of events.
//! - `o`, a client of the first revision (the window of the whole screen
//!   OPEN gives, the keys of the session of focus OPEN gives): the keys it
//!   reads are those of the time its window had the focus and no others.
//! - `j`, the input: it injects the keys of the scene (a key to the window
//!   of the first revision, the chord of Super and Tab, a key to the native
//!   window, the chord again, a key to the first, the chord that ends the
//!   manager, a key to the window that kept the focus, and a key to the other
//!   once the first has ended), and tells when the manager is gone.
//!
//! The image of the top-window protocol (`focus::TOP_TABLE`, the third image of
//! xtask's focus-probe) has two roles:
//!
//! - `t`, a client with a window of 200 by 150 whose buffers hold the whole screen
//!   (so it can be resized): it sets its title and its application's kind, checks
//!   the refusals of SIZE and of SET_TEXT, answers a CONFIGURE with a SIZE and,
//!   when it is asked, with the POST that carries the new size, and ends on
//!   CLOSE_REQUEST.
//! - `w`, a manager: it reads the client's texts and capacity (INFO), makes a
//!   frame of its own window, links it to the client (LINK), moves the pair while
//!   the client has said its new size but not posted it, asks for the size
//!   (CONFIGURE), resizes the frame when RESIZED comes, and closes the client
//!   (CLOSE). It prints the CRC-32 of the screen after the link, after the move,
//!   after the new size and after the close, which xtask compares with QEMU's
//!   screenshot.
//!
//! Each check prints its line, and the last of a role says `focus-probe: ok`;
//! xtask reads them.

#![no_std]
#![no_main]

use abi::{Access, Error, MESSAGE_MAX, Rights, Source};
use core::cell::Cell;
use proto_comp::{
    Attach, BUTTON, CREATE, CURSOR_PLANE, Create, Description, EVENTS_BIT, Event, FOCUS_IN,
    FOCUS_OUT, FORMAT_ARGB8888, FORMAT_XRGB8888, HAS_MANAGER, KEY, MAX_EVENTS, MOVE, Method, Post,
    Rect, WindowRecord, manage,
};
use proto_gpu::{HEIGHT, WIDTH};
use proto_init::ServiceArgs;
use proto_input::Event as KeyEvent;
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Memory, Outgoing, Resource};
use rt::sys::Received;
use rt::wait::{Waited, Waiter};
use rt::{Handle, sys, time};

rt::entry!(main);

/// Where the probe maps its buffers.
const MAP_AT: usize = 0x20_0000_0000;
const MAP_STEP: usize = 0x100_0000;
/// The pause after a frame for the host to photograph it, when the run has
/// the wall clock; the retry period; the longest wait.
const SNAPSHOT_NS: u64 = if cfg!(feature = "quick") {
    0
} else {
    2_500_000_000
};
const RETRY_NS: u64 = 5_000_000;
const WAIT_NS: u64 = 60_000_000_000;

/// Linux's key codes of the scene, and the left button.
const KEY_A: u16 = 30;
const KEY_S: u16 = 31;
const KEY_D: u16 = 32;
const KEY_F: u16 = 33;
const KEY_TAB: u16 = 15;
const KEY_B: u16 = 48;
const KEY_C: u16 = 46;
const KEY_E: u16 = 18;
const KEY_H: u16 = 35;
const KEY_Q: u16 = 16;
const KEY_SUPER: u16 = 125;
const BTN_LEFT: u16 = 0x110;

/// The windows: the first opaque, the second with an alpha, both 240 by 180.
const A: Rect = Rect {
    x: 40,
    y: 40,
    w: 240,
    h: 180,
};
const B: Rect = Rect {
    x: 160,
    y: 100,
    w: 240,
    h: 180,
};
/// The windows of the scenes of sixteen windows (`Probe::many`): the service's
/// most, the windows of a context, and the fifteen of the run under -icount,
/// which lie over the first client's.
const WINDOWS: usize = 16;
const PER_CONTEXT: usize = 4;
const MANY: usize = WINDOWS - 1;
/// Where the injected pointer clicks (in A alone), and where the tablet does
/// (in A, with B gone).
const CLICK: (i32, i32) = (60, 60);
const TABLET: (i32, i32) = (200, 120);

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    let own = ServiceArgs::read(start.args()).map_or(&[][..], |a| a.own);
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let Ok(channel) = sys::channel_create(level) else {
        return 1;
    };
    let Ok(waiter) = Waiter::new(&channel, 0, level) else {
        return 1;
    };
    let probe = Probe {
        process: &start.process,
        parent: &start.parent,
        channel,
        waiter,
        maps: Cell::new(0),
        bits: Cell::new(0),
    };
    let result = match own {
        b"a" => probe.client(false),
        b"b" => probe.client(true),
        b"m" => probe.manager(),
        b"i" => probe.input(),
        b"n" => probe.many(),
        b"p" => probe.wm_new(),
        b"o" => probe.wm_old(),
        b"j" => probe.wm_input(),
        b"t" => probe.top_client(),
        b"w" => probe.top_manager(),
        _ => Err("an unknown role"),
    };
    match result {
        Ok(()) => {
            rt::println!("focus-probe: ok");
            0
        }
        Err(reason) => {
            rt::println!("focus-probe: failed: {reason}");
            2
        }
    }
}

/// The reason of a failed step, in the log with what the call said.
fn say<E: core::fmt::Debug>(what: &'static str) -> impl Fn(E) -> &'static str {
    move |e| {
        rt::println!("focus-probe: {what}: {e:?}");
        what
    }
}

/// What a request to the service came to.
#[derive(Debug, PartialEq, Eq)]
enum Fail {
    Status(Status),
    Kernel(Error),
    Bad(&'static str),
}

/// The objects of a window's buffers and where they are mapped.
type Buffers = ([Option<Handle<Memory>>; 3], [usize; 3]);

/// The windows of `Probe::spawn` and the objects of their buffers.
type Made = (
    [Option<Handle<Channel>>; WINDOWS],
    [Option<[Option<Handle<Memory>>; 3]>; WINDOWS],
);

struct Probe<'a> {
    process: &'a Handle<rt::handle::Process>,
    parent: &'a Handle<Channel>,
    channel: Handle<Channel>,
    waiter: Waiter,
    maps: Cell<usize>,
    /// The bits the service sent the channel and nobody read yet.
    bits: Cell<u64>,
}

/// The status of a reply and the reply.
fn status_of(reply: sys::Reply) -> Result<(Status, sys::Reply), Fail> {
    let mut buffer = [0; MESSAGE_MAX];
    let word = {
        let bytes = reply.bytes(&mut buffer);
        let word = bytes.get(..4).ok_or(Fail::Bad("a short reply"))?;
        [word[0], word[1], word[2], word[3]]
    };
    Ok((Status::from_code(u32::from_le_bytes(word)), reply))
}

fn call(session: &Handle<Channel>, request: &[u8]) -> Result<(Status, sys::Reply), Fail> {
    status_of(sys::send(session, request).map_err(Fail::Kernel)?)
}

fn call_with(
    session: &Handle<Channel>,
    request: &[u8],
    handles: Outgoing,
) -> Result<(Status, sys::Reply), Fail> {
    let reply = sys::send_handles(session, request, handles)
        .map_err(|refused| Fail::Kernel(refused.error))?;
    status_of(reply)
}

/// A request whose reply is its status: Ok for status 0.
fn plain(session: &Handle<Channel>, request: &[u8]) -> Result<(), Fail> {
    match call(session, request)? {
        (Status::Ok, _) => Ok(()),
        (status, _) => Err(Fail::Status(status)),
    }
}

/// The CRC-32 of IEEE 802.3, the one xtask computes over a screenshot's
/// colours.
struct Crc(u32);

const TABLE: [u32; 256] = {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

impl Crc {
    fn byte(&mut self, b: u8) {
        self.0 = TABLE[((self.0 ^ u32::from(b)) & 0xFF) as usize] ^ (self.0 >> 8);
    }

    fn point(&mut self, p: u32) {
        self.byte((p >> 16) as u8);
        self.byte((p >> 8) as u8);
        self.byte(p as u8);
    }
}

impl Probe<'_> {
    /// Waits `ns`, keeping the bits the service sends meanwhile.
    fn sleep(&self, ns: u64) {
        if ns == 0 {
            return;
        }
        let deadline = time::ticks_to_ns(time::now()).saturating_add(ns);
        while let Ok(Waited::Got(got)) = self.waiter.receive_until(&self.channel, deadline) {
            self.keep(&got);
        }
    }

    fn keep(&self, got: &Received) {
        if let Received::Notification {
            source: Source::Unlabeled,
            bits,
            ..
        } = got
        {
            self.bits.set(self.bits.get() | bits);
        }
    }

    /// Waits until the bits of `mask` came, at most WAIT_NS.
    fn wait_bits(&self, mask: u64) -> bool {
        let deadline = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        while self.bits.get() & mask != mask {
            match self.waiter.receive_until(&self.channel, deadline) {
                Ok(Waited::Got(got)) => self.keep(&got),
                _ => return false,
            }
        }
        self.bits.set(self.bits.get() & !mask);
        true
    }

    fn display(&self) -> Result<Handle<Channel>, &'static str> {
        rt::service::connect(self.parent, "gpu").map_err(say("connect to gpu"))
    }

    fn describe(&self, display: &Handle<Channel>) -> Result<Description, Fail> {
        let reply = sys::send(display, &Method::Describe.header().bytes()).map_err(Fail::Kernel)?;
        let mut buffer = [0; MESSAGE_MAX];
        Description::read(reply.bytes(&mut buffer)).map_err(Fail::Status)
    }

    /// DESCRIBE until the service has its screen (it says CLEARING while
    /// the driver is being set up).
    fn describe_when_ready(&self, display: &Handle<Channel>) -> Result<Description, &'static str> {
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        loop {
            match self.describe(display) {
                Ok(d) => return Ok(d),
                Err(Fail::Status(s)) if s == proto_gpu::code(proto_gpu::CLEARING) => {}
                Err(_) => return Err("DESCRIBE"),
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err("the service never had its screen");
            }
            self.sleep(RETRY_NS);
        }
    }

    /// A window: its session and number.
    fn create_as(
        &self,
        display: &Handle<Channel>,
        rect: Rect,
        format: u32,
    ) -> Result<(Handle<Channel>, u32), Fail> {
        let notify = sys::handle_duplicate(&self.channel, Rights::NOTIFY | Rights::TRANSFER)
            .map_err(Fail::Kernel)?;
        let mut w = Writer::new();
        Create {
            x: rect.x,
            y: rect.y,
            w: rect.w,
            h: rect.h,
            format,
            flags: 0,
        }
        .write(&mut w)
        .map_err(Fail::Status)?;
        let (status, mut reply) = call_with(display, w.as_bytes(), [notify.erase()].into())?;
        if status != Status::Ok {
            return Err(Fail::Status(status));
        }
        let mut buffer = [0; MESSAGE_MAX];
        let bytes = reply.bytes(&mut buffer);
        let id = bytes
            .get(4..8)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or(Fail::Bad("WINDOW_CREATE's reply"))?;
        let session = reply
            .handles
            .take::<Channel>(0)
            .map_err(|_| Fail::Bad("WINDOW_CREATE's handle"))?;
        Ok((session, id))
    }

    /// `count` buffers of `h` lines of `stride` bytes, mapped for writing:
    /// the objects and the addresses.
    fn buffers(&self, count: usize, bytes: u64) -> Result<Buffers, &'static str> {
        let mut objects = [const { None }; 3];
        let mut at = [0; 3];
        let len = bytes.div_ceil(4096) * 4096;
        for b in 0..count {
            let memory = sys::mem_create(len).map_err(say("mem_create"))?;
            let n = self.maps.get();
            self.maps.set(n + 1);
            at[b] = MAP_AT + n * MAP_STEP;
            sys::mem_map(self.process, &memory, 0, len, at[b], Access::ReadWrite)
                .map_err(say("map a buffer"))?;
            objects[b] = Some(memory);
        }
        Ok((objects, at))
    }

    fn attach_as(
        &self,
        window: &Handle<Channel>,
        stride: u32,
        objects: &[Option<Handle<Memory>>],
        format: u32,
    ) -> Result<(), Fail> {
        let mut w = Writer::new();
        Attach {
            count: objects.len() as u32,
            stride,
            format,
        }
        .write(&mut w)
        .map_err(Fail::Status)?;
        let mut handles = Outgoing::new();
        for object in objects.iter().flatten() {
            let copy = sys::handle_duplicate(object, Rights::MAP_READ | Rights::TRANSFER)
                .map_err(Fail::Kernel)?;
            handles
                .push(copy.erase())
                .map_err(|_| Fail::Bad("too many"))?;
        }
        match call_with(window, w.as_bytes(), handles)? {
            (Status::Ok, _) => Ok(()),
            (status, _) => Err(Fail::Status(status)),
        }
    }

    fn post(&self, window: &Handle<Channel>, buffer: u32, rects: &[Rect]) -> Result<(), Fail> {
        let mut w = Writer::new();
        Post::new(buffer, rects)
            .and_then(|p| p.write(&mut w))
            .map_err(Fail::Status)?;
        plain(window, w.as_bytes())
    }
}

// ------------------------------------------------------------ the pictures

/// The point (x, y) of the first window: opaque.
fn a_point(x: u32, y: u32) -> u32 {
    let r = x * 255 / (A.w - 1);
    let g = y * 255 / (A.h - 1);
    let b = (x ^ y) & 0xFF;
    r << 16 | g << 8 | b
}

/// The point (x, y) of the second window, premultiplied: none at the bottom,
/// opaque at the right, a half elsewhere.
fn b_point(x: u32, y: u32) -> u32 {
    let r = x * 255 / (B.w - 1);
    let g = y * 255 / (B.h - 1);
    if y >= 150 {
        0
    } else if x >= 180 {
        0xFF00_0000 | r << 16 | g << 8 | 0x30
    } else {
        let half = |c: u32| c * 0x80 / 255;
        0x8000_0000 | half(r) << 16 | half(g) << 8 | half(0x60)
    }
}

/// pixman's multiplication of two bytes, rounded.
fn mul(a: u32, b: u32) -> u32 {
    let t = a * b + 0x80;
    ((t >> 8) + t) >> 8
}

/// A premultiplied point laid over another, channel by channel as pixman's
/// OVER does it onto XRGB8888.
fn over(dst: u32, src: u32) -> u32 {
    let alpha = src >> 24;
    if alpha == 0xFF {
        return src;
    }
    if src == 0 {
        return dst;
    }
    let inverse = 255 - alpha;
    let mut out = 0;
    for shift in [0, 8, 16] {
        let c = (mul((dst >> shift) & 0xFF, inverse) + ((src >> shift) & 0xFF)).min(255);
        out |= c << shift;
    }
    out
}

/// What the screen shows: the windows bottom first (A, B). The pointer is on
/// the display's cursor pipeline and is not in the screen's points.
fn expected_crc(order: [bool; 2], only_a: bool) -> u32 {
    let inside = |r: Rect, x: u32, y: u32| x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h;
    let mut crc = Crc(0xFFFF_FFFF);
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let mut point = 0;
            // `order[0]` true: A is below B.
            let layers: &[bool] = if only_a {
                &[true]
            } else if order[0] {
                &[true, false]
            } else {
                &[false, true]
            };
            for &is_a in layers {
                if is_a && inside(A, x, y) {
                    point = a_point(x - A.x, y - A.y);
                } else if !is_a && inside(B, x, y) {
                    point = over(point, b_point(x - B.x, y - B.y));
                }
            }
            crc.point(point);
        }
    }
    !crc.0
}

/// Window `k` of the scene of sixteen windows (`Probe::many` with the monitor):
/// staggered so that all of them share one region, every third XRGB8888 (the value
/// is the colour) and the others ARGB8888 (the value is premultiplied, an alpha
/// of 0x60 to 0xD8 and each channel under it).
fn sixteen_of(k: usize) -> (Rect, u32, u32) {
    let n = k as u32;
    // Steps of 8 across and 5 down: every window holds the region from (140, 85)
    // to (220, 120), so the damage of any post meets all sixteen.
    let rect = Rect {
        x: 20 + 8 * n,
        y: 10 + 5 * n,
        w: 200,
        h: 110,
    };
    let channel = |step: u32| (n * step + 40) & 0xFF;
    if k.is_multiple_of(3) {
        let colour = channel(53) << 16 | channel(97) << 8 | channel(29);
        return (rect, FORMAT_XRGB8888, colour);
    }
    let alpha = 0x60 + 8 * n;
    let under = |step: u32| channel(step) * alpha / 255;
    (
        rect,
        FORMAT_ARGB8888,
        alpha << 24 | under(61) << 16 | under(83) << 8 | under(37),
    )
}

/// What the screen shows with the sixteen windows of `sixteen_of`, in order,
/// over the black.
fn sixteen_crc() -> u32 {
    let inside = |r: Rect, x: u32, y: u32| x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h;
    let windows: [(Rect, u32, u32); WINDOWS] = core::array::from_fn(sixteen_of);
    let mut crc = Crc(0xFFFF_FFFF);
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let mut point = 0;
            for &(rect, format, value) in &windows {
                if !inside(rect, x, y) {
                    continue;
                }
                point = if format == FORMAT_ARGB8888 {
                    over(point, value)
                } else {
                    value
                };
            }
            crc.point(point);
        }
    }
    !crc.0
}

/// One event of a window's list, as the client expects it: the kind, the
/// code and the value (the coordinates are checked apart).
type Want = (u16, u16, i32);

const A_WANTS: [Want; 11] = [
    (FOCUS_IN, 0, 0),
    (FOCUS_OUT, 0, 0),
    (FOCUS_IN, 0, 0),
    (BUTTON, BTN_LEFT, 1),
    (BUTTON, BTN_LEFT, 0),
    (KEY, KEY_S, 1),
    (KEY, KEY_S, 0),
    (FOCUS_OUT, 0, 0),
    (FOCUS_IN, 0, 0),
    (KEY, KEY_F, 1),
    (KEY, KEY_F, 0),
];
/// Then the tablet's click on the surviving window.
const A_TABLET: [Want; 2] = [(BUTTON, BTN_LEFT, 1), (BUTTON, BTN_LEFT, 0)];
const B_WANTS: [Want; 7] = [
    (FOCUS_IN, 0, 0),
    (KEY, KEY_A, 1),
    (KEY, KEY_A, 0),
    (FOCUS_OUT, 0, 0),
    (FOCUS_IN, 0, 0),
    (KEY, KEY_D, 1),
    (KEY, KEY_D, 0),
];
/// The native client of the window manager's image: the focus of its
/// making, the focus the window of the first revision took, the chord that
/// brought it back, its key, the focus the first one's end gave back, its
/// key.
const P_WANTS: [Want; 9] = [
    (FOCUS_IN, 0, 0),
    (FOCUS_OUT, 0, 0),
    (FOCUS_IN, 0, 0),
    (KEY, KEY_B, 1),
    (KEY, KEY_B, 0),
    (FOCUS_OUT, 0, 0),
    (FOCUS_IN, 0, 0),
    (KEY, KEY_F, 1),
    (KEY, KEY_F, 0),
];
/// The keys the client of the first revision reads.
const O_WANTS: [(u16, i32); 8] = [
    (KEY_A, 1),
    (KEY_A, 0),
    // Held while the focus leaves: the compositor releases it, and the real
    // release, made while the other window has the focus, comes to nobody.
    (KEY_H, 1),
    (KEY_H, 0),
    (KEY_C, 1),
    (KEY_C, 0),
    (KEY_E, 1),
    (KEY_E, 0),
];
/// The manager's: the Super keys and the Tab under them.
const M_WANTS: [Want; 4] = [
    (KEY, KEY_SUPER, 1),
    (KEY, KEY_TAB, 1),
    (KEY, KEY_TAB, 0),
    (KEY, KEY_SUPER, 0),
];

impl Probe<'_> {
    /// The events of a session (a window's, or the manager's): up to
    /// MAX_EVENTS, without waiting.
    fn events(
        &self,
        session: &Handle<Channel>,
        out: &mut [Event; MAX_EVENTS],
    ) -> Result<(usize, u32), Fail> {
        let reply = sys::send(session, &Method::Events.header().bytes()).map_err(Fail::Kernel)?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut n = 0;
        let flags = proto_comp::read_events(reply.bytes(&mut buffer), |e| {
            if n < MAX_EVENTS {
                out[n] = e;
                n += 1;
            }
        })
        .map_err(Fail::Status)?;
        Ok((n, flags))
    }

    /// Takes the events of `session` as they come until `done` says it has
    /// enough (true), each one to `each`; false when none came in WAIT_NS.
    fn watch(
        &self,
        session: &Handle<Channel>,
        mut each: impl FnMut(&Event) -> Result<bool, &'static str>,
    ) -> Result<(), &'static str> {
        loop {
            let mut out = [Event::default(); MAX_EVENTS];
            let (n, _) = self.events(session, &mut out).map_err(say("EVENTS"))?;
            for e in &out[..n] {
                if each(e)? {
                    return Ok(());
                }
            }
            if n == 0 && !self.wait_bits(EVENTS_BIT) {
                rt::println!("focus-probe: no event of a window in {WAIT_NS} ns");
                return Err("the events never came");
            }
        }
    }

    /// Takes the events of a window that has no channel of its own to say
    /// they came (the window of the first revision: OPEN gives none), by
    /// asking again after a pause, until `each` says it has enough (true);
    /// the events it saw are printed as they come, so that a failure shows
    /// the last of them.
    fn poll(
        &self,
        name: &str,
        session: &Handle<Channel>,
        mut each: impl FnMut(&Event) -> Result<bool, &'static str>,
    ) -> Result<(), &'static str> {
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        loop {
            let mut out = [Event::default(); MAX_EVENTS];
            let (n, _) = self.events(session, &mut out).map_err(say("EVENTS"))?;
            for e in &out[..n] {
                rt::println!("focus-probe: {name}: event {e:?}");
                if each(e)? {
                    return Ok(());
                }
            }
            if n == 0 {
                if time::ticks_to_ns(time::now()) > end {
                    rt::println!("focus-probe: {name}: no event in {WAIT_NS} ns");
                    return Err("the events never came");
                }
                self.sleep(RETRY_NS);
            }
        }
    }

    /// A client: a window, its picture, and the list of its events.
    fn client(self, second: bool) -> Result<(), &'static str> {
        // In the run under -icount (quick) the first window is ARGB8888 with every
        // point opaque (the same picture), so that the seven windows of the many
        // windows over it make eight translucent layers over one place, as the
        // overload of the frame probe does.
        let quick = cfg!(feature = "quick");
        let (name, rect, format) = if second {
            ("b", B, FORMAT_ARGB8888)
        } else if quick {
            ("a", A, FORMAT_ARGB8888)
        } else {
            ("a", A, FORMAT_XRGB8888)
        };
        let display = self.display()?;
        let d = self.describe_when_ready(&display)?;
        if d.open != 0 && !second {
            return Err("the screen is not free");
        }
        // The manager decides who has the focus: the windows wait for it.
        self.until(&display, "the manager never subscribed", |d| {
            d.flags & HAS_MANAGER != 0
        })?;
        if second {
            // Wait for the first window to be on the screen.
            let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
            loop {
                let d = self.describe(&display).map_err(say("DESCRIBE"))?;
                if d.created >= 1 && d.frames >= 1 && d.busy == 0 {
                    break;
                }
                if time::ticks_to_ns(time::now()) > end {
                    return Err("the first window never came");
                }
                self.sleep(RETRY_NS);
            }
        }
        let (window, _) = self
            .create_as(&display, rect, format)
            .map_err(say("WINDOW_CREATE"))?;
        let stride = rect.w * 4;
        let bytes = u64::from(stride) * u64::from(rect.h);
        let (objects, at) = self.buffers(1, bytes)?;
        self.attach_as(&window, stride, &objects[..1], format)
            .map_err(say("ATTACH"))?;
        for y in 0..rect.h {
            for x in 0..rect.w {
                let point = if second {
                    b_point(x, y)
                } else if quick {
                    0xFF00_0000 | a_point(x, y)
                } else {
                    a_point(x, y)
                };
                // SAFETY: `buffers` mapped this object for writing at this
                // address; the probe is the only user, in one thread.
                unsafe {
                    (at[0] as *mut u32)
                        .add((y * rect.w + x) as usize)
                        .write(point)
                };
            }
        }
        self.post(&window, 0, &[]).map_err(say("POST"))?;
        rt::println!("focus-probe: {name} window is up");
        let wants: &[Want] = if second { &B_WANTS } else { &A_WANTS };
        let mut seen = 0;
        // The window sees the pointer in its own coordinates only while the
        // injected pointer is in it: the second never.
        let mut last_move = None;
        self.watch(&window, |e| {
            match e.kind {
                MOVE => {
                    if second {
                        return Err("the second window got a pointer move");
                    }
                    last_move = Some((e.x, e.y));
                    return Ok(false);
                }
                BUTTON if second => return Err("the second window got a button"),
                _ => {}
            }
            let got = (e.kind, e.code, e.value);
            if seen < wants.len() {
                if got != wants[seen] {
                    rt::println!(
                        "focus-probe: {name}: event {seen} is {got:?}, {:?} expected",
                        wants[seen]
                    );
                    return Err("an event is not the one expected");
                }
                // The injected click is at CLICK, in the window's coordinates.
                if got.0 == BUTTON && (e.x, e.y) != (CLICK.0 - A.x as i32, CLICK.1 - A.y as i32) {
                    rt::println!("focus-probe: {name}: the click is at ({}, {})", e.x, e.y);
                    return Err("a click is not where the pointer was");
                }
                seen += 1;
            }
            Ok(seen == wants.len())
        })?;
        rt::println!("focus-probe: {name} events are exactly the focus and the keys it had");
        if second {
            return Ok(());
        }
        if cfg!(feature = "quick") {
            // The run under -icount has no monitor to move the tablet: the
            // injector holds the last key until the many windows went, so
            // this window is there when they make eight.
            // The last of the programs to end: xtask stops on this one.
            self.sleep(100_000_000);
            return Ok(());
        }
        // The tablet: its click, in the window's coordinates, after the moves
        // that took the pointer there.
        let mut seen = 0;
        let want = (TABLET.0 - A.x as i32, TABLET.1 - A.y as i32);
        self.watch(&window, |e| {
            match e.kind {
                MOVE => {
                    last_move = Some((e.x, e.y));
                    return Ok(false);
                }
                BUTTON => {}
                _ => return Err("a window with the focus got an event it should not"),
            }
            if (e.kind, e.code, e.value) != (A_TABLET[seen].0, A_TABLET[seen].1, A_TABLET[seen].2)
                || (e.x - want.0).abs() > 2
                || (e.y - want.1).abs() > 2
            {
                rt::println!("focus-probe: a: the tablet's event {seen} is {e:?}");
                return Err("the tablet's click is not where it was made");
            }
            seen += 1;
            Ok(seen == A_TABLET.len())
        })?;
        if last_move.is_none() {
            return Err("no move came before the tablet's click");
        }
        rt::println!("focus-probe: a the tablet's click reached the window under it");
        Ok(())
    }

    /// The manager.
    fn manager(self) -> Result<(), &'static str> {
        let display = self.display()?;
        self.describe_when_ready(&display)?;
        let notify = sys::handle_duplicate(&self.channel, Rights::NOTIFY | Rights::TRANSFER)
            .map_err(say("duplicate"))?;
        let mut w = Writer::new();
        proto_comp::write_manage(manage::SUBSCRIBE, 0, 0, 0, &mut w)
            .map_err(say("MANAGE's bytes"))?;
        match call_with(&display, w.as_bytes(), [notify.erase()].into())
            .map_err(say("SUBSCRIBE"))?
        {
            (Status::Ok, _) => {}
            _ => return Err("SUBSCRIBE was refused"),
        }
        rt::println!("focus-probe: the manager has subscribed");
        let mut seen = 0;
        let mut switched = false;
        self.watch(&display, |e| {
            if e.kind == CREATE {
                // A window of the clients' size has the focus when it is made;
                // the others (the many windows) have none.
                self.focus_new(&display, e.value as u32)?;
                return Ok(false);
            }
            if e.kind != KEY {
                // The windows gone.
                return Ok(false);
            }
            let got = (e.kind, e.code, e.value);
            if seen >= M_WANTS.len() || got != M_WANTS[seen] {
                rt::println!("focus-probe: m: key event {seen} is {got:?}");
                return Err("the manager got a key it should not");
            }
            seen += 1;
            if got == (KEY, KEY_TAB, 1) && !switched {
                switched = true;
                let id = self.switch(&display)?;
                rt::println!("focus-probe: the manager gave the focus to window {id}");
            }
            Ok(seen == M_WANTS.len())
        })?;
        rt::println!("focus-probe: the manager heard the Super keys and the windows did not");
        if cfg!(feature = "quick") {
            // The manager runs while the many windows are made (the run under
            // -icount): they take no focus from it.
            self.wait_open(&display, 1 + MANY as u32)?;
            self.wait_open(&display, 1)?;
        }
        Ok(())
    }

    /// FOCUS of window `id` when it is a window of the two clients (their
    /// size), found by LIST: the manager's policy of the probe.
    fn focus_new(&self, display: &Handle<Channel>, id: u32) -> Result<(), &'static str> {
        let mut w = Writer::new();
        proto_comp::write_manage(manage::LIST, 0, 0, 0, &mut w).map_err(say("MANAGE's bytes"))?;
        let reply = sys::send(display, w.as_bytes()).map_err(say("LIST"))?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut mine = false;
        proto_comp::read_list(reply.bytes(&mut buffer), |r| {
            mine |= r.id == id && r.w == A.w && r.h == A.h;
        })
        .map_err(say("LIST's reply"))?;
        if !mine {
            return Ok(());
        }
        let mut w = Writer::new();
        proto_comp::write_manage(manage::FOCUS, id, 0, 0, &mut w).map_err(say("MANAGE's bytes"))?;
        plain(display, w.as_bytes()).map_err(say("FOCUS"))
    }

    /// LIST, then FOCUS of the shown window that has not the focus.
    fn switch(&self, display: &Handle<Channel>) -> Result<u32, &'static str> {
        let mut w = Writer::new();
        proto_comp::write_manage(manage::LIST, 0, 0, 0, &mut w).map_err(say("MANAGE's bytes"))?;
        let reply = sys::send(display, w.as_bytes()).map_err(say("LIST"))?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut windows = [WindowRecord::default(); WINDOWS];
        let mut n = 0;
        proto_comp::read_list(reply.bytes(&mut buffer), |r| {
            if n < windows.len() {
                windows[n] = r;
                n += 1;
            }
        })
        .map_err(say("LIST's reply"))?;
        let other = windows[..n]
            .iter()
            .find(|r| r.flags & proto_comp::SHOWN != 0 && r.flags & proto_comp::FOCUSED == 0)
            .ok_or("no other window to give the focus to")?;
        let mut w = Writer::new();
        proto_comp::write_manage(manage::FOCUS, other.id, 0, 0, &mut w)
            .map_err(say("MANAGE's bytes"))?;
        plain(display, w.as_bytes()).map_err(say("FOCUS"))?;
        Ok(other.id)
    }

    fn inject(&self, display: &Handle<Channel>, e: Event) -> Result<(), &'static str> {
        let mut w = Writer::new();
        e.write_inject(&mut w).map_err(say("INJECT's bytes"))?;
        plain(display, w.as_bytes()).map_err(say("INJECT"))
    }

    fn key(&self, display: &Handle<Channel>, code: u16) -> Result<(), &'static str> {
        self.inject(display, Event::new(KEY, code, 1))?;
        self.inject(display, Event::new(KEY, code, 0))
    }

    /// DESCRIBE until `ready` is true of it (and the screen has settled),
    /// at most WAIT_NS.
    fn until(
        &self,
        display: &Handle<Channel>,
        what: &'static str,
        ready: impl Fn(&Description) -> bool,
    ) -> Result<Description, &'static str> {
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        loop {
            let d = self.describe(display).map_err(say("DESCRIBE"))?;
            if ready(&d) && d.busy == 0 {
                return Ok(d);
            }
            if time::ticks_to_ns(time::now()) > end {
                rt::println!(
                    "focus-probe: {what}: the service said created {} open {} frames {} busy {} manager {}",
                    d.created,
                    d.open,
                    d.frames,
                    d.busy,
                    d.flags & HAS_MANAGER != 0
                );
                return Err(what);
            }
            self.sleep(RETRY_NS);
        }
    }

    /// The many windows, in two forms by the run.
    ///
    /// Under -icount: fifteen windows more over the first client's place, four
    /// of this context and four of each of three clones' (a context has four;
    /// the last has three), all of ARGB8888 and all on one place over the first
    /// client's window (ARGB8888 in that run), which with it make the sixteen the
    /// service has: a band over that place lays sixteen translucent layers,
    /// which the service draws in groups (the model of a band charges each layer
    /// after the first). None has the focus while the manager runs, and the bands
    /// of the frames they make stay under the bound (xtask reads the steps of
    /// that run).
    ///
    /// With the monitor: when both clients are gone, sixteen windows over one
    /// another (`sixteen_of`, some ARGB8888 and some XRGB8888, each of a colour of
    /// its own, in four contexts of four), the CRC of the screen they make,
    /// which xtask compares with QEMU's screenshot, and then the windows go. The
    /// service draws that frame in groups of layers.
    fn many(self) -> Result<(), &'static str> {
        let quick = cfg!(feature = "quick");
        let display = self.display()?;
        self.describe_when_ready(&display)?;
        if quick {
            // The first client alone is on the screen.
            self.until(&display, "the first client never stood alone", |d| {
                d.open == 1 && d.created >= 2
            })?;
        } else {
            // Both clients are gone.
            self.until(&display, "the clients never went", |d| {
                d.open == 0 && d.created >= 2
            })?;
        }
        let clones = self.clones::<3>(&display)?;
        let sessions = [&display, &clones[0], &clones[1], &clones[2]];
        let count = if quick { MANY } else { WINDOWS };
        let made = if quick {
            self.spawn(&sessions, count, |_| {
                (
                    Rect {
                        x: A.x + 10,
                        y: A.y + 10,
                        w: 200,
                        h: 150,
                    },
                    FORMAT_ARGB8888,
                    0x8040_4040,
                )
            })?
        } else {
            self.spawn(&sessions, count, sixteen_of)?
        };
        if quick {
            self.until(&display, "the many windows never settled", |d| {
                d.open == 1 + MANY as u32
            })?;
            self.none_has_the_focus(&made.0)?;
            rt::println!(
                "focus-probe: sixteen windows are shown and none of the fifteen took the focus"
            );
            // Held until the first client has seen them all.
            self.sleep(500_000_000);
            return Ok(());
        }
        // The screen has settled: all the windows are open, no frame is being
        // made and the count of frames stood still over a pause.
        let mut frames = None;
        loop {
            let d = self.until(&display, "the sixteen windows never settled", |d| {
                d.open == WINDOWS as u32
            })?;
            if frames == Some(d.frames) {
                break;
            }
            frames = Some(d.frames);
            self.sleep(200_000_000);
        }
        rt::println!("focus-probe: sixteen crc {:08x}", sixteen_crc());
        self.sleep(SNAPSHOT_NS);
        Ok(())
    }

    /// `N` clones of the display session: contexts of their own.
    fn clones<const N: usize>(
        &self,
        display: &Handle<Channel>,
    ) -> Result<[Handle<Channel>; N], &'static str> {
        let mut out = [const { None }; N];
        for slot in &mut out {
            let (status, mut reply) =
                call(display, &proto_gpu::Method::Clone.header().bytes()).map_err(say("CLONE"))?;
            if status != Status::Ok {
                return Err("CLONE was refused");
            }
            *slot = Some(
                reply
                    .handles
                    .take::<Channel>(0)
                    .map_err(|_| "CLONE's handle")?,
            );
        }
        Ok(out.map(|c| c.expect("every clone was made")))
    }

    /// `count` windows of `many`: window `k` is made in session
    /// `sessions[k / PER_CONTEXT]` with the rectangle, the format and the value
    /// of every point `of(k)` gives (premultiplied for ARGB8888), has one buffer
    /// and posts it. The windows and the objects of their buffers are returned.
    fn spawn(
        &self,
        sessions: &[&Handle<Channel>],
        count: usize,
        of: impl Fn(usize) -> (Rect, u32, u32),
    ) -> Result<Made, &'static str> {
        let mut windows = [const { None }; WINDOWS];
        let mut keep = [const { None }; WINDOWS];
        for k in 0..count {
            let (rect, format, value) = of(k);
            let (window, _) = self
                .create_as(sessions[k / PER_CONTEXT], rect, format)
                .map_err(say("WINDOW_CREATE of many"))?;
            let (objects, at) = self.buffers(1, u64::from(rect.w) * u64::from(rect.h) * 4)?;
            self.attach_as(&window, rect.w * 4, &objects[..1], format)
                .map_err(say("ATTACH of many"))?;
            // SAFETY: `buffers` mapped this object for writing at this
            // address, `w` by `h` points; one thread.
            let points = unsafe {
                core::slice::from_raw_parts_mut(at[0] as *mut u32, (rect.w * rect.h) as usize)
            };
            points.fill(value);
            self.post(&window, 0, &[]).map_err(say("POST of many"))?;
            windows[k] = Some(window);
            keep[k] = Some(objects);
        }
        Ok((windows, keep))
    }

    /// No window of `windows` has an event (none was given the focus).
    fn none_has_the_focus(
        &self,
        windows: &[Option<Handle<Channel>>; WINDOWS],
    ) -> Result<(), &'static str> {
        for window in windows.iter().flatten() {
            let mut out = [Event::default(); MAX_EVENTS];
            let (n, _) = self
                .events(window, &mut out)
                .map_err(say("EVENTS of many"))?;
            if n != 0 {
                rt::println!(
                    "focus-probe: n: an event {:?} came to a window of the many",
                    out[0]
                );
                return Err("a window made while a manager runs took the focus");
            }
        }
        Ok(())
    }

    /// DESCRIBE until `n` windows are open, whether or not a frame is being
    /// made, at most WAIT_NS.
    fn wait_open(&self, display: &Handle<Channel>, n: u32) -> Result<(), &'static str> {
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        while self.describe(display).map_err(say("DESCRIBE"))?.open != n {
            if time::ticks_to_ns(time::now()) > end {
                return Err("the windows never were the number wanted");
            }
            self.sleep(RETRY_NS);
        }
        Ok(())
    }

    /// The input: the scene, one step at a time, each with the CRC of the
    /// screen it leaves.
    fn input(self) -> Result<(), &'static str> {
        let display = self.display()?;
        let ready = self.describe_when_ready(&display)?;
        if ready.flags & CURSOR_PLANE == 0 {
            return Err("the pointer is not on the cursor pipeline");
        }
        rt::println!("focus-probe: the pointer is on the cursor pipeline");
        // Both windows on the screen, the manager subscribed.
        let d = self.until(&display, "the windows and the manager never came", |d| {
            d.open == 2 && d.created == 2 && d.frames >= 2 && d.flags & HAS_MANAGER != 0
        })?;
        rt::println!(
            "focus-probe: overlap crc {:08x}",
            expected_crc([true, false], false)
        );
        self.sleep(SNAPSHOT_NS);
        // A key while the second window has the focus.
        self.key(&display, KEY_A)?;
        // The pointer goes to the first window alone and clicks: the focus
        // and the top place are its.
        self.inject(&display, Event::at(MOVE, 0, 0, CLICK.0, CLICK.1))?;
        self.inject(&display, Event::at(BUTTON, BTN_LEFT, 1, CLICK.0, CLICK.1))?;
        self.inject(&display, Event::at(BUTTON, BTN_LEFT, 0, CLICK.0, CLICK.1))?;
        let d = self.until(&display, "the click never made a frame", |n| {
            n.frames > d.frames
        })?;
        rt::println!(
            "focus-probe: click crc {:08x}",
            expected_crc([false, true], false)
        );
        self.sleep(SNAPSHOT_NS);
        self.key(&display, KEY_S)?;
        // Super and Tab are the manager's.
        for (code, value) in [(KEY_SUPER, 1), (KEY_TAB, 1), (KEY_TAB, 0), (KEY_SUPER, 0)] {
            self.inject(&display, Event::new(KEY, code, value))?;
        }
        self.until(&display, "the manager never switched the windows", |n| {
            n.frames > d.frames
        })?;
        rt::println!(
            "focus-probe: switch crc {:08x}",
            expected_crc([true, false], false)
        );
        self.sleep(SNAPSHOT_NS);
        self.key(&display, KEY_D)?;
        // The second client ends with its window: the first is untouched.
        self.until(&display, "the second window never went", |n| n.open == 1)?;
        rt::println!(
            "focus-probe: survivor crc {:08x}",
            expected_crc([true, false], true)
        );
        self.sleep(SNAPSHOT_NS);
        if cfg!(feature = "quick") {
            // The many windows come and go first (the run under -icount).
            let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
            while self.describe(&display).map_err(say("DESCRIBE"))?.created < 2 + MANY as u32 {
                if time::ticks_to_ns(time::now()) > end {
                    return Err("the many windows never came");
                }
                self.sleep(RETRY_NS);
            }
            self.wait_open(&display, 1)?;
        }
        // The focus passed to the first window.
        self.key(&display, KEY_F)?;
        rt::println!("focus-probe: the keys are injected");
        Ok(())
    }
}

// ------------------------------------------------------------ the window manager's image

impl Probe<'_> {
    /// The native client of the window manager's image.
    fn wm_new(self) -> Result<(), &'static str> {
        let display = self.display()?;
        self.describe_when_ready(&display)?;
        self.until(&display, "the manager never subscribed", |d| {
            d.flags & HAS_MANAGER != 0
        })?;
        let (window, _) = self
            .create_as(&display, A, FORMAT_XRGB8888)
            .map_err(say("WINDOW_CREATE"))?;
        let stride = A.w * 4;
        let (objects, at) = self.buffers(1, u64::from(stride) * u64::from(A.h))?;
        self.attach_as(&window, stride, &objects[..1], FORMAT_XRGB8888)
            .map_err(say("ATTACH"))?;
        for y in 0..A.h {
            for x in 0..A.w {
                // SAFETY: `buffers` mapped this object for writing at this
                // address; the probe is the only user, in one thread.
                unsafe {
                    (at[0] as *mut u32)
                        .add((y * A.w + x) as usize)
                        .write(a_point(x, y))
                };
            }
        }
        self.post(&window, 0, &[]).map_err(say("POST"))?;
        rt::println!("focus-probe: p window is up");
        let mut seen = 0;
        self.watch(&window, |e| {
            rt::println!("focus-probe: p: event {e:?}");
            let got = (e.kind, e.code, e.value);
            if seen >= P_WANTS.len() || got != P_WANTS[seen] {
                rt::println!("focus-probe: p: event {seen} is {got:?}");
                return Err("an event of the native client is not the one expected");
            }
            seen += 1;
            Ok(seen == P_WANTS.len())
        })?;
        rt::println!("focus-probe: p events are exactly the focus and the keys it had");
        // The window stays until the end of the injector's scene would show a
        // key it should not have: the last events come from the compositor
        // at once, and a stray one would be in the ring by now.
        self.sleep(200_000_000);
        let mut out = [Event::default(); MAX_EVENTS];
        let (n, _) = self.events(&window, &mut out).map_err(say("EVENTS"))?;
        if n != 0 {
            rt::println!("focus-probe: p: a late event {:?}", out[0]);
            return Err("the native client got an event after its list");
        }
        Ok(())
    }

    /// The client of the first revision: OPEN, a pattern, FLUSH, and the
    /// keys of its session of focus.
    fn wm_old(self) -> Result<(), &'static str> {
        let display = self.display()?;
        self.describe_when_ready(&display)?;
        // The native client's window is on the screen and the manager is
        // there: this window is made after the first one.
        self.until(&display, "the native window never came", |d| {
            d.flags & HAS_MANAGER != 0 && d.created >= 1 && d.frames >= 1
        })?;
        let open = proto_gpu::Method::Open.header().bytes();
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        let (status, mut reply) = loop {
            let (status, reply) = call(&display, &open).map_err(say("OPEN"))?;
            if status != proto_gpu::code(proto_gpu::CLEARING) {
                break (status, reply);
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err("OPEN says CLEARING for good");
            }
            self.sleep(RETRY_NS);
        };
        if status != Status::Ok {
            return Err("OPEN gave no session of focus (the image has a keyboard)");
        }
        let (Ok(memory), Ok(owner), Ok(focus)) = (
            reply.handles.take::<Memory>(0),
            reply.handles.take::<Channel>(1),
            reply.handles.take::<Channel>(2),
        ) else {
            return Err("OPEN's handles");
        };
        let at = MAP_AT + self.maps.get() * MAP_STEP;
        self.maps.set(self.maps.get() + 1);
        sys::mem_map(
            self.process,
            &memory,
            0,
            u64::from(proto_gpu::SCREEN_BYTES),
            at,
            Access::ReadWrite,
        )
        .map_err(say("map the buffer"))?;
        // SAFETY: mapped for reading and writing just above; one thread.
        let points = unsafe {
            core::slice::from_raw_parts_mut(
                at as *mut u32,
                (proto_gpu::STRIDE / 4 * HEIGHT) as usize,
            )
        };
        points.fill(0x0020_4060);
        let mut w = Writer::new();
        proto_gpu::Rect::SCREEN
            .write(&mut w)
            .map_err(say("FLUSH's bytes"))?;
        plain(&owner, w.as_bytes()).map_err(say("FLUSH"))?;
        // The window is shown. The manager answers its making with FOCUS: the
        // window says so with FOCUS_IN in its ring.
        self.poll("o", &owner, |e| Ok(e.kind == FOCUS_IN))?;
        // A window made and closed again tells the injector that all of it
        // happened: the windows made are three and the open ones two.
        let (marker, _) = self
            .create_as(
                &display,
                Rect {
                    x: 0,
                    y: 0,
                    w: 1,
                    h: 1,
                },
                FORMAT_XRGB8888,
            )
            .map_err(say("WINDOW_CREATE of the marker"))?;
        drop(marker);
        rt::println!("focus-probe: o window is up");
        let mut seen = 0;
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        while seen < O_WANTS.len() {
            let mut request = Writer::new();
            proto_input::write_read(32, &mut request).map_err(say("READ's bytes"))?;
            let reply = sys::send(&focus, request.as_bytes()).map_err(say("READ"))?;
            let mut buffer = [0; MESSAGE_MAX];
            let mut wrong = None;
            let mut got = 0;
            proto_input::read_events(reply.bytes(&mut buffer), |e: KeyEvent| {
                rt::println!("focus-probe: o: key event {e:?}");
                got += 1;
                let key = (e.code, e.value);
                if e.kind != proto_input::EV_KEY || seen >= O_WANTS.len() || key != O_WANTS[seen] {
                    wrong.get_or_insert(e);
                } else {
                    seen += 1;
                }
            })
            .map_err(say("READ's reply"))?;
            if let Some(e) = wrong {
                rt::println!("focus-probe: o: key event {seen} is {e:?}");
                return Err("the client of the first revision read a key it should not");
            }
            if got == 0 {
                if time::ticks_to_ns(time::now()) > end {
                    rt::println!("focus-probe: o: {seen} of {} keys came", O_WANTS.len());
                    return Err("the keys never came");
                }
                self.sleep(RETRY_NS);
            }
        }
        rt::println!("focus-probe: o keys are exactly the keys it had");
        Ok(())
    }

    /// The chord of Super and Tab, injected.
    fn chord(&self, display: &Handle<Channel>, code: u16) -> Result<(), &'static str> {
        for (key, value) in [(KEY_SUPER, 1), (code, 1), (code, 0), (KEY_SUPER, 0)] {
            self.inject(display, Event::new(KEY, key, value))?;
        }
        Ok(())
    }

    /// The input of the window manager's image.
    fn wm_input(self) -> Result<(), &'static str> {
        let display = self.display()?;
        self.describe_when_ready(&display)?;
        // Both windows are on the screen, the manager answered the making of
        // each, and the client of the first revision made and closed its
        // marker window to say so (three windows made, two open).
        self.until(&display, "the windows and the manager never came", |d| {
            d.open == 2 && d.created == 3 && d.flags & HAS_MANAGER != 0
        })?;
        // The window of the first revision was made last: the manager gave
        // it the focus, and the key is its.
        self.key(&display, KEY_A)?;
        // A key it holds while the focus leaves.
        self.inject(&display, Event::new(KEY, KEY_H, 1))?;
        // The chord: the focus passes to the native window, and the
        // manager's FOCUS raises it, a frame.
        let d = self.until(&display, "the screen never settled", |_| true)?;
        self.chord(&display, KEY_TAB)?;
        let d = self.until(&display, "the chord never switched the windows", |n| {
            n.frames > d.frames
        })?;
        self.inject(&display, Event::new(KEY, KEY_H, 0))?;
        self.key(&display, KEY_B)?;
        // And back to the window of the first revision.
        self.chord(&display, KEY_TAB)?;
        self.until(&display, "the second chord never switched back", |n| {
            n.frames > d.frames
        })?;
        self.key(&display, KEY_C)?;
        rt::println!("focus-probe: the chords are injected");
        // The manager ends on its chord; the compositor goes on.
        self.chord(&display, KEY_Q)?;
        self.until(&display, "the manager never ended", |n| {
            n.flags & HAS_MANAGER == 0
        })?;
        rt::println!("focus-probe: the manager is gone and the compositor answers");
        // The focus stays where it was: the key is the first client's, which
        // ends on it; the focus then passes to the window on top by the
        // compositor's rule.
        self.key(&display, KEY_E)?;
        self.until(&display, "the first client never went", |n| n.open == 1)?;
        self.key(&display, KEY_F)?;
        rt::println!("focus-probe: the keys are injected");
        Ok(())
    }
}

// ------------------------------------------------------------ the top window

/// The client's window, the size it is asked for, and the place the pair is moved to.
const TOP_AT: Rect = Rect {
    x: 100,
    y: 100,
    w: 200,
    h: 150,
};
const TOP_SIZE: (u32, u32) = (300, 200);
const TOP_MOVE: (u32, u32) = (150, 120);
/// The frame is wider than the client by an edge on each side and taller by a
/// title above and an edge below.
const EDGE: u32 = 4;
const TITLE_H: u32 = 24;
/// The bytes of a buffer that holds the whole screen: the capacity of a
/// window that can be resized to it.
const SCREEN_BYTES: u64 = WIDTH as u64 * HEIGHT as u64 * 4;

/// The point (x, y) of the client's window of `w` by `h` points.
fn top_point(x: u32, y: u32, w: u32, h: u32) -> u32 {
    let r = x * 255 / (w - 1);
    let g = y * 255 / (h - 1);
    r << 16 | g << 8 | ((x ^ y) & 0xFF)
}

/// The point (x, y) of the manager's frame of `w` by `h` points: a title, an
/// edge and a dark middle (the client lies over it).
fn frame_point(x: u32, y: u32, w: u32, h: u32) -> u32 {
    if y < TITLE_H {
        0x30_30_90 | (x * 255 / (w - 1)) << 8
    } else if x < EDGE || x >= w - EDGE || y >= h - EDGE {
        0x20_20_60 | (y * 255 / (h - 1))
    } else {
        0x10_10_10
    }
}

/// What the screen shows of the frame and the client, `(rectangle, is the
/// frame)` bottom first, over the black: the rectangles' sizes are the sizes
/// the pictures were made for.
fn top_crc(layers: &[(Rect, bool)]) -> u32 {
    let mut crc = Crc(0xFFFF_FFFF);
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let mut point = 0;
            for &(r, frame) in layers {
                if x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h {
                    let (lx, ly) = (x - r.x, y - r.y);
                    point = if frame {
                        frame_point(lx, ly, r.w, r.h)
                    } else {
                        top_point(lx, ly, r.w, r.h)
                    };
                }
            }
            crc.point(point);
        }
    }
    !crc.0
}

/// A picture of `w` by `h` points at `at`, in buffers of the screen's width.
fn paint(at: usize, w: u32, h: u32, point: impl Fn(u32, u32) -> u32) {
    for y in 0..h {
        for x in 0..w {
            // SAFETY: `buffers` mapped this object for writing at this address,
            // for the whole screen; the probe is the only user, in one thread.
            unsafe {
                (at as *mut u32)
                    .add((y * WIDTH + x) as usize)
                    .write(point(x, y))
            };
        }
    }
}

impl Probe<'_> {
    /// SET_TEXT of a window.
    fn text(&self, window: &Handle<Channel>, which: u32, text: &str) -> Result<(), Fail> {
        let mut w = Writer::new();
        proto_comp::SetText::new(which, text)
            .and_then(|t| t.write(&mut w))
            .map_err(Fail::Status)?;
        plain(window, w.as_bytes())
    }

    /// A SET_TEXT whose bytes are `bytes` as they are, whatever they are.
    fn text_raw(&self, window: &Handle<Channel>, which: u32, bytes: &[u8]) -> Result<(), Fail> {
        let mut w = Writer::new();
        Method::SetText
            .header()
            .write(&mut w)
            .map_err(Fail::Status)?;
        w.u32(which).map_err(Fail::Status)?;
        w.u32(bytes.len() as u32).map_err(Fail::Status)?;
        w.bytes(bytes).map_err(Fail::Status)?;
        plain(window, w.as_bytes())
    }

    /// SIZE of a window.
    fn size(&self, window: &Handle<Channel>, w: u32, h: u32, serial: u32) -> Result<(), Fail> {
        let mut out = Writer::new();
        proto_comp::Size { w, h, serial }
            .write(&mut out)
            .map_err(Fail::Status)?;
        plain(window, out.as_bytes())
    }

    /// Whether `result` is the refusal `code`.
    fn refused(result: Result<(), Fail>, code: u32) -> bool {
        result == Err(Fail::Status(proto_comp::code(code)))
    }

    /// MANAGE `op` with `a`, `b`, `c`.
    fn manage(
        &self,
        display: &Handle<Channel>,
        op: u32,
        a: u32,
        b: u32,
        c: u32,
    ) -> Result<(), Fail> {
        let mut w = Writer::new();
        proto_comp::write_manage(op, a, b, c, &mut w).map_err(Fail::Status)?;
        plain(display, w.as_bytes())
    }

    /// INFO of the window `id`.
    fn info(&self, display: &Handle<Channel>, id: u32) -> Result<proto_comp::Info, Fail> {
        let mut w = Writer::new();
        proto_comp::write_manage(manage::INFO, id, 0, 0, &mut w).map_err(Fail::Status)?;
        let reply = sys::send(display, w.as_bytes()).map_err(Fail::Kernel)?;
        let mut buffer = [0; MESSAGE_MAX];
        proto_comp::Info::read(reply.bytes(&mut buffer)).map_err(Fail::Status)
    }

    /// The record of LIST for the window `id`.
    fn listed(&self, display: &Handle<Channel>, id: u32) -> Result<WindowRecord, &'static str> {
        let mut w = Writer::new();
        proto_comp::write_manage(manage::LIST, 0, 0, 0, &mut w).map_err(say("MANAGE's bytes"))?;
        let reply = sys::send(display, w.as_bytes()).map_err(say("LIST"))?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut found = None;
        proto_comp::read_list(reply.bytes(&mut buffer), |r| {
            if r.id == id {
                found = Some(r);
            }
        })
        .map_err(say("LIST's reply"))?;
        found.ok_or("a window is not in LIST")
    }

    /// The screen has settled: no frame is being made and the count of frames
    /// stood still over a pause.
    fn settled(&self, display: &Handle<Channel>) -> Result<(), &'static str> {
        let mut frames = None;
        loop {
            let d = self.until(display, "the screen never settled", |_| true)?;
            if frames == Some(d.frames) {
                return Ok(());
            }
            frames = Some(d.frames);
            self.sleep(200_000_000);
        }
    }

    /// The client of the top-window image: a window that can be resized to the
    /// whole screen, which answers CONFIGURE and CLOSE_REQUEST.
    fn top_client(self) -> Result<(), &'static str> {
        let display = self.display()?;
        self.describe_when_ready(&display)?;
        self.until(&display, "the manager never subscribed", |d| {
            d.flags & HAS_MANAGER != 0
        })?;
        let (window, _) = self
            .create_as(&display, TOP_AT, FORMAT_XRGB8888)
            .map_err(say("WINDOW_CREATE"))?;
        self.text(&window, proto_comp::TEXT_TITLE, "Top")
            .map_err(say("SET_TEXT"))?;
        self.text(&window, proto_comp::TEXT_APP, "probe")
            .map_err(say("SET_TEXT"))?;
        // A text that is not UTF-8, a zero in a text, an unknown text: refused.
        let bad = [
            (proto_comp::TEXT_TITLE, &[0xC3, 0x28][..]),
            (proto_comp::TEXT_TITLE, &[b'a', 0][..]),
            (3, &b"a"[..]),
        ];
        for (which, bytes) in bad {
            if !Self::refused(self.text_raw(&window, which, bytes), proto_comp::INVALID) {
                return Err("a bad text was not refused with INVALID");
            }
        }
        // No size before the buffers.
        if !Self::refused(self.size(&window, 100, 100, 0), proto_comp::NOT_ALLOWED) {
            return Err("SIZE before ATTACH was not refused with NOT_ALLOWED");
        }
        let (objects, at) = self.buffers(2, SCREEN_BYTES)?;
        self.attach_as(&window, WIDTH * 4, &objects[..2], FORMAT_XRGB8888)
            .map_err(say("ATTACH"))?;
        // The size is refused past what the buffers hold (a width of 641, a
        // height of 401), past the screen at the window's place (600 wide at
        // x 100), when it is empty, and with the serial of no CONFIGURE.
        for (w, h, serial) in [
            (641, 100, 0),
            (100, 401, 0),
            (600, 100, 0),
            (0, 10, 0),
            (10, 0, 0),
            (200, 150, 9),
        ] {
            if !Self::refused(self.size(&window, w, h, serial), proto_comp::INVALID) {
                rt::println!("focus-probe: SIZE {w} {h} {serial} was not refused");
                return Err("a bad size was not refused with INVALID");
            }
        }
        paint(at[0], TOP_AT.w, TOP_AT.h, |x, y| {
            top_point(x, y, TOP_AT.w, TOP_AT.h)
        });
        self.post(&window, 0, &[]).map_err(say("POST"))?;
        rt::println!("focus-probe: top client window is up and its refusals are exact");
        let mut stage = 0;
        let mut serial = 0;
        self.watch(&window, |e| {
            match (stage, e.kind) {
                (0, proto_comp::CONFIGURE) => {
                    if (e.x, e.y) != (TOP_SIZE.0 as i32, TOP_SIZE.1 as i32)
                        || e.code != proto_comp::STATE_RESIZING as u16
                        || e.value <= 0
                    {
                        rt::println!("focus-probe: top client: the CONFIGURE is {e:?}");
                        return Err("the first CONFIGURE is not the one asked");
                    }
                    serial = e.value as u32;
                    // The answer: the size, and the picture of that size, which
                    // waits in the second buffer for the second CONFIGURE.
                    self.size(&window, TOP_SIZE.0, TOP_SIZE.1, serial)
                        .map_err(say("SIZE"))?;
                    paint(at[1], TOP_SIZE.0, TOP_SIZE.1, |x, y| {
                        top_point(x, y, TOP_SIZE.0, TOP_SIZE.1)
                    });
                    // The manager hears of it by the title.
                    self.text(&window, proto_comp::TEXT_TITLE, "sized")
                        .map_err(say("SET_TEXT"))?;
                    rt::println!("focus-probe: top client was asked for a size and answered");
                    stage = 1;
                }
                (1, proto_comp::CONFIGURE) => {
                    if (e.x, e.y) != (0, 0) || e.value as u32 <= serial {
                        return Err("the second CONFIGURE is not a later choice of the client");
                    }
                    self.post(
                        &window,
                        1,
                        &[Rect {
                            x: 0,
                            y: 0,
                            w: TOP_SIZE.0,
                            h: TOP_SIZE.1,
                        }],
                    )
                    .map_err(say("POST"))?;
                    rt::println!("focus-probe: top client posted the new size");
                    stage = 2;
                }
                (2, proto_comp::CLOSE_REQUEST) => {
                    rt::println!("focus-probe: top client was asked to close");
                    return Ok(true);
                }
                _ => {}
            }
            Ok(false)
        })
    }

    /// The manager of the top-window image.
    fn top_manager(self) -> Result<(), &'static str> {
        let display = self.display()?;
        self.describe_when_ready(&display)?;
        let notify = sys::handle_duplicate(&self.channel, Rights::NOTIFY | Rights::TRANSFER)
            .map_err(say("duplicate"))?;
        let mut w = Writer::new();
        proto_comp::write_manage(manage::SUBSCRIBE, 0, 0, 0, &mut w)
            .map_err(say("MANAGE's bytes"))?;
        match call_with(&display, w.as_bytes(), [notify.erase()].into())
            .map_err(say("SUBSCRIBE"))?
        {
            (Status::Ok, _) => {}
            _ => return Err("SUBSCRIBE was refused"),
        }
        // An operation the service has not is refused.
        if !Self::refused(
            self.manage(&display, manage::LAST + 1, 0, 0, 0),
            proto_comp::INVALID,
        ) {
            return Err("an unknown operation was not refused with INVALID");
        }
        // The client's making and its two texts.
        let mut client = None;
        let mut texts = 0;
        self.watch(&display, |e| {
            match e.kind {
                CREATE => client = Some(e.value as u32),
                proto_comp::TITLE if Some(e.value as u32) == client => texts |= e.x,
                _ => {}
            }
            Ok(client.is_some() && texts == 3)
        })?;
        let id = client.ok_or("no window was made")?;
        self.until(&display, "the client never showed its window", |d| {
            d.frames >= 1
        })?;
        let info = self.info(&display, id).map_err(say("INFO"))?;
        if info.title() != b"Top"
            || info.app() != b"probe"
            || (info.cap_w, info.cap_h) != (WIDTH, HEIGHT)
            || info.flags != 0
        {
            rt::println!("focus-probe: top manager: INFO is {info:?}");
            return Err("INFO of the client is not what it set");
        }
        if !Self::refused(
            self.info(&display, 0x7fff_fff0).map(drop),
            proto_comp::INVALID,
        ) {
            return Err("INFO of no window was not refused with INVALID");
        }
        rt::println!("focus-probe: top manager has the client's texts and capacity");
        // The frame: a window of the manager's own, over the client until it is
        // linked.
        let frame_at = Rect {
            x: TOP_AT.x - EDGE,
            y: TOP_AT.y - TITLE_H,
            w: TOP_AT.w + 2 * EDGE,
            h: TOP_AT.h + TITLE_H + EDGE,
        };
        let (frame, fid) = self
            .create_as(&display, frame_at, FORMAT_XRGB8888)
            .map_err(say("WINDOW_CREATE of the frame"))?;
        let (objects, at) = self.buffers(2, SCREEN_BYTES)?;
        self.attach_as(&frame, WIDTH * 4, &objects[..2], FORMAT_XRGB8888)
            .map_err(say("ATTACH of the frame"))?;
        paint(at[0], frame_at.w, frame_at.h, |x, y| {
            frame_point(x, y, frame_at.w, frame_at.h)
        });
        self.post(&frame, 0, &[])
            .map_err(say("POST of the frame"))?;
        self.until(&display, "the frame never showed", |d| d.frames >= 2)?;
        if self.listed(&display, fid)?.depth < self.listed(&display, id)?.depth {
            return Err("a window of the manager is under the client before the link");
        }
        self.manage(&display, manage::LINK, id, fid, 0)
            .map_err(say("LINK"))?;
        // Linked: the frame is directly under the client.
        let (c, f) = (self.listed(&display, id)?, self.listed(&display, fid)?);
        if f.depth + 1 != c.depth {
            return Err("the frame is not directly under the client once linked");
        }
        let flags = |i: &proto_comp::Info| i.flags;
        let (ic, iff) = (
            self.info(&display, id).map_err(say("INFO"))?,
            self.info(&display, fid).map_err(say("INFO"))?,
        );
        if flags(&ic) != proto_comp::INFO_LEADER
            || flags(&iff) != proto_comp::INFO_FOLLOWER | proto_comp::INFO_MANAGER
        {
            return Err("INFO does not tell the link");
        }
        rt::println!("focus-probe: top frame is linked directly under the client");
        self.settled(&display)?;
        rt::println!(
            "focus-probe: top linked crc {:08x}",
            top_crc(&[(frame_at, true), (TOP_AT, false)])
        );
        self.sleep(SNAPSHOT_NS);
        // The size: the client answers with SIZE and says so by its title. Its
        // window is the old size until it posts, and moves with its frame.
        self.manage(
            &display,
            manage::CONFIGURE,
            id,
            manage::size(TOP_SIZE.0, TOP_SIZE.1),
            proto_comp::STATE_RESIZING,
        )
        .map_err(say("CONFIGURE"))?;
        self.watch(&display, |e| {
            Ok(e.kind == proto_comp::TITLE && e.value as u32 == id && e.x == 1)
        })?;
        self.manage(&display, manage::MOVE, id, TOP_MOVE.0, TOP_MOVE.1)
            .map_err(say("MOVE"))?;
        let (c, f) = (self.listed(&display, id)?, self.listed(&display, fid)?);
        let (dx, dy) = (TOP_MOVE.0 - TOP_AT.x, TOP_MOVE.1 - TOP_AT.y);
        if (c.x, c.y, c.w, c.h) != (TOP_MOVE.0, TOP_MOVE.1, TOP_AT.w, TOP_AT.h)
            || (f.x, f.y, f.w, f.h) != (frame_at.x + dx, frame_at.y + dy, frame_at.w, frame_at.h)
        {
            rt::println!("focus-probe: top manager: the pair is {c:?} {f:?}");
            return Err("the pair did not move together, or the size changed with SIZE");
        }
        // A move that takes the frame off the screen moves neither.
        if !Self::refused(
            self.manage(&display, manage::MOVE, id, 2, 200),
            proto_comp::INVALID,
        ) {
            return Err("a move that takes the frame off the screen was not refused");
        }
        if (self.listed(&display, id)?.x, self.listed(&display, fid)?.x)
            != (TOP_MOVE.0, frame_at.x + dx)
        {
            return Err("a refused move moved a window");
        }
        let moved_frame = Rect {
            x: frame_at.x + dx,
            y: frame_at.y + dy,
            ..frame_at
        };
        let moved = Rect {
            x: TOP_MOVE.0,
            y: TOP_MOVE.1,
            ..TOP_AT
        };
        self.settled(&display)?;
        rt::println!(
            "focus-probe: top pending crc {:08x}",
            top_crc(&[(moved_frame, true), (moved, false)])
        );
        self.sleep(SNAPSHOT_NS);
        // The client's choice: it posts the new size, and the frame follows.
        self.manage(&display, manage::CONFIGURE, id, 0, 0)
            .map_err(say("CONFIGURE"))?;
        self.watch(&display, |e| {
            if e.kind == proto_comp::RESIZED && e.value as u32 == id {
                if (e.x, e.y) != (TOP_SIZE.0 as i32, TOP_SIZE.1 as i32) {
                    return Err("RESIZED does not say the size posted");
                }
                return Ok(true);
            }
            Ok(false)
        })?;
        let grown = Rect {
            w: TOP_SIZE.0 + 2 * EDGE,
            h: TOP_SIZE.1 + TITLE_H + EDGE,
            ..moved_frame
        };
        self.size(&frame, grown.w, grown.h, 0)
            .map_err(say("SIZE of the frame"))?;
        paint(at[1], grown.w, grown.h, |x, y| {
            frame_point(x, y, grown.w, grown.h)
        });
        self.post(
            &frame,
            1,
            &[Rect {
                x: 0,
                y: 0,
                w: grown.w,
                h: grown.h,
            }],
        )
        .map_err(say("POST of the frame"))?;
        self.watch(&display, |e| {
            Ok(e.kind == proto_comp::RESIZED
                && e.value as u32 == fid
                && (e.x, e.y) == (grown.w as i32, grown.h as i32))
        })?;
        let regrown = Rect {
            w: TOP_SIZE.0,
            h: TOP_SIZE.1,
            ..moved
        };
        self.settled(&display)?;
        let (c, f) = (self.listed(&display, id)?, self.listed(&display, fid)?);
        if (c.x, c.y, c.w, c.h) != (regrown.x, regrown.y, regrown.w, regrown.h)
            || (f.x, f.y, f.w, f.h) != (grown.x, grown.y, grown.w, grown.h)
        {
            rt::println!("focus-probe: top manager: the pair is {c:?} {f:?}");
            return Err("the sizes in LIST are not the sizes posted");
        }
        rt::println!(
            "focus-probe: top resized crc {:08x}",
            top_crc(&[(grown, true), (regrown, false)])
        );
        self.sleep(SNAPSHOT_NS);
        // The end: the client is asked, closes itself, and its frame goes with
        // it (hidden by the service).
        self.manage(&display, manage::CLOSE, id, 0, 0)
            .map_err(say("CLOSE"))?;
        self.watch(&display, |e| {
            Ok(e.kind == proto_comp::CLOSE && e.value as u32 == id)
        })?;
        self.settled(&display)?;
        if self.listed(&display, fid)?.flags & proto_comp::SHOWN != 0 {
            return Err("the frame is still shown after its window went");
        }
        let info = self.info(&display, fid).map_err(say("INFO"))?;
        if info.flags != proto_comp::INFO_MANAGER {
            return Err("the link did not end with the window");
        }
        rt::println!("focus-probe: top closed crc {:08x}", top_crc(&[]));
        self.sleep(SNAPSHOT_NS);
        Ok(())
    }
}
