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
                self.focus_new(&display, e.code)?;
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
            self.wait_open(&display, 8)?;
            self.wait_open(&display, 1)?;
        }
        Ok(())
    }

    /// FOCUS of window `id` when it is a window of the two clients (their
    /// size), found by LIST: the manager's policy of the probe.
    fn focus_new(&self, display: &Handle<Channel>, id: u16) -> Result<(), &'static str> {
        let mut w = Writer::new();
        proto_comp::write_manage(manage::LIST, 0, 0, 0, &mut w).map_err(say("MANAGE's bytes"))?;
        let reply = sys::send(display, w.as_bytes()).map_err(say("LIST"))?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut mine = false;
        proto_comp::read_list(reply.bytes(&mut buffer), |r| {
            mine |= r.id == u32::from(id) && r.w == A.w && r.h == A.h;
        })
        .map_err(say("LIST's reply"))?;
        if !mine {
            return Ok(());
        }
        let mut w = Writer::new();
        proto_comp::write_manage(manage::FOCUS, u32::from(id), 0, 0, &mut w)
            .map_err(say("MANAGE's bytes"))?;
        plain(display, w.as_bytes()).map_err(say("FOCUS"))
    }

    /// LIST, then FOCUS of the shown window that has not the focus.
    fn switch(&self, display: &Handle<Channel>) -> Result<u32, &'static str> {
        let mut w = Writer::new();
        proto_comp::write_manage(manage::LIST, 0, 0, 0, &mut w).map_err(say("MANAGE's bytes"))?;
        let reply = sys::send(display, w.as_bytes()).map_err(say("LIST"))?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut windows = [WindowRecord::default(); 8];
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

    /// The many windows: seven windows more over the screen's lower right,
    /// four of this context and three of a clone's (a context has four), all of
    /// ARGB8888 and all on one place over the first client's window (ARGB8888 in
    /// the run under -icount), which with it make the eight the service has: a
    /// band over that place lays eight translucent layers (the model of a band
    /// charges each layer after the first). None has the focus while the manager runs, and the bands of
    /// the frames they make stay under the bound (xtask reads the steps of the
    /// run under -icount, which is the one that has them: the other has the
    /// screenshots, and these windows are not in them).
    fn many(self) -> Result<(), &'static str> {
        if !cfg!(feature = "quick") {
            return Ok(());
        }
        let display = self.display()?;
        self.describe_when_ready(&display)?;
        // The first client alone is on the screen.
        self.until(&display, "the first client never stood alone", |d| {
            d.open == 1 && d.created >= 2
        })?;
        let (status, mut reply) =
            call(&display, &proto_gpu::Method::Clone.header().bytes()).map_err(say("CLONE"))?;
        if status != Status::Ok {
            return Err("CLONE was refused");
        }
        let clone = reply
            .handles
            .take::<Channel>(0)
            .map_err(|_| "CLONE's handle")?;
        let mut windows = [const { None }; 7];
        let mut keep = [const { None }; 7];
        for k in 0..7usize {
            let rect = Rect {
                x: A.x + 10,
                y: A.y + 10,
                w: 200,
                h: 150,
            };
            let format = FORMAT_ARGB8888;
            let session = if k < 4 { &display } else { &clone };
            let (window, _) = self
                .create_as(session, rect, format)
                .map_err(say("WINDOW_CREATE of many"))?;
            let (objects, at) = self.buffers(1, 200 * 150 * 4)?;
            self.attach_as(&window, 800, &objects[..1], format)
                .map_err(say("ATTACH of many"))?;
            // SAFETY: `buffers` mapped this object for writing at this
            // address, 200 by 150 points; one thread.
            let points = unsafe { core::slice::from_raw_parts_mut(at[0] as *mut u32, 200 * 150) };
            points.fill(0x8040_4040);
            self.post(&window, 0, &[]).map_err(say("POST of many"))?;
            windows[k] = Some(window);
            keep[k] = Some(objects);
        }
        self.until(&display, "the many windows never settled", |d| d.open == 8)?;
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
        rt::println!("focus-probe: eight windows are shown and none of the seven took the focus");
        // Held until the first client has seen them all.
        self.sleep(500_000_000);
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
            while self.describe(&display).map_err(say("DESCRIBE"))?.created < 9 {
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
