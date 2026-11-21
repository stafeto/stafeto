// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guest probe of the composition service (`gpu` in the image of
//! `comp::TABLE`, services/compositor). A client of init whose role the
//! byte of its own arguments names:
//!
//! - `w`, the window client: DESCRIBE, the refusals of WINDOW_CREATE,
//!   ATTACH and POST, a window of 320 by 200 at (100, 50) with two
//!   buffers; a pattern in buffer 0 and POST, a line with the CRC-32 of
//!   the screen as it should look (black around the window) that xtask
//!   compares with a screenshot of QEMU; buffer 1, the same but a
//!   rectangle, and POST of that rectangle alone, buffer 0 free once the
//!   frame is shown; a second window over the first (the newest on top),
//!   a fifth window of the context refused. It ends holding its windows:
//!   the end of the process frees them.
//! - `l`, the program of the first revision: waits for the first client's
//!   windows to go, a line with the CRC of the black screen they left,
//!   then OPEN of proto_gpu, a pattern in the buffer (the display driver's
//!   pool, which the service gives it) and FLUSH of all of it and of a
//!   rectangle (the reply of FLUSH comes once the frame is shown), a second
//!   OPEN BUSY, the cleared buffer. The window covers the screen with
//!   nothing above it, so the display shows the pool as it is: DESCRIBE's
//!   `bands` does not grow over three FLUSHes and `bypassed` grows by three
//!   (xtask checks the trace of the device for the scanout of resource 2).
//!   It then waits for the third client's window to come over its own, which
//!   makes the service put the frame together (`bands` grows), and to go,
//!   after which the frames are direct again. After the CLOSE it keeps the
//!   buffer's mapping, then the bare handle, and OPEN is BUSY each time until
//!   the handle is closed; the next window's buffer is cleared (the pool is
//!   cleared once the frame that took the screen back is shown).
//! - `x`, the third client: waits for the program of the first revision to
//!   have its window shown directly, makes a window over it and a line with
//!   the CRC of the screen as it should look, and ends.
//!
//! - `s`, the holder of a scene (init gives its session the scene's mark):
//!   waits until the first revision's program has gone, then refuses a
//!   scene past the limits and what no operation draws, commits a scene of
//!   two windows at the places the first client's windows had (the line
//!   with the CRC of the screen is that of the first client's overlap, which
//!   the first revision's drawing of the same windows makes), FLUSHes a window
//!   of the first revision that no element shows (the reply must come), commits
//!   a scene of that window alone and FLUSHes it (the display shows its pool
//!   directly: `bands` stay as they were), and ends with a scene composed on
//!   request (SCENE_COMPOSE). A SCENE_COMMIT of a window's session is refused.
//!
//! Each check prints its line, and the last says `comp-probe: ok`; xtask
//! reads them.

#![no_std]
#![no_main]

use abi::{Access, Error, MESSAGE_MAX, Rights, Source};
use core::cell::Cell;
use proto_comp::{
    ACTIVE, ASK_COMMITTED, ASK_COMPOSED, Attach, BILINEAR, BUSY, COMMITTED_BIT, COMPOSED_BIT,
    Create, Description, Element, FORMAT_A8, FORMAT_ARGB8888, FORMAT_XRGB8888, INVALID, MIRROR,
    Method, NEAREST, NO_WINDOW, NOT_ALLOWED, Post, Rect, SceneCommit, TRANSPARENCY_ALPHA,
    TRANSPARENCY_MASK, TRANSPARENCY_SOURCE, UNSUPPORTED, code, manage, meaning,
};
use proto_gpu::{HEIGHT, STRIDE, WIDTH};
use proto_init::ServiceArgs;
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Memory, Outgoing, Resource};
use rt::sys::Received;
use rt::wait::{Waited, Waiter};
use rt::{Handle, sys, time};

rt::entry!(main);

/// Where the probe maps its buffers, one place for each.
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
        b"w" => probe.windows(),
        b"l" => probe.legacy(),
        b"x" => probe.above(),
        b"s" => probe.scene(),
        _ => Err("an unknown role"),
    };
    match result {
        Ok(()) => {
            rt::println!("comp-probe: ok");
            0
        }
        Err(reason) => {
            rt::println!("comp-probe: failed: {reason}");
            2
        }
    }
}

/// The reason of a failed step, in the log with what the call said.
fn say<E: core::fmt::Debug>(what: &'static str) -> impl Fn(E) -> &'static str {
    move |e| {
        rt::println!("comp-probe: {what}: {e:?}");
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

fn refused(result: Result<(), Fail>, status: Status) -> bool {
    result == Err(Fail::Status(status))
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

/// The pattern of the screen of the first revision, as gpu-probe has it.
fn screen_pattern(x: u32, y: u32) -> u32 {
    let r = x * 255 / (WIDTH - 1);
    let g = y * 255 / (HEIGHT - 1);
    let b = (x ^ y) & 0xFF;
    r << 16 | g << 8 | b
}

/// The pattern of the first window (320 by 200).
fn window_pattern(x: u32, y: u32) -> u32 {
    let r = x * 255 / 319;
    let g = y * 255 / 199;
    let b = (x ^ y) & 0xFF;
    r << 16 | g << 8 | b
}

/// The pattern of the second window (100 by 100).
fn second_pattern(x: u32, y: u32) -> u32 {
    let r = y * 255 / 99;
    let g = x * 255 / 99;
    r << 16 | g << 8 | 0x40
}

const MARK: u32 = 0x00FF_8000;
/// The rectangle of the first revision's screen that it fills with MARK
/// in its second FLUSH.
const LEGACY_MARK: Rect = Rect {
    x: 100,
    y: 50,
    w: 200,
    h: 100,
};

/// The CRC of the screen of the first revision, with its marked rectangle,
/// and the window of the third client over it when `above`.
fn legacy_crc(above: bool) -> u32 {
    let mut crc = Crc(0xFFFF_FFFF);
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let r = LEGACY_MARK;
            let mut point = if x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h {
                MARK
            } else {
                screen_pattern(x, y)
            };
            let s = SECOND;
            if above && x >= s.x && x < s.x + s.w && y >= s.y && y < s.y + s.h {
                point = second_pattern(x - s.x, y - s.y);
            }
            crc.point(point);
        }
    }
    !crc.0
}
/// The rectangle of buffer 1 that differs from buffer 0, in window
/// coordinates.
const CHANGED: Rect = Rect {
    x: 20,
    y: 20,
    w: 100,
    h: 60,
};

/// The first window's place on the screen, and the second's.
const FIRST: Rect = Rect {
    x: 100,
    y: 50,
    w: 320,
    h: 200,
};
const SECOND: Rect = Rect {
    x: 200,
    y: 100,
    w: 100,
    h: 100,
};

/// The place of the window the scene holder paints and posts once, while no
/// element shows it (a static picture).
const THIRD: Rect = Rect {
    x: 400,
    y: 250,
    w: 100,
    h: 100,
};

/// Whether the point (x, y) of the window is in CHANGED.
fn in_changed(x: u32, y: u32) -> bool {
    (CHANGED.x..CHANGED.x + CHANGED.w).contains(&x)
        && (CHANGED.y..CHANGED.y + CHANGED.h).contains(&y)
}

// -------------------------------------------------- the windows of the elements

/// The points of the window of the elements that has no alpha of its own (64
/// by 40): every point differs from its neighbours.
fn pat_xrgb(x: u32, y: u32) -> u32 {
    let r = (x * 5 + y * 2 + 1) & 0xFF;
    let g = (y * 9 + x + 2) & 0xFF;
    let b = (x * y * 3 + x * 7 + y + 3) & 0xFF;
    r << 16 | g << 8 | b
}

/// The points of the window with an alpha (40 by 30): the colour premultiplied.
fn pat_argb(x: u32, y: u32) -> u32 {
    let a = ((x * 11 + y * 3 + 40) & 0xFF) | 0x20;
    let c = pat_xrgb(x + 3, y + 1);
    a << 24 | ((c >> 16) & 0xFF).min(a) << 16 | ((c >> 8) & 0xFF).min(a) << 8 | (c & 0xFF).min(a)
}

/// The points of a mask.
fn pat_a8(x: u32, y: u32) -> u32 {
    (x * 17 + y * 29 + 5) & 0xFF
}

/// A window of the elements as the reference needs it: its number, its size and
/// format, and the value of a point (as the window's own format has it: the
/// colour of XRGB8888, the premultiplied value of ARGB8888, the alpha of A8).
struct Win {
    id: u32,
    w: u32,
    h: u32,
    format: u32,
    point: fn(u32, u32) -> u32,
}

impl Win {
    /// The point as the source of a drawing: premultiplied ARGB, opaque for the
    /// window without alpha; for A8 the byte.
    fn argb(&self, x: u32, y: u32) -> u32 {
        let v = (self.point)(x, y);
        if self.format == FORMAT_XRGB8888 {
            v | 0xFF00_0000
        } else {
            v
        }
    }
}

/// The CRC of the screen the elements mean over the background `bg`, the
/// points worked out one at a time from the geometry of each element
/// (`proto_comp::meaning`, which knows no band and no matrix).
#[inline(never)]
fn reference_crc(els: &[Element], wins: &[Win], bg: u32) -> u32 {
    let find = |id: u32| wins.iter().find(|w| w.id == id);
    let mut crc = Crc(0xFFFF_FFFF);
    for y in 0..HEIGHT as i32 {
        for x in 0..WIDTH as i32 {
            let mut value = bg & 0x00FF_FFFF;
            for e in els {
                if !meaning::covers(e, x, y) {
                    continue;
                }
                let Some(src) = find(e.source) else {
                    continue;
                };
                let m = if e.transparency & TRANSPARENCY_MASK != 0 {
                    match find(e.mask) {
                        Some(m) => m.argb((x - e.dx) as u32, (y - e.dy) as u32),
                        None => continue,
                    }
                } else {
                    255
                };
                if let Some(s) = meaning::sample(e, x, y, (src.w, src.h), |u, v| src.argb(u, v)) {
                    value = meaning::mix(e, s, m, value);
                }
            }
            crc.point(value);
        }
    }
    !crc.0
}

/// An element of `window` (its whole, `w` by `h` points) on the target
/// (`dx`, `dy`, `dw`, `dh`), turned by `orient` and drawn with `filter` and
/// the `transparency` and `alpha` given.
fn placed(
    window: &Win,
    target: [i32; 4],
    orient: u32,
    filter: u32,
    transparency: u32,
    alpha: u32,
    mask: Option<&Win>,
) -> Element {
    Element {
        source: window.id,
        mask: mask.map_or(NO_WINDOW, |m| m.id),
        sx: 0,
        sy: 0,
        sw: (window.w as i32) << 16,
        sh: (window.h as i32) << 16,
        dx: target[0],
        dy: target[1],
        dw: target[2],
        dh: target[3],
        orient,
        filter,
        transparency,
        alpha,
    }
}

/// What a window of the screen shows, for the expected CRC.
#[derive(Clone, Copy)]
enum Layer {
    /// The first window with buffer 0, or with buffer 1 (the rectangle).
    First {
        marked: bool,
    },
    Second,
    Third,
}

fn layer_point(layer: Layer, x: u32, y: u32) -> u32 {
    match layer {
        Layer::First { marked } => {
            let (wx, wy) = (x - FIRST.x, y - FIRST.y);
            let inside = in_changed(wx, wy);
            if marked && inside {
                MARK
            } else {
                window_pattern(wx, wy)
            }
        }
        Layer::Second => second_pattern(x - SECOND.x, y - SECOND.y),
        Layer::Third => second_pattern(x - THIRD.x, y - THIRD.y),
    }
}

fn layer_rect(layer: Layer) -> Rect {
    match layer {
        Layer::First { .. } => FIRST,
        Layer::Second => SECOND,
        Layer::Third => THIRD,
    }
}

/// The CRC of the screen made of `layers`, bottom first, over black.
fn expected_crc(layers: &[Layer]) -> u32 {
    let mut crc = Crc(0xFFFF_FFFF);
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let mut point = 0;
            for &layer in layers {
                let r = layer_rect(layer);
                if x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h {
                    point = layer_point(layer, x, y);
                }
            }
            crc.point(point);
        }
    }
    !crc.0
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

    /// Waits until the service has shown what was posted: no frame in
    /// progress and no damage waiting.
    fn settled(&self, display: &Handle<Channel>) -> Result<Description, &'static str> {
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        loop {
            let d = self.describe(display).map_err(say("DESCRIBE"))?;
            if d.busy == 0 {
                return Ok(d);
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err("the service never settled");
            }
            self.sleep(RETRY_NS);
        }
    }

    /// A window: its session and number.
    fn create(
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

    fn attach(
        &self,
        window: &Handle<Channel>,
        stride: u32,
        format: u32,
        objects: &[Option<Handle<Memory>>],
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

    fn windows(self) -> Result<(), &'static str> {
        let display = self.display()?;
        let d = self.describe_when_ready(&display)?;
        if (d.width, d.height, d.format) != (WIDTH, HEIGHT, FORMAT_XRGB8888) || d.open != 0 {
            return Err("DESCRIBE does not say a free 640 by 400 screen");
        }
        rt::println!("comp-probe: the screen is 640x400, no window yet");
        // The refusals of WINDOW_CREATE.
        let outside = Rect { x: 400, ..FIRST };
        if self.create(&display, outside, FORMAT_XRGB8888).err()
            != Some(Fail::Status(code(INVALID)))
            || self.create(&display, FIRST, 2).err() != Some(Fail::Status(code(UNSUPPORTED)))
        {
            return Err("a window outside the screen or of another format was not refused");
        }
        rt::println!("comp-probe: windows outside the screen or of another format are refused");
        let (window, id) = self
            .create(&display, FIRST, FORMAT_XRGB8888)
            .map_err(say("WINDOW_CREATE"))?;
        let stride = FIRST.w * 4;
        let bytes = u64::from(stride) * u64::from(FIRST.h);
        // POST before ATTACH, ATTACH with too small an object.
        if !refused(self.post(&window, 0, &[]), code(NOT_ALLOWED)) {
            return Err("POST before ATTACH was not refused");
        }
        let small = sys::mem_create(4096).map_err(say("mem_create"))?;
        if !refused(
            self.attach(&window, stride, FORMAT_XRGB8888, &[Some(small)]),
            code(INVALID),
        ) {
            return Err("ATTACH of too small an object was not refused");
        }
        let fresh = sys::mem_create(bytes.div_ceil(4096) * 4096).map_err(say("mem_create"))?;
        if !refused(
            self.attach(&window, stride - 4, FORMAT_XRGB8888, &[Some(fresh)]),
            code(INVALID),
        ) {
            return Err("ATTACH of a stride under the width was not refused");
        }
        let (objects, at) = self.buffers(2, bytes)?;
        self.attach(&window, stride, FORMAT_XRGB8888, &objects[..2])
            .map_err(say("ATTACH"))?;
        if !refused(
            self.attach(&window, stride, FORMAT_XRGB8888, &objects[..2]),
            code(BUSY),
        ) {
            return Err("a second ATTACH was not BUSY");
        }
        rt::println!("comp-probe: ATTACH takes the buffers once and checks them");
        let points = |b: usize| -> &'static mut [u32] {
            // SAFETY: `buffers` mapped this object for writing at this
            // address; the probe is the only user in one thread.
            unsafe {
                core::slice::from_raw_parts_mut(at[b] as *mut u32, (FIRST.w * FIRST.h) as usize)
            }
        };
        for y in 0..FIRST.h {
            for x in 0..FIRST.w {
                points(0)[(y * FIRST.w + x) as usize] = window_pattern(x, y);
            }
        }
        let before = self.describe(&display).map_err(say("DESCRIBE"))?;
        if before.open != 1 || before.created != 1 {
            return Err("DESCRIBE does not count the window");
        }
        self.post(&window, 0, &[]).map_err(say("POST"))?;
        let after = self.settled(&display)?;
        if after.frames != before.frames + 1 {
            return Err("the first POST was not one frame");
        }
        rt::println!(
            "comp-probe: window crc {:08x}",
            expected_crc(&[Layer::First { marked: false }])
        );
        self.sleep(SNAPSHOT_NS);
        // Buffer 0 is on the screen: posting it again is BUSY.
        if !refused(self.post(&window, 0, &[]), code(BUSY)) {
            return Err("POST of the buffer on the screen was not BUSY");
        }
        // Buffer 1: the same but a rectangle; only the rectangle is posted.
        for y in 0..FIRST.h {
            for x in 0..FIRST.w {
                let inside = in_changed(x, y);
                points(1)[(y * FIRST.w + x) as usize] =
                    if inside { MARK } else { window_pattern(x, y) };
            }
        }
        let wide = Rect {
            w: FIRST.w + 1,
            ..CHANGED
        };
        if !refused(self.post(&window, 1, &[wide]), code(INVALID))
            || !refused(self.post(&window, 2, &[]), code(INVALID))
            || !refused(self.post(&window, 1, &[CHANGED; 5]), code(INVALID))
        {
            return Err("a POST with a wrong rectangle or buffer was not INVALID");
        }
        rt::println!("comp-probe: a POST with a wrong buffer or rectangle is INVALID");
        self.post(&window, 1, &[CHANGED])
            .map_err(say("POST of a rectangle"))?;
        self.settled(&display)?;
        rt::println!(
            "comp-probe: partial crc {:08x}",
            expected_crc(&[Layer::First { marked: true }])
        );
        if !self.wait_bits(1) {
            return Err("buffer 0 never came free");
        }
        rt::println!("comp-probe: the buffer the frame replaced came free");
        self.sleep(SNAPSHOT_NS);
        // The kinds of session: the window's cannot DESCRIBE, the
        // context's cannot POST, and FLUSH is the first revision's.
        let mut flush = Writer::new();
        proto_gpu::Rect::SCREEN
            .write(&mut flush)
            .map_err(say("FLUSH's bytes"))?;
        let mut create = Writer::new();
        Create {
            x: 0,
            y: 0,
            w: 1,
            h: 1,
            format: FORMAT_XRGB8888,
            flags: 0,
        }
        .write(&mut create)
        .map_err(say("CREATE's bytes"))?;
        if !refused(
            plain(&window, &Method::Describe.header().bytes()),
            code(NOT_ALLOWED),
        ) || !refused(plain(&window, create.as_bytes()), code(NOT_ALLOWED))
            || !refused(self.post(&display, 0, &[]), code(NOT_ALLOWED))
            || !refused(plain(&window, flush.as_bytes()), code(NOT_ALLOWED))
        {
            return Err("a method of the other kind of session was not refused");
        }
        rt::println!("comp-probe: a session calls its own methods only");
        // A second window over the first: the newest is on top.
        let (second, _) = self
            .create(&display, SECOND, FORMAT_XRGB8888)
            .map_err(say("the second WINDOW_CREATE"))?;
        let (objects2, at2) = self.buffers(1, 100 * 100 * 4)?;
        self.attach(&second, 400, FORMAT_XRGB8888, &objects2[..1])
            .map_err(say("ATTACH"))?;
        for y in 0..100u32 {
            for x in 0..100u32 {
                // SAFETY: as above, for the second window's buffer.
                unsafe {
                    (at2[0] as *mut u32)
                        .add((y * 100 + x) as usize)
                        .write(second_pattern(x, y))
                };
            }
        }
        self.post(&second, 0, &[])
            .map_err(say("POST of the second"))?;
        self.settled(&display)?;
        rt::println!(
            "comp-probe: overlap crc {:08x}",
            expected_crc(&[Layer::First { marked: true }, Layer::Second])
        );
        self.sleep(SNAPSHOT_NS);
        // The second window goes: its place is reused for a window with
        // buffers once the pages are unmapped.
        drop(second);
        drop(objects2);
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        while self.settled(&display)?.open != 1 {
            if time::ticks_to_ns(time::now()) > end {
                return Err("the second window never went");
            }
            self.sleep(RETRY_NS);
        }
        let (reuse, _) = self
            .create(
                &display,
                Rect {
                    x: 0,
                    y: 100,
                    w: 8,
                    h: 8,
                },
                FORMAT_XRGB8888,
            )
            .map_err(say("the window after one went"))?;
        let (objects3, _) = self.buffers(1, 8 * 8 * 4)?;
        self.attach(&reuse, 32, FORMAT_XRGB8888, &objects3[..1])
            .map_err(say("ATTACH after a window went"))?;
        rt::println!("comp-probe: a window that went gives its place to a window with buffers");
        // The context's share of windows: four, the fifth is refused.
        let _third = self
            .create(
                &display,
                Rect {
                    x: 0,
                    y: 0,
                    w: 8,
                    h: 8,
                },
                FORMAT_XRGB8888,
            )
            .map_err(say("the third window"))?;
        let _fourth = self
            .create(
                &display,
                Rect {
                    x: 8,
                    y: 0,
                    w: 8,
                    h: 8,
                },
                FORMAT_XRGB8888,
            )
            .map_err(say("the fourth window"))?;
        let fifth = self.create(
            &display,
            Rect {
                x: 16,
                y: 0,
                w: 8,
                h: 8,
            },
            FORMAT_XRGB8888,
        );
        if fifth.err() != Some(Fail::Status(proto_gpu::LIMIT)) {
            return Err("the fifth window of a context was not refused");
        }
        let d = self.describe(&display).map_err(say("DESCRIBE"))?;
        if d.open != 4 || d.created != 5 {
            return Err("DESCRIBE does not count four windows");
        }
        rt::println!("comp-probe: a context has four windows at most");
        let _ = id;
        rt::println!("comp-probe: the client ends with its windows");
        Ok(())
    }

    /// The third client: a window over the window of the first revision once
    /// the service shows that window's buffer directly.
    fn above(self) -> Result<(), &'static str> {
        let display = self.display()?;
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        loop {
            let d = self.describe_when_ready(&display)?;
            if d.open == 1 && d.bypassed >= 4 && d.busy == 0 {
                break;
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err("the window of the first revision was never shown directly");
            }
            self.sleep(RETRY_NS);
        }
        rt::println!("comp-probe: the window below is shown from its pool");
        let (window, _) = self
            .create(&display, SECOND, FORMAT_XRGB8888)
            .map_err(say("WINDOW_CREATE over the pool"))?;
        let (objects, at) = self.buffers(1, 100 * 100 * 4)?;
        self.attach(&window, 400, FORMAT_XRGB8888, &objects[..1])
            .map_err(say("ATTACH"))?;
        for y in 0..100u32 {
            for x in 0..100u32 {
                // SAFETY: the buffer is mapped for writing at `at[0]`, 100 by
                // 100 points of 4 bytes, and this probe is the only user.
                unsafe {
                    (at[0] as *mut u32)
                        .add((y * 100 + x) as usize)
                        .write(second_pattern(x, y))
                };
            }
        }
        self.post(&window, 0, &[])
            .map_err(say("POST over the pool"))?;
        self.settled(&display)?;
        rt::println!("comp-probe: above crc {:08x}", legacy_crc(true));
        self.sleep(SNAPSHOT_NS);
        rt::println!("comp-probe: the client over the pool ends with its window");
        Ok(())
    }

    /// SCENE_COMMIT of `elements`.
    fn commit(
        &self,
        session: &Handle<Channel>,
        flags: u32,
        elements: &[Element],
    ) -> Result<(), Fail> {
        let mut w = Writer::new();
        SceneCommit::new(flags, 0xFF00_0000, elements)
            .and_then(|c| c.write(&mut w))
            .map_err(Fail::Status)?;
        plain(session, w.as_bytes())
    }

    /// The window of `size` that shows through the whole of `at` on the
    /// screen: an element.
    fn element(window: u32, at: Rect) -> Element {
        Element {
            source: window,
            mask: NO_WINDOW,
            sx: 0,
            sy: 0,
            sw: (at.w as i32) << 16,
            sh: (at.h as i32) << 16,
            dx: at.x as i32,
            dy: at.y as i32,
            dw: at.w as i32,
            dh: at.h as i32,
            orient: 0,
            filter: 0,
            transparency: 0,
            alpha: 255,
        }
    }

    /// A window `rect` with two buffers, both filled by `point`, and its id. The
    /// objects stay mapped for the probe's life.
    fn painted(
        &self,
        display: &Handle<Channel>,
        rect: Rect,
        point: fn(u32, u32) -> u32,
    ) -> Result<(Handle<Channel>, u32), &'static str> {
        let (window, id, _) = self.painted_in(display, rect, FORMAT_XRGB8888, point)?;
        Ok((window, id))
    }

    /// A window of `format` (an A8 window is `rect.w` bytes a line, rounded up to
    /// a multiple of 4) with two buffers filled by `point`: its session, its id
    /// and its description for the reference.
    fn painted_in(
        &self,
        display: &Handle<Channel>,
        rect: Rect,
        format: u32,
        point: fn(u32, u32) -> u32,
    ) -> Result<(Handle<Channel>, u32, Win), &'static str> {
        let (window, id) = self
            .create(display, rect, format)
            .map_err(say("WINDOW_CREATE"))?;
        let (stride, bytes_per_point) = if format == FORMAT_A8 {
            ((rect.w + 3) & !3, 1)
        } else {
            (rect.w * 4, 4)
        };
        let bytes = u64::from(stride) * u64::from(rect.h);
        let (objects, at) = self.buffers(2, bytes)?;
        self.attach(&window, stride, format, &objects[..2])
            .map_err(say("ATTACH"))?;
        for buffer in &at[..2] {
            for y in 0..rect.h {
                for x in 0..rect.w {
                    // SAFETY: the buffer is mapped for writing at `buffer`, `stride`
                    // bytes by `rect.h` lines, and this probe is its only user.
                    unsafe {
                        let line = (*buffer as *mut u8).add((y * stride) as usize);
                        if bytes_per_point == 1 {
                            line.add(x as usize).write(point(x, y) as u8);
                        } else {
                            (line as *mut u32).add(x as usize).write(point(x, y));
                        }
                    }
                }
            }
        }
        // The objects live as long as the window's session in the service, which
        // holds its own handles; the probe leaves its mappings in place.
        core::mem::forget(objects);
        Ok((
            window,
            id,
            Win {
                id,
                w: rect.w,
                h: rect.h,
                format,
                point,
            },
        ))
    }

    /// The holder of a scene.
    fn scene(self) -> Result<(), &'static str> {
        let display = self.display()?;
        // The others are done: the first revision's program has had its frames
        // shown directly (`bypassed` 5) and its window has gone.
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        loop {
            let d = self.describe_when_ready(&display)?;
            if d.open == 0 && d.bypassed >= 5 && d.busy == 0 {
                break;
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err("the other clients never finished");
            }
            self.sleep(RETRY_NS);
        }
        let notify = sys::handle_duplicate(&self.channel, Rights::NOTIFY | Rights::TRANSFER)
            .map_err(say("a handle for the scene"))?;
        let mut w = Writer::new();
        proto_comp::write_manage(manage::SUBSCRIBE, 0, 0, 0, &mut w).map_err(say("SUBSCRIBE"))?;
        match call_with(&display, w.as_bytes(), [notify.erase()].into()) {
            Ok((Status::Ok, _)) => {}
            _ => return Err("the scene session could not subscribe"),
        }
        let (a, a_id) = self.painted(&display, FIRST, window_pattern)?;
        let (b, b_id) = self.painted(&display, SECOND, second_pattern)?;
        // A SCENE_COMMIT is the scene session's alone.
        let first = Self::element(a_id, FIRST);
        let second = Self::element(b_id, SECOND);
        if !refused(self.commit(&a, ACTIVE, &[first]), code(NOT_ALLOWED)) {
            return Err("a window's session committed a scene");
        }
        // Refusals: a count of 17 (the bytes of 16 and a word patched), a
        // source rectangle past the window, a turn no operation draws.
        let mut buffer = [0u8; MESSAGE_MAX];
        let mut sixteen = Writer::new();
        SceneCommit::new(ACTIVE, 0, &[first; 16])
            .and_then(|c| c.write(&mut sixteen))
            .map_err(say("a scene of 16"))?;
        let bytes = sixteen.as_bytes();
        buffer[..bytes.len()].copy_from_slice(bytes);
        buffer[16..20].copy_from_slice(&17u32.to_le_bytes());
        if !refused(plain(&display, &buffer[..bytes.len()]), code(INVALID)) {
            return Err("a scene of 17 elements was not INVALID");
        }
        let mut big = first;
        big.sw += 1 << 16;
        big.dw += 1;
        // A turn is drawn: taken. Sixteen elements that each cost a band's calls
        // are taken too: the service draws them in groups, a step each.
        let mut turned = first;
        turned.orient = 1;
        let mut dear = first;
        dear.filter = BILINEAR;
        dear.transparency = TRANSPARENCY_ALPHA | TRANSPARENCY_SOURCE;
        if !refused(self.commit(&display, ACTIVE, &[big]), code(INVALID))
            || self.commit(&display, ACTIVE, &[turned]).is_err()
            || self.commit(&display, ACTIVE, &[dear; 16]).is_err()
        {
            return Err("a scene out of its limits was not refused as it should be");
        }
        self.commit(&display, ACTIVE, &[first; 16])
            .map_err(say("a scene of 16"))?;
        rt::println!("comp-probe: a scene is committed by its session and refused past its limits");
        // The scene of the two windows. COMMITTED comes with the frame that takes it.
        self.commit(&display, ACTIVE | ASK_COMMITTED, &[first, second])
            .map_err(say("SCENE_COMMIT"))?;
        if !self.wait_bits(COMMITTED_BIT) {
            return Err("COMMITTED never came");
        }
        self.settled(&display)?;
        self.post(&a, 0, &[]).map_err(say("POST of the first"))?;
        self.post(&b, 0, &[]).map_err(say("POST of the second"))?;
        self.settled(&display)?;
        rt::println!("comp-probe: the scene is taken whole, COMMITTED comes");
        rt::println!(
            "comp-probe: scene crc {:08x}",
            expected_crc(&[Layer::First { marked: false }, Layer::Second])
        );
        self.sleep(SNAPSHOT_NS);
        // A window of the first revision that no element shows: its FLUSH is
        // answered at the taking and does not wait for a frame that has none of it.
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
        if status != proto_gpu::code(proto_gpu::NO_INPUT) {
            return Err("OPEN's status is not NO_INPUT");
        }
        let (Ok(memory), Ok(owner)) = (
            reply.handles.take::<Memory>(0),
            reply.handles.take::<Channel>(1),
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
        .map_err(say("map the pool"))?;
        // SAFETY: mapped for reading and writing just above; the probe is the
        // only user, in one thread.
        let points = unsafe {
            core::slice::from_raw_parts_mut(at as *mut u32, (STRIDE / 4 * HEIGHT) as usize)
        };
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                points[(y * WIDTH + x) as usize] = screen_pattern(x, y);
            }
        }
        let flush = |rect: proto_gpu::Rect| -> Result<(), Fail> {
            let mut w = Writer::new();
            rect.write(&mut w).map_err(Fail::Status)?;
            plain(&owner, w.as_bytes())
        };
        flush(proto_gpu::Rect::SCREEN).map_err(say("FLUSH of a window no element shows"))?;
        rt::println!("comp-probe: a FLUSH of a window no element shows is answered");
        // Its id is the 640 by 400 window of LIST.
        let mut w = Writer::new();
        proto_comp::write_manage(manage::LIST, 0, 0, 0, &mut w).map_err(say("LIST"))?;
        let (status, reply) = call(&display, w.as_bytes()).map_err(say("LIST"))?;
        if status != Status::Ok {
            return Err("LIST was refused");
        }
        let mut pool_id = None;
        let mut bytes = [0u8; MESSAGE_MAX];
        proto_comp::read_list(reply.bytes(&mut bytes), |r| {
            if (r.w, r.h) == (WIDTH, HEIGHT) {
                pool_id = Some(r.id);
            }
        })
        .map_err(say("LIST's reply"))?;
        let pool_id = pool_id.ok_or("LIST has no window of the screen's size")?;
        // The scene of that window alone: shown from its pool, no band.
        let whole = Rect {
            x: 0,
            y: 0,
            w: WIDTH,
            h: HEIGHT,
        };
        self.commit(&display, ACTIVE, &[Self::element(pool_id, whole)])
            .map_err(say("SCENE_COMMIT of the pool"))?;
        let before = self.settled(&display)?;
        flush(proto_gpu::Rect::SCREEN).map_err(say("FLUSH of the shown window"))?;
        let after = self.settled(&display)?;
        if after.bands != before.bands || after.bypassed != before.bypassed + 1 {
            rt::println!(
                "comp-probe: bands {} then {}, bypassed {} then {}",
                before.bands,
                after.bands,
                before.bypassed,
                after.bypassed
            );
            return Err("the window of the first revision under a scene was not shown directly");
        }
        let mut crc = Crc(0xFFFF_FFFF);
        for &p in &points[..(WIDTH * HEIGHT) as usize] {
            crc.point(p);
        }
        rt::println!("comp-probe: scene legacy crc {:08x}", !crc.0);
        self.sleep(SNAPSHOT_NS);
        // A window that posted once while no element showed it: a static
        // picture. A scene that shows it later has it in its first frame.
        let (c, c_id) = self.painted(&display, THIRD, second_pattern)?;
        self.post(&c, 0, &[])
            .map_err(say("POST of the static window"))?;
        self.sleep(100_000_000);
        self.settled(&display)?;
        self.commit(
            &display,
            ACTIVE,
            &[first, second, Self::element(c_id, THIRD)],
        )
        .map_err(say("SCENE_COMMIT with the static window"))?;
        self.settled(&display)?;
        rt::println!(
            "comp-probe: scene static crc {:08x}",
            expected_crc(&[Layer::First { marked: false }, Layer::Second, Layer::Third])
        );
        self.sleep(SNAPSHOT_NS);
        // A scene composed on request: SCENE_COMPOSE is refused for an active
        // scene, and for the other it makes the frame, with COMPOSED at its end.
        if !refused(
            {
                let mut w = Writer::new();
                proto_comp::write_scene_compose(ASK_COMPOSED, &mut w).map_err(say("COMPOSE"))?;
                plain(&display, w.as_bytes())
            },
            code(UNSUPPORTED),
        ) {
            return Err("SCENE_COMPOSE of an active scene was not UNSUPPORTED");
        }
        self.commit(&display, ASK_COMMITTED, &[first, second])
            .map_err(say("SCENE_COMMIT, composed on request"))?;
        if !self.wait_bits(COMMITTED_BIT) {
            return Err("COMMITTED of a scene composed on request never came");
        }
        // The windows' buffers were given back while no element showed them, and
        // are posted again; nothing is taken until the request.
        self.post(&a, 1, &[])
            .map_err(say("POST of the first again"))?;
        self.post(&b, 1, &[])
            .map_err(say("POST of the second again"))?;
        let held = self.settled(&display)?;
        let mut w = Writer::new();
        proto_comp::write_scene_compose(ASK_COMPOSED, &mut w).map_err(say("COMPOSE"))?;
        plain(&display, w.as_bytes()).map_err(say("SCENE_COMPOSE"))?;
        if !self.wait_bits(COMPOSED_BIT) {
            return Err("COMPOSED never came");
        }
        let done = self.settled(&display)?;
        if done.frames <= held.frames {
            return Err("SCENE_COMPOSE made no frame");
        }
        rt::println!(
            "comp-probe: a scene composed on request is made by SCENE_COMPOSE, COMPOSED comes"
        );
        rt::println!(
            "comp-probe: scene composed crc {:08x}",
            expected_crc(&[Layer::First { marked: false }, Layer::Second])
        );
        self.sleep(SNAPSHOT_NS);
        // The windows so far go, for a context has four places: then the scenes
        // of the elements, each with a kind of drawing the service has.
        drop((a, b, c));
        drop(owner);
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        while self.settled(&display)?.open != 0 {
            if time::ticks_to_ns(time::now()) > end {
                return Err("the windows of the scene never closed");
            }
            self.sleep(RETRY_NS);
        }
        self.elements(&display)?;
        let _ = memory;
        rt::println!("comp-probe: the scene holder ends with its windows");
        Ok(())
    }

    /// The scenes of the elements: a stretch, the eight orientations, the
    /// bilinear filter, a global alpha and a mask, each drawn by the service and
    /// told as the CRC of the screen the reference (`meaning`) works out for it.
    #[inline(never)]
    fn elements(&self, display: &Handle<Channel>) -> Result<(), &'static str> {
        let at = |w: u32, h: u32| Rect { x: 0, y: 0, w, h };
        let (p, p_id, pw) = self.painted_in(display, at(64, 40), FORMAT_XRGB8888, pat_xrgb)?;
        let (q, q_id, qw) = self.painted_in(display, at(40, 30), FORMAT_ARGB8888, pat_argb)?;
        let (m, m_id, mw) = self.painted_in(display, at(64, 40), FORMAT_A8, pat_a8)?;
        let (n, n_id, nw) = self.painted_in(display, at(128, 80), FORMAT_A8, pat_a8)?;
        let _ = (p_id, q_id, m_id, n_id);
        for window in [&p, &q, &m, &n] {
            self.post(window, 0, &[])
                .map_err(say("POST of an element's window"))?;
        }
        let wins = [pw, qw, mw, nw];
        let [pw, qw, mw, nw] = &wins;
        let bg = 0xFF20_4060;
        let src = TRANSPARENCY_SOURCE;
        let alpha = TRANSPARENCY_ALPHA;
        let mask = TRANSPARENCY_MASK;
        // Each scene is made, shown and told in turn (the probe's stack is small).
        let show = |name: &str, els: &[Element]| -> Result<(), &'static str> {
            let mut w = Writer::new();
            SceneCommit::new(ACTIVE, bg, els)
                .and_then(|c| c.write(&mut w))
                .map_err(say("a scene of elements"))?;
            plain(display, w.as_bytes()).map_err(say("SCENE_COMMIT of elements"))?;
            self.settled(display)?;
            rt::println!(
                "comp-probe: element {name} crc {:08x}",
                reference_crc(els, &wins, bg)
            );
            self.sleep(SNAPSHOT_NS);
            Ok(())
        };
        show(
            "stretch",
            &[
                placed(pw, [40, 30, 128, 80], 0, NEAREST, 0, 255, None),
                placed(pw, [200, 30, 32, 20], 0, NEAREST, 0, 255, None),
                placed(qw, [300, 40, 80, 60], 0, NEAREST, src, 255, None),
                placed(qw, [300, 130, 20, 15], 0, NEAREST, src, 255, None),
                placed(pw, [40, 150, 128, 40], 0, NEAREST, 0, 255, None),
            ],
        )?;
        let mut grid = [Element::NONE; 8];
        for (k, e) in grid.iter_mut().enumerate() {
            let (w, h) = if k & 1 != 0 { (40, 64) } else { (64, 40) };
            let (x, y) = (10 + (k as i32 % 4) * 150, 40 + (k as i32 / 4) * 150);
            *e = placed(pw, [x, y, w, h], k as u32, NEAREST, 0, 255, None);
        }
        show("orient", &grid)?;
        show(
            "bilinear",
            &[
                placed(pw, [30, 30, 128, 80], 0, BILINEAR, 0, 255, None),
                placed(pw, [200, 30, 32, 20], 0, BILINEAR, 0, 255, None),
                placed(qw, [300, 30, 80, 60], 0, BILINEAR, src, 255, None),
                placed(pw, [30, 150, 80, 128], 1, BILINEAR, 0, 255, None),
                placed(pw, [150, 150, 40, 64], 3 | MIRROR, BILINEAR, 0, 255, None),
                placed(qw, [300, 150, 80, 60], 2, BILINEAR, src, 255, None),
            ],
        )?;
        show(
            "alpha",
            &[
                placed(pw, [0, 0, 256, 160], 0, NEAREST, 0, 255, None),
                placed(pw, [50, 50, 64, 40], 0, NEAREST, alpha, 128, None),
                placed(qw, [150, 50, 40, 30], 0, NEAREST, alpha, 160, None),
                placed(qw, [250, 50, 40, 30], 0, NEAREST, alpha | src, 160, None),
                placed(pw, [50, 150, 128, 80], 0, NEAREST, alpha, 200, None),
                placed(qw, [250, 150, 60, 80], 1, BILINEAR, alpha | src, 90, None),
            ],
        )?;
        show(
            "mask",
            &[
                placed(pw, [0, 0, 256, 160], 0, NEAREST, 0, 255, None),
                placed(pw, [50, 50, 64, 40], 0, NEAREST, mask, 255, Some(mw)),
                placed(pw, [200, 50, 128, 80], 0, BILINEAR, mask, 255, Some(nw)),
                placed(
                    pw,
                    [50, 150, 64, 40],
                    0,
                    NEAREST,
                    mask | alpha,
                    140,
                    Some(mw),
                ),
            ],
        )?;
        // The edges of the screen cut the elements, and the mask goes with them.
        show(
            "maskcut",
            &[
                placed(pw, [-30, -20, 64, 40], 0, NEAREST, mask, 255, Some(mw)),
                placed(pw, [600, 370, 64, 40], 0, NEAREST, mask, 255, Some(mw)),
                placed(
                    pw,
                    [320, 300, 128, 80],
                    0,
                    NEAREST,
                    mask | alpha,
                    200,
                    Some(nw),
                ),
            ],
        )?;
        rt::println!(
            "comp-probe: elements are drawn: a stretch, the turns and the reflection, the bilinear mean, a global alpha, a mask"
        );
        Ok(())
    }

    /// The program of the first revision.
    fn legacy(self) -> Result<(), &'static str> {
        let display = self.display()?;
        // The first client's window must have been made and be gone, and
        // the black frame its place left must be shown.
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        loop {
            let d = self.describe_when_ready(&display)?;
            if d.created >= 1 && d.open == 0 && d.busy == 0 {
                break;
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err("the first client's windows never went");
            }
            self.sleep(RETRY_NS);
        }
        rt::println!("comp-probe: the windows of the client that ended are gone");
        let mut crc = Crc(0xFFFF_FFFF);
        for _ in 0..WIDTH * HEIGHT {
            crc.point(0);
        }
        rt::println!("comp-probe: black crc {:08x}", !crc.0);
        self.sleep(SNAPSHOT_NS);
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
        if status != proto_gpu::code(proto_gpu::NO_INPUT) {
            return Err("OPEN's status is not NO_INPUT (no input service in the image)");
        }
        let mut buffer = [0; MESSAGE_MAX];
        let (_, screen) =
            proto_gpu::Screen::read(reply.bytes(&mut buffer)).map_err(say("OPEN's reply"))?;
        let (Ok(memory), Ok(owner)) = (
            reply.handles.take::<Memory>(0),
            reply.handles.take::<Channel>(1),
        ) else {
            return Err("OPEN's handles");
        };
        if screen != proto_gpu::Screen::FIXED || !screen.fits() {
            return Err("the screen of OPEN is not 640 by 400");
        }
        let n = self.maps.get();
        let at = MAP_AT + n * MAP_STEP;
        sys::mem_map(
            self.process,
            &memory,
            0,
            u64::from(proto_gpu::SCREEN_BYTES),
            at,
            Access::ReadWrite,
        )
        .map_err(say("map the buffer"))?;
        // SAFETY: mapped for reading and writing just above; the probe is
        // the only user, in one thread.
        let points = unsafe {
            core::slice::from_raw_parts_mut(at as *mut u32, (STRIDE / 4 * HEIGHT) as usize)
        };
        if points.iter().any(|&p| p != 0) {
            return Err("the buffer of a new window is not zero");
        }
        rt::println!("comp-probe: OPEN gives a window of the whole screen, a cleared buffer");
        if call(&display, &open).map(|(s, _)| s) != Ok(proto_gpu::code(proto_gpu::BUSY)) {
            return Err("a second OPEN was not BUSY");
        }
        rt::println!("comp-probe: a second OPEN is BUSY");
        let before = self.settled(&display)?;
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                points[(y * WIDTH + x) as usize] = screen_pattern(x, y);
            }
        }
        let flush = |rect: proto_gpu::Rect| -> Result<(), Fail> {
            let mut w = Writer::new();
            rect.write(&mut w).map_err(Fail::Status)?;
            plain(&owner, w.as_bytes())
        };
        flush(proto_gpu::Rect::SCREEN).map_err(say("FLUSH of the screen"))?;
        let mut crc = Crc(0xFFFF_FFFF);
        for &p in &points[..(WIDTH * HEIGHT) as usize] {
            crc.point(p);
        }
        rt::println!("comp-probe: legacy crc {:08x}", !crc.0);
        self.sleep(SNAPSHOT_NS);
        let inside = LEGACY_MARK;
        for y in inside.y..inside.y + inside.h {
            for x in inside.x..inside.x + inside.w {
                points[(y * WIDTH + x) as usize] = MARK;
            }
        }
        flush(inside).map_err(say("FLUSH of a rectangle"))?;
        let mut crc = Crc(0xFFFF_FFFF);
        for &p in &points[..(WIDTH * HEIGHT) as usize] {
            crc.point(p);
        }
        rt::println!("comp-probe: legacy partial crc {:08x}", !crc.0);
        if !crc.0 != legacy_crc(false) {
            return Err("the legacy partial crc differs from the pattern's");
        }
        self.sleep(SNAPSHOT_NS);
        flush(inside).map_err(say("the third FLUSH"))?;
        if !refused(
            flush(proto_gpu::Rect {
                x: WIDTH,
                y: 0,
                w: 1,
                h: 1,
            }),
            proto_gpu::code(proto_gpu::INVALID),
        ) {
            return Err("a rectangle outside the screen was not INVALID");
        }
        rt::println!("comp-probe: FLUSH of a rectangle outside the screen is INVALID");
        // Three FLUSHes were shown from the pool: no band was put together.
        let after = self.settled(&display)?;
        if after.bands != before.bands || after.bypassed != before.bypassed + 3 {
            rt::println!(
                "comp-probe: bands {} then {}, bypassed {} then {}",
                before.bands,
                after.bands,
                before.bypassed,
                after.bypassed
            );
            return Err("three FLUSHes of a window over the screen were not shown directly");
        }
        rt::println!(
            "comp-probe: three FLUSHes were shown from the pool, no band was put together"
        );
        // A fourth FLUSH: the third client starts once it has seen four frames
        // shown directly, so the check above has been made by then.
        flush(inside).map_err(say("the fourth FLUSH"))?;
        let fourth = self.settled(&display)?;
        if fourth.bands != after.bands || fourth.bypassed != after.bypassed + 1 {
            return Err("the fourth FLUSH was not shown directly");
        }
        // The third client puts a window over the window and ends: the frame
        // that has it is put together (`bands` grow), and the one after it
        // went is direct again. The service may be seen only after both (the
        // third client can end at once when it does not wait for a
        // screenshot), so the wait is for its window to have been made and
        // gone.
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        let back = loop {
            let d = self.settled(&display)?;
            if d.created == fourth.created + 1 && d.open == 1 {
                break d;
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err("the window over the pool never came and went");
            }
            self.sleep(RETRY_NS);
        };
        if back.bands <= fourth.bands {
            return Err("a frame with a window above was not put together");
        }
        rt::println!("comp-probe: a window above the pool made the service put the frame together");
        if back.bypassed != fourth.bypassed + 1 {
            return Err("the frame after the window above went was not direct");
        }
        rt::println!("comp-probe: the window above went and the pool was shown again with no band");
        rt::println!("comp-probe: legacy back crc {:08x}", legacy_crc(false));
        self.sleep(SNAPSHOT_NS);
        // CLOSE with the buffer kept: the next OPEN is BUSY while anyone
        // besides the service holds a reference to it, a mapping first and
        // then the bare handle, and succeeds with a cleared buffer once
        // the handle is gone.
        plain(&owner, &proto_gpu::Method::Close.header().bytes()).map_err(say("CLOSE"))?;
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        loop {
            let (status, _) = call(&display, &open).map_err(say("OPEN after CLOSE"))?;
            if status == proto_gpu::code(proto_gpu::BUSY) {
                break;
            }
            if status != proto_gpu::code(proto_gpu::CLEARING)
                || time::ticks_to_ns(time::now()) > end
            {
                return Err("OPEN with a mapping kept was not BUSY");
            }
            self.sleep(RETRY_NS);
        }
        rt::println!("comp-probe: OPEN is BUSY while a closed window's mapping is kept");
        // The pool is cleared once the frame that took the screen back is
        // shown, which the mapping kept here sees as zeros. The program then
        // writes into it, as a program that kept its mapping can: the pool
        // must be cleared again before a next window has it.
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        while points.iter().any(|&p| p != 0) {
            if time::ticks_to_ns(time::now()) > end {
                return Err("the closed window's buffer was never cleared");
            }
            self.sleep(RETRY_NS);
        }
        points[0] = 0x00DE_AD00;
        points[(WIDTH * HEIGHT) as usize - 1] = 0x00BE_EF00;
        rt::println!("comp-probe: the pool is cleared and written again through the kept mapping");
        // SAFETY: the probe uses `points` no more.
        unsafe { sys::mem_unmap(self.process, at, u64::from(proto_gpu::SCREEN_BYTES)) }
            .map_err(say("unmap"))?;
        if call(&display, &open).map(|(s, _)| s) != Ok(proto_gpu::code(proto_gpu::BUSY)) {
            return Err("OPEN with a handle kept and no mapping was not BUSY");
        }
        rt::println!("comp-probe: OPEN is BUSY while a closed window's handle is kept");
        drop(memory);
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        let (status, mut reply) = loop {
            let (status, reply) = call(&display, &open).map_err(say("OPEN after the unmap"))?;
            if status != proto_gpu::code(proto_gpu::CLEARING) {
                break (status, reply);
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err("OPEN says CLEARING for good");
            }
            self.sleep(RETRY_NS);
        };
        let again = reply.handles.take::<Memory>(0);
        if status != proto_gpu::code(proto_gpu::NO_INPUT) || again.is_err() {
            return Err("OPEN after the unmap failed");
        }
        let again = again.map_err(|_| "OPEN's buffer")?;
        let at2 = MAP_AT + (self.maps.get() + 1) * MAP_STEP;
        sys::mem_map(
            self.process,
            &again,
            0,
            u64::from(proto_gpu::SCREEN_BYTES),
            at2,
            Access::ReadWrite,
        )
        .map_err(say("map again"))?;
        // SAFETY: mapped just above, for reading; the probe is the only user.
        let zero = unsafe { core::slice::from_raw_parts(at2 as *const u32, 256_000) };
        if zero.iter().any(|&p| p != 0) {
            return Err("the buffer of the next window was not cleared");
        }
        rt::println!("comp-probe: after the unmap OPEN gives a cleared buffer");
        rt::println!("comp-probe: the program ends with its window");
        Ok(())
    }
}
