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
//!   then OPEN of proto_gpu, a pattern in the buffer the service made and
//!   FLUSH of all of it and of a rectangle (the reply of FLUSH comes once
//!   the frame is shown), a second OPEN BUSY, the cleared buffer. It ends
//!   holding the window.
//!
//! Each check prints its line, and the last says `comp-probe: ok`; xtask
//! reads them.

#![no_std]
#![no_main]

use abi::{Access, Error, MESSAGE_MAX, Rights, Source};
use core::cell::Cell;
use proto_comp::{
    Attach, BUSY, Create, Description, FORMAT_XRGB8888, INVALID, Method, NOT_ALLOWED, Post, Rect,
    UNSUPPORTED, code,
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

/// Whether the point (x, y) of the window is in CHANGED.
fn in_changed(x: u32, y: u32) -> bool {
    (CHANGED.x..CHANGED.x + CHANGED.w).contains(&x)
        && (CHANGED.y..CHANGED.y + CHANGED.h).contains(&y)
}

/// What a window of the screen shows, for the expected CRC.
#[derive(Clone, Copy)]
enum Layer {
    /// The first window with buffer 0, or with buffer 1 (the rectangle).
    First {
        marked: bool,
    },
    Second,
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
    }
}

fn layer_rect(layer: Layer) -> Rect {
    match layer {
        Layer::First { .. } => FIRST,
        Layer::Second => SECOND,
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
        objects: &[Option<Handle<Memory>>],
    ) -> Result<(), Fail> {
        let mut w = Writer::new();
        Attach {
            count: objects.len() as u32,
            stride,
            format: FORMAT_XRGB8888,
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
        if !refused(self.attach(&window, stride, &[Some(small)]), code(INVALID)) {
            return Err("ATTACH of too small an object was not refused");
        }
        let fresh = sys::mem_create(bytes.div_ceil(4096) * 4096).map_err(say("mem_create"))?;
        if !refused(
            self.attach(&window, stride - 4, &[Some(fresh)]),
            code(INVALID),
        ) {
            return Err("ATTACH of a stride under the width was not refused");
        }
        let (objects, at) = self.buffers(2, bytes)?;
        self.attach(&window, stride, &objects[..2])
            .map_err(say("ATTACH"))?;
        if !refused(self.attach(&window, stride, &objects[..2]), code(BUSY)) {
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
        self.attach(&second, 400, &objects2[..1])
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
        self.attach(&reuse, 32, &objects3[..1])
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
        let inside = proto_gpu::Rect {
            x: 100,
            y: 50,
            w: 200,
            h: 100,
        };
        for y in inside.y..inside.y + inside.h {
            for x in inside.x..inside.x + inside.w {
                points[(y * WIDTH + x) as usize] = 0x00FF_8000;
            }
        }
        flush(inside).map_err(say("FLUSH of a rectangle"))?;
        let mut crc = Crc(0xFFFF_FFFF);
        for &p in &points[..(WIDTH * HEIGHT) as usize] {
            crc.point(p);
        }
        rt::println!("comp-probe: legacy partial crc {:08x}", !crc.0);
        self.sleep(SNAPSHOT_NS);
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
        rt::println!("comp-probe: the program ends with its window");
        Ok(())
    }
}
