// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The guest probe of the display service (`gpu`, services/virtio-gpu). A
//! client of init whose role the byte of its own arguments names:
//!
//! - `o`, the owner: OPEN of the free screen, a pattern in the buffer and
//!   FLUSH of all of it, a line with the CRC-32 of the pattern's colours
//!   that xtask compares with a screenshot of QEMU; then a rectangle
//!   inside the screen in another colour and FLUSH of that alone (its
//!   offset `y * stride + x * 4` is checked by the second screenshot);
//!   rectangles outside the screen refused; a second OPEN, from the same
//!   session and from a clone, gets BUSY; the owner's session cannot OPEN
//!   or CLONE and a `Display` session cannot FLUSH or CLOSE. It ends
//!   holding the screen: the end of the process returns it.
//! - `s`, the second: asks for the screen until it has seen it BUSY and
//!   then free again, which is after the owner ended; the buffer it finds
//!   is all zero. It shows a pattern and CLOSEs the screen: a FLUSH of the
//!   closed session is REVOKED, and the next OPEN finds the screen free
//!   (CLEARING while it returns, if it comes early) with the buffer it
//!   maps all zero again. Then it kills the service (CRASH): a FLUSH
//!   of the old owner's session gets the channel's refusal, and a new
//!   session from init opens the screen of the new instance.
//!
//! Each check prints its line, and the last says `gpu-probe: ok`; xtask
//! reads them.

#![no_std]
#![no_main]

use abi::{Access, Error, MESSAGE_MAX};
use proto_gpu::{
    BUFFER_BYTES, BUSY, CLEARING, HEIGHT, INVALID, Method, NO_INPUT, NOT_ALLOWED, REVOKED, Rect,
    STRIDE, Screen, WIDTH, code,
};
use proto_init::ServiceArgs;
use proto_wire::{Status, Writer};
use rt::handle::{Channel, Memory, Resource};
use rt::wait::Waiter;
use rt::{Handle, sys, time};

rt::entry!(main);

/// Where the probe maps the screen's buffer, one address for each OPEN.
const FB_AT: usize = 0x20_0000_0000;
const FB_STEP: usize = 0x100_0000;
/// The pause after a frame for the host to photograph it, when the run
/// has the wall clock; the retry period of an OPEN that is told to ask
/// again; the longest wait for the screen.
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
        maps: 0,
    };
    let result = match own {
        b"o" => probe.owner(),
        b"s" => probe.second(),
        _ => Err("an unknown role"),
    };
    match result {
        Ok(()) => {
            rt::println!("gpu-probe: ok");
            0
        }
        Err(reason) => {
            rt::println!("gpu-probe: failed: {reason}");
            2
        }
    }
}

/// What a request to the service came to.
#[derive(Debug, PartialEq, Eq)]
enum Fail {
    /// The service's refusal.
    Status(Status),
    /// The kernel's: the channel closed, for one.
    Kernel(Error),
    /// A reply that is none.
    Bad(&'static str),
}

/// An open screen: what OPEN gave.
struct Opened {
    screen: Screen,
    status: Status,
    buffer: Handle<Memory>,
    owner: Handle<Channel>,
}

struct Probe<'a> {
    process: &'a Handle<rt::handle::Process>,
    parent: &'a Handle<Channel>,
    channel: Handle<Channel>,
    waiter: Waiter,
    maps: usize,
}

/// One request, and the status of its reply with the reply's handles.
fn call(session: &Handle<Channel>, request: &[u8]) -> Result<(Status, sys::Reply), Fail> {
    let reply = sys::send(session, request).map_err(Fail::Kernel)?;
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    let word = bytes.get(..4).ok_or(Fail::Bad("a short reply"))?;
    let status = Status::from_code(u32::from_le_bytes([word[0], word[1], word[2], word[3]]));
    Ok((status, reply))
}

/// A request of the header alone; Ok for status 0.
fn plain(session: &Handle<Channel>, method: Method) -> Result<(), Fail> {
    match call(session, &method.header().bytes())? {
        (Status::Ok, _) => Ok(()),
        (status, _) => Err(Fail::Status(status)),
    }
}

/// OPEN: the screen and its handles, or the service's refusal.
fn open(session: &Handle<Channel>) -> Result<Opened, Fail> {
    let (status, mut reply) = call(session, &Method::Open.header().bytes())?;
    if status != Status::Ok && status != code(NO_INPUT) {
        return Err(Fail::Status(status));
    }
    let mut buffer = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut buffer);
    let (_, screen) = Screen::read(bytes).map_err(|_| Fail::Bad("OPEN's reply"))?;
    let (Ok(buffer), Ok(owner)) = (
        reply.handles.take::<Memory>(0),
        reply.handles.take::<Channel>(1),
    ) else {
        return Err(Fail::Bad("OPEN's handles"));
    };
    if !reply.handles.is_empty() && reply.handles.len() != 2 {
        return Err(Fail::Bad("OPEN's handle count"));
    }
    Ok(Opened {
        screen,
        status,
        buffer,
        owner,
    })
}

/// FLUSH of `rect` through the owner's session.
fn flush(owner: &Handle<Channel>, rect: Rect) -> Result<(), Fail> {
    let mut w = Writer::new();
    rect.write(&mut w).map_err(Fail::Status)?;
    match call(owner, w.as_bytes())? {
        (Status::Ok, _) => Ok(()),
        (status, _) => Err(Fail::Status(status)),
    }
}

/// FLUSH of four numbers as they are, which `Rect::write` would refuse.
fn flush_raw(owner: &Handle<Channel>, numbers: [u32; 4]) -> Result<(), Fail> {
    let mut w = Writer::new();
    Method::Flush.header().write(&mut w).map_err(Fail::Status)?;
    for n in numbers {
        w.u32(n).map_err(Fail::Status)?;
    }
    match call(owner, w.as_bytes())? {
        (Status::Ok, _) => Ok(()),
        (status, _) => Err(Fail::Status(status)),
    }
}

/// The CRC-32 of IEEE 802.3 (the polynomial 0xEDB88320 reflected), the one
/// xtask computes over a screenshot's colours.
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
    fn new() -> Crc {
        Crc(0xFFFF_FFFF)
    }

    fn byte(&mut self, b: u8) {
        self.0 = TABLE[((self.0 ^ u32::from(b)) & 0xFF) as usize] ^ (self.0 >> 8);
    }

    fn finish(&self) -> u32 {
        !self.0
    }
}

/// The CRC of the screen's points as red, green and blue bytes in
/// scanline order.
fn screen_crc(points: &[u32]) -> u32 {
    let mut crc = Crc::new();
    for &p in points {
        crc.byte((p >> 16) as u8);
        crc.byte((p >> 8) as u8);
        crc.byte(p as u8);
    }
    crc.finish()
}

/// The colour of the point (x, y) of the pattern.
fn pattern(x: u32, y: u32) -> u32 {
    let r = x * 255 / (WIDTH - 1);
    let g = y * 255 / (HEIGHT - 1);
    let b = (x ^ y) & 0xFF;
    r << 16 | g << 8 | b
}

/// The points of the screen in the buffer mapped at `at`.
fn points(at: usize) -> &'static mut [u32] {
    // SAFETY: `map` mapped the buffer's object, read and write, at `at`;
    // the probe is its only user, in one thread.
    unsafe { core::slice::from_raw_parts_mut(at as *mut u32, (STRIDE / 4 * HEIGHT) as usize) }
}

impl Probe<'_> {
    fn sleep(&self, ns: u64) {
        if ns == 0 {
            return;
        }
        let deadline = time::ticks_to_ns(time::now()).saturating_add(ns);
        while let Ok(rt::wait::Waited::Got(_)) = self.waiter.receive_until(&self.channel, deadline)
        {
        }
    }

    fn display(&self) -> Result<Handle<Channel>, &'static str> {
        rt::service::connect(self.parent, "gpu").map_err(|_| "connect to gpu")
    }

    /// Maps the buffer of `opened` at the next address; the points.
    fn map(&mut self, opened: &Opened) -> Result<&'static mut [u32], &'static str> {
        let at = FB_AT + self.maps * FB_STEP;
        self.maps += 1;
        sys::mem_map(
            self.process,
            &opened.buffer,
            0,
            u64::from(BUFFER_BYTES),
            at,
            Access::ReadWrite,
        )
        .map_err(|_| "map the buffer")?;
        Ok(points(at))
    }

    /// OPEN until the service stops saying CLEARING (it is being set up, or
    /// the last owner's buffer is being cleared): `saw` says whether it
    /// did. Any other refusal is the answer.
    fn open_when_clear(&self, session: &Handle<Channel>) -> Result<Opened, Fail> {
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        loop {
            match open(session) {
                Err(Fail::Status(status)) if status == code(CLEARING) => {}
                other => return other,
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err(Fail::Bad("CLEARING for good"));
            }
            self.sleep(RETRY_NS);
        }
    }

    fn owner(mut self) -> Result<(), &'static str> {
        let display = self.display()?;
        let opened = self.open_when_clear(&display).map_err(|f| {
            rt::println!("gpu-probe: OPEN: {f:?}");
            "OPEN"
        })?;
        if opened.screen != Screen::FIXED || !opened.screen.fits() {
            return Err("the screen is not 640 by 400");
        }
        if opened.status != code(NO_INPUT) {
            return Err("a session of focus without a service of input");
        }
        let points = self.map(&opened)?;
        if points.iter().any(|&p| p != 0) {
            return Err("the buffer of a new screen is not zero");
        }
        rt::println!("gpu-probe: screen 640x400, stride 2560, a cleared buffer");
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                points[(y * WIDTH + x) as usize] = pattern(x, y);
            }
        }
        flush(&opened.owner, Rect::SCREEN).map_err(|_| "FLUSH of the screen")?;
        rt::println!(
            "gpu-probe: pattern crc {:08x}",
            screen_crc(&points[..(WIDTH * HEIGHT) as usize])
        );
        self.sleep(SNAPSHOT_NS);
        // A rectangle inside, in another colour, alone to the device: the
        // points around it keep the pattern on the screen.
        let inside = Rect {
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
        flush(&opened.owner, inside).map_err(|_| "FLUSH of a rectangle")?;
        rt::println!(
            "gpu-probe: partial crc {:08x}",
            screen_crc(&points[..(WIDTH * HEIGHT) as usize])
        );
        self.sleep(SNAPSHOT_NS);
        for numbers in [
            [WIDTH, 0, 1, 1],
            [0, HEIGHT, 1, 1],
            [0, 0, 0, 1],
            [0, 0, 1, 0],
            [1, 0, WIDTH, 1],
            [0, 1, 1, HEIGHT],
            [u32::MAX, 0, 2, 1],
            [2, 0, u32::MAX, 1],
            [0, u32::MAX, 1, 2],
            [0, 2, 1, u32::MAX],
        ] {
            if flush_raw(&opened.owner, numbers) != Err(Fail::Status(code(INVALID))) {
                return Err("a rectangle outside the screen was not refused");
            }
        }
        rt::println!("gpu-probe: rectangles outside the screen are INVALID");
        // A second owner: from the owner's own Display session and from a
        // clone of it.
        let clone = rt::service::clone_session(&display, &Method::Clone.header().bytes())
            .map_err(|_| "CLONE")?;
        for session in [&display, &clone] {
            if open(session).err() != Some(Fail::Status(code(BUSY))) {
                return Err("a second OPEN was not BUSY");
            }
        }
        rt::println!("gpu-probe: a second OPEN is BUSY");
        // A session may call only its own methods.
        let not_allowed = Fail::Status(code(NOT_ALLOWED));
        if open(&opened.owner).err() != Some(Fail::Status(code(NOT_ALLOWED)))
            || flush(&display, Rect::SCREEN) != Err(Fail::Status(code(NOT_ALLOWED)))
            || plain(&display, Method::Close) != Err(not_allowed)
            || plain(&opened.owner, Method::Clone).is_ok()
        {
            return Err("a method of the other kind of session was not refused");
        }
        rt::println!("gpu-probe: a session calls its own methods only");
        // The process ends with the screen: its end returns it.
        rt::println!("gpu-probe: the owner ends with the screen");
        Ok(())
    }

    fn second(mut self) -> Result<(), &'static str> {
        let display = self.display()?;
        // Ask for the screen until it was BUSY (the first probe has it) and
        // is free again (the first probe ended). A screen got before it was
        // BUSY is given back.
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        let mut saw_busy = false;
        let opened = loop {
            match open(&display) {
                Ok(opened) if saw_busy => break opened,
                Ok(opened) => {
                    plain(&opened.owner, Method::Close).map_err(|_| "CLOSE of an early screen")?;
                }
                Err(Fail::Status(status)) if status == code(BUSY) => saw_busy = true,
                Err(Fail::Status(status)) if status == code(CLEARING) => {}
                Err(_) => return Err("OPEN"),
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err("the screen never came free");
            }
            self.sleep(RETRY_NS);
        };
        let points = self.map(&opened)?;
        if points.iter().any(|&p| p != 0) {
            return Err("the buffer of the owner that ended was not cleared");
        }
        rt::println!("gpu-probe: the screen came back cleared when its owner ended");
        for (i, p) in points
            .iter_mut()
            .enumerate()
            .take((WIDTH * HEIGHT) as usize)
        {
            *p = 0x00DE_AD00 | (i as u32 & 0xFF);
        }
        flush(&opened.owner, Rect::SCREEN).map_err(|_| "FLUSH")?;
        self.sleep(SNAPSHOT_NS / 5);
        // CLOSE returns the screen. The service runs above the probe and
        // the device answers within the doorbell, so the way back (the
        // scanout off, 64 portions of clearing) is over before the probe
        // runs again, and its OPEN finds the screen free; an OPEN that came
        // earlier would be told CLEARING (the machine's tests on the host
        // have it). The buffer is all zero in either case.
        let first = opened.owner;
        plain(&first, Method::Close).map_err(|_| "CLOSE")?;
        if flush(&first, Rect::SCREEN) != Err(Fail::Status(code(REVOKED))) {
            return Err("FLUSH after CLOSE was not REVOKED");
        }
        let again = self
            .open_when_clear(&display)
            .map_err(|_| "OPEN after CLOSE")?;
        if points.iter().any(|&p| p != 0) {
            return Err("CLOSE did not clear the buffer");
        }
        rt::println!("gpu-probe: CLOSE returned the screen, a cleared buffer, FLUSH REVOKED");
        flush(&again.owner, Rect::SCREEN).map_err(|_| "FLUSH of the new owner")?;
        // Kill the service: it never replies, and the channel's end is the
        // answer. The owner's session leads nowhere now.
        let crashed = sys::send(&display, &Method::Crash.header().bytes());
        if crashed.is_ok() {
            return Err("CRASH was answered");
        }
        if flush(&again.owner, Rect::SCREEN) != Err(Fail::Kernel(Error::PeerClosed)) {
            return Err("FLUSH after the service ended was not refused by the channel");
        }
        rt::println!("gpu-probe: FLUSH after the service ended is PEER_CLOSED");
        // A session from init leads to the new instance, which opens the
        // screen with a cleared buffer.
        let end = time::ticks_to_ns(time::now()).saturating_add(WAIT_NS);
        let display = loop {
            if let Ok(session) = rt::service::connect(self.parent, "gpu") {
                break session;
            }
            if time::ticks_to_ns(time::now()) > end {
                return Err("no session with the new instance");
            }
            self.sleep(RETRY_NS * 10);
        };
        let reopened = self
            .open_when_clear(&display)
            .map_err(|_| "OPEN after the restart")?;
        let points = self.map(&reopened)?;
        if points.iter().any(|&p| p != 0) {
            return Err("the buffer of the new instance is not zero");
        }
        flush(&reopened.owner, Rect::SCREEN).map_err(|_| "FLUSH after the restart")?;
        rt::println!("gpu-probe: a new session after the restart opened the screen");
        Ok(())
    }
}
