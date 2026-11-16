// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the composition service (services/compositor),
//! proto_wire: the numbers of its methods, which never change once given,
//! its codes and the bodies of its requests. Every number goes low byte
//! first. The service answers on the channel a client knows as its display
//! service (`Display`, the name `gpu` in init's table), so its methods
//! share that channel with the methods of proto_gpu's first revision (1, 2,
//! 3, 8) and keep their numbers apart from them (17 and up). It serves
//! those too: OPEN gives a program that knows nothing of windows a window
//! of the whole screen, whose buffer the service makes and FLUSH posts.
//!
//! | Method | Session | Request | Reply | Refusals |
//! |---|---|---|---|---|
//! | DESCRIBE (17) | `Display` | the header alone | status, `width`, `height`, `format`, `flags`, `open`, `created`, `frames`, `busy` (u32 each) | NO_DEVICE |
//! | WINDOW_CREATE (18) | `Display` | `x`, `y`, `w`, `h`, `format`, `flags` (u32); one handle: a channel with NOTIFY and TRANSFER | status, `id` (u32); one handle: the window's session (SEND, TRANSFER) | INVALID, UNSUPPORTED, NO_DEVICE, LIMIT_REACHED |
//! | ATTACH (19) | window | `count`, `stride`, `format` (u32); `count` memory objects with MAP_READ and TRANSFER | the status alone | BUSY, INVALID, UNSUPPORTED, REVOKED |
//! | POST (20) | window | `buffer`, `count` (u32), then `count` rectangles of 4 u32 | the status alone, at once | BUSY, INVALID, NOT_ALLOWED, REVOKED |
//! | EVENTS (21) | window or manager | the header alone | status, `count`, `flags` (u32 each: bit 0 is LOST), then `count` events of 16 bytes | NOT_ALLOWED, REVOKED |
//! | MANAGE (22) | manager | `op`, `a`, `b`, `c` (u32 each); SUBSCRIBE has one handle: a channel with NOTIFY and TRANSFER | the status alone; LIST: status, `count`, then `count` records of 28 bytes | INVALID, NOT_ALLOWED |
//! | INJECT (23) | input | one event of 16 bytes | the status alone | INVALID, NOT_ALLOWED |
//!
//! The context is the `Display` session. A window is a session of its own
//! (a label the service gives): the window goes when the last copy of its
//! session closes or when the context's session does (the process ended),
//! and its pixels leave the next frame. The window is `w` by `h` points of
//! FORMAT_XRGB8888 at (`x`, `y`) of the screen, all of it inside the
//! screen; its place and size do not change. It shows once the first POST
//! is taken into a frame; windows lie in the order they were made, the
//! newest on top, and the one the screen has nothing of shows black.
//!
//! The buffers of a window are 1 to 3 objects of memory the client made;
//! ATTACH gives them once, with a `stride` of at least 4 `w` bytes, and
//! they must hold `h` lines of it. The service maps them for reading only.
//! POST names one by its number and the changed rectangles in window
//! coordinates (up to MAX_RECTS; none means the whole window). A buffer is
//! free until a POST posts it; while posted the client leaves it alone. A
//! POST while another buffer is posted and not yet taken replaces it, and
//! the replaced one is free at once ("the latest wins"). Once a frame took
//! the posted buffer, the buffer it replaced on the screen is free when
//! that frame is shown. The service tells the client a buffer is free by
//! the bit of its number (bit 0 to 2) on the channel WINDOW_CREATE gave,
//! and never waits for the client: a buffer the client did not post in time
//! leaves the window on the screen as it was.
//!
//! A window is XRGB8888 (a point is 0x00RRGGBB, opaque) or ARGB8888 (the
//! colour already multiplied by the alpha in the top byte, laid over what
//! is below). Opaque and transparent windows are told apart by the format
//! of WINDOW_CREATE and ATTACH, which must agree.
//!
//! Events. The service keeps a ring of 64 events (EVENT_LEN bytes each) for
//! every window, and a ring for the manager. EVENTS takes up to MAX_EVENTS
//! of them without waiting; when more came than the ring holds the oldest
//! went and the next EVENTS says LOST. The bit EVENTS_BIT (bit 3) of the
//! channel WINDOW_CREATE gave says a ring has something to take. The
//! window that has the focus gets the keys; a window gets the pointer's
//! moves and buttons with the coordinates of its own (the window under the
//! pointer, or the one a pressed button holds until it is released); a click
//! on a window gives it the focus and the top place; a window that has
//! its first buffer taken into a frame gets the focus and the top place
//! at once. FOCUS_IN and FOCUS_OUT tell a window it won or lost the focus.
//!
//! The manager (the session init gave a program of the table's
//! `manager`, a label with MANAGER_MARK) lists the windows, moves them,
//! raises them, shows and hides them, and gives one the focus (MANAGE with
//! the ops below), and reads CREATE and CLOSE of every window in its own
//! ring. While a manager has subscribed, the Alt keys and the keys pressed
//! with Alt held go to it alone: the window with the focus never sees them.
//!
//! The input session (a label with INPUT_MARK, given by init to the probes)
//! injects an event as if the device had made it: a KEY, a MOVE with the
//! screen's coordinates (the pointer goes there) or a BUTTON.
//!
//! DESCRIBE's `open` is the windows alive now, `created` the windows ever
//! made, `frames` the frames shown, `busy` 1 while a frame is being made
//! or waits to be: a probe that waits for `busy` to be 0 finds the screen
//! settled.

#![cfg_attr(not(test), no_std)]

use proto_wire::{Header, Reader, Status, Writer};

pub use proto_gpu::Rect;

/// The version of the protocol, in the header of each request: the one of
/// proto_gpu's first revision, which the same channel speaks.
pub const VERSION: u16 = 1;

/// The most buffers of a window, and the most rectangles of a POST.
pub const BUFFERS: usize = 3;
pub const MAX_RECTS: usize = 4;
/// The most bytes of one buffer's object: a megabyte, the screen's.
pub const BUFFER_MAX: u64 = 1 << 20;

/// The formats of a point: proto_gpu's XRGB8888, and ARGB8888 with the
/// colour premultiplied by the alpha. 2 is no format (the probes refuse it).
pub const FORMAT_XRGB8888: u32 = proto_gpu::FORMAT_XRGB8888;
pub const FORMAT_ARGB8888: u32 = 3;

/// The labels init gives a session of the manager and of the input
/// (services/init `comp_mark`): bits the service's own labels never have
/// (a clone's is bit 63, a window's 62, the driver's 61).
pub const MANAGER_MARK: u64 = 1 << 60;
pub const INPUT_MARK: u64 = 1 << 59;

/// The bit the service sends a window's channel when its ring has events;
/// bits 0 to 2 tell the buffer that is free.
pub const EVENTS_BIT: u64 = 1 << 3;

/// The codes of the service, apart from the kernel's, proto_wire's and
/// proto_gpu's.
pub const BUSY: u32 = 1201;
pub const INVALID: u32 = 1202;
pub const NOT_ALLOWED: u32 = 1203;
pub const REVOKED: u32 = 1204;
pub const UNSUPPORTED: u32 = 1205;
pub const NO_DEVICE: u32 = 1206;

pub const fn code(code: u32) -> Status {
    Status::Unknown(code)
}

/// The methods with their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Describe = 17,
    WindowCreate = 18,
    Attach = 19,
    Post = 20,
    Events = 21,
    Manage = 22,
    Inject = 23,
}

impl Method {
    pub const ALL: [Method; 7] = [
        Method::Describe,
        Method::WindowCreate,
        Method::Attach,
        Method::Post,
        Method::Events,
        Method::Manage,
        Method::Inject,
    ];

    pub const fn number(self) -> u16 {
        self as u16
    }

    pub fn from_number(number: u16) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.number() == number)
    }

    /// The header of a request of this method.
    pub const fn header(self) -> Header {
        Header::new(self.number(), VERSION)
    }
}

/// DESCRIBE's reply after its status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Description {
    pub width: u32,
    pub height: u32,
    pub format: u32,
    pub flags: u32,
    pub open: u32,
    pub created: u32,
    pub frames: u32,
    pub busy: u32,
}

impl Description {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(Status::Ok.code())?;
        for n in [
            self.width,
            self.height,
            self.format,
            self.flags,
            self.open,
            self.created,
            self.frames,
            self.busy,
        ] {
            w.u32(n)?;
        }
        Ok(())
    }

    /// The description of a reply: a refusal that carries none is its
    /// status alone and comes back as the error; BAD_SIZE for any other
    /// length.
    pub fn read(reply: &[u8]) -> Result<Description, Status> {
        let mut r = Reader::new(reply);
        let status = Status::from_code(r.u32()?);
        if status != Status::Ok {
            return Err(status);
        }
        let d = Description {
            width: r.u32()?,
            height: r.u32()?,
            format: r.u32()?,
            flags: r.u32()?,
            open: r.u32()?,
            created: r.u32()?,
            frames: r.u32()?,
            busy: r.u32()?,
        };
        r.finish()?;
        Ok(d)
    }
}

/// WINDOW_CREATE's body: the place, the size, the format and the flags
/// (none are defined: 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Create {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub format: u32,
    pub flags: u32,
}

impl Create {
    /// The header and the body.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Method::WindowCreate.header().write(w)?;
        for n in [self.x, self.y, self.w, self.h, self.format, self.flags] {
            w.u32(n)?;
        }
        Ok(())
    }

    /// The body after the header: BAD_SIZE unless it is the six numbers.
    pub fn read(mut body: Reader<'_>) -> Result<Create, Status> {
        let c = Create {
            x: body.u32()?,
            y: body.u32()?,
            w: body.u32()?,
            h: body.u32()?,
            format: body.u32()?,
            flags: body.u32()?,
        };
        body.finish()?;
        Ok(c)
    }

    /// Whether the window is a part of a screen of `width` by `height`
    /// points, neither side empty.
    pub const fn fits(&self, width: u32, height: u32) -> bool {
        Rect {
            x: self.x,
            y: self.y,
            w: self.w,
            h: self.h,
        }
        .within(width, height)
    }
}

/// ATTACH's body: how many buffers, their stride and format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attach {
    pub count: u32,
    pub stride: u32,
    pub format: u32,
}

impl Attach {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Method::Attach.header().write(w)?;
        w.u32(self.count)?;
        w.u32(self.stride)?;
        w.u32(self.format)
    }

    /// The body after the header: BAD_SIZE unless it is the three numbers,
    /// INVALID for a count outside 1 to BUFFERS.
    pub fn read(mut body: Reader<'_>) -> Result<Attach, Status> {
        let a = Attach {
            count: body.u32()?,
            stride: body.u32()?,
            format: body.u32()?,
        };
        body.finish()?;
        if a.count == 0 || a.count as usize > BUFFERS {
            return Err(code(INVALID));
        }
        Ok(a)
    }

    /// The bytes of a buffer of a window `h` points high.
    pub const fn bytes(&self, h: u32) -> u64 {
        self.stride as u64 * h as u64
    }
}

/// POST's body: the buffer and its changed rectangles, in the window's
/// coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Post {
    pub buffer: u32,
    pub count: u32,
    pub rects: [Rect; MAX_RECTS],
}

const NONE: Rect = Rect {
    x: 0,
    y: 0,
    w: 0,
    h: 0,
};

impl Post {
    /// A POST of `buffer` with the rectangles `rects` (none: all of the
    /// window); INVALID past MAX_RECTS.
    pub fn new(buffer: u32, rects: &[Rect]) -> Result<Post, Status> {
        if rects.len() > MAX_RECTS {
            return Err(code(INVALID));
        }
        let mut post = Post {
            buffer,
            count: rects.len() as u32,
            rects: [NONE; MAX_RECTS],
        };
        post.rects[..rects.len()].copy_from_slice(rects);
        Ok(post)
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Method::Post.header().write(w)?;
        w.u32(self.buffer)?;
        w.u32(self.count)?;
        for r in &self.rects[..self.count as usize] {
            for n in [r.x, r.y, r.w, r.h] {
                w.u32(n)?;
            }
        }
        Ok(())
    }

    /// The body after the header: BAD_SIZE unless the bytes are the two
    /// numbers and `count` rectangles, INVALID for a count past MAX_RECTS.
    pub fn read(mut body: Reader<'_>) -> Result<Post, Status> {
        let buffer = body.u32()?;
        let count = body.u32()?;
        if count as usize > MAX_RECTS {
            return Err(code(INVALID));
        }
        let mut post = Post {
            buffer,
            count,
            rects: [NONE; MAX_RECTS],
        };
        for r in &mut post.rects[..count as usize] {
            *r = Rect {
                x: body.u32()?,
                y: body.u32()?,
                w: body.u32()?,
                h: body.u32()?,
            };
        }
        body.finish()?;
        Ok(post)
    }
}

/// The events a ring holds, and the most one EVENTS takes: a reply of 12 +
/// 32 * 16 bytes fits the message.
pub const RING: usize = 64;
pub const MAX_EVENTS: usize = 32;
/// EVENTS' `flags`: events were dropped since the last EVENTS.
pub const LOST: u32 = 1;
/// The bytes of an event.
pub const EVENT_LEN: usize = 16;

/// The kinds of an event.
pub const KEY: u16 = 1;
pub const MOVE: u16 = 2;
pub const BUTTON: u16 = 3;
pub const FOCUS_IN: u16 = 4;
pub const FOCUS_OUT: u16 = 5;
/// The manager's: a window was made, a window went. `code` is its id.
pub const CREATE: u16 = 6;
pub const CLOSE: u16 = 7;

/// One event. KEY: `code` is Linux's key code, `value` 1 for pressed and 0
/// for released. MOVE: `x` and `y` the pointer's place in the window's own
/// coordinates (INJECT: in the screen's). BUTTON: `code` the button (Linux's
/// BTN_LEFT, 0x110, and the others), `value` as a key's, `x` and `y` as a
/// MOVE's. FOCUS_IN, FOCUS_OUT: no number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Event {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
    pub x: i32,
    pub y: i32,
}

impl Event {
    pub const fn new(kind: u16, code: u16, value: i32) -> Event {
        Event {
            kind,
            code,
            value,
            x: 0,
            y: 0,
        }
    }

    pub const fn at(kind: u16, code: u16, value: i32, x: i32, y: i32) -> Event {
        Event {
            kind,
            code,
            value,
            x,
            y,
        }
    }

    pub const fn to_bytes(self) -> [u8; EVENT_LEN] {
        let k = self.kind.to_le_bytes();
        let c = self.code.to_le_bytes();
        let v = self.value.to_le_bytes();
        let x = self.x.to_le_bytes();
        let y = self.y.to_le_bytes();
        [
            k[0], k[1], c[0], c[1], v[0], v[1], v[2], v[3], x[0], x[1], x[2], x[3], y[0], y[1],
            y[2], y[3],
        ]
    }

    pub const fn from_bytes(b: [u8; EVENT_LEN]) -> Event {
        Event {
            kind: u16::from_le_bytes([b[0], b[1]]),
            code: u16::from_le_bytes([b[2], b[3]]),
            value: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            x: i32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            y: i32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        }
    }

    /// INJECT's request: the header and the event.
    pub fn write_inject(&self, w: &mut Writer) -> Result<(), Status> {
        Method::Inject.header().write(w)?;
        w.bytes(&self.to_bytes())
    }

    /// The event of INJECT's body: BAD_SIZE unless it is 16 bytes, INVALID
    /// for a kind that no input makes (INJECT takes KEY, MOVE and BUTTON).
    pub fn read_inject(mut body: Reader<'_>) -> Result<Event, Status> {
        let b = body.bytes(EVENT_LEN)?;
        body.finish()?;
        let mut raw = [0; EVENT_LEN];
        raw.copy_from_slice(b);
        let event = Event::from_bytes(raw);
        match event.kind {
            KEY | MOVE | BUTTON => Ok(event),
            _ => Err(code(INVALID)),
        }
    }
}

/// EVENTS' reply: status 0, the count, the flags, the events.
pub fn write_events(events: &[Event], lost: bool, w: &mut Writer) -> Result<(), Status> {
    w.u32(Status::Ok.code())?;
    w.u32(events.len() as u32)?;
    w.u32(if lost { LOST } else { 0 })?;
    for e in events {
        w.bytes(&e.to_bytes())?;
    }
    Ok(())
}

/// The flags and the events of a reply of EVENTS, each event given to
/// `each`; BAD_SIZE unless the reply is what the count says. A refusal is
/// its status alone and comes back as the error.
pub fn read_events(reply: &[u8], mut each: impl FnMut(Event)) -> Result<u32, Status> {
    let mut r = Reader::new(reply);
    let status = Status::from_code(r.u32()?);
    if status != Status::Ok {
        return Err(status);
    }
    let count = r.u32()?;
    let flags = r.u32()?;
    for _ in 0..count {
        let b = r.bytes(EVENT_LEN)?;
        let mut raw = [0; EVENT_LEN];
        raw.copy_from_slice(b);
        each(Event::from_bytes(raw));
    }
    r.finish()?;
    Ok(flags)
}

/// The operations of MANAGE (`op`, then `a`, `b`, `c`).
pub mod manage {
    /// A channel with NOTIFY and TRANSFER in the request's handle: the
    /// service sends it EVENTS_BIT when the manager's ring has events.
    pub const SUBSCRIBE: u32 = 0;
    /// The windows: the reply holds a record of WINDOW_RECORD bytes each.
    pub const LIST: u32 = 1;
    /// Window `a` goes to (`b`, `c`).
    pub const MOVE: u32 = 2;
    /// Window `a` goes to the top.
    pub const RAISE: u32 = 3;
    /// Window `a` has the focus and the top place.
    pub const FOCUS: u32 = 4;
    /// Window `a` is shown (`b` is 1) or hidden (0).
    pub const VISIBLE: u32 = 5;
    pub const LAST: u32 = VISIBLE;
}

/// MANAGE's request: the header, `op`, `a`, `b`, `c`.
pub fn write_manage(op: u32, a: u32, b: u32, c: u32, w: &mut Writer) -> Result<(), Status> {
    Method::Manage.header().write(w)?;
    for n in [op, a, b, c] {
        w.u32(n)?;
    }
    Ok(())
}

/// The four numbers of MANAGE's body; BAD_SIZE unless it is four, INVALID
/// for an `op` the service has not.
pub fn read_manage(mut body: Reader<'_>) -> Result<[u32; 4], Status> {
    let n = [body.u32()?, body.u32()?, body.u32()?, body.u32()?];
    body.finish()?;
    if n[0] > manage::LAST {
        return Err(code(INVALID));
    }
    Ok(n)
}

/// A window of LIST: its id (the number WINDOW_CREATE said), place and
/// size, flags and its place in the order of depth (0 is the lowest).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowRecord {
    pub id: u32,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub flags: u32,
    pub depth: u32,
}

/// The bytes of a record of LIST.
pub const WINDOW_RECORD: usize = 28;
/// WindowRecord's `flags`: the window is shown (it has something and is not
/// hidden), it has the focus.
pub const SHOWN: u32 = 1;
pub const FOCUSED: u32 = 2;

impl WindowRecord {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        for n in [self.id, self.x, self.y, self.w, self.h, self.flags, self.depth] {
            w.u32(n)?;
        }
        Ok(())
    }
}

/// LIST's reply: status 0, the count, the records.
pub fn write_list(records: &[WindowRecord], w: &mut Writer) -> Result<(), Status> {
    w.u32(Status::Ok.code())?;
    w.u32(records.len() as u32)?;
    for r in records {
        r.write(w)?;
    }
    Ok(())
}

/// The records of a reply of LIST, each given to `each`.
pub fn read_list(reply: &[u8], mut each: impl FnMut(WindowRecord)) -> Result<(), Status> {
    let mut r = Reader::new(reply);
    let status = Status::from_code(r.u32()?);
    if status != Status::Ok {
        return Err(status);
    }
    let count = r.u32()?;
    for _ in 0..count {
        each(WindowRecord {
            id: r.u32()?,
            x: r.u32()?,
            y: r.u32()?,
            w: r.u32()?,
            h: r.u32()?,
            flags: r.u32()?,
            depth: r.u32()?,
        });
    }
    r.finish()
}

/// The union of rectangles: the least rectangle that holds both; an empty
/// side counts as no rectangle.
pub fn union(a: Option<Rect>, b: Rect) -> Rect {
    match a {
        None => b,
        Some(a) => {
            let x0 = a.x.min(b.x);
            let y0 = a.y.min(b.y);
            let x1 = (a.x + a.w).max(b.x + b.w);
            let y1 = (a.y + a.h).max(b.y + b.h);
            Rect {
                x: x0,
                y: y0,
                w: x1 - x0,
                h: y1 - y0,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_methods_keep_their_numbers_apart_from_gpus() {
        let numbers: Vec<_> = Method::ALL.iter().map(|m| m.number()).collect();
        assert_eq!(numbers, [17, 18, 19, 20, 21, 22, 23]);
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
            assert_eq!(m.header().version, proto_gpu::VERSION);
            assert!(proto_gpu::Method::from_number(m.number()).is_none());
        }
        assert_eq!(Method::from_number(16), None);
    }

    #[test]
    fn the_codes_are_apart_from_the_other_services() {
        let codes = [BUSY, INVALID, NOT_ALLOWED, REVOKED, UNSUPPORTED, NO_DEVICE];
        let others = [
            proto_gpu::BUSY,
            proto_gpu::CLEARING,
            proto_gpu::REVOKED,
            proto_gpu::NO_DEVICE,
            proto_gpu::NO_INPUT,
            proto_gpu::INVALID,
            proto_gpu::IO,
            proto_gpu::NOT_ALLOWED,
        ];
        for (i, c) in codes.iter().enumerate() {
            assert!(!codes[..i].contains(c));
            assert!(!others.contains(c));
            assert!(*c > 512);
        }
    }

    #[test]
    fn a_description_round_trips_and_a_refusal_is_its_status() {
        let d = Description {
            width: 640,
            height: 400,
            format: FORMAT_XRGB8888,
            flags: 0,
            open: 1,
            created: 2,
            frames: 3,
            busy: 1,
        };
        let mut w = Writer::new();
        d.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 36);
        assert_eq!(Description::read(w.as_bytes()), Ok(d));
        assert_eq!(Description::read(&w.as_bytes()[..32]), Err(Status::BadSize));
        let refused = proto_wire::reply(code(NO_DEVICE));
        assert_eq!(Description::read(&refused), Err(code(NO_DEVICE)));
    }

    #[test]
    fn a_window_create_round_trips() {
        let c = Create {
            x: 100,
            y: 50,
            w: 320,
            h: 200,
            format: FORMAT_XRGB8888,
            flags: 0,
        };
        let mut w = Writer::new();
        c.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 8 + 24);
        assert_eq!(Create::read(Reader::new(&w.as_bytes()[8..])), Ok(c));
        assert_eq!(
            Create::read(Reader::new(&w.as_bytes()[8..30])),
            Err(Status::BadSize)
        );
        assert!(c.fits(640, 400));
        assert!(!Create { x: 321, ..c }.fits(640, 400));
        assert!(!Create { w: 0, ..c }.fits(640, 400));
        assert!(!Create { y: u32::MAX, ..c }.fits(640, 400));
    }

    #[test]
    fn an_attach_counts_its_buffers() {
        let a = Attach {
            count: 2,
            stride: 1280,
            format: FORMAT_XRGB8888,
        };
        let mut w = Writer::new();
        a.write(&mut w).unwrap();
        assert_eq!(Attach::read(Reader::new(&w.as_bytes()[8..])), Ok(a));
        assert_eq!(a.bytes(200), 256_000);
        for bad in [0, 4] {
            let mut w = Writer::new();
            Attach { count: bad, ..a }.write(&mut w).unwrap();
            assert_eq!(
                Attach::read(Reader::new(&w.as_bytes()[8..])),
                Err(code(INVALID))
            );
        }
    }

    #[test]
    fn a_post_round_trips_with_its_rectangles() {
        let rect = |x| Rect {
            x,
            y: 1,
            w: 2,
            h: 3,
        };
        for rects in [&[][..], &[rect(0)], &[rect(0), rect(5), rect(9), rect(11)]] {
            let post = Post::new(1, rects).unwrap();
            let mut w = Writer::new();
            post.write(&mut w).unwrap();
            assert_eq!(w.as_bytes().len(), 8 + 8 + 16 * rects.len());
            let read = Post::read(Reader::new(&w.as_bytes()[8..])).unwrap();
            assert_eq!(read, post);
            assert_eq!(&read.rects[..read.count as usize], rects);
        }
        assert_eq!(Post::new(0, &[rect(0); 5]), Err(code(INVALID)));
        // A count that promises more rectangles than the body has.
        let mut w = Writer::new();
        w.u32(0).unwrap();
        w.u32(2).unwrap();
        w.u32(0).unwrap();
        assert_eq!(Post::read(Reader::new(w.as_bytes())), Err(Status::BadSize));
        let mut w = Writer::new();
        w.u32(0).unwrap();
        w.u32(5).unwrap();
        assert_eq!(Post::read(Reader::new(w.as_bytes())), Err(code(INVALID)));
    }

    #[test]
    fn an_event_round_trips_and_inject_takes_three_kinds() {
        let e = Event::at(MOVE, 0, -3, 100, -200);
        assert_eq!(Event::from_bytes(e.to_bytes()), e);
        let mut w = Writer::new();
        e.write_inject(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 8 + EVENT_LEN);
        assert_eq!(Event::read_inject(Reader::new(&w.as_bytes()[8..])), Ok(e));
        assert_eq!(
            Event::read_inject(Reader::new(&w.as_bytes()[8..20])),
            Err(Status::BadSize)
        );
        for kind in [0, FOCUS_IN, FOCUS_OUT, CREATE, CLOSE, 99] {
            let mut w = Writer::new();
            Event::new(kind, 0, 0).write_inject(&mut w).unwrap();
            assert_eq!(
                Event::read_inject(Reader::new(&w.as_bytes()[8..])),
                Err(code(INVALID))
            );
        }
    }

    #[test]
    fn events_and_lists_round_trip() {
        let events = [Event::new(KEY, 30, 1), Event::at(BUTTON, 0x110, 1, 5, 6)];
        let mut w = Writer::new();
        write_events(&events, true, &mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 12 + 2 * EVENT_LEN);
        let mut got = Vec::new();
        assert_eq!(read_events(w.as_bytes(), |e| got.push(e)), Ok(LOST));
        assert_eq!(got, events);
        let refused = proto_wire::reply(code(REVOKED));
        assert_eq!(read_events(&refused, |_| {}), Err(code(REVOKED)));
        let a = WindowRecord {
            id: 1,
            x: 2,
            y: 3,
            w: 4,
            h: 5,
            flags: SHOWN | FOCUSED,
            depth: 6,
        };
        let mut w = Writer::new();
        write_list(&[a, a], &mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 8 + 2 * WINDOW_RECORD);
        let mut got = Vec::new();
        read_list(w.as_bytes(), |r| got.push(r)).unwrap();
        assert_eq!(got, [a, a]);
        // The most a reply holds.
        let mut w = Writer::new();
        write_events(&[Event::default(); MAX_EVENTS], false, &mut w).unwrap();
    }

    #[test]
    fn manage_takes_four_numbers_and_a_known_op() {
        let mut w = Writer::new();
        write_manage(manage::MOVE, 1, 20, 30, &mut w).unwrap();
        assert_eq!(
            read_manage(Reader::new(&w.as_bytes()[8..])),
            Ok([manage::MOVE, 1, 20, 30])
        );
        assert_eq!(
            read_manage(Reader::new(&w.as_bytes()[8..20])),
            Err(Status::BadSize)
        );
        let mut w = Writer::new();
        write_manage(manage::LAST + 1, 0, 0, 0, &mut w).unwrap();
        assert_eq!(
            read_manage(Reader::new(&w.as_bytes()[8..])),
            Err(code(INVALID))
        );
    }

    #[test]
    fn the_union_holds_both() {
        let a = Rect {
            x: 10,
            y: 10,
            w: 10,
            h: 10,
        };
        let b = Rect {
            x: 30,
            y: 5,
            w: 5,
            h: 5,
        };
        assert_eq!(union(None, a), a);
        assert_eq!(
            union(Some(a), b),
            Rect {
                x: 10,
                y: 5,
                w: 25,
                h: 15
            }
        );
        assert_eq!(union(Some(a), a), a);
    }
}
