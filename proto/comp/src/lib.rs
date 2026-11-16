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
/// The most bytes of one buffer's object: 1024 by 1024 points.
pub const BUFFER_MAX: u64 = 4 << 20;

/// The format of a point: proto_gpu's XRGB8888, the only one.
pub const FORMAT_XRGB8888: u32 = proto_gpu::FORMAT_XRGB8888;

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
}

impl Method {
    pub const ALL: [Method; 4] = [
        Method::Describe,
        Method::WindowCreate,
        Method::Attach,
        Method::Post,
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
        assert_eq!(numbers, [17, 18, 19, 20]);
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
