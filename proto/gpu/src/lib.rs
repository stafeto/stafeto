// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the display service (services/virtio-gpu), proto_wire:
//! the numbers of its methods, which never change once given, its codes
//! and the bodies of its requests. The screen is fixed: WIDTH by HEIGHT
//! points of 4 bytes, STRIDE bytes a line, FORMAT_XRGB8888 (a point is the
//! word 0x00RRGGBB, low byte first). Every number goes low byte first.
//!
//! | Method | Session | Request | Reply | Refusals |
//! |---|---|---|---|---|
//! | OPEN (1) | `Display` | the header alone | status, `width`, `height`, `stride`, `format`, `flags` (u32 each); handles: the screen's buffer (MAP_READ, MAP_WRITE, TRANSFER), the owner's session (SEND, TRANSFER), and the focus session when the service has one | BUSY, CLEARING, NO_DEVICE |
//! | FLUSH (2) | the owner's | `x`, `y`, `w`, `h` (u32) | the status alone, once the device returned both commands | INVALID, REVOKED, IO, LIMIT_REACHED |
//! | CLOSE (3) | the owner's | the header alone | the status alone | none |
//! | CRASH (4) | `Display` | the header alone | none: the service ends with a fault | only a service built with the feature `crash` has it |
//! | CLONE (8) | `Display` | the header alone | status 0 and one handle, a new `Display` session (SEND, DUPLICATE, TRANSFER) | LIMIT_REACHED |
//!
//! The screen belongs to one owner at a time. OPEN of a free screen makes
//! the owner's session, a new label of the service, and the reply's
//! handles; of a screen with an owner it gets BUSY. The owner's session
//! ends the ownership when its last copy closes (the process ended, or
//! `exec` closed it), and CLOSE ends it at once. The screen then goes
//! through the device off and the buffer is cleared in portions; OPEN
//! meanwhile gets CLEARING, which a client asks again after a pause, and
//! BUSY it does not. A service that has no device to show on (the device
//! did not answer at the start) gets NO_DEVICE; one that is still setting
//! the device up gets CLEARING.
//!
//! When the service has no session of keyboard focus to give, OPEN's
//! status is NO_INPUT and the reply carries the two handles and the same
//! fields: the screen is the client's all the same. With one, the status
//! is 0 and there are three.
//!
//! FLUSH takes the rectangle of points the device is told to show, after
//! the owner wrote them in the buffer. It is checked without a sum that
//! can overflow: `x <= width`, `w <= width - x`, the same for the height,
//! and neither side empty. One FLUSH is with the device at a time; a second
//! of the same owner waits (a queue of one), and a third gets
//! LIMIT_REACHED. The owner of a screen that was taken away gets REVOKED.
//!
//! After the service ended and started again, every session of the old
//! one leads to a closed channel (PEER_CLOSED): the new one knows none of
//! them.

#![cfg_attr(not(test), no_std)]

use abi::Error;
use proto_wire::{Header, Reader, Status, Writer};

/// The version of the protocol, in the header of each request.
pub const VERSION: u16 = 1;

/// The screen: points, bytes a line, bytes in all.
pub const WIDTH: u32 = 640;
pub const HEIGHT: u32 = 400;
pub const STRIDE: u32 = WIDTH * 4;
pub const SCREEN_BYTES: u32 = STRIDE * HEIGHT;
/// The bytes of the buffer's object: a megabyte, a block of 256 pages.
pub const BUFFER_BYTES: u32 = 1 << 20;

const _: () = assert!(SCREEN_BYTES <= BUFFER_BYTES);

/// The format of a point (OPEN's `format`): B, G, R, X in memory, the word
/// 0x00RRGGBB.
pub const FORMAT_XRGB8888: u32 = 1;

/// OPEN's `flags`: the client cleans the cache lines of the rectangle
/// before FLUSH (rt::dma::clean). The service for virtio never sets it.
pub const CLEAN_BEFORE_FLUSH: u32 = 1;

/// The codes of the service. LIMIT_REACHED is the kernel's.
pub const BUSY: u32 = 1001;
pub const CLEARING: u32 = 1002;
pub const REVOKED: u32 = 1003;
pub const NO_DEVICE: u32 = 1004;
pub const NO_INPUT: u32 = 1005;
pub const INVALID: u32 = 1006;
pub const IO: u32 = 1007;
/// A method the session cannot call: FLUSH or CLOSE by a `Display`
/// session, OPEN or CLONE by the owner's.
pub const NOT_ALLOWED: u32 = 1008;

pub const fn code(code: u32) -> Status {
    Status::Unknown(code)
}

/// The methods with their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Open = 1,
    Flush = 2,
    Close = 3,
    Crash = 4,
    Clone = 8,
}

impl Method {
    pub const ALL: [Method; 5] = [
        Method::Open,
        Method::Flush,
        Method::Close,
        Method::Crash,
        Method::Clone,
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

/// FLUSH: the rectangle of points to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    /// The whole screen.
    pub const SCREEN: Rect = Rect {
        x: 0,
        y: 0,
        w: WIDTH,
        h: HEIGHT,
    };

    /// Whether the rectangle is a part of a screen of `width` by `height`
    /// points, neither side empty. No sum is formed, which could overflow:
    /// `x <= width` and `w <= width - x`, the same for the height.
    pub const fn within(&self, width: u32, height: u32) -> bool {
        self.w > 0
            && self.h > 0
            && self.x <= width
            && self.w <= width - self.x
            && self.y <= height
            && self.h <= height - self.y
    }

    /// The check of FLUSH on the fixed screen: INVALID outside it.
    pub fn check(&self) -> Result<(), Status> {
        if self.within(WIDTH, HEIGHT) {
            Ok(())
        } else {
            Err(code(INVALID))
        }
    }

    /// The offset in the buffer of the rectangle's first point,
    /// `y * stride + x * 4`; the device's TRANSFER_TO_HOST_2D reads the
    /// rectangle's lines from there, `stride` bytes apart.
    pub const fn offset(&self) -> u64 {
        self.y as u64 * STRIDE as u64 + self.x as u64 * 4
    }

    /// The header of FLUSH and the rectangle. INVALID outside the screen.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        self.check()?;
        Method::Flush.header().write(w)?;
        w.u32(self.x)?;
        w.u32(self.y)?;
        w.u32(self.w)?;
        w.u32(self.h)
    }

    /// The rectangle from `body`, the bytes after the header: BAD_SIZE
    /// unless they are the four numbers, INVALID outside the screen.
    pub fn read(mut body: Reader<'_>) -> Result<Rect, Status> {
        let rect = Rect {
            x: body.u32()?,
            y: body.u32()?,
            w: body.u32()?,
            h: body.u32()?,
        };
        body.finish()?;
        rect.check()?;
        Ok(rect)
    }
}

/// OPEN's reply after its status: the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Screen {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
    pub flags: u32,
}

impl Screen {
    /// The screen of the service for virtio.
    pub const FIXED: Screen = Screen {
        width: WIDTH,
        height: HEIGHT,
        stride: STRIDE,
        format: FORMAT_XRGB8888,
        flags: 0,
    };

    /// The reply: `status` and the fields.
    pub fn write(&self, status: Status, w: &mut Writer) -> Result<(), Status> {
        w.u32(status.code())?;
        w.u32(self.width)?;
        w.u32(self.height)?;
        w.u32(self.stride)?;
        w.u32(self.format)?;
        w.u32(self.flags)
    }

    /// The status and the screen of a reply of OPEN; BAD_SIZE unless the
    /// bytes are the six numbers. A refusal that carries no screen is its
    /// status alone, 8 bytes: it comes back as the error.
    pub fn read(reply: &[u8]) -> Result<(Status, Screen), Status> {
        let mut r = Reader::new(reply);
        let status = Status::from_code(r.u32()?);
        if reply.len() == proto_wire::HEADER_LEN {
            return Err(status);
        }
        let screen = Screen {
            width: r.u32()?,
            height: r.u32()?,
            stride: r.u32()?,
            format: r.u32()?,
            flags: r.u32()?,
        };
        r.finish()?;
        Ok((status, screen))
    }

    /// Whether the buffer holds the screen: `height` lines of `stride`
    /// bytes, in the object of BUFFER_BYTES.
    pub fn fits(&self) -> bool {
        u64::from(self.stride) >= u64::from(self.width) * 4
            && u64::from(self.stride) * u64::from(self.height) <= u64::from(BUFFER_BYTES)
    }
}

/// The refusal of the kernel's LIMIT_REACHED, for CLONE and FLUSH.
pub const LIMIT: Status = Status::Kernel(Error::LimitReached);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_screen_fits_its_object() {
        assert_eq!(SCREEN_BYTES, 1_024_000);
        assert!(Screen::FIXED.fits());
        assert_eq!(BUFFER_BYTES / 4096, 256);
    }

    #[test]
    fn the_methods_keep_their_numbers() {
        let numbers: Vec<_> = Method::ALL.iter().map(|m| m.number()).collect();
        assert_eq!(numbers, [1, 2, 3, 4, 8]);
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
        }
        assert_eq!(Method::from_number(0), None);
        assert_eq!(Method::from_number(5), None);
    }

    #[test]
    fn the_codes_are_apart_from_the_kernels_and_the_wires() {
        let codes = [
            BUSY,
            CLEARING,
            REVOKED,
            NO_DEVICE,
            NO_INPUT,
            INVALID,
            IO,
            NOT_ALLOWED,
        ];
        for (i, c) in codes.iter().enumerate() {
            assert!(*c > 512, "above the codes of the wire");
            assert_eq!(code(*c).code(), *c);
            assert_eq!(Status::from_code(*c), Status::Unknown(*c));
            assert!(!codes[..i].contains(c));
        }
    }

    #[test]
    fn a_rectangle_inside_the_screen_passes() {
        for r in [
            Rect::SCREEN,
            Rect {
                x: 0,
                y: 0,
                w: 1,
                h: 1,
            },
            Rect {
                x: WIDTH - 1,
                y: HEIGHT - 1,
                w: 1,
                h: 1,
            },
            Rect {
                x: 100,
                y: 50,
                w: 200,
                h: 100,
            },
            Rect {
                x: 0,
                y: HEIGHT - 1,
                w: WIDTH,
                h: 1,
            },
        ] {
            assert_eq!(r.check(), Ok(()), "{r:?}");
        }
    }

    #[test]
    fn a_rectangle_outside_the_screen_is_invalid() {
        let bad = |x, y, w, h| Rect { x, y, w, h }.check() == Err(code(INVALID));
        // Empty sides.
        assert!(bad(0, 0, 0, 1));
        assert!(bad(0, 0, 1, 0));
        // Over the edge by one.
        assert!(bad(1, 0, WIDTH, 1));
        assert!(bad(0, 1, 1, HEIGHT));
        assert!(bad(WIDTH, 0, 1, 1));
        assert!(bad(0, HEIGHT, 1, 1));
        assert!(bad(WIDTH - 1, 0, 2, 1));
        assert!(bad(0, HEIGHT - 1, 1, 2));
        // A sum that wraps a u32 would pass a naive check.
        assert!(bad(u32::MAX, 0, 2, 1));
        assert!(bad(2, 0, u32::MAX, 1));
        assert!(bad(0, u32::MAX, 1, 2));
        assert!(bad(0, 2, 1, u32::MAX));
        assert!(bad(u32::MAX, u32::MAX, u32::MAX, u32::MAX));
        assert!(bad(WIDTH + 1, 0, 1, 1));
    }

    #[test]
    fn the_offset_is_y_stride_plus_x_4() {
        let at = |x, y| Rect { x, y, w: 1, h: 1 }.offset();
        assert_eq!(at(0, 0), 0);
        assert_eq!(at(1, 0), 4);
        assert_eq!(at(0, 1), 2560);
        assert_eq!(at(639, 0), 2556);
        assert_eq!(at(0, 399), 399 * 2560);
        assert_eq!(at(320, 200), 200 * 2560 + 1280);
        assert_eq!(at(639, 399), u64::from(SCREEN_BYTES) - 4);
    }

    #[test]
    fn flush_round_trips() {
        let r = Rect {
            x: 3,
            y: 4,
            w: 5,
            h: 6,
        };
        let mut w = Writer::new();
        r.write(&mut w).expect("write");
        let bytes = w.as_bytes();
        assert_eq!(bytes.len(), 24);
        let header = Header::read(&mut Reader::new(bytes)).expect("header");
        assert_eq!(header, Method::Flush.header());
        assert_eq!(Rect::read(Reader::new(&bytes[8..])), Ok(r));
    }

    #[test]
    fn flush_bodies_of_the_wrong_size_are_refused() {
        let mut w = Writer::new();
        Rect::SCREEN.write(&mut w).expect("write");
        let body = &w.as_bytes()[8..];
        assert_eq!(Rect::read(Reader::new(&body[..15])), Err(Status::BadSize));
        let mut long = body.to_vec();
        long.push(0);
        assert_eq!(Rect::read(Reader::new(&long)), Err(Status::BadSize));
        let mut bad = Writer::new();
        assert_eq!(
            Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0
            }
            .write(&mut bad),
            Err(code(INVALID))
        );
    }

    #[test]
    fn open_replies_round_trip_with_each_status() {
        for status in [Status::Ok, code(NO_INPUT)] {
            let mut w = Writer::new();
            Screen::FIXED.write(status, &mut w).expect("write");
            assert_eq!(w.as_bytes().len(), 24);
            assert_eq!(Screen::read(w.as_bytes()), Ok((status, Screen::FIXED)));
        }
    }

    #[test]
    fn a_refusal_of_open_is_its_status_alone() {
        let reply = proto_wire::reply(code(BUSY));
        assert_eq!(Screen::read(&reply), Err(code(BUSY)));
        assert_eq!(Screen::read(&reply[..4]), Err(Status::BadSize));
        let mut w = Writer::new();
        Screen::FIXED.write(Status::Ok, &mut w).expect("write");
        let long = [w.as_bytes(), &[0]].concat();
        assert_eq!(Screen::read(&long), Err(Status::BadSize));
        assert_eq!(Screen::read(&w.as_bytes()[..20]), Err(Status::BadSize));
    }

    #[test]
    fn a_buffer_too_small_for_the_screen_does_not_fit() {
        let mut s = Screen::FIXED;
        s.height = 410;
        assert!(!s.fits());
        s = Screen::FIXED;
        s.stride = 100;
        assert!(!s.fits());
    }
}
