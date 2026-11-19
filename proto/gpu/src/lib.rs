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
//! | SUBSCRIBE (5) | the owner's | the header alone and one handle: a channel of the owner with NOTIFY and TRANSFER | the status alone | INVALID, NOT_ALLOWED |
//! | COMMIT (6) | the owner's | `x`, `y`, `w`, `h` (u32) | the status alone, as soon as the commands are in the device's queue | INVALID, REVOKED, BUSY, IO |
//! | PIPELINES (9) | the owner's | the header alone | status, `count`, `period_us` (u32 each), then `count` records of 32 bytes (`Pipeline`) | NOT_ALLOWED, REVOKED |
//! | SOURCE (10) | the owner's | `kind` (u32: 1 pool, 2 cursor) | status, `id`, `width`, `height`, `stride`, `format` (u32 each); one handle, the source's memory object (MAP_READ, MAP_WRITE, TRANSFER, and DUPLICATE for the pool) | LIMIT_REACHED, INVALID, REVOKED, BUSY |
//! | LAYERS (11) | the owner's | `count` (u32, 1 to 4), then `count` rows of 40 bytes (`LayerRow`) | the status alone, as soon as the commands are in the device's queue | INVALID, REVOKED, BUSY, NOT_ALLOWED |
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
//!
//! Revision 2 (REVISION) adds the two methods a service of composition
//! drives the screen with, and changes none of the first revision: the
//! header's version stays VERSION, so that a program built for the series
//! of ABI that froze with revision 1 and a service that takes both
//! revisions keep talking. SUBSCRIBE gives the driver the owner's channel,
//! once; COMMIT takes the rectangle like FLUSH but answers at once, and the
//! driver says on that channel, in the bits FRAME_SHOWN or FRAME_FAILED,
//! when the device finished the transfer and the flush of that rectangle.
//! One COMMIT is with the device at a time: a second before the bit is
//! BUSY. The owner never waits for the device inside a step.
//!
//! Revision 3 (REVISION) adds the hardware layers and changes none of the
//! methods 1 to 6 and 8; the header's version stays VERSION once more.
//! Its words are those of OpenWF Display: a *pipeline* is a unit of the
//! display hardware that takes one source and puts it on the screen (a
//! primary pipeline for the whole picture, a cursor pipeline for a small
//! picture that moves without a frame, later overlays); a *source* is a
//! buffer the device can show; a LAYERS row binds a source to a pipeline,
//! and the rows of one LAYERS take effect together. PIPELINES lists what
//! the device has, SOURCE hands the owner the memory object of a source
//! of its own (the pool buffer, the cursor picture), and LAYERS binds.
//! The three belong to the owner's session alone: any other session gets
//! NOT_ALLOWED, and a screen that was taken away REVOKED.
//!
//! The pipelines of the service for virtio-gpu (`VIRTIO_PIPELINES`):
//! pipeline 1 is PRIMARY, XRGB8888, 640 by 400, FULL_SCREEN (it takes a
//! source of the whole screen's size, at 0, 0, and none other), depth 0;
//! pipeline 2 is CURSOR, ARGB8888, exactly 64 by 64, HOT_SPOT, depth 255.
//! `period_us` is 0: the device tells no refresh period. The sources
//! (`VIRTIO_SOURCES`), each with the number of the device's resource of
//! the same id: 1 is the compositing target (the buffer OPEN gave; SOURCE
//! never hands it out), 2 the pool buffer (640 by 400, XRGB8888), 3 the
//! cursor picture (64 by 64, ARGB8888 with the colours multiplied by the
//! alpha, the word 0xAARRGGBB). SOURCE gives each kind once to an owner:
//! a second SOURCE of the same kind is LIMIT_REACHED; BUSY means that
//! somebody else still holds the source's object (more references than
//! the base count). The pool's handle has DUPLICATE and the cursor's does
//! not: the owner that shows the pool to the programs of the first revision
//! gives each a copy without it, one window after another, and checks the
//! references before each.
//!
//! The rules the driver keeps in the order of the device's commands, so
//! that a service of composition may rely on them:
//!
//! - A row may bind the pool (source 2) or the cursor picture (source 3)
//!   only after SOURCE gave that kind to this owner: otherwise the whole
//!   request is INVALID, as for a source the device does not have. A
//!   program that holds a copy of the pool from an earlier owner of the
//!   screen therefore cannot have its drawing shown through a later
//!   owner's session. Source 1, the target, is always the owner's.
//! - A primary row that binds a source other than the one bound now makes
//!   the driver transfer the whole of the new source to the host, set the
//!   scanout to it, and only then flush the whole screen: the transfer is
//!   complete before the scanout changes. The changed area of such a row
//!   is not used: the host's copy of the new source may be stale.
//! - A primary row with the same source transfers and flushes the changed
//!   area alone, as COMMIT does. COMMIT is a LAYERS with one primary row of
//!   the bound source and COMMIT's rectangle.
//! - The work of a primary row ends with FRAME_SHOWN or FRAME_FAILED on
//!   the owner's channel; a LAYERS with a primary row while the device
//!   holds the work of an earlier one is BUSY.
//! - A cursor row that binds a new source (or the first) makes the driver
//!   transfer the whole picture with a fence, and send the cursor update
//!   only after the device answered that transfer: the fence comes before
//!   the cursor update. A transfer that waits for a frame's work in the
//!   control queue goes after it.
//! - A cursor row with source 0 hides the cursor. A cursor row that only
//!   moves is a move of the cursor, which carries the resource of the
//!   picture (the device takes the resource of every cursor command as
//!   the pointer's on flag). A new hot spot alone is an update with no
//!   transfer, since the device takes the hot spot on updates only.
//! - The device reads the cursor's points only on its update command. A
//!   cursor row with the same source and a nonzero changed area therefore
//!   makes the driver transfer the whole picture again with a fence and
//!   then send the cursor update; a plain move would never show the new
//!   picture.
//! - A LAYERS of cursor rows alone is always taken. The cursor queue
//!   holds one chain; the driver keeps the last place it was given while
//!   a chain is out, and sends that place alone when the chain returns, so
//!   moves merge and none is queued behind another.
//!
//! Scaling and cropping (the source and destination rectangles of OpenWF)
//! come later as a new method with a longer row; LAYERS stays as it is.
//!
//! The grammar of a row is checked by `LayerRow::check` against the
//! tables of the device, with no sums that can overflow; BAD_SIZE is the
//! status of a body of the wrong length and INVALID of a value out of its
//! range.

#![cfg_attr(not(test), no_std)]

use abi::Error;
use proto_wire::{Header, Reader, Status, Writer};

/// The version of the protocol, in the header of each request.
pub const VERSION: u16 = 1;

/// The revision of the protocol: 2 adds SUBSCRIBE and COMMIT to the
/// methods of revision 1 and 3 adds PIPELINES, SOURCE and LAYERS; none of
/// the earlier methods changes, so the version in the header stays VERSION
/// (see above).
pub const REVISION: u16 = 3;

/// The bits of the driver's notification to the channel SUBSCRIBE gave:
/// the last COMMIT is on the screen, or the device refused it.
pub const FRAME_SHOWN: u64 = 1;
pub const FRAME_FAILED: u64 = 2;

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
/// The format of the cursor picture (a source's `format`): B, G, R, A in
/// memory, the word 0xAARRGGBB, the colours multiplied by the alpha.
pub const FORMAT_ARGB8888: u32 = 3;
/// The bit of a format in a pipeline's `formats`: bit 0 for XRGB8888, bit 1
/// for ARGB8888; 0 for a number that is no format (2 is none).
pub const fn format_bit(format: u32) -> u32 {
    match format {
        FORMAT_XRGB8888 => FORMATS_XRGB8888,
        FORMAT_ARGB8888 => FORMATS_ARGB8888,
        _ => 0,
    }
}

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
    Subscribe = 5,
    Commit = 6,
    Clone = 8,
    Pipelines = 9,
    Source = 10,
    Layers = 11,
}

impl Method {
    pub const ALL: [Method; 10] = [
        Method::Open,
        Method::Flush,
        Method::Close,
        Method::Crash,
        Method::Subscribe,
        Method::Commit,
        Method::Clone,
        Method::Pipelines,
        Method::Source,
        Method::Layers,
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
        self.write_as(Method::Flush, w)
    }

    /// The header of `method` (FLUSH or COMMIT) and the rectangle.
    pub fn write_as(&self, method: Method, w: &mut Writer) -> Result<(), Status> {
        self.check()?;
        method.header().write(w)?;
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
    /// bytes, in an object of at most BUFFER_BYTES (the compositor's is the screen's 250 pages).
    pub fn fits(&self) -> bool {
        u64::from(self.stride) >= u64::from(self.width) * 4
            && u64::from(self.stride) * u64::from(self.height) <= u64::from(BUFFER_BYTES)
    }
}

/// The side of the cursor picture of the device for virtio, in points.
pub const CURSOR_SIZE: u32 = 64;
/// The most records PIPELINES reports.
pub const MAX_PIPELINES: usize = 8;
/// The most rows one LAYERS holds.
pub const MAX_LAYERS: usize = 4;
/// The bytes of a pipeline's record, and of a layer's row.
pub const PIPELINE_BYTES: usize = 32;
pub const LAYER_BYTES: usize = 40;

/// A pipeline's `kind`.
pub const KIND_PRIMARY: u32 = 1;
pub const KIND_CURSOR: u32 = 2;
/// A pipeline of an extra plane: the device for virtio has none, the
/// controllers of boards will.
pub const KIND_OVERLAY: u32 = 3;

/// A pipeline's `formats`: the bits of `format_bit`.
pub const FORMATS_XRGB8888: u32 = 1;
pub const FORMATS_ARGB8888: u32 = 2;

/// A pipeline's `flags`.
pub const PIPELINE_SCALE: u32 = 1;
pub const PIPELINE_GLOBAL_ALPHA: u32 = 2;
pub const PIPELINE_HOT_SPOT: u32 = 4;
/// The source of the pipeline is the whole screen's size and sits at
/// 0, 0.
pub const PIPELINE_FULL_SCREEN: u32 = 8;
const PIPELINE_FLAGS: u32 = 15;

/// The ids of the pipelines of the device for virtio.
pub const PIPELINE_PRIMARY: u32 = 1;
pub const PIPELINE_CURSOR: u32 = 2;

/// The ids of the sources of the device for virtio, which are the numbers
/// of its resources.
pub const SOURCE_TARGET: u32 = 1;
pub const SOURCE_POOL: u32 = 2;
pub const SOURCE_CURSOR: u32 = 3;

/// SOURCE's `kind`: which source the owner asks for.
pub const SOURCE_KIND_POOL: u32 = 1;
pub const SOURCE_KIND_CURSOR: u32 = 2;

/// A record of PIPELINES: one unit of the display hardware (OpenWF
/// Display's WFDPipeline). Eight u32, 32 bytes, in this order: `id`,
/// `kind`, `formats`, `max_w`, `max_h`, `flags`, `depth`, and a word
/// reserved for a display number: 0 is the first display, and the records
/// of revision 3 all say 0. `max_w` and `max_h` are the largest source in points; a
/// CURSOR pipeline takes a source of exactly that size and a FULL_SCREEN
/// one a source of the screen's. `depth` orders the pipelines on the
/// screen, 0 at the bottom.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pipeline {
    pub id: u32,
    pub kind: u32,
    pub formats: u32,
    pub max_w: u32,
    pub max_h: u32,
    pub flags: u32,
    pub depth: u32,
}

impl Pipeline {
    /// Pipeline 1 of the device for virtio.
    pub const VIRTIO_PRIMARY: Pipeline = Pipeline {
        id: PIPELINE_PRIMARY,
        kind: KIND_PRIMARY,
        formats: FORMATS_XRGB8888,
        max_w: WIDTH,
        max_h: HEIGHT,
        flags: PIPELINE_FULL_SCREEN,
        depth: 0,
    };

    /// Pipeline 2 of the device for virtio.
    pub const VIRTIO_CURSOR: Pipeline = Pipeline {
        id: PIPELINE_CURSOR,
        kind: KIND_CURSOR,
        formats: FORMATS_ARGB8888,
        max_w: CURSOR_SIZE,
        max_h: CURSOR_SIZE,
        flags: PIPELINE_HOT_SPOT,
        depth: 255,
    };

    /// The filler of the unused places of a list.
    const BLANK: Pipeline = Pipeline {
        id: 0,
        kind: 0,
        formats: 0,
        max_w: 0,
        max_h: 0,
        flags: 0,
        depth: 0,
    };

    pub const fn has(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        for v in [
            self.id,
            self.kind,
            self.formats,
            self.max_w,
            self.max_h,
            self.flags,
            self.depth,
            0,
        ] {
            w.u32(v)?;
        }
        Ok(())
    }

    /// A record: BAD_SIZE unless 32 bytes are left, INVALID for a last word
    /// that is not zero (it is reserved for a display number, 0 the first
    /// display), an id of 0, a kind that is none of the three, no
    /// format or an unknown one, an unknown flag, or a side of 0.
    pub fn read(r: &mut Reader<'_>) -> Result<Pipeline, Status> {
        let p = Pipeline {
            id: r.u32()?,
            kind: r.u32()?,
            formats: r.u32()?,
            max_w: r.u32()?,
            max_h: r.u32()?,
            flags: r.u32()?,
            depth: r.u32()?,
        };
        let reserved = r.u32()?;
        let ok = reserved == 0
            && p.id != 0
            && (KIND_PRIMARY..=KIND_OVERLAY).contains(&p.kind)
            && p.formats != 0
            && p.formats & !(FORMATS_XRGB8888 | FORMATS_ARGB8888) == 0
            && p.flags & !PIPELINE_FLAGS == 0
            && p.max_w != 0
            && p.max_h != 0;
        if ok { Ok(p) } else { Err(code(INVALID)) }
    }
}

/// PIPELINES' reply: the records of the device and its refresh period.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pipelines {
    /// The microseconds between refreshes of the display, 0 when the
    /// device tells none (virtio-gpu).
    pub period_us: u32,
    count: usize,
    items: [Pipeline; MAX_PIPELINES],
}

impl Pipelines {
    /// The reply of the device for virtio.
    pub const VIRTIO: Pipelines = {
        let mut items = [Pipeline::BLANK; MAX_PIPELINES];
        items[0] = Pipeline::VIRTIO_PRIMARY;
        items[1] = Pipeline::VIRTIO_CURSOR;
        Pipelines {
            period_us: 0,
            count: 2,
            items,
        }
    };

    /// The reply for `records`, 1 to MAX_PIPELINES of them, with no id
    /// twice: INVALID otherwise.
    pub fn new(period_us: u32, records: &[Pipeline]) -> Result<Pipelines, Status> {
        if records.is_empty() || records.len() > MAX_PIPELINES {
            return Err(code(INVALID));
        }
        let mut items = [Pipeline::BLANK; MAX_PIPELINES];
        for (i, p) in records.iter().enumerate() {
            if records[..i].iter().any(|q| q.id == p.id) {
                return Err(code(INVALID));
            }
            items[i] = *p;
        }
        Ok(Pipelines {
            period_us,
            count: records.len(),
            items,
        })
    }

    pub fn as_slice(&self) -> &[Pipeline] {
        &self.items[..self.count]
    }

    pub fn find(&self, id: u32) -> Option<&Pipeline> {
        self.as_slice().iter().find(|p| p.id == id)
    }

    /// The request: the header alone.
    pub fn write_request(w: &mut Writer) -> Result<(), Status> {
        Method::Pipelines.header().write(w)
    }

    /// The reply: status 0, `count`, `period_us`, the records.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(0)?;
        w.u32(self.count as u32)?;
        w.u32(self.period_us)?;
        self.as_slice().iter().try_for_each(|p| p.write(w))
    }

    /// The reply: the refusal's status when it is not 0 (a refusal is its
    /// status alone, 8 bytes); otherwise BAD_SIZE unless the bytes are the
    /// three numbers and `count` records, INVALID for a `count` of 0 or
    /// over MAX_PIPELINES, a bad record or an id twice.
    pub fn read(reply: &[u8]) -> Result<Pipelines, Status> {
        let mut r = Reader::new(reply);
        let status = Status::from_code(r.u32()?);
        if status != Status::Ok {
            return Err(status);
        }
        let count = r.u32()? as usize;
        let period_us = r.u32()?;
        if count == 0 || count > MAX_PIPELINES {
            return Err(code(INVALID));
        }
        if r.left() != count * PIPELINE_BYTES {
            return Err(Status::BadSize);
        }
        let mut items = [Pipeline::BLANK; MAX_PIPELINES];
        for item in items.iter_mut().take(count) {
            *item = Pipeline::read(&mut r)?;
        }
        let list = Pipelines::new(period_us, &items[..count])?;
        r.finish()?;
        Ok(list)
    }
}

/// SOURCE's reply after its status: the source the owner got (OpenWF
/// Display's WFDSource), whose memory object comes as the one handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceInfo {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
}

impl SourceInfo {
    /// Source 1: the compositing target, the buffer OPEN gave.
    pub const TARGET: SourceInfo = SourceInfo {
        id: SOURCE_TARGET,
        width: WIDTH,
        height: HEIGHT,
        stride: STRIDE,
        format: FORMAT_XRGB8888,
    };

    /// Source 2: the pool buffer.
    pub const POOL: SourceInfo = SourceInfo {
        id: SOURCE_POOL,
        width: WIDTH,
        height: HEIGHT,
        stride: STRIDE,
        format: FORMAT_XRGB8888,
    };

    /// Source 3: the cursor picture.
    pub const CURSOR: SourceInfo = SourceInfo {
        id: SOURCE_CURSOR,
        width: CURSOR_SIZE,
        height: CURSOR_SIZE,
        stride: CURSOR_SIZE * 4,
        format: FORMAT_ARGB8888,
    };

    /// What the device for virtio shows: source 1, 2 and 3.
    pub const VIRTIO: [SourceInfo; 3] = [SourceInfo::TARGET, SourceInfo::POOL, SourceInfo::CURSOR];

    /// The source SOURCE hands out for `kind`, on the device for virtio:
    /// INVALID for a kind that is none.
    pub fn for_kind(kind: u32) -> Result<SourceInfo, Status> {
        match kind {
            SOURCE_KIND_POOL => Ok(SourceInfo::POOL),
            SOURCE_KIND_CURSOR => Ok(SourceInfo::CURSOR),
            _ => Err(code(INVALID)),
        }
    }

    /// The request for `kind`: the header and the kind. INVALID for a kind
    /// that is none.
    pub fn write_request(kind: u32, w: &mut Writer) -> Result<(), Status> {
        SourceInfo::for_kind(kind)?;
        Method::Source.header().write(w)?;
        w.u32(kind)
    }

    /// The kind of a request from `body`, the bytes after the header:
    /// BAD_SIZE unless they are the one number, INVALID for a kind that is
    /// none.
    pub fn read_request(mut body: Reader<'_>) -> Result<u32, Status> {
        let kind = body.u32()?;
        body.finish()?;
        SourceInfo::for_kind(kind)?;
        Ok(kind)
    }

    /// Whether the layout of the source is sound: nonzero sides, `stride`
    /// at least a line of points, `format` known. The sum `stride * height`
    /// is formed in 64 bits and cannot overflow. The size of the object is
    /// the driver's to check.
    pub fn fits(&self) -> bool {
        self.id != 0
            && self.width != 0
            && self.height != 0
            && format_bit(self.format) != 0
            && u64::from(self.stride) >= u64::from(self.width) * 4
    }

    /// Whether `pipeline` takes the source: its format is among the
    /// pipeline's, a FULL_SCREEN pipeline's source is of its size
    /// (`max_w` by `max_h`, the screen's), a CURSOR pipeline's of exactly
    /// that size, any other's at most that size.
    pub fn suits(&self, pipeline: &Pipeline) -> bool {
        let size = (self.width, self.height) == (pipeline.max_w, pipeline.max_h);
        let within = self.width <= pipeline.max_w && self.height <= pipeline.max_h;
        pipeline.formats & format_bit(self.format) != 0
            && if pipeline.has(PIPELINE_FULL_SCREEN) || pipeline.kind == KIND_CURSOR {
                size
            } else {
                within
            }
    }

    /// The reply: `status` and the fields.
    pub fn write(&self, status: Status, w: &mut Writer) -> Result<(), Status> {
        w.u32(status.code())?;
        w.u32(self.id)?;
        w.u32(self.width)?;
        w.u32(self.height)?;
        w.u32(self.stride)?;
        w.u32(self.format)
    }

    /// The reply: the refusal's status when it is not 0 (its status alone,
    /// 8 bytes); otherwise BAD_SIZE unless the bytes are the six numbers,
    /// INVALID for fields that do not fit (`fits`).
    pub fn read(reply: &[u8]) -> Result<SourceInfo, Status> {
        let mut r = Reader::new(reply);
        let status = Status::from_code(r.u32()?);
        if status != Status::Ok {
            return Err(status);
        }
        let s = SourceInfo {
            id: r.u32()?,
            width: r.u32()?,
            height: r.u32()?,
            stride: r.u32()?,
            format: r.u32()?,
        };
        r.finish()?;
        if s.fits() { Ok(s) } else { Err(code(INVALID)) }
    }
}

/// A row of LAYERS: the binding of a source to a pipeline (OpenWF
/// Display's wfdBindSourceToPipeline with the pipeline's place). Ten
/// words, 40 bytes, in this order: `pipeline`, `source` (0: the pipeline
/// is off), `x`, `y` (i32: for a CURSOR pipeline the place of the pointer,
/// that is of the hot spot, always on the screen, so that the hot spot
/// may put the picture partly off an edge; for an overlay the place of the
/// picture's top left point; for a FULL_SCREEN pipeline 0, 0), `hot_x`,
/// `hot_y` (the point of the picture that lies at `x`, `y`; CURSOR only),
/// `dx`, `dy`, `dw`,
/// `dh` (the area of the source that changed since the last row of this
/// pipeline, in the source's points; `dw` of 0 says no point changed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerRow {
    pub pipeline: u32,
    pub source: u32,
    pub x: i32,
    pub y: i32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub dx: u32,
    pub dy: u32,
    pub dw: u32,
    pub dh: u32,
}

impl LayerRow {
    /// A row that switches `pipeline` off.
    pub const fn off(pipeline: u32) -> LayerRow {
        LayerRow {
            pipeline,
            source: 0,
            x: 0,
            y: 0,
            hot_x: 0,
            hot_y: 0,
            dx: 0,
            dy: 0,
            dw: 0,
            dh: 0,
        }
    }

    /// A primary row of `source` with the changed `area` (None: nothing
    /// changed), at 0, 0.
    pub const fn primary(pipeline: u32, source: u32, area: Option<Rect>) -> LayerRow {
        let (dx, dy, dw, dh) = match area {
            Some(a) => (a.x, a.y, a.w, a.h),
            None => (0, 0, 0, 0),
        };
        LayerRow {
            pipeline,
            source,
            x: 0,
            y: 0,
            hot_x: 0,
            hot_y: 0,
            dx,
            dy,
            dw,
            dh,
        }
    }

    /// A cursor row of `source` with the pointer at `x`, `y` and the hot
    /// spot `hot_x`, `hot_y`, no point of the picture changed.
    pub const fn cursor(pipeline: u32, source: u32, x: i32, y: i32, hot: (u32, u32)) -> LayerRow {
        LayerRow {
            pipeline,
            source,
            x,
            y,
            hot_x: hot.0,
            hot_y: hot.1,
            dx: 0,
            dy: 0,
            dw: 0,
            dh: 0,
        }
    }

    /// The changed area, None when `dw` is 0.
    pub const fn area(&self) -> Option<Rect> {
        if self.dw == 0 {
            None
        } else {
            Some(Rect {
                x: self.dx,
                y: self.dy,
                w: self.dw,
                h: self.dh,
            })
        }
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.u32(self.pipeline)?;
        w.u32(self.source)?;
        w.u32(self.x as u32)?;
        w.u32(self.y as u32)?;
        w.u32(self.hot_x)?;
        w.u32(self.hot_y)?;
        w.u32(self.dx)?;
        w.u32(self.dy)?;
        w.u32(self.dw)?;
        w.u32(self.dh)
    }

    /// A row, with no check of its values (`check`): BAD_SIZE unless 40
    /// bytes are left.
    pub fn read(r: &mut Reader<'_>) -> Result<LayerRow, Status> {
        Ok(LayerRow {
            pipeline: r.u32()?,
            source: r.u32()?,
            x: r.u32()? as i32,
            y: r.u32()? as i32,
            hot_x: r.u32()?,
            hot_y: r.u32()?,
            dx: r.u32()?,
            dy: r.u32()?,
            dw: r.u32()?,
            dh: r.u32()?,
        })
    }

    /// The row against its `pipeline` and, unless the row is off, its
    /// `source`, which the caller found by the ids (INVALID for an id the
    /// tables do not have, see `Layers::check`):
    ///
    /// - `source` 0 (None here) switches a pipeline off, and the other
    ///   fields are zero. A PRIMARY pipeline is never off: the screen
    ///   always shows a source.
    /// - the source suits the pipeline (`SourceInfo::suits`): a format the
    ///   pipeline takes, the screen's size for FULL_SCREEN, exactly 64 by
    ///   64 for the cursor of virtio.
    /// - a FULL_SCREEN pipeline's place is 0, 0; a CURSOR pipeline's place
    ///   (the hot spot) is a point of the `screen` given, which the caller
    ///   takes from the full-screen primary pipeline's `max_w` and `max_h`
    ///   (the device's field is unsigned); an overlay's place is free.
    /// - the hot spot is 0, 0 unless the pipeline has HOT_SPOT, and then a
    ///   point of the picture: `hot_x < width`, `hot_y < height`.
    /// - the changed area is empty (`dx`, `dy`, `dw`, `dh` all zero, or
    ///   `dw` or `dh` zero with the rest zero) or a rectangle inside the
    ///   source (`Rect::within`, no sum is formed that could overflow).
    pub fn check(
        &self,
        pipeline: &Pipeline,
        source: Option<&SourceInfo>,
        screen: (u32, u32),
    ) -> Result<(), Status> {
        let bad = Err(code(INVALID));
        if self.pipeline != pipeline.id {
            return bad;
        }
        let Some(source) = source else {
            let zero = self.source == 0
                && (self.x, self.y) == (0, 0)
                && [self.hot_x, self.hot_y, self.dx, self.dy, self.dw, self.dh] == [0; 6];
            return if zero && pipeline.kind != KIND_PRIMARY {
                Ok(())
            } else {
                bad
            };
        };
        if source.id != self.source || self.source == 0 || !source.fits() || !source.suits(pipeline)
        {
            return bad;
        }
        let place = if pipeline.has(PIPELINE_FULL_SCREEN) {
            (self.x, self.y) == (0, 0)
        } else if pipeline.kind == KIND_CURSOR {
            (self.x as i64) >= 0
                && (self.x as i64) < i64::from(screen.0)
                && (self.y as i64) >= 0
                && (self.y as i64) < i64::from(screen.1)
        } else {
            true
        };
        let hot = if pipeline.has(PIPELINE_HOT_SPOT) {
            self.hot_x < source.width && self.hot_y < source.height
        } else {
            (self.hot_x, self.hot_y) == (0, 0)
        };
        let area = if self.dw == 0 || self.dh == 0 {
            [self.dx, self.dy, self.dw, self.dh] == [0; 4]
        } else {
            self.area()
                .is_some_and(|a| a.within(source.width, source.height))
        };
        if place && hot && area { Ok(()) } else { bad }
    }
}

/// LAYERS' request: 1 to MAX_LAYERS rows, which take effect together. At
/// most 8 + 4 + 4 * 40 = 172 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layers {
    count: usize,
    rows: [LayerRow; MAX_LAYERS],
}

impl Layers {
    /// The request of `rows`: INVALID unless there are 1 to MAX_LAYERS.
    pub fn new(rows: &[LayerRow]) -> Result<Layers, Status> {
        if rows.is_empty() || rows.len() > MAX_LAYERS {
            return Err(code(INVALID));
        }
        let mut all = [LayerRow::off(0); MAX_LAYERS];
        all[..rows.len()].copy_from_slice(rows);
        Ok(Layers {
            count: rows.len(),
            rows: all,
        })
    }

    pub fn rows(&self) -> &[LayerRow] {
        &self.rows[..self.count]
    }

    /// Whether a row is for a PRIMARY pipeline of `pipelines`, which makes
    /// the work of a frame.
    pub fn has_frame(&self, pipelines: &[Pipeline]) -> bool {
        self.rows().iter().any(|r| {
            pipelines
                .iter()
                .any(|p| p.id == r.pipeline && p.kind == KIND_PRIMARY)
        })
    }

    /// The header, `count` and the rows.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Method::Layers.header().write(w)?;
        w.u32(self.count as u32)?;
        self.rows().iter().try_for_each(|r| r.write(w))
    }

    /// The request from `body`, the bytes after the header: INVALID for a
    /// `count` of 0 or over MAX_LAYERS, BAD_SIZE unless the rest is
    /// `count` rows. The rows are not yet checked (`check`).
    pub fn read(mut body: Reader<'_>) -> Result<Layers, Status> {
        let count = body.u32()? as usize;
        if count == 0 || count > MAX_LAYERS {
            return Err(code(INVALID));
        }
        if body.left() != count * LAYER_BYTES {
            return Err(Status::BadSize);
        }
        let mut rows = [LayerRow::off(0); MAX_LAYERS];
        for row in rows.iter_mut().take(count) {
            *row = LayerRow::read(&mut body)?;
        }
        body.finish()?;
        Ok(Layers { count, rows })
    }

    /// Every row against the tables of the device: a pipeline or a source
    /// the tables do not have is INVALID, a pipeline in two rows is
    /// INVALID, and each row passes `LayerRow::check`.
    pub fn check(&self, pipelines: &[Pipeline], sources: &[SourceInfo]) -> Result<(), Status> {
        let screen = pipelines
            .iter()
            .find(|p| p.kind == KIND_PRIMARY && p.has(PIPELINE_FULL_SCREEN))
            .map(|p| (p.max_w, p.max_h))
            .ok_or(code(INVALID))?;
        for (i, row) in self.rows().iter().enumerate() {
            if self.rows()[..i].iter().any(|o| o.pipeline == row.pipeline) {
                return Err(code(INVALID));
            }
            let pipeline = pipelines
                .iter()
                .find(|p| p.id == row.pipeline)
                .ok_or(code(INVALID))?;
            let source = match row.source {
                0 => None,
                id => Some(sources.iter().find(|s| s.id == id).ok_or(code(INVALID))?),
            };
            row.check(pipeline, source, screen)?;
        }
        Ok(())
    }

    /// `check` against the device for virtio.
    pub fn check_virtio(&self) -> Result<(), Status> {
        self.check(Pipelines::VIRTIO.as_slice(), &SourceInfo::VIRTIO)
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
        assert_eq!(numbers, [1, 2, 3, 4, 5, 6, 8, 9, 10, 11]);
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
        }
        assert_eq!(Method::from_number(0), None);
        assert_eq!(Method::from_number(7), None);
        assert_eq!(Method::from_number(12), None);
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
    fn commit_is_flush_under_its_own_number() {
        let r = Rect {
            x: 8,
            y: 9,
            w: 10,
            h: 11,
        };
        let mut flush = Writer::new();
        let mut commit = Writer::new();
        r.write(&mut flush).expect("flush");
        r.write_as(Method::Commit, &mut commit).expect("commit");
        assert_eq!(flush.as_bytes()[8..], commit.as_bytes()[8..]);
        let header = Header::read(&mut Reader::new(commit.as_bytes())).expect("header");
        assert_eq!(header, Method::Commit.header());
        assert_eq!(header.version, VERSION);
        assert_eq!(Rect::read(Reader::new(&commit.as_bytes()[8..])), Ok(r));
    }

    #[test]
    fn revisions_2_and_3_change_no_header_version() {
        assert_eq!(VERSION, 1);
        assert_eq!(REVISION, 3);
        for m in Method::ALL {
            assert_eq!(m.header().version, 1);
        }
        assert_eq!(FRAME_SHOWN & FRAME_FAILED, 0);
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

    fn bytes_of(f: impl FnOnce(&mut Writer) -> Result<(), Status>) -> Vec<u8> {
        let mut w = Writer::new();
        f(&mut w).expect("write");
        w.as_bytes().to_vec()
    }

    fn words(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn the_numbers_and_sizes_of_revision_3_are_pinned() {
        assert_eq!(Method::Pipelines.number(), 9);
        assert_eq!(Method::Source.number(), 10);
        assert_eq!(Method::Layers.number(), 11);
        assert_eq!(PIPELINE_BYTES, 32);
        assert_eq!(LAYER_BYTES, 40);
        assert_eq!(MAX_LAYERS, 4);
        assert_eq!(8 + 4 + MAX_LAYERS * LAYER_BYTES, 172);
        assert_eq!([KIND_PRIMARY, KIND_CURSOR, KIND_OVERLAY], [1, 2, 3]);
        assert_eq!(
            [
                PIPELINE_SCALE,
                PIPELINE_GLOBAL_ALPHA,
                PIPELINE_HOT_SPOT,
                PIPELINE_FULL_SCREEN
            ],
            [1, 2, 4, 8]
        );
        assert_eq!([FORMAT_XRGB8888, FORMAT_ARGB8888], [1, 3]);
        assert_eq!(
            [
                format_bit(1),
                format_bit(2),
                format_bit(3),
                format_bit(4),
                format_bit(0)
            ],
            [1, 0, 2, 0, 0]
        );
        assert_eq!([FORMATS_XRGB8888, FORMATS_ARGB8888], [1, 2]);
        assert_eq!([PIPELINE_PRIMARY, PIPELINE_CURSOR], [1, 2]);
        assert_eq!([SOURCE_TARGET, SOURCE_POOL, SOURCE_CURSOR], [1, 2, 3]);
        assert_eq!([SOURCE_KIND_POOL, SOURCE_KIND_CURSOR], [1, 2]);
        assert_eq!(CURSOR_SIZE, 64);
        // The ids of the sources are the numbers of the resources.
        for (s, id) in SourceInfo::VIRTIO.iter().zip(1..) {
            assert_eq!(s.id, id);
            assert!(s.fits());
        }
        assert_eq!(SourceInfo::CURSOR.stride, 256);
    }

    #[test]
    fn the_fields_of_a_pipeline_record_keep_their_places() {
        let p = Pipeline {
            id: 11,
            kind: 2,
            formats: 3,
            max_w: 14,
            max_h: 15,
            flags: 12,
            depth: 17,
        };
        let b = bytes_of(|w| p.write(w));
        assert_eq!(words(&b), [11, 2, 3, 14, 15, 12, 17, 0]);
        assert_eq!(b.len(), PIPELINE_BYTES);
        assert_eq!(Pipeline::read(&mut Reader::new(&b)), Ok(p));
    }

    #[test]
    fn the_fields_of_a_layer_row_keep_their_places() {
        let row = LayerRow {
            pipeline: 1,
            source: 2,
            x: -3,
            y: 4,
            hot_x: 5,
            hot_y: 6,
            dx: 7,
            dy: 8,
            dw: 9,
            dh: 10,
        };
        let b = bytes_of(|w| row.write(w));
        assert_eq!(b.len(), LAYER_BYTES);
        assert_eq!(words(&b), [1, 2, (-3i32) as u32, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(LayerRow::read(&mut Reader::new(&b)), Ok(row));
    }

    #[test]
    fn pipelines_round_trip() {
        let request = bytes_of(Pipelines::write_request);
        assert_eq!(request, Method::Pipelines.header().bytes());
        let reply = bytes_of(|w| Pipelines::VIRTIO.write(w));
        assert_eq!(reply.len(), 12 + 2 * PIPELINE_BYTES);
        assert_eq!(words(&reply)[..3], [0, 2, 0]);
        let list = Pipelines::read(&reply).expect("read");
        assert_eq!(list, Pipelines::VIRTIO);
        assert_eq!(list.find(1), Some(&Pipeline::VIRTIO_PRIMARY));
        assert_eq!(list.find(2), Some(&Pipeline::VIRTIO_CURSOR));
        assert_eq!(list.find(3), None);
        let p = Pipeline::VIRTIO_PRIMARY;
        assert_eq!(
            (p.kind, p.formats, p.max_w, p.max_h, p.flags, p.depth),
            (1, 1, 640, 400, 8, 0)
        );
        let c = Pipeline::VIRTIO_CURSOR;
        assert_eq!(
            (c.kind, c.formats, c.max_w, c.max_h, c.flags, c.depth),
            (2, 2, 64, 64, 4, 255)
        );
    }

    #[test]
    fn pipelines_replies_of_the_wrong_shape_are_refused() {
        let reply = bytes_of(|w| Pipelines::VIRTIO.write(w));
        // A refusal is its status alone.
        assert_eq!(
            Pipelines::read(&proto_wire::reply(code(NOT_ALLOWED))),
            Err(code(NOT_ALLOWED))
        );
        assert_eq!(
            Pipelines::read(&proto_wire::reply(Status::Ok)),
            Err(Status::BadSize)
        );
        assert_eq!(
            Pipelines::read(&reply[..reply.len() - 1]),
            Err(Status::BadSize)
        );
        let long = [&reply[..], &[0]].concat();
        assert_eq!(Pipelines::read(&long), Err(Status::BadSize));
        // A count that is 0 or too large, or does not match the bytes.
        for count in [0u32, 9] {
            let mut bad = reply.clone();
            bad[4..8].copy_from_slice(&count.to_le_bytes());
            assert_eq!(Pipelines::read(&bad), Err(code(INVALID)));
        }
        let mut bad = reply.clone();
        bad[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(Pipelines::read(&bad), Err(Status::BadSize));
        // A record's last word is zero; an id is not twice; values are known.
        let mut bad = reply.clone();
        bad[12 + 28] = 1;
        assert_eq!(Pipelines::read(&bad), Err(code(INVALID)));
        let mut bad = reply.clone();
        bad[12 + 32] = 1;
        assert_eq!(Pipelines::read(&bad), Err(code(INVALID)));
        for field in 0..7 {
            let mut p = Pipeline::VIRTIO_PRIMARY;
            match field {
                0 => p.id = 0,
                1 => p.kind = 4,
                2 => p.formats = 0,
                3 => p.formats = 4,
                4 => p.max_w = 0,
                5 => p.max_h = 0,
                _ => p.flags = 16,
            }
            let b = bytes_of(|w| p.write(w));
            assert_eq!(Pipeline::read(&mut Reader::new(&b)), Err(code(INVALID)));
        }
        assert_eq!(Pipelines::new(0, &[]), Err(code(INVALID)));
        assert_eq!(
            Pipelines::new(0, &[Pipeline::VIRTIO_PRIMARY; 2]),
            Err(code(INVALID))
        );
        assert_eq!(
            Pipelines::new(0, &[Pipeline::VIRTIO_PRIMARY; MAX_PIPELINES + 1]),
            Err(code(INVALID))
        );
    }

    #[test]
    fn source_round_trips_for_each_kind() {
        for (kind, info) in [
            (SOURCE_KIND_POOL, SourceInfo::POOL),
            (SOURCE_KIND_CURSOR, SourceInfo::CURSOR),
        ] {
            let request = bytes_of(|w| SourceInfo::write_request(kind, w));
            assert_eq!(request.len(), 12);
            assert_eq!(request[..8], Method::Source.header().bytes());
            assert_eq!(
                SourceInfo::read_request(Reader::new(&request[8..])),
                Ok(kind)
            );
            assert_eq!(SourceInfo::for_kind(kind), Ok(info));
            let reply = bytes_of(|w| info.write(Status::Ok, w));
            assert_eq!(reply.len(), 24);
            assert_eq!(SourceInfo::read(&reply), Ok(info));
        }
        let reply = bytes_of(|w| SourceInfo::CURSOR.write(Status::Ok, w));
        assert_eq!(words(&reply), [0, 3, 64, 64, 256, 3]);
        let reply = bytes_of(|w| SourceInfo::POOL.write(Status::Ok, w));
        assert_eq!(words(&reply), [0, 2, 640, 400, 2560, 1]);
    }

    #[test]
    fn source_requests_and_replies_of_the_wrong_shape_are_refused() {
        for kind in [0, 3, u32::MAX] {
            assert_eq!(
                SourceInfo::write_request(kind, &mut Writer::new()),
                Err(code(INVALID))
            );
            assert_eq!(
                SourceInfo::read_request(Reader::new(&kind.to_le_bytes())),
                Err(code(INVALID))
            );
        }
        assert_eq!(
            SourceInfo::read_request(Reader::new(&[])),
            Err(Status::BadSize)
        );
        assert_eq!(
            SourceInfo::read_request(Reader::new(&[1, 0, 0, 0, 0])),
            Err(Status::BadSize)
        );
        assert_eq!(SourceInfo::read(&proto_wire::reply(LIMIT)), Err(LIMIT));
        assert_eq!(
            SourceInfo::read(&proto_wire::reply(code(BUSY))),
            Err(code(BUSY))
        );
        assert_eq!(
            SourceInfo::read(&proto_wire::reply(Status::Ok)),
            Err(Status::BadSize)
        );
        let reply = bytes_of(|w| SourceInfo::POOL.write(Status::Ok, w));
        assert_eq!(SourceInfo::read(&reply[..20]), Err(Status::BadSize));
        assert_eq!(
            SourceInfo::read(&[&reply[..], &[0]].concat()),
            Err(Status::BadSize)
        );
        for field in 1..6 {
            let mut bad = SourceInfo::POOL;
            match field {
                1 => bad.id = 0,
                2 => bad.width = 0,
                3 => bad.height = 0,
                4 => bad.stride = 100,
                _ => bad.format = 2,
            }
            let b = bytes_of(|w| bad.write(Status::Ok, w));
            assert_eq!(SourceInfo::read(&b), Err(code(INVALID)));
        }
    }

    fn layers(rows: &[LayerRow]) -> Result<Layers, Status> {
        let l = Layers::new(rows)?;
        let b = bytes_of(|w| l.write(w));
        assert_eq!(b.len(), 12 + rows.len() * LAYER_BYTES);
        assert_eq!(b[..8], Method::Layers.header().bytes());
        let back = Layers::read(Reader::new(&b[8..]))?;
        assert_eq!(back, l);
        Ok(back)
    }

    fn arrow() -> LayerRow {
        LayerRow::cursor(PIPELINE_CURSOR, SOURCE_CURSOR, 100, 50, (0, 0))
    }

    fn frame(source: u32) -> LayerRow {
        LayerRow::primary(PIPELINE_PRIMARY, source, Some(Rect::SCREEN))
    }

    #[test]
    fn layers_round_trip_and_pass_on_the_device_for_virtio() {
        for rows in [
            vec![frame(SOURCE_POOL)],
            vec![frame(SOURCE_TARGET)],
            vec![LayerRow::primary(PIPELINE_PRIMARY, SOURCE_POOL, None)],
            vec![LayerRow::primary(
                PIPELINE_PRIMARY,
                SOURCE_POOL,
                Some(Rect {
                    x: 600,
                    y: 390,
                    w: 40,
                    h: 10,
                }),
            )],
            vec![arrow()],
            vec![LayerRow::off(PIPELINE_CURSOR)],
            vec![frame(SOURCE_POOL), arrow()],
            vec![frame(SOURCE_TARGET), LayerRow::off(PIPELINE_CURSOR)],
            vec![LayerRow::cursor(
                PIPELINE_CURSOR,
                SOURCE_CURSOR,
                639,
                399,
                (63, 63),
            )],
        ] {
            let l = layers(&rows).expect("round trip");
            assert_eq!(l.rows(), &rows[..]);
            assert_eq!(l.check_virtio(), Ok(()), "{rows:?}");
        }
        // The cursor row with `dw` 0 is a move.
        assert_eq!(arrow().area(), None);
        assert!(
            layers(&[frame(2)])
                .unwrap()
                .has_frame(Pipelines::VIRTIO.as_slice())
        );
        assert!(
            !layers(&[arrow()])
                .unwrap()
                .has_frame(Pipelines::VIRTIO.as_slice())
        );
    }

    #[test]
    fn layers_of_the_wrong_count_or_length_are_refused() {
        assert_eq!(Layers::new(&[]), Err(code(INVALID)));
        assert_eq!(Layers::new(&[arrow(); 5]), Err(code(INVALID)));
        assert!(Layers::new(&[arrow(); 4]).is_ok());
        let one = bytes_of(|w| Layers::new(&[frame(2)]).unwrap().write(w));
        let body = &one[8..];
        for count in [0u32, 5, u32::MAX] {
            let mut bad = body.to_vec();
            bad[..4].copy_from_slice(&count.to_le_bytes());
            assert_eq!(Layers::read(Reader::new(&bad)), Err(code(INVALID)));
        }
        let mut two = body.to_vec();
        two[..4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(Layers::read(Reader::new(&two)), Err(Status::BadSize));
        assert_eq!(
            Layers::read(Reader::new(&body[..body.len() - 1])),
            Err(Status::BadSize)
        );
        assert_eq!(
            Layers::read(Reader::new(&[body, &[0]].concat())),
            Err(Status::BadSize)
        );
        assert_eq!(Layers::read(Reader::new(&[])), Err(Status::BadSize));
        assert_eq!(Layers::read(Reader::new(&[1, 0])), Err(Status::BadSize));
    }

    #[test]
    fn rows_with_ids_or_places_out_of_range_are_invalid() {
        let check = |row: LayerRow| Layers::new(&[row]).unwrap().check_virtio();
        let bad = Err(code(INVALID));
        // An unknown pipeline or source id.
        assert_eq!(
            check(LayerRow {
                pipeline: 0,
                ..frame(2)
            }),
            bad
        );
        assert_eq!(
            check(LayerRow {
                pipeline: 3,
                ..frame(2)
            }),
            bad
        );
        assert_eq!(check(frame(4)), bad);
        assert_eq!(check(frame(u32::MAX)), bad);
        assert_eq!(
            check(LayerRow {
                source: 9,
                ..arrow()
            }),
            bad
        );
        // A pipeline in two rows.
        assert_eq!(
            Layers::new(&[arrow(), arrow()]).unwrap().check_virtio(),
            bad
        );
        // A cursor source that is not 64 by 64: the pool on the cursor.
        assert_eq!(
            check(LayerRow {
                source: SOURCE_POOL,
                ..arrow()
            }),
            bad
        );
        assert_eq!(
            check(LayerRow {
                source: SOURCE_TARGET,
                ..arrow()
            }),
            bad
        );
        // A primary source that is not the whole screen: the picture.
        assert_eq!(check(frame(SOURCE_CURSOR)), bad);
        // A source of a size the pipeline does not take, from other tables.
        let small = SourceInfo {
            id: 7,
            width: 639,
            height: 400,
            stride: 2560,
            format: 1,
        };
        let l = Layers::new(&[frame(7)]).unwrap();
        assert_eq!(l.check(Pipelines::VIRTIO.as_slice(), &[small]), bad);
        let wide = SourceInfo {
            id: 8,
            width: 65,
            height: 64,
            stride: 260,
            format: FORMAT_ARGB8888,
        };
        let l = Layers::new(&[LayerRow {
            source: 8,
            ..arrow()
        }])
        .unwrap();
        assert_eq!(l.check(Pipelines::VIRTIO.as_slice(), &[wide]), bad);
        let narrow = SourceInfo {
            id: 8,
            width: 32,
            height: 64,
            stride: 128,
            format: FORMAT_ARGB8888,
        };
        assert_eq!(l.check(Pipelines::VIRTIO.as_slice(), &[narrow]), bad);
        // A source of a format the pipeline does not take.
        let argb = SourceInfo {
            id: 9,
            format: FORMAT_ARGB8888,
            ..SourceInfo::POOL
        };
        let l = Layers::new(&[frame(9)]).unwrap();
        assert_eq!(l.check(Pipelines::VIRTIO.as_slice(), &[argb]), bad);
        // The primary is at 0, 0 and never off.
        assert_eq!(check(LayerRow { x: 1, ..frame(2) }), bad);
        assert_eq!(check(LayerRow { y: -1, ..frame(2) }), bad);
        assert_eq!(check(LayerRow::off(PIPELINE_PRIMARY)), bad);
        // The cursor is at a point of the screen.
        for (x, y) in [
            (-1, 0),
            (0, -1),
            (640, 0),
            (0, 400),
            (i32::MIN, 0),
            (0, i32::MAX),
        ] {
            assert_eq!(check(LayerRow { x, y, ..arrow() }), bad, "{x} {y}");
        }
        // The hot spot is inside the picture, and absent where there is none.
        for hot in [(64, 0), (0, 64), (u32::MAX, 0), (0, u32::MAX)] {
            assert_eq!(
                check(LayerRow {
                    hot_x: hot.0,
                    hot_y: hot.1,
                    ..arrow()
                }),
                bad
            );
        }
        assert_eq!(
            check(LayerRow {
                hot_x: 1,
                ..frame(2)
            }),
            bad
        );
        // An off row carries no other field.
        assert_eq!(
            check(LayerRow {
                x: 1,
                ..LayerRow::off(2)
            }),
            bad
        );
        assert_eq!(
            check(LayerRow {
                dw: 1,
                ..LayerRow::off(2)
            }),
            bad
        );
        assert_eq!(
            check(LayerRow {
                hot_y: 1,
                ..LayerRow::off(2)
            }),
            bad
        );
    }

    #[test]
    fn rows_with_a_changed_area_out_of_the_source_are_invalid() {
        let check = |row: LayerRow| Layers::new(&[row]).unwrap().check_virtio();
        let area = |dx, dy, dw, dh| LayerRow {
            dx,
            dy,
            dw,
            dh,
            ..frame(2)
        };
        assert_eq!(check(area(0, 0, 640, 400)), Ok(()));
        assert_eq!(check(area(639, 399, 1, 1)), Ok(()));
        assert_eq!(check(area(0, 0, 0, 0)), Ok(()));
        let bad = Err(code(INVALID));
        assert_eq!(check(area(1, 0, 640, 1)), bad);
        assert_eq!(check(area(0, 1, 1, 400)), bad);
        assert_eq!(check(area(640, 0, 1, 1)), bad);
        assert_eq!(check(area(u32::MAX, 0, 2, 1)), bad);
        assert_eq!(check(area(2, 0, u32::MAX, 1)), bad);
        assert_eq!(check(area(0, u32::MAX, 1, 2)), bad);
        assert_eq!(check(area(0, 2, 1, u32::MAX)), bad);
        // An empty side with a rest that is not zero.
        assert_eq!(check(area(5, 0, 0, 0)), bad);
        assert_eq!(check(area(0, 0, 0, 5)), bad);
        assert_eq!(check(area(0, 0, 5, 0)), bad);
        // The cursor picture's area is inside 64 by 64.
        let cur = |dw, dh| LayerRow { dw, dh, ..arrow() };
        assert_eq!(check(cur(64, 64)), Ok(()));
        assert_eq!(check(cur(65, 64)), bad);
        assert_eq!(check(cur(64, 65)), bad);
    }

    #[test]
    fn the_longest_layers_request_is_172_bytes() {
        let l = Layers::new(&[frame(2), arrow(), LayerRow::off(3), LayerRow::off(4)]).unwrap();
        assert_eq!(bytes_of(|w| l.write(w)).len(), 172);
    }

    #[test]
    fn the_cursor_may_sit_at_every_edge_of_the_screen_with_a_hot_spot() {
        let check = |x, y, hot| {
            Layers::new(&[LayerRow::cursor(PIPELINE_CURSOR, SOURCE_CURSOR, x, y, hot)])
                .unwrap()
                .check_virtio()
        };
        // The hot spot of the picture lies at the pointer: the picture hangs
        // off the right and bottom edges, or off the left and top ones.
        assert_eq!(check(0, 0, (0, 0)), Ok(()));
        assert_eq!(check(639, 399, (0, 0)), Ok(()));
        assert_eq!(check(639, 399, (63, 63)), Ok(()));
        assert_eq!(check(0, 0, (63, 63)), Ok(()));
        assert_eq!(check(639, 0, (32, 7)), Ok(()));
        assert_eq!(check(0, 399, (7, 32)), Ok(()));
        assert_eq!(check(640, 399, (63, 63)), Err(code(INVALID)));
        assert_eq!(check(639, 400, (63, 63)), Err(code(INVALID)));
        assert_eq!(check(-1, 0, (63, 63)), Err(code(INVALID)));
    }

    #[test]
    fn the_screen_of_the_cursor_bounds_is_the_primary_pipelines() {
        let big = Pipeline {
            max_w: 800,
            max_h: 600,
            ..Pipeline::VIRTIO_PRIMARY
        };
        let tables = [big, Pipeline::VIRTIO_CURSOR];
        let at = |x, y| {
            Layers::new(&[LayerRow::cursor(
                PIPELINE_CURSOR,
                SOURCE_CURSOR,
                x,
                y,
                (0, 0),
            )])
            .unwrap()
            .check(&tables, &SourceInfo::VIRTIO)
        };
        assert_eq!(at(799, 599), Ok(()));
        assert_eq!(at(800, 0), Err(code(INVALID)));
        assert_eq!(at(0, 600), Err(code(INVALID)));
        // Without a full-screen primary pipeline the bounds are unknown.
        let l = Layers::new(&[LayerRow::cursor(
            PIPELINE_CURSOR,
            SOURCE_CURSOR,
            0,
            0,
            (0, 0),
        )])
        .unwrap();
        assert_eq!(
            l.check(&[Pipeline::VIRTIO_CURSOR], &SourceInfo::VIRTIO),
            Err(code(INVALID))
        );
    }

    #[test]
    fn a_source_layout_has_no_size_cap_and_the_reserved_word_is_zero() {
        let big = SourceInfo {
            id: 5,
            width: 4096,
            height: 4096,
            stride: 4096 * 4,
            format: FORMAT_XRGB8888,
        };
        assert!(big.fits());
        let huge = SourceInfo {
            stride: u32::MAX,
            height: u32::MAX,
            ..big
        };
        assert!(huge.fits(), "the product is formed in 64 bits");
        assert!(
            !SourceInfo {
                stride: 4096 * 4 - 1,
                ..big
            }
            .fits()
        );
        assert!(!SourceInfo { format: 2, ..big }.fits());
        let mut b = bytes_of(|w| Pipeline::VIRTIO_PRIMARY.write(w));
        assert_eq!(words(&b)[7], 0);
        b[28] = 1;
        assert_eq!(Pipeline::read(&mut Reader::new(&b)), Err(code(INVALID)));
        assert_eq!(
            Pipeline::read(&mut Reader::new(&b[..31])),
            Err(Status::BadSize)
        );
    }
}
