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
//! of the whole screen, whose buffer the service makes and FLUSH posts, and
//! whose keys (the session of focus OPEN gives, proto_input's READ) are
//! those of its ring: they come while the window has the focus.
//!
//! | Method | Session | Request | Reply | Refusals |
//! |---|---|---|---|---|
//! | DESCRIBE (17) | `Display`, manager, input | the header alone | status, `width`, `height`, `format`, `flags`, `open`, `created`, `frames`, `busy`, `bypassed`, `bands` (u32 each) | NO_DEVICE |
//! | WINDOW_CREATE (18) | `Display` | `x`, `y`, `w`, `h`, `format`, `flags` (u32); one handle: a channel with NOTIFY and TRANSFER | status, `id` (u32); one handle: the window's session (SEND, TRANSFER) | INVALID, UNSUPPORTED, NO_DEVICE, LIMIT_REACHED |
//! | ATTACH (19) | window | `count`, `stride`, `format` (u32); `count` memory objects with MAP_READ and TRANSFER | the status alone | BUSY, INVALID, UNSUPPORTED, REVOKED |
//! | POST (20) | window | `buffer`, `count` (u32), then `count` rectangles of 4 u32 | the status alone, at once | BUSY, INVALID, NOT_ALLOWED, REVOKED |
//! | EVENTS (21) | window or manager | the header alone | status, `count`, `flags` (u32 each: bit 0 is LOST), then `count` events of 16 bytes | NOT_ALLOWED, REVOKED |
//! | MANAGE (22) | manager | `op`, `a`, `b`, `c` (u32 each); SUBSCRIBE has one handle: a channel with NOTIFY and TRANSFER | the status alone; LIST: status, `count`, then `count` records of 28 bytes | INVALID, NOT_ALLOWED |
//! | INJECT (23) | input | one event of 16 bytes | the status alone | INVALID, NOT_ALLOWED |
//! | SET (24) | window | `property`, `value` (u32) | the status alone | INVALID, UNSUPPORTED, NOT_ALLOWED, REVOKED |
//! | STATS (25) | context, window, manager, input | `flags` (u32) | status, 17 counters, 33 buckets, `count` (u32), then `count` records of 32 bytes | INVALID, NOT_ALLOWED, REVOKED |
//! | SCENE_COMMIT (26) | scene | `flags`, `bg`, `count` (u32), then `count` records of 56 bytes | the status alone, at once | INVALID, NOT_ALLOWED, BUSY, LIMIT_REACHED |
//! | SCENE_COMPOSE (27) | scene | `flags` (u32) | the status alone, at once | INVALID, NOT_ALLOWED, UNSUPPORTED, BUSY |
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
//! A POST of a buffer that is not free is BUSY, and nothing is posted. The
//! rule for the client: it keeps its own mask of the free buffers for the life
//! of the window, clears a buffer's bit when it posts it, sets it when the
//! service's bit for it comes, and posts only a buffer whose bit is set. It
//! never sets the mask afresh while the window lives (a window kept from one
//! stretch of a run to the next still has the buffers the service holds: the
//! one on the screen, and one posted and waiting), and it drops no bit. All
//! buffers are free when ATTACH has answered. With an interval (SET) a buffer
//! posted before its start waits posted until that start, and the one that was
//! on the screen is free when the frame that took it is shown; a client that
//! posts every period with two buffers therefore waits for the bit of the
//! buffer it posted two periods ago, and a bit that has not come is the
//! service's frame still in work: the client skips that period's POST (a
//! frame it did not draw is counted by the service as a miss of the window).
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
//! ring. While a manager has subscribed, the Super keys (Linux's
//! KEY_LEFTMETA and KEY_RIGHTMETA) and the keys pressed with Super held go
//! to it alone: the window with the focus never sees them. The Alt, Ctrl and
//! Shift keys stay the windows' (a game of the first revision binds them).
//!
//! The input session (a label with INPUT_MARK, given by init to the probes)
//! injects an event as if the device had made it: a KEY, a MOVE with the
//! screen's coordinates (the pointer goes there) or a BUTTON.
//!
//! The scene session (a label with SCENE_MARK, given by init to the clients
//! of its table's `COMP_SCENES`, which may be processes of POSIX) is a
//! context and a manager both (it has every right of the manager above, and
//! its ring is the manager's) and holds a scene: the windows that show are
//! the elements of the last scene it committed, and no others. A clone of a
//! session (what `fork` and `posix_spawn` give a child) never has the mark, so
//! the children of the holder of a scene are ordinary contexts; `exec` keeps
//! the session. While a scene session has subscribed (MANAGE SUBSCRIBE) a
//! session with MANAGER_MARK is NOT_ALLOWED in MANAGE, and the scene session's
//! SUBSCRIBE is BUSY while a manager holds the subscription. A session that
//! ends takes its scene with it: the windows show as they did without one at
//! the next frame.
//! `exec` keeps the session, and so the scene: the scene the old image
//! committed stays on screen, its elements naming windows the old image's
//! producers may have closed (such an element shows nothing), until the new
//! image commits its own.
//!
//! The scene is a list of up to MAX_ELEMENTS elements, lowest first, each of
//! SCENE_ELEMENT bytes (see `Element`): the window it shows (the `id` of
//! WINDOW_CREATE; a number no window has shows nothing), the rectangle of the
//! window it takes the points from, in 16.16 points, the rectangle of the
//! screen it puts them in, the orientation (a rotation by 0, 90, 180 or 270
//! degrees clockwise, then a reflection about the vertical axis when bit 2
//! is set), the filter, the kind of transparency (the bits of OpenWF
//! Composition's `WFC_TRANSPARENCY_*`: global alpha, the window's own alpha,
//! a mask), the global alpha (0 to 255) and the mask (the number of a window
//! of FORMAT_A8 the size of the target rectangle; "not shown" as every
//! window of that format). SCENE_COMMIT keeps the last scene it was given
//! as the pending one; it becomes the working one whole, at the taking of a
//! frame, and the bands of a frame read the working scene alone, so a frame
//! shows a scene of one commit or the one before. `flags` bit 0 (ACTIVE)
//! says the scene is composed by itself, at the start of a period that has a
//! change in it or in a window it shows; with the bit clear (the default of
//! a context) a frame is made only by SCENE_COMPOSE, which is UNSUPPORTED for
//! an active scene. `flags` bit 1 asks for the bit COMMITTED (4) on the
//! scene's channel when the pending scene is taken into a frame, and
//! SCENE_COMPOSE's bit 0 for COMPOSED (5) when the frame it made is over. A
//! window that no element of the working scene shows gets the buffer it
//! posted back at the taking (the bit of its number), and a FLUSH of the
//! first revision on such a window is answered at once. The service draws every
//! element whose numbers are in their places (the stretch, the turn, the
//! reflection, the filter, the global alpha and the mask; `meaning` says what each
//! field comes to point by point); SCENE_COMMIT refuses with INVALID what no
//! drawing could make sense of.
//!
//! The elements that turn, reflect or stretch a window are drawn from images the
//! service makes, which a SCENE_COMMIT reserves (two images of 4 bytes a point of the
//! target for each such element, in a pool of 2 MiB shared with the scenes still in
//! use). A refused commit changes nothing. LIMIT_REACHED: the images do not fit the pool
//! beside the images of the working scene, or its fragmentation does not allow them
//! (a scene that fits alone can still get LIMIT); the holder commits a smaller scene.
//! BUSY (also the answer of a second holder): the images fit once the worker that
//! makes them lets go of the slots it holds, which it does within one piece of its
//! work at the commit's level (the service raises it to that level when it refuses with
//! BUSY); the holder tries again after its next event or one period, never in a tight
//! loop. A committed scene is taken when its images are made (the previous scene
//! stays until then, and COMMITTED and COMPOSED come with the whole scene), except
//! for a window that has posted nothing, whose element shows nothing until it posts.
//!
//! Input under a scene: the keys go to the window with the focus, which the
//! scene gives by MANAGE FOCUS; the moves and buttons of the pointer go to
//! the scene's ring as events of the screen's coordinates, and to no window.
//!
//! DESCRIBE's `flags` has bit 0 (HAS_MANAGER) set while a manager has
//! subscribed, and bit 1 (CURSOR_PLANE) once the service put the pointer's
//! picture on the display's cursor pipeline. Its `open` is the windows alive
//! now, `created` the windows ever made, `frames` the frames shown, `busy` 1
//! while a frame is being made or waits to be: a probe that waits for `busy`
//! to be 0 finds the screen settled. `bypassed` counts the frames the display
//! showed straight from the buffer of a window of the first revision (the
//! window covers the whole screen with nothing above it, so the service put
//! nothing together), `bands` the bands of the frames it did put together,
//! both since the service started.
//!
//! The flag `SCANOUT` (bit 0) of WINDOW_CREATE's `flags` is reserved for a
//! window of the second revision whose buffer the display could show
//! directly; the service answers UNSUPPORTED to any nonzero `flags` until it
//! is defined.

#![cfg_attr(not(test), no_std)]

pub mod meaning;

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
pub const FORMAT_ARGB8888: u32 = proto_gpu::FORMAT_ARGB8888;
/// A window of 8 bits an alpha, a point a byte, a line `stride` bytes (at
/// least `w`, a multiple of 4): the mask of an element. It never reaches the
/// screen by itself, under a scene or without one.
pub const FORMAT_A8: u32 = 4;

/// The labels init gives a session of the manager and of the input
/// (services/init `comp_mark`): bits the service's own labels never have
/// (a clone's is bit 63, a window's 62, the driver's 61). The scene's mark is
/// bit 54: bit 58 is the label of the keyboard's grant and 55 the timer's.
pub const MANAGER_MARK: u64 = 1 << 60;
pub const INPUT_MARK: u64 = 1 << 59;
pub const SCENE_MARK: u64 = 1 << 54;

/// DESCRIBE's `flags`: a manager has subscribed.
pub const HAS_MANAGER: u32 = 1;
/// DESCRIBE's `flags`: the pointer's picture is on the display's cursor
/// pipeline, so the points of the screen (the screenshot, the guest's CRC of
/// the frames) never hold it. Without the bit the service draws the picture
/// into the frame.
pub const CURSOR_PLANE: u32 = 2;

/// The bytes of a line of `width` points of `format` at the least: 4 a point,
/// or for FORMAT_A8 a byte a point rounded up to a multiple of 4 (the stride
/// of an A8 window is any multiple of 4 from there). None past a `u32`.
pub const fn line_bytes(format: u32, width: u32) -> Option<u32> {
    if format == FORMAT_A8 {
        match width.checked_add(3) {
            Some(w) => Some(w & !3),
            None => None,
        }
    } else {
        width.checked_mul(4)
    }
}

/// The id of a window: its place in the service's table (3 bits) and the
/// count of windows made at that place (`generation`, 1 to ID_GENERATION_MAX,
/// above the place), so the id of a window that went is no window's again and
/// is below 2^27, a positive `i32`. It is what WINDOW_CREATE answers, what LIST
/// and the events CREATE and CLOSE carry and what MANAGE and an element name.
pub const ID_GENERATION_MAX: u32 = (1 << 24) - 1;
pub const fn window_id(place: u32, generation: u32) -> u32 {
    generation << 3 | place
}
pub const fn id_place(id: u32) -> u32 {
    id & 7
}
pub const fn id_generation(id: u32) -> u32 {
    id >> 3
}

/// The bit the service sends a window's channel when its ring has events;
/// bits 0 to 2 tell the buffer that is free.
pub const EVENTS_BIT: u64 = 1 << 3;
/// The bits the service sends the scene's channel: the pending scene was
/// taken into a frame, and the frame SCENE_COMPOSE asked for is over.
pub const COMMITTED_BIT: u64 = 1 << 4;
pub const COMPOSED_BIT: u64 = 1 << 5;

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
    Set = 24,
    Stats = 25,
    SceneCommit = 26,
    SceneCompose = 27,
}

impl Method {
    pub const ALL: [Method; 11] = [
        Method::Describe,
        Method::WindowCreate,
        Method::Attach,
        Method::Post,
        Method::Events,
        Method::Manage,
        Method::Inject,
        Method::Set,
        Method::Stats,
        Method::SceneCommit,
        Method::SceneCompose,
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
    /// The frames shown straight from a window's buffer (no band), and the
    /// bands put together, both since the service started. A probe that
    /// reads `bands` before and after some frames and finds it unchanged
    /// while `bypassed` grew by their number knows the frames cost the
    /// service no copy.
    pub bypassed: u32,
    pub bands: u32,
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
            self.bypassed,
            self.bands,
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
            bypassed: r.u32()?,
            bands: r.u32()?,
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
/// The manager's: a window was made, a window went. `code` is its place and
/// `value` its id (`window_id`), which the manager gives back in MANAGE.
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
        for n in [
            self.id, self.x, self.y, self.w, self.h, self.flags, self.depth,
        ] {
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

/// The picture of the pointer, which the service lays over the screen and
/// a probe computes the screen's CRC with.
pub mod cursor {
    /// The pointer's picture: 12 by 19 points, '#' black, 'o' white.
    pub const CURSOR_W: u32 = 12;
    pub const CURSOR_H: u32 = 19;
    const CURSOR_ART: [&[u8; CURSOR_W as usize]; CURSOR_H as usize] = [
        b"#           ",
        b"##          ",
        b"#o#         ",
        b"#oo#        ",
        b"#ooo#       ",
        b"#oooo#      ",
        b"#ooooo#     ",
        b"#oooooo#    ",
        b"#ooooooo#   ",
        b"#oooooooo#  ",
        b"#ooooo######",
        b"#oo#oo#     ",
        b"#o# #oo#    ",
        b"##  #oo#    ",
        b"#    #oo#   ",
        b"     #oo#   ",
        b"      #oo#  ",
        b"      #oo#  ",
        b"       ##   ",
    ];

    /// The bytes of the pointer's picture as ARGB8888, premultiplied (the
    /// points are opaque or empty), CURSOR_W * 4 bytes a line.
    pub const CURSOR: [u8; (CURSOR_W * CURSOR_H * 4) as usize] = {
        let mut out = [0u8; (CURSOR_W * CURSOR_H * 4) as usize];
        let mut y = 0;
        while y < CURSOR_H as usize {
            let mut x = 0;
            while x < CURSOR_W as usize {
                let point: u32 = match CURSOR_ART[y][x] {
                    b'#' => 0xFF00_0000,
                    b'o' => 0xFFFF_FFFF,
                    _ => 0,
                };
                let b = point.to_le_bytes();
                let at = (y * CURSOR_W as usize + x) * 4;
                out[at] = b[0];
                out[at + 1] = b[1];
                out[at + 2] = b[2];
                out[at + 3] = b[3];
                x += 1;
            }
            y += 1;
        }
        out
    };
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

// ------------------------------------------------------------- the scene

/// The most elements of a scene: 16 records of SCENE_ELEMENT bytes and the
/// 12 bytes of SCENE_COMMIT's numbers fit the message after the header.
pub const MAX_ELEMENTS: usize = 16;
/// The bytes of an element's record.
pub const SCENE_ELEMENT: usize = 56;
/// The most bytes of a SCENE_COMMIT: the header, `flags`, `bg`, `count`, and
/// the records of MAX_ELEMENTS elements.
pub const SCENE_COMMIT_MAX: usize = 8 + 12 + MAX_ELEMENTS * SCENE_ELEMENT;
const _: () = assert!(SCENE_COMMIT_MAX == 916);

/// SCENE_COMMIT's `flags`: the scene is composed by itself (ACTIVE), and the
/// scene's channel is told by COMMITTED_BIT when the scene is taken into a
/// frame (ASK_COMMITTED).
pub const ACTIVE: u32 = 1;
pub const ASK_COMMITTED: u32 = 2;
/// SCENE_COMPOSE's `flags`: the scene's channel is told by COMPOSED_BIT when
/// the frame is over.
pub const ASK_COMPOSED: u32 = 1;

/// An element's `orient`: the rotation, clockwise, in quarter turns (bits 0
/// and 1), then the reflection about the vertical axis (bit 2).
pub const ROTATION: u32 = 3;
pub const MIRROR: u32 = 4;
/// An element's `filter`: the nearest point, or the bilinear mean (OpenWF's
/// FASTER and NONE are the first, BETTER the second).
pub const NEAREST: u32 = 0;
pub const BILINEAR: u32 = 1;
/// An element's `transparency`, the bits of OpenWF Composition's
/// `WFC_TRANSPARENCY_*`: none is 0; the others lie over what is below by the
/// global `alpha`, by the alpha of the window's own points (FORMAT_ARGB8888),
/// by the mask. The pairs the specification allows are the global alpha with
/// the window's own alpha and the global alpha with the mask.
pub const TRANSPARENCY_ALPHA: u32 = 1;
pub const TRANSPARENCY_SOURCE: u32 = 2;
pub const TRANSPARENCY_MASK: u32 = 4;
/// The greatest magnitude of a coordinate or a side: 2^24, the limit of
/// OpenWF's integers; the 16.16 numbers of the source rectangle are at most
/// that in points.
pub const COORD_MAX: i32 = 1 << 24;

/// The `source` or `mask` of an element that names no window. Window numbers
/// start at 0, so the zero a record is made of cannot mean "none".
pub const NO_WINDOW: u32 = u32::MAX;

/// One element of a scene (SCENE_ELEMENT bytes, fourteen numbers of 4 bytes
/// in this order). `source` and `mask` are the numbers of windows, or
/// NO_WINDOW (a number no window has also shows nothing; the mask is read
/// only when `transparency` has TRANSPARENCY_MASK). The source rectangle (`sx`, `sy`, `sw`,
/// `sh`) is in 16.16 points of the window, the target rectangle (`dx`, `dy`,
/// `dw`, `dh`) in points of the screen, after the orientation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Element {
    pub source: u32,
    pub mask: u32,
    pub sx: i32,
    pub sy: i32,
    pub sw: i32,
    pub sh: i32,
    pub dx: i32,
    pub dy: i32,
    pub dw: i32,
    pub dh: i32,
    pub orient: u32,
    pub filter: u32,
    pub transparency: u32,
    pub alpha: u32,
}

impl Element {
    pub const NONE: Element = Element {
        source: NO_WINDOW,
        mask: NO_WINDOW,
        sx: 0,
        sy: 0,
        sw: 0,
        sh: 0,
        dx: 0,
        dy: 0,
        dw: 0,
        dh: 0,
        orient: 0,
        filter: 0,
        transparency: 0,
        alpha: 0,
    };

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        for n in [self.source, self.mask] {
            w.u32(n)?;
        }
        for n in [
            self.sx, self.sy, self.sw, self.sh, self.dx, self.dy, self.dw, self.dh,
        ] {
            w.u32(n as u32)?;
        }
        for n in [self.orient, self.filter, self.transparency, self.alpha] {
            w.u32(n)?;
        }
        Ok(())
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Element, Status> {
        Ok(Element::from_bytes(r.bytes(SCENE_ELEMENT)?))
    }

    /// The element of a record's SCENE_ELEMENT bytes (a shorter slice reads
    /// zeros for what it lacks).
    pub fn from_bytes(b: &[u8]) -> Element {
        let word = |k: usize| -> u32 {
            match b.get(4 * k..4 * k + 4) {
                Some(w) => u32::from_le_bytes([w[0], w[1], w[2], w[3]]),
                None => 0,
            }
        };
        Element {
            source: word(0),
            mask: word(1),
            sx: word(2) as i32,
            sy: word(3) as i32,
            sw: word(4) as i32,
            sh: word(5) as i32,
            dx: word(6) as i32,
            dy: word(7) as i32,
            dw: word(8) as i32,
            dh: word(9) as i32,
            orient: word(10),
            filter: word(11),
            transparency: word(12),
            alpha: word(13),
        }
    }

    /// Whether the numbers are in the limits of the protocol, whatever the
    /// windows are: an orientation of the listed bits, a filter of the two,
    /// a transparency of the pairs the specification allows, an alpha to 255,
    /// a source rectangle that has a size and starts at or after the window's
    /// corner, a target rectangle of no negative side, and a target place and
    /// size of no magnitude past COORD_MAX.
    pub const fn in_limits(&self) -> bool {
        const fn small(n: i32) -> bool {
            n >= -COORD_MAX && n <= COORD_MAX
        }
        self.sw > 0
            && self.sh > 0
            && self.sx >= 0
            && self.sy >= 0
            && small(self.dx)
            && small(self.dy)
            && self.dw >= 0
            && self.dh >= 0
            && small(self.dw)
            && small(self.dh)
            && self.orient & !(ROTATION | MIRROR) == 0
            && self.filter <= BILINEAR
            && transparency_allowed(self.transparency)
            && self.alpha <= 255
    }
}

/// Whether `bits` are a transparency the specification allows: none, any one
/// kind, the global alpha with the window's own alpha, the global alpha with
/// the mask.
pub const fn transparency_allowed(bits: u32) -> bool {
    matches!(
        bits,
        0 | TRANSPARENCY_ALPHA
            | TRANSPARENCY_SOURCE
            | TRANSPARENCY_MASK
            | 3 // ALPHA | SOURCE
            | 5 // ALPHA | MASK
    )
}

/// SCENE_COMMIT's body: the flags, the background (0xAARRGGBB, the colour
/// premultiplied by the alpha) and the elements, lowest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SceneCommit {
    pub flags: u32,
    pub bg: u32,
    pub count: u32,
    pub elements: [Element; MAX_ELEMENTS],
}

impl SceneCommit {
    /// A SCENE_COMMIT of `elements`; INVALID past MAX_ELEMENTS.
    pub fn new(flags: u32, bg: u32, elements: &[Element]) -> Result<SceneCommit, Status> {
        if elements.len() > MAX_ELEMENTS {
            return Err(code(INVALID));
        }
        let mut commit = SceneCommit {
            flags,
            bg,
            count: elements.len() as u32,
            elements: [Element::NONE; MAX_ELEMENTS],
        };
        commit.elements[..elements.len()].copy_from_slice(elements);
        Ok(commit)
    }

    pub fn elements(&self) -> &[Element] {
        &self.elements[..self.count as usize]
    }

    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Method::SceneCommit.header().write(w)?;
        w.u32(self.flags)?;
        w.u32(self.bg)?;
        w.u32(self.count)?;
        for e in self.elements() {
            e.write(w)?;
        }
        Ok(())
    }

    /// The body after the header: BAD_SIZE unless it is the three numbers and
    /// `count` records, INVALID for a count past MAX_ELEMENTS (read before the
    /// records, so a count that is too big is INVALID whatever follows), a
    /// flag the service has not, or a record out of the limits.
    pub fn read(body: Reader<'_>) -> Result<SceneCommit, Status> {
        let mut commit = SceneCommit {
            flags: 0,
            bg: 0,
            count: 0,
            elements: [Element::NONE; MAX_ELEMENTS],
        };
        let (flags, bg, count) = SceneCommit::read_into(body, &mut commit.elements)?;
        commit.flags = flags;
        commit.bg = bg;
        commit.count = count as u32;
        Ok(commit)
    }

    /// `read` into `elements` (room for MAX_ELEMENTS) with no copy of a whole
    /// scene: the flags, the background and the count of the elements set. The
    /// service parses into the place its scene is kept in.
    pub fn read_into(
        mut body: Reader<'_>,
        elements: &mut [Element],
    ) -> Result<(u32, u32, usize), Status> {
        let flags = body.u32()?;
        let bg = body.u32()?;
        let count = body.u32()? as usize;
        if count > MAX_ELEMENTS || count > elements.len() {
            return Err(code(INVALID));
        }
        for e in &mut elements[..count] {
            *e = Element::read(&mut body)?;
        }
        body.finish()?;
        if flags & !(ACTIVE | ASK_COMMITTED) != 0
            || elements[..count].iter().any(|e| !e.in_limits())
        {
            return Err(code(INVALID));
        }
        Ok((flags, bg, count))
    }
}

/// SCENE_COMPOSE's request: the header and the flags.
pub fn write_scene_compose(flags: u32, w: &mut Writer) -> Result<(), Status> {
    Method::SceneCompose.header().write(w)?;
    w.u32(flags)
}

/// The flags of SCENE_COMPOSE's body: BAD_SIZE unless it is one number,
/// INVALID for a bit the service has not.
pub fn read_scene_compose(mut body: Reader<'_>) -> Result<u32, Status> {
    let flags = body.u32()?;
    body.finish()?;
    if flags & !ASK_COMPOSED != 0 {
        return Err(code(INVALID));
    }
    Ok(flags)
}

// ------------------------------------------------------- the frame clock

/// The properties of SET (the methods of the frame clock, stage G5). A SET
/// goes on a window's session, names a property and gives its value; the
/// numbers leave room for the others of the design (visibility, opacity, a
/// title).
///
/// INTERVAL: the periods a window promises between its posts, 0 to
/// INTERVAL_MAX. 0 (the default) is "the latest wins" at every frame and no
/// lateness of the window is counted. N from 1: the window's buffer is taken
/// at most once in N periods; after a taking at the start of period k the
/// window is awaited at the start of k + N. A buffer posted by then is on
/// time; one posted after it and before the start of k + N + 1 is late
/// (`WindowStats::late`, the time after the start in `late_max_us`); a
/// window with nothing posted by the start of k + N + 1 has missed
/// (`WindowStats::missed`) and is awaited no more until its next POST, so a
/// client that goes quiet gets one `missed` for the pause. A window of the
/// first revision has no interval: its SET is NOT_ALLOWED.
pub const INTERVAL: u32 = 1;
pub const INTERVAL_MAX: u32 = 4;

/// STATS' flags: bit 0 RESET clears the counters and their greatest values
/// after the reply is made. The counters are shared, so only a session with
/// MANAGER_MARK or INPUT_MARK may ask it (others: NOT_ALLOWED). A frame taken
/// before a RESET and shown after it is counted in `frames` of the period
/// that follows (and not in its `releases`), so in the first period after a
/// reset `frames` can be one more than `releases`.
pub const RESET: u32 = 1;

/// The most windows STATS' reply holds records of: MAX_WINDOWS of the service.
pub const STATS_WINDOWS: usize = 8;
/// The buckets of the histogram of the time of a frame: 32 of T/16 up to 2 T,
/// and one for what is more.
pub const BUCKETS: usize = 33;
/// The counters before the histogram.
pub const COUNTERS: usize = 17;
/// The bytes of a window's record.
pub const WINDOW_STATS_LEN: usize = 32;
/// The most bytes of STATS' reply: the status, the counters, the buckets,
/// the count and the records of every window.
pub const STATS_MAX: usize = 4 + (COUNTERS + BUCKETS + 1) * 4 + STATS_WINDOWS * WINDOW_STATS_LEN;

/// SET's body: the property and its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetBody {
    pub property: u32,
    pub value: u32,
}

impl SetBody {
    /// The header and the body.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Method::Set.header().write(w)?;
        w.u32(self.property)?;
        w.u32(self.value)
    }

    /// The body after the header: BAD_SIZE unless it is the two numbers,
    /// UNSUPPORTED for a property the service has not, INVALID for an
    /// interval past INTERVAL_MAX.
    pub fn read(mut body: Reader<'_>) -> Result<SetBody, Status> {
        let set = SetBody {
            property: body.u32()?,
            value: body.u32()?,
        };
        body.finish()?;
        match set.property {
            INTERVAL if set.value > INTERVAL_MAX => Err(code(INVALID)),
            INTERVAL => Ok(set),
            _ => Err(code(UNSUPPORTED)),
        }
    }
}

/// STATS' request: the header and the flags.
pub fn write_stats(flags: u32, w: &mut Writer) -> Result<(), Status> {
    Method::Stats.header().write(w)?;
    w.u32(flags)
}

/// The flags of STATS' body: BAD_SIZE unless it is one number, INVALID for
/// a bit the service has not.
pub fn read_stats_request(mut body: Reader<'_>) -> Result<u32, Status> {
    let flags = body.u32()?;
    body.finish()?;
    if flags & !RESET != 0 {
        return Err(code(INVALID));
    }
    Ok(flags)
}

/// The counters of the frame clock since the last reset (times in
/// microseconds, but `since_ms`). The meaning of each is in the design of the
/// frame clock (docs/compositor.md, "The frame clock").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    /// The period and the work cap of a period; `period_us` 0 is the free
    /// run (a frame as soon as the device is ready).
    pub period_us: u32,
    pub cap_us: u32,
    pub since_ms: u32,
    /// Takings at the start of a period, shown frames, of which direct.
    pub releases: u32,
    pub frames: u32,
    pub direct: u32,
    /// Frames that released a buffer and were shown after the start of the
    /// next period (a frame taken before a reset is not counted), starts of a period
    /// at which a change waited and nothing was taken, frames the device
    /// failed, periods in which the cap put bands off, firings of the frame's
    /// timer.
    pub late: u32,
    pub skipped: u32,
    pub failed: u32,
    pub capped: u32,
    pub wakeups: u32,
    /// The greatest delay of a taking, time to compose, time of the device,
    /// time of a frame and of a direct frame, and the longest step of a band
    /// by the wall.
    pub take_max_us: u32,
    pub compose_max_us: u32,
    pub device_max_us: u32,
    pub frame_max_us: u32,
    pub direct_max_us: u32,
    pub band_max_us: u32,
    /// The time of a frame: 32 buckets of T/16 up to 2 T and one beyond.
    pub hist: [u32; BUCKETS],
}

impl Stats {
    /// Every counter zero.
    pub const ZERO: Stats = Stats {
        period_us: 0,
        cap_us: 0,
        since_ms: 0,
        releases: 0,
        frames: 0,
        direct: 0,
        late: 0,
        skipped: 0,
        failed: 0,
        capped: 0,
        wakeups: 0,
        take_max_us: 0,
        compose_max_us: 0,
        device_max_us: 0,
        frame_max_us: 0,
        direct_max_us: 0,
        band_max_us: 0,
        hist: [0; BUCKETS],
    };
}

impl Default for Stats {
    fn default() -> Stats {
        Stats::ZERO
    }
}

/// One window's counters: its place, its interval, the POSTs it made, the
/// buffers taken into a frame, the buffers a newer one replaced before they
/// were taken, the times it was late and missed (with an interval), and the
/// greatest lateness.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowStats {
    pub id: u32,
    pub interval: u32,
    pub posts: u32,
    pub taken: u32,
    pub replaced: u32,
    pub late: u32,
    pub missed: u32,
    pub late_max_us: u32,
}

impl WindowStats {
    fn write(&self, w: &mut Writer) -> Result<(), Status> {
        for n in [
            self.id,
            self.interval,
            self.posts,
            self.taken,
            self.replaced,
            self.late,
            self.missed,
            self.late_max_us,
        ] {
            w.u32(n)?;
        }
        Ok(())
    }

    fn read(r: &mut Reader<'_>) -> Result<WindowStats, Status> {
        Ok(WindowStats {
            id: r.u32()?,
            interval: r.u32()?,
            posts: r.u32()?,
            taken: r.u32()?,
            replaced: r.u32()?,
            late: r.u32()?,
            missed: r.u32()?,
            late_max_us: r.u32()?,
        })
    }
}

/// STATS' reply: the counters and the windows (up to STATS_WINDOWS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatsReply {
    pub stats: Stats,
    pub windows: [WindowStats; STATS_WINDOWS],
    pub count: usize,
}

impl StatsReply {
    /// The reply of `stats` and `windows` (BAD_SIZE for more than
    /// STATS_WINDOWS).
    pub fn new(stats: Stats, windows: &[WindowStats]) -> Result<StatsReply, Status> {
        if windows.len() > STATS_WINDOWS {
            return Err(Status::BadSize);
        }
        let mut reply = StatsReply {
            stats,
            windows: [WindowStats::default(); STATS_WINDOWS],
            count: windows.len(),
        };
        reply.windows[..windows.len()].copy_from_slice(windows);
        Ok(reply)
    }

    pub fn windows(&self) -> &[WindowStats] {
        &self.windows[..self.count]
    }

    /// Status 0, the counters, the buckets, the count, the records.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        let s = &self.stats;
        w.u32(Status::Ok.code())?;
        for n in [
            s.period_us,
            s.cap_us,
            s.since_ms,
            s.releases,
            s.frames,
            s.direct,
            s.late,
            s.skipped,
            s.failed,
            s.capped,
            s.wakeups,
            s.take_max_us,
            s.compose_max_us,
            s.device_max_us,
            s.frame_max_us,
            s.direct_max_us,
            s.band_max_us,
        ] {
            w.u32(n)?;
        }
        for n in s.hist {
            w.u32(n)?;
        }
        w.u32(self.count as u32)?;
        for record in self.windows() {
            record.write(w)?;
        }
        Ok(())
    }

    /// The reply in `reply`: a refusal that carries nothing is its status
    /// alone and comes back as the error; BAD_SIZE for a count past
    /// STATS_WINDOWS or any length but the one the count says.
    pub fn read(reply: &[u8]) -> Result<StatsReply, Status> {
        let mut r = Reader::new(reply);
        let status = Status::from_code(r.u32()?);
        if status != Status::Ok {
            return Err(status);
        }
        let mut c = [0u32; COUNTERS];
        for n in &mut c {
            *n = r.u32()?;
        }
        let mut hist = [0u32; BUCKETS];
        for n in &mut hist {
            *n = r.u32()?;
        }
        let count = r.u32()? as usize;
        if count > STATS_WINDOWS {
            return Err(Status::BadSize);
        }
        let mut windows = [WindowStats::default(); STATS_WINDOWS];
        for record in &mut windows[..count] {
            *record = WindowStats::read(&mut r)?;
        }
        r.finish()?;
        Ok(StatsReply {
            stats: Stats {
                period_us: c[0],
                cap_us: c[1],
                since_ms: c[2],
                releases: c[3],
                frames: c[4],
                direct: c[5],
                late: c[6],
                skipped: c[7],
                failed: c[8],
                capped: c[9],
                wakeups: c[10],
                take_max_us: c[11],
                compose_max_us: c[12],
                device_max_us: c[13],
                frame_max_us: c[14],
                direct_max_us: c[15],
                band_max_us: c[16],
                hist,
            },
            windows,
            count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_format_numbers_are_those_of_gpu() {
        assert_eq!(FORMAT_XRGB8888, 1);
        assert_eq!(FORMAT_ARGB8888, 3);
        assert_eq!(proto_gpu::format_bit(2), 0, "2 is no format");
    }

    #[test]
    fn the_methods_keep_their_numbers_apart_from_gpus() {
        let numbers: Vec<_> = Method::ALL.iter().map(|m| m.number()).collect();
        assert_eq!(numbers, [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27]);
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
            bypassed: 2,
            bands: 77,
        };
        let mut w = Writer::new();
        d.write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 44);
        assert_eq!(Description::read(w.as_bytes()), Ok(d));
        assert_eq!(Description::read(&w.as_bytes()[..36]), Err(Status::BadSize));
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

    fn sample_stats() -> Stats {
        let mut s = Stats {
            period_us: 16_667,
            cap_us: 12_500,
            since_ms: 900,
            releases: 5,
            frames: 6,
            direct: 7,
            late: 8,
            skipped: 9,
            failed: 10,
            capped: 11,
            wakeups: 12,
            take_max_us: 13,
            compose_max_us: 14,
            device_max_us: 15,
            frame_max_us: 16,
            direct_max_us: 17,
            band_max_us: 18,
            hist: [0; BUCKETS],
        };
        for (i, n) in s.hist.iter_mut().enumerate() {
            *n = 100 + i as u32;
        }
        s
    }

    fn window(id: u32) -> WindowStats {
        WindowStats {
            id,
            interval: 1 + id % 4,
            posts: 10 * id,
            taken: 11 * id,
            replaced: 12 * id,
            late: 13 * id,
            missed: 14 * id,
            late_max_us: 15 * id,
        }
    }

    fn reply_bytes(reply: &StatsReply) -> Vec<u8> {
        let mut w = Writer::new();
        reply.write(&mut w).unwrap();
        w.as_bytes().to_vec()
    }

    #[test]
    fn the_numbers_of_the_frame_clock_methods() {
        assert_eq!(Method::Set.number(), 24);
        assert_eq!(Method::Stats.number(), 25);
        assert_eq!(VERSION, 1);
        assert_eq!((INTERVAL, INTERVAL_MAX, RESET), (1, 4, 1));
    }

    #[test]
    fn a_set_round_trips_and_a_bad_one_is_refused() {
        for value in 0..=INTERVAL_MAX {
            let set = SetBody {
                property: INTERVAL,
                value,
            };
            let mut w = Writer::new();
            set.write(&mut w).unwrap();
            let mut r = Reader::new(w.as_bytes());
            Header::read(&mut r).unwrap();
            assert_eq!(SetBody::read(r), Ok(set));
        }
        let read = |property, value| {
            let mut w = Writer::new();
            SetBody { property, value }.write(&mut w).unwrap();
            let mut r = Reader::new(w.as_bytes());
            Header::read(&mut r).unwrap();
            SetBody::read(r)
        };
        assert_eq!(read(INTERVAL, 5), Err(code(INVALID)));
        assert_eq!(read(INTERVAL, u32::MAX), Err(code(INVALID)));
        assert_eq!(read(2, 0), Err(code(UNSUPPORTED)));
        assert_eq!(read(0, 0), Err(code(UNSUPPORTED)));
        // A body of one number or of three is BAD_SIZE.
        assert_eq!(
            SetBody::read(Reader::new(&[1, 0, 0, 0])),
            Err(Status::BadSize)
        );
        assert_eq!(SetBody::read(Reader::new(&[0; 12])), Err(Status::BadSize));
    }

    #[test]
    fn a_stats_request_carries_the_flags() {
        let mut w = Writer::new();
        write_stats(RESET, &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        let header = Header::read(&mut r).unwrap();
        assert_eq!(header.method, 25);
        assert_eq!(read_stats_request(r), Ok(RESET));
        assert_eq!(read_stats_request(Reader::new(&[0; 4])), Ok(0));
        assert_eq!(
            read_stats_request(Reader::new(&[2, 0, 0, 0])),
            Err(code(INVALID))
        );
        assert_eq!(
            read_stats_request(Reader::new(&[0; 3])),
            Err(Status::BadSize)
        );
        assert_eq!(
            read_stats_request(Reader::new(&[0; 8])),
            Err(Status::BadSize)
        );
    }

    #[test]
    fn a_stats_reply_round_trips_with_no_window_and_with_eight() {
        for count in [0, 1, 8] {
            let windows: Vec<WindowStats> = (1..=count).map(window).collect();
            let reply = StatsReply::new(sample_stats(), &windows).unwrap();
            let bytes = reply_bytes(&reply);
            assert_eq!(
                bytes.len(),
                4 + (COUNTERS + BUCKETS + 1) * 4 + count as usize * WINDOW_STATS_LEN
            );
            let back = StatsReply::read(&bytes).unwrap();
            assert_eq!(back, reply);
            assert_eq!(back.windows(), &windows[..]);
        }
        // The longest reply is the 464 bytes of the design.
        assert_eq!(STATS_MAX, 464);
        let full = StatsReply::new(sample_stats(), &(1..=8).map(window).collect::<Vec<_>>());
        assert_eq!(reply_bytes(&full.unwrap()).len(), 464);
    }

    #[test]
    fn a_stats_reply_of_another_length_is_refused() {
        let reply = StatsReply::new(sample_stats(), &[window(1), window(2)]).unwrap();
        let bytes = reply_bytes(&reply);
        // Shorter, longer, and a count that the length does not match.
        assert_eq!(
            StatsReply::read(&bytes[..bytes.len() - 1]),
            Err(Status::BadSize)
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(StatsReply::read(&longer), Err(Status::BadSize));
        let at = 4 + (COUNTERS + BUCKETS) * 4;
        let mut wrong = bytes.clone();
        wrong[at] = 3;
        assert_eq!(StatsReply::read(&wrong), Err(Status::BadSize));
        // A count past 8 is more than 464 bytes can hold.
        let mut nine = bytes.clone();
        nine[at] = 9;
        nine.resize(4 + (COUNTERS + BUCKETS + 1) * 4 + 9 * WINDOW_STATS_LEN, 0);
        assert!(nine.len() > STATS_MAX);
        assert_eq!(StatsReply::read(&nine), Err(Status::BadSize));
        assert_eq!(StatsReply::read(&[0; 3]), Err(Status::BadSize));
        assert!(StatsReply::new(sample_stats(), &[WindowStats::default(); 9]).is_err());
        // A refusal is its status alone.
        let refused = proto_wire::reply(code(NOT_ALLOWED));
        assert_eq!(StatsReply::read(&refused), Err(code(NOT_ALLOWED)));
    }

    /// Every field has its own place: a different number in each of the 51
    /// words of the reply and the 8 of a record comes back in its field.
    #[test]
    fn every_field_keeps_its_place_in_the_reply() {
        let reply = StatsReply::new(sample_stats(), &[window(3)]).unwrap();
        let bytes = reply_bytes(&reply);
        let word = |i: usize| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
        // Status, then the counters in the order of the table.
        assert_eq!(word(0), 0);
        let order = [
            16_667, 12_500, 900, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ];
        for (i, n) in order.iter().enumerate() {
            assert_eq!(word(1 + i), *n, "counter {i}");
        }
        assert_eq!(word(1 + COUNTERS), 100);
        assert_eq!(word(COUNTERS + BUCKETS), 132);
        assert_eq!(word(1 + COUNTERS + BUCKETS), 1);
        let w = window(3);
        let record = [
            w.id,
            w.interval,
            w.posts,
            w.taken,
            w.replaced,
            w.late,
            w.missed,
            w.late_max_us,
        ];
        for (i, n) in record.iter().enumerate() {
            assert_eq!(word(2 + COUNTERS + BUCKETS + i), *n, "record {i}");
        }
    }

    // ------------------------------------------------------------ the scene

    fn element(source: u32) -> Element {
        Element {
            source,
            mask: NO_WINDOW,
            sx: 0,
            sy: 0,
            sw: 100 << 16,
            sh: 50 << 16,
            dx: 10,
            dy: -20,
            dw: 100,
            dh: 50,
            orient: 0,
            filter: NEAREST,
            transparency: 0,
            alpha: 255,
        }
    }

    fn commit_bytes(commit: &SceneCommit) -> Vec<u8> {
        let mut w = Writer::new();
        commit.write(&mut w).unwrap();
        w.as_bytes().to_vec()
    }

    fn read_commit(bytes: &[u8]) -> Result<SceneCommit, Status> {
        let mut r = Reader::new(bytes);
        Header::read(&mut r).unwrap();
        SceneCommit::read(r)
    }

    #[test]
    fn the_scene_marks_and_bits_are_apart_from_the_others() {
        let marks = [MANAGER_MARK, INPUT_MARK, SCENE_MARK];
        for (i, a) in marks.iter().enumerate() {
            assert_eq!(a.count_ones(), 1);
            // Not a clone's (63), a window's (62), the driver's (61), the
            // keyboard's and the pointer's grants (58, 57), a window's keys (56)
            // or the timer's (55).
            assert_eq!(
                a & (1 << 63 | 1 << 62 | 1 << 61 | 1 << 58 | 1 << 57 | 1 << 56 | 1 << 55),
                0
            );
            assert!(!marks[..i].contains(a));
        }
        assert_eq!(EVENTS_BIT | COMMITTED_BIT | COMPOSED_BIT, 0b111000);
        assert_eq!(FORMAT_A8, 4);
        assert_ne!(proto_gpu::format_bit(FORMAT_A8), 1);
    }

    #[test]
    fn a_scene_of_sixteen_elements_is_916_bytes_of_the_1024() {
        let commit = SceneCommit::new(ACTIVE, 0xFF10_2030, &[element(1); MAX_ELEMENTS]).unwrap();
        let bytes = commit_bytes(&commit);
        assert_eq!(bytes.len(), SCENE_COMMIT_MAX);
        assert_eq!(bytes.len(), 916);
        assert!(bytes.len() <= 1024);
        assert_eq!(SCENE_ELEMENT, 56);
        let mut w = Writer::new();
        element(3).write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), SCENE_ELEMENT);
    }

    #[test]
    fn a_scene_round_trips_with_its_flags_background_and_order() {
        let mut a = element(2);
        a.orient = ROTATION | MIRROR;
        a.filter = BILINEAR;
        a.transparency = TRANSPARENCY_ALPHA | TRANSPARENCY_MASK;
        a.mask = 5;
        a.alpha = 191;
        a.sx = 3 << 16 | 0x8000;
        let elements = [element(1), a, element(NO_WINDOW)];
        let commit = SceneCommit::new(ACTIVE | ASK_COMMITTED, 0x8000_0000, &elements).unwrap();
        let back = read_commit(&commit_bytes(&commit)).unwrap();
        assert_eq!(back, commit);
        assert_eq!(back.elements(), &elements);
        assert_eq!((back.flags, back.bg, back.count), (3, 0x8000_0000, 3));
        // An empty scene is only its three numbers.
        let empty = SceneCommit::new(0, 0, &[]).unwrap();
        assert_eq!(commit_bytes(&empty).len(), 20);
        assert_eq!(read_commit(&commit_bytes(&empty)).unwrap().count, 0);
    }

    #[test]
    fn the_record_has_the_fields_in_their_order_on_the_wire() {
        let mut e = element(7);
        e.mask = 8;
        e.alpha = 9;
        let mut w = Writer::new();
        e.write(&mut w).unwrap();
        let b = w.as_bytes();
        let word = |i: usize| i32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
        assert_eq!(word(0), 7);
        assert_eq!(word(1), 8);
        assert_eq!(
            [word(2), word(3), word(4), word(5)],
            [0, 0, 100 << 16, 50 << 16]
        );
        assert_eq!([word(6), word(7), word(8), word(9)], [10, -20, 100, 50]);
        assert_eq!([word(10), word(11), word(12), word(13)], [0, 0, 0, 9]);
    }

    #[test]
    fn a_scene_past_sixteen_elements_or_of_the_wrong_length_is_refused() {
        assert_eq!(
            SceneCommit::new(0, 0, &[element(1); MAX_ELEMENTS + 1]),
            Err(code(INVALID))
        );
        // A count of 17 in the bytes is INVALID whatever follows.
        let mut bytes = commit_bytes(&SceneCommit::new(0, 0, &[element(1)]).unwrap());
        bytes[16..20].copy_from_slice(&17u32.to_le_bytes());
        assert_eq!(read_commit(&bytes), Err(code(INVALID)));
        // A count that says more records than the bytes hold is BAD_SIZE.
        let mut bytes = commit_bytes(&SceneCommit::new(0, 0, &[element(1)]).unwrap());
        bytes[16..20].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(read_commit(&bytes), Err(Status::BadSize));
        // Bytes after the last record are BAD_SIZE.
        let mut bytes = commit_bytes(&SceneCommit::new(0, 0, &[element(1)]).unwrap());
        bytes.push(0);
        assert_eq!(read_commit(&bytes), Err(Status::BadSize));
        // A record cut short.
        let bytes = commit_bytes(&SceneCommit::new(0, 0, &[element(1)]).unwrap());
        assert_eq!(read_commit(&bytes[..bytes.len() - 4]), Err(Status::BadSize));
    }

    #[test]
    fn an_unknown_flag_or_a_record_out_of_its_limits_is_invalid() {
        let commit = |e: Element| SceneCommit::new(0, 0, &[e]).unwrap();
        assert_eq!(
            read_commit(&commit_bytes(&SceneCommit::new(4, 0, &[]).unwrap())),
            Err(code(INVALID))
        );
        type Change = fn(&mut Element);
        let broken: [(&str, Change); 14] = [
            ("a zero width", |e| e.sw = 0),
            ("a zero height", |e| e.sh = 0),
            ("a negative source place", |e| e.sx = -1),
            ("a negative source line", |e| e.sy = -1),
            ("a negative target width", |e| e.dw = -1),
            ("a negative target height", |e| e.dh = -1),
            ("a target place past the limit", |e| e.dx = COORD_MAX + 1),
            ("a target place under the limit", |e| e.dy = -COORD_MAX - 1),
            ("a target side past the limit", |e| e.dw = COORD_MAX + 1),
            ("a turn bit that is none", |e| e.orient = 8),
            ("a filter that is none", |e| e.filter = 2),
            ("a source with a mask", |e| {
                e.transparency = TRANSPARENCY_SOURCE | TRANSPARENCY_MASK
            }),
            ("a transparency of three kinds", |e| e.transparency = 7),
            ("an alpha past 255", |e| e.alpha = 256),
        ];
        for (what, change) in broken {
            let mut e = element(1);
            change(&mut e);
            assert_eq!(
                read_commit(&commit_bytes(&commit(e))),
                Err(code(INVALID)),
                "{what}"
            );
        }
        // The edges that are allowed.
        for change in [
            (|e: &mut Element| e.dw = 0) as fn(&mut Element),
            |e| e.dw = COORD_MAX,
            |e| e.dx = -COORD_MAX,
            |e| e.alpha = 255,
            |e| e.transparency = TRANSPARENCY_ALPHA | TRANSPARENCY_SOURCE,
            |e| e.transparency = TRANSPARENCY_MASK,
            |e| e.orient = ROTATION | MIRROR,
        ] {
            let mut e = element(1);
            change(&mut e);
            assert!(read_commit(&commit_bytes(&commit(e))).is_ok());
        }
    }

    #[test]
    fn the_pairs_of_transparency_are_the_ones_of_the_specification() {
        let allowed: Vec<u32> = (0..8).filter(|&b| transparency_allowed(b)).collect();
        assert_eq!(allowed, [0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn scene_compose_is_one_flag_word() {
        let mut w = Writer::new();
        write_scene_compose(ASK_COMPOSED, &mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 12);
        let mut r = Reader::new(w.as_bytes());
        let header = Header::read(&mut r).unwrap();
        assert_eq!(header.method, 27);
        assert_eq!(read_scene_compose(r), Ok(ASK_COMPOSED));
        let mut w = Writer::new();
        write_scene_compose(2, &mut w).unwrap();
        let mut r = Reader::new(w.as_bytes());
        Header::read(&mut r).unwrap();
        assert_eq!(read_scene_compose(r), Err(code(INVALID)));
        assert_eq!(read_scene_compose(Reader::new(&[])), Err(Status::BadSize));
    }

    #[test]
    fn a_window_id_is_its_place_and_the_count_of_windows_made_there() {
        let id = window_id(5, 77);
        assert_eq!(id_place(id), 5);
        assert_eq!(id_generation(id), 77);
        assert_ne!(window_id(5, 78), id);
        // The greatest id is a positive i32 and is not NO_WINDOW.
        let top = window_id(7, ID_GENERATION_MAX);
        assert!(top < 1 << 27 && top as i32 > 0);
        assert_ne!(top, NO_WINDOW);
    }
}
