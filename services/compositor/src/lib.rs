// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the composition service decides, apart from the calls it makes:
//! the windows and their buffers (`Scene`), who has the focus and where
//! the events of the keys and of the pointer go, and the putting together
//! of the screen from the windows (`compose`, whose pixel operations are a
//! `Raster`: pixman in the program, a plain copy in the host tests).
//! Everything here builds for the host too, where `cargo test -p
//! compositor` exercises it.
//!
//! A window is a rectangle of the screen with up to three buffers. A
//! buffer is free (the client draws in it), posted (the client gave it up)
//! or taken (a frame reads it, or the screen shows it). A frame takes the
//! posted buffer of every window at its start: that is the whole of the
//! "taking" of the design, one step. The frame is then made in bands of a
//! few lines, a step each; the buffer the taken one replaced on the screen
//! is free once the frame is shown. The windows that have nothing taken
//! yet show nothing.
//!
//! The scene routes the events (`key`, `pointer`, `button`): into the ring
//! of the window with the focus or under the pointer, and the manager's.
//! Whoever called then asks `delivered` which rings got something, to tell
//! their owners.
//!
//! A frame reaches the screen in one of three ways (`FrameKind`). The
//! composed frame puts the windows together in the target (`fb`) and the
//! primary pipeline shows the target. The direct frame (`Plan::Bypass`,
//! decided by `Scene::plan` when a frame starts) puts nothing together: one
//! window of the first revision covers the whole screen with nothing above
//! it, and the primary pipeline shows its buffer, the pool, as it is. When
//! the rule stops holding the frame that follows is a rebind: the whole
//! screen is put together in the target (the target is stale, for it was not
//! kept while the pool was shown) and the primary pipeline is bound to the
//! target after the last band, so that the screen shows the last frame of
//! the window until the new one is whole. The pool is cleared only once the
//! primary pipeline does not show it any more (`take_pool_clear`).

#![cfg_attr(not(test), no_std)]

pub mod fit;
pub mod frame;

use proto_comp::{
    BUFFERS, BUTTON, CLOSE, CREATE, Event, FOCUS_IN, FOCUS_OUT, KEY, MAX_RECTS, MOVE, RING, Rect,
    union,
};
use proto_gpu::{HEIGHT, LayerRow, STRIDE, WIDTH};

/// The windows at once, and the windows of one context.
pub const MAX_WINDOWS: usize = 8;
// The places a mask of `u8` names (`Scene::create`).
const _: () = assert!(MAX_WINDOWS <= 8);
pub const PER_CONTEXT: usize = 4;
/// The most lines of one band of a frame (`Scene::tile` makes a band
/// shorter where its layers cost more). A copy band over the whole width
/// holds nine lines at the prices below, so the limit leaves the prices to
/// decide.
pub const BAND_ROWS: u32 = 16;

/// What a band costs the service in ticks (`Scene::tile`): at most
/// BAND_TICKS in all. The step of a band is its work and a part of about
/// 2 400 ticks of the step itself, and the gate of a band is 16 328, so a
/// band of 15 000 leaves the tenth of a step for the interrupts.
pub const BAND_TICKS: u32 = 15_000;

/// The price of one kind of operation (the black a band starts with, a layer
/// copied, a layer laid over others): what one operation costs is
/// `call + rows * row + points * point`. The call is what pixman does
/// whatever the size, the row what it does for each line (the entry of the
/// loop of a line and the edges before the aligned points), the point what it
/// does for each point. There are no prices by alignment or by the format of
/// the source: the edges fall on the row, and a window of XRGB8888 is always a
/// copy and one of ARGB8888 always a layer laid over others.
///
/// A `_measured` is the greatest figure of the probes under -icount (the line
/// `service raster` of `px::cost`, class by class: the call over operations of
/// one row and 8 points or fewer, the row over operations at most 16 points
/// wide and at least 8 rows, the point over operations of 1 024 points or
/// more, the call and the rows taken off), and the constant the scene charges
/// is the measure with the margin of MARGIN_PERCENT, rounded up. A call is in
/// ticks, a row and a point in hundredths of a tick. `*_estimate` marks a
/// price no probe has measured: a figure scaled from the cost before the NEON
/// paths of pixman (a copy 2.7 ticks a point, a layer laid over others 25) or
/// a guess (the row), kept high on purpose until the probe's line gives it,
/// and the table takes that. The test
/// `the_constants_cover_the_measures_with_the_margin` holds every constant to
/// its measure.
///
/// What the fit showed (the same in both probes). The cost of a row at a width
/// is the price of a row plus the width's points where the width is 64 points or
/// more (copy: 144 ticks at 64 wide, 265 at 152, a slope of 1.38 a point and a
/// row of 55), and cheaper at the narrow widths (4 to 12 wide: 16 to 30 ticks
/// for a copy): the narrow rows do not cost more a point than the model says,
/// so three terms suffice, and the model overstates a narrow tall shape (4 by
/// 32: by 273 ticks for the black, 1 090 for a copy, 3 189 for a layer laid over
/// others), which only makes a band of a narrow damage smaller than it could be.
/// The shapes of the width of the screen are in the fit (a copy of 640 by 13:
/// 12 438 to 12 945 ticks, a layer laid over others 36 345 to 38 620, the black
/// 3 459 to 3 641), and the model with the constants is above their greatest.
/// The widths of the shapes go up to 152 points and include 640 (the width of
/// the screen: 640 by 1, 8 and 13 lines), the width of the main band of the
/// table. Under -icount the time is instructions: there is no cold cache, no
/// miss of a translation, no first touch of a buffer (the buffers are mapped in
/// advance), and the one cache of the service that can be cold, pixman's table of
/// fast paths, is warmed at the start (`px::Pixman::warm`: the three
/// combinations of operation and formats the service uses); the bounds of the
/// bands under -icount therefore hold no cold cache, and on HVF and on a board it
/// is in the measures of the hour and of the stage of the board. The lines
/// `service raster` are wall time: a 640 by 8 copy shown there at 3.64 ticks a
/// point is about 18 600 ticks, while the step of the band that holds it is at
/// most 10 528 of the thread's own time, so the greatest of those lines holds the
/// levels above that ran in the middle and the interrupts; only the lines of the
/// steps judge a band.
/// The alignment of the target and of the source changes an operation by up to
/// half (a layer laid over others 64 by 32: 9 932 to 15 532 ticks), and the
/// greatest is what the fit takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Price {
    pub kind: &'static str,
    pub call_measured: u32,
    pub call: u32,
    /// Hundredths of a tick a row.
    pub row_measured: u32,
    pub row: u32,
    pub row_estimate: bool,
    /// Hundredths of a tick a point.
    pub point_measured: u32,
    pub point: u32,
    pub point_estimate: bool,
}

/// The margin over a measure, in percent.
pub const MARGIN_PERCENT: u32 = 15;

/// The constant that covers `measured` with the margin: rounded up.
pub const fn with_margin(measured: u32) -> u32 {
    (measured * (100 + MARGIN_PERCENT)).div_ceil(100)
}

const fn price(
    kind: &'static str,
    call_measured: u32,
    row_measured: u32,
    row_estimate: bool,
    point_measured: u32,
    point_estimate: bool,
) -> Price {
    Price {
        kind,
        call_measured,
        call: with_margin(call_measured),
        row_measured,
        row: with_margin(row_measured),
        row_estimate,
        point_measured,
        point: with_margin(point_measured),
        point_estimate,
    }
}

/// The prices: black, copy, over, each the upper fit of the model over the
/// greatest ticks of 26 shapes of operations, the widths 1 to 152 and 640
/// (`compositor::fit`, `px::calibration`),
/// measured under -icount, the same in `comp-probe` and in `focus-probe`
/// (the run is deterministic). Every entry is a measure.
pub const PRICES: [Price; 3] = [
    price("black", 209, 2_400, false, 38, false),
    price("copy", 780, 5_480, false, 138, false),
    price("over", 785, 18_981, false, 427, false),
];
/// What each layer after the first costs a band beyond its operation (ticks,
/// for each window the band lays after the first layer and for the pointer's
/// picture): the work of `compose` around the call of a layer (the window's place
/// and buffer, the clip) and what pixman does when the source changes from one
/// call to the next. The probes measure a whole band of one, two, four and eight
/// layers on the same rows (`px::calibration`, the lines `service shape` of
/// the kinds `layers1` to `layers8`) and the term is the greatest excess of a
/// shape of L layers over the shape of one, for each layer added; a band of
/// eight windows on one place cost 18 460 ticks as a step where its operations
/// were 13 000 by the table.
/// The probes' greatest excess of a layer added is 172 ticks at 2 layers, 190 at
/// 4 and 226 at 8 (both probes, the same run under -icount): it grows a little
/// with the count, and the service has at most 9 layers (8 windows and the
/// pointer's picture), so the greatest, at 8, is the measure; the margin of 15 %
/// (260) is over the 235 the growth gives at 9.
pub const LAYER_MEASURED: u32 = 226;
pub const LAYER: u32 = with_margin(LAYER_MEASURED);

/// What every band costs beyond its layers (ticks, once for each band): the
/// work of `compose` around the band (its place, the clip, the choice of the
/// buffers), which depends on neither the layers nor the operation. A wide band
/// hides it inside the overstatement of the fit of its operation; a narrow one
/// does not: a band of one layer 16 points wide and one line is 1 565 ticks in
/// the probes against 1 477 by the prices and the term of a layer, 88 ticks
/// short, and 64 by 1 is 53 short (the bands of 8 by 8 and of 150 points or
/// wider are over their measure). The measure is the greatest shortfall of a
/// band of one layer under the prices over all the shapes the calibration
/// measures (`px::calibration`, the kind `layers1`), and the constant is the
/// measure with the margin. `band_size` takes it off BAND_TICKS with the calls.
pub const BAND_FIXED_MEASURED: u32 = 88;
pub const BAND_FIXED: u32 = with_margin(BAND_FIXED_MEASURED);
pub const FILL: Price = PRICES[0];
pub const OPAQUE: Price = PRICES[1];
pub const OVER: Price = PRICES[2];

/// Linux's key codes the scene knows: the Super keys (the manager's
/// modifier: Doom binds Alt, Ctrl and Shift, so a program of the first
/// revision keeps all of its keys) and Tab.
pub const KEY_TAB: u16 = 15;
pub const KEY_LEFTMETA: u16 = 125;
pub const KEY_RIGHTMETA: u16 = 126;

/// The key codes whose presses are followed (Linux's keyboard codes are
/// below 256), and what the owner of a press can be: nobody yet, a window
/// (its place plus 1), the manager, or none (the press was dropped, or its
/// release was already given: the release is dropped too).
pub const KEYS_TRACKED: usize = 256;
const OWNER_NONE: u8 = 0;
const OWNER_DROPPED: u8 = 254;
const OWNER_MANAGER: u8 = 255;

/// Whether the compositor must take the focus of an input device again:
/// the device is in the image (`present`) and the compositor does not hold
/// its focus (`holds`), as after the driver ended and started again.
pub const fn wants_focus(present: bool, holds: bool) -> bool {
    present && !holds
}

/// What OPEN of the first revision does with the pool, as a decision of the
/// pool's state alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolOpen {
    /// A copy besides the service's own is out: BUSY.
    Busy,
    /// The clearing runs or waits for the frame that takes the screen back
    /// from the pool: ask again.
    Clearing,
    /// The pool may hold pixels a program wrote after the last clearing
    /// ended (a copy was given, or the pool is new): start the clearing, and
    /// ask again.
    StartClearing,
    /// The pool is clean and the service's own: a window may have it.
    Go,
}

/// The decision of OPEN. `refs` is the object's references now and `base`
/// the count the service recorded after it mapped the pool: more means a
/// program holds a copy. `dirty` is set when a copy is given and cleared only
/// by a clearing that ended with no copy out (`dirty_after_clearing`), so a
/// program that closed its window, kept its mapping and wrote after the
/// clearing passed leaves the pool dirty until it is gone and cleared again.
pub fn pool_open(
    refs: u64,
    base: u64,
    dirty: bool,
    clearing: bool,
    release_pending: bool,
) -> PoolOpen {
    if refs > base {
        PoolOpen::Busy
    } else if clearing || release_pending {
        PoolOpen::Clearing
    } else if dirty {
        PoolOpen::StartClearing
    } else {
        PoolOpen::Go
    }
}

/// Whether the pool is still dirty when a clearing ends: it is when a copy
/// was out then (the program could write after the clearing passed a place).
pub const fn dirty_after_clearing(refs: u64, base: u64) -> bool {
    refs != base
}

/// The owner byte of window place `i`.
const fn window_owner(i: usize) -> u8 {
    i as u8 + 1
}

/// The state of a buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Buf {
    Free,
    Posted,
    Taken,
}

/// The format of a window's points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// 0x00RRGGBB, opaque.
    Xrgb,
    /// The colour premultiplied by the alpha in the top byte.
    Argb,
}

/// Why a call of the scene is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The table of windows, or the context's share, is full.
    Limit,
    /// The rectangle, the number or the size is wrong.
    Invalid,
    /// The buffer is not free, or the window has its buffers.
    Busy,
    /// The call is not for this window (a POST before ATTACH, a FLUSH of a
    /// window that has buffers of its own, or the other way round).
    NotAllowed,
}

/// One window.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    pub label: u64,
    pub ctx: u64,
    pub rect: Rect,
    pub format: Format,
    /// The window of a program that knows no windows (OPEN of proto_gpu):
    /// the whole screen, one buffer the service made.
    pub legacy: bool,
    pub seq: u32,
    pub stride: u32,
    /// The buffers attached, 0 before ATTACH.
    pub attached: u8,
    pub bufs: [Buf; BUFFERS],
    pub posted: Option<u8>,
    /// What the screen shows of the window, once something was taken.
    pub current: Option<u8>,
    /// The buffer the last take replaced: free when the frame is shown.
    pub retired: Option<u8>,
    /// Whether the frame in progress took something of this window.
    pub in_frame: bool,
    /// Whether the window is shown when it has something (the manager hides
    /// it).
    pub visible: bool,
    /// Whether a buffer was ever taken: the first take gives the focus.
    pub shown_once: bool,
    /// The window's promise of an interval and its counts (stage G5): the
    /// service sets and reads them; the scene keeps them with the window.
    pub pace: frame::Pace,
    /// The damage of a post that waits for the window's interval: the window's
    /// buffer is taken at the start it is due, and the rectangle joins the
    /// frame's damage then.
    pub held: Option<Rect>,
}

/// What the primary pipeline of the display shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Primary {
    /// The target the service puts the windows together in.
    Target,
    /// The pool, the buffer of a window of the first revision.
    Pool,
}

/// How a frame reaches the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    /// Bands into the target, which the primary pipeline shows: COMMIT.
    Compose,
    /// Bands over the whole screen into the target, then the primary
    /// pipeline is bound to the target (a LAYERS row of source 1).
    Rebind,
    /// No bands: the primary pipeline is bound to the pool (a LAYERS row of
    /// source 2 with the changed area).
    Bypass,
}

/// What `Scene::plan` decides for the next frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Put the windows together.
    Compose,
    /// Show the buffer of this window (its place) as it is.
    Bypass(usize),
}

/// What a finished frame frees of a window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ended {
    pub freed: Option<u8>,
    pub in_frame: bool,
}

/// The events of a window or of the manager that nobody has taken: the
/// last RING, and whether older ones were dropped.
#[derive(Clone, Copy)]
pub struct Ring {
    buf: [Event; RING],
    head: usize,
    len: usize,
    lost: bool,
}

impl Ring {
    pub const fn new() -> Ring {
        Ring {
            buf: [Event::new(0, 0, 0); RING],
            head: 0,
            len: 0,
            lost: false,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
        self.lost = false;
    }

    /// Adds an event; the oldest goes when the ring is full.
    pub fn push(&mut self, e: Event) {
        if self.len == RING {
            self.head = (self.head + 1) % RING;
            self.len -= 1;
            self.lost = true;
        }
        self.buf[(self.head + self.len) % RING] = e;
        self.len += 1;
    }

    /// Up to `out.len()` events, oldest first, and whether events were
    /// dropped since the last take (which clears the mark).
    pub fn take(&mut self, out: &mut [Event]) -> (usize, bool) {
        let n = out.len().min(self.len);
        for (k, slot) in out.iter_mut().enumerate().take(n) {
            *slot = self.buf[(self.head + k) % RING];
        }
        self.head = (self.head + n) % RING;
        self.len -= n;
        (n, core::mem::take(&mut self.lost))
    }
}

impl Default for Ring {
    fn default() -> Ring {
        Ring::new()
    }
}

/// The rings that got events since `Scene::delivered` was last asked: the
/// windows by place (bit `i`) and the manager.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Delivered {
    pub windows: u8,
    pub manager: bool,
}

/// The windows, the damage to be shown, the frame's state, the focus and
/// the pointer.
pub struct Scene {
    windows: [Option<Window>; MAX_WINDOWS],
    rings: [Ring; MAX_WINDOWS],
    manager_ring: Ring,
    manager: bool,
    delivered: Delivered,
    focus: Option<usize>,
    /// The pointer's place, once the pointer was seen, and the window a
    /// pressed button holds.
    pointer: Option<(i32, i32)>,
    /// The device's cursor pipeline, when the driver has one: the pointer's
    /// picture is then the device's, and the frame never draws it.
    cursor: Option<CursorPlane>,
    held: Option<usize>,
    /// Whether the display can show the pool directly (the driver has a
    /// primary pipeline that takes the screen's whole size and gave the
    /// service the pool source), what the primary pipeline shows now, and
    /// whether the target lacks what the pool showed since it was last
    /// whole.
    direct: bool,
    primary: Primary,
    stale: bool,
    /// How the frame in progress (or the last one) reaches the screen, and
    /// whether it covers the whole screen.
    kind: FrameKind,
    whole: bool,
    /// The legacy window went and the pool waits to be cleared.
    release: bool,
    bypassed: u32,
    bands: u32,
    /// The Super keys held, one bit each (left, right).
    modifier: u8,
    /// Who got the press of each key below KEYS_TRACKED: its release goes
    /// to the same (OWNER_NONE: no press seen).
    owner: [u8; KEYS_TRACKED],
    damage: Option<Rect>,
    /// The earliest start a window left by the last taking is due at (the
    /// caller says `hold` with it to the pacer).
    held_until: Option<u64>,
    frame: bool,
    seq: u32,
    created: u32,
    frames: u32,
}

impl Default for Scene {
    fn default() -> Scene {
        Scene::new()
    }
}

/// The whole screen.
pub const SCREEN: Rect = Rect {
    x: 0,
    y: 0,
    w: WIDTH,
    h: HEIGHT,
};

pub use proto_comp::cursor::{CURSOR, CURSOR_H, CURSOR_W};

/// What the device's cursor pipeline shows now, as the last LAYERS row the
/// driver accepted said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shown {
    Hidden,
    At(i32, i32),
}

/// The pointer on the device's cursor pipeline (proto_gpu revision 3): the
/// pipeline's id, the source that holds the picture, and what the device
/// shows of it. The arrow's hot spot is its top left point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CursorPlane {
    pipeline: u32,
    source: u32,
    shown: Shown,
}

/// The hot spot of the pointer's picture: the point that lies at the
/// pointer's place.
pub const CURSOR_HOT: (u32, u32) = (0, 0);

/// The pointer's picture on a 4-byte boundary, as pixman wants its memory.
#[repr(align(4))]
struct Aligned([u8; CURSOR.len()]);
static PICTURE: Aligned = Aligned(CURSOR);

/// The pointer's picture (ARGB8888, CURSOR_W by CURSOR_H points), the bytes
/// a band lays over a screen the pointer touches.
pub fn pointer_picture() -> &'static [u8] {
    &PICTURE.0
}

impl Scene {
    pub const fn new() -> Scene {
        Scene {
            windows: [None; MAX_WINDOWS],
            rings: [Ring::new(); MAX_WINDOWS],
            manager_ring: Ring::new(),
            manager: false,
            delivered: Delivered {
                windows: 0,
                manager: false,
            },
            focus: None,
            pointer: None,
            cursor: None,
            held: None,
            direct: false,
            primary: Primary::Target,
            stale: false,
            kind: FrameKind::Compose,
            whole: false,
            release: false,
            bypassed: 0,
            bands: 0,
            modifier: 0,
            owner: [OWNER_NONE; KEYS_TRACKED],
            damage: None,
            held_until: None,
            frame: false,
            seq: 0,
            created: 0,
            frames: 0,
        }
    }

    pub fn window(&self, i: usize) -> Option<&Window> {
        self.windows.get(i).and_then(Option::as_ref)
    }

    /// The place of the window with `label`.
    pub fn find(&self, label: u64) -> Option<usize> {
        self.windows
            .iter()
            .position(|w| w.is_some_and(|w| w.label == label))
    }

    /// The windows alive, those ever made and the frames shown.
    pub fn open(&self) -> u32 {
        self.windows.iter().flatten().count() as u32
    }

    pub fn created(&self) -> u32 {
        self.created
    }

    pub fn frames(&self) -> u32 {
        self.frames
    }

    /// The frames shown without a band (the pool was the screen) and the
    /// bands put together since the start.
    pub fn bypassed(&self) -> u32 {
        self.bypassed
    }

    pub fn bands(&self) -> u32 {
        self.bands
    }

    /// A band of a frame was put together.
    pub fn band_done(&mut self) {
        self.bands = self.bands.wrapping_add(1);
    }

    /// The display can show the pool directly (or no more, with false: a
    /// refusal of the driver is final).
    pub fn set_direct(&mut self, on: bool) {
        self.direct = on;
    }

    pub fn direct(&self) -> bool {
        self.direct
    }

    /// What the primary pipeline shows, once the last frame shown ended.
    pub fn primary(&self) -> Primary {
        self.primary
    }

    /// Whether the target lacks what the pool showed.
    pub fn stale(&self) -> bool {
        self.stale
    }

    /// How the frame in progress, or the last one, reaches the screen.
    pub fn frame_kind(&self) -> FrameKind {
        self.kind
    }

    /// Whether the pool may be cleared: the primary pipeline does not show
    /// it and no frame that binds it is on its way to the device.
    pub fn pool_idle(&self) -> bool {
        self.primary == Primary::Target && !(self.frame && self.kind == FrameKind::Bypass)
    }

    /// Whether a window of the first revision has gone and the pool still
    /// waits to be cleared (a new window must not take it yet).
    pub fn pool_release_pending(&self) -> bool {
        self.release
    }

    /// True once, when the window of the first revision has gone and the
    /// pool is idle: the pool's clearing starts then, and never while the
    /// screen shows it.
    pub fn take_pool_clear(&mut self) -> bool {
        if self.release && self.pool_idle() {
            self.release = false;
            return true;
        }
        false
    }

    /// Whether a frame is in progress or a change waits for one: damage of the
    /// scene, or a buffer a window holds for the start of its interval.
    pub fn busy(&self) -> bool {
        self.frame
            || self.damage.is_some()
            || self.windows.iter().flatten().any(|w| w.held.is_some())
    }

    pub fn framing(&self) -> bool {
        self.frame
    }

    /// Whether a legacy window lives.
    pub fn has_legacy(&self) -> bool {
        self.windows.iter().flatten().any(|w| w.legacy)
    }

    /// The window with the focus.
    pub fn focus(&self) -> Option<usize> {
        self.focus
    }

    /// The place of the pointer's picture in the frame: the pointer's, when
    /// it was seen and the device's cursor pipeline does not show it.
    fn drawn_pointer(&self) -> Option<(i32, i32)> {
        self.pointer.filter(|_| self.cursor.is_none())
    }

    /// The pointer's place, once it was seen.
    pub fn pointer(&self) -> Option<(i32, i32)> {
        self.pointer
    }

    /// The pointer goes onto the device's cursor pipeline `pipeline`, its
    /// picture in `source` (or back into the frame, with None): from now
    /// on a move of the pointer damages nothing and the frame draws no
    /// picture. The picture the frame drew before is painted over.
    pub fn set_cursor_plane(&mut self, plane: Option<(u32, u32)>) {
        let was = self.cursor.is_some();
        self.cursor = plane.map(|(pipeline, source)| CursorPlane {
            pipeline,
            source,
            shown: Shown::Hidden,
        });
        if was != self.cursor.is_some()
            && let Some(p) = self.pointer
        {
            self.add_damage(Scene::cursor_rect(p));
        }
    }

    /// Whether the pointer is on the device's cursor pipeline (DESCRIBE's
    /// CURSOR_PLANE).
    pub fn cursor_plane(&self) -> bool {
        self.cursor.is_some()
    }

    /// The row of LAYERS that brings the device's cursor to the pointer, or
    /// None when it shows the pointer already, or there is no cursor
    /// pipeline. The pointer unseen is a hidden cursor (source 0), the
    /// pointer seen is the picture at its place; a move is the same row with
    /// a new place, which the driver takes for a move of the cursor. At most
    /// one row for any number of moves: the caller asks once a step of input.
    /// `cursor_shown` tells the driver took the row.
    pub fn cursor_row(&self) -> Option<LayerRow> {
        let plane = self.cursor?;
        let wanted = match self.pointer {
            Some((x, y)) => Shown::At(x, y),
            None => Shown::Hidden,
        };
        if wanted == plane.shown {
            return None;
        }
        Some(match wanted {
            Shown::Hidden => LayerRow::off(plane.pipeline),
            Shown::At(x, y) => LayerRow::cursor(plane.pipeline, plane.source, x, y, CURSOR_HOT),
        })
    }

    /// The driver refused a row of the cursor pipeline, for good: the
    /// pointer goes back into the frame (`set_cursor_plane(None)`, which
    /// damages the arrow's rectangle), and no row is made again. When the
    /// device may be showing the cursor the row that hides it is returned,
    /// for the caller to send and not to wait for, so that the pointer is
    /// never in the frame and on the device both. None when the device was
    /// never shown the cursor.
    pub fn cursor_refused(&mut self) -> Option<LayerRow> {
        let plane = self.cursor?;
        self.set_cursor_plane(None);
        (plane.shown != Shown::Hidden).then(|| LayerRow::off(plane.pipeline))
    }

    /// The driver took `row` (made by `cursor_row`).
    pub fn cursor_shown(&mut self, row: &LayerRow) {
        if let Some(plane) = &mut self.cursor {
            plane.shown = if row.source == 0 {
                Shown::Hidden
            } else {
                Shown::At(row.x, row.y)
            };
        }
    }

    /// Whether a window of the table is shown: it has something taken and
    /// is not hidden.
    fn shown(w: &Window) -> bool {
        w.visible && w.current.is_some()
    }

    /// A window of context `ctx` at `rect`: its place, which is none of the
    /// places the bits of `taken` name (a place whose mappings are still
    /// going). Limit when the table or the context's share is full, Invalid
    /// for a rectangle outside the screen.
    pub fn create(
        &mut self,
        label: u64,
        ctx: u64,
        rect: Rect,
        legacy: bool,
        taken: u8,
    ) -> Result<usize, Refusal> {
        if !rect.within(WIDTH, HEIGHT) {
            return Err(Refusal::Invalid);
        }
        let mine = self
            .windows
            .iter()
            .flatten()
            .filter(|w| w.ctx == ctx)
            .count();
        if mine >= PER_CONTEXT {
            return Err(Refusal::Limit);
        }
        let place = self
            .windows
            .iter()
            .enumerate()
            .position(|(i, w)| w.is_none() && taken & (1 << i) == 0)
            .ok_or(Refusal::Limit)?;
        self.seq = self.seq.wrapping_add(1);
        self.created += 1;
        self.windows[place] = Some(Window {
            label,
            ctx,
            rect,
            format: Format::Xrgb,
            legacy,
            seq: self.seq,
            stride: if legacy { STRIDE } else { 0 },
            attached: u8::from(legacy),
            bufs: [Buf::Free; BUFFERS],
            posted: None,
            current: None,
            retired: None,
            pace: frame::Pace::new(),
            held: None,
            in_frame: false,
            visible: true,
            shown_once: false,
        });
        self.rings[place].clear();
        self.tell_manager(Event::new(CREATE, place as u16, 0));
        Ok(place)
    }

    /// The format of window `i`, before its buffers are attached.
    pub fn set_format(&mut self, i: usize, format: Format) {
        if let Some(Some(w)) = self.windows.get_mut(i) {
            w.format = format;
        }
    }

    /// The buffers of window `i`: `count` of them with `stride`, which
    /// must hold the window's lines. Once.
    pub fn attach(&mut self, i: usize, count: u8, stride: u32) -> Result<(), Refusal> {
        let w = self
            .windows
            .get_mut(i)
            .and_then(Option::as_mut)
            .ok_or(Refusal::Invalid)?;
        if w.attached != 0 {
            return Err(Refusal::Busy);
        }
        if count == 0 || count as usize > BUFFERS || u64::from(stride) < u64::from(w.rect.w) * 4 {
            return Err(Refusal::Invalid);
        }
        w.attached = count;
        w.stride = stride;
        Ok(())
    }

    /// The window's places that `rects` change, on the screen; the whole
    /// window for none. Invalid for a rectangle outside the window.
    fn changed(rect: Rect, rects: &[Rect]) -> Result<Rect, Refusal> {
        if rects.is_empty() {
            return Ok(rect);
        }
        let mut sum = None;
        for r in rects {
            if !r.within(rect.w, rect.h) {
                return Err(Refusal::Invalid);
            }
            sum = Some(union(
                sum,
                Rect {
                    x: rect.x + r.x,
                    y: rect.y + r.y,
                    w: r.w,
                    h: r.h,
                },
            ));
        }
        Ok(sum.unwrap_or(rect))
    }

    fn add_damage(&mut self, r: Rect) {
        self.damage = Some(union(self.damage, r));
    }

    /// POST of buffer `buffer` of window `i` with the changed `rects`: the
    /// buffer a posted one it replaced ("the latest wins"), which is free
    /// at once.
    pub fn post(&mut self, i: usize, buffer: u8, rects: &[Rect]) -> Result<Option<u8>, Refusal> {
        self.post_inner(i, buffer, rects, None)
            .map(|(replaced, _)| replaced)
    }

    /// POST at `now` on the clock of the frame: the window's promise of an
    /// interval is judged (`frame::Pace::posted`), and a buffer that is due
    /// at a start later than the nearest waits with its damage in the window.
    /// The replaced buffer, and the start the buffer is due at (None: any).
    pub fn post_paced(
        &mut self,
        i: usize,
        buffer: u8,
        rects: &[Rect],
        clock: &frame::Clock,
        now: u64,
    ) -> Result<(Option<u8>, Option<u64>), Refusal> {
        self.post_inner(i, buffer, rects, Some((clock, now)))
    }

    fn post_inner(
        &mut self,
        i: usize,
        buffer: u8,
        rects: &[Rect],
        paced: Option<(&frame::Clock, u64)>,
    ) -> Result<(Option<u8>, Option<u64>), Refusal> {
        if rects.len() > MAX_RECTS {
            return Err(Refusal::Invalid);
        }
        let w = self
            .windows
            .get_mut(i)
            .and_then(Option::as_mut)
            .ok_or(Refusal::Invalid)?;
        if w.legacy || w.attached == 0 {
            return Err(Refusal::NotAllowed);
        }
        if buffer >= w.attached {
            return Err(Refusal::Invalid);
        }
        if w.bufs[buffer as usize] != Buf::Free {
            return Err(Refusal::Busy);
        }
        let mut damage = Scene::changed(w.rect, rects)?;
        w.bufs[buffer as usize] = Buf::Posted;
        let replaced = w.posted.replace(buffer);
        if let Some(j) = replaced {
            w.bufs[j as usize] = Buf::Free;
        }
        let mut due = None;
        match paced {
            Some((clock, now)) => {
                due = w.pace.posted(clock, now, replaced.is_some());
                if due.is_some_and(|e| e > clock.next(now)) {
                    // Not at the nearest start: the damage waits in the window.
                    w.held = Some(union(w.held, damage));
                    return Ok((replaced, due));
                }
            }
            None => w.pace.count_post(replaced.is_some()),
        }
        if let Some(h) = w.held.take() {
            damage = union(Some(damage), h);
        }
        self.add_damage(damage);
        Ok((replaced, due))
    }

    /// Whether a change waits for a frame: damage the next frame will take.
    pub fn damaged(&self) -> bool {
        self.damage.is_some()
    }

    /// The start the windows a taking left are due at, the earliest.
    pub fn held_until(&self) -> Option<u64> {
        self.held_until
    }

    /// The pace of window `i`.
    pub fn pace(&self, i: usize) -> Option<&frame::Pace> {
        self.windows.get(i)?.as_ref().map(|w| &w.pace)
    }

    pub fn pace_mut(&mut self, i: usize) -> Option<&mut frame::Pace> {
        self.windows.get_mut(i)?.as_mut().map(|w| &mut w.pace)
    }

    /// FLUSH of the legacy window `i`: its one buffer, whose changed
    /// rectangle is `rect` in window coordinates.
    pub fn flush(&mut self, i: usize, rect: Rect) -> Result<(), Refusal> {
        let w = self
            .windows
            .get_mut(i)
            .and_then(Option::as_mut)
            .ok_or(Refusal::Invalid)?;
        if !w.legacy {
            return Err(Refusal::NotAllowed);
        }
        let damage = Scene::changed(w.rect, &[rect])?;
        w.posted = Some(0);
        self.add_damage(damage);
        Ok(())
    }

    /// The window `i` goes: its place on the screen is to be shown again,
    /// the focus it had passes to the window on top, and the manager is
    /// told.
    pub fn destroy(&mut self, i: usize) -> Option<Window> {
        let w = self.windows.get_mut(i)?.take()?;
        if w.legacy {
            self.release = true;
        }
        // A window of the first revision always has its line to say.
        if w.legacy || w.current.is_some() || w.posted.is_some() {
            self.add_damage(w.rect);
        }
        self.rings[i].clear();
        // The releases of what the window held are nobody's.
        for o in &mut self.owner {
            if *o == window_owner(i) {
                *o = OWNER_DROPPED;
            }
        }
        if self.held == Some(i) {
            self.held = None;
        }
        self.tell_manager(Event::new(CLOSE, i as u16, 0));
        if self.focus == Some(i) {
            self.focus = None;
            if let Some(top) = self.top(None) {
                self.set_focus(top);
            }
        }
        Some(w)
    }

    /// The topmost shown window, except `except`.
    fn top(&self, except: Option<usize>) -> Option<usize> {
        let mut best: Option<(u32, usize)> = None;
        for (i, w) in self.windows.iter().enumerate() {
            let Some(w) = w else {
                continue;
            };
            if Some(i) == except || !Scene::shown(w) {
                continue;
            }
            if best.is_none_or(|(seq, _)| w.seq > seq) {
                best = Some((w.seq, i));
            }
        }
        best.map(|(_, i)| i)
    }

    // ------------------------------------------------------------ the events

    fn tell(&mut self, i: usize, e: Event) {
        self.rings[i].push(e);
        self.delivered.windows |= 1 << i;
    }

    fn tell_manager(&mut self, e: Event) {
        if self.manager {
            self.manager_ring.push(e);
            self.delivered.manager = true;
        }
    }

    /// The rings that got events since the last call.
    pub fn delivered(&mut self) -> Delivered {
        core::mem::take(&mut self.delivered)
    }

    /// The manager has subscribed: the Super keys and the keys pressed with
    /// Super held are its alone from now on, and it is told of the windows
    /// to come.
    pub fn set_manager(&mut self, on: bool) {
        self.manager = on;
        if !on {
            self.manager_ring.clear();
            self.modifier = 0;
        }
    }

    pub fn has_manager(&self) -> bool {
        self.manager
    }

    /// EVENTS of window `i`: up to `out.len()` events, and whether some
    /// were dropped.
    pub fn take_events(&mut self, i: usize, out: &mut [Event]) -> (usize, bool) {
        self.rings.get_mut(i).map_or((0, false), |r| r.take(out))
    }

    /// The keys of window `i`'s ring, for the session of focus of a window of
    /// the first revision: up to `out.len()` KEY events (the other kinds in
    /// the ring are dropped), and whether events were dropped.
    pub fn take_keys(&mut self, i: usize, out: &mut [Event]) -> (usize, bool) {
        let Some(ring) = self.rings.get_mut(i) else {
            return (0, false);
        };
        let mut lost = false;
        let mut n = 0;
        let mut one = [Event::default(); 1];
        while n < out.len() {
            let (got, l) = ring.take(&mut one);
            lost |= l;
            if got == 0 {
                break;
            }
            if one[0].kind == KEY {
                out[n] = one[0];
                n += 1;
            }
        }
        (n, lost)
    }

    /// EVENTS of the manager.
    pub fn take_manager_events(&mut self, out: &mut [Event]) -> (usize, bool) {
        self.manager_ring.take(out)
    }

    /// Window `i` has the focus: FOCUS_OUT to the window that had it,
    /// FOCUS_IN to `i`.
    fn set_focus(&mut self, i: usize) {
        if self.focus == Some(i) {
            return;
        }
        if let Some(old) = self.focus.replace(i) {
            // A window of the first revision sees no FOCUS_OUT: the keys it
            // still holds are released in its ring before the focus goes,
            // and their real releases are dropped.
            if self.window(old).is_some_and(|w| w.legacy) {
                for code in 0..KEYS_TRACKED {
                    if self.owner[code] == window_owner(old) {
                        self.owner[code] = OWNER_DROPPED;
                        self.tell(old, Event::new(KEY, code as u16, 0));
                    }
                }
            }
            self.tell(old, Event::new(FOCUS_OUT, 0, 0));
        }
        self.tell(i, Event::new(FOCUS_IN, 0, 0));
    }

    /// A key of the device or of INJECT. With a manager the Super keys and
    /// the keys under Super go to it; any other key goes to the window with
    /// the focus (a window of the first revision too: its ring holds the
    /// keys its session of focus reads), and is dropped when there is none.
    /// A release goes where its press went, whoever has the focus or holds
    /// Super by then.
    pub fn key(&mut self, code: u16, pressed: bool) {
        let bit = match code {
            KEY_LEFTMETA => 1,
            KEY_RIGHTMETA => 2,
            _ => 0,
        };
        if pressed {
            self.modifier |= bit;
        } else {
            self.modifier &= !bit;
        }
        let event = Event::new(KEY, code, i32::from(pressed));
        let routed = if self.manager && (bit != 0 || self.modifier != 0) {
            OWNER_MANAGER
        } else {
            self.focus.map_or(OWNER_DROPPED, window_owner)
        };
        let target = match self.owner.get_mut(usize::from(code)) {
            Some(owner) if pressed => {
                *owner = routed;
                routed
            }
            Some(owner) => match core::mem::replace(owner, OWNER_NONE) {
                OWNER_NONE => routed,
                known => known,
            },
            None => routed,
        };
        match target {
            OWNER_DROPPED => {}
            OWNER_MANAGER => self.tell_manager(event),
            w => {
                let i = usize::from(w) - 1;
                if self.window(i).is_some() {
                    self.tell(i, event);
                }
            }
        }
    }

    /// The topmost shown window that covers the point.
    pub fn hit(&self, x: i32, y: i32) -> Option<usize> {
        let mut best: Option<(u32, usize)> = None;
        for (i, w) in self.windows.iter().enumerate() {
            let Some(w) = w else {
                continue;
            };
            let r = w.rect;
            let inside = x >= r.x as i32
                && y >= r.y as i32
                && x < (r.x + r.w) as i32
                && y < (r.y + r.h) as i32;
            if inside && Scene::shown(w) && best.is_none_or(|(seq, _)| w.seq > seq) {
                best = Some((w.seq, i));
            }
        }
        best.map(|(_, i)| i)
    }

    /// The rectangle of the pointer's picture at `at`, on the screen.
    fn cursor_rect(at: (i32, i32)) -> Rect {
        let x = at.0.clamp(0, WIDTH as i32 - 1) as u32;
        let y = at.1.clamp(0, HEIGHT as i32 - 1) as u32;
        Rect {
            x,
            y,
            w: CURSOR_W.min(WIDTH - x),
            h: CURSOR_H.min(HEIGHT - y),
        }
    }

    /// The pointer moved to (`x`, `y`) of the screen: the picture is drawn
    /// there, and the window a held button names or the one under the
    /// pointer gets a MOVE with its own coordinates.
    pub fn pointer_to(&mut self, x: i32, y: i32) {
        let at = (x.clamp(0, WIDTH as i32 - 1), y.clamp(0, HEIGHT as i32 - 1));
        if self.pointer == Some(at) {
            return;
        }
        let before = self.pointer.replace(at);
        // On the device's cursor pipeline the move is the device's: the
        // frame holds no picture, so nothing is damaged.
        if self.cursor.is_none() {
            let mut damage = Scene::cursor_rect(at);
            if let Some(old) = before {
                damage = union(Some(damage), Scene::cursor_rect(old));
            }
            self.add_damage(damage);
        }
        // A window of the first revision takes no pointer: its ring holds the
        // keys, which a stream of moves would push out.
        if let Some(i) = self.held.or_else(|| self.hit(at.0, at.1))
            && let Some(w) = self.window(i)
            && !w.legacy
        {
            let e = Event::at(MOVE, 0, 0, at.0 - w.rect.x as i32, at.1 - w.rect.y as i32);
            self.tell(i, e);
        }
    }

    /// A button of the pointer. Pressed: the window under the pointer gets
    /// the focus and the top place and holds the button until it is
    /// released. Either way that window gets a BUTTON with its own
    /// coordinates.
    pub fn button(&mut self, code: u16, pressed: bool) {
        let Some(at) = self.pointer else {
            return;
        };
        let target = if pressed {
            let hit = self.hit(at.0, at.1);
            if let Some(i) = hit {
                self.set_focus(i);
                let _ = self.raise(i);
                self.held = Some(i);
            }
            hit
        } else {
            self.held.take().or_else(|| self.hit(at.0, at.1))
        };
        if let Some(i) = target
            && let Some(w) = self.window(i)
            && !w.legacy
        {
            let e = Event::at(
                BUTTON,
                code,
                i32::from(pressed),
                at.0 - w.rect.x as i32,
                at.1 - w.rect.y as i32,
            );
            self.tell(i, e);
        }
    }

    /// An event of INJECT, as the device would have made it: a key, the
    /// pointer's place on the screen, or a button.
    pub fn inject(&mut self, e: Event) {
        match e.kind {
            KEY => self.key(e.code, e.value != 0),
            MOVE => self.pointer_to(e.x, e.y),
            BUTTON => self.button(e.code, e.value != 0),
            _ => {}
        }
    }

    // ------------------------------------------------------------ the manager

    /// Window `i` goes to the top. Invalid for a window that is none.
    pub fn raise(&mut self, i: usize) -> Result<(), Refusal> {
        let rect = self.window(i).ok_or(Refusal::Invalid)?.rect;
        let top = self.windows.iter().flatten().map(|w| w.seq).max();
        if top == self.window(i).map(|w| w.seq) {
            return Ok(());
        }
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        if let Some(Some(w)) = self.windows.get_mut(i) {
            w.seq = seq;
            if Scene::shown(w) {
                self.add_damage(rect);
            }
        }
        Ok(())
    }

    /// Window `i` has the focus and the top place.
    pub fn focus_on(&mut self, i: usize) -> Result<(), Refusal> {
        if self.window(i).is_none() {
            return Err(Refusal::Invalid);
        }
        self.set_focus(i);
        self.raise(i)
    }

    /// Window `i` moves to (`x`, `y`): all of it stays on the screen. A
    /// window of the first revision does not move.
    pub fn move_to(&mut self, i: usize, x: u32, y: u32) -> Result<(), Refusal> {
        let w = self.window(i).ok_or(Refusal::Invalid)?;
        if w.legacy {
            return Err(Refusal::NotAllowed);
        }
        let to = Rect { x, y, ..w.rect };
        if !to.within(WIDTH, HEIGHT) {
            return Err(Refusal::Invalid);
        }
        let was = w.rect;
        let shown = Scene::shown(w);
        if let Some(Some(w)) = self.windows.get_mut(i) {
            w.rect = to;
        }
        if shown {
            self.add_damage(union(Some(was), to));
        }
        Ok(())
    }

    /// Window `i` is shown or hidden. A hidden window has no focus: it
    /// passes to the window on top.
    pub fn set_visible(&mut self, i: usize, visible: bool) -> Result<(), Refusal> {
        let w = self.window(i).ok_or(Refusal::Invalid)?;
        if w.visible == visible {
            return Ok(());
        }
        let rect = w.rect;
        let had = w.current.is_some();
        if let Some(Some(w)) = self.windows.get_mut(i) {
            w.visible = visible;
        }
        if had {
            self.add_damage(rect);
        }
        if !visible && self.held == Some(i) {
            self.held = None;
        }
        if !visible
            && self.focus == Some(i)
            && let Some(top) = self.top(Some(i))
        {
            self.set_focus(top);
        }
        Ok(())
    }

    /// The windows in the order of depth, lowest first: the place, and the
    /// window.
    pub fn by_depth(&self) -> ([u8; MAX_WINDOWS], usize) {
        let mut at = [0u8; MAX_WINDOWS];
        let mut n = 0;
        for (i, w) in self.windows.iter().enumerate() {
            if w.is_some() {
                // Insertion by `seq`: the oldest first.
                let seq = |k: u8| self.windows[k as usize].map_or(0, |w| w.seq);
                let mut p = n;
                while p > 0 && seq(at[p - 1]) > seq(i as u8) {
                    at[p] = at[p - 1];
                    p -= 1;
                }
                at[p] = i as u8;
                n += 1;
            }
        }
        (at, n)
    }

    // ------------------------------------------------------------ the frame

    /// Starts a frame when none is in progress and damage waits: the
    /// damage, clipped to the screen. Each window's posted buffer is taken,
    /// and, when no manager has subscribed, a window that has its first
    /// buffer taken gets the focus and the top place.
    pub fn begin(&mut self) -> Option<Rect> {
        self.begin_at(u64::MAX)
    }

    /// `begin` for the frame of period `k`: a window with an interval whose
    /// buffer is due at a later start is left posted (its damage waits in the
    /// window, and `held_until` says the start it is due), and the others are
    /// taken, each counted taken at `k`.
    pub fn begin_at(&mut self, k: u64) -> Option<Rect> {
        if self.frame {
            return None;
        }
        // The start the windows this taking leaves are due at, whether or not
        // anything else is taken: with nothing to take the caller says `hold`.
        self.held_until = self
            .windows
            .iter()
            .flatten()
            .filter(|w| w.posted.is_some() && !w.pace.due(k))
            .filter_map(|w| w.pace.earliest())
            .min();
        for w in self.windows.iter_mut().flatten() {
            if w.pace.due(k)
                && let Some(h) = w.held.take()
            {
                self.damage = Some(union(self.damage, h));
            }
        }
        let d = self.damage.take()?;
        let x1 = (d.x + d.w).min(WIDTH);
        let y1 = (d.y + d.h).min(HEIGHT);
        if d.x >= x1 || d.y >= y1 {
            return None;
        }
        let mut first = 0u8;
        for (i, w) in self.windows.iter_mut().enumerate() {
            let Some(w) = w else {
                continue;
            };
            if w.posted.is_some() && !w.pace.due(k) {
                // Not its start: the buffer stays posted, and the frame is
                // owed it at its start (`held_until`).
                continue;
            }
            let Some(b) = w.posted.take() else {
                continue;
            };
            if w.legacy {
                w.current = Some(0);
            } else {
                w.retired = w.current.replace(b);
                w.bufs[b as usize] = Buf::Taken;
                if k == u64::MAX {
                    w.pace.count_taken();
                } else {
                    w.pace.took(k);
                }
            }
            w.in_frame = true;
            if !core::mem::replace(&mut w.shown_once, true) {
                first |= 1 << i;
            }
        }
        // With a manager the window's making was told to it (CREATE), and it
        // decides who has the focus; without one the window that is shown
        // first takes it.
        if !self.manager {
            for i in 0..MAX_WINDOWS {
                if first & (1 << i) != 0 {
                    self.set_focus(i);
                    let _ = self.raise(i);
                }
            }
        }
        let mut area = Rect {
            x: d.x,
            y: d.y,
            w: x1 - d.x,
            h: y1 - d.y,
        };
        self.kind = match self.plan() {
            Plan::Bypass(_) => {
                // The target is not kept while the pool is shown.
                self.stale = true;
                FrameKind::Bypass
            }
            Plan::Compose if self.primary == Primary::Pool => {
                area = SCREEN;
                FrameKind::Rebind
            }
            Plan::Compose => {
                if self.stale {
                    area = SCREEN;
                }
                FrameKind::Compose
            }
        };
        self.whole = area == SCREEN;
        self.frame = true;
        Some(area)
    }

    /// What the next frame does: the rule of the direct scan-out. A frame
    /// is shown from the pool, with no band, when all of these hold:
    ///
    /// 1. the display can show the pool (`set_direct`);
    /// 2. the topmost shown window is of the first revision (its buffer is
    ///    the pool), opaque, and covers the whole screen, which also means
    ///    that no window under it is seen;
    /// 3. no shown window is above it (a window that is hidden or has
    ///    nothing taken is not shown);
    /// 4. the pointer is not in the frame: it is on the cursor pipeline or
    ///    not seen yet (a pointer drawn in the frame would lie in the
    ///    window).
    ///
    /// The decision reads the scene alone, so a probe on the host can
    /// tabulate it.
    pub fn plan(&self) -> Plan {
        if !self.direct || (self.pointer.is_some() && self.cursor.is_none()) {
            return Plan::Compose;
        }
        let Some(top) = self.top(None) else {
            return Plan::Compose;
        };
        match self.windows[top] {
            Some(w) if w.legacy && w.format == Format::Xrgb && w.rect == SCREEN => {
                Plan::Bypass(top)
            }
            _ => Plan::Compose,
        }
    }

    /// The frame is shown (or failed): what it frees of each window.
    pub fn end(&mut self, shown: bool) -> [Ended; MAX_WINDOWS] {
        let mut out = [Ended::default(); MAX_WINDOWS];
        for (w, e) in self.windows.iter_mut().zip(out.iter_mut()) {
            let Some(w) = w else {
                continue;
            };
            e.in_frame = core::mem::take(&mut w.in_frame);
            if let Some(r) = w.retired.take() {
                w.bufs[r as usize] = Buf::Free;
                e.freed = Some(r);
            }
        }
        self.frame = false;
        if shown {
            self.frames += 1;
            match self.kind {
                FrameKind::Bypass => {
                    self.primary = Primary::Pool;
                    self.bypassed = self.bypassed.wrapping_add(1);
                }
                FrameKind::Rebind => {
                    self.primary = Primary::Target;
                    self.stale = false;
                }
                FrameKind::Compose => {
                    if self.whole {
                        self.stale = false;
                    }
                }
            }
        }
        out
    }

    /// The windows with something to show, bottom first.
    fn order(&self) -> ([u8; MAX_WINDOWS], usize) {
        let (all, n) = self.by_depth();
        let mut at = [0u8; MAX_WINDOWS];
        let mut m = 0;
        for &k in &all[..n] {
            if self.windows[k as usize].is_some_and(|w| Scene::shown(&w)) {
                at[m] = k;
                m += 1;
            }
        }
        (at, m)
    }

    /// The size of the next band of a frame over `damage`, as columns and
    /// lines. A band costs, for every layer it makes (each shown window that
    /// touches the damage, the pointer's picture when it does, and the black
    /// the band starts with when no window covers the damage), a call, a price
    /// for each of its lines and a price for each of its points (`PRICES`), and
    /// holds as many lines of the damage's width as BAND_TICKS leaves after the
    /// calls (at most BAND_ROWS), or a part of one line, at least one point. The
    /// estimate counts every window that touches the damage, the ones under a
    /// covering window too, so it never falls short.
    fn tile(&self, damage: Rect) -> (u32, u32) {
        let touches = |r: Rect| {
            r.x < damage.x + damage.w
                && damage.x < r.x + r.w
                && r.y < damage.y + damage.h
                && damage.y < r.y + r.h
        };
        let (mut opaque, mut over) = (0u32, 0u32);
        for w in self.windows.iter().flatten() {
            if Scene::shown(w) && touches(w.rect) {
                if w.format == Format::Argb {
                    over += 1;
                } else {
                    opaque += 1;
                }
            }
        }
        over += u32::from(
            self.drawn_pointer()
                .is_some_and(|p| touches(Scene::cursor_rect(p))),
        );
        let covered = self.windows.iter().flatten().any(|w| {
            Scene::shown(w)
                && w.format == Format::Xrgb
                && w.rect.x <= damage.x
                && w.rect.y <= damage.y
                && w.rect.x + w.rect.w >= damage.x + damage.w
                && w.rect.y + w.rect.h >= damage.y + damage.h
        });
        let fill = u32::from(!covered);
        // What the layers cost: the calls, a price for each line of each, a
        // price for each point of each (hundredths of a tick where it is a
        // line or a point).
        let calls = OPAQUE.call * opaque
            + OVER.call * over
            + FILL.call * fill
            + LAYER * (opaque + over).saturating_sub(1);
        let per_row = OPAQUE.row * opaque + OVER.row * over + FILL.row * fill;
        let per_point = OPAQUE.point * opaque + OVER.point * over + FILL.point * fill;
        band_size(calls, per_row, per_point, damage.w)
    }
}

/// The size of a band of a damage `damage_w` wide: the layers cost `calls` ticks
/// in all, `per_row` hundredths of a tick for each line and `per_point`
/// hundredths for each point. The lines of the damage's width that BAND_TICKS
/// leaves after the calls (at most BAND_ROWS), or one line's part, at least one
/// point. Nothing to price (no row and no point) is a band of BAND_ROWS lines.
pub fn band_size(calls: u32, per_row: u32, per_point: u32, damage_w: u32) -> (u32, u32) {
    if per_row + per_point == 0 {
        return (damage_w, BAND_ROWS);
    }
    let budget = u64::from(BAND_TICKS.saturating_sub(calls + BAND_FIXED)) * 100;
    let one_row = u64::from(per_row) + u64::from(damage_w) * u64::from(per_point);
    let rows = budget / one_row;
    if rows >= 1 {
        // The width of the damage, as many lines as the ticks allow.
        return (damage_w, rows.min(u64::from(BAND_ROWS)) as u32);
    }
    // Not even one line of the whole width: a part of a line.
    let room = budget.saturating_sub(u64::from(per_row));
    let w = room.checked_div(u64::from(per_point)).unwrap_or(0);
    (w.clamp(1, u64::from(damage_w)) as u32, 1)
}

/// The bands a frame of one copy over the whole screen takes by the prices of
/// `PRICES` (a window of XRGB8888 that covers the screen, nothing above it): the
/// figure the probes print, and the one that must stay at 45 or fewer for the
/// frame to fit a period of 60 Hz under -icount without load.
pub fn full_screen_bands() -> u32 {
    let mut s = Scene::new();
    let screen = Rect::SCREEN;
    let Ok(a) = s.create(1, 1, screen, true, 0) else {
        return u32::MAX;
    };
    if s.flush(a, screen).is_err() {
        return u32::MAX;
    }
    let Some(d) = s.begin() else {
        return u32::MAX;
    };
    s.end(true);
    HEIGHT.div_ceil(s.tile(d).1)
}

/// Where the pixels of a window's buffer are.
pub trait Source {
    /// The bytes of buffer `buffer` of window `window`: at least `stride`
    /// times the window's height.
    fn pixels(&self, window: usize, buffer: u8) -> &[u8];
}

/// The pixel operations of a band. The program's is pixman's.
pub trait Raster {
    /// The rectangle of the screen's bytes `fb` (XRGB8888, STRIDE bytes a
    /// line) becomes black.
    fn black(&mut self, fb: &mut [u8], rect: Rect);

    /// The points of `src` (a surface of `size` points, `stride` bytes a
    /// line, in `format`) that start at (`from.0`, `from.1`) go to the
    /// screen at `to`, `area` of them: replacing what is there when `over`
    /// is false, laid over it (premultiplied) when it is true.
    #[allow(clippy::too_many_arguments)]
    fn blit(
        &mut self,
        fb: &mut [u8],
        src: &[u8],
        stride: u32,
        format: Format,
        size: (u32, u32),
        from: (u32, u32),
        to: (u32, u32),
        area: (u32, u32),
        over: bool,
    );
}

/// A place in the frame: the line, and the column from the damage's left edge,
/// where the next band starts. The frame is done when the line is past the
/// damage's last.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Band {
    pub row: u32,
    pub col: u32,
}

/// One band of the frame, from `at` in `damage`: the lines
/// `at.row..at.row + rows` (to the damage's end) of the columns from `at.col`
/// (to the damage's end, `width` of them) are made in `fb`, the screen's
/// bytes. The topmost opaque window that covers the band whole is its base, and the windows above it lie over it; a band no
/// opaque window covers whole starts black. The pointer's picture goes last.
/// The place of the next band, whose line is the damage's end when the frame
/// is done.
pub fn compose(
    scene: &Scene,
    damage: Rect,
    at: Band,
    fb: &mut [u8],
    src: &impl Source,
    raster: &mut impl Raster,
) -> Band {
    let size = scene.tile(damage);
    compose_sized(scene, damage, at, size, fb, src, raster)
}

/// `compose` for a band of `size` (columns and lines) that the caller names:
/// the calibration measures the bands of its own shapes.
pub fn compose_sized(
    scene: &Scene,
    damage: Rect,
    at: Band,
    size: (u32, u32),
    fb: &mut [u8],
    src: &impl Source,
    raster: &mut impl Raster,
) -> Band {
    let (width, rows) = size;
    let y0 = at.row.max(damage.y);
    let y1 = (y0 + rows).min(damage.y + damage.h);
    let x0 = damage.x + at.col;
    let x1 = (x0 + width).min(damage.x + damage.w);
    if y0 >= y1 || x0 >= x1 {
        return Band {
            row: damage.y + damage.h,
            col: 0,
        };
    }
    let (order, n) = scene.order();
    let window = |k: u8| scene.window(k as usize).copied();
    // The topmost opaque window over the whole band.
    let base = order[..n].iter().rposition(|&k| {
        window(k).is_some_and(|w| {
            w.format == Format::Xrgb
                && w.rect.x <= x0
                && w.rect.x + w.rect.w >= x1
                && w.rect.y <= y0
                && w.rect.y + w.rect.h >= y1
        })
    });
    if base.is_none() {
        raster.black(
            fb,
            Rect {
                x: x0,
                y: y0,
                w: x1 - x0,
                h: y1 - y0,
            },
        );
    }
    for &k in &order[base.unwrap_or(0)..n] {
        let Some(w) = window(k) else {
            continue;
        };
        let Some(b) = w.current else {
            continue;
        };
        let (wx0, wx1) = (x0.max(w.rect.x), x1.min(w.rect.x + w.rect.w));
        let (wy0, wy1) = (y0.max(w.rect.y), y1.min(w.rect.y + w.rect.h));
        if wx0 >= wx1 || wy0 >= wy1 {
            continue;
        }
        raster.blit(
            fb,
            src.pixels(k as usize, b),
            w.stride,
            w.format,
            (w.rect.w, w.rect.h),
            (wx0 - w.rect.x, wy0 - w.rect.y),
            (wx0, wy0),
            (wx1 - wx0, wy1 - wy0),
            w.format == Format::Argb,
        );
    }
    if let Some(p) = scene.drawn_pointer() {
        let c = Scene::cursor_rect(p);
        let (cx0, cx1) = (x0.max(c.x), x1.min(c.x + c.w));
        let (cy0, cy1) = (y0.max(c.y), y1.min(c.y + c.h));
        if cx0 < cx1 && cy0 < cy1 {
            raster.blit(
                fb,
                &PICTURE.0,
                CURSOR_W * 4,
                Format::Argb,
                (CURSOR_W, CURSOR_H),
                (cx0 - c.x, cy0 - c.y),
                (cx0, cy0),
                (cx1 - cx0, cy1 - cy0),
                true,
            );
        }
    }
    if x1 < damage.x + damage.w {
        Band {
            row: y0,
            col: x1 - damage.x,
        }
    } else {
        Band { row: y1, col: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: u32, y: u32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    /// Buffers of fixed bytes, a byte value for each window and buffer.
    struct Flat(Vec<Vec<u8>>);

    impl Source for Flat {
        fn pixels(&self, window: usize, buffer: u8) -> &[u8] {
            &self.0[window * BUFFERS + buffer as usize]
        }
    }

    /// The pixel operations of the tests: a copy, and the premultiplied
    /// "over" per byte.
    struct Plain;

    impl Raster for Plain {
        fn black(&mut self, fb: &mut [u8], r: Rect) {
            for y in r.y..r.y + r.h {
                let at = (y * STRIDE + r.x * 4) as usize;
                fb[at..at + (r.w * 4) as usize].fill(0);
            }
        }

        fn blit(
            &mut self,
            fb: &mut [u8],
            src: &[u8],
            stride: u32,
            format: Format,
            _: (u32, u32),
            from: (u32, u32),
            to: (u32, u32),
            area: (u32, u32),
            over: bool,
        ) {
            assert_eq!(over, format == Format::Argb);
            for y in 0..area.1 {
                for x in 0..area.0 * 4 {
                    let s = src[((from.1 + y) * stride + from.0 * 4 + (x / 4) * 4) as usize..][..4]
                        .to_vec();
                    let at = ((to.1 + y) * STRIDE + to.0 * 4 + x) as usize;
                    let c = s[(x % 4) as usize];
                    fb[at] = if over {
                        let alpha = u32::from(s[3]);
                        (u32::from(c) + u32::from(fb[at]) * (255 - alpha) / 255).min(255) as u8
                    } else {
                        c
                    };
                }
            }
        }
    }

    fn flat(fill: &[(usize, u8, u8, usize)]) -> Flat {
        let mut v = vec![Vec::new(); MAX_WINDOWS * BUFFERS];
        for &(w, b, value, bytes) in fill {
            v[w * BUFFERS + b as usize] = vec![value; bytes];
        }
        Flat(v)
    }

    fn make(scene: &mut Scene, label: u64, ctx: u64, r: Rect, count: u8) -> usize {
        let i = scene.create(label, ctx, r, false, 0).unwrap();
        scene.attach(i, count, r.w * 4).unwrap();
        i
    }

    /// Makes the bands of a frame over `d` into `fb`, one after another.
    fn draw(scene: &Scene, d: Rect, fb: &mut [u8], src: &impl Source) -> usize {
        let mut at = Band { row: d.y, col: 0 };
        let mut bands = 0;
        while at.row < d.y + d.h {
            at = compose(scene, d, at, fb, src, &mut Plain);
            bands += 1;
        }
        bands
    }

    /// Runs one whole frame into `fb`.
    fn frame(scene: &mut Scene, fb: &mut [u8], src: &impl Source) -> [Ended; MAX_WINDOWS] {
        let d = scene.begin().expect("a frame");
        draw(scene, d, fb, src);
        scene.end(true)
    }

    fn screen() -> Vec<u8> {
        vec![0xEE; (STRIDE * HEIGHT) as usize]
    }

    fn at(fb: &[u8], x: u32, y: u32) -> u8 {
        fb[(y * STRIDE + x * 4) as usize]
    }

    #[test]
    fn a_window_needs_the_screen_and_its_context_a_share() {
        let mut s = Scene::new();
        assert_eq!(
            s.create(1, 7, rect(600, 0, 41, 10), false, 0),
            Err(Refusal::Invalid)
        );
        assert_eq!(
            s.create(1, 7, rect(0, 0, 0, 10), false, 0),
            Err(Refusal::Invalid)
        );
        for k in 0..PER_CONTEXT as u64 {
            s.create(k, 7, rect(0, 0, 10, 10), false, 0).unwrap();
        }
        assert_eq!(
            s.create(9, 7, rect(0, 0, 10, 10), false, 0),
            Err(Refusal::Limit)
        );
        // Another context has its own share, until the table is full.
        for k in 0..(MAX_WINDOWS - PER_CONTEXT) as u64 {
            s.create(100 + k, 8, rect(0, 0, 10, 10), false, 0).unwrap();
        }
        assert_eq!(
            s.create(200, 9, rect(0, 0, 10, 10), false, 0),
            Err(Refusal::Limit)
        );
        assert_eq!(s.open(), MAX_WINDOWS as u32);
        assert_eq!(s.created(), MAX_WINDOWS as u32);
    }

    #[test]
    fn a_taken_place_is_not_given() {
        let mut s = Scene::new();
        let a = s.create(1, 1, rect(0, 0, 8, 8), false, 0).unwrap();
        assert_eq!(a, 0);
        s.destroy(a);
        // Place 0 is free in the scene but its pages are still going.
        let b = s.create(2, 1, rect(0, 0, 8, 8), false, 0b1).unwrap();
        assert_eq!(b, 1);
        assert_eq!(s.create(3, 1, rect(0, 0, 8, 8), false, 0b11).unwrap(), 2);
        let all = u8::MAX;
        assert_eq!(
            s.create(4, 2, rect(0, 0, 8, 8), false, all),
            Err(Refusal::Limit)
        );
        assert_eq!(s.create(5, 2, rect(0, 0, 8, 8), false, 0).unwrap(), 0);
    }

    #[test]
    fn attach_is_once_and_checks_the_stride() {
        let mut s = Scene::new();
        let i = s.create(1, 1, rect(0, 0, 100, 10), false, 0).unwrap();
        assert_eq!(s.attach(i, 0, 400), Err(Refusal::Invalid));
        assert_eq!(s.attach(i, 4, 400), Err(Refusal::Invalid));
        assert_eq!(s.attach(i, 2, 399), Err(Refusal::Invalid));
        assert_eq!(s.post(i, 0, &[]), Err(Refusal::NotAllowed));
        assert_eq!(s.attach(i, 2, 400), Ok(()));
        assert_eq!(s.attach(i, 2, 400), Err(Refusal::Busy));
        assert_eq!(s.attach(5, 1, 400), Err(Refusal::Invalid));
    }

    #[test]
    fn a_post_checks_the_buffer_the_rectangles_and_the_state() {
        let mut s = Scene::new();
        let i = make(&mut s, 1, 1, rect(10, 20, 100, 50), 2);
        assert_eq!(s.post(i, 2, &[]), Err(Refusal::Invalid));
        assert_eq!(s.post(i, 0, &[rect(0, 0, 101, 1)]), Err(Refusal::Invalid));
        assert_eq!(s.post(i, 0, &[rect(0, 0, 0, 1)]), Err(Refusal::Invalid));
        assert_eq!(
            s.post(i, 0, &[rect(0, 0, 1, 1); MAX_RECTS + 1]),
            Err(Refusal::Invalid)
        );
        // The refusals left nothing posted and no damage.
        assert!(!s.busy());
        assert_eq!(s.post(i, 0, &[]), Ok(None));
        assert!(s.busy());
        assert_eq!(s.post(i, 0, &[]), Err(Refusal::Busy));
        // The latest wins: buffer 1 replaces the posted 0, which is free.
        assert_eq!(s.post(i, 1, &[rect(5, 5, 10, 10)]), Ok(Some(0)));
        assert_eq!(
            s.window(i).unwrap().bufs,
            [Buf::Free, Buf::Posted, Buf::Free]
        );
        assert_eq!(s.post(5, 0, &[]), Err(Refusal::Invalid));
    }

    #[test]
    fn the_damage_is_the_union_of_the_posts_in_screen_coordinates() {
        let mut s = Scene::new();
        let i = make(&mut s, 1, 1, rect(10, 20, 100, 50), 2);
        s.post(i, 0, &[rect(0, 0, 5, 5), rect(90, 40, 10, 10)])
            .unwrap();
        s.post(i, 1, &[rect(50, 0, 1, 1)]).unwrap();
        assert_eq!(s.begin(), Some(rect(10, 20, 100, 50)));
    }

    #[test]
    fn a_frame_takes_the_posted_buffer_and_frees_the_replaced_one_when_shown() {
        let mut s = Scene::new();
        let i = make(&mut s, 1, 1, rect(0, 0, 4, 4), 2);
        let src = flat(&[(i, 0, 1, 64), (i, 1, 2, 64)]);
        let mut fb = screen();
        s.post(i, 0, &[]).unwrap();
        assert!(!s.window(i).unwrap().in_frame);
        let ended = frame(&mut s, &mut fb, &src);
        assert_eq!(
            ended[i],
            Ended {
                freed: None,
                in_frame: true
            }
        );
        assert_eq!(at(&fb, 0, 0), 1);
        assert_eq!(
            s.window(i).unwrap().bufs,
            [Buf::Taken, Buf::Free, Buf::Free]
        );
        // The next post is taken: buffer 0 goes free only with the frame.
        s.post(i, 1, &[]).unwrap();
        let d = s.begin().unwrap();
        assert_eq!(s.window(i).unwrap().bufs[0], Buf::Taken);
        draw(&s, d, &mut fb, &src);
        let ended = s.end(true);
        assert_eq!(
            ended[i],
            Ended {
                freed: Some(0),
                in_frame: true
            }
        );
        assert_eq!(at(&fb, 0, 0), 2);
        assert_eq!(
            s.window(i).unwrap().bufs,
            [Buf::Free, Buf::Taken, Buf::Free]
        );
        assert_eq!(s.frames(), 2);
        assert!(!s.busy());
    }

    #[test]
    fn a_post_during_a_frame_waits_for_the_next() {
        let mut s = Scene::new();
        let i = make(&mut s, 1, 1, rect(0, 0, 4, 4), 2);
        s.post(i, 0, &[]).unwrap();
        s.begin().unwrap();
        assert!(s.framing());
        assert_eq!(s.begin(), None);
        s.post(i, 1, &[]).unwrap();
        assert_eq!(s.begin(), None);
        let ended = s.end(true);
        assert!(ended[i].in_frame);
        assert!(s.busy());
        assert!(s.begin().is_some());
    }

    #[test]
    fn a_frame_that_failed_counts_no_frame() {
        let mut s = Scene::new();
        let i = make(&mut s, 1, 1, rect(0, 0, 4, 4), 1);
        s.post(i, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(false);
        assert_eq!(s.frames(), 0);
    }

    #[test]
    fn the_newest_window_is_on_top_and_a_black_screen_stays_black() {
        let mut s = Scene::new();
        let a = make(&mut s, 1, 1, rect(0, 0, 20, 20), 1);
        let b = make(&mut s, 2, 1, rect(10, 10, 20, 20), 1);
        let src = flat(&[(a, 0, 0xA, 20 * 20 * 4), (b, 0, 0xB, 20 * 20 * 4)]);
        let mut fb = screen();
        s.post(a, 0, &[]).unwrap();
        s.post(b, 0, &[]).unwrap();
        frame(&mut s, &mut fb, &src);
        assert_eq!(at(&fb, 5, 5), 0xA);
        assert_eq!(at(&fb, 15, 15), 0xB);
        assert_eq!(at(&fb, 25, 25), 0xB);
        // Inside the damage and under no window: black: the old 0xEE is gone.
        assert_eq!(at(&fb, 25, 5), 0);
        // Outside the damage: untouched.
        assert_eq!(at(&fb, 40, 40), 0xEE);
    }

    #[test]
    fn a_window_that_goes_is_painted_out() {
        let mut s = Scene::new();
        let a = make(&mut s, 1, 1, rect(0, 0, 8, 8), 1);
        let src = flat(&[(a, 0, 0xA, 8 * 8 * 4)]);
        let mut fb = screen();
        s.post(a, 0, &[]).unwrap();
        frame(&mut s, &mut fb, &src);
        assert_eq!(at(&fb, 3, 3), 0xA);
        assert!(!s.busy());
        let gone = s.destroy(a).unwrap();
        assert_eq!(gone.label, 1);
        assert!(s.busy());
        frame(&mut s, &mut fb, &src);
        assert_eq!(at(&fb, 3, 3), 0);
        assert_eq!(s.open(), 0);
        assert_eq!(s.find(1), None);
        assert!(s.destroy(a).is_none());
    }

    #[test]
    fn a_window_that_never_posted_leaves_no_damage_when_it_goes() {
        let mut s = Scene::new();
        let a = make(&mut s, 1, 1, rect(0, 0, 8, 8), 1);
        s.destroy(a);
        assert!(!s.busy());
    }

    #[test]
    fn the_legacy_window_flushes_its_one_buffer() {
        let mut s = Scene::new();
        let i = s.create(1, 1, SCREEN, true, 0).unwrap();
        assert!(s.has_legacy());
        assert_eq!(s.window(i).unwrap().stride, STRIDE);
        assert_eq!(s.post(i, 0, &[]), Err(Refusal::NotAllowed));
        assert_eq!(s.flush(i, rect(0, 0, 641, 1)), Err(Refusal::Invalid));
        let src = flat(&[(i, 0, 7, (STRIDE * HEIGHT) as usize)]);
        let mut fb = screen();
        s.flush(i, rect(100, 100, 50, 10)).unwrap();
        s.flush(i, rect(120, 100, 50, 10)).unwrap();
        let d = s.begin().unwrap();
        assert_eq!(d, rect(100, 100, 70, 10));
        draw(&s, d, &mut fb, &src);
        let ended = s.end(true);
        assert_eq!(
            ended[i],
            Ended {
                freed: None,
                in_frame: true
            }
        );
        assert_eq!(at(&fb, 100, 100), 7);
        assert_eq!(at(&fb, 169, 109), 7);
        assert_eq!(at(&fb, 170, 100), 0xEE);
        assert_eq!(at(&fb, 99, 100), 0xEE);
        // A native window refuses FLUSH.
        let n = make(&mut s, 2, 1, rect(0, 0, 4, 4), 1);
        assert_eq!(s.flush(n, rect(0, 0, 1, 1)), Err(Refusal::NotAllowed));
    }

    #[test]
    fn a_band_is_a_few_lines_and_the_frame_ends_at_the_damage() {
        let mut s = Scene::new();
        let i = s.create(1, 1, SCREEN, true, 0).unwrap();
        let src = flat(&[(i, 0, 1, (STRIDE * HEIGHT) as usize)]);
        let mut fb = screen();
        s.flush(i, SCREEN).unwrap();
        let d = s.begin().unwrap();
        let mut bands = 0;
        let mut at = Band { row: d.y, col: 0 };
        while at.row < d.y + d.h {
            let next = compose(&s, d, at, &mut fb, &src, &mut Plain);
            assert_eq!(next.col, 0);
            assert_eq!(next.row, (at.row + 12).min(HEIGHT));
            at = next;
            bands += 1;
        }
        assert_eq!(bands, HEIGHT.div_ceil(12));
        assert_eq!(at.row, HEIGHT);
        // A band past the damage is a no-op that says the frame is done.
        let done = Band {
            row: HEIGHT,
            col: 0,
        };
        assert_eq!(compose(&s, d, done, &mut fb, &src, &mut Plain), done);
        s.end(true);
    }

    #[test]
    fn the_covering_window_is_the_base_and_nothing_under_it_is_read() {
        let mut s = Scene::new();
        // A window under with no readable pixels (an empty source) and a
        // covering one above: the band never reads the one under.
        let a = make(&mut s, 1, 1, rect(0, 0, 8, 8), 1);
        let b = make(&mut s, 2, 1, rect(0, 0, 16, 16), 1);
        let src = flat(&[(b, 0, 9, 16 * 16 * 4)]);
        let mut fb = screen();
        s.post(b, 0, &[]).unwrap();
        s.post(a, 0, &[]).unwrap();
        // `a` has a posted buffer too but its source is empty: it is the
        // older one, under `b`, and `b` covers the band whole.
        let d = s.begin().unwrap();
        assert_eq!(d, rect(0, 0, 16, 16));
        draw(&s, d, &mut fb, &src);
        assert_eq!(at(&fb, 2, 2), 9);
        s.end(true);
    }

    /// Two windows posted and shown, the second on top and with the focus:
    /// the places 0 and 1, their events drained.
    fn two(s: &mut Scene) -> (usize, usize) {
        let a = make(s, 1, 1, rect(0, 0, 100, 100), 1);
        let b = make(s, 2, 2, rect(50, 50, 100, 100), 1);
        s.post(a, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        s.post(b, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        // The raise of the first show left damage: shown too.
        if s.begin().is_some() {
            s.end(true);
        }
        s.delivered();
        for i in [a, b] {
            s.take_events(i, &mut [Event::default(); 64]);
        }
        (a, b)
    }

    fn events(s: &mut Scene, i: usize) -> Vec<Event> {
        let mut out = [Event::default(); 64];
        let (n, _) = s.take_events(i, &mut out);
        out[..n].to_vec()
    }

    #[test]
    fn a_window_that_is_shown_first_has_the_focus_and_the_top() {
        let mut s = Scene::new();
        let a = make(&mut s, 1, 1, rect(0, 0, 100, 100), 1);
        assert_eq!(s.focus(), None);
        s.post(a, 0, &[]).unwrap();
        // Posted is not yet shown: no focus.
        assert_eq!(s.focus(), None);
        s.begin().unwrap();
        assert_eq!(s.focus(), Some(a));
        assert_eq!(events(&mut s, a), [Event::new(FOCUS_IN, 0, 0)]);
        assert_eq!(s.delivered().windows, 1 << a);
        s.end(true);
        let b = make(&mut s, 2, 2, rect(50, 50, 100, 100), 1);
        s.post(b, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        assert_eq!(s.focus(), Some(b));
        assert_eq!(events(&mut s, a), [Event::new(FOCUS_OUT, 0, 0)]);
        assert_eq!(events(&mut s, b), [Event::new(FOCUS_IN, 0, 0)]);
        // A second take of the same window's buffer is not a first show.
        s.post(b, 0, &[]).ok();
    }

    #[test]
    fn keys_go_to_the_window_with_the_focus_only() {
        let mut s = Scene::new();
        let (a, b) = two(&mut s);
        s.key(30, true);
        s.key(30, false);
        assert_eq!(
            events(&mut s, b),
            [Event::new(KEY, 30, 1), Event::new(KEY, 30, 0)]
        );
        assert!(events(&mut s, a).is_empty());
        assert_eq!(
            s.delivered(),
            Delivered {
                windows: 1 << b,
                manager: false
            }
        );
        // No window with the focus: the key is dropped.
        s.destroy(b);
        s.destroy(a);
        s.delivered();
        s.key(30, true);
        assert_eq!(s.delivered(), Delivered::default());
    }

    #[test]
    fn a_click_gives_the_focus_and_the_top_and_the_window_holds_the_button() {
        let mut s = Scene::new();
        let (a, b) = two(&mut s);
        // The point (10, 10) is in a alone.
        s.pointer_to(10, 10);
        assert_eq!(events(&mut s, a), [Event::at(MOVE, 0, 0, 10, 10)]);
        assert!(events(&mut s, b).is_empty());
        s.button(0x110, true);
        assert_eq!(s.focus(), Some(a));
        assert_eq!(
            events(&mut s, a),
            [
                Event::new(FOCUS_IN, 0, 0),
                Event::at(BUTTON, 0x110, 1, 10, 10)
            ]
        );
        assert_eq!(events(&mut s, b), [Event::new(FOCUS_OUT, 0, 0)]);
        // a is on top now: at (60, 60), where both lie, a is hit.
        assert_eq!(s.hit(60, 60), Some(a));
        // The button is held: the pointer over b still moves a.
        s.pointer_to(120, 120);
        assert_eq!(events(&mut s, a), [Event::at(MOVE, 0, 0, 120, 120)]);
        assert!(events(&mut s, b).is_empty());
        s.button(0x110, false);
        assert_eq!(events(&mut s, a), [Event::at(BUTTON, 0x110, 0, 120, 120)]);
        // Released: the pointer over b alone moves b, in b's coordinates.
        s.pointer_to(140, 140);
        assert_eq!(events(&mut s, b), [Event::at(MOVE, 0, 0, 90, 90)]);
        // A click on nothing gives nothing and keeps the focus.
        s.pointer_to(300, 300);
        s.button(0x110, true);
        assert_eq!(s.focus(), Some(a));
        assert!(events(&mut s, a).is_empty() && events(&mut s, b).is_empty());
    }

    #[test]
    fn a_button_without_a_pointer_is_dropped_and_a_move_is_damage() {
        let mut s = Scene::new();
        let (a, _) = two(&mut s);
        s.button(0x110, true);
        assert!(events(&mut s, a).is_empty());
        assert!(!s.busy());
        s.pointer_to(10, 10);
        assert!(s.busy());
        let d = s.begin().unwrap();
        assert_eq!(d, rect(10, 10, CURSOR_W, CURSOR_H));
        s.end(true);
        s.pointer_to(30, 40);
        // The union of the old and the new picture.
        assert_eq!(
            s.begin(),
            Some(rect(10, 10, 30 + CURSOR_W - 10, 40 + CURSOR_H - 10))
        );
        // The same place again is nothing.
        s.end(true);
        s.pointer_to(30, 40);
        assert!(!s.busy());
        // The picture at the corner is clipped to the screen.
        s.pointer_to(WIDTH as i32 + 50, HEIGHT as i32 + 50);
        assert_eq!(s.pointer(), Some((WIDTH as i32 - 1, HEIGHT as i32 - 1)));
        let d = s.begin().unwrap();
        assert_eq!((d.x + d.w, d.y + d.h), (WIDTH, HEIGHT));
    }

    #[test]
    fn the_focus_passes_to_the_window_on_top_when_its_window_goes() {
        let mut s = Scene::new();
        let (a, b) = two(&mut s);
        assert_eq!(s.focus(), Some(b));
        s.destroy(b);
        assert_eq!(s.focus(), Some(a));
        assert_eq!(events(&mut s, a), [Event::new(FOCUS_IN, 0, 0)]);
        s.destroy(a);
        assert_eq!(s.focus(), None);
        // The ring of a place that is reused starts empty.
        let c = make(&mut s, 3, 3, rect(0, 0, 10, 10), 1);
        assert!(events(&mut s, c).is_empty());
    }

    #[test]
    fn the_manager_gets_the_super_keys_and_the_windows_coming_and_going() {
        let mut s = Scene::new();
        let (a, b) = two(&mut s);
        let mut out = [Event::default(); 64];
        s.set_manager(true);
        let c = make(&mut s, 3, 3, rect(0, 0, 10, 10), 1);
        s.destroy(c);
        let (n, lost) = s.take_manager_events(&mut out);
        assert_eq!(
            (&out[..n], lost),
            (
                &[
                    Event::new(CREATE, c as u16, 0),
                    Event::new(CLOSE, c as u16, 0)
                ][..],
                false
            )
        );
        assert!(s.delivered().manager);
        // Super, Tab under Super, and Tab alone: the first two are the
        // manager's, the third the window's.
        s.key(KEY_LEFTMETA, true);
        s.key(KEY_TAB, true);
        s.key(KEY_TAB, false);
        s.key(KEY_LEFTMETA, false);
        s.key(KEY_TAB, true);
        let (n, _) = s.take_manager_events(&mut out);
        assert_eq!(
            &out[..n],
            [
                Event::new(KEY, KEY_LEFTMETA, 1),
                Event::new(KEY, KEY_TAB, 1),
                Event::new(KEY, KEY_TAB, 0),
                Event::new(KEY, KEY_LEFTMETA, 0),
            ]
        );
        assert_eq!(events(&mut s, b), [Event::new(KEY, KEY_TAB, 1)]);
        assert!(events(&mut s, a).is_empty());
        // The manager switches: a has the focus and the top.
        s.focus_on(a).unwrap();
        assert_eq!(s.focus(), Some(a));
        assert_eq!(s.hit(60, 60), Some(a));
        assert_eq!(s.focus_on(7), Err(Refusal::Invalid));
        // Without a manager the Super keys are the window's.
        s.set_manager(false);
        s.key(KEY_LEFTMETA, true);
        assert_eq!(
            events(&mut s, a).last(),
            Some(&Event::new(KEY, KEY_LEFTMETA, 1))
        );
    }

    /// A window of the first revision shown with the focus, a native one
    /// made before it (so below it).
    fn old_and_new(s: &mut Scene) -> (usize, usize) {
        let n = make(s, 1, 1, rect(0, 0, 100, 100), 1);
        let l = s.create(2, 2, SCREEN, true, 0).unwrap();
        s.post(n, 0, &[]).unwrap();
        s.flush(l, SCREEN).unwrap();
        s.begin().unwrap();
        s.end(true);
        s.delivered();
        for i in [n, l] {
            s.take_events(i, &mut [Event::default(); 64]);
        }
        assert_eq!(s.focus(), Some(l));
        (n, l)
    }

    #[test]
    fn the_keys_of_a_first_revision_window_follow_the_focus() {
        let mut s = Scene::new();
        let (n, l) = old_and_new(&mut s);
        // The window of the first revision has the focus: its keys are the
        // KEY events of its ring.
        s.key(30, true);
        s.key(30, false);
        let mut out = [Event::default(); 8];
        assert_eq!(
            s.take_keys(l, &mut out),
            (2, false),
            "the keys of the focus"
        );
        assert_eq!(&out[..2], [Event::new(KEY, 30, 1), Event::new(KEY, 30, 0)]);
        assert!(events(&mut s, n).is_empty());
        // The focus goes to the native window: the first revision's gets no
        // key, whatever the keyboard's driver does.
        s.focus_on(n).unwrap();
        s.key(31, true);
        s.key(31, false);
        assert_eq!(s.take_keys(l, &mut out), (0, false));
        assert_eq!(
            events(&mut s, n),
            [
                Event::new(FOCUS_IN, 0, 0),
                Event::new(KEY, 31, 1),
                Event::new(KEY, 31, 0)
            ]
        );
        // And back: the keys of the time come to it; the focus events in its
        // ring are not keys and are left out of what it reads.
        s.focus_on(l).unwrap();
        s.key(32, true);
        assert_eq!(s.take_keys(l, &mut out), (1, false));
        assert_eq!(out[0], Event::new(KEY, 32, 1));
        // The window goes: the keys are the native window's again.
        s.destroy(l);
        s.key(33, true);
        assert_eq!(s.take_keys(l, &mut out), (0, false));
        assert_eq!(events(&mut s, n).last(), Some(&Event::new(KEY, 33, 1)));
    }

    #[test]
    fn a_first_revision_window_takes_no_pointer_events_but_a_click_gives_it_the_focus() {
        let mut s = Scene::new();
        let (n, l) = old_and_new(&mut s);
        // The window of the first revision covers the screen: moves and
        // buttons over it leave its ring free for keys.
        s.pointer_to(10, 10);
        s.button(0x110, true);
        s.button(0x110, false);
        let mut out = [Event::default(); 64];
        let (got, lost) = s.take_events(l, &mut out);
        assert!(!lost);
        assert_eq!(&out[..got], []);
        assert_eq!(s.focus(), Some(l));
        // A key is the only thing in the ring.
        s.key(30, true);
        assert_eq!(s.take_keys(l, &mut out), (1, false));
        // The native window has the focus; a click where only the window of
        // the first revision lies gives that window the focus, and the keys
        // follow.
        s.focus_on(n).unwrap();
        assert_eq!(s.focus(), Some(n));
        s.pointer_to(500, 300);
        s.button(0x110, true);
        s.button(0x110, false);
        assert_eq!(s.focus(), Some(l));
        s.key(31, true);
        // Key 30 was still held when the focus left: its release is in the
        // ring, then the new key.
        assert_eq!(s.take_keys(l, &mut out), (2, false));
        assert_eq!(&out[..2], [Event::new(KEY, 30, 0), Event::new(KEY, 31, 1)]);
    }

    #[test]
    fn a_first_revision_ring_that_overflows_says_it_lost_keys() {
        let mut s = Scene::new();
        let (_, l) = old_and_new(&mut s);
        for _ in 0..70 {
            s.focus_on(l).unwrap();
            s.key(30, true);
        }
        let mut out = [Event::default(); 64];
        let (n, lost) = s.take_keys(l, &mut out);
        assert!(lost);
        assert_eq!(n, 64);
    }

    #[test]
    fn the_modifier_of_the_manager_is_super_and_alt_ctrl_and_shift_are_the_windows() {
        let mut s = Scene::new();
        let (a, b) = two(&mut s);
        s.set_manager(true);
        s.take_manager_events(&mut [Event::default(); 64]);
        // The keys a game binds (Ctrl 29, Shift 42, Alt 56) reach the window
        // with the focus, and Tab under them.
        for code in [29, 42, 56, KEY_TAB] {
            s.key(code, true);
        }
        assert_eq!(events(&mut s, b).len(), 4);
        assert!(events(&mut s, a).is_empty());
        assert!(!s.delivered().manager);
        // The right Super is the manager's as well.
        s.key(KEY_RIGHTMETA, true);
        s.key(16, true);
        assert!(s.delivered().manager);
        assert!(events(&mut s, b).is_empty());
    }

    #[test]
    fn a_first_revision_window_is_released_of_the_keys_it_holds_when_the_focus_leaves() {
        let mut s = Scene::new();
        let (n, l) = old_and_new(&mut s);
        s.key(17, true);
        s.focus_on(n).unwrap();
        // The release came before the focus left, and the key's real
        // release, while the other window has the focus, goes nowhere.
        s.key(17, false);
        let mut out = [Event::default(); 8];
        assert_eq!(s.take_keys(l, &mut out), (2, false));
        assert_eq!(&out[..2], [Event::new(KEY, 17, 1), Event::new(KEY, 17, 0)]);
        assert_eq!(
            events(&mut s, n),
            [Event::new(FOCUS_IN, 0, 0)],
            "a release of another window's key is no key of this one"
        );
        // A key pressed and released with no focus change is not doubled.
        s.focus_on(l).unwrap();
        s.key(18, true);
        s.key(18, false);
        assert_eq!(s.take_keys(l, &mut out), (2, false));
    }

    #[test]
    fn a_release_goes_to_the_window_that_got_the_press_even_under_super() {
        let mut s = Scene::new();
        let (a, b) = two(&mut s);
        s.set_manager(true);
        s.take_manager_events(&mut [Event::default(); 64]);
        s.delivered();
        // b holds W; Super is tapped; W is released under Super.
        s.key(17, true);
        s.key(KEY_LEFTMETA, true);
        s.key(17, false);
        s.key(KEY_LEFTMETA, false);
        assert_eq!(
            events(&mut s, b),
            [Event::new(KEY, 17, 1), Event::new(KEY, 17, 0)]
        );
        assert!(events(&mut s, a).is_empty());
        let mut out = [Event::default(); 8];
        let (n, _) = s.take_manager_events(&mut out);
        assert_eq!(
            &out[..n],
            [
                Event::new(KEY, KEY_LEFTMETA, 1),
                Event::new(KEY, KEY_LEFTMETA, 0)
            ]
        );
        // And Tab pressed under Super and released after it: the manager's.
        s.key(KEY_LEFTMETA, true);
        s.key(KEY_TAB, true);
        s.key(KEY_LEFTMETA, false);
        s.key(KEY_TAB, false);
        let (n, _) = s.take_manager_events(&mut out);
        assert_eq!(n, 4);
        assert!(events(&mut s, b).is_empty());
    }

    #[test]
    fn two_super_keys_hold_the_manager_s_modifier_until_both_are_up() {
        let mut s = Scene::new();
        let (_, b) = two(&mut s);
        s.set_manager(true);
        s.take_manager_events(&mut [Event::default(); 64]);
        s.key(KEY_LEFTMETA, true);
        s.key(KEY_RIGHTMETA, true);
        s.key(KEY_RIGHTMETA, false);
        s.key(KEY_TAB, true);
        assert!(events(&mut s, b).is_empty());
        s.key(KEY_LEFTMETA, false);
        s.key(KEY_TAB, false);
        s.key(KEY_TAB, true);
        assert_eq!(events(&mut s, b), [Event::new(KEY, KEY_TAB, 1)]);
    }

    #[test]
    fn a_window_that_goes_drops_the_releases_of_its_keys() {
        let mut s = Scene::new();
        let (a, b) = two(&mut s);
        s.key(17, true);
        s.destroy(b);
        s.key(17, false);
        assert!(events(&mut s, a).iter().all(|e| e.kind != KEY));
    }

    #[test]
    fn the_compositor_takes_a_devices_focus_again_when_it_is_there_and_not_held() {
        assert!(wants_focus(true, false));
        assert!(!wants_focus(true, true));
        assert!(!wants_focus(false, false));
    }

    #[test]
    fn a_first_revision_window_made_under_a_manager_gets_its_focus_in_its_ring() {
        let mut s = Scene::new();
        s.set_manager(true);
        let n = make(&mut s, 1, 1, rect(0, 0, 100, 100), 1);
        s.post(n, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        // The manager is told of each making and gives the focus: the
        // native window first, then the window of the first revision.
        s.focus_on(n).unwrap();
        let l = s.create(2, 2, SCREEN, true, 0).unwrap();
        let mut out = [Event::default(); 8];
        let (got, _) = s.take_manager_events(&mut out);
        assert_eq!(
            &out[..got],
            [
                Event::new(CREATE, n as u16, 0),
                Event::new(CREATE, l as u16, 0)
            ]
        );
        // Nothing gave the window the focus yet: the first take of its
        // buffer, with a manager, leaves it to the manager.
        s.flush(l, SCREEN).unwrap();
        s.begin().unwrap();
        s.end(true);
        assert_eq!(s.focus(), Some(n));
        assert!(events(&mut s, l).is_empty());
        // The manager's FOCUS: the window's ring (what EVENTS of its session
        // reads) has FOCUS_IN, the native window FOCUS_OUT, and the keys are
        // the first revision's.
        s.focus_on(l).unwrap();
        assert_eq!(events(&mut s, l), [Event::new(FOCUS_IN, 0, 0)]);
        assert_eq!(events(&mut s, n).last(), Some(&Event::new(FOCUS_OUT, 0, 0)));
        s.key(30, true);
        let mut keys = [Event::default(); 4];
        assert_eq!(s.take_keys(l, &mut keys), (1, false));
    }

    #[test]
    fn a_ring_keeps_the_last_events_and_says_what_it_lost() {
        let mut s = Scene::new();
        let (_, b) = two(&mut s);
        for n in 0..RING as u16 + 5 {
            s.key(n + 1, true);
        }
        let mut out = [Event::default(); 40];
        let (n, lost) = s.take_events(b, &mut out);
        assert!(lost);
        assert_eq!((n, out[0].code), (40, 6));
        let (n, lost) = s.take_events(b, &mut out);
        assert!(!lost);
        assert_eq!((n, out[0].code), (RING - 40, 46));
        assert_eq!(s.take_events(b, &mut out), (0, false));
    }

    #[test]
    fn the_manager_moves_raises_and_hides() {
        let mut s = Scene::new();
        let (a, b) = two(&mut s);
        s.begin();
        s.end(true);
        // Raise a over b.
        s.raise(a).unwrap();
        assert_eq!(s.hit(60, 60), Some(a));
        assert_eq!(s.begin(), Some(rect(0, 0, 100, 100)));
        s.end(true);
        // Move b: the damage is where it was and where it is.
        s.move_to(b, 200, 150).unwrap();
        assert_eq!(s.begin(), Some(rect(50, 50, 250, 200)));
        s.end(true);
        assert_eq!(s.hit(60, 60), Some(a));
        assert_eq!(s.hit(210, 160), Some(b));
        assert_eq!(s.move_to(b, 600, 0), Err(Refusal::Invalid));
        assert_eq!(s.move_to(9, 0, 0), Err(Refusal::Invalid));
        // Hide b, which has the focus: it passes to a, and b is not hit.
        assert_eq!(s.focus(), Some(b));
        s.set_visible(b, false).unwrap();
        assert_eq!(s.focus(), Some(a));
        assert_eq!(s.hit(210, 160), None);
        assert_eq!(s.begin(), Some(rect(200, 150, 100, 100)));
        s.end(true);
        s.set_visible(b, true).unwrap();
        assert_eq!(s.hit(210, 160), Some(b));
        // The window of the first revision does not move.
        let l = s.create(9, 9, SCREEN, true, 0b11).unwrap();
        assert_eq!(s.move_to(l, 0, 0), Err(Refusal::NotAllowed));
    }

    #[test]
    fn inject_is_the_device_for_keys_moves_and_buttons() {
        let mut s = Scene::new();
        let (a, b) = two(&mut s);
        s.inject(Event::new(KEY, 30, 1));
        s.inject(Event::at(MOVE, 0, 0, 10, 10));
        s.inject(Event::at(BUTTON, 0x110, 1, 0, 0));
        s.inject(Event::new(FOCUS_IN, 0, 0));
        assert_eq!(s.focus(), Some(a));
        assert_eq!(events(&mut s, b)[0], Event::new(KEY, 30, 1));
    }

    #[test]
    fn an_alpha_window_lies_over_what_is_below_and_the_pointer_over_both() {
        let mut s = Scene::new();
        let a = make(&mut s, 1, 1, rect(0, 0, 20, 20), 1);
        let b = s.create(2, 2, rect(10, 10, 20, 20), false, 0).unwrap();
        s.set_format(b, Format::Argb);
        s.attach(b, 1, 80).unwrap();
        // b: a point of alpha 0x80 whose colour is premultiplied, 0x40 in
        // every byte but the alpha.
        let mut half = vec![0x40u8; 20 * 20 * 4];
        for p in half.chunks_mut(4) {
            p[3] = 0x80;
        }
        let mut src = flat(&[(a, 0, 0x80, 20 * 20 * 4)]);
        src.0[b * BUFFERS] = half;
        let mut fb = screen();
        s.post(a, 0, &[]).unwrap();
        s.post(b, 0, &[]).unwrap();
        // A frame with an alpha window in it is made in bands of
        // the points the prices allow the layers: 30 wide, a copy and a
        // layer over it, so the most lines of a band.
        let d = s.begin().unwrap();
        assert_eq!(d, rect(0, 0, 30, 30));
        let first = compose(&s, d, Band::default(), &mut fb, &src, &mut Plain);
        assert_eq!(
            first,
            Band {
                row: s.tile(d).1,
                col: 0
            }
        );
        assert_eq!(first.row, BAND_ROWS);
        draw(&s, d, &mut fb, &src);
        s.end(true);
        // Only a: 0x80. Over a: 0x40 + 0x80 * 0x7F / 255 = 0x80.
        assert_eq!(at(&fb, 5, 5), 0x80);
        assert_eq!(at(&fb, 15, 15), 0x40 + (0x80u32 * 0x7F / 255) as u8);
        // Over black: 0x40.
        assert_eq!(at(&fb, 25, 25), 0x40);
        assert_eq!(at(&fb, 25, 5), 0);
        // The pointer's picture on top: its '#' is opaque black.
        s.pointer_to(2, 2);
        let d = s.begin().unwrap();
        draw(&s, d, &mut fb, &src);
        s.end(true);
        assert_eq!(at(&fb, 2, 2), 0);
        assert_eq!(at(&fb, 3, 4), 0xFF);
    }

    /// A raster that only counts what a band would cost pixman: the
    /// calls and the ticks the model of `Scene::tile` gives them.
    #[derive(Default)]
    struct Cost {
        /// Ticks of the calls.
        calls: u32,
        /// Hundredths of a tick.
        centi: u32,
    }

    impl Cost {
        fn ticks(&self) -> u32 {
            self.centi.div_ceil(100)
        }
    }

    impl Raster for Cost {
        fn black(&mut self, _: &mut [u8], r: Rect) {
            self.calls += FILL.call;
            self.centi += FILL.row * r.h + FILL.point * r.w * r.h;
        }

        fn blit(
            &mut self,
            _: &mut [u8],
            _: &[u8],
            _: u32,
            _: Format,
            _: (u32, u32),
            _: (u32, u32),
            _: (u32, u32),
            area: (u32, u32),
            over: bool,
        ) {
            let p = if over { OVER } else { OPAQUE };
            self.calls += p.call;
            self.centi += p.row * area.1 + p.point * area.0 * area.1;
        }
    }

    /// The most ticks one band of the frame over `d` costs, by the model.
    fn worst_band(s: &Scene, d: Rect, src: &impl Source) -> (u32, u32) {
        let mut fb = screen();
        let mut at = Band { row: d.y, col: 0 };
        let (mut worst, mut bands) = (0, 0);
        while at.row < d.y + d.h {
            let mut cost = Cost::default();
            at = compose(s, d, at, &mut fb, src, &mut cost);
            worst = worst.max(cost.calls + cost.ticks());
            bands += 1;
        }
        (worst, bands)
    }

    #[test]
    fn a_band_holds_the_points_the_ticks_of_its_layers_allow() {
        let mut s = Scene::new();
        let a = s.create(1, 1, SCREEN, true, 0).unwrap();
        s.flush(a, SCREEN).unwrap();
        let d = s.begin().unwrap();
        s.end(true);
        // One window that covers the damage: lines of the width.
        // (a copy of a point is 1.58 in the model, with a call of 897, a fixed
        // term of 102 and a row of 63: 12 lines of 640; 13 lines would cost 15 026).
        assert_eq!(s.tile(d), (640, 12));
        // The pointer over it: a layer laid over others costs more a point and
        // a line, so the band holds fewer lines of the width.
        s.pointer_to(5, 5);
        let (w, rows) = s.tile(d);
        assert_eq!(w, 640);
        assert!((1..13).contains(&rows), "{rows}");
        // A damage nothing covers starts black: fewer lines.
        let mut t = Scene::new();
        let b = t.create(1, 1, rect(10, 10, 50, 50), true, 0).unwrap();
        t.flush(b, rect(0, 0, 50, 50)).unwrap();
        t.begin().unwrap();
        assert_eq!(t.tile(rect(10, 10, 50, 50)).1, BAND_ROWS);
        assert!(t.tile(rect(0, 0, 640, 400)).1 < BAND_ROWS);
    }

    /// The windows of the overload: eight of ARGB8888, 320 by 200 on one place,
    /// two contexts of four.
    fn eight_windows(s: &mut Scene, n: usize) {
        for i in 0..n {
            let r = rect(100, 100, 320, 200);
            let w = s.create(i as u64 + 1, 1 + (i / PER_CONTEXT) as u64, r, false, 0);
            let w = w.unwrap();
            s.set_format(w, Format::Argb);
            s.attach(w, 2, 320 * 4).unwrap();
            s.post(w, 0, &[]).unwrap();
        }
        let _ = s.begin().unwrap();
        s.end(true);
    }

    /// What the model charges for a band of the size `tile` gives: the layers'
    /// calls, rows and points, the term of each layer after the first, and the
    /// black.
    fn band_cost(s: &Scene, d: Rect, over: u32) -> u64 {
        let (w, h) = s.tile(d);
        // The prices of a row and of a point are hundredths of a tick: the sum
        // is in hundredths, which the band's size is made in.
        let price = |p: Price| {
            u64::from(p.call) * 100
                + u64::from(p.row) * u64::from(h)
                + u64::from(p.point) * u64::from(w) * u64::from(h)
        };
        (u64::from(over) * price(OVER)
            + price(FILL)
            + u64::from(BAND_FIXED) * 100
            + u64::from(LAYER) * 100 * u64::from(over.saturating_sub(1)))
        .div_ceil(100)
    }

    #[test]
    fn a_band_of_eight_windows_on_one_place_is_under_the_limit_by_the_model() {
        for n in 1..=8usize {
            let mut s = Scene::new();
            eight_windows(&mut s, n);
            let d = rect(100, 100, 320, 200);
            let cost = band_cost(&s, d, n as u32);
            assert!(cost <= u64::from(BAND_TICKS), "{n} windows: {cost}");
        }
        // The band is narrower with more layers: the term and the calls of each.
        let width_of = |n: usize| {
            let mut s = Scene::new();
            eight_windows(&mut s, n);
            s.tile(rect(100, 100, 320, 200))
        };
        let (w8, h8) = width_of(8);
        assert_eq!(h8, 1, "eight layers make a part of a line");
        // By the measured terms eight layers get 96 points of a line (a frame of the
        // 320 by 200 windows is 4 bands a line, 800 in all; 151 points and 600
        // bands before the terms).
        assert_eq!(w8, 96);
        let (w4, _) = width_of(4);
        assert!(w8 < w4);
        // Without the term of a layer the band would be this wide: the term is
        // charged.
        let calls = OVER.call * 8 + FILL.call;
        let no_term = band_size(
            calls,
            OVER.row * 8 + FILL.row,
            OVER.point * 8 + FILL.point,
            320,
        );
        assert!(w8 < no_term.0, "{w8} {}", no_term.0);
    }

    /// The bands of layers the probes measured under -icount (the greatest
    /// ticks of a whole band as `compose` makes it: the black and the layers
    /// laid over each other on the same rows): the model with the term of a layer
    /// is at or above every one.
    #[test]
    fn the_model_with_the_term_covers_the_measured_bands_of_layers() {
        // (layers, width, height, greatest ticks).
        let measured = [
            (1u32, 150u32, 1u32, 2_187u64),
            (1, 150, 4, 4_913),
            (1, 16, 1, 1_565),
            (1, 64, 1, 1_787),
            (1, 76, 8, 5_689),
            (1, 8, 8, 1_647),
            (2, 150, 1, 3_980),
            (2, 150, 4, 9_195),
            (2, 76, 8, 10_647),
            (4, 150, 1, 7_620),
            (4, 150, 4, 17_813),
            (4, 76, 8, 20_617),
            (8, 150, 1, 15_116),
            (8, 150, 4, 35_265),
            (8, 16, 1, 10_483),
            (8, 64, 1, 12_133),
            (8, 76, 8, 40_773),
            (8, 8, 8, 10_733),
        ];
        let price = |p: Price, w: u32, h: u32| {
            u64::from(p.call)
                + (u64::from(p.row) * u64::from(h)
                    + u64::from(p.point) * u64::from(w) * u64::from(h))
                .div_ceil(100)
        };
        let mut short = 0u64;
        for (n, w, h, ticks) in measured {
            let model = price(FILL, w, h)
                + u64::from(n) * price(OVER, w, h)
                + u64::from(LAYER) * u64::from(n - 1);
            // A band of one layer 16 or 64 points wide is under its measure by 88
            // and 53 ticks by the prices alone: the fixed term of a band covers it.
            assert!(
                model + u64::from(BAND_FIXED) >= ticks,
                "{n} layers {w}x{h}: {model} + {BAND_FIXED} < {ticks}"
            );
            // The greatest shortfall under the prices is the measure of the fixed
            // term, and the constant covers it with the margin.
            short = short.max(ticks.saturating_sub(model));
        }
        assert_eq!(short, u64::from(BAND_FIXED_MEASURED));
        assert_eq!(BAND_FIXED, with_margin(BAND_FIXED_MEASURED));
    }

    /// The term of a layer covers its measure with the margin.
    #[test]
    fn the_term_of_a_layer_covers_its_measure_with_the_margin() {
        assert_eq!(LAYER, with_margin(LAYER_MEASURED));
        assert!(u64::from(LAYER) * 100 >= u64::from(LAYER_MEASURED) * 115);
    }

    /// Every constant covers its measure with the margin, and the table says
    /// which: a measure above its constant (a margin of nothing, an old
    /// constant) fails here.
    #[test]
    fn the_constants_cover_the_measures_with_the_margin() {
        let covers = |constant: u32, measured: u32| {
            u64::from(constant) * 100 >= u64::from(measured) * u64::from(100 + MARGIN_PERCENT)
        };
        for p in PRICES {
            assert!(covers(p.call, p.call_measured), "{} call", p.kind);
            assert!(covers(p.row, p.row_measured), "{} row", p.kind);
            assert!(covers(p.point, p.point_measured), "{} point", p.kind);
            assert_eq!(p.call, with_margin(p.call_measured), "{}", p.kind);
            assert_eq!(p.row, with_margin(p.row_measured), "{}", p.kind);
            assert_eq!(p.point, with_margin(p.point_measured), "{}", p.kind);
        }
        // Every entry is a measure of the fit, the same in both probes, and the
        // costs of the large operations of the probes' scenes (the least all-in
        // figures: a copy 1.56 to 1.62 a point at 3 840 to 5 120 points, a layer
        // laid over others 5.78 at 480 points, the black 0.44 to 0.46) are under
        // the model with the constants: the model errs only high.
        assert!(PRICES.iter().all(|p| !p.row_estimate && !p.point_estimate));
        let model = |p: Price, w: u32, h: u32| -> u64 {
            u64::from(p.call)
                + (u64::from(p.row) * u64::from(h)
                    + u64::from(p.point) * u64::from(w) * u64::from(h))
                .div_ceil(100)
        };
        // (kind, width, height, ticks a hundred points of the live least).
        for (p, w, h, per_hundred) in [
            (OPAQUE, 640u32, 8u32, 156u32),
            (OPAQUE, 640, 6, 162),
            (OVER, 480, 1, 578),
            (OVER, 160, 3, 578),
            (FILL, 640, 8, 46),
            (FILL, 640, 8, 44),
        ] {
            let live = u64::from(per_hundred) * u64::from(w) * u64::from(h) / 100;
            assert!(
                model(p, w, h) >= live,
                "{} {w}x{h}: {} < {live}",
                p.kind,
                model(p, w, h)
            );
        }
        // The shapes of the width of the screen, the greatest of each over the
        // four offsets (the refit of the probes): the model is above them.
        for (p, w, h, greatest) in [
            (OPAQUE, 640u32, 1u32, 1_715u64),
            (OPAQUE, 640, 8, 8_265),
            (OPAQUE, 640, 13, 12_945),
            (OVER, 640, 13, 38_620),
            (FILL, 640, 13, 3_641),
        ] {
            assert!(
                model(p, w, h) >= greatest + greatest * 15 / 100,
                "{} {w}x{h}: {} below {greatest} with the margin",
                p.kind,
                model(p, w, h)
            );
        }
        // The margin of nothing would leave a measure above the constant.
        assert!(with_margin(190) > 190);
    }

    /// Eight windows with an alpha over the whole screen, the worst case of a
    /// band: by the model no band costs more than BAND_TICKS, and a frame of
    /// the whole screen of one copy is made in the bands the constants give.
    #[test]
    fn eight_translucent_windows_make_bands_within_the_band_ticks() {
        let mut s = Scene::new();
        let mut src = flat(&[]);
        for k in 0..MAX_WINDOWS {
            let i = s
                .create(k as u64 + 1, 1 + (k / PER_CONTEXT) as u64, SCREEN, false, 0)
                .unwrap();
            s.set_format(i, Format::Argb);
            s.attach(i, 1, 2560).unwrap();
            src.0[i * BUFFERS] = vec![0x10; 2560 * 400];
            s.post(i, 0, &[]).unwrap();
        }
        s.begin().unwrap();
        s.end(true);
        let (worst, bands) = worst_band(&s, SCREEN, &src);
        assert!(
            worst <= BAND_TICKS,
            "a band of {worst} ticks by the model, {bands} bands"
        );
    }

    #[test]
    fn a_frame_of_one_copy_of_the_whole_screen_is_made_in_few_bands() {
        let mut s = Scene::new();
        let a = s.create(1, 1, SCREEN, true, 0).unwrap();
        s.flush(a, SCREEN).unwrap();
        let d = s.begin().unwrap();
        s.end(true);
        let src = flat(&[(a, 0, 0x10, (STRIDE * HEIGHT) as usize)]);
        let (worst, bands) = worst_band(&s, d, &src);
        assert!(worst <= BAND_TICKS, "{worst}");
        // The bands of the whole screen, by the prices: loud when it passes 45.
        assert!(bands <= 45, "{bands} bands: the full phase is no promise");
        assert_eq!(bands, full_screen_bands());
        // With the fixed term of a band a copy over the whole width is 12 lines
        // (13 cost 15 026 by the prices): 34 bands.
        assert_eq!(bands, 34);
    }

    /// A window with an interval of 2, taken at period 3, is awaited at 5.
    /// Another window's post brings a frame at 4: the frame leaves the first
    /// window's buffer posted, with its damage, and says the start it is due.
    #[test]
    fn a_frame_before_the_start_of_a_window_with_an_interval_leaves_it_posted() {
        let clock = frame::Clock::new(0, 1_000);
        let mut s = Scene::new();
        let a = s.create(1, 1, rect(0, 0, 40, 40), false, 0).unwrap();
        let b = s.create(2, 2, rect(100, 100, 40, 40), false, 0).unwrap();
        for i in [a, b] {
            s.attach(i, 2, 160).unwrap();
        }
        assert!(s.pace_mut(b).unwrap().set_interval(2));
        s.pace_mut(b).unwrap().took(3);
        // B posts in period 3, early: due at 5, so its damage waits in the window.
        let (_, due) = s.post_paced(b, 0, &[], &clock, 3_200).unwrap();
        assert_eq!(due, Some(5));
        // A posts in period 3 (no interval): a frame at 4 takes A alone.
        let (_, due) = s.post_paced(a, 0, &[], &clock, 3_500).unwrap();
        assert_eq!(due, None);
        assert!(s.damaged());
        assert_eq!(s.begin_at(4), Some(rect(0, 0, 40, 40)));
        s.end(true);
        assert_eq!(s.held_until(), Some(5));
        // (B's one taking is the setup's, at period 3.)
        assert_eq!((s.pace(a).unwrap().taken, s.pace(b).unwrap().taken), (1, 1));
        // At 5 the held damage joins and B is taken, with no new post.
        let d = s.begin_at(5).unwrap();
        assert!(d.x <= 100 && d.y <= 100 && d.x + d.w >= 140 && d.y + d.h >= 140);
        s.end(true);
        assert_eq!(s.held_until(), None);
        assert_eq!(s.pace(b).unwrap().taken, 2);
        // A post counts in the window's record whatever the clock.
        let r = s.pace(a).unwrap().record(a as u32);
        assert_eq!((r.posts, r.taken), (1, 1));
        s.post(b, 1, &[]).unwrap();
        assert_eq!(s.pace(b).unwrap().posts, 2);
    }

    /// A taking with nothing to take that leaves a window held: the scene says
    /// the start it is due at, the pacer is told to hold it, and the next
    /// arming stands at that start, where the buffer is taken with no new post.
    /// The scene is busy meanwhile, so a probe that waits for the screen to
    /// settle does not decide it has.
    #[test]
    fn a_taking_with_nothing_to_take_leaves_the_held_window_a_timer() {
        let mut p = frame::Pacer::new(0, 1_000, 52);
        let clock = *p.clock();
        let mut s = Scene::new();
        let b = s.create(2, 2, rect(100, 100, 40, 40), false, 0).unwrap();
        s.attach(b, 2, 160).unwrap();
        assert!(s.pace_mut(b).unwrap().set_interval(2));
        s.pace_mut(b).unwrap().took(3); // awaited at 5
        assert!(!s.busy());
        // B posts early, in period 3: its damage waits in the window.
        let (_, due) = s.post_paced(b, 0, &[], &clock, 3_200).unwrap();
        assert_eq!(due, Some(5));
        assert!(!s.damaged() && s.busy());
        // Another change (a window gone, the manager) brings a taking at 4.
        assert_eq!(p.change(3_500, None), frame::Wake::At(4_000));
        assert_eq!(p.fire(4_000), frame::Fire::Take(4));
        // Nothing is taken, and the scene says B is due at 5.
        assert_eq!(s.begin_at(4), None);
        assert_eq!(s.held_until(), Some(5));
        assert!(s.busy());
        p.hold(s.held_until().unwrap());
        assert_eq!(p.nothing_taken(4_100), frame::Wake::At(5_000));
        // At 5 the buffer is taken without a new post, and the scene settles.
        assert_eq!(p.fire(5_000), frame::Fire::Take(5));
        assert!(s.begin_at(5).is_some());
        assert_eq!(s.held_until(), None);
        s.end(true);
        assert!(!s.busy());
        assert_eq!(s.pace(b).unwrap().taken, 2);
    }

    /// One opaque window of XRGB8888 over the whole screen covers the damage of
    /// a frame of the whole screen, so no black is charged and a band holds
    /// thirteen lines (31 bands); a window one column short does not cover it,
    /// the black is charged too, and a band holds nine lines (45 bands).
    #[test]
    fn a_window_that_covers_the_damage_pays_no_black() {
        let bands = |w: u32| {
            let mut s = Scene::new();
            let a = s.create(1, 1, rect(0, 0, w, 400), false, 0).unwrap();
            s.attach(a, 1, w * 4).unwrap();
            s.post(a, 0, &[]).unwrap();
            s.begin().unwrap();
            s.end(true);
            // The whole screen changes: the frame's damage is the screen.
            s.add_damage(SCREEN);
            let d = s.begin().unwrap();
            assert_eq!(d, SCREEN);
            let rows = s.tile(d).1;
            s.end(true);
            (rows, 400u32.div_ceil(rows))
        };
        let (rows, n) = bands(640);
        assert_eq!((rows, n), (13, 31));
        assert_eq!(n, full_screen_bands());
        // One column short: the black is charged.
        let (rows, n) = bands(639);
        assert_eq!((rows, n), (9, 45));
    }

    use proto_gpu::{PIPELINE_CURSOR, SOURCE_CURSOR};

    /// A scene with a window over the whole screen, shown and settled, and
    /// the pointer on the device's cursor pipeline when `plane`.
    fn settled(plane: bool) -> Scene {
        let mut s = Scene::new();
        let a = s.create(1, 1, SCREEN, true, 0).unwrap();
        s.flush(a, SCREEN).unwrap();
        s.begin().unwrap();
        s.end(true);
        if plane {
            s.set_cursor_plane(Some((PIPELINE_CURSOR, SOURCE_CURSOR)));
        }
        s
    }

    #[test]
    fn on_the_cursor_pipeline_a_move_of_the_pointer_damages_nothing() {
        let mut s = settled(true);
        s.pointer_to(10, 10);
        s.pointer_to(300, 200);
        assert!(!s.busy());
        assert_eq!(s.begin(), None);
        assert_eq!(s.pointer(), Some((300, 200)));
        // Without the pipeline the move damages both places, as it did.
        let mut t = settled(false);
        t.pointer_to(10, 10);
        assert!(t.busy());
        t.begin().unwrap();
        t.end(true);
        t.pointer_to(300, 200);
        assert_eq!(
            t.begin(),
            Some(rect(10, 10, 300 + CURSOR_W - 10, 200 + CURSOR_H - 10))
        );
    }

    #[test]
    fn on_the_cursor_pipeline_the_frame_draws_no_pointer_and_prices_none() {
        let mut s = settled(true);
        s.pointer_to(5, 5);
        // The tile of a frame over the pointer is that of a copy alone.
        assert_eq!(s.tile(SCREEN), (640, 12));
        s.add_damage(SCREEN);
        let d = s.begin().unwrap();
        let src = flat(&[(0, 0, 0x80, 640 * 4 * 400)]);
        let mut fb = screen();
        draw(&s, d, &mut fb, &src);
        // The arrow's '#' at (0, 0) of its picture would be black here.
        assert_eq!(at(&fb, 5, 5), 0x80);
        assert_eq!(at(&fb, 6, 6), 0x80);
        // The same scene without the pipeline draws it.
        let mut t = settled(false);
        t.pointer_to(5, 5);
        t.begin().unwrap();
        t.end(true);
        t.add_damage(SCREEN);
        let d = t.begin().unwrap();
        let mut fb = screen();
        draw(&t, d, &mut fb, &src);
        assert_eq!(at(&fb, 5, 5), 0);
    }

    #[test]
    fn the_cursor_is_hidden_until_the_pointer_is_seen_and_then_one_row_per_ask() {
        let mut s = settled(true);
        // Nothing seen: the device shows nothing, no row.
        assert_eq!(s.cursor_row(), None);
        s.pointer_to(10, 20);
        s.pointer_to(30, 40);
        s.pointer_to(50, 60);
        // Three moves before the ask: one row, the last place.
        let row = s.cursor_row().unwrap();
        assert_eq!(
            row,
            LayerRow::cursor(PIPELINE_CURSOR, SOURCE_CURSOR, 50, 60, CURSOR_HOT)
        );
        // Until the driver took it the same row is due again (a refusal
        // is asked again at the next step).
        assert_eq!(s.cursor_row(), Some(row));
        s.cursor_shown(&row);
        assert_eq!(s.cursor_row(), None);
        // The same place again is no move.
        s.pointer_to(50, 60);
        assert_eq!(s.cursor_row(), None);
        s.pointer_to(51, 60);
        assert_eq!(s.cursor_row().map(|r| (r.x, r.y)), Some((51, 60)));
    }

    #[test]
    fn a_refused_row_gives_the_pointer_back_to_the_frame_and_no_row_follows() {
        // Never shown on the device: nothing to hide, the frame draws it.
        let mut s = settled(true);
        s.pointer_to(10, 10);
        assert!(s.cursor_row().is_some());
        assert_eq!(s.cursor_refused(), None);
        assert!(!s.cursor_plane());
        assert_eq!(s.cursor_row(), None);
        s.pointer_to(30, 30);
        assert_eq!(s.cursor_row(), None);
        // The arrow's place is damaged at once, and a later move damages
        // both places again.
        assert_eq!(
            s.begin(),
            Some(rect(10, 10, 30 + CURSOR_W - 10, 30 + CURSOR_H - 10))
        );
        // The frame draws the pointer from now on.
        assert_eq!(s.drawn_pointer(), Some((30, 30)));
    }

    #[test]
    fn a_refusal_after_the_cursor_was_shown_hides_it_and_it_is_in_one_place_only() {
        let mut s = settled(true);
        s.pointer_to(10, 10);
        let row = s.cursor_row().unwrap();
        s.cursor_shown(&row);
        s.pointer_to(20, 20);
        assert_eq!(s.drawn_pointer(), None);
        assert_eq!(s.cursor_refused(), Some(LayerRow::off(PIPELINE_CURSOR)));
        assert_eq!(s.drawn_pointer(), Some((20, 20)));
        assert_eq!(s.cursor_row(), None);
        // A second refusal has nothing to say.
        assert_eq!(s.cursor_refused(), None);
        // The picture the device showed is painted over, and the new one
        // drawn, by the next frame.
        assert!(s.busy());
    }

    #[test]
    fn the_cursor_rows_pass_the_driver_check() {
        let mut s = settled(true);
        for (x, y) in [(0, 0), (639, 399), (-5, 900)] {
            s.pointer_to(x, y);
            let row = s.cursor_row().unwrap();
            let layers = proto_gpu::Layers::new(&[row]).unwrap();
            assert_eq!(layers.check_virtio(), Ok(()), "{x} {y}");
            s.cursor_shown(&row);
        }
    }

    #[test]
    fn a_cursor_row_hides_when_the_pointer_is_unseen_but_shown() {
        let mut s = settled(true);
        s.pointer_to(1, 1);
        let row = s.cursor_row().unwrap();
        s.cursor_shown(&row);
        s.pointer = None;
        let off = s.cursor_row().unwrap();
        assert_eq!(off, LayerRow::off(PIPELINE_CURSOR));
        s.cursor_shown(&off);
        assert_eq!(s.cursor_row(), None);
    }

    #[test]
    fn without_a_cursor_pipeline_there_is_no_row_and_the_pointer_is_drawn() {
        let mut s = settled(false);
        s.pointer_to(10, 10);
        assert_eq!(s.cursor_row(), None);
        assert!(!s.cursor_plane());
        assert!(s.busy());
    }

    #[test]
    fn taking_the_pipeline_paints_over_the_picture_the_frame_drew() {
        let mut s = settled(false);
        s.pointer_to(10, 10);
        s.begin().unwrap();
        s.end(true);
        s.set_cursor_plane(Some((PIPELINE_CURSOR, SOURCE_CURSOR)));
        assert_eq!(s.begin(), Some(rect(10, 10, CURSOR_W, CURSOR_H)));
        s.end(true);
        // The device's cursor shows nothing yet: the next ask brings it.
        assert!(s.cursor_row().is_some());
    }

    /// A scene whose display can show the pool, with the pointer on the
    /// cursor pipeline when `plane`.
    fn direct(plane: bool) -> Scene {
        let mut s = Scene::new();
        s.set_direct(true);
        if plane {
            s.set_cursor_plane(Some((PIPELINE_CURSOR, SOURCE_CURSOR)));
        }
        s
    }

    /// A window of the first revision over the whole screen, flushed.
    fn legacy_window(s: &mut Scene) -> usize {
        let a = s.create(1, 1, SCREEN, true, 0).unwrap();
        s.flush(a, SCREEN).unwrap();
        a
    }

    /// Takes what is posted and ends the frame as shown, as the service does
    /// (a direct frame has no band).
    fn settle(s: &mut Scene) {
        let _ = s.begin().expect("a frame");
        s.end(true);
    }

    /// A window of the second revision at `r`, posted and shown.
    fn shown_window(s: &mut Scene, label: u64, r: Rect) -> usize {
        let i = make(s, label, 2, r, 1);
        s.post(i, 0, &[]).unwrap();
        settle(s);
        i
    }

    #[test]
    fn open_of_the_pool_is_decided_by_references_dirt_and_clearing() {
        // base 5 references.
        assert_eq!(pool_open(5, 5, false, false, false), PoolOpen::Go);
        assert_eq!(pool_open(6, 5, false, false, false), PoolOpen::Busy);
        // Busy comes before everything else.
        assert_eq!(pool_open(7, 5, true, true, true), PoolOpen::Busy);
        assert_eq!(pool_open(5, 5, true, true, false), PoolOpen::Clearing);
        assert_eq!(pool_open(5, 5, false, false, true), PoolOpen::Clearing);
        assert_eq!(pool_open(5, 5, true, false, false), PoolOpen::StartClearing);
    }

    #[test]
    fn a_program_that_writes_after_the_clearing_leaves_the_pool_dirty() {
        // The window went and a program kept its mapping: BUSY, and the
        // clearing that runs meanwhile ends with the copy out.
        let (base, mut dirty) = (5, true);
        assert_eq!(pool_open(6, base, dirty, false, false), PoolOpen::Busy);
        dirty = dirty_after_clearing(6, base);
        assert!(dirty);
        // It writes, and exits: the pool is the service's again but dirty,
        // so OPEN clears it and does not give it.
        assert_eq!(
            pool_open(5, base, dirty, false, false),
            PoolOpen::StartClearing
        );
        // The clearing that ends with no copy out makes it clean.
        dirty = dirty_after_clearing(5, base);
        assert!(!dirty);
        assert_eq!(pool_open(5, base, dirty, false, false), PoolOpen::Go);
        // A copy given dirties it again (the caller sets the flag).
        assert_eq!(pool_open(6, base, true, false, false), PoolOpen::Busy);
    }

    #[test]
    fn the_decision_table_of_the_direct_frame() {
        // One window of the first revision over the whole screen.
        let mut s = direct(true);
        assert_eq!(s.plan(), Plan::Compose);
        let a = legacy_window(&mut s);
        settle(&mut s);
        assert_eq!(s.plan(), Plan::Bypass(a));
        // A shown window above it.
        let b = shown_window(&mut s, 2, rect(100, 50, 100, 100));
        assert_eq!(s.plan(), Plan::Compose);
        // The same window hidden: the window under it is the screen again.
        s.set_visible(b, false).unwrap();
        assert_eq!(s.plan(), Plan::Bypass(a));
        s.set_visible(b, true).unwrap();
        assert_eq!(s.plan(), Plan::Compose);
        // A window that went.
        s.destroy(b);
        assert_eq!(s.plan(), Plan::Bypass(a));
        // The display that cannot show the pool.
        s.set_direct(false);
        assert_eq!(s.plan(), Plan::Compose);
    }

    #[test]
    fn the_pointer_decides_by_where_it_is_drawn() {
        // On the cursor pipeline, seen or not: direct.
        let mut s = direct(true);
        let a = legacy_window(&mut s);
        settle(&mut s);
        assert_eq!(s.plan(), Plan::Bypass(a));
        s.pointer_to(10, 10);
        assert_eq!(s.plan(), Plan::Bypass(a));
        // Without a cursor pipeline a seen pointer is drawn in the frame,
        // which a direct frame would not hold; one not yet seen is not.
        let mut t = direct(false);
        let a = legacy_window(&mut t);
        settle(&mut t);
        assert_eq!(t.plan(), Plan::Bypass(a));
        t.pointer_to(10, 10);
        assert_eq!(t.plan(), Plan::Compose);
        // The driver refused the cursor row for good: the pointer is back in
        // the frame, and the rule reads false at once.
        let mut u = direct(true);
        let a = legacy_window(&mut u);
        settle(&mut u);
        u.pointer_to(30, 30);
        assert_eq!(u.plan(), Plan::Bypass(a));
        u.cursor_refused();
        assert_eq!(u.plan(), Plan::Compose);
        // A pointer that was never seen costs the rule nothing, refused or
        // not.
        let mut v = direct(true);
        let a = legacy_window(&mut v);
        settle(&mut v);
        v.cursor_refused();
        assert_eq!(v.plan(), Plan::Bypass(a));
    }

    #[test]
    fn a_window_that_is_not_an_opaque_one_of_the_first_revision_is_composed() {
        // A window of the second revision over the whole screen.
        let mut s = direct(true);
        shown_window(&mut s, 1, SCREEN);
        assert_eq!(s.plan(), Plan::Compose);
        // With an alpha.
        let mut s = direct(true);
        let i = make(&mut s, 1, 1, SCREEN, 1);
        s.set_format(i, Format::Argb);
        s.post(i, 0, &[]).unwrap();
        settle(&mut s);
        assert_eq!(s.plan(), Plan::Compose);
        // A window of the first revision whose format says alpha.
        let mut s = direct(true);
        let a = legacy_window(&mut s);
        s.set_format(a, Format::Argb);
        settle(&mut s);
        assert_eq!(s.plan(), Plan::Compose);
        // A window of the second revision under one of the first is not seen.
        let mut s = direct(true);
        shown_window(&mut s, 1, SCREEN);
        let a = legacy_window(&mut s);
        settle(&mut s);
        assert_eq!(s.plan(), Plan::Bypass(a));
        // And over it, it is the screen.
        shown_window(&mut s, 3, SCREEN);
        assert_eq!(s.plan(), Plan::Compose);
    }

    /// The bands a frame over `d` makes, counted as the service counts them.
    fn counted(s: &mut Scene, d: Rect, src: &impl Source) -> usize {
        let mut fb = screen();
        let n = draw(s, d, &mut fb, src);
        for _ in 0..n {
            s.band_done();
        }
        n
    }

    #[test]
    fn a_direct_frame_has_no_band_and_a_frame_that_returns_carries_the_whole_screen() {
        let mut s = direct(true);
        let a = legacy_window(&mut s);
        // Composed to direct: the changed area of the window, no band, and the
        // target is stale from here on.
        assert_eq!(s.begin(), Some(SCREEN));
        assert_eq!(s.frame_kind(), FrameKind::Bypass);
        assert!(s.stale());
        assert_eq!(s.primary(), Primary::Target);
        s.end(true);
        assert_eq!(
            (s.primary(), s.bypassed(), s.bands()),
            (Primary::Pool, 1, 0)
        );
        // Direct to direct: the damage alone, still no band.
        s.flush(a, rect(10, 10, 20, 20)).unwrap();
        assert_eq!(s.begin(), Some(rect(10, 10, 20, 20)));
        assert_eq!(s.frame_kind(), FrameKind::Bypass);
        s.end(true);
        assert_eq!((s.bypassed(), s.bands()), (2, 0));
        // A window above posts a small rectangle: the frame is a return, and
        // its area is the whole screen.
        let b = make(&mut s, 2, 2, rect(100, 50, 100, 100), 1);
        s.post(b, 0, &[]).unwrap();
        let d = s.begin().unwrap();
        assert_eq!(s.frame_kind(), FrameKind::Rebind);
        assert_eq!(d, SCREEN);
        // The screen shows the pool until the frame is shown.
        assert_eq!(s.primary(), Primary::Pool);
        assert!(!s.pool_idle());
        let src = flat(&[
            (0, 0, 0x40, (STRIDE * HEIGHT) as usize),
            (b, 0, 0x80, 100 * 4 * 100),
        ]);
        let n = counted(&mut s, d, &src);
        let whole = counted(&mut s, SCREEN, &src);
        assert_eq!(n, whole);
        s.end(true);
        assert_eq!(s.primary(), Primary::Target);
        assert!(!s.stale());
        assert_eq!(s.bands() as usize, n + whole);
        assert_eq!(s.bypassed(), 2);
        // Composed frames over the target are of their damage again.
        s.flush(a, rect(0, 0, 8, 8)).unwrap();
        assert_eq!(s.begin(), Some(rect(0, 0, 8, 8)));
        assert_eq!(s.frame_kind(), FrameKind::Compose);
        s.end(true);
        // The window above goes: the way back to the pool is direct again,
        // with the damage as it is (the driver transfers the whole pool when
        // the source changes, whatever the area says).
        s.destroy(b);
        s.flush(a, rect(0, 0, 8, 8)).unwrap();
        assert_eq!(s.begin(), Some(rect(0, 0, 200, 150)));
        assert_eq!(s.frame_kind(), FrameKind::Bypass);
        s.end(true);
        assert_eq!(s.bypassed(), 3);
    }

    #[test]
    fn a_frame_in_the_target_after_a_direct_one_is_whole_even_without_a_window_above() {
        // The pointer drawn into the frame again (the cursor was refused)
        // takes the screen back from the pool: the whole screen.
        let mut s = direct(true);
        legacy_window(&mut s);
        settle(&mut s);
        s.pointer_to(10, 10);
        assert_eq!(s.cursor_refused(), None);
        assert_eq!(s.begin(), Some(SCREEN));
        assert_eq!(s.frame_kind(), FrameKind::Rebind);
    }

    #[test]
    fn a_failed_frame_keeps_the_binding_and_the_stale_target() {
        let mut s = direct(true);
        let a = legacy_window(&mut s);
        // A failed frame into the direct state binds nothing.
        s.begin().unwrap();
        s.end(false);
        assert_eq!((s.primary(), s.bypassed()), (Primary::Target, 0));
        assert!(s.stale());
        // The next composed frame is whole for it.
        s.flush(a, rect(0, 0, 8, 8)).unwrap();
        s.set_direct(false);
        assert_eq!(s.begin(), Some(SCREEN));
        assert_eq!(s.frame_kind(), FrameKind::Compose);
        s.end(false);
        assert!(s.stale());
        s.add_damage(rect(0, 0, 8, 8));
        assert_eq!(s.begin(), Some(SCREEN));
        s.end(true);
        assert!(!s.stale());
        s.add_damage(rect(0, 0, 8, 8));
        assert_eq!(s.begin(), Some(rect(0, 0, 8, 8)));
    }

    #[test]
    fn the_pool_is_cleared_after_the_frame_that_unbound_it_is_shown() {
        // The window goes while the screen shows its pool: the frame that
        // returns the screen to the target comes first.
        let mut s = direct(true);
        let a = legacy_window(&mut s);
        settle(&mut s);
        assert_eq!(s.primary(), Primary::Pool);
        s.destroy(a);
        assert!(!s.take_pool_clear());
        assert_eq!(s.begin(), Some(SCREEN));
        assert_eq!(s.frame_kind(), FrameKind::Rebind);
        assert!(!s.take_pool_clear());
        // A frame that failed unbound nothing.
        s.end(false);
        assert!(!s.take_pool_clear());
        s.add_damage(SCREEN);
        s.begin().unwrap();
        assert!(!s.take_pool_clear());
        s.end(true);
        assert!(s.take_pool_clear());
        // Once.
        assert!(!s.take_pool_clear());
    }

    #[test]
    fn the_pool_is_cleared_at_once_when_the_screen_does_not_show_it() {
        // The window was covered, so the target is the screen.
        let mut s = direct(true);
        let a = legacy_window(&mut s);
        settle(&mut s);
        shown_window(&mut s, 2, rect(0, 0, 50, 50));
        assert_eq!(s.primary(), Primary::Target);
        s.destroy(a);
        assert!(s.take_pool_clear());
        // A window that was never shown.
        let mut t = direct(true);
        let a = t.create(1, 1, SCREEN, true, 0).unwrap();
        t.destroy(a);
        assert!(t.take_pool_clear());
    }

    #[test]
    fn a_direct_frame_on_its_way_holds_the_pool() {
        let mut s = direct(true);
        let a = legacy_window(&mut s);
        s.begin().unwrap();
        s.destroy(a);
        // The device may read the pool while this frame is its job.
        assert!(!s.take_pool_clear());
        s.end(true);
        assert!(!s.take_pool_clear());
        s.begin().unwrap();
        s.end(true);
        assert!(s.take_pool_clear());
    }

    #[test]
    fn the_counters_count_shown_frames_and_bands() {
        let mut s = direct(true);
        let a = legacy_window(&mut s);
        settle(&mut s);
        for _ in 0..3 {
            s.flush(a, rect(0, 0, 4, 4)).unwrap();
            settle(&mut s);
        }
        assert_eq!((s.bypassed(), s.bands(), s.frames()), (4, 0, 4));
        // A failed direct frame is no frame and no bypass.
        s.flush(a, rect(0, 0, 4, 4)).unwrap();
        s.begin().unwrap();
        s.end(false);
        assert_eq!((s.bypassed(), s.frames()), (4, 4));
        // A composed frame counts its bands and no bypass.
        s.set_direct(false);
        s.add_damage(rect(0, 0, 64, 8));
        let d = s.begin().unwrap();
        let src = flat(&[(0, 0, 0x40, (STRIDE * HEIGHT) as usize)]);
        let n = counted(&mut s, d, &src);
        s.end(true);
        assert!(n >= 1);
        assert_eq!((s.bypassed(), s.bands() as usize), (4, n));
    }

    #[test]
    fn eight_windows_in_a_damage_make_bands_under_the_bound() {
        let mut s = Scene::new();
        let mut src = flat(&[]);
        // Eight windows, opaque and with an alpha in turn, staggered over
        // one another, two contexts of four.
        for k in 0..MAX_WINDOWS {
            let r = rect(100 + 7 * k as u32, 100 + 5 * k as u32, 300, 200);
            let i = s
                .create(k as u64 + 1, 1 + (k / PER_CONTEXT) as u64, r, false, 0)
                .unwrap();
            if k % 2 == 1 {
                s.set_format(i, Format::Argb);
            }
            s.attach(i, 1, 1200).unwrap();
            src.0[i * BUFFERS] = vec![0x10; 1200 * 200];
            s.post(i, 0, &[]).unwrap();
        }
        let d = s.begin().unwrap();
        s.end(true);
        assert_eq!(s.open(), 8);
        // The damage of the whole screen, every window in it.
        let (worst, bands) = worst_band(&s, SCREEN, &src);
        assert!(
            worst <= 16_500,
            "a band of {worst} ticks by the model, {bands} bands"
        );
        // One window's rectangle, the others under or over it.
        let (worst, _) = worst_band(&s, d, &src);
        assert!(worst <= 16_500, "{worst}");
        // The points of a band: far under what one window's copy holds.
        let (w, rows) = s.tile(SCREEN);
        assert!(w * rows < 640 * BAND_ROWS / 10, "{w} x {rows}");
    }

    #[test]
    fn a_wide_layer_is_made_in_bands_across_the_damage() {
        let mut s = Scene::new();
        let a = s.create(1, 1, SCREEN, true, 0).unwrap();
        let b = s.create(2, 2, rect(0, 0, 600, 100), false, 0).unwrap();
        s.set_format(b, Format::Argb);
        s.attach(b, 1, 2400).unwrap();
        s.flush(a, SCREEN).unwrap();
        s.post(b, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        let damage = rect(0, 0, 600, 100);
        let (w, rows) = s.tile(damage);
        assert!(w <= 600 && (1..100).contains(&rows), "{w} x {rows}");
        let src = flat(&[
            (a, 0, 7, (STRIDE * HEIGHT) as usize),
            (b, 0, 0x10, 2400 * 100),
        ]);
        let mut fb = screen();
        let first = compose(&s, damage, Band::default(), &mut fb, &src, &mut Plain);
        // The band is the whole width and a few lines.
        assert_eq!((w, first), (600, Band { row: rows, col: 0 }));
        let (worst, _) = worst_band(&s, damage, &src);
        assert!(worst <= 16_500);
    }

    #[test]
    fn with_a_manager_the_first_frame_gives_no_focus_and_create_is_told() {
        let mut s = Scene::new();
        s.set_manager(true);
        let a = make(&mut s, 1, 1, rect(0, 0, 100, 100), 1);
        s.post(a, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        assert_eq!(s.focus(), None);
        assert!(events(&mut s, a).is_empty());
        let mut out = [Event::default(); 4];
        let (n, _) = s.take_manager_events(&mut out);
        assert_eq!(&out[..n], [Event::new(CREATE, a as u16, 0)]);
        // The manager decides.
        s.focus_on(a).unwrap();
        assert_eq!(events(&mut s, a), [Event::new(FOCUS_IN, 0, 0)]);
        // Without it the first frame decides again.
        s.set_manager(false);
        let b = make(&mut s, 2, 2, rect(50, 50, 10, 10), 1);
        s.post(b, 0, &[]).unwrap();
        s.begin().unwrap();
        assert_eq!(s.focus(), Some(b));
    }
}
