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

pub mod damage;
#[cfg(test)]
mod element_tests;
pub mod elements;
pub mod fit;
pub mod frame;
pub mod prep;
#[cfg(test)]
mod top_tests;

/// The stack of the service in the images (`COMP_STACK_SIZE` of xtask, which a test
/// holds to this): the steps build paints the part of it that `px::stack` scans.
pub const STACK_BYTES: usize = 128 * 1024;
#[cfg(test)]
mod measures;

use damage::DamageList;
use elements::{Def, Fault, Shape};
use proto_comp::{
    BUFFERS, BUTTON, CLOSE, CLOSE_REQUEST, CONFIGURE, CREATE, Element, Event, FOCUS_IN, FOCUS_OUT,
    KEY, MAX_ELEMENTS, MAX_RECTS, MOVE, RESIZED, RING, Rect, STATES, SceneCommit, TEXT_MAX, TITLE,
    union,
};
use proto_gpu::{HEIGHT, LayerRow, STRIDE, WIDTH};

/// The windows at once, and the windows of one context.
pub const MAX_WINDOWS: usize = 16;
// The places a mask of `u16` names (`Scene::create`).
const _: () = assert!(MAX_WINDOWS <= 16);
pub const PER_CONTEXT: usize = 4;
/// The windows the manager's session may hold: its panel and the frames of
/// the windows it manages.
pub const MANAGER_SHARE: usize = 8;
/// The most lines of one band of a frame (`Scene::tile` makes a band
/// shorter where its layers cost more). A copy band over the whole width
/// holds nine lines at the prices below, so the limit leaves the prices to
/// decide.
pub const BAND_ROWS: u32 = 16;

/// The work of a band by the model (`Scene::tile`): the calls, the lines, the
/// points, the term of every layer and the fixed term of a band come to at most
/// BAND_TICKS. The step of the band is the `compose` of the band and the cost of
/// the step around it (the entry, the notice of the next band, the reply to the
/// loop), which the probes measure at about 1 080 ticks (a band of 15 544 ticks of
/// `compose` was a step of 16 621), so the work and the cost stay at or under 15 800
/// for the band of eight windows, 500 under the gate of a band, 16 328 ticks. The
/// model of the work is over the measure (the prices and the terms carry the margin
/// of 15 %), and the real operations of eight windows came to 1.08 of the model's
/// before the terms were set from the real bands: at 14 000 the band of eight layers
/// is 43 points of a line (45 before the call of the black was raised to its measure of
/// 264 ticks) and its step is expected near 15 500.
pub const BAND_TICKS: u32 = 14_000;

/// The gate of a band: 0.8 of term B, the most one step of a portion may take
/// (`PORTION_MAX` of the probes, which xtask checks against this constant). The
/// cap of the bands of a period divides by it, so that the cap means the share of
/// a period by the gates.
pub const BAND_GATE: u32 = 16_328;

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
    /// What a call of this kind pays when pixman's cache of resolved paths has
    /// lost its key (`LOOKUP_MISS_MEASURED`): measured for the kind, ticks, and
    /// with the margin.
    pub miss_measured: u32,
    pub miss: u32,
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
    miss_measured: u32,
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
        miss_measured,
        miss: with_margin(miss_measured),
    }
}

/// The prices: black, copy, over and the kinds of the elements' operations, each
/// the upper fit of the model over the greatest ticks of 26 shapes of operations, the widths 1 to 152 and 640
/// (`compositor::fit`, `px::calibration`),
/// measured under -icount, the same in `comp-probe` and in `focus-probe`
/// (the run is deterministic). Every entry is a measure. The rows from
/// `fast-nearest-copy` on are the fast class (`elements::Class::FastNearestCopy`):
/// a scale by a fraction with no turn and no reflection, whose paths pixman
/// has apart from its general path; each has the miss
/// the calibration of the lookup measured for its kind (`measures::LOOKUPS`).
pub const PRICES: [Price; 24] = [
    price("black", 264, 2_400, false, 38, false, LOOKUP_MISS_MEASURED),
    price("copy", 780, 5_480, false, 138, false, LOOKUP_MISS_MEASURED),
    price("over", 785, 18_981, false, 427, false, LOOKUP_MISS_MEASURED),
    price(
        "scale-nearest-copy",
        5_711,
        19_973,
        false,
        2_900,
        false,
        LOOKUP_MISS_MEASURED,
    ),
    price(
        "scale-nearest-over",
        5_651,
        27_984,
        false,
        2_875,
        false,
        LOOKUP_MISS_MEASURED,
    ),
    price(
        "scale-bilinear-copy",
        5_741,
        19_976,
        false,
        8_299,
        false,
        LOOKUP_MISS_MEASURED,
    ),
    price(
        "scale-bilinear-over",
        5_664,
        27_956,
        false,
        9_475,
        false,
        LOOKUP_MISS_MEASURED,
    ),
    price(
        "rotate90",
        2_861,
        94,
        false,
        646,
        false,
        LOOKUP_MISS_MEASURED,
    ),
    price(
        "alpha",
        4_942,
        35_650,
        false,
        969,
        false,
        LOOKUP_MISS_MEASURED,
    ),
    price(
        "mask",
        1_170,
        260,
        false,
        4_695,
        false,
        LOOKUP_MISS_MEASURED,
    ),
    price("mask-alpha", 3_246, 4_785, false, 4_820, false, 908),
    price("fast-nearest-copy", 2776, 1719, false, 595, false, 3634),
    price("fast-nearest-over", 2707, 19082, false, 1013, false, 1537),
    price("fast-bilinear-copy", 2744, 24014, false, 1374, false, 2103),
    price("fast-bilinear-over", 3526, 38744, false, 2098, false, 2481),
    price("fast-nearest-alpha", 6112, 40994, false, 3268, false, 4374),
    price("fast-bilinear-alpha", 6103, 40937, false, 9868, false, 4373),
    price("fast-nearest-mask", 6043, 50313, false, 3737, false, 4411),
    price("fast-bilinear-mask", 2917, 35785, false, 4001, false, 2836),
    price(
        "fast-bilinear-mask-alpha",
        4464,
        40454,
        false,
        4123,
        false,
        3298,
    ),
    price(
        "fast-nearest-alpha-opaque",
        6106,
        29671,
        false,
        3428,
        false,
        4256,
    ),
    price(
        "fast-bilinear-alpha-opaque",
        6115,
        30024,
        false,
        8766,
        false,
        4259,
    ),
    price(
        "fast-nearest-mask-opaque",
        6207,
        38416,
        false,
        3834,
        false,
        4263,
    ),
    price(
        "fast-bilinear-mask-opaque",
        6218,
        38396,
        false,
        9234,
        false,
        4249,
    ),
];
/// What the model charges for one operation of `price` over `w` by `h` points, ticks:
/// the call, the rows and the points, rounded up.
pub const fn model_ticks(price: Price, w: u32, h: u32) -> u64 {
    price.call as u64
        + (price.row as u64 * h as u64 + price.point as u64 * w as u64 * h as u64).div_ceil(100)
}

/// The kinds of the calibration that are two steps of the service: a stretch with a
/// mask and an alpha that is no scale, each with the class of its stretch.
pub const TWO_STEP_KINDS: [(&str, elements::Class); 2] = [
    (
        "scale-nearest-mask-alpha",
        elements::Class::ScaleNearestOver,
    ),
    (
        "scale-bilinear-mask-alpha",
        elements::Class::ScaleBilinearOver,
    ),
];

/// What the model charges for one operation of the calibration's kind `kind` over `w`
/// by `h` points, ticks: its row of `PRICES`, or for a kind of two steps the sum of
/// the product of the mask and the alpha (`MaskAlpha`) and the stretch through it (the
/// laying over with the rows and the points of a mask, and no call of the mask's).
/// None for a kind with no price.
pub fn kind_model_ticks(kind: &str, w: u32, h: u32) -> Option<u64> {
    if let Some((_, class)) = TWO_STEP_KINDS.iter().find(|(k, _)| *k == kind) {
        let product = model_ticks(PRICES[elements::Class::MaskAlpha.row()], w, h);
        let mask = PRICES[elements::Class::Mask.row()];
        let stretch = PRICES[class.row()];
        let through = model_ticks(stretch, w, h)
            + (u64::from(mask.row) * u64::from(h)
                + u64::from(mask.point) * u64::from(w) * u64::from(h))
            .div_ceil(100);
        return Some(product + through);
    }
    PRICES
        .iter()
        .find(|p| p.kind == kind)
        .map(|p| model_ticks(*p, w, h))
}

/// What the model charges a call of the calibration's kind `kind` when pixman's cache of
/// paths has lost its key, ticks (the constant with the margin): the miss of its row of
/// `PRICES`, or for a kind of two steps the misses of the product and of the stretch.
/// None for a kind with no price.
pub fn kind_miss_ticks(kind: &str) -> Option<u32> {
    if let Some((_, class)) = TWO_STEP_KINDS.iter().find(|(k, _)| *k == kind) {
        return Some(PRICES[elements::Class::MaskAlpha.row()].miss + PRICES[class.row()].miss);
    }
    PRICES.iter().find(|p| p.kind == kind).map(|p| p.miss)
}

/// What every layer costs a band beyond its operation (ticks, for each window
/// the band lays and for the pointer's picture), and what every band costs beyond
/// its layers: the work of `compose` around the calls (the stacking, the clip,
/// the window's place and buffer, the source of each) and the timing of the
/// operations themselves. They are measured on the bands the service makes (the
/// steps build tells them by layers: the line `service band`, ticks of `compose`
/// less the operations in it): a band of no layer, the black alone, spends 538 to
/// 560 ticks around its operation, and a band of L layers 677 to 810 for one, 945 for
/// two, 1 219, 1 427, 1 683 and 1 946 for three to six, 2 458 for eight (about 240 a
/// layer on 560). The fixed term is the greatest of the band of no layer. The term of
/// a layer is the greatest (outside - outside of no layer) / L over the counts: 250,
/// 197, 220, 217, 225, 231 and 237 for 1, 2, 3, 4, 5, 6 and 8 layers. The band of seven
/// layers is left out: 2 668 against 2 202 to 2 458 of the bands near it, because the
/// band that made it was preempted (its compose was 24 612 ticks and its operations
/// 22 410, where the bands of six and eight layers were 14 733 and 15 525). The
/// measure 250 is that of one layer (the greatest of its 98 bands, 810, and the
/// term of a layer is charged for every layer, the first too). The model's outside
/// of a band of eight layers is then 2 948 ticks, over the 2 827 of the measure with
/// the margin. The
/// calibration of `px::calibration` (the kinds `layers1` to `layers9`) checks the
/// model on shapes of its own; the real bands are what the table follows.
/// `band_size` takes the fixed term off BAND_TICKS with the calls.
pub const LAYER_MEASURED: u32 = 250;
pub const LAYER: u32 = with_margin(LAYER_MEASURED);
pub const BAND_FIXED_MEASURED: u32 = 560;
pub const BAND_FIXED: u32 = with_margin(BAND_FIXED_MEASURED);
/// What every step of a frame under a scene spends beyond its operations for each
/// element of the scene, whether it shows something over the damage or not (ticks): a step
/// makes the groups of the layers (`Scene::passes`) and asks each element
/// whether it has something to draw on the band. Measured on the steps of the
/// scenes of 16 elements of the probe (the greatest excess of a step's own
/// work over `BAND_FIXED` and the term of its layers, for each element), with the
/// margin.
pub const ELEMENT_TERM_MEASURED: u32 = 106;
/// What a call of an element pays when pixman's cache of resolved paths (8
/// places) has lost its key: the greatest, over the kinds of the elements'
/// operations at both variants of the flags (inside the source and at its edge), of
/// the call of one point after eight calls of other keys less the same call
/// repeated (the line `service lookup` of `px::calibration`, ticks), and the
/// constant with the margin. An element with a transform has two keys, so a scene
/// of 16 has up to 32 and the cache is lost on every band: under a scene every
/// layer of an element pays it with its call (`Scene::passes`). The windows with no
/// scene have three keys and the pointer's, all warm.
pub const LOOKUP_MISS_MEASURED: u32 = 4_546;
pub const LOOKUP_MISS: u32 = with_margin(LOOKUP_MISS_MEASURED);
pub const ELEMENT_TERM: u32 = with_margin(ELEMENT_TERM_MEASURED);
/// What a step under a scene spends beyond the terms of its elements, in ticks:
/// the making of the groups and the entry into them. Set from the longest steps of
/// the probe (a step of 16 344 ticks at a model that left 16 under the gate for it);
/// it takes the band of a place that many ticks of the model off.
pub const SCENE_STEP: u32 = 250;
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

/// Where the screen is while the service opens it from a request: the
/// driver's frame buffer is mapped a portion of pages a step of the work, and
/// the screen counts as open (`Open`) only after the last portion and the
/// steps that finish the opening (the subscription and the planes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenPhase {
    /// No driver session: the next request asks the driver.
    Closed,
    /// The driver gave its buffer and `done` pages of it are mapped.
    Mapping { done: usize },
    /// Every page is mapped: the next step subscribes.
    Subscribing,
    /// The next step asks the pipelines.
    Planes,
    /// The next step takes the cursor's picture.
    Cursor,
    /// The next step asks the pool's source.
    Pool,
    /// The screen is open.
    Open,
}

/// What a request that needs the screen does, by the phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenAsk {
    /// Ask the driver (and begin the mapping when it gives its buffer).
    Ask,
    /// The opening is under way: the answer is CLEARING, ask again.
    Clearing,
    /// The screen is open: the request goes on.
    Ready,
}

impl ScreenPhase {
    /// The decision of a request that needs the screen.
    pub const fn ask(self) -> ScreenAsk {
        match self {
            ScreenPhase::Closed => ScreenAsk::Ask,
            ScreenPhase::Open => ScreenAsk::Ready,
            _ => ScreenAsk::Clearing,
        }
    }

    /// Whether the frame clock may take a frame: only an open screen.
    pub const fn takes_frames(self) -> bool {
        matches!(self, ScreenPhase::Open)
    }

    /// Whether a step of the work is due for the opening.
    pub const fn has_work(self) -> bool {
        !matches!(self, ScreenPhase::Closed | ScreenPhase::Open)
    }

    /// The driver gave its buffer: the mapping begins (a phase other than
    /// `Closed` keeps itself).
    pub const fn begin(self) -> ScreenPhase {
        match self {
            ScreenPhase::Closed => ScreenPhase::Mapping { done: 0 },
            other => other,
        }
    }

    /// The pages the next step maps of a buffer of `total` pages, `chunk` at
    /// most: 0 outside `Mapping`.
    pub const fn portion(self, total: usize, chunk: usize) -> usize {
        match self {
            ScreenPhase::Mapping { done } if done < total => {
                if total - done < chunk {
                    total - done
                } else {
                    chunk
                }
            }
            _ => 0,
        }
    }

    /// A portion of `pages` was mapped: `Subscribing` after the last one.
    pub const fn mapped(self, pages: usize, total: usize) -> ScreenPhase {
        match self {
            ScreenPhase::Mapping { done } => {
                if done + pages >= total {
                    ScreenPhase::Subscribing
                } else {
                    ScreenPhase::Mapping { done: done + pages }
                }
            }
            other => other,
        }
    }

    /// A step of the finishing ended well: the next one, `Open` after the last.
    pub const fn advanced(self) -> ScreenPhase {
        match self {
            ScreenPhase::Subscribing => ScreenPhase::Planes,
            ScreenPhase::Planes => ScreenPhase::Cursor,
            ScreenPhase::Cursor => ScreenPhase::Pool,
            ScreenPhase::Pool => ScreenPhase::Open,
            other => other,
        }
    }

    /// A refusal, a stop notice or a dead driver in the middle: the phase
    /// goes back to `Closed` and the pages mapped so far are to be
    /// unmapped (`total` of them once the mapping is complete). An open
    /// screen keeps itself.
    pub const fn release(self, total: usize) -> (ScreenPhase, usize) {
        match self {
            ScreenPhase::Mapping { done } => (ScreenPhase::Closed, done),
            ScreenPhase::Subscribing
            | ScreenPhase::Planes
            | ScreenPhase::Cursor
            | ScreenPhase::Pool => (ScreenPhase::Closed, total),
            other => (other, 0),
        }
    }
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
    /// 8 bits an alpha, a byte a point: the mask of an element. Never shown.
    A8,
}

impl Format {
    /// The bytes of a line of `w` points at the least (`proto_comp::line_bytes`).
    pub const fn line(self, w: u32) -> u64 {
        match self {
            Format::A8 => (w as u64 + 3) & !3,
            _ => w as u64 * 4,
        }
    }
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
    /// The service has no operation that draws it (SCENE_COMMIT).
    Unsupported,
    /// The call is not for this window (a POST before ATTACH, a FLUSH of a
    /// window that has buffers of its own, or the other way round).
    NotAllowed,
}

/// One window.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    /// The id the clients know the window by (`proto_comp::window_id`): its
    /// place and the count of windows made there.
    pub id: u32,
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

/// What a window has of the top-window protocol (proto_comp's SET_TEXT, SIZE and
/// MANAGE operations), kept apart from `Window` so that the bands, which copy a
/// window a layer, copy no more than they did.
#[derive(Clone, Copy, Debug)]
struct Top {
    /// The most the size can be: the width a stride holds and the lines the
    /// smallest buffer holds (0 by 0 before ATTACH).
    cap: (u32, u32),
    /// The size SIZE gave for the next POST, and the size of the buffer posted
    /// and not yet taken, which the taking makes the window's.
    next: Option<(u32, u32)>,
    posted: Option<(u32, u32)>,
    /// The last serial a CONFIGURE gave the window.
    serial: u32,
    /// The window belongs to the manager's session.
    mgr: bool,
    /// The window of the manager that follows this window, and the window this
    /// window follows (places).
    follower: Option<u8>,
    leader: Option<u8>,
    /// The TITLE events (bit 1 the title, bit 2 the kind) in the manager's ring
    /// that it has not taken: a change of a text that has its bit set tells
    /// nothing more, so that alternating SET_TEXTs cannot fill the ring.
    told: u8,
    title_len: u8,
    app_len: u8,
    title: [u8; TEXT_MAX],
    app: [u8; TEXT_MAX],
}

impl Top {
    const NEW: Top = Top {
        cap: (0, 0),
        next: None,
        posted: None,
        serial: 0,
        mgr: false,
        follower: None,
        leader: None,
        told: 0,
        title_len: 0,
        app_len: 0,
        title: [0; TEXT_MAX],
        app: [0; TEXT_MAX],
    };
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
    pub windows: u16,
    pub manager: bool,
}

/// The windows, the damage to be shown, the frame's state, the focus and
/// the pointer.
pub struct Scene {
    windows: [Option<Window>; MAX_WINDOWS],
    tops: [Top; MAX_WINDOWS],
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
    damage: DamageList,
    /// The damage of the frame in progress, as `begin_at` took it: the rectangles
    /// its bands cover (`frame_damage`).
    frame_damage: DamageList,
    /// The earliest start a window left by the last taking is due at (the
    /// caller says `hold` with it to the pacer).
    held_until: Option<u64>,
    frame: bool,
    seq: u32,
    created: u32,
    frames: u32,
    /// The scene of a scene session (proto_comp's SCENE_COMMIT): the last one
    /// committed, which a taking makes the working one whole, and the working
    /// one, which the bands of a frame read. Neither: the windows show as the
    /// policy of the windows says.
    /// The three places scenes are kept in: the pending scene, the working one
    /// and the one a commit is parsed into (no scene is copied: the places
    /// change their roles).
    defs: [Def; 3],
    /// The windows made at each place so far (the generation of the id).
    made: [u32; MAX_WINDOWS],
    slot_pending: Option<u8>,
    slot_working: Option<u8>,
    stage: Stage,
    /// The prepared images of the elements that turn or stretch (`prep`), when the
    /// service has a worker for them: the table, the slots of the elements of each
    /// of the three places of scenes, and what the frame in work holds.
    prep: Option<&'static prep::Table>,
    maps: [prep::Map; 3],
    /// The image of each slot the frame in work reads, taken at its start.
    front: [Option<u8>; prep::SLOTS],
    /// The buffers of each window whose free waits for the worker to let go of
    /// them (a bit each), and the id of the window the worker was told of.
    owed: [u8; MAX_WINDOWS],
    told: [u32; MAX_WINDOWS],
    /// A frame ended with the worker blocked on it: the worker is to be woken.
    wake: bool,
    /// The period the service is in (`set_period`), the period of the commit the
    /// pending scene's wait began at, and the takings the wait has seen (the count
    /// serves where there is no clock of periods).
    period: u64,
    pending_since: Option<u64>,
    waited: u32,
}

/// What the scene session's own state holds besides its two scenes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Stage {
    /// The damage of changes that wait for the scene's frame while the scene
    /// is not composed by itself.
    held: Option<Rect>,
    /// A SCENE_COMPOSE waits for the taking; the frame it made is in work.
    compose_due: bool,
    composing: bool,
    /// The bits the scene's channel is to be told, asked for and ready.
    ask_committed: bool,
    ask_composed: bool,
    committed_now: bool,
    composed_now: bool,
    /// A window no element shows posted something: a taking gives it back.
    give_back: bool,
    /// The damage of a commit whose scene waits for its images: kept aside, and
    /// applied at the taking that makes the scene the working one.
    pending_damage: Option<Rect>,
    /// The scene session ended while a frame was in work: the taking that
    /// follows goes back to the policy of the windows.
    ending: bool,
    /// What the last taking gave back: the buffer of each window, and the
    /// windows of the first revision whose FLUSH is answered.
    given: [Option<u8>; MAX_WINDOWS],
    answered: u16,
}

impl Stage {
    const NEW: Stage = Stage {
        held: None,
        compose_due: false,
        composing: false,
        ask_committed: false,
        ask_composed: false,
        committed_now: false,
        composed_now: false,
        give_back: false,
        pending_damage: None,
        ending: false,
        given: [None; MAX_WINDOWS],
        answered: 0,
    };
}

/// What a taking gave back of the windows no element shows (`Scene::given_back`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GivenBack {
    /// The buffer of each window that is free again, by place: the one a
    /// window no element shows had as its current one before it posted.
    pub freed: [Option<u8>; MAX_WINDOWS],
    /// The windows of the first revision whose FLUSH has its answer, by place.
    pub answered: u16,
}

/// The bits a scene session's channel is told by (`Scene::scene_bits`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SceneBits {
    pub committed: bool,
    pub composed: bool,
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
            tops: [Top::NEW; MAX_WINDOWS],
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
            damage: DamageList::new(),
            frame_damage: DamageList::new(),
            held_until: None,
            frame: false,
            seq: 0,
            created: 0,
            frames: 0,
            defs: [Def::EMPTY; 3],
            made: [0; MAX_WINDOWS],
            slot_pending: None,
            slot_working: None,
            stage: Stage::NEW,
            prep: None,
            maps: [prep::NO_MAP; 3],
            front: [None; prep::SLOTS],
            owed: [0; MAX_WINDOWS],
            told: [0; MAX_WINDOWS],
            wake: false,
            period: 0,
            pending_since: None,
            waited: 0,
        }
    }

    /// The period the service is in, for the commits that follow: a scene that waits
    /// for its images is taken at the latest at the start of the second period after
    /// the commit's (`u64::MAX` for no clock of periods: the third taking).
    pub fn set_period(&mut self, k: u64) {
        self.period = k;
    }

    /// The elements that turn, reflect or stretch a window are drawn from the
    /// prepared images of `table` from now on: a commit reserves them, and an
    /// element shows nothing until its image is first made.
    pub fn set_prep(&mut self, table: &'static prep::Table) {
        self.prep = Some(table);
    }

    pub fn window(&self, i: usize) -> Option<&Window> {
        self.windows.get(i).and_then(Option::as_ref)
    }

    /// The place of the live window with id `id`: None for an id that names no
    /// window, or the window of that place that went (the place holds another
    /// window now, with another id).
    pub fn place_of(&self, id: u32) -> Option<usize> {
        let place = proto_comp::id_place(id) as usize;
        self.window(place).filter(|w| w.id == id).map(|_| place)
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
            || !self.damage.is_empty()
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
        w.visible && w.current.is_some() && w.format != Format::A8
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
        taken: u16,
    ) -> Result<usize, Refusal> {
        self.create_as(label, ctx, rect, legacy, taken, false)
    }

    /// `create` for a context that is the manager's session (`manager`: its
    /// share is MANAGER_SHARE windows and its windows that follow none lie above
    /// all others) or any other (PER_CONTEXT).
    pub fn create_as(
        &mut self,
        label: u64,
        ctx: u64,
        rect: Rect,
        legacy: bool,
        taken: u16,
        manager: bool,
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
        if mine >= if manager { MANAGER_SHARE } else { PER_CONTEXT } {
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
        let generation = if self.made[place] >= proto_comp::ID_GENERATION_MAX {
            1
        } else {
            self.made[place] + 1
        };
        self.made[place] = generation;
        let id = proto_comp::window_id(place as u32, generation);
        self.windows[place] = Some(Window {
            id,
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
        self.tops[place] = Top {
            mgr: manager,
            ..Top::NEW
        };
        self.tell_manager(Event::new(CREATE, place as u16, id as i32));
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
        let bytes = self
            .window(i)
            .map_or(0, |w| u64::from(stride) * u64::from(w.rect.h));
        self.attach_sized(i, count, stride, bytes)
    }

    /// `attach` for buffers that hold `bytes` each (the smallest of them): the
    /// window's capacity is the width a stride holds and the lines `bytes` hold.
    pub fn attach_sized(
        &mut self,
        i: usize,
        count: u8,
        stride: u32,
        bytes: u64,
    ) -> Result<(), Refusal> {
        let w = self
            .windows
            .get_mut(i)
            .and_then(Option::as_mut)
            .ok_or(Refusal::Invalid)?;
        if w.attached != 0 {
            return Err(Refusal::Busy);
        }
        let line = w.format.line(w.rect.w);
        if count == 0
            || count as usize > BUFFERS
            || u64::from(stride) < line
            || (w.format == Format::A8 && !stride.is_multiple_of(4))
        {
            return Err(Refusal::Invalid);
        }
        w.attached = count;
        w.stride = stride;
        let lines = bytes / u64::from(stride.max(1));
        self.tops[i].cap = (
            if w.format == Format::A8 {
                stride
            } else {
                stride / 4
            },
            u32::try_from(lines).unwrap_or(u32::MAX),
        );
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
        self.damage.add(r);
    }

    /// Whether a scene session holds a scene (committed, or taken).
    pub fn scene_on(&self) -> bool {
        self.slot_pending.is_some() || self.slot_working.is_some()
    }

    /// The pending scene: the last one committed that no taking has made the
    /// working one.
    fn pending_def(&self) -> Option<&Def> {
        self.slot_pending.map(|k| &self.defs[usize::from(k)])
    }

    /// The place no scene is in.
    fn free_slot(&self) -> usize {
        (0..3u8)
            .find(|&k| Some(k) != self.slot_pending && Some(k) != self.slot_working)
            .map_or(0, usize::from)
    }

    /// Whether the scene the last commit left is composed by itself.
    fn scene_active(&self) -> bool {
        self.pending_def()
            .or(self.working())
            .is_some_and(|d| d.active)
    }

    /// The change of window `i` at the rectangles `rects` of its own points
    /// (none: all of it), as the screen sees it: without a scene the window's
    /// place; with one the elements that use the window carry it. None when
    /// the window changes nothing on the screen (no element uses it, or what
    /// they show of it is off the screen).
    fn window_damage(&self, i: usize, rects: &[Rect]) -> Option<Rect> {
        let legacy = self.window(i).is_some_and(|w| w.legacy);
        self.window_damage_in(i, rects, self.prep.is_some() && !legacy)
    }

    /// `window_damage`, with or without the elements whose image the worker makes
    /// (`prepared`: their change is damage when the image is made; a window that
    /// goes is damage of all of them).
    fn window_damage_in(&self, i: usize, rects: &[Rect], prepared: bool) -> Option<Rect> {
        let w = self.window(i)?;
        if !self.scene_on() {
            return Scene::changed(w.rect, rects).ok();
        }
        let whole = Rect {
            x: 0,
            y: 0,
            w: w.rect.w,
            h: w.rect.h,
        };
        let mut sum = None;
        let all = [whole];
        let rects = if rects.is_empty() { &all[..] } else { rects };
        // Both scenes: the taking that makes the pending one the working one
        // may come before or after the window's buffer is taken.
        for def in [self.working(), self.pending_def()].into_iter().flatten() {
            for r in rects {
                if let Some(d) = elements::window_damage_by(def, w.id, *r, prepared) {
                    sum = Some(union(sum, d));
                }
            }
        }
        sum
    }

    /// The damage `d` of a window's change under a scene goes where the scene
    /// says (`seen`: some element shows the window).
    fn route_damage(&mut self, d: Rect, seen: bool) {
        if !seen {
            self.stage.give_back = true;
        } else if self.scene_on() && !self.scene_active() {
            self.stage.held = Some(union(self.stage.held, d));
        } else {
            self.add_damage(d);
        }
    }

    /// The damage of a change of window `i` goes where the scene says: a frame
    /// of the working scene's own at the next taking when the scene is composed
    /// by itself (or there is none), the scene's stock for SCENE_COMPOSE when
    /// it is not. A change no element shows asks for the taking that gives
    /// the buffer back.
    fn add_window_damage(&mut self, i: usize, rects: &[Rect]) {
        match self.window_damage(i, rects) {
            Some(d) => self.route_damage(d, true),
            None if self.scene_on() => self.stage.give_back = true,
            None => {}
        }
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

    /// A post of `buffer` of window `i` with the changed `rects` (its own points,
    /// none for all) by a client at `level`: the prepared images of the elements
    /// that show the window are behind by what the element carries of the change,
    /// and the worker is to draw it from `buffer`. True when some image is behind.
    pub fn note_post(&mut self, i: usize, buffer: u8, rects: &[Rect], level: u8) -> bool {
        let Some(t) = self.prep else {
            return false;
        };
        let Some(w) = self.window(i).copied() else {
            return false;
        };
        if self.told[i] != w.id {
            t.set_window(i, w.id, w.format, w.stride, w.rect.w, w.rect.h);
            self.told[i] = w.id;
        }
        t.set_latest(i, buffer);
        let all = [Rect {
            x: 0,
            y: 0,
            w: w.rect.w,
            h: w.rect.h,
        }];
        let rects = if rects.is_empty() { &all[..] } else { rects };
        let mut behind = false;
        for k in [self.slot_working, self.slot_pending].into_iter().flatten() {
            let k = usize::from(k);
            for (j, e) in self.defs[k].elements().iter().enumerate() {
                let slot = self.maps[k][j];
                if e.source != w.id || slot == prep::NO_SLOT {
                    continue;
                }
                for r in rects {
                    if let Some(local) = elements::target_local(e, *r) {
                        t.damage(usize::from(slot), local, level);
                        behind = true;
                    }
                }
            }
        }
        behind
    }

    /// The buffers whose free waited for the worker to let go and can be free
    /// now, by window (a bit each): the clients are to be told.
    #[allow(clippy::needless_range_loop)]
    pub fn release_owed(&mut self) -> [u8; MAX_WINDOWS] {
        let mut freed = [0u8; MAX_WINDOWS];
        let Some(t) = self.prep else {
            return freed;
        };
        for i in 0..MAX_WINDOWS {
            for j in 0..BUFFERS {
                if self.owed[i] & (1 << j) != 0 && !t.reads(i, Some(j as u8)) {
                    self.owed[i] &= !(1 << j);
                    if let Some(w) = self.windows[i].as_mut() {
                        w.bufs[j] = Buf::Free;
                        freed[i] |= 1 << j;
                    }
                }
            }
        }
        freed
    }

    /// The worker drew the rectangles `drawn` of the images of some slots: the
    /// screen is damaged where an element shows them (in the working scene and the
    /// pending one, each at its own place), as a change of a window is. The number
    /// of slots told.
    pub fn images_drawn(&mut self, drawn: &[(usize, Rect)]) -> usize {
        let mut told = 0;
        for &(slot, local) in drawn {
            let mut sum = None;
            for k in [self.slot_working, self.slot_pending].into_iter().flatten() {
                let k = usize::from(k);
                for (j, e) in self.defs[k].elements().iter().enumerate() {
                    if usize::from(self.maps[k][j]) != slot {
                        continue;
                    }
                    let (x0, y0) = (
                        i64::from(e.dx) + i64::from(local.x),
                        i64::from(e.dy) + i64::from(local.y),
                    );
                    if let Some(r) =
                        elements::clip(x0, y0, x0 + i64::from(local.w), y0 + i64::from(local.h))
                    {
                        sum = Some(union(sum, r));
                    }
                }
            }
            if let Some(d) = sum {
                self.route_damage(d, true);
                told += 1;
            }
        }
        told
    }

    /// Whether the worker may be reading window `i` (its unmapping waits).
    pub fn worker_reads(&self, i: usize) -> bool {
        self.prep.is_some_and(|t| t.reads(i, None))
    }

    /// The frame ended with a slot waiting for the image a frame held: the worker
    /// is to be woken (once).
    pub fn take_wake(&mut self) -> bool {
        core::mem::take(&mut self.wake)
    }

    /// Whether the pending scene has an image that is not made yet, of a window that
    /// has something to read: the taking leaves the scene pending until it is, so that
    /// a scene never shows with an element missing for the images' time (a window that
    /// has posted nothing never has its image, and does not hold the scene).
    fn pending_waits(&self) -> bool {
        self.slot_pending
            .is_some_and(|p| self.waits_map(usize::from(p)))
    }

    /// Whether the scene at place `k` has an image that is not made yet.
    fn waits_map(&self, k: usize) -> bool {
        let Some(t) = self.prep else {
            return false;
        };
        self.maps[k]
            .iter()
            .any(|&s| s != prep::NO_SLOT && !t.ready(usize::from(s)))
    }

    /// Whether the pending scene's wait for its images is over: the second start of a
    /// period after the commit that began it, or with no clock of periods the third
    /// taking. The elements still without an image then show their previous image or
    /// nothing.
    fn wait_over(&mut self, k: u64) -> bool {
        if k == u64::MAX {
            self.waited += 1;
            return self.waited > 2;
        }
        self.pending_since
            .is_some_and(|since| k >= since.saturating_add(2))
    }

    /// The service has no worker (it could not be made): the elements that turn or
    /// stretch are drawn by the bands through the transform, as without images.
    pub fn clear_prep(&mut self) {
        self.prep = None;
    }

    /// Whether the elements that turn or stretch are drawn from images a worker makes
    /// (false: the bands draw them through the transform, as without a worker).
    pub fn prepared(&self) -> bool {
        self.prep.is_some()
    }

    /// The slots no scene holds are let go (a taking made another scene the
    /// working one, or the scene ended).
    fn sweep(&self) {
        if let Some(t) = self.prep {
            let frame = self.frame_map();
            let keep: [Option<&prep::Map>; 3] = [
                self.slot_working.map(|k| &self.maps[usize::from(k)]),
                self.slot_pending.map(|k| &self.maps[usize::from(k)]),
                Some(&frame),
            ];
            let mut held = [&prep::NO_MAP; 3];
            let mut n = 0;
            for m in keep.into_iter().flatten() {
                held[n] = m;
                n += 1;
            }
            let _ = t.reserve(&[], &held[..n], 1);
        }
    }

    /// The slots whose image the frame in work holds: they stay until the frame ends,
    /// whatever scene is the working one by then.
    fn frame_map(&self) -> prep::Map {
        let mut map = prep::NO_MAP;
        let mut n = 0;
        for (s, f) in self.front.iter().enumerate() {
            if f.is_some() && n < map.len() {
                map[n] = s as u8;
                n += 1;
            }
        }
        map
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
        // With a scene the change is what the elements carry to the screen.
        let in_scene = self.scene_on().then(|| self.window_damage(i, rects));
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
        let wrect = w.rect;
        // The rectangles are in the size the buffer will have: the one SIZE
        // gave, or the one a buffer still waiting for its taking carries.
        let size = self.tops[i]
            .next
            .or(self.tops[i].posted)
            .unwrap_or((w.rect.w, w.rect.h));
        let resizing = size != (w.rect.w, w.rect.h);
        let new_rect = Rect {
            x: w.rect.x,
            y: w.rect.y,
            w: size.0,
            h: size.1,
        };
        let changed = Scene::changed(new_rect, rects)?;
        // A change of size damages the old rectangle with the new one.
        let mut damage = if resizing {
            union(Some(w.rect), new_rect)
        } else {
            changed
        };
        let mut seen = true;
        if let Some(carried) = in_scene {
            match carried {
                Some(d) => damage = d,
                None => seen = false,
            }
        }
        if let Some(n) = self.tops[i].next.take() {
            self.tops[i].posted = Some(n);
        }
        w.bufs[buffer as usize] = Buf::Posted;
        let mut replaced = w.posted.replace(buffer);
        if let Some(j) = replaced {
            // A buffer the worker may be reading is free when it lets go.
            if self.prep.is_some_and(|t| t.reads(i, Some(j))) {
                w.bufs[j as usize] = Buf::Taken;
                self.owed[i] |= 1 << j;
                replaced = None;
            } else {
                w.bufs[j as usize] = Buf::Free;
            }
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
        let held = w.held.take();
        if let Some(h) = held {
            damage = union(Some(damage), h);
        }
        if in_scene.is_some() {
            self.route_damage(damage, seen);
        } else if held.is_some() || rects.is_empty() || resizing {
            self.add_damage(damage);
        } else {
            // The areas of the change stay apart in the frame's damage.
            for r in rects {
                self.add_damage(Rect {
                    x: wrect.x + r.x,
                    y: wrect.y + r.y,
                    w: r.w,
                    h: r.h,
                });
            }
        }
        Ok((replaced, due))
    }

    /// Whether a change waits for a frame: damage the next frame will take, or
    /// something of the scene a taking is for (a buffer to give back, a
    /// SCENE_COMPOSE, the end of the scene).
    pub fn damaged(&self) -> bool {
        !self.damage.is_empty()
            || self.stage.give_back
            || self.stage.compose_due
            || self.stage.ending
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
        if self.scene_on() {
            // A window no element shows has nothing to wait for: the taking
            // it asks for answers the FLUSH (`given_back`).
            self.add_window_damage(i, &[rect]);
        } else {
            self.add_damage(damage);
        }
        Ok(())
    }

    /// The window `i` goes: its place on the screen is to be shown again,
    /// the focus it had passes to the window on top, and the manager is
    /// told.
    pub fn destroy(&mut self, i: usize) -> Option<Window> {
        let carried = self
            .scene_on()
            .then(|| self.window_damage_in(i, &[], false));
        let w = self.windows.get_mut(i)?.take()?;
        // A leader that goes hides the window that followed it and ends the
        // link (the manager sees CLOSE of the leader); a follower that goes
        // leaves its leader alone.
        let top = core::mem::replace(&mut self.tops[i], Top::NEW);
        if let Some(l) = top.leader {
            self.tops[usize::from(l)].follower = None;
        }
        if let Some(f) = top.follower.map(usize::from) {
            self.tops[f].leader = None;
            self.set_visible_one(f, false);
        }
        if let Some(t) = self.prep {
            t.clear_window(i);
        }
        self.owed[i] = 0;
        self.told[i] = 0;
        if w.legacy {
            self.release = true;
        }
        // A window of the first revision always has its line to say.
        if w.legacy || w.current.is_some() || w.posted.is_some() {
            match carried {
                None => self.add_damage(w.rect),
                Some(Some(d)) => self.route_damage(d, true),
                Some(None) => {}
            }
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
        self.tell_manager(Event::new(CLOSE, i as u16, w.id as i32));
        if self.focus == Some(i) {
            self.focus = None;
            if let Some(top) = self.focus_top(None) {
                self.set_focus(top);
            }
        }
        Some(w)
    }

    /// The place of window `i` in the order of depth: the windows of the manager
    /// that follow none lie above all others, then the order they were raised in.
    fn depth_key(&self, i: usize) -> u64 {
        let t = &self.tops[i];
        let seq = self.windows[i].map_or(0, |w| w.seq);
        (u64::from(t.mgr && t.leader.is_none()) << 32) | u64::from(seq)
    }

    /// The topmost shown window, except `except`.
    fn top(&self, except: Option<usize>) -> Option<usize> {
        self.topmost(except, false, false)
    }

    /// The topmost shown window that may have the focus, except `except`: a
    /// window of a client when there is one (the focus does not fall to the
    /// manager's panel), else any window that is not a follower (a follower
    /// never has the focus).
    fn focus_top(&self, except: Option<usize>) -> Option<usize> {
        self.topmost(except, true, true)
            .or_else(|| self.topmost(except, true, false))
    }

    fn topmost(&self, except: Option<usize>, focusable: bool, clients: bool) -> Option<usize> {
        let mut best: Option<(u64, usize)> = None;
        for (i, w) in self.windows.iter().enumerate() {
            let Some(w) = w else {
                continue;
            };
            if Some(i) == except
                || !Scene::shown(w)
                || (focusable && self.tops[i].leader.is_some())
                || (clients && self.tops[i].mgr)
            {
                continue;
            }
            let key = self.depth_key(i);
            if best.is_none_or(|(k, _)| key > k) {
                best = Some((key, i));
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
        for t in &mut self.tops {
            t.told = 0;
        }
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
        let (n, lost) = self.manager_ring.take(out);
        // A TITLE the manager has taken can be told again; when the ring lost
        // events any TITLE may be one of them.
        if lost {
            for t in &mut self.tops {
                t.told = 0;
            }
        }
        for e in &out[..n] {
            if e.kind == TITLE
                && let Some(t) = self.tops.get_mut(usize::from(e.code))
            {
                t.told &= !(1 << (e.x - 1).clamp(0, 7));
            }
        }
        (n, lost)
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
        let mut best: Option<(u64, usize)> = None;
        for (i, w) in self.windows.iter().enumerate() {
            let Some(w) = w else {
                continue;
            };
            let r = w.rect;
            let inside = x >= r.x as i32
                && y >= r.y as i32
                && x < (r.x + r.w) as i32
                && y < (r.y + r.h) as i32;
            if inside && Scene::shown(w) {
                let key = self.depth_key(i);
                if best.is_none_or(|(k, _)| key > k) {
                    best = Some((key, i));
                }
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
            self.add_damage(Scene::cursor_rect(at));
            if let Some(old) = before {
                self.add_damage(Scene::cursor_rect(old));
            }
        }
        // Under a scene the place of a window on the screen is the element's,
        // with its scale and turn: the pointer is the scene's, in the screen's
        // own coordinates, and no window's.
        if self.scene_on() {
            self.tell_manager(Event::at(MOVE, 0, 0, at.0, at.1));
            return;
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
        if self.scene_on() {
            let e = Event::at(BUTTON, code, i32::from(pressed), at.0, at.1);
            self.tell_manager(e);
            return;
        }
        let target = if pressed {
            let hit = self.hit(at.0, at.1);
            if let Some(i) = hit {
                // A click on a follower is a click on its leader's frame: the
                // leader has the focus and the top place with it, and the
                // button stays held by the follower.
                let lead = self.tops[i].leader.map_or(i, usize::from);
                self.set_focus(lead);
                let _ = self.raise(lead);
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

    /// Window `i` goes to the top. Invalid for a window that is none. The
    /// window that follows a window goes with it and lies directly under it, so
    /// raising a follower raises its leader.
    pub fn raise(&mut self, i: usize) -> Result<(), Refusal> {
        self.window(i).ok_or(Refusal::Invalid)?;
        let i = self.tops[i].leader.map_or(i, usize::from);
        let follower = self.tops[i].follower.map(usize::from);
        // On top of the windows of its own tier (the manager's unlinked windows
        // lie above the others whatever their order).
        let tier = |k: usize| self.tops[k].mgr && self.tops[k].leader.is_none();
        let top = (0..MAX_WINDOWS)
            .filter(|&k| tier(k) == tier(i))
            .filter_map(|k| self.window(k).map(|w| w.seq))
            .max();
        let mine = self.window(i).map(|w| w.seq);
        let under = follower.is_none_or(|f| {
            self.window(f)
                .zip(mine)
                .is_some_and(|(w, m)| w.seq.wrapping_add(1) == m)
        });
        if top == mine && under {
            return Ok(());
        }
        for k in [follower, Some(i)].into_iter().flatten() {
            self.seq = self.seq.wrapping_add(1);
            let seq = self.seq;
            let mut damaged = None;
            if let Some(Some(w)) = self.windows.get_mut(k) {
                w.seq = seq;
                if Scene::shown(w) {
                    damaged = Some(w.rect);
                }
            }
            if let Some(r) = damaged {
                self.add_damage(r);
            }
        }
        Ok(())
    }

    /// Window `i` has the focus and the top place (a follower's leader has
    /// them: a follower never has the focus).
    pub fn focus_on(&mut self, i: usize) -> Result<(), Refusal> {
        if self.window(i).is_none() {
            return Err(Refusal::Invalid);
        }
        let i = self.tops[i].leader.map_or(i, usize::from);
        self.set_focus(i);
        self.raise(i)
    }

    /// The size window `i` may have to be reckoned with when it moves: its own,
    /// or the greater of the sizes a SIZE and a POST that waits for its taking
    /// gave.
    fn reach(&self, i: usize) -> (u32, u32) {
        let (mut w, mut h) = self.window(i).map_or((0, 0), |w| (w.rect.w, w.rect.h));
        for (nw, nh) in [self.tops[i].next, self.tops[i].posted]
            .into_iter()
            .flatten()
        {
            w = w.max(nw);
            h = h.max(nh);
        }
        (w, h)
    }

    /// The rectangle window `i` would take at (`x`, `y`) with every size it may
    /// have by the next frame, when all of it is on the screen.
    fn placed(&self, i: usize, x: i64, y: i64) -> Option<Rect> {
        let (w, h) = self.reach(i);
        let (x, y) = (u32::try_from(x).ok()?, u32::try_from(y).ok()?);
        let r = Rect { x, y, w, h };
        r.within(WIDTH, HEIGHT).then_some(r)
    }

    /// Window `i` moves to (`x`, `y`): all of it stays on the screen. A
    /// window of the first revision does not move. The window that follows it
    /// moves by the same step, in the same call; when either would leave the
    /// screen nothing moves.
    pub fn move_to(&mut self, i: usize, x: u32, y: u32) -> Result<(), Refusal> {
        let w = self.window(i).ok_or(Refusal::Invalid)?;
        if w.legacy {
            return Err(Refusal::NotAllowed);
        }
        let from = w.rect;
        let to = self
            .placed(i, i64::from(x), i64::from(y))
            .ok_or(Refusal::Invalid)?;
        let mut moves = [Some((i, from, to)), None];
        if let Some(f) = self.tops[i].follower.map(usize::from)
            && let Some(fw) = self.window(f)
        {
            let at = (
                i64::from(fw.rect.x) + i64::from(x) - i64::from(from.x),
                i64::from(fw.rect.y) + i64::from(y) - i64::from(from.y),
            );
            let fto = self.placed(f, at.0, at.1).ok_or(Refusal::Invalid)?;
            moves[1] = Some((f, fw.rect, fto));
        }
        for (k, was, to) in moves.into_iter().flatten() {
            let shown = self.window(k).is_some_and(Scene::shown);
            if let Some(Some(w)) = self.windows.get_mut(k) {
                w.rect.x = to.x;
                w.rect.y = to.y;
            }
            if shown {
                self.add_damage(was);
                self.add_damage(to);
            }
        }
        Ok(())
    }

    /// Window `i` is shown or hidden, and the window that follows it with it. A
    /// hidden window has no focus: it passes to the window on top.
    pub fn set_visible(&mut self, i: usize, visible: bool) -> Result<(), Refusal> {
        self.window(i).ok_or(Refusal::Invalid)?;
        let follower = self.tops[i].follower.map(usize::from);
        self.set_visible_one(i, visible);
        if let Some(f) = follower {
            self.set_visible_one(f, visible);
        }
        Ok(())
    }

    fn set_visible_one(&mut self, i: usize, visible: bool) {
        let Some(w) = self.window(i) else {
            return;
        };
        if w.visible == visible {
            return;
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
            && let Some(top) = self.focus_top(Some(i))
        {
            self.set_focus(top);
        }
    }

    /// The windows in the order of depth, lowest first: the place, and the
    /// window.
    pub fn by_depth(&self) -> ([u8; MAX_WINDOWS], usize) {
        let mut at = [0u8; MAX_WINDOWS];
        let mut n = 0;
        for (i, w) in self.windows.iter().enumerate() {
            if w.is_some() {
                // Insertion by depth: the lowest first.
                let key = |k: u8| self.depth_key(usize::from(k));
                let mut p = n;
                while p > 0 && key(at[p - 1]) > key(i as u8) {
                    at[p] = at[p - 1];
                    p -= 1;
                }
                at[p] = i as u8;
                n += 1;
            }
        }
        (at, n)
    }

    // ------------------------------------------------------ the top window

    /// SIZE: window `i` has `w` by `h` points from the buffer its next POST
    /// posts (`serial` is the CONFIGURE the client answers, or 0). Invalid for a
    /// size no buffer holds, one that takes the window off the screen at its
    /// place, or a serial that no CONFIGURE gave; NotAllowed for a window of the
    /// first revision, a mask, a window without buffers, or while a scene
    /// shows the windows.
    pub fn set_size(&mut self, i: usize, w: u32, h: u32, serial: u32) -> Result<(), Refusal> {
        let win = self.window(i).ok_or(Refusal::Invalid)?;
        if win.legacy || win.format == Format::A8 || win.attached == 0 || self.scene_on() {
            return Err(Refusal::NotAllowed);
        }
        let cap = self.tops[i].cap;
        let place = Rect {
            x: win.rect.x,
            y: win.rect.y,
            w,
            h,
        };
        if w == 0
            || h == 0
            || w > cap.0
            || h > cap.1
            || (serial != 0 && serial != self.tops[i].serial)
            || !place.within(WIDTH, HEIGHT)
        {
            return Err(Refusal::Invalid);
        }
        self.tops[i].next = Some((w, h));
        Ok(())
    }

    /// The size of the buffer window `i` posted last and the frame has not
    /// taken, or the size of the window.
    pub fn posted_size(&self, i: usize) -> (u32, u32) {
        let own = self.window(i).map_or((0, 0), |w| (w.rect.w, w.rect.h));
        self.tops[i].next.or(self.tops[i].posted).unwrap_or(own)
    }

    /// The lines the buffers of window `i` hold at the least (the window's own
    /// height before ATTACH, and for the first revision).
    pub fn buffer_lines(&self, i: usize) -> u32 {
        let own = self.window(i).map_or(0, |w| w.rect.h);
        self.tops[i].cap.1.max(own)
    }

    /// SET_TEXT: the title (`which` 1) or the application's kind (2) of window
    /// `i`; the manager is told when it changed. Invalid for a `which` that is
    /// none or more than TEXT_MAX bytes.
    pub fn set_text(&mut self, i: usize, which: u32, text: &[u8]) -> Result<(), Refusal> {
        let id = self.window(i).ok_or(Refusal::Invalid)?.id;
        if text.len() > TEXT_MAX {
            return Err(Refusal::Invalid);
        }
        let top = &mut self.tops[i];
        let (bytes, len) = match which {
            proto_comp::TEXT_TITLE => (&mut top.title, &mut top.title_len),
            proto_comp::TEXT_APP => (&mut top.app, &mut top.app_len),
            _ => return Err(Refusal::Invalid),
        };
        let same = &bytes[..usize::from(*len)] == text;
        bytes[..text.len()].copy_from_slice(text);
        *len = text.len() as u8;
        let bit = 1 << (which - 1);
        if !same && top.told & bit == 0 {
            top.told |= bit;
            self.tell_manager(Event::at(TITLE, i as u16, id as i32, which as i32, 0));
        }
        Ok(())
    }

    /// INFO: the flags, the capacity and the texts of window `i`.
    pub fn info(&self, i: usize) -> Option<proto_comp::Info> {
        let w = self.window(i)?;
        let t = &self.tops[i];
        let mut flags = 0;
        if w.legacy {
            flags |= proto_comp::INFO_LEGACY;
        }
        if w.format == Format::Argb {
            flags |= proto_comp::INFO_ARGB;
        }
        if t.follower.is_some() {
            flags |= proto_comp::INFO_LEADER;
        }
        if t.leader.is_some() {
            flags |= proto_comp::INFO_FOLLOWER;
        }
        if t.mgr {
            flags |= proto_comp::INFO_MANAGER;
        }
        Some(proto_comp::Info {
            flags,
            cap_w: t.cap.0,
            cap_h: t.cap.1,
            title_len: usize::from(t.title_len),
            app_len: usize::from(t.app_len),
            title: t.title,
            app: t.app,
        })
    }

    /// CONFIGURE: window `i` is asked for `w` by `h` points (0 by 0: its own
    /// choice) and the states `states`; its ring gets CONFIGURE with a serial
    /// the answer gives back in SIZE. Invalid for a size over the screen, one
    /// side 0 or a state that is none; NotAllowed for a window that has no ring
    /// of events for it (the first revision, a mask).
    pub fn configure(&mut self, i: usize, w: u32, h: u32, states: u32) -> Result<(), Refusal> {
        let win = self.window(i).ok_or(Refusal::Invalid)?;
        if win.legacy || win.format == Format::A8 {
            return Err(Refusal::NotAllowed);
        }
        if states & !STATES != 0 || w > WIDTH || h > HEIGHT || (w == 0) != (h == 0) {
            return Err(Refusal::Invalid);
        }
        // The serial is a positive i32 (the event's `value`): it wraps to 1, and
        // SIZE accepts only the last one given.
        let last = self.tops[i].serial;
        self.tops[i].serial = if last >= i32::MAX as u32 { 1 } else { last + 1 };
        let serial = self.tops[i].serial;
        self.tell(
            i,
            Event::at(CONFIGURE, states as u16, serial as i32, w as i32, h as i32),
        );
        Ok(())
    }

    /// CLOSE: window `i`'s ring gets CLOSE_REQUEST; the client decides.
    pub fn close_request(&mut self, i: usize) -> Result<(), Refusal> {
        let win = self.window(i).ok_or(Refusal::Invalid)?;
        if win.legacy {
            return Err(Refusal::NotAllowed);
        }
        self.tell(i, Event::new(CLOSE_REQUEST, 0, 0));
        Ok(())
    }

    /// LINK: the window `follower` of the manager follows window `leader` (None:
    /// `leader` has no follower any more). Moving, raising, hiding and showing the
    /// leader do the same for the follower in one step; the two are raised
    /// together now. Invalid when the follower is no window of the manager's
    /// session, the leader is one, either is in a link already, or they are one.
    pub fn link(&mut self, leader: usize, follower: Option<usize>) -> Result<(), Refusal> {
        self.window(leader).ok_or(Refusal::Invalid)?;
        let Some(f) = follower else {
            if let Some(old) = self.tops[leader].follower.take() {
                let old = usize::from(old);
                self.tops[old].leader = None;
                // The window that followed lies above all others again.
                if let Some(w) = self.window(old).filter(|w| Scene::shown(w)) {
                    let r = w.rect;
                    self.add_damage(r);
                }
            }
            return Ok(());
        };
        self.window(f).ok_or(Refusal::Invalid)?;
        let (lt, ft) = (&self.tops[leader], &self.tops[f]);
        if leader == f
            || !ft.mgr
            || lt.mgr
            || lt.follower.is_some()
            || lt.leader.is_some()
            || ft.leader.is_some()
            || ft.follower.is_some()
        {
            return Err(Refusal::Invalid);
        }
        self.tops[leader].follower = Some(f as u8);
        self.tops[f].leader = Some(leader as u8);
        // The frame shows when its window does.
        let visible = self.window(leader).is_some_and(|w| w.visible);
        self.set_visible_one(f, visible);
        // The pair lies together at the top, the follower directly under.
        if self.focus == Some(f) {
            self.focus = None;
            if let Some(top) = self.focus_top(None) {
                self.set_focus(top);
            }
        }
        self.raise(leader)
    }

    // ------------------------------------------------------------ the frame

    /// The rectangles the bands of the frame in progress cover, which do not
    /// overlap: at most `damage::MAX_DAMAGE`, all inside the rectangle `begin`
    /// returned (their bounds are it for a frame that composes only the damage).
    pub fn frame_damage(&self) -> &[Rect] {
        self.frame_damage.rects()
    }

    /// Starts a frame when none is in progress and damage waits: the
    /// bounds of its damage, clipped to the screen. Each window's posted buffer is taken,
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
        if core::mem::take(&mut self.stage.ending) {
            self.slot_pending = None;
            self.slot_working = None;
            self.stage = Stage::NEW;
            self.add_damage(SCREEN);
            self.sweep();
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
                self.damage.add(h);
            }
        }
        // A pending scene is taken when its images are made, at the latest when the
        // wait is over (`wait_over`). Until then the frames go on with the working
        // scene; a frame that is asked for the pending scene (SCENE_COMPOSE) waits,
        // and the end of the images wakes it.
        let hold = self.pending_waits() && !self.wait_over(k);
        if hold && self.stage.compose_due {
            return None;
        }
        let compose_now = core::mem::take(&mut self.stage.compose_due);
        let mut list = self.damage.take();
        let frozen = self.take_scene(compose_now, !list.is_empty(), hold);
        // The damage the commit kept aside came with the taking.
        list.add_all(&self.damage.take());
        // The rectangles cut to the screen; what lies outside it is nothing.
        let mut clipped = DamageList::new();
        for r in list.rects() {
            let x1 = (r.x + r.w).min(WIDTH);
            let y1 = (r.y + r.h).min(HEIGHT);
            if r.x < x1 && r.y < y1 {
                clipped.add(Rect {
                    x: r.x,
                    y: r.y,
                    w: x1 - r.x,
                    h: y1 - r.y,
                });
            }
        }
        let d = clipped.bounds()?;
        let mut first = 0u16;
        let mut resized = 0u16;
        for (i, w) in self.windows.iter_mut().enumerate() {
            let Some(w) = w else {
                continue;
            };
            // A scene that is composed on request keeps what its elements show
            // until the SCENE_COMPOSE that makes the frame.
            if frozen
                && [self.slot_working, self.slot_pending]
                    .into_iter()
                    .flatten()
                    .any(|k| self.defs[usize::from(k)].uses(w.id))
            {
                continue;
            }
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
                // The buffer carries the size SIZE gave: the window has it
                // from this frame.
                // Under a scene the elements name the window's own rectangle: a
                // size that waited is dropped (SIZE is refused while a scene is
                // on, and a commit clears the ones given before it).
                let carried = self.tops[i].posted.take();
                if let Some((nw, nh)) = carried
                    && !(self.slot_working.is_some() || self.slot_pending.is_some())
                    && (nw, nh) != (w.rect.w, w.rect.h)
                {
                    w.rect.w = nw;
                    w.rect.h = nh;
                    self.told[i] = 0;
                    resized |= 1 << i;
                }
                if k == u64::MAX {
                    w.pace.count_taken();
                } else {
                    w.pace.took(k);
                }
            }
            w.in_frame = true;
            // A mask gets neither the focus nor the top place.
            if !core::mem::replace(&mut w.shown_once, true) && w.format != Format::A8 {
                first |= 1 << i;
            }
        }
        for i in 0..MAX_WINDOWS {
            if resized & (1 << i) != 0
                && let Some(w) = self.windows[i]
            {
                let e = Event::at(
                    RESIZED,
                    i as u16,
                    w.id as i32,
                    w.rect.w as i32,
                    w.rect.h as i32,
                );
                self.tell_manager(e);
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
        let mut area = d;
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
        // Only a frame that composes the damage walks its rectangles; the others
        // have the one the frame is over.
        self.frame_damage = DamageList::new();
        if self.kind == FrameKind::Compose && area == d {
            self.frame_damage.add_all(&clipped);
        } else {
            self.frame_damage.add(area);
        }
        self.frame = true;
        // The images the frame reads are taken now and held to its end.
        if let (Some(t), Some(w)) = (self.prep, self.slot_working) {
            for s in self.maps[usize::from(w)] {
                if s != prep::NO_SLOT && self.front[usize::from(s)].is_none() {
                    self.front[usize::from(s)] = t.frame_take(usize::from(s));
                }
            }
        }
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
        if let Some(def) = self.working() {
            // Under a scene the topmost element that shows something is the
            // one that counts: it is a window of the first revision, opaque, the
            // whole of it on the whole screen, with no turn, no reflection, no
            // mask and no transparency.
            let top = def.elements().iter().rev().find_map(|e| {
                let place = self.place_of(e.source)?;
                let w = self.window(place)?;
                (w.current.is_some() && elements::source_fits(e, w.rect.w, w.rect.h))
                    .then_some((e, w, place))
            });
            return match top {
                Some((e, w, place))
                    if w.legacy
                        && w.format == Format::Xrgb
                        && w.rect == SCREEN
                        && fills_the_screen(e) =>
                {
                    Plan::Bypass(place)
                }
                _ => Plan::Compose,
            };
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
        let prep = self.prep;
        for (i, (w, e)) in self.windows.iter_mut().zip(out.iter_mut()).enumerate() {
            let Some(w) = w else {
                continue;
            };
            e.in_frame = core::mem::take(&mut w.in_frame);
            if let Some(r) = w.retired.take() {
                // A buffer the worker may be reading is free when it lets go.
                if prep.is_some_and(|t| t.reads(i, Some(r))) {
                    self.owed[i] |= 1 << r;
                } else {
                    w.bufs[r as usize] = Buf::Free;
                    e.freed = Some(r);
                }
            }
        }
        if let Some(t) = prep {
            for s in 0..prep::SLOTS {
                if self.front[s].take().is_some() {
                    t.frame_release(s);
                }
            }
            if t.unblock() {
                self.wake = true;
            }
        }
        self.frame = false;
        if core::mem::take(&mut self.stage.composing)
            && core::mem::take(&mut self.stage.ask_composed)
        {
            self.stage.composed_now = true;
        }
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
    pub fn tile(&self, damage: Rect) -> (u32, u32) {
        let passes = self.layer_groups(damage);
        self.tile_with(damage, passes.as_ref())
    }

    /// `tile` with the groups of the frame's layers (`layer_groups`) already
    /// made: they are the working scene's over `damage`, those of the windows
    /// when more than WINDOW_GROUPS_ABOVE show over it, or none.
    pub fn tile_with(&self, damage: Rect, passes: Option<&Passes>) -> (u32, u32) {
        let touches = |r: Rect| {
            r.x < damage.x + damage.w
                && damage.x < r.x + r.w
                && r.y < damage.y + damage.h
                && damage.y < r.y + r.h
        };
        if let Some(plan) = passes {
            // Under a scene: the layers are drawn in groups, each over the rectangle
            // of its own elements. The size of a band is that of its group; the
            // size told here is the smallest of the groups.
            let mut size: Option<(u32, u32)> = None;
            for g in 0..plan.groups {
                let (w, h) = plan.band(g);
                size = Some(match size {
                    Some((sw, sh)) if (sh, sw) <= (h, w) => (sw, sh),
                    _ => (w, h),
                });
            }
            return size.unwrap_or((damage.w, BAND_ROWS));
        }
        // What the layers cost: the calls, a price for each line of each, a
        // price for each point of each (hundredths of a tick where it is a
        // line or a point).
        let (mut calls, mut per_row, mut per_point) = (0u32, 0u32, 0u32);
        let mut charge = |p: Price| {
            calls += p.call + LAYER;
            per_row += p.row;
            per_point += p.point;
        };
        for w in self.windows.iter().flatten() {
            if Scene::shown(w) && touches(w.rect) {
                charge(if w.format == Format::Argb {
                    OVER
                } else {
                    OPAQUE
                });
            }
        }
        let covered =
            self.windows.iter().flatten().any(|w| {
                Scene::shown(w) && w.format == Format::Xrgb && covers_rect(w.rect, damage)
            });
        if self
            .drawn_pointer()
            .is_some_and(|p| touches(Scene::cursor_rect(p)))
        {
            charge(OVER);
        }
        if !covered {
            calls += FILL.call;
            per_row += FILL.row;
            per_point += FILL.point;
        }
        band_size(calls, per_row, per_point, damage.w)
    }

    /// How the layers of a frame over `damage` are split into groups, drawn in
    /// turn, bottom up, each in bands of its own over the rectangle of its
    /// elements (cut to the damage). The black the frame starts with (when no
    /// element covers the damage whole) is the group of its own over the damage.
    /// Each element of the working scene that shows something over the damage, in
    /// order, goes to the group it fits (a group's calls come to at most
    /// GROUP_CALLS ticks, or it is one dear element alone); elements under the
    /// topmost opaque one that covers the damage are not drawn at all. The
    /// pointer's picture, when it is over the damage, is the last group. A band
    /// of a group costs by the model what its group's elements cost on its width,
    /// so that however dear the layers a step costs at most BAND_TICKS.
    pub fn passes(&self, def: &Def, damage: Rect) -> Passes {
        let touches = |r: Rect| {
            r.x < damage.x + damage.w
                && damage.x < r.x + r.w
                && r.y < damage.y + damage.h
                && damage.y < r.y + r.h
        };
        let mut plan = Passes::EMPTY;
        // Every element of the scene is a term of a step (`ELEMENT_TERM`), the ones
        // under the base and off the damage too: the step asks each of them.
        plan.elements = def.elements().len() as u32;
        // The topmost opaque element that covers the damage whole: the base.
        let mut base = None;
        for (k, e) in def.elements().iter().enumerate() {
            if let Some(r) = self.element_place_at(k, e)
                && e.transparency == 0
                && covers_rect(r, damage)
            {
                base = Some(k);
            }
        }
        if base.is_none() {
            plan.groups = 1;
            plan.black = true;
            plan.cost[0] = GroupCost::of(FILL, 0, damage);
        }
        // The group that takes the next layer, when it fits.
        let mut open: Option<usize> = None;
        for (k, e) in def.elements().iter().enumerate().skip(base.unwrap_or(0)) {
            let Some(prepared) = self.drawn(k, e) else {
                continue;
            };
            let Some(r) = elements::target_bounds(e) else {
                continue;
            };
            if !touches(r) {
                continue;
            }
            let argb = match prepared {
                Some((slot, _)) => self.slot_argb(slot),
                None => self
                    .place_of(e.source)
                    .and_then(|p| self.window(p))
                    .is_some_and(|w| w.format == Format::Argb),
            };
            // An element drawn from its image is a plain element of the target's size.
            let (first, second) = match prepared {
                Some(_) => elements::classes(&prep::view(e), argb),
                None => elements::classes(e, argb),
            };
            let (a, b) = (PRICES[first.row()], second.map(|c| PRICES[c.row()]));
            // The alpha or the mask is part of the one call of pixman the stretch
            // makes: it adds its rows and points, and no second call. A stretch that
            // is no scale, with a mask and an alpha, is two steps (the product of
            // the mask and the alpha in the work band, then the stretch through
            // it): the group is priced as the second, the dearer of the two, with
            // the mask.
            let two = second == Some(elements::Class::MaskAlpha);
            let b = if two {
                Some(PRICES[elements::Class::Mask.row()])
            } else {
                b
            };
            let calls = a.call + LAYER + a.miss;
            let at = match open {
                Some(g) if plan.cost[g].calls + calls <= GROUP_CALLS => g,
                _ => {
                    plan.groups += 1;
                    plan.groups - 1
                }
            };
            open = Some(at);
            let area = intersect(r, damage);
            plan.group[k] = at as u8;
            plan.members[at] |= 1 << k;
            plan.two_step[at] = two;
            debug_assert!(
                !two || plan.members_of(at) == 1,
                "a group of two steps is alone"
            );
            let c = &mut plan.cost[at];
            c.add(a, LAYER + a.miss, area);
            if let Some(b) = b {
                c.add(b, 0, area);
                c.calls -= b.call;
            }
        }
        let cursor = self.drawn_pointer().map(Scene::cursor_rect);
        if let Some(c) = cursor.filter(|&c| touches(c)) {
            // Under a scene the picture's path may miss the cache too.
            plan.pointer = plan.groups as u8;
            plan.cost[plan.groups] = GroupCost::of(OVER, LAYER + OVER.miss, intersect(c, damage));
            plan.groups += 1;
        }
        plan
    }

    /// The groups of the layers of a frame over `damage`: the working scene's
    /// (`passes`), or, with no scene, the shown windows' (`window_passes`) when
    /// more than WINDOW_GROUPS_ABOVE of them touch the damage; None otherwise.
    pub fn layer_groups(&self, damage: Rect) -> Option<Passes> {
        match self.working() {
            Some(def) => Some(self.passes(def, damage)),
            None => self.window_passes(damage),
        }
    }

    /// The groups of the shown windows over `damage` when no scene is working
    /// and more than WINDOW_GROUPS_ABOVE of the windows touch it (up to that many
    /// the windows are one band's layers, `tile_with`). The windows go in the
    /// order of depth by the rule of `passes`: the topmost opaque window that
    /// covers the damage whole is the base, the windows under it are not drawn,
    /// and when no opaque window covers the damage the black is group 0; each
    /// window that touches the damage is a layer (a copy of an XRGB8888 window, a
    /// laying over of an ARGB8888 one, and the term of a layer) that joins the
    /// open group while the group's calls stay within GROUP_CALLS; the pointer's
    /// picture, when the frame draws it, is the last group. A step pays
    /// ELEMENT_TERM for every shown window (`Passes::elements`). The groups name
    /// the windows by place (`Passes::group_of`), so a window that moves in the
    /// order of depth while the place is walked stays in its group.
    pub fn window_passes(&self, damage: Rect) -> Option<Passes> {
        let touches = |r: Rect| {
            r.x < damage.x + damage.w
                && damage.x < r.x + r.w
                && r.y < damage.y + damage.h
                && damage.y < r.y + r.h
        };
        // The shown windows that touch the damage, counted before the windows are
        // put in order: up to WINDOW_GROUPS_ABOVE they are one band's layers.
        let over = self
            .windows
            .iter()
            .flatten()
            .filter(|w| Scene::shown(w) && touches(w.rect))
            .count();
        if over <= WINDOW_GROUPS_ABOVE {
            return None;
        }
        let (order, n) = self.order();
        let mut plan = Passes::EMPTY;
        plan.windows = true;
        plan.elements = n as u32;
        let base = order[..n].iter().rposition(|&k| {
            self.windows[usize::from(k)]
                .is_some_and(|w| w.format == Format::Xrgb && covers_rect(w.rect, damage))
        });
        if base.is_none() {
            plan.groups = 1;
            plan.black = true;
            plan.cost[0] = GroupCost::of(FILL, 0, damage);
        }
        let mut open: Option<usize> = None;
        for &k in &order[base.unwrap_or(0)..n] {
            let Some(w) = self.windows[usize::from(k)] else {
                continue;
            };
            if !touches(w.rect) {
                continue;
            }
            let price = if w.format == Format::Argb {
                OVER
            } else {
                OPAQUE
            };
            let at = match open {
                Some(g) if plan.cost[g].calls + price.call + LAYER <= GROUP_CALLS => g,
                _ => {
                    plan.groups += 1;
                    plan.groups - 1
                }
            };
            open = Some(at);
            plan.group[usize::from(k)] = at as u8;
            plan.members[at] |= 1 << k;
            plan.placed[usize::from(k)] = w.rect;
            plan.cost[at].add(price, LAYER, intersect(w.rect, damage));
        }
        if let Some(c) = self
            .drawn_pointer()
            .map(Scene::cursor_rect)
            .filter(|&c| touches(c))
        {
            plan.pointer = plan.groups as u8;
            plan.cost[plan.groups] = GroupCost::of(OVER, LAYER, intersect(c, damage));
            plan.groups += 1;
        }
        Some(plan)
    }
}

/// The most windows over a damage that make one band's layers; more are drawn in
/// groups (`Scene::window_passes`).
pub const WINDOW_GROUPS_ABOVE: usize = 8;

// The groups name windows by place in the arrays of the elements' groups, and
// the black and the pointer's picture add two groups.
const _: () = assert!(MAX_WINDOWS <= MAX_ELEMENTS);

/// The calls of a group of layers (ticks): what a step may spend on its calls
/// and the terms of its layers before the rows and the points, half of the
/// work of a band. A layer dearer than that is a group of its own.
pub const GROUP_CALLS: u32 = BAND_TICKS / 2;

// An element of two steps is alone in its group: its layer (the call, the term of a
// layer and the miss of the stretch it makes) is dearer than a group may hold, so
// no element joins it and it joins none (`Scene::passes`).
const _: () = {
    let nearest = PRICES[elements::Class::ScaleNearestOver.row()];
    let bilinear = PRICES[elements::Class::ScaleBilinearOver.row()];
    assert!(nearest.call + LAYER + nearest.miss > GROUP_CALLS);
    assert!(bilinear.call + LAYER + bilinear.miss > GROUP_CALLS);
};

/// The group no element is in.
const NO_GROUP: u8 = u8::MAX;

/// The rectangle both hold (they touch).
fn intersect(a: Rect, b: Rect) -> Rect {
    let (x0, y0) = (a.x.max(b.x), a.y.max(b.y));
    let (x1, y1) = ((a.x + a.w).min(b.x + b.w), (a.y + a.h).min(b.y + b.h));
    Rect {
        x: x0,
        y: y0,
        w: x1 - x0,
        h: y1 - y0,
    }
}

/// The smallest rectangle that holds both.
fn bounds(a: Rect, b: Rect) -> Rect {
    let (x0, y0) = (a.x.min(b.x), a.y.min(b.y));
    let (x1, y1) = ((a.x + a.w).max(b.x + b.w), (a.y + a.h).max(b.y + b.h));
    Rect {
        x: x0,
        y: y0,
        w: x1 - x0,
        h: y1 - y0,
    }
}

/// What a group costs by the model, and where it draws: the calls with the terms
/// of its layers (ticks), the price of a line, the price of the points of one
/// line of the group's rectangle (each layer on its own width) and the price of
/// a column of the layers (hundredths of a tick), and the rectangle.
#[derive(Clone, Copy, Debug)]
pub struct GroupCost {
    pub calls: u32,
    pub per_row: u32,
    /// The points of one line of `rect`, each layer cut to its own width.
    pub per_line: u32,
    /// A point of every layer: the price of a part of a line.
    pub per_point: u32,
    pub rect: Rect,
}

impl GroupCost {
    const EMPTY: GroupCost = GroupCost {
        calls: 0,
        per_row: 0,
        per_line: 0,
        per_point: 0,
        rect: Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        },
    };

    /// A group of one operation `p`, the term of a layer `layer`, over `area`.
    fn of(p: Price, layer: u32, area: Rect) -> GroupCost {
        let mut c = GroupCost::EMPTY;
        c.add(p, layer, area);
        c
    }

    /// An operation of price `p` and the term of a layer (`layer`) over `area`: the
    /// group's rectangle grows to hold it when it has none yet.
    fn add(&mut self, p: Price, layer: u32, area: Rect) {
        self.rect = if self.rect.w == 0 {
            area
        } else {
            bounds(self.rect, area)
        };
        self.calls += p.call + layer;
        self.per_row += p.row;
        self.per_line += p.point * area.w;
        self.per_point += p.point;
    }
}

/// The groups of layers of a frame (`Scene::passes`, `Scene::window_passes`): the
/// group of each element of the working scene (or of each window by place, with
/// no scene) and of the pointer's picture, and what each group costs by the
/// model.
#[derive(Clone, Copy, Debug)]
pub struct Passes {
    group: [u8; MAX_ELEMENTS],
    pointer: u8,
    /// Whether group 0 is the black over the damage.
    black: bool,
    /// Whether the layers are the shown windows (`group` is by place) and not the
    /// elements of a scene.
    windows: bool,
    /// For the groups of windows: the rectangle each window had when the groups
    /// were made, by place. The costs of the groups were charged on these
    /// widths, so a step draws a window on its planned rectangle cut to its
    /// current one (a window that moved meanwhile is repaired by the next frame,
    /// its move damaged the old place and the new).
    placed: [Rect; MAX_ELEMENTS],
    pub groups: usize,
    pub cost: [GroupCost; MAX_ELEMENTS + 2],
    /// The elements of the scene: each is a term of every step (`ELEMENT_TERM`).
    pub elements: u32,
    /// The elements of each group, a bit each (the places of the windows).
    members: [u16; MAX_ELEMENTS + 2],
    /// The groups that are one element drawn in two steps for each band (the
    /// product of its mask and alpha, then the element).
    two_step: [bool; MAX_ELEMENTS + 2],
}

impl Passes {
    const EMPTY: Passes = Passes {
        group: [NO_GROUP; MAX_ELEMENTS],
        pointer: NO_GROUP,
        black: false,
        windows: false,
        placed: [Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        }; MAX_ELEMENTS],
        groups: 0,
        cost: [GroupCost::EMPTY; MAX_ELEMENTS + 2],
        elements: 0,
        members: [0; MAX_ELEMENTS + 2],
        two_step: [false; MAX_ELEMENTS + 2],
    };

    /// The size of a band of group `g` (columns and lines): by the calls of the
    /// group with the terms of every element of the scene and of the step, and
    /// by the rows and the points of the group on its width.
    pub fn band(&self, g: usize) -> (u32, u32) {
        let c = &self.cost[g];
        let calls = c.calls + ELEMENT_TERM * self.elements + SCENE_STEP;
        band_size_of(calls, c)
    }

    /// The group of element `k` of the scene (of the window at place `k` for
    /// the groups of windows), if it draws over the damage.
    pub fn group_of(&self, k: usize) -> Option<usize> {
        Some(usize::from(self.group[k])).filter(|&g| g != usize::from(NO_GROUP))
    }

    /// The group of the pointer's picture, if it is over the damage.
    pub fn pointer_group(&self) -> Option<usize> {
        Some(usize::from(self.pointer)).filter(|&g| g != usize::from(NO_GROUP))
    }

    /// Whether group `g` is drawn in two steps for each band (`PHASE`).
    pub fn is_two_step(&self, g: usize) -> bool {
        self.two_step[g]
    }

    /// The elements (the windows) in group `g`.
    pub fn members_of(&self, g: usize) -> usize {
        self.members[g].count_ones() as usize
    }

    /// Whether group `g` is the black.
    pub fn is_black(&self, g: usize) -> bool {
        self.black && g == 0
    }
}

/// Whether `outer` holds every point of `inner`.
fn covers_rect(outer: Rect, inner: Rect) -> bool {
    outer.x <= inner.x
        && outer.y <= inner.y
        && outer.x + outer.w >= inner.x + inner.w
        && outer.y + outer.h >= inner.y + inner.h
}

/// Who holds the subscription to the ring of the manager (MANAGE SUBSCRIBE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holder {
    Unsubscribed,
    /// A session with MANAGER_MARK (`wm`).
    Manager,
    /// The scene session.
    Scene,
}

/// Whether SCENE_COMMIT and SCENE_COMPOSE are taken: not while a manager that
/// holds no scene has subscribed (input under a scene goes to the ring, which
/// would then be the manager's).
pub const fn scene_allowed(holder: Holder) -> bool {
    !matches!(holder, Holder::Manager)
}

/// Whether a SUBSCRIBE is taken: the scene session's not while a manager has
/// subscribed, and no session's while another session holds the subscription
/// (`same_session`: the holder is the caller itself). The holder's session
/// ending frees it, so a manager that restarts is told BUSY until the old one
/// has gone.
pub const fn subscribe_allowed(holder: Holder, caller_scene: bool, same_session: bool) -> bool {
    if caller_scene && matches!(holder, Holder::Manager) {
        return false;
    }
    matches!(holder, Holder::Unsubscribed) || same_session
}

/// Whether a MANAGE of a session is taken: the scene session's always; a
/// manager's not once the scene has subscribed or has committed a scene.
pub const fn manage_allowed(holder: Holder, scene_committed: bool, caller_scene: bool) -> bool {
    caller_scene || !(matches!(holder, Holder::Scene) || scene_committed)
}

/// Whether an element shows the whole window of the first revision, one point
/// for one, on the whole screen: no turn, no reflection, no mask, no
/// transparency, the source rectangle the whole window (the rule of the direct
/// frame under a scene).
fn fills_the_screen(e: &Element) -> bool {
    e.orient == 0
        && e.transparency == 0
        && e.sx == 0
        && e.sy == 0
        && i64::from(e.sw) == i64::from(WIDTH) << 16
        && i64::from(e.sh) == i64::from(HEIGHT) << 16
        && e.dx == 0
        && e.dy == 0
        && i64::from(e.dw) == i64::from(WIDTH)
        && i64::from(e.dh) == i64::from(HEIGHT)
}

// ---------------------------------------------------------- the scene session

impl Scene {
    /// SCENE_COMMIT: the scene becomes the pending one. Refused INVALID for a
    /// number the windows make wrong (`elements::check`): every element the
    /// numbers allow is drawn. A scene that composes by
    /// itself damages what changed from the scene before it (the pending one,
    /// or the working one), and a taking makes it the working one whole; a
    /// scene composed on request only keeps the damage for SCENE_COMPOSE, and
    /// its COMMITTED, if asked, is told at once.
    pub fn scene_commit(&mut self, commit: &SceneCommit) -> Result<(), Refusal> {
        self.commit_slot().load(commit);
        self.commit_done(commit.flags & proto_comp::ASK_COMMITTED != 0)
    }

    /// The place SCENE_COMMIT's body is parsed into (`Def::parse`): no scene
    /// is in it. `commit_done` makes what was parsed the pending scene.
    pub fn commit_slot(&mut self) -> &mut Def {
        let k = self.free_slot();
        &mut self.defs[k]
    }

    /// The scene parsed into `commit_slot` (with the flag ASK_COMMITTED as the
    /// body said) is checked against the windows and becomes the pending one;
    /// what is refused leaves the scenes as they were.
    pub fn commit_done(&mut self, ask: bool) -> Result<(), Refusal> {
        self.commit_done_at(ask, 1)
    }

    /// `commit_done` of a commit that came at `level`, the level the worker draws
    /// the images of elements whose window has not posted yet.
    pub fn commit_done_at(&mut self, ask: bool, level: u8) -> Result<(), Refusal> {
        let k = self.free_slot();
        let def = &self.defs[k];
        let shape = |id: u32| {
            self.place_of(id)
                .and_then(|p| self.window(p))
                .map(|w| Shape {
                    format: w.format,
                    w: w.rect.w,
                    h: w.rect.h,
                })
        };
        elements::check(def, shape).map_err(|Fault::Invalid| Refusal::Invalid)?;
        self.reserve_images(k, level)?;
        let def = &self.defs[k];
        let active = def.active;
        let damage = elements::scene_damage(self.pending_def().or(self.working()), def);
        // A scene that waits for its images keeps its damage aside until it is taken,
        // and the wait is timed from the first commit that waits.
        let waits = self.waits_map(k);
        if waits {
            if self.pending_since.is_none() {
                self.pending_since = Some(self.period);
                self.waited = 0;
            }
        } else {
            self.pending_since = None;
        }
        if active {
            self.stage.ask_committed |= ask;
            match damage {
                Some(d) if waits => {
                    self.stage.pending_damage = Some(union(self.stage.pending_damage, d));
                    self.slot_pending = Some(k as u8);
                }
                Some(d) => {
                    // The damage kept aside by a pending scene this one replaces
                    // comes with this one.
                    let d = match self.stage.pending_damage.take() {
                        Some(a) => union(Some(a), d),
                        None => d,
                    };
                    self.add_damage(d);
                    self.slot_pending = Some(k as u8);
                }
                // The same picture: nothing is to be drawn, so the scene is the
                // working one now (the bands read the same elements) and is told.
                None => {
                    self.slot_pending = None;
                    self.slot_working = Some(k as u8);
                    self.sweep();
                    if core::mem::take(&mut self.stage.ask_committed) {
                        self.stage.committed_now = true;
                    }
                }
            }
        } else {
            if let Some(d) = damage {
                self.stage.held = Some(union(self.stage.held, d));
            }
            self.slot_pending = Some(k as u8);
            self.stage.committed_now |= ask;
        }
        // The sizes given before the scene are dropped with it (SIZE is refused
        // while a scene is on).
        for t in &mut self.tops {
            t.next = None;
        }
        Ok(())
    }

    /// The images of the elements of the scene parsed into place `k` are reserved
    /// (`prep::Table::reserve`): the slots the working and the pending scene hold
    /// are kept as they are, and when the pool is short for those too, the pending
    /// scene's (the commit replaces it) are let go. LIMIT when the images do not fit
    /// the pool at all, BUSY when they fit once the worker lets go of slots.
    fn reserve_images(&mut self, k: usize, level: u8) -> Result<(), Refusal> {
        let Some(t) = self.prep else {
            return Ok(());
        };
        let mut wants: [Option<(prep::Key, usize)>; MAX_ELEMENTS] = [None; MAX_ELEMENTS];
        for (j, e) in self.defs[k].elements().iter().enumerate() {
            let Some(place) = self.place_of(e.source) else {
                continue;
            };
            let Some(w) = self.window(place) else {
                continue;
            };
            if !w.legacy {
                wants[j] = prep::key_of(e, w.format).map(|key| (key, place));
            }
        }
        let working = self.slot_working.map(|w| self.maps[usize::from(w)]);
        let pending = self.slot_pending.map(|p| self.maps[usize::from(p)]);
        let frame = self.frame_map();
        let mut both = [&prep::NO_MAP; 3];
        let mut n = 0;
        for m in [working.as_ref(), pending.as_ref(), Some(&frame)]
            .into_iter()
            .flatten()
        {
            both[n] = m;
            n += 1;
        }
        let count = self.defs[k].elements().len();
        // With the pending scene's images kept, then, when they do not fit, with
        // them let go (the commit replaces that scene). A refused attempt changes
        // nothing.
        // The pending scene's slots matter only when they are not the working
        // scene's or the frame's: with none of those the second attempt is the first.
        let pending_only = pending.is_some_and(|p| {
            p.iter().any(|&s| {
                s != prep::NO_SLOT
                    && !working.is_some_and(|w| w.contains(&s))
                    && !frame.contains(&s)
            })
        });
        let map = match t.reserve(&wants[..count], &both[..n], level) {
            Ok(map) => map,
            Err(why) if !pending_only => {
                return Err(match why {
                    prep::Refuse::Full => Refusal::Limit,
                    prep::Refuse::Wait => Refusal::Busy,
                });
            }
            Err(_) => {
                let only = [working.as_ref().unwrap_or(&prep::NO_MAP), &frame];
                t.reserve(&wants[..count], &only, level)
                    .map_err(|why| match why {
                        prep::Refuse::Full => Refusal::Limit,
                        prep::Refuse::Wait => Refusal::Busy,
                    })?
            }
        };
        self.maps[k] = map;
        // The holder lends its level to the images its scene waits for.
        for &s in map.iter() {
            if s != prep::NO_SLOT && !t.ready(usize::from(s)) {
                t.raise_level(usize::from(s), level);
            }
        }
        Ok(())
    }

    /// SCENE_COMPOSE: the frame of a scene that is composed on request is to
    /// be made at the next taking. UNSUPPORTED for a scene that composes by
    /// itself, BUSY while the frame of an earlier request is not over. With no
    /// scene committed the scene is the empty one (the background alone).
    pub fn scene_compose(&mut self, ask: bool) -> Result<(), Refusal> {
        if self.scene_active() {
            return Err(Refusal::Unsupported);
        }
        if self.stage.compose_due || self.stage.composing {
            return Err(Refusal::Busy);
        }
        if !self.scene_on() {
            let k = self.free_slot();
            self.defs[k].clear();
            self.maps[k] = prep::NO_MAP;
            self.slot_pending = Some(k as u8);
            self.stage.held = Some(SCREEN);
            self.sweep();
        }
        self.stage.compose_due = true;
        self.stage.ask_composed = ask;
        if let Some(d) = self.stage.held.take() {
            self.add_damage(d);
        }
        Ok(())
    }

    /// The scene session ended: the windows show as the policy of the windows
    /// says from the next taking, the whole screen drawn again.
    pub fn scene_end(&mut self) {
        if !self.scene_on() {
            return;
        }
        if self.frame {
            self.stage.ending = true;
        } else {
            self.slot_pending = None;
            self.slot_working = None;
            self.stage = Stage::NEW;
            self.add_damage(SCREEN);
            self.sweep();
        }
    }

    /// The scene of the taking: the pending scene becomes the working one
    /// whole when it composes by itself or SCENE_COMPOSE asked for this taking
    /// (`compose_now`; `damaged` says the frame has something to show), and the
    /// buffers of the windows no scene shows are given back at once (a window of
    /// the first revision has its FLUSH answered). Whether the scene is held
    /// still: composed on request, with no request for this taking.
    fn take_scene(&mut self, compose_now: bool, damaged: bool, hold: bool) -> bool {
        if self.pending_def().is_some_and(|p| p.active || compose_now) && !hold {
            self.slot_working = self.slot_pending.take();
            self.pending_since = None;
            self.waited = 0;
            if let Some(d) = self.stage.pending_damage.take() {
                self.add_damage(d);
            }
            if core::mem::take(&mut self.stage.ask_committed) {
                self.stage.committed_now = true;
            }
            self.sweep();
        }
        if compose_now {
            if damaged {
                self.stage.composing = true;
            } else if core::mem::take(&mut self.stage.ask_composed) {
                // Nothing changed: the frame is the one on the screen.
                self.stage.composed_now = true;
            }
        }
        if !self.scene_on() {
            return false;
        }
        self.stage.give_back = false;
        let (working, pending) = (
            self.slot_working.map(|k| &self.defs[usize::from(k)]),
            self.slot_pending.map(|k| &self.defs[usize::from(k)]),
        );
        let prep = self.prep;
        for (i, w) in self.windows.iter_mut().enumerate() {
            let Some(w) = w else {
                continue;
            };
            let id = w.id;
            if working.is_some_and(|d| d.uses(id)) || pending.is_some_and(|d| d.uses(id)) {
                continue;
            }
            // A window no element shows keeps the last buffer it posted as its
            // current one, which an element added later shows from its first
            // frame, and the buffer that was current is free at once (no band
            // reads it). A window of the first revision has its FLUSH answered.
            if w.legacy {
                if w.posted.take().is_some() {
                    w.current = Some(0);
                    self.stage.answered |= 1 << i;
                }
            } else if let Some(b) = w.posted.take() {
                w.bufs[b as usize] = Buf::Taken;
                if let Some(old) = w.current.replace(b) {
                    if prep.is_some_and(|t| t.reads(i, Some(old))) {
                        self.owed[i] |= 1 << old;
                    } else {
                        w.bufs[old as usize] = Buf::Free;
                        self.stage.given[i] = Some(old);
                    }
                }
            }
        }
        !self.working().is_some_and(|d| d.active) && !compose_now
    }

    /// What the last taking gave back of the windows no element shows.
    pub fn given_back(&mut self) -> GivenBack {
        GivenBack {
            freed: core::mem::take(&mut self.stage.given),
            answered: core::mem::take(&mut self.stage.answered),
        }
    }

    /// The bits the scene's channel is to be told: COMMITTED, COMPOSED.
    pub fn scene_bits(&mut self) -> SceneBits {
        SceneBits {
            committed: core::mem::take(&mut self.stage.committed_now),
            composed: core::mem::take(&mut self.stage.composed_now),
        }
    }

    /// The working scene, which the bands of a frame read.
    pub fn working(&self) -> Option<&Def> {
        self.slot_working.map(|k| &self.defs[usize::from(k)])
    }

    /// Whether element `k` (`e`) of the working scene draws something now: its
    /// window has a buffer taken and holds the source rectangle, and for an element
    /// whose image the worker makes, an image was made. The inner value is the slot
    /// and the image of the frame's hold for such an element, None for one drawn
    /// from the window's own points.
    pub fn drawn(&self, k: usize, e: &Element) -> Option<Option<(u8, u8)>> {
        let w = self.window(self.place_of(e.source)?)?;
        if w.current.is_none() || !elements::source_fits(e, w.rect.w, w.rect.h) {
            return None;
        }
        // A window of the first revision (its buffer is the pool, which no POST
        // names) is drawn by the bands through the transform, as before.
        if self.prep.is_some() && prep::needs(e) && !w.legacy {
            let slot = self.maps[usize::from(self.slot_working?)][k];
            if slot == prep::NO_SLOT {
                return None;
            }
            let image = self.front[usize::from(slot)]?;
            return Some(Some((slot, image)));
        }
        Some(None)
    }

    /// The place of element `k` of the working scene on the screen (`drawn`): its
    /// target rectangle cut to the screen, which the image has as well.
    pub fn element_place_at(&self, k: usize, e: &Element) -> Option<Rect> {
        self.drawn(k, e)?;
        elements::target_bounds(e)
    }

    /// Whether the image slot `slot` holds is of ARGB8888 (and not XRGB8888).
    fn slot_argb(&self, slot: u8) -> bool {
        self.prep
            .is_some_and(|t| t.geometry(usize::from(slot)).key.argb)
    }

    /// The place on the screen where element `e` of the working scene puts
    /// something now: its target rectangle cut to the screen, when its window
    /// has a buffer taken and holds the source rectangle; None otherwise (it
    /// shows nothing).
    pub fn element_place(&self, e: &Element) -> Option<Rect> {
        let w = self.window(self.place_of(e.source)?)?;
        if w.current.is_none() || !elements::source_fits(e, w.rect.w, w.rect.h) {
            return None;
        }
        elements::target_bounds(e)
    }
}

/// The number of the surface of buffer `buffer` of window `window` for the raster's table
/// of images: the same in every band, and different for every buffer of every window
/// (below `POINTER_IMAGE`).
pub const fn image_of(window: usize, buffer: u8) -> usize {
    window * proto_comp::BUFFERS + buffer as usize
}

/// The number of the pointer's picture, after the buffers of every window.
pub const POINTER_IMAGE: usize = MAX_WINDOWS * proto_comp::BUFFERS;

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

/// The size of a band of a group that costs `c` besides `calls` ticks (its own
/// calls, the terms of the elements and of the step): the lines of the group's
/// width that BAND_TICKS leaves after the calls (at most BAND_ROWS), each layer
/// on its own width, or a part of one line (every layer on the whole of it), at
/// least one point. A group of nothing to price is a band of BAND_ROWS lines.
pub fn band_size_of(calls: u32, c: &GroupCost) -> (u32, u32) {
    let w = c.rect.w;
    if c.per_row + c.per_point == 0 {
        return (w, BAND_ROWS);
    }
    let budget = u64::from(BAND_TICKS.saturating_sub(calls + BAND_FIXED)) * 100;
    let one_row = u64::from(c.per_row) + u64::from(c.per_line);
    let rows = budget / one_row.max(1);
    if rows >= 1 {
        return (w, rows.min(u64::from(BAND_ROWS)) as u32);
    }
    let room = budget.saturating_sub(u64::from(c.per_row));
    let part = room.checked_div(u64::from(c.per_point)).unwrap_or(0);
    (part.clamp(1, u64::from(w)) as u32, 1)
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

    /// The prepared image `image` of slot `slot` (`prep`): its bytes, stride,
    /// size and whether it is of ARGB8888. A source with no prepared images has
    /// none.
    fn prepared(&self, slot: u8, image: u8) -> (&[u8], u32, (u32, u32), bool) {
        let _ = (slot, image);
        (&[], 0, (0, 0), false)
    }
}

/// The number of the surface of image `image` of prepared slot `slot` for the
/// raster's table of images: none (the table looks the image up in its ring).
pub const fn prep_image(slot: u8, image: u8) -> usize {
    let _ = (slot, image);
    usize::MAX
}

/// The pixel operations of a band. The program's is pixman's.
pub trait Raster {
    /// The rectangle of the screen's bytes `fb` (XRGB8888, STRIDE bytes a
    /// line) becomes the colour `rgb` (0x00RRGGBB).
    fn fill(&mut self, fb: &mut [u8], rect: Rect, rgb: u32);

    /// The rectangle becomes black.
    fn black(&mut self, fb: &mut [u8], rect: Rect) {
        self.fill(fb, rect, 0);
    }

    /// The points of `src` (a surface of `size` points, `stride` bytes a
    /// line, in `format`) that start at (`from.0`, `from.1`) go to the
    /// screen at `to`, `area` of them: replacing what is there when `over`
    /// is false, laid over it (premultiplied) when it is true. `image` is the
    /// number of the surface for the raster's own table of images (`image_of`
    /// for a window's buffer, `POINTER_IMAGE` for the pointer's picture): the
    /// same surface has the same number in every band.
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
        image: usize,
    );

    /// An element's drawing: the points of `draw.src` carried to the screen by
    /// the transform, with the mask or the global alpha (`Draw`).
    fn element(&mut self, fb: &mut [u8], draw: &Draw<'_>);

    /// The first step of an element that is stretched, turned or reflected, with a
    /// mask and an alpha: the first `size` points of the area from `at` of the A8
    /// `mask`, times `alpha`, go to the raster's work band; the second step is
    /// `element` with `Draw::work`, which reads that band as its mask. `owner` is
    /// the element (its number in the scene) and the area of the band it is made
    /// for: the raster remembers them for `product_made`. False when the product
    /// was not made.
    fn product(
        &mut self,
        owner: (u32, Rect),
        mask: &Surface<'_>,
        at: (u32, u32),
        alpha: u8,
        size: (u32, u32),
    ) -> bool {
        let _ = (owner, mask, at, alpha, size);
        panic!("this raster has no work band");
    }

    /// The element and the area of the product the work band holds: the last that
    /// `product` made, none when the last failed.
    fn product_made(&self) -> Option<(u32, Rect)> {
        None
    }
}

/// A surface a band reads: a window's buffer (the points of a window of
/// `format`, `stride` bytes a line, `size` points) and the number it has for
/// the raster's table of images (`image_of`).
#[derive(Clone, Copy, Debug)]
pub struct Surface<'a> {
    pub bytes: &'a [u8],
    pub stride: u32,
    pub format: Format,
    pub size: (u32, u32),
    pub image: usize,
}

/// What a band draws of an element that is not a plain copy or laying over: the
/// area of the screen (`area`, cut to the band and the screen), the surface the
/// points come from, and how they come (`matrix`, the map of the screen's
/// points to the surface's, or none when the element is plain and the area's
/// first point is at `from`; `filter`), and what they are mixed with: the
/// element's `transparency` bits, the global `alpha` and the mask (an A8
/// surface the size of the element's target rectangle, `mask_at` the point of
/// it that goes with the area's first point). The meaning of every field is
/// `proto_comp::meaning`'s.
#[derive(Clone, Copy, Debug)]
pub struct Draw<'a> {
    pub src: Surface<'a>,
    pub matrix: Option<[i32; 6]>,
    pub from: (u32, u32),
    pub filter: u32,
    pub transparency: u32,
    pub alpha: u8,
    pub mask: Option<(Surface<'a>, (u32, u32))>,
    /// The mask is the work band that `Raster::product` made for this area (the
    /// transparency has both the mask and the alpha bits, `mask` is none, and the
    /// alpha is already in the band).
    pub work: bool,
    pub area: Rect,
}

/// A place in the frame: the line, and the column from the damage's left edge,
/// where the next band starts, and the group of layers it is at. The frame is
/// done when the line is past the damage's last.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Band {
    pub row: u32,
    pub col: u32,
    /// The group of layers the next step draws on this place (`Plan`): 0 for the
    /// first step of a place, and for the frame of a scene of windows with no
    /// elements, always. The bit `PHASE` says the next step is the second of an
    /// element of two steps.
    pub pass: u32,
}

/// The bit of `Band::pass` that says the band is at the second step of its group
/// (the group is one element that is stretched, turned or reflected, with a mask and
/// an alpha: the first step makes the product of the mask and the alpha, the second
/// draws).
pub const PHASE: u32 = 1 << 31;

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
    let passes = plan(scene, damage);
    compose_planned(scene, damage, at, passes.as_ref(), fb, src, raster)
}

/// The groups of the layers of a frame over `damage` (`Scene::passes` of the
/// working scene, or `Scene::window_passes` with no scene), None when the
/// windows are one band's layers. The caller of a place makes them once
/// and gives them to every `compose_planned` of the place: the place walks one
/// set of groups however the windows change in the middle of it (a window
/// that goes draws nothing in its group; `at.pass` keeps its meaning).
pub fn plan(scene: &Scene, damage: Rect) -> Option<Passes> {
    scene.layer_groups(damage)
}

/// `compose` with the groups of the place made by `plan` (None with no scene).
pub fn compose_planned(
    scene: &Scene,
    damage: Rect,
    at: Band,
    passes: Option<&Passes>,
    fb: &mut [u8],
    src: &impl Source,
    raster: &mut impl Raster,
) -> Band {
    // A band of a scene is the size its group allows; one of windows is the
    // size of the layers that touch the damage.
    let size = match passes {
        Some(plan) if ((at.pass & !PHASE) as usize) < plan.groups => {
            plan.band((at.pass & !PHASE) as usize)
        }
        _ => scene.tile_with(damage, passes),
    };
    compose_with(scene, damage, at, size, passes, fb, src, raster)
}

/// The step of the band `band` of group `pass` of `passes` in a frame of the
/// working scene `def`. The black group fills the band unless an opaque element
/// covers it whole (that element draws over it in its own group). In the group of
/// elements the topmost opaque element of the group that covers the band whole
/// is its base (copied, so the elements of the group under it are not drawn); the
/// elements above lie over it in their order. What an element draws is its
/// source rectangle carried to its target rectangle (the operations of a band:
/// `Raster::blit` for a plain copy or laying over, `Raster::element` for the
/// rest: the stretch, the turn, the reflection, the filter, the global alpha and
/// the mask), cut to the band and the screen; an element whose window has
/// nothing taken or does not hold the source rectangle (a window of the number
/// went and another took its place), or whose mask is not there, draws nothing.
/// The pointer's group draws no element (`compose_with` draws the picture). A
/// group of two steps (`Passes::is_two_step`) makes the product of the mask and
/// the alpha at `phase` false and draws the element at `phase` true.
#[allow(clippy::too_many_arguments)]
fn compose_elements(
    scene: &Scene,
    def: &Def,
    passes: &Passes,
    pass: usize,
    phase: bool,
    band: Rect,
    fb: &mut [u8],
    src: &impl Source,
    raster: &mut impl Raster,
) -> Product {
    let mut product = Product::None;
    let (x0, y0) = (i64::from(band.x), i64::from(band.y));
    let (x1, y1) = (x0 + i64::from(band.w), y0 + i64::from(band.h));
    let els = def.elements();
    let places = |k: usize, e: &Element| {
        let place = scene.place_of(e.source)?;
        scene.drawn(k, e).map(|_| (place, scene.window(place)))
    };
    // Whether an element copies and covers the band whole.
    let covers = |k: usize, e: &Element| {
        e.transparency == 0
            && places(k, e).is_some()
            && i64::from(e.dx) <= x0
            && i64::from(e.dy) <= y0
            && i64::from(e.dx) + i64::from(e.dw) >= x1
            && i64::from(e.dy) + i64::from(e.dh) >= y1
    };
    if passes.is_black(pass) {
        if !els.iter().enumerate().any(|(k, e)| covers(k, e)) {
            raster.fill(fb, band, def.fill());
        }
        return product;
    }
    // The topmost element of the group that covers the band whole.
    let base = els
        .iter()
        .enumerate()
        .rposition(|(k, e)| passes.group_of(k) == Some(pass) && covers(k, e))
        .unwrap_or(0);
    // The area an element covers of the band: None when nothing, or when the
    // element is under the base or has no window to draw from.
    let area_of = |k: usize, e: &Element| -> Option<(Rect, (i64, i64))> {
        if k < base || places(k, e).is_none() {
            return None;
        }
        let (ex0, ey0) = (i64::from(e.dx), i64::from(e.dy));
        let (ax0, ax1) = (x0.max(ex0), x1.min(ex0 + i64::from(e.dw)));
        let (ay0, ay1) = (y0.max(ey0), y1.min(ey0 + i64::from(e.dh)));
        if ax0 >= ax1 || ay0 >= ay1 {
            return None;
        }
        let area = Rect {
            x: ax0 as u32,
            y: ay0 as u32,
            w: (ax1 - ax0) as u32,
            h: (ay1 - ay0) as u32,
        };
        Some((area, (ax0 - ex0, ay0 - ey0)))
    };
    for (k, e) in els.iter().enumerate() {
        if passes.group_of(k) != Some(pass) {
            continue;
        }
        let Some((area, (dx, dy))) = area_of(k, e) else {
            continue;
        };
        let Some((place, Some(w))) = places(k, e) else {
            continue;
        };
        let Some(b) = w.current else {
            continue;
        };
        // The element as it is drawn: its prepared image's view when the worker
        // makes the image, with the image as the surface.
        let Some(prepared) = scene.drawn(k, e) else {
            continue;
        };
        let view;
        let e = if prepared.is_some() {
            view = prep::view(e);
            &view
        } else {
            e
        };
        let plain = elements::is_plain(e);
        let from = (
            ((i64::from(e.sx) >> 16) + dx) as u32,
            ((i64::from(e.sy) >> 16) + dy) as u32,
        );
        let surface = match prepared {
            Some((slot, image)) => {
                let (bytes, stride, size, argb) = src.prepared(slot, image);
                Surface {
                    bytes,
                    stride,
                    format: if argb { Format::Argb } else { Format::Xrgb },
                    size,
                    image: prep_image(slot, image),
                }
            }
            None => Surface {
                bytes: src.pixels(place, b),
                stride: w.stride,
                format: w.format,
                size: (w.rect.w, w.rect.h),
                image: image_of(place, b),
            },
        };
        if plain && (e.transparency == 0 || e.transparency == proto_comp::TRANSPARENCY_SOURCE) {
            raster.blit(
                fb,
                surface.bytes,
                surface.stride,
                surface.format,
                surface.size,
                from,
                (area.x, area.y),
                (area.w, area.h),
                e.transparency == proto_comp::TRANSPARENCY_SOURCE,
                surface.image,
            );
            continue;
        }
        // The mask is a window of its own: A8, the target rectangle's size, a
        // buffer taken. Without one (the window went, was replaced by another
        // of another shape, or has posted nothing) the element is the mask
        // of nothing and draws nothing.
        let mask = if e.transparency & proto_comp::TRANSPARENCY_MASK != 0 {
            let Some(mp) = scene.place_of(e.mask) else {
                continue;
            };
            let Some(mw) = scene.window(mp) else {
                continue;
            };
            let Some(mb) = mw.current else {
                continue;
            };
            if mw.format != Format::A8
                || i64::from(mw.rect.w) != i64::from(e.dw)
                || i64::from(mw.rect.h) != i64::from(e.dh)
            {
                continue;
            }
            Some((
                Surface {
                    bytes: src.pixels(mp, mb),
                    stride: mw.stride,
                    format: Format::A8,
                    size: (mw.rect.w, mw.rect.h),
                    image: image_of(mp, mb),
                },
                (dx as u32, dy as u32),
            ))
        } else {
            None
        };
        // A group of one element with a mask and an alpha that is stretched, turned or
        // reflected is two steps: the product of the mask and the alpha, then the
        // element drawn through it.
        let two = passes.is_two_step(pass);
        if two {
            let Some((m, at)) = &mask else {
                continue;
            };
            let owner = (k as u32, area);
            if !phase {
                let made = raster.product(owner, m, *at, e.alpha as u8, (area.w, area.h));
                product = if made { Product::Made } else { Product::Failed };
                continue;
            }
            // The work band holds the product of this element for this area, or
            // the second step is not drawn: the plan of the step was made again
            // and may name another element than the first step's.
            if raster.product_made() != Some(owner) {
                product = Product::Stale;
                continue;
            }
        }
        raster.element(
            fb,
            &Draw {
                src: surface,
                matrix: if plain {
                    None
                } else {
                    Some(elements::matrix(e))
                },
                from,
                filter: e.filter,
                transparency: e.transparency,
                alpha: e.alpha as u8,
                mask: if two { None } else { mask },
                work: two,
                area,
            },
        );
    }
    product
}

/// What the step of a group of two steps did about the product of the mask and the
/// alpha (`compose_elements`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Product {
    /// The step had no element of such a group to draw on the band.
    None,
    /// The first step made the product.
    Made,
    /// The first step could not make it: the band is not drawn.
    Failed,
    /// The second step found the work band holding another product (the plan was
    /// made again between the steps): the band goes back to the first step.
    Stale,
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
    let passes = scene.working().map(|def| scene.passes(def, damage));
    compose_with(scene, damage, at, size, passes.as_ref(), fb, src, raster)
}

/// The window at place `k` laid on the band `band` of the frame: the part of
/// its current buffer the band holds, nothing when it has none.
fn draw_window(
    scene: &Scene,
    k: u8,
    band: Rect,
    fb: &mut [u8],
    src: &impl Source,
    raster: &mut impl Raster,
) {
    let Some(w) = scene.window(k as usize).copied() else {
        return;
    };
    let Some(b) = w.current else {
        return;
    };
    let (wx0, wx1) = (
        band.x.max(w.rect.x),
        (band.x + band.w).min(w.rect.x + w.rect.w),
    );
    let (wy0, wy1) = (
        band.y.max(w.rect.y),
        (band.y + band.h).min(w.rect.y + w.rect.h),
    );
    if wx0 >= wx1 || wy0 >= wy1 {
        return;
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
        image_of(k as usize, b),
    );
}

/// The step of the band `band` of group `pass` of the groups of windows
/// (`Scene::window_passes`). The black group fills the band. In a group
/// of windows the topmost opaque window of the group that covers the band whole
/// by its planned rectangle is its base, and the windows of the group above it lie over it in the order of
/// depth. The pointer's group draws no window (`compose_with` draws the picture).
fn compose_windows(
    scene: &Scene,
    passes: &Passes,
    pass: usize,
    band: Rect,
    fb: &mut [u8],
    src: &impl Source,
    raster: &mut impl Raster,
) {
    if passes.is_black(pass) {
        raster.black(fb, band);
        return;
    }
    let (order, n) = scene.order();
    // The planned rectangle of a window of this group that touches the band, cut
    // to the band: what the group's price was charged for.
    let part = |k: u8| {
        if passes.group_of(usize::from(k)) != Some(pass) {
            return None;
        }
        let r = passes.placed[usize::from(k)];
        let touches = r.x < band.x + band.w
            && band.x < r.x + r.w
            && r.y < band.y + band.h
            && band.y < r.y + r.h;
        touches.then(|| intersect(r, band))
    };
    let covers = |k: u8| {
        scene
            .window(k as usize)
            .is_some_and(|w| w.format == Format::Xrgb)
            && passes.placed[usize::from(k)].x <= band.x
            && passes.placed[usize::from(k)].y <= band.y
            && passes.placed[usize::from(k)].x + passes.placed[usize::from(k)].w >= band.x + band.w
            && passes.placed[usize::from(k)].y + passes.placed[usize::from(k)].h >= band.y + band.h
            && part(k).is_some()
    };
    let base = order[..n].iter().rposition(|&k| covers(k)).unwrap_or(0);
    for &k in &order[base..n] {
        if let Some(cut) = part(k) {
            draw_window(scene, k, cut, fb, src, raster);
        }
    }
}

/// `compose_sized` with the groups of the layers (`Scene::passes`) of the working
/// scene over `damage` made by the caller (None with no scene).
#[allow(clippy::too_many_arguments)]
fn compose_with(
    scene: &Scene,
    damage: Rect,
    at: Band,
    size: (u32, u32),
    passes: Option<&Passes>,
    fb: &mut [u8],
    src: &impl Source,
    raster: &mut impl Raster,
) -> Band {
    let (width, rows) = size;
    let (group, phase) = ((at.pass & !PHASE) as usize, at.pass & PHASE != 0);
    let done = Band {
        row: damage.y + damage.h,
        col: 0,
        pass: 0,
    };
    // The rectangle this band walks: the group's under a scene, the damage
    // otherwise.
    let groups = match (scene.working(), passes) {
        (_, Some(plan)) if plan.windows => Some((None, plan)),
        (Some(def), Some(plan)) => Some((Some(def), plan)),
        _ => None,
    };
    let walk = match groups {
        Some((_, plan)) => {
            if group >= plan.groups {
                return done;
            }
            plan.cost[group].rect
        }
        None => damage,
    };
    let y0 = at.row.max(walk.y);
    let y1 = (y0 + rows).min(walk.y + walk.h);
    let x0 = (damage.x + at.col).max(walk.x);
    let x1 = (x0 + width).min(walk.x + walk.w);
    if y0 >= y1 || x0 >= x1 {
        return done;
    }
    let band = Rect {
        x: x0,
        y: y0,
        w: x1 - x0,
        h: y1 - y0,
    };
    let mut pointer_now = true;
    let mut product = Product::None;
    if let Some((def, passes)) = groups {
        match def {
            Some(def) => {
                product = compose_elements(scene, def, passes, group, phase, band, fb, src, raster);
            }
            None => compose_windows(scene, passes, group, band, fb, src, raster),
        }
        // The pointer's picture is the last group, drawn in the steps of it.
        pointer_now = passes.pointer_group() == Some(group);
    } else {
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
            raster.black(fb, band);
        }
        for &k in &order[base.unwrap_or(0)..n] {
            draw_window(scene, k, band, fb, src, raster);
        }
    }
    if let Some(p) = scene.drawn_pointer().filter(|_| pointer_now) {
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
                POINTER_IMAGE,
            );
        }
    }
    // The first step of an element of two steps is followed by its second, on the
    // same band, when it made the product; the second that finds another product
    // goes back to the first.
    if let Some((_, plan)) = groups
        && plan.is_two_step(group)
    {
        let again = match (phase, product) {
            (false, Product::Made) => Some(at.pass | PHASE),
            (true, Product::Stale) => Some(group as u32),
            _ => None,
        };
        if let Some(pass) = again {
            return Band {
                row: y0,
                col: x0 - damage.x,
                pass,
            };
        }
    }
    if x1 < walk.x + walk.w {
        Band {
            row: y0,
            col: x1 - damage.x,
            pass: group as u32,
        }
    } else if y1 < walk.y + walk.h {
        Band {
            row: y1,
            col: walk.x - damage.x,
            pass: group as u32,
        }
    } else if let Some((_, plan)) = groups
        && group + 1 < plan.groups
    {
        // The next group, from the corner of its rectangle.
        let next = plan.cost[group + 1].rect;
        Band {
            row: next.y,
            col: next.x - damage.x,
            pass: group as u32 + 1,
        }
    } else {
        done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: u32, y: u32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    /// The id of the first window made at `place`.
    fn gen1(place: usize) -> i32 {
        proto_comp::window_id(place as u32, 1) as i32
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
        fn fill(&mut self, fb: &mut [u8], r: Rect, rgb: u32) {
            for y in r.y..r.y + r.h {
                for x in r.x..r.x + r.w {
                    let at = (y * STRIDE + x * 4) as usize;
                    fb[at..at + 4].copy_from_slice(&rgb.to_le_bytes());
                }
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
            _: usize,
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

        fn element(&mut self, _: &mut [u8], _: &Draw<'_>) {
            panic!("these tests draw plain elements");
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
        let mut at = Band {
            row: d.y,
            col: 0,
            pass: 0,
        };
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
        // Other contexts have their own shares, until the table is full.
        for ctx in 8..(8 + (MAX_WINDOWS / PER_CONTEXT - 1) as u64) {
            for k in 0..PER_CONTEXT as u64 {
                s.create(100 * ctx + k, ctx, rect(0, 0, 10, 10), false, 0)
                    .unwrap();
            }
        }
        assert_eq!(
            s.create(200, 99, rect(0, 0, 10, 10), false, 0),
            Err(Refusal::Limit),
            "the 17th window"
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
        let all = u16::MAX;
        assert_eq!(
            s.create(4, 2, rect(0, 0, 8, 8), false, all),
            Err(Refusal::Limit)
        );
        assert_eq!(s.create(5, 2, rect(0, 0, 8, 8), false, 0).unwrap(), 0);
    }

    #[test]
    fn sixteen_windows_from_four_contexts_fill_the_places_and_a_dying_high_place_is_skipped() {
        let mut s = Scene::new();
        for k in 0..MAX_WINDOWS {
            let ctx = (k % 4) as u64 + 1;
            let i = s.create(k as u64, ctx, rect(0, 0, 8, 8), false, 0).unwrap();
            assert_eq!(i, k, "the places are given in turn");
        }
        // The fifth window of a context is Limit, and so is the 17th window.
        assert_eq!(
            s.create(50, 1, rect(0, 0, 8, 8), false, 0),
            Err(Refusal::Limit)
        );
        assert_eq!(
            s.create(51, 5, rect(0, 0, 8, 8), false, 0),
            Err(Refusal::Limit)
        );
        // Places 9 and 15 go; 9 is still dying (its bit is `taken`), 15 is free.
        s.destroy(9);
        s.destroy(15);
        let b = s.create(60, 2, rect(0, 0, 8, 8), false, 1 << 9).unwrap();
        assert_eq!(b, 15, "place 9 is skipped while it is taken");
        let id = s.window(b).unwrap().id;
        assert_eq!(proto_comp::id_place(id), 15);
        assert_eq!(s.create(61, 4, rect(0, 0, 8, 8), false, 0).unwrap(), 9);
        let id = s.window(9).unwrap().id;
        assert_eq!(proto_comp::id_place(id), 9);
        assert_eq!(proto_comp::id_generation(id), 2);
    }

    #[test]
    fn the_generation_wraps_at_place_15() {
        let mut s = Scene::new();
        for k in 0..MAX_WINDOWS {
            s.create(
                k as u64,
                1 + (k / PER_CONTEXT) as u64,
                rect(0, 0, 8, 8),
                false,
                0,
            )
            .unwrap();
        }
        s.destroy(15);
        s.made[15] = proto_comp::ID_GENERATION_MAX;
        let i = s.create(99, 4, rect(0, 0, 8, 8), false, 0).unwrap();
        assert_eq!(i, 15);
        let id = s.window(i).unwrap().id;
        assert_eq!(proto_comp::id_place(id), 15);
        assert_eq!(proto_comp::id_generation(id), 1);
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
    fn two_far_areas_are_two_rectangles_and_make_fewer_bands_than_their_union() {
        let mut s = Scene::new();
        let i = make(&mut s, 1, 1, SCREEN, 2);
        let bytes = (STRIDE * HEIGHT) as usize;
        let src = flat(&[(i, 0, 1, bytes), (i, 1, 2, bytes)]);
        let mut fb = screen();
        s.post(i, 0, &[]).unwrap();
        frame(&mut s, &mut fb, &src);
        // Two small areas at the opposite corners.
        let (a, b) = (rect(0, 0, 16, 16), rect(600, 380, 16, 16));
        s.post(i, 1, &[a, b]).unwrap();
        let bounds = s.begin().expect("a frame");
        assert_eq!(bounds, rect(0, 0, 616, 396));
        assert_eq!(s.frame_damage(), &[a, b]);
        let list = s.frame_damage().to_vec();
        let mut walked = 0;
        for r in &list {
            walked += draw(&s, *r, &mut fb, &src);
        }
        // The bands of the union of the two, for the same scene.
        let union_bands = draw(&s, bounds, &mut screen(), &src);
        s.end(true);
        assert!(walked >= 2);
        assert!(walked < union_bands, "{walked} bands against {union_bands}");
        // The areas show the new buffer, and what lies between them is as it was.
        assert_eq!(at(&fb, 0, 0), 2);
        assert_eq!(at(&fb, 610, 390), 2);
        assert_eq!(at(&fb, 300, 200), 1);
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
        let mut at = Band {
            row: d.y,
            col: 0,
            pass: 0,
        };
        while at.row < d.y + d.h {
            let next = compose(&s, d, at, &mut fb, &src, &mut Plain);
            assert_eq!(next.col, 0);
            assert_eq!(next.row, (at.row + 11).min(HEIGHT));
            at = next;
            bands += 1;
        }
        assert_eq!(bands, HEIGHT.div_ceil(11));
        assert_eq!(at.row, HEIGHT);
        // A band past the damage is a no-op that says the frame is done.
        let done = Band {
            row: HEIGHT,
            col: 0,
            pass: 0,
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
                    Event::new(CREATE, c as u16, gen1(c)),
                    Event::new(CLOSE, c as u16, gen1(c))
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
                Event::new(CREATE, n as u16, gen1(n)),
                Event::new(CREATE, l as u16, gen1(l))
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
                col: 0,
                pass: 0
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
        /// The layers laid (the copies and the layings over, the pointer's too).
        layers: u32,
    }

    impl Cost {
        fn ticks(&self) -> u32 {
            self.centi.div_ceil(100)
        }
    }

    impl Raster for Cost {
        fn fill(&mut self, _: &mut [u8], r: Rect, _: u32) {
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
            _: usize,
        ) {
            let p = if over { OVER } else { OPAQUE };
            self.calls += p.call;
            self.layers += 1;
            self.centi += p.row * area.1 + p.point * area.0 * area.1;
        }

        fn element(&mut self, _: &mut [u8], _: &Draw<'_>) {
            panic!("these tests draw plain elements");
        }
    }

    /// The most ticks one band of the frame over `d` costs, by the model.
    fn worst_band(s: &Scene, d: Rect, src: &impl Source) -> (u32, u32) {
        let mut fb = screen();
        let mut at = Band {
            row: d.y,
            col: 0,
            pass: 0,
        };
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
        // (a copy of a point is 1.58 in the model, with a call of 897, the term of
        // a layer 288, the fixed term of a band 644 and a row of 63: 11 lines of
        // 640; 12 lines would cost 14 796).
        assert_eq!(s.tile(d), (640, 11));
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
    /// calls, rows and points, the term of each layer, the fixed term of the band
    /// and the black.
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
            + u64::from(LAYER) * 100 * u64::from(over))
        .div_ceil(100)
    }

    /// The raster is told the number of each surface for its table of images: the
    /// same in every band, different for every window and buffer, and the pointer's
    /// picture after all of them.
    #[test]
    fn every_blit_names_its_surface_the_same_way_in_every_band() {
        struct Names(Vec<usize>);
        impl Raster for Names {
            fn fill(&mut self, _: &mut [u8], _: Rect, _: u32) {}
            fn blit(
                &mut self,
                _: &mut [u8],
                _: &[u8],
                _: u32,
                _: Format,
                _: (u32, u32),
                _: (u32, u32),
                _: (u32, u32),
                _: (u32, u32),
                _: bool,
                image: usize,
            ) {
                self.0.push(image);
            }
            fn element(&mut self, _: &mut [u8], _: &Draw<'_>) {}
        }
        struct Nothing;
        impl Source for Nothing {
            fn pixels(&self, _: usize, _: u8) -> &[u8] {
                &[]
            }
        }
        let mut s = Scene::new();
        eight_windows(&mut s, 8);
        s.pointer_to(100, 100);
        let d = rect(100, 100, 320, 200);
        let mut fb = screen();
        let mut seen: Vec<Vec<usize>> = Vec::new();
        let mut at = Band {
            row: d.y,
            col: 0,
            pass: 0,
        };
        for _ in 0..3 {
            let mut names = Names(Vec::new());
            at = compose(&s, d, at, &mut fb, &Nothing, &mut names);
            seen.push(names.0);
        }
        // The windows have the same numbers in every band (the pointer is in the
        // first ones only).
        assert!(seen.iter().all(|n| n[..8] == seen[0][..8]), "{seen:?}");
        let band = &seen[0];
        assert_eq!(band.len(), 9);
        let (windows, pointer) = band.split_at(8);
        assert_eq!(pointer, [POINTER_IMAGE]);
        let mut sorted = windows.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 8);
        assert!(sorted.iter().all(|&i| i < POINTER_IMAGE));
        for k in 0..8usize {
            let w = s.window(k).unwrap();
            assert!(windows.contains(&image_of(k, w.current.unwrap())));
        }
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
        // By the terms measured on the real bands and 14 000 ticks eight layers get 43
        // points of a line (a frame of the 320 by 200 windows is 8 bands a line,
        // 1 600 in all; 151 points and 600 bands before the terms).
        assert_eq!(w8, 43);
        assert_eq!(320u32.div_ceil(w8) * 200, 1_600);
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

    /// The bands of layers the calibration measured under -icount (the greatest
    /// ticks of a whole band as `compose` makes it, with `tile`: the black and the
    /// layers laid over each other on the same rows): the model with the terms of
    /// a band and of every layer is at or above every one.
    #[test]
    fn the_model_with_the_terms_covers_the_calibrated_bands_of_layers() {
        // (layers, width, height, greatest ticks).
        let measured = [
            (1u32, 150u32, 1u32, 2_381u64),
            (1, 150, 4, 5_107),
            (1, 16, 1, 1_759),
            (1, 64, 1, 1_981),
            (1, 76, 8, 5_883),
            (1, 8, 8, 1_841),
            (2, 150, 1, 4_186),
            (2, 150, 4, 9_401),
            (2, 16, 1, 2_991),
            (2, 64, 1, 3_417),
            (2, 76, 8, 10_853),
            (2, 8, 8, 3_097),
            (4, 150, 1, 7_850),
            (4, 16, 1, 5_509),
            (4, 64, 1, 6_343),
            (8, 150, 1, 15_401),
            (8, 16, 1, 10_761),
            (8, 64, 1, 12_411),
            (9, 150, 1, 16_506),
            (9, 64, 1, 13_523),
        ];
        let price = |p: Price, w: u32, h: u32| {
            u64::from(p.call)
                + (u64::from(p.row) * u64::from(h)
                    + u64::from(p.point) * u64::from(w) * u64::from(h))
                .div_ceil(100)
        };
        for (n, w, h, ticks) in measured {
            let model = price(FILL, w, h)
                + u64::from(n) * price(OVER, w, h)
                + u64::from(LAYER) * u64::from(n)
                + u64::from(BAND_FIXED);
            assert!(model >= ticks, "{n} layers {w}x{h}: {model} < {ticks}");
        }
    }

    /// What the real bands of the service spend around their operations, by
    /// layers (`service band`: the greatest ticks of `compose` less its operations
    /// in the run of focus-probe under -icount, 450 bands of eight layers and fewer
    /// of the others): the model's fixed term and the term of each layer cover them
    /// with the margin, a band of seven layers (2 668, preempted: its compose took
    /// 24 612 ticks) left out.
    #[test]
    fn the_terms_cover_what_a_real_band_spends_around_its_operations() {
        let outside = [
            (0u32, 560u32),
            (1, 810),
            (2, 955),
            (3, 1_219),
            (4, 1_427),
            (5, 1_683),
            (6, 1_946),
            (8, 2_458),
        ];
        for (layers, ticks) in outside {
            let model = BAND_FIXED + LAYER * layers;
            assert!(
                u64::from(model) * 100 >= u64::from(ticks) * u64::from(100 + MARGIN_PERCENT),
                "{layers} layers: {model} < {ticks} with the margin"
            );
        }
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
        // The black of one row, the greatest of the calibration's shapes of the call
        // (the measure of the call was 280 ticks at 1 by 1 and 311 at 64 by 1 when the
        // comp-probe judged the constants): the model is above both, margin or none.
        for (w, greatest) in [(1u32, 280u64), (64, 311)] {
            assert!(model(FILL, w, 1) >= greatest, "black {w}x1");
        }
        // The kinds of the elements' operations: every shape the calibration
        // measured is under the model with the constants, by the margin.
        for (kind, w, h, greatest) in measures::SHAPES {
            let priced = kind_model_ticks(kind, w, h).expect("a priced kind");
            assert!(
                priced * 100 >= greatest * u64::from(100 + MARGIN_PERCENT),
                "{kind} {w}x{h}: {priced} below {greatest} with the margin"
            );
        }
        assert_eq!(LOOKUP_MISS, with_margin(LOOKUP_MISS_MEASURED));
        // Every row's miss covers its kind's measure with the margin, and the
        // general miss covers every general kind's; a kind with no measure keeps
        // the general one.
        for p in PRICES {
            let measured = measures::LOOKUPS.iter().any(|(k, _)| *k == p.kind);
            assert!(p.miss >= LOOKUP_MISS || measured, "{}", p.kind);
        }
        for (kind, greatest) in measures::LOOKUPS {
            let p = PRICES
                .iter()
                .find(|p| p.kind == kind)
                .expect("a priced kind");
            assert_eq!(p.miss_measured, greatest, "{kind}");
            assert!(p.miss >= with_margin(greatest), "{kind}");
        }
        // The product of a mask and an alpha has its own key: its measure is in.
        assert!(measures::LOOKUPS.iter().any(|(k, _)| *k == "mask-alpha"));
        for p in PRICES.iter().filter(|p| p.kind.starts_with("fast-")) {
            assert!(
                measures::LOOKUPS.iter().any(|(k, _)| *k == p.kind),
                "{}",
                p.kind
            );
        }
        // The margin of nothing would leave a measure above the constant.
        assert!(with_margin(190) > 190);
    }

    /// A stretch that is no scale, with a mask and an alpha, is two steps of the service
    /// (the product of the mask and the alpha, then the stretch through it). Its price is
    /// the sum of the prices of the two kinds, never measured on its own until the
    /// calibration drew it (`scale-nearest-mask-alpha`, `scale-bilinear-mask-alpha`): the
    /// sum is above every measured shape, by the margin, at both filters.
    #[test]
    fn the_sum_of_a_stretch_and_its_mixing_covers_the_measured_two_steps() {
        for (kind, class) in TWO_STEP_KINDS {
            let shapes: Vec<_> = measures::SHAPES.iter().filter(|s| s.0 == kind).collect();
            assert_eq!(shapes.len(), 17, "{kind}");
            for &&(_, w, h, greatest) in &shapes {
                let sum = kind_model_ticks(kind, w, h).unwrap();
                assert!(
                    sum * 100 >= greatest * u64::from(100 + MARGIN_PERCENT),
                    "{kind} {w}x{h}: the sum {sum} is below {greatest} with the margin"
                );
                // The sum is the two kinds' prices: the product and the stretch with
                // the rows and the points of the mask.
                let (m, a, x) = (
                    PRICES[elements::Class::MaskAlpha.row()],
                    PRICES[class.row()],
                    PRICES[elements::Class::Mask.row()],
                );
                let (w64, h64) = (u64::from(w), u64::from(h));
                let mixing =
                    (u64::from(x.row) * h64 + u64::from(x.point) * w64 * h64).div_ceil(100);
                assert_eq!(sum, model_ticks(m, w, h) + model_ticks(a, w, h) + mixing);
            }
            // The widest measured row is 152 points: the largest shape is pinned.
            assert_eq!(shapes.iter().map(|s| s.1).max(), Some(152), "{kind}");
        }
        assert!(kind_model_ticks("no-such-kind", 1, 1).is_none());
    }

    /// Eight windows with an alpha over the whole screen, the worst case of a
    /// band: by the model no band costs more than BAND_TICKS, and a frame of
    /// the whole screen of one copy is made in the bands the constants give.
    #[test]
    fn eight_translucent_windows_make_bands_within_the_band_ticks() {
        let mut s = Scene::new();
        let mut src = flat(&[]);
        for k in 0..8 {
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

    /// Sixteen windows over the whole screen, from four contexts, ARGB8888 when
    /// `argb(k)`, each of the value `value(k)` in every byte, posted and shown:
    /// the scene, the sources and the damage.
    fn sixteen(
        argb: impl Fn(usize) -> bool,
        rect_of: impl Fn(usize) -> Rect,
        value: impl Fn(usize) -> u8,
    ) -> (Scene, Flat, Rect) {
        let mut s = Scene::new();
        let mut src = flat(&[]);
        for k in 0..MAX_WINDOWS {
            let r = rect_of(k);
            let i = s
                .create(k as u64 + 1, 1 + (k / PER_CONTEXT) as u64, r, false, 0)
                .unwrap();
            if argb(k) {
                s.set_format(i, Format::Argb);
            }
            s.attach(i, 1, r.w * 4).unwrap();
            src.0[i * BUFFERS] = vec![value(k); (r.w * 4 * r.h) as usize];
            s.post(i, 0, &[]).unwrap();
        }
        let d = s.begin().unwrap();
        s.end(true);
        (s, src, d)
    }

    /// The bands of the frame over `d` by the model, each with the terms a
    /// step pays beyond its operations (the layers, the term of every shown
    /// window, the step and the fixed term of a band): the greatest, and the count.
    fn worst_step(s: &Scene, d: Rect, src: &impl Source) -> (u32, u32) {
        let plan = plan(s, d);
        let shown = s.order().1 as u32;
        let mut fb = screen();
        let mut at = Band {
            row: d.y,
            col: 0,
            pass: 0,
        };
        let (mut worst, mut bands) = (0, 0);
        while at.row < d.y + d.h {
            let mut cost = Cost::default();
            at = compose_planned(s, d, at, plan.as_ref(), &mut fb, src, &mut cost);
            let terms = LAYER * cost.layers + ELEMENT_TERM * shown + SCENE_STEP + BAND_FIXED;
            worst = worst.max(cost.calls + cost.ticks() + terms);
            bands += 1;
        }
        (worst, bands)
    }

    #[test]
    fn sixteen_translucent_windows_are_drawn_in_groups_each_within_the_band_ticks() {
        let (s, src, d) = sixteen(|_| true, |_| SCREEN, |_| 0x10);
        assert_eq!(s.open(), 16);
        let plan = plan(&s, d).expect("more than eight layers make groups");
        // The black is group 0, the windows follow, in groups of calls within
        // GROUP_CALLS each (one layer alone may pass it, none here does).
        assert!(plan.is_black(0));
        assert!(plan.groups >= 3, "{} groups", plan.groups);
        let mut layers = 0;
        for g in 1..plan.groups {
            assert!(plan.cost[g].calls <= GROUP_CALLS, "group {g}");
            layers += plan.members_of(g);
        }
        assert_eq!(layers, 16);
        // Without groups the calls of 16 layers alone pass the band.
        const { assert!(16 * (OVER.call + LAYER) > BAND_TICKS) };
        let (worst, bands) = worst_step(&s, d, &src);
        assert!(
            worst <= BAND_TICKS,
            "a band of {worst} ticks by the model, {bands} bands"
        );
        // The size the frame's bound uses is that of the smallest group.
        let (w, rows) = s.tile(d);
        assert!(w >= 1 && rows >= 1);
    }

    #[test]
    fn a_window_that_moves_in_the_middle_of_a_place_keeps_the_band_within_the_ticks() {
        let mut s = Scene::new();
        let mut src = flat(&[]);
        let d = rect(0, 0, 200, 100);
        // One layer over the whole damage and eight of 200 by 100 that lie mostly
        // beyond its right edge, so the plan charges them on 10 points a line.
        let mut places = Vec::new();
        for k in 0..9 {
            let r = if k == 0 {
                rect(0, 0, 200, 100)
            } else {
                rect(190, 0, 200, 100)
            };
            let i = s
                .create(k as u64 + 1, 1 + (k / PER_CONTEXT) as u64, r, false, 0)
                .unwrap();
            s.set_format(i, Format::Argb);
            s.attach(i, 1, r.w * 4).unwrap();
            src.0[i * BUFFERS] = vec![0x10; (r.w * 4 * r.h) as usize];
            s.post(i, 0, &[]).unwrap();
            places.push(i);
        }
        s.begin().unwrap();
        s.end(true);
        let plan = plan(&s, d).expect("nine windows make groups");
        let steady = |s: &Scene| {
            let mut fb = screen();
            let mut at = Band {
                row: d.y,
                col: 0,
                pass: 0,
            };
            let mut worst = 0;
            while at.row < d.y + d.h {
                let mut cost = Cost::default();
                at = compose_planned(s, d, at, Some(&plan), &mut fb, &src, &mut cost);
                let terms = LAYER * cost.layers + ELEMENT_TERM * 9 + SCENE_STEP + BAND_FIXED;
                worst = worst.max(cost.calls + cost.ticks() + terms);
            }
            worst
        };
        assert!(steady(&s) <= BAND_TICKS);
        // The eight move to the left edge in the middle of the place: the plan is
        // the same, and a band is still within the ticks.
        for &i in &places[1..] {
            s.move_to(i, 0, 0).unwrap();
        }
        let worst = steady(&s);
        assert!(
            worst <= BAND_TICKS,
            "a band of {worst} ticks after the move"
        );
    }

    #[test]
    fn eight_windows_over_a_damage_make_no_groups_and_the_nine_do() {
        let mut s = Scene::new();
        let mut src = flat(&[]);
        let mut place = Vec::new();
        for k in 0..9 {
            let i = s
                .create(k as u64 + 1, 1 + (k / PER_CONTEXT) as u64, SCREEN, false, 0)
                .unwrap();
            s.set_format(i, Format::Argb);
            s.attach(i, 1, 2560).unwrap();
            src.0[i * BUFFERS] = vec![0x10; 2560 * 400];
            place.push(i);
            if k < 8 {
                s.post(i, 0, &[]).unwrap();
            }
        }
        s.begin().unwrap();
        s.end(true);
        assert!(s.window_passes(SCREEN).is_none(), "eight windows");
        assert!(plan(&s, SCREEN).is_none());
        // The tile of the eight is the one band of their layers (as before).
        let one = s.tile(SCREEN);
        s.post(place[8], 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        assert!(s.window_passes(SCREEN).is_some(), "nine windows");
        // A damage that only one window touches stays one band's layers.
        let (s2, _, _) = sixteen(|_| true, |k| rect(10 + 40 * k as u32, 10, 30, 30), |_| 0x10);
        assert!(s2.window_passes(rect(10, 10, 30, 30)).is_none());
        assert!(one.1 >= 1);
    }

    #[test]
    fn the_windows_under_an_opaque_cover_are_in_no_group() {
        let mut s = Scene::new();
        let mut src = flat(&[]);
        let mut places = Vec::new();
        for k in 0..12 {
            let i = s
                .create(k as u64 + 1, 1 + (k / PER_CONTEXT) as u64, SCREEN, false, 0)
                .unwrap();
            if k != 5 {
                s.set_format(i, Format::Argb);
            }
            s.attach(i, 1, 2560).unwrap();
            src.0[i * BUFFERS] = vec![0x10 + k as u8; 2560 * 400];
            s.post(i, 0, &[]).unwrap();
            places.push(i);
        }
        s.begin().unwrap();
        s.end(true);
        let plan = plan(&s, SCREEN).unwrap();
        assert!(!plan.is_black(0), "an opaque window covers the damage");
        for &i in &places[..5] {
            assert_eq!(plan.group_of(i), None, "window {i} is under the cover");
        }
        for &i in &places[5..] {
            assert!(plan.group_of(i).is_some(), "window {i} is drawn");
        }
        // Nothing under the cover is read: its buffers are empty in `src`.
        let mut fb = screen();
        let mut under = src;
        for &i in &places[..5] {
            under.0[i * BUFFERS].clear();
        }
        let n = draw(&s, SCREEN, &mut fb, &under);
        assert!(n >= 1);
    }

    /// The frame over `d` in one step of every band, the windows' layers of one
    /// band each (the picture the groups must make).
    fn one_step(s: &Scene, d: Rect, src: &impl Source) -> Vec<u8> {
        let mut fb = screen();
        let mut at = Band {
            row: d.y,
            col: 0,
            pass: 0,
        };
        while at.row < d.y + d.h {
            at = compose_with(s, d, at, (640, 16), None, &mut fb, src, &mut Plain);
        }
        fb
    }

    #[test]
    fn the_groups_of_sixteen_overlapping_windows_draw_the_picture_of_one_step() {
        let (mut s, src, d) = sixteen(
            |k| k % 3 != 0,
            |k| {
                rect(
                    20 + 30 * (k as u32 % 8),
                    10 + 40 * (k as u32 / 8) + 9 * (k as u32 % 5),
                    260 + 7 * k as u32,
                    170,
                )
            },
            |k| 0x15 + 0x0B * k as u8,
        );
        s.pointer_to(300, 120);
        let whole = SCREEN;
        let plan = plan(&s, whole).expect("groups");
        assert!(plan.groups >= 3);
        assert!(plan.pointer_group() == Some(plan.groups - 1));
        let one = one_step(&s, whole, &src);
        let mut grouped = screen();
        let n = draw(&s, whole, &mut grouped, &src);
        assert!(n > 1);
        assert!(
            grouped == one,
            "the groups drew another picture than one step"
        );
        // Something was drawn: not the 0xEE of the empty target.
        assert!(grouped.iter().any(|&b| b != 0xEE));
        // A damage that cuts through them, too.
        let cut = rect(100, 60, 333, 120);
        let one = one_step(&s, cut, &src);
        let mut grouped = screen();
        draw(&s, cut, &mut grouped, &src);
        assert!(grouped == one, "the cut damage differs");
        let _ = d;
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
        // With the fixed term of a band and the term of the layer a copy over the
        // whole width is 11 lines (12 cost 14 796 by the prices): 37 bands.
        assert_eq!(bands, 37);
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
    /// eleven lines (37 bands); a window one column short does not cover it,
    /// the black is charged too, and a band holds eight lines (50 bands).
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
        assert_eq!((rows, n), (11, 37));
        assert_eq!(n, full_screen_bands());
        // One column short: the black is charged.
        let (rows, n) = bands(639);
        assert_eq!((rows, n), (8, 50));
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
        assert_eq!(s.tile(SCREEN), (640, 11));
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
        for k in 0..8 {
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
        assert_eq!(
            (w, first),
            (
                600,
                Band {
                    row: rows,
                    col: 0,
                    pass: 0
                }
            )
        );
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
        assert_eq!(&out[..n], [Event::new(CREATE, a as u16, gen1(a))]);
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

    // ------------------------------------------------------ the screen's opening

    const FB_PAGES: usize = 256;
    const PORTION: usize = 32;

    /// A model of the opening in steps, with faults planted by the tests.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Plant {
        None,
        /// The frame clock takes a frame while the pages are being mapped.
        FrameWhileMapping,
        /// A request is answered Ready before the last portion.
        ReadyEarly,
        /// A stop notice leaves the mapped pages.
        KeepOnStop,
        /// The last portion leaves a page unmapped.
        ShortMapping,
    }

    /// Runs the opening to its end or to a stop after `stop_at` steps and
    /// tells the first rule that broke, if any.
    fn run(plant: Plant, stop_at: Option<usize>) -> Result<(usize, usize), &'static str> {
        let mut phase = ScreenPhase::Closed.begin();
        let mut mapped = 0;
        let mut steps = 0;
        loop {
            if plant == Plant::FrameWhileMapping && phase.has_work() {
                // The clock's check is replaced by a fault.
                return Err("a frame was taken while mapping");
            }
            if phase.takes_frames() && mapped != FB_PAGES {
                return Err("a frame was taken before the last portion");
            }
            let early = plant == Plant::ReadyEarly
                && matches!(phase, ScreenPhase::Mapping { done } if done >= 64);
            if !early && phase.has_work() && phase.ask() != ScreenAsk::Clearing {
                return Err("a request was not answered while mapping");
            }
            if early {
                return Err("a request was told ready before the last portion");
            }
            if stop_at == Some(steps) {
                let (_, pages) = phase.release(FB_PAGES);
                let left = if plant == Plant::KeepOnStop {
                    mapped
                } else {
                    mapped - pages
                };
                return if left == 0 {
                    Ok((steps, pages))
                } else {
                    Err("pages were left mapped")
                };
            }
            match phase {
                ScreenPhase::Mapping { .. } => {
                    let pages = phase.portion(FB_PAGES, PORTION);
                    // The fault: the last page of the last portion is not mapped.
                    let short = plant == Plant::ShortMapping && mapped + pages >= FB_PAGES;
                    mapped += pages - usize::from(short);
                    phase = phase.mapped(pages, FB_PAGES);
                }
                ScreenPhase::Subscribing
                | ScreenPhase::Planes
                | ScreenPhase::Cursor
                | ScreenPhase::Pool => phase = phase.advanced(),
                ScreenPhase::Open => return Ok((steps, mapped)),
                ScreenPhase::Closed => return Err("closed in the middle"),
            }
            steps += 1;
            if mapped > FB_PAGES {
                return Err("more pages than the buffer");
            }
        }
    }

    #[test]
    fn the_screen_opens_in_portions_of_thirty_two_pages() {
        // 8 portions, four finishing steps, then open.
        assert_eq!(run(Plant::None, None), Ok((12, FB_PAGES)));
        assert_eq!(ScreenPhase::Closed.ask(), ScreenAsk::Ask);
        assert_eq!(ScreenPhase::Mapping { done: 0 }.ask(), ScreenAsk::Clearing);
        assert_eq!(ScreenPhase::Subscribing.ask(), ScreenAsk::Clearing);
        assert_eq!(ScreenPhase::Planes.ask(), ScreenAsk::Clearing);
        assert_eq!(ScreenPhase::Cursor.ask(), ScreenAsk::Clearing);
        assert_eq!(ScreenPhase::Pool.ask(), ScreenAsk::Clearing);
        assert_eq!(ScreenPhase::Open.ask(), ScreenAsk::Ready);
        assert!(!ScreenPhase::Closed.takes_frames());
        assert!(!ScreenPhase::Mapping { done: 224 }.takes_frames());
        assert!(!ScreenPhase::Pool.takes_frames());
        assert!(ScreenPhase::Open.takes_frames());
    }

    #[test]
    fn the_last_portion_is_the_rest_and_no_page_is_mapped_twice() {
        assert_eq!(ScreenPhase::Mapping { done: 0 }.portion(70, 32), 32);
        assert_eq!(ScreenPhase::Mapping { done: 64 }.portion(70, 32), 6);
        assert_eq!(ScreenPhase::Mapping { done: 70 }.portion(70, 32), 0);
        assert_eq!(ScreenPhase::Open.portion(70, 32), 0);
        assert_eq!(ScreenPhase::Closed.portion(70, 32), 0);
        assert_eq!(
            ScreenPhase::Mapping { done: 64 }.mapped(6, 70),
            ScreenPhase::Subscribing
        );
        assert_eq!(
            ScreenPhase::Mapping { done: 32 }.mapped(32, 70),
            ScreenPhase::Mapping { done: 64 }
        );
    }

    #[test]
    fn a_stop_in_the_middle_releases_what_was_mapped() {
        for stop in 0..12 {
            let (steps, pages) = run(Plant::None, Some(stop)).unwrap();
            assert_eq!(steps, stop);
            assert_eq!(pages, (stop * PORTION).min(FB_PAGES));
        }
        assert_eq!(
            ScreenPhase::Planes.release(FB_PAGES),
            (ScreenPhase::Closed, FB_PAGES)
        );
        assert_eq!(ScreenPhase::Open.release(FB_PAGES), (ScreenPhase::Open, 0));
        assert_eq!(
            ScreenPhase::Closed.release(FB_PAGES),
            (ScreenPhase::Closed, 0)
        );
    }

    #[test]
    fn the_planted_faults_are_caught() {
        assert!(run(Plant::FrameWhileMapping, None).is_err());
        assert!(run(Plant::ReadyEarly, None).is_err());
        assert!(run(Plant::KeepOnStop, Some(3)).is_err());
        assert!(run(Plant::ShortMapping, None).is_err());
    }

    // ------------------------------------------------------------ the scene

    use proto_comp::{ACTIVE, ASK_COMMITTED, NO_WINDOW, SceneCommit, TRANSPARENCY_SOURCE};

    /// An element showing all of window `source` (`w` by `h` points) at (`x`, `y`).
    fn element(source: usize, x: i32, y: i32, w: i32, h: i32) -> Element {
        Element {
            source: gen1(source) as u32,
            mask: NO_WINDOW,
            sx: 0,
            sy: 0,
            sw: w << 16,
            sh: h << 16,
            dx: x,
            dy: y,
            dw: w,
            dh: h,
            orient: 0,
            filter: 0,
            transparency: 0,
            alpha: 255,
        }
    }

    fn commit(flags: u32, bg: u32, els: &[Element]) -> SceneCommit {
        SceneCommit::new(flags, bg, els).unwrap()
    }

    /// The fixed bytes of a window's buffer 0 and the others, 0 for the rest.
    fn solid(fills: &[(usize, u8)]) -> Flat {
        let mut all = vec![vec![0u8; (STRIDE * HEIGHT) as usize]; MAX_WINDOWS * BUFFERS];
        for &(window, byte) in fills {
            all[window * BUFFERS].fill(byte);
        }
        Flat(all)
    }

    /// A scene of two windows of 100 by 50 (places 0 and 1), both with a buffer
    /// posted, and a third (place 2) that no element shows, posted too.
    fn staged() -> Scene {
        let mut s = Scene::new();
        s.set_manager(true);
        for (k, label) in [1u64, 2, 3].into_iter().enumerate() {
            let i = make(&mut s, label, 1, rect(0, 0, 100, 50), 2);
            assert_eq!(i, k);
        }
        s
    }

    fn post_all(s: &mut Scene) {
        for i in 0..3 {
            s.post(i, 0, &[]).unwrap();
        }
    }

    #[test]
    fn a_commit_waits_for_the_taking_and_a_frame_reads_the_working_scene_only() {
        let mut s = staged();
        s.scene_commit(&commit(ACTIVE, 0xFF00_0000, &[element(0, 0, 0, 100, 50)]))
            .unwrap();
        // Pending: no band could read it yet.
        assert!(s.working().is_none());
        post_all(&mut s);
        let d = s.begin().unwrap();
        assert_eq!(s.working().unwrap().elements().len(), 1);
        let src = solid(&[(0, 0x40), (1, 0x80)]);
        let mut fb = screen();
        // Half of the frame is made, then a commit comes: the frame goes on
        // with the scene it began with, and the new one waits for the next taking.
        let mut at = Band {
            row: d.y,
            col: 0,
            pass: 0,
        };
        at = compose(&s, d, at, &mut fb, &src, &mut Plain);
        s.scene_commit(&commit(
            ACTIVE,
            0xFF00_0000,
            &[element(1, 200, 100, 100, 50)],
        ))
        .unwrap();
        assert_eq!(s.working().unwrap().elements()[0].source, gen1(0) as u32);
        assert!(s.begin().is_none(), "no second frame in work");
        while at.row < d.y + d.h {
            at = compose(&s, d, at, &mut fb, &src, &mut Plain);
        }
        s.end(true);
        assert_eq!(at_point(&fb, 10, 10), 0x40);
        assert_eq!(
            at_point(&fb, 210, 110),
            0,
            "the second scene is not in this frame"
        );
        // The next taking makes the second scene the working one whole. The
        // window it shows posted before it was in a scene: its last buffer is
        // its current one (nothing was lost).
        let d = s.begin().unwrap();
        assert_eq!(s.working().unwrap().elements()[0].source, gen1(1) as u32);
        assert!(d.w > 0);
        draw(&s, d, &mut fb, &src);
        s.end(true);
        assert_eq!(at_point(&fb, 210, 110), 0x80);
        assert_eq!(
            at_point(&fb, 10, 10),
            0,
            "the first scene is gone from the frame"
        );
    }

    /// A window that goes in the middle of a place changes the groups `Scene::passes`
    /// makes: the black group appears once the opaque element that covered the
    /// damage is gone.
    fn two_over_a_screen() -> (Scene, Rect) {
        let mut s = staged();
        s.scene_commit(&commit(
            ACTIVE,
            0xFF00_0000,
            &[element(0, 0, 0, 100, 50), element(1, 20, 10, 100, 50)],
        ))
        .unwrap();
        post_all(&mut s);
        let d = s.begin().unwrap();
        (s, d)
    }

    #[test]
    fn a_window_that_goes_in_the_middle_of_a_place_changes_the_groups() {
        let (mut s, d) = two_over_a_screen();
        let before = plan(&s, d).unwrap();
        s.destroy(0);
        let after = plan(&s, d).unwrap();
        assert_ne!(before.groups, after.groups);
    }

    /// The groups the bands of a place walk, in order, when window 0 goes after
    /// the first band, with the groups made once (`plan`) or made again at each
    /// band (`compose`).
    fn walked(frozen: bool) -> (Vec<u32>, usize) {
        let (mut s, d) = two_over_a_screen();
        let src = solid(&[(0, 0x40), (1, 0x80)]);
        let mut fb = screen();
        let made = plan(&s, d);
        let groups = made.unwrap().groups;
        let mut at = Band {
            row: d.y,
            col: 0,
            pass: 0,
        };
        let mut passes = Vec::new();
        while at.row < d.y + d.h {
            passes.push(at.pass & !PHASE);
            at = if frozen {
                compose_planned(&s, d, at, made.as_ref(), &mut fb, &src, &mut Plain)
            } else {
                compose(&s, d, at, &mut fb, &src, &mut Plain)
            };
            if passes.len() == 1 {
                s.destroy(0);
            }
        }
        (passes, groups)
    }

    #[test]
    fn a_place_walks_the_groups_it_began_with_when_a_window_goes() {
        let (passes, groups) = walked(true);
        assert_eq!(groups, 3);
        // Every group once, in order: the bands of a group are consecutive.
        let mut seen: Vec<u32> = passes.clone();
        seen.dedup();
        assert_eq!(seen, (0..groups as u32).collect::<Vec<_>>(), "{passes:?}");
    }

    #[test]
    fn groups_made_again_at_each_band_lose_their_place_when_a_window_goes() {
        let (passes, groups) = walked(false);
        let mut seen = passes.clone();
        seen.dedup();
        assert_ne!(seen, (0..groups as u32).collect::<Vec<_>>(), "{passes:?}");
    }

    fn at_point(fb: &[u8], x: u32, y: u32) -> u8 {
        at(fb, x, y)
    }

    #[test]
    fn a_commit_that_is_refused_changes_nothing() {
        let mut s = staged();
        let good = commit(ACTIVE, 0xFF00_0000, &[element(0, 0, 0, 100, 50)]);
        s.scene_commit(&good).unwrap();
        // A source rectangle past the window: INVALID.
        let mut big = element(0, 0, 0, 100, 50);
        big.sw = 101 << 16;
        big.dw = 101;
        assert_eq!(
            s.scene_commit(&commit(ACTIVE, 0, &[big])),
            Err(Refusal::Invalid)
        );
        // A mask that is a window of the wrong format: INVALID.
        let mut e = element(0, 0, 0, 100, 50);
        e.transparency = proto_comp::TRANSPARENCY_MASK;
        e.mask = gen1(1) as u32;
        assert_eq!(
            s.scene_commit(&commit(ACTIVE, 0, &[e])),
            Err(Refusal::Invalid)
        );
        // The scene the first commit left is the one taken.
        post_all(&mut s);
        s.begin().unwrap();
        assert_eq!(s.working().unwrap().elements()[0].source, gen1(0) as u32);
        assert_eq!(s.working().unwrap().bg, 0xFF00_0000);
    }

    #[test]
    fn a_window_no_element_shows_keeps_its_last_buffer_and_frees_the_one_before() {
        let mut s = staged();
        s.scene_commit(&commit(ACTIVE, 0xFF00_0000, &[element(0, 0, 0, 100, 50)]))
            .unwrap();
        post_all(&mut s);
        let d = s.begin().unwrap();
        // Windows 1 and 2 posted buffer 0 and no element shows them: it is
        // their current buffer now, and no buffer is free again yet.
        let given = s.given_back();
        assert_eq!(given.freed, [None; MAX_WINDOWS]);
        assert_eq!(s.window(1).unwrap().current, Some(0));
        assert_eq!(s.window(1).unwrap().bufs[0], Buf::Taken);
        assert_eq!(s.window(0).unwrap().bufs[0], Buf::Taken);
        assert_eq!(s.given_back(), GivenBack::default(), "told once");
        draw(&s, d, &mut screen(), &solid(&[]));
        s.end(true);
        // Its next buffer replaces it, and the one before is free at the taking,
        // which has no frame to make: no damage, a buffer free.
        s.post(1, 1, &[]).unwrap();
        assert!(s.damaged());
        assert!(s.begin().is_none());
        assert_eq!(s.given_back().freed[1], Some(0));
        assert!(!s.damaged());
        assert_eq!(s.window(1).unwrap().bufs[0], Buf::Free);
        assert_eq!(s.window(1).unwrap().current, Some(1));
        s.post(1, 0, &[]).unwrap();
    }

    #[test]
    fn an_element_added_later_shows_the_picture_its_window_posted_before() {
        let mut s = staged();
        s.scene_commit(&commit(ACTIVE, 0xFF00_0000, &[element(0, 0, 0, 100, 50)]))
            .unwrap();
        post_all(&mut s);
        let d = s.begin().unwrap();
        draw(&s, d, &mut screen(), &solid(&[]));
        s.end(true);
        // Window 2 posted once, before any element showed it: a static picture.
        s.scene_commit(&commit(
            ACTIVE,
            0xFF00_0000,
            &[element(0, 0, 0, 100, 50), element(2, 300, 200, 100, 50)],
        ))
        .unwrap();
        let d = s.begin().unwrap();
        let mut fb = screen();
        draw(&s, d, &mut fb, &solid(&[(0, 0x10), (2, 0x66)]));
        s.end(true);
        assert_eq!(at_point(&fb, 310, 210), 0x66, "the first frame has it");
    }

    #[test]
    fn a_window_that_took_the_place_of_one_that_went_is_not_shown_by_the_old_element() {
        let mut s = Scene::new();
        s.set_manager(true);
        let a = make(&mut s, 1, 1, rect(0, 0, 100, 50), 2);
        let old = s.window(a).unwrap().id;
        s.post(a, 0, &[]).unwrap();
        let shown = Element {
            source: old,
            ..element(0, 300, 200, 100, 50)
        };
        s.scene_commit(&commit(ACTIVE, 0xFF00_0000, &[shown]))
            .unwrap();
        let d = s.begin().unwrap();
        let mut fb = screen();
        draw(&s, d, &mut fb, &solid(&[(0, 0x55)]));
        s.end(true);
        assert_eq!(at_point(&fb, 310, 210), 0x55);
        // The window goes and a window of another client takes its place.
        s.destroy(a);
        let mut out = [Event::default(); 8];
        let _ = s.take_manager_events(&mut out);
        let b = make(&mut s, 2, 2, rect(0, 0, 100, 50), 2);
        assert_eq!(b, a, "the same place");
        let new = s.window(b).unwrap().id;
        assert_ne!(new, old);
        assert_eq!(proto_comp::id_place(new), proto_comp::id_place(old));
        assert_eq!(s.place_of(old), None);
        assert_eq!(s.place_of(new), Some(b));
        let (n, _) = s.take_manager_events(&mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0], Event::new(CREATE, b as u16, new as i32));
        // The element of the working scene shows nothing of it ...
        s.post(b, 0, &[]).unwrap();
        let d = s.begin().unwrap();
        let mut fb = screen();
        draw(&s, d, &mut fb, &solid(&[(0, 0x77)]));
        s.end(true);
        assert_eq!(at_point(&fb, 310, 210), 0x00, "no foreign content");
        // ... and a commit that still names the old id (it was sent before the
        // holder read the CLOSE event) shows nothing either.
        let late = Element {
            alpha: 200,
            ..shown
        };
        s.scene_commit(&commit(ACTIVE, 0xFF00_0000, &[late]))
            .unwrap();
        let d = s.begin().unwrap();
        let mut fb = screen();
        draw(&s, d, &mut fb, &solid(&[(0, 0x77)]));
        s.end(true);
        assert_eq!(at_point(&fb, 310, 210), 0x00);
        // The commit that names the new id shows it.
        let fresh = Element {
            source: new,
            ..late
        };
        s.scene_commit(&commit(ACTIVE, 0xFF00_0000, &[fresh]))
            .unwrap();
        let d = s.begin().unwrap();
        let mut fb = screen();
        draw(&s, d, &mut fb, &solid(&[(0, 0x77)]));
        s.end(true);
        assert_eq!(at_point(&fb, 310, 210), 0x77);
    }

    #[test]
    fn the_generation_of_an_id_wraps_past_its_greatest_and_never_to_zero() {
        let mut s = Scene::new();
        s.made[0] = proto_comp::ID_GENERATION_MAX - 1;
        let a = make(&mut s, 1, 1, rect(0, 0, 8, 8), 1);
        assert_eq!(
            proto_comp::id_generation(s.window(a).unwrap().id),
            proto_comp::ID_GENERATION_MAX
        );
        assert!(s.window(a).unwrap().id < 1 << 27);
        s.destroy(a);
        let b = make(&mut s, 2, 1, rect(0, 0, 8, 8), 1);
        assert_eq!(proto_comp::id_generation(s.window(b).unwrap().id), 1);
    }

    #[test]
    fn a_mask_window_gets_no_focus_and_no_top_place() {
        let mut s = Scene::new();
        let a = make(&mut s, 1, 1, rect(0, 0, 8, 8), 1);
        s.post(a, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        assert_eq!(s.focus(), Some(a));
        let m = s.create(2, 1, rect(0, 0, 8, 8), false, 0).unwrap();
        s.set_format(m, Format::A8);
        s.attach(m, 1, 8).unwrap();
        s.post(m, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        assert_eq!(s.focus(), Some(a), "the mask took no focus");
    }

    #[test]
    fn the_scene_and_a_manager_exclude_each_other_in_both_orders() {
        use Holder::{Manager, Scene as Holds, Unsubscribed};
        // wm first: the scene is BUSY, in SUBSCRIBE, SCENE_COMMIT and SCENE_COMPOSE.
        assert!(!scene_allowed(Manager));
        assert!(!manage_allowed(Holds, false, false));
        // Nobody, or the scene's own holder: allowed.
        assert!(scene_allowed(Unsubscribed));
        assert!(scene_allowed(Holds));
        // A scene committed before anyone subscribed: the manager's MANAGE is
        // NOT_ALLOWED from the commit on, the scene session's is not.
        assert!(manage_allowed(Unsubscribed, false, false));
        assert!(!manage_allowed(Unsubscribed, true, false));
        assert!(manage_allowed(Unsubscribed, true, true));
        assert!(manage_allowed(Holds, true, true));
        // A manager that holds the subscription goes on while there is no scene.
        assert!(manage_allowed(Manager, false, false));
        // The scene session's own subscription is refused while the manager has.
        assert!(!subscribe_allowed(Manager, true, false));
        assert!(!subscribe_allowed(Manager, true, true));
        assert!(subscribe_allowed(Unsubscribed, true, false));
        assert!(subscribe_allowed(Unsubscribed, false, false));
        // A second manager's session is refused while the first holds the
        // subscription, and the holder itself may subscribe again.
        assert!(!subscribe_allowed(Manager, false, false));
        assert!(subscribe_allowed(Manager, false, true));
        assert!(!subscribe_allowed(Holds, true, false));
        assert!(subscribe_allowed(Holds, true, true));
        assert!(!subscribe_allowed(Holds, false, false));
    }

    #[test]
    fn the_latest_post_of_a_window_no_element_shows_wins_and_the_one_it_replaced_is_free() {
        let mut s = staged();
        s.scene_commit(&commit(ACTIVE, 0xFF00_0000, &[])).unwrap();
        s.post(2, 0, &[]).unwrap();
        s.post(2, 1, &[]).unwrap();
        // "The latest wins": the second POST replaced the first (free at once),
        // and the second is the window's current one.
        assert!(s.begin().is_some());
        assert_eq!(s.given_back().freed[2], None);
        assert_eq!(s.window(2).unwrap().current, Some(1));
        assert_eq!(
            s.window(2).unwrap().bufs,
            [Buf::Free, Buf::Taken, Buf::Free]
        );
    }

    #[test]
    fn a_flush_of_the_first_revision_that_no_element_shows_is_answered_at_the_taking() {
        let mut s = Scene::new();
        let a = legacy_window(&mut s);
        let b = make(&mut s, 2, 2, rect(0, 0, 100, 50), 1);
        s.scene_commit(&commit(ACTIVE, 0, &[element(b, 0, 0, 100, 50)]))
            .unwrap();
        // The commit made a frame to take; the window's FLUSH comes after.
        s.flush(a, SCREEN).unwrap();
        s.post(b, 0, &[]).unwrap();
        s.begin().unwrap();
        let given = s.given_back();
        assert_eq!(given.answered, 1 << a);
        assert_eq!(given.freed[a], None);
        assert!(!s.window(a).unwrap().in_frame, "it waits for no frame");
        assert!(s.window(b).unwrap().in_frame);
        // The window that is shown is not answered.
        s.end(true);
        s.flush(a, rect(0, 0, 10, 10)).unwrap();
        assert!(s.damaged());
        s.begin();
        assert_eq!(s.given_back().answered, 1 << a);
    }

    #[test]
    fn the_masks_of_delivered_rings_and_answered_flushes_carry_the_places_8_to_15() {
        let mut s = Scene::new();
        // Nine windows take the places 0 to 8; the window of the first revision
        // takes place 9 and a window of the second revision place 10.
        for k in 0..9 {
            let r = rect(0, 0, 8, 8);
            s.create(k as u64, 1 + (k / PER_CONTEXT) as u64, r, false, 0)
                .unwrap();
        }
        let a = s.create(100, 4, SCREEN, true, 0).unwrap();
        let b = make(&mut s, 101, 5, rect(0, 0, 100, 50), 1);
        assert_eq!((a, b), (9, 10));
        s.flush(a, SCREEN).unwrap();
        s.scene_commit(&commit(ACTIVE, 0, &[element(b, 0, 0, 100, 50)]))
            .unwrap();
        s.flush(a, SCREEN).unwrap();
        s.post(b, 0, &[]).unwrap();
        s.begin().unwrap();
        let given = s.given_back();
        assert_eq!(given.answered, 1 << 9, "the FLUSH of place 9 is answered");
        // A ring told at a place above 7.
        let c = make(&mut s, 102, 5, rect(10, 10, 20, 20), 1);
        assert_eq!(c, 11);
        s.delivered();
        s.tell(c, Event::new(FOCUS_IN, 0, 0));
        assert_eq!(s.delivered().windows, 1 << 11);
    }

    #[test]
    fn under_a_scene_the_direct_frame_needs_the_top_element_to_be_the_whole_pool() {
        let mut s = direct(true);
        let a = legacy_window(&mut s);
        let b = make(&mut s, 2, 2, rect(0, 0, 100, 50), 1);
        s.post(b, 0, &[]).unwrap();
        let full = element(a, 0, 0, WIDTH as i32, HEIGHT as i32);
        s.scene_commit(&commit(ACTIVE, 0, &[full])).unwrap();
        settle(&mut s);
        assert_eq!(s.plan(), Plan::Bypass(a));
        // Anything but a copy of all of it at the screen's own place.
        let changed = |f: fn(&mut Element)| {
            let mut e = full;
            f(&mut e);
            e
        };
        for e in [
            changed(|e| e.transparency = TRANSPARENCY_SOURCE),
            changed(|e| e.dx = 1),
            changed(|e| e.sx = 1 << 16),
        ] {
            let mut t = direct(true);
            let a = legacy_window(&mut t);
            assert_eq!(a, 0);
            // Their commits may be refused for the scale; the plan reads what was
            // taken, so only the ones the service accepts count.
            if t.scene_commit(&commit(ACTIVE, 0, &[e])).is_ok() {
                settle(&mut t);
                assert_eq!(t.plan(), Plan::Compose, "{e:?}");
            }
        }
        // An element over it that shows something: composed.
        s.scene_commit(&commit(ACTIVE, 0, &[full, element(b, 10, 10, 100, 50)]))
            .unwrap();
        settle(&mut s);
        assert_eq!(s.plan(), Plan::Compose);
        // An element over it whose window shows nothing (none, or never taken):
        // the one below is the top.
        let ghost = element(7, 0, 0, 10, 10);
        let none = Element {
            source: NO_WINDOW,
            ..element(0, 0, 0, 10, 10)
        };
        s.scene_commit(&commit(ACTIVE, 0, &[full, ghost, none]))
            .unwrap();
        settle(&mut s);
        assert_eq!(s.plan(), Plan::Bypass(a));
        // A window of the second revision that fills the screen is composed.
        let mut t = direct(true);
        let c = make(&mut t, 1, 1, SCREEN, 1);
        t.post(c, 0, &[]).unwrap();
        t.scene_commit(&commit(
            ACTIVE,
            0,
            &[element(c, 0, 0, WIDTH as i32, HEIGHT as i32)],
        ))
        .unwrap();
        settle(&mut t);
        assert_eq!(t.plan(), Plan::Compose);
    }

    #[test]
    fn a_scene_composed_on_request_makes_a_frame_only_for_the_request() {
        let mut s = staged();
        let els = [element(0, 0, 0, 100, 50)];
        s.scene_commit(&commit(ASK_COMMITTED, 0xFF00_0000, &els))
            .unwrap();
        // COMMITTED comes at once for a scene that does not compose by itself.
        assert_eq!(
            s.scene_bits(),
            SceneBits {
                committed: true,
                composed: false
            }
        );
        s.post(0, 0, &[]).unwrap();
        assert!(!s.damaged(), "the change waits for SCENE_COMPOSE");
        assert!(s.begin().is_none());
        assert_eq!(
            s.window(0).unwrap().posted,
            Some(0),
            "the buffer is not taken"
        );
        // The request: one frame, and one is not asked for at the same time.
        s.scene_compose(true).unwrap();
        assert_eq!(s.scene_compose(true), Err(Refusal::Busy));
        let d = s.begin().unwrap();
        assert_eq!(s.window(0).unwrap().posted, None);
        assert_eq!(
            s.scene_compose(true),
            Err(Refusal::Busy),
            "the frame is in work"
        );
        draw(&s, d, &mut screen(), &solid(&[]));
        assert!(!s.scene_bits().composed);
        s.end(true);
        assert!(s.scene_bits().composed, "COMPOSED at the end of the frame");
        assert_eq!(s.scene_bits(), SceneBits::default());
        // Again, with nothing changed: the answer comes at the taking, no frame.
        s.scene_compose(true).unwrap();
        assert!(s.begin().is_none());
        assert!(s.scene_bits().composed);
        // A request that did not ask for the bit tells none.
        s.post(0, 1, &[]).unwrap();
        s.scene_compose(false).unwrap();
        assert!(s.begin().is_some());
        s.end(true);
        assert_eq!(s.scene_bits(), SceneBits::default());
        // A scene that composes by itself refuses a request.
        s.scene_commit(&commit(ACTIVE, 0xFF00_0000, &els)).unwrap();
        assert_eq!(s.scene_compose(true), Err(Refusal::Unsupported));
    }

    #[test]
    fn a_compose_with_no_scene_shows_the_background_alone() {
        let mut s = staged();
        s.scene_compose(true).unwrap();
        let d = s.begin().unwrap();
        assert_eq!(d, SCREEN);
        let mut fb = screen();
        draw(&s, d, &mut fb, &solid(&[]));
        s.end(true);
        assert_eq!(at_point(&fb, 300, 300), 0);
        assert!(s.scene_bits().composed);
    }

    #[test]
    fn the_committed_bit_of_an_active_scene_comes_at_the_taking_that_makes_it_working() {
        let mut s = staged();
        s.scene_commit(&commit(
            ACTIVE | ASK_COMMITTED,
            0xFF00_0000,
            &[element(0, 0, 0, 100, 50)],
        ))
        .unwrap();
        assert_eq!(s.scene_bits(), SceneBits::default());
        s.post(0, 0, &[]).unwrap();
        s.begin().unwrap();
        assert!(s.scene_bits().committed);
        s.end(true);
        // Without the flag, none.
        s.scene_commit(&commit(ACTIVE, 0xFF00_0000, &[element(0, 5, 5, 100, 50)]))
            .unwrap();
        s.begin().unwrap();
        assert_eq!(s.scene_bits(), SceneBits::default());
    }

    #[test]
    fn what_a_buffer_changes_on_the_screen_is_what_its_element_carries() {
        let mut s = staged();
        s.scene_commit(&commit(
            ACTIVE,
            0xFF00_0000,
            &[element(0, 300, 200, 100, 50)],
        ))
        .unwrap();
        s.post(0, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        // A rectangle of the window goes to the element's place.
        s.post(0, 1, &[rect(10, 5, 20, 10)]).unwrap();
        assert_eq!(s.begin(), Some(rect(310, 205, 20, 10)));
        s.end(true);
        // A scene that moves the element damages the old place and the new.
        s.scene_commit(&commit(
            ACTIVE,
            0xFF00_0000,
            &[element(0, 320, 200, 100, 50)],
        ))
        .unwrap();
        assert_eq!(s.begin(), Some(rect(300, 200, 120, 50)));
        s.end(true);
        // The window that went damages what it showed.
        s.destroy(0);
        assert_eq!(s.begin(), Some(rect(320, 200, 100, 50)));
    }

    #[test]
    fn a_frame_of_a_scene_draws_the_elements_in_order_over_the_background() {
        let mut s = staged();
        // The third window is ARGB: a point of alpha 0x40 over what is below.
        s.set_format(2, Format::Argb);
        let els = [element(0, 10, 10, 100, 50), element(1, 60, 30, 100, 50)];
        s.scene_commit(&commit(ACTIVE, 0xFF00_8000, &els)).unwrap();
        post_all(&mut s);
        let d = s.begin().unwrap();
        let mut fb = screen();
        draw(&s, d, &mut fb, &solid(&[(0, 0x40), (1, 0x80)]));
        s.end(true);
        // The background where no element is, the first below the second, the
        // second over the first where they meet.
        assert_eq!(
            fb[(300 * STRIDE + 300 * 4) as usize..][..4],
            [0x00, 0x80, 0x00, 0x00]
        );
        assert_eq!(at_point(&fb, 20, 20), 0x40);
        assert_eq!(at_point(&fb, 70, 40), 0x80);
        assert_eq!(at_point(&fb, 5, 5), 0x00, "the background's blue is 0");
        assert_eq!(at_point(&fb, 159, 79), 0x80);
        assert_eq!(at_point(&fb, 160, 79), 0x00);
        // An element laid over by the window's own alpha.
        s.set_format(1, Format::Argb);
        let over = Element {
            transparency: TRANSPARENCY_SOURCE,
            ..element(1, 60, 30, 100, 50)
        };
        s.scene_commit(&commit(
            ACTIVE,
            0xFF00_8000,
            &[element(0, 10, 10, 100, 50), over],
        ))
        .unwrap();
        s.post(1, 1, &[]).unwrap();
        // (the buffer 1 of window 1 is a fresh one for the frame)
        let d = s.begin().unwrap();
        assert!(d.w > 0);
        s.end(true);
    }

    #[test]
    fn a_band_over_an_opaque_element_that_covers_it_has_no_background_fill() {
        let mut s = staged();
        s.scene_commit(&commit(ACTIVE, 0xFF00_0000, &[element(0, 0, 0, 100, 50)]))
            .unwrap();
        s.post(0, 0, &[]).unwrap();
        let d = s.begin().unwrap();
        let mut fb = screen();
        // The band is the element's own: no fill under it (the 0xEE of the
        // screen is replaced by the copy alone, and a fill would show in the
        // price: the tile counts one layer).
        let (w, rows) = s.tile(d);
        assert!(w > 0 && rows > 0);
        draw(&s, d, &mut fb, &solid(&[(0, 0x21)]));
        assert_eq!(at_point(&fb, 50, 25), 0x21);
        // A frame over more than the element is priced with the fill.
        let whole = s.tile(SCREEN);
        assert!(whole.1 <= rows.max(BAND_ROWS));
    }

    #[test]
    fn the_end_of_the_scene_session_returns_the_windows_to_their_policy() {
        let mut s = staged();
        s.scene_commit(&commit(
            ACTIVE,
            0xFF00_0000,
            &[element(0, 300, 200, 100, 50)],
        ))
        .unwrap();
        s.post(0, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        assert!(s.scene_on());
        s.scene_end();
        assert!(!s.scene_on());
        assert!(s.working().is_none());
        // The whole screen is to be drawn again, with the windows as they are:
        // window 0 at its own place of the screen (0, 0).
        assert_eq!(s.begin(), Some(SCREEN));
        let mut fb = screen();
        draw(&s, SCREEN, &mut fb, &solid(&[(0, 0x33)]));
        s.end(true);
        assert_eq!(at_point(&fb, 10, 10), 0x33);
        assert_eq!(at_point(&fb, 310, 210), 0x00);
        // An end in the middle of a frame waits for the next taking.
        s.scene_commit(&commit(ACTIVE, 0xFF00_0000, &[element(0, 5, 5, 100, 50)]))
            .unwrap();
        let d = s.begin().unwrap();
        s.scene_end();
        assert!(s.scene_on(), "the frame in work still reads its scene");
        draw(&s, d, &mut screen(), &solid(&[]));
        s.end(true);
        assert_eq!(s.begin(), Some(SCREEN));
        assert!(!s.scene_on());
    }

    #[test]
    fn under_a_scene_the_pointer_and_the_keys_follow_the_scene_not_the_windows() {
        let mut s = staged();
        // Without a scene a move goes to the window under the pointer.
        s.post(0, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        s.pointer_to(10, 10);
        let mut out = [Event::default(); 8];
        assert_eq!(s.take_events(0, &mut out).0, 1);
        // With one it goes to the scene's ring in the screen's coordinates.
        s.scene_commit(&commit(
            ACTIVE,
            0xFF00_0000,
            &[element(0, 300, 200, 100, 50)],
        ))
        .unwrap();
        let _ = s.take_manager_events(&mut out);
        let focus = s.focus();
        s.pointer_to(310, 210);
        s.button(0x110, true);
        assert_eq!(s.take_events(0, &mut out).0, 0, "the window gets none");
        let (n, _) = s.take_manager_events(&mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0], Event::at(proto_comp::MOVE, 0, 0, 310, 210));
        assert_eq!(out[1], Event::at(proto_comp::BUTTON, 0x110, 1, 310, 210));
        // The click gave no window the focus.
        assert_eq!(s.focus(), focus);
        // A key goes to the window with the focus, as it did.
        s.focus_on(0).unwrap();
        s.key(30, true);
        assert!(s.take_events(0, &mut out).0 >= 1);
    }

    #[test]
    fn a_mask_window_is_never_shown_and_takes_a_stride_of_its_own() {
        let mut s = Scene::new();
        let m = s.create(1, 1, rect(0, 0, 10, 10), false, 0).unwrap();
        s.set_format(m, Format::A8);
        // One byte a point: 10 points is a line of 12 bytes at least, a multiple
        // of 4.
        assert_eq!(s.attach(m, 1, 9), Err(Refusal::Invalid));
        assert_eq!(s.attach(m, 1, 11), Err(Refusal::Invalid));
        assert_eq!(s.attach(m, 1, 13), Err(Refusal::Invalid));
        assert_eq!(s.attach(m, 1, 12), Ok(()));
        s.post(m, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(true);
        assert!(s.window(m).unwrap().current.is_some());
        assert!(!Scene::shown(s.window(m).unwrap()));
        assert_eq!(s.top(None), None);
        assert_eq!(s.hit(5, 5), None);
        // And no frame puts it on the screen.
        let mut fb = screen();
        let d = SCREEN;
        draw(&s, d, &mut fb, &solid(&[(m, 0x77)]));
        assert_eq!(at_point(&fb, 5, 5), 0);
        assert_eq!(Format::A8.line(10), 12);
        assert_eq!(Format::Xrgb.line(10), 40);
    }
}
