// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The pixel operations of a band, which are pixman's (lib/pixman): the
//! rectangle of the screen's bytes black, and the points of a window's
//! buffer replacing or lying over those of the screen.

use compositor::{Draw, Format, Raster};
use pixman::{
    Filter, Format as Px, Images, Mask, Source, Target, composite, composite_element, fill, prepare,
};
use proto_comp::Rect;
use proto_gpu::{HEIGHT, STRIDE, WIDTH};

/// One point on a 4-byte boundary, as pixman wants its memory.
#[repr(align(4))]
struct Point([u8; 4]);

/// The operations over the screen's buffer, and the pixman images they keep.
pub struct Pixman {
    images: Images,
    /// The layers and fills that were not drawn (pixman refused: no
    /// memory in its arena, or a rectangle outside a surface).
    refused: u32,
}

// The images pixman keeps cover every buffer the scene can name: three of each
// window, the screen, the pointer's picture and the pool.
const _: () = assert!(pixman::KEPT >= compositor::MAX_WINDOWS * proto_comp::BUFFERS + 3);

/// The pixman format of a window's points.
const fn format(f: Format) -> Px {
    match f {
        Format::Xrgb => Px::Xrgb8888,
        Format::Argb => Px::Argb8888,
        Format::A8 => Px::A8,
    }
}

/// What each kind of layer costs, for the run of the probes under -icount
/// (feature `steps`): `Pixman` times each of its operations with the
/// counter, and the service tells the totals after a frame, for the
/// constants of `compositor::Scene::tile` (`PRICES`: the prices of a point and the
/// calls of the three kinds) to be set from a run.
#[cfg(feature = "steps")]
pub mod cost {
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    /// The kinds: the black of a band, a layer copied, a layer laid over
    /// others (the pointer's picture too).
    pub const BLACK: usize = 0;
    pub const COPY: usize = 1;
    pub const OVER: usize = 2;
    const NAMES: [&str; 3] = ["black", "copy", "over"];
    /// An operation of at least BIG points tells the cost of a point (its
    /// call is a small part of it); one of at most SMALL points tells the
    /// cost of a call.
    const BIG: u64 = 64;
    const SMALL: u64 = 8;
    /// An operation of at least LARGE points tells the price of a point with
    /// its call under a few percent of it: 256 points make a call of 800
    /// ticks at most 3 ticks a point.
    const LARGE: u64 = 256;

    struct Kind {
        calls: AtomicU64,
        points: AtomicU64,
        ticks: AtomicU64,
        /// Ticks a hundred points, over the big operations.
        big_best: AtomicU64,
        big_worst: AtomicU64,
        /// Ticks of an operation, over the small ones.
        small_best: AtomicU64,
        small_worst: AtomicU64,
        /// The operations of LARGE points or more: how many, the least ticks a
        /// hundred points and the points of the operation that made it, and
        /// the greatest.
        large_calls: AtomicU64,
        large_best: AtomicU64,
        large_best_points: AtomicU64,
        large_worst: AtomicU64,
        /// The three prices of the model `call + rows * row + points * point`,
        /// each the greatest over its class of operations, and how many there
        /// were: the call (one row, 8 points or fewer), the row (at most 16
        /// points wide, at least 8 rows) hundredths of a tick a row with the call
        /// taken off, the point (1 024 points or more) hundredths of a tick with
        /// the call and the rows taken off. The row and the point take off the
        /// greatest call and row known when the operation came, which can only
        /// be less than the final ones: the figure never falls short.
        call_g: AtomicU64,
        row_g: AtomicU64,
        point_g: AtomicU64,
        call_n: AtomicU64,
        row_n: AtomicU64,
        point_n: AtomicU64,
    }

    static KINDS: [Kind; 3] = [const {
        Kind {
            calls: AtomicU64::new(0),
            points: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            big_best: AtomicU64::new(u64::MAX),
            big_worst: AtomicU64::new(0),
            small_best: AtomicU64::new(u64::MAX),
            small_worst: AtomicU64::new(0),
            large_calls: AtomicU64::new(0),
            large_best: AtomicU64::new(u64::MAX),
            large_best_points: AtomicU64::new(0),
            large_worst: AtomicU64::new(0),
            call_g: AtomicU64::new(0),
            row_g: AtomicU64::new(0),
            point_g: AtomicU64::new(0),
            call_n: AtomicU64::new(0),
            row_n: AtomicU64::new(0),
            point_n: AtomicU64::new(0),
        }
    }; 3];
    /// What a band spends outside its operations, by the layers it laid: for
    /// each count of layers (1 to MAX_LAYERS - 1) how many bands, the least and
    /// the greatest ticks of `compose` less the operations in it (the work of
    /// `compose` around the calls: the stacking, the clip, the sources), and the
    /// greatest step of the band's own code with the compose and the operations
    /// of that band.
    pub const MAX_LAYERS: usize = 10;

    struct Split {
        n: AtomicU64,
        outside_least: AtomicU64,
        outside_greatest: AtomicU64,
        total_greatest: AtomicU64,
        compose_at_greatest: AtomicU64,
        ops_at_greatest: AtomicU64,
    }

    static SPLIT: [Split; MAX_LAYERS] = [const {
        Split {
            n: AtomicU64::new(0),
            outside_least: AtomicU64::new(u64::MAX),
            outside_greatest: AtomicU64::new(0),
            total_greatest: AtomicU64::new(0),
            compose_at_greatest: AtomicU64::new(0),
            ops_at_greatest: AtomicU64::new(0),
        }
    }; MAX_LAYERS];
    /// The operations of the band in progress: their ticks and the layers (the
    /// operations other than the black).
    static BAND_OPS: AtomicU64 = AtomicU64::new(0);
    static BAND_LAYERS: AtomicU32 = AtomicU32::new(0);

    /// The bands of the frame in progress and the tick its first band began at, and
    /// the frame that has just ended (told after its step, `tell`).
    static FRAME_BANDS: AtomicU32 = AtomicU32::new(0);
    static FRAME_FIRST: AtomicU64 = AtomicU64::new(0);
    static ENDED_BANDS: AtomicU32 = AtomicU32::new(0);
    static ENDED_TICKS: AtomicU64 = AtomicU64::new(0);
    static ENDED_DUE: AtomicU32 = AtomicU32::new(0);

    /// A band begins: its operations are counted from zero.
    pub fn band_begin() {
        BAND_OPS.store(0, Ordering::Relaxed);
        BAND_LAYERS.store(0, Ordering::Relaxed);
        if FRAME_BANDS.fetch_add(1, Ordering::Relaxed) == 0 {
            FRAME_FIRST.store(rt::time::now(), Ordering::Relaxed);
        }
    }

    /// The band ended: `compose` took `compose` ticks, the band's code in all
    /// `total`.
    pub fn band_end(compose: u64, total: u64) {
        let ops = BAND_OPS.load(Ordering::Relaxed);
        let layers = (BAND_LAYERS.load(Ordering::Relaxed) as usize).min(MAX_LAYERS - 1);
        let s = &SPLIT[layers];
        let outside = compose.saturating_sub(ops);
        s.n.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "irq-trace")]
        trace::band_ended(layers, s.n.load(Ordering::Relaxed), compose, ops, total);
        s.outside_least.fetch_min(outside, Ordering::Relaxed);
        s.outside_greatest.fetch_max(outside, Ordering::Relaxed);
        // The service is one thread: the three go together.
        if total > s.total_greatest.load(Ordering::Relaxed) {
            s.total_greatest.store(total, Ordering::Relaxed);
            s.compose_at_greatest.store(compose, Ordering::Relaxed);
            s.ops_at_greatest.store(ops, Ordering::Relaxed);
        }
    }

    /// What the run with the feature `irq-trace` tells of its bands of two layers or more
    /// (the lines `service band floor`, `place`, `histogram` and `trace`; a run without
    /// the feature tells none of them): the floor of each count of layers, the places the
    /// bands came at, their ticks in bins, and what a band spent in the kernel and in the
    /// table of images. The figures are the thread's own ticks (a preemption of a higher
    /// level does not lengthen them), read by two calls of the kernel in each band, and
    /// the folding runs from the loop's hook after the step, so no step pays for it.
    #[cfg(feature = "irq-trace")]
    pub mod trace {
        use super::{MAX_LAYERS, SPLIT};
        use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

        /// The ticks of the step around a band (the entry, the notice of the next band,
        /// the reply to the loop) that the probes measure, about 1 080: a band whose
        /// ticks and these pass the gate is a step past it.
        const STEP_AROUND: u64 = 1_080;
        /// The count of bands of a count of layers from which the bands are told again
        /// at each power of two: the console is shared with the other services, and a
        /// long line written while another service writes is cut by its lines (a run's
        /// last line of the conductor was lost so), so the lines of the bands are few.
        const TELL_FROM: u64 = 256;

        /// The floor of a count of layers: the band whose own code took least (what a
        /// band costs when nothing else happened in it), its `compose` and operations,
        /// and how many bands passed the gate of a band (a preempted band does too).
        struct Floor {
            least: AtomicU64,
            compose: AtomicU64,
            ops: AtomicU64,
            above_gate: AtomicU64,
        }
        static FLOOR: [Floor; MAX_LAYERS] = [const {
            Floor {
                least: AtomicU64::new(u64::MAX),
                compose: AtomicU64::new(0),
                ops: AtomicU64::new(0),
                above_gate: AtomicU64::new(0),
            }
        }; MAX_LAYERS];
        /// A count of two layers or more has made its 256th, 512th, 1024th... band.
        static BANDS_DUE: AtomicU32 = AtomicU32::new(0);

        /// The place of a band in the work of the service: after an expiry of the timer
        /// that went on with the bands put off by the cap, the first of its frame (the
        /// step before it took the frame), the last before the cap, or any other.
        const PLACES: [&str; 4] = ["rest", "after-expiry", "first-of-frame", "before-cap"];
        const AFTER_EXPIRY: u32 = 1;
        const FIRST_OF_FRAME: u32 = 2;
        const BEFORE_CAP: u32 = 3;
        static NEXT_PLACE: AtomicU32 = AtomicU32::new(0);
        static LAST_PLACE: AtomicU32 = AtomicU32::new(0);
        static LAST_LAYERS: AtomicU32 = AtomicU32::new(0);
        static LAST_DUE: AtomicU32 = AtomicU32::new(0);

        /// The expiry of the timer went on with the bands the cap put off: the next band
        /// is the first after it.
        pub fn mark_expiry() {
            NEXT_PLACE.fetch_max(AFTER_EXPIRY, Ordering::Relaxed);
        }

        /// A frame was taken: the next band is the first of it.
        pub fn mark_first_of_frame() {
            NEXT_PLACE.fetch_max(FIRST_OF_FRAME, Ordering::Relaxed);
        }

        /// The band that just ended reached the cap.
        pub fn mark_before_cap() {
            LAST_PLACE.store(BEFORE_CAP, Ordering::Relaxed);
        }

        /// The bands of two layers or more by their ticks: 500 ticks a bin from 11 000
        /// (bin 0 is under 11 000, the last 19 000 or more), and by the places they came
        /// at (their number, the greatest ticks, and how many passed the gate).
        const BINS: usize = 18;
        const BIN_FROM: u64 = 11_000;
        const BIN_STEP: u64 = 500;
        static HIST: [AtomicU32; BINS] = [const { AtomicU32::new(0) }; BINS];
        struct Place {
            n: AtomicU64,
            greatest: AtomicU64,
            past: AtomicU64,
        }
        static AT: [Place; 4] = [const {
            Place {
                n: AtomicU64::new(0),
                greatest: AtomicU64::new(0),
                past: AtomicU64::new(0),
            }
        }; 4];

        static OWN: AtomicU64 = AtomicU64::new(0);
        static LAST_RAN: AtomicU64 = AtomicU64::new(0);
        static LAST_SYS: AtomicU64 = AtomicU64::new(0);
        static LAST_SCAN: AtomicU32 = AtomicU32::new(0);
        static SYS_LEAST: AtomicU64 = AtomicU64::new(u64::MAX);
        static SCAN_LEAST: AtomicU32 = AtomicU32::new(u32::MAX);
        static UNDER: AtomicU32 = AtomicU32::new(0);
        static UNDER_SYS_GREATEST: AtomicU64 = AtomicU64::new(0);
        static UNDER_SCAN_GREATEST: AtomicU32 = AtomicU32::new(0);
        static PAST: AtomicU32 = AtomicU32::new(0);
        static PAST_SYS_LEAST: AtomicU64 = AtomicU64::new(u64::MAX);
        static PAST_SYS_GREATEST: AtomicU64 = AtomicU64::new(0);
        static PAST_SCAN_LEAST: AtomicU32 = AtomicU32::new(u32::MAX);
        static PAST_SCAN_GREATEST: AtomicU32 = AtomicU32::new(0);
        /// Past the gate with a system time more than 200 ticks over the least.
        static PAST_WITH_SYS: AtomicU32 = AtomicU32::new(0);

        /// The ticks the thread has run, and of them those it has spent in the
        /// kernel (0 and 0 when the kernel does not say): the time of its own
        /// stints, which a higher level that runs in the middle does not lengthen.
        pub fn times() -> (u64, u64) {
            let mut raw = OWN.load(Ordering::Relaxed);
            if raw == 0 {
                match rt::sys::self_thread() {
                    Ok(handle) => {
                        raw = handle.into_raw().0;
                        OWN.store(raw, Ordering::Relaxed);
                    }
                    Err(_) => return (0, 0),
                }
            }
            let handle = core::mem::ManuallyDrop::new(
                rt::handle::Handle::<rt::handle::Thread>::borrowed(abi::Handle(raw)),
            );
            rt::sys::thread_times(&handle).unwrap_or((0, 0))
        }

        /// The band's own figures: the ticks the thread ran in it, those of them in the
        /// kernel, and the entries looked at.
        pub fn band(ran: u64, sys: u64, scan: u32) {
            LAST_RAN.store(ran, Ordering::Relaxed);
            LAST_SYS.store(sys, Ordering::Relaxed);
            LAST_SCAN.store(scan, Ordering::Relaxed);
        }

        /// A band of `layers` layers (the `n`th of its count) ended: `compose` took
        /// `compose` ticks, its operations `ops`, its code in all `total` by the wall.
        pub(super) fn band_ended(layers: usize, n: u64, compose: u64, ops: u64, total: u64) {
            LAST_LAYERS.store(layers as u32, Ordering::Relaxed);
            LAST_PLACE.store(NEXT_PLACE.swap(0, Ordering::Relaxed), Ordering::Relaxed);
            LAST_DUE.store(1, Ordering::Relaxed);
            if layers >= 2 && n >= TELL_FROM && n.is_power_of_two() {
                BANDS_DUE.store(1, Ordering::Relaxed);
            }
            let f = &FLOOR[layers];
            if total > u64::from(compositor::BAND_GATE) {
                f.above_gate.fetch_add(1, Ordering::Relaxed);
            }
            if total < f.least.load(Ordering::Relaxed) {
                f.least.store(total, Ordering::Relaxed);
                f.compose.store(compose, Ordering::Relaxed);
                f.ops.store(ops, Ordering::Relaxed);
            }
        }

        /// The band that ended in the step just taken is folded into the histogram, the
        /// places and the trace (from the loop's hook after the step). Whether the bands
        /// are due to be told.
        pub(super) fn fold() -> bool {
            if LAST_DUE.swap(0, Ordering::Relaxed) != 0 && LAST_LAYERS.load(Ordering::Relaxed) >= 2
            {
                let ran = LAST_RAN.load(Ordering::Relaxed);
                let bin = if ran < BIN_FROM {
                    0
                } else {
                    (1 + (ran - BIN_FROM) / BIN_STEP).min(BINS as u64 - 1) as usize
                };
                HIST[bin].fetch_add(1, Ordering::Relaxed);
                let place = &AT[LAST_PLACE.load(Ordering::Relaxed) as usize % 4];
                place.n.fetch_add(1, Ordering::Relaxed);
                place.greatest.fetch_max(ran, Ordering::Relaxed);
                let past = ran + STEP_AROUND > u64::from(compositor::BAND_GATE);
                if past {
                    place.past.fetch_add(1, Ordering::Relaxed);
                }
                let sys = LAST_SYS.load(Ordering::Relaxed);
                let scan = LAST_SCAN.load(Ordering::Relaxed);
                let least = SYS_LEAST.fetch_min(sys, Ordering::Relaxed).min(sys);
                SCAN_LEAST.fetch_min(scan, Ordering::Relaxed);
                if past {
                    PAST.fetch_add(1, Ordering::Relaxed);
                    PAST_SYS_LEAST.fetch_min(sys, Ordering::Relaxed);
                    PAST_SYS_GREATEST.fetch_max(sys, Ordering::Relaxed);
                    PAST_SCAN_LEAST.fetch_min(scan, Ordering::Relaxed);
                    PAST_SCAN_GREATEST.fetch_max(scan, Ordering::Relaxed);
                    if sys > least + 200 {
                        PAST_WITH_SYS.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    UNDER.fetch_add(1, Ordering::Relaxed);
                    UNDER_SYS_GREATEST.fetch_max(sys, Ordering::Relaxed);
                    UNDER_SCAN_GREATEST.fetch_max(scan, Ordering::Relaxed);
                }
            }
            BANDS_DUE.swap(0, Ordering::Relaxed) != 0
        }

        /// The lines of the bands of two layers or more: the floors, the places, the
        /// histogram and the trace.
        pub(super) fn tell() {
            let zero = |v: u64| if v == u64::MAX { 0 } else { v };
            let zero32 = |v: u32| if v == u32::MAX { 0 } else { v };
            for (layers, f) in FLOOR.iter().enumerate().skip(2) {
                let n = SPLIT[layers].n.load(Ordering::Relaxed);
                if n == 0 {
                    continue;
                }
                rt::println!(
                    "service band floor: 17 layers {layers} n {n} total least {} compose {} ops {} above-gate {}",
                    zero(f.least.load(Ordering::Relaxed)),
                    f.compose.load(Ordering::Relaxed),
                    f.ops.load(Ordering::Relaxed),
                    f.above_gate.load(Ordering::Relaxed),
                );
            }
            for (name, p) in PLACES.iter().zip(&AT) {
                rt::println!(
                    "service band place: 17 {name} n {} greatest {} past-gate {}",
                    p.n.load(Ordering::Relaxed),
                    p.greatest.load(Ordering::Relaxed),
                    p.past.load(Ordering::Relaxed),
                );
            }
            let mut bins = [0u32; BINS];
            for (b, h) in bins.iter_mut().zip(&HIST) {
                *b = h.load(Ordering::Relaxed);
            }
            rt::println!(
                "service band histogram: 17 layers 2+ from {BIN_FROM} step {BIN_STEP}: {bins:?}"
            );
            rt::println!(
                "service band trace: 17 system least {} scan least {} under-gate {} system greatest {} scan greatest {} past-gate {} of which system over the least by 200 or more {} system {}..{} scan {}..{}",
                zero(SYS_LEAST.load(Ordering::Relaxed)),
                zero32(SCAN_LEAST.load(Ordering::Relaxed)),
                UNDER.load(Ordering::Relaxed),
                UNDER_SYS_GREATEST.load(Ordering::Relaxed),
                UNDER_SCAN_GREATEST.load(Ordering::Relaxed),
                PAST.load(Ordering::Relaxed),
                PAST_WITH_SYS.load(Ordering::Relaxed),
                zero(PAST_SYS_LEAST.load(Ordering::Relaxed)),
                PAST_SYS_GREATEST.load(Ordering::Relaxed),
                zero32(PAST_SCAN_LEAST.load(Ordering::Relaxed)),
                PAST_SCAN_GREATEST.load(Ordering::Relaxed),
            );
        }
    }

    /// Frames done, and whether the one that just ended is yet to be told.
    static FRAMES: AtomicU32 = AtomicU32::new(0);
    static DUE: AtomicU32 = AtomicU32::new(0);

    /// The classes of the model: the call is an operation of one row and 8
    /// points or fewer, the row one at most 16 points wide and at least 8 rows,
    /// the point one of 1 024 points or more.
    const CALL_POINTS: u64 = 8;
    const ROW_WIDTH: u64 = 16;
    const ROW_ROWS: u64 = 8;
    const POINT_POINTS: u64 = 1_024;

    /// One operation of `width` by `height` points that took `ticks`.
    pub fn record(kind: usize, width: u64, height: u64, ticks: u64) {
        BAND_OPS.fetch_add(ticks, Ordering::Relaxed);
        if kind != BLACK {
            BAND_LAYERS.fetch_add(1, Ordering::Relaxed);
        }
        let points = width * height;
        let k = &KINDS[kind];
        if height == 1 && points <= CALL_POINTS {
            k.call_n.fetch_add(1, Ordering::Relaxed);
            k.call_g.fetch_max(ticks, Ordering::Relaxed);
        }
        if width <= ROW_WIDTH && height >= ROW_ROWS {
            k.row_n.fetch_add(1, Ordering::Relaxed);
            let net = ticks.saturating_sub(k.call_g.load(Ordering::Relaxed));
            k.row_g.fetch_max(net * 100 / height, Ordering::Relaxed);
        }
        if points >= POINT_POINTS {
            k.point_n.fetch_add(1, Ordering::Relaxed);
            let rows = k.row_g.load(Ordering::Relaxed) * height / 100;
            let net = ticks.saturating_sub(k.call_g.load(Ordering::Relaxed) + rows);
            k.point_g.fetch_max(net * 100 / points, Ordering::Relaxed);
        }
        k.calls.fetch_add(1, Ordering::Relaxed);
        k.points.fetch_add(points, Ordering::Relaxed);
        k.ticks.fetch_add(ticks, Ordering::Relaxed);
        if points >= BIG {
            let per_hundred = ticks * 100 / points;
            k.big_best.fetch_min(per_hundred, Ordering::Relaxed);
            k.big_worst.fetch_max(per_hundred, Ordering::Relaxed);
        } else if points <= SMALL {
            k.small_best.fetch_min(ticks, Ordering::Relaxed);
            k.small_worst.fetch_max(ticks, Ordering::Relaxed);
        }
        if points >= LARGE {
            let per_hundred = ticks * 100 / points;
            k.large_calls.fetch_add(1, Ordering::Relaxed);
            // The service is one thread: the least and its points go together.
            if per_hundred < k.large_best.load(Ordering::Relaxed) {
                k.large_best.store(per_hundred, Ordering::Relaxed);
                k.large_best_points.store(points, Ordering::Relaxed);
            }
            k.large_worst.fetch_max(per_hundred, Ordering::Relaxed);
        }
    }

    /// A frame ended.
    pub fn frame_done() {
        FRAMES.fetch_add(1, Ordering::Relaxed);
        DUE.store(1, Ordering::Relaxed);
        let bands = FRAME_BANDS.swap(0, Ordering::Relaxed);
        if bands != 0 {
            ENDED_BANDS.store(bands, Ordering::Relaxed);
            ENDED_TICKS.store(
                rt::time::now() - FRAME_FIRST.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            ENDED_DUE.store(1, Ordering::Relaxed);
        }
    }

    /// Runs after each step of the loop (rt::service::step_after): at the
    /// 1st, 2nd, 4th, 8th... frame it tells the totals so far, a line for
    /// each kind that has been drawn: `service raster: 17 KIND calls C
    /// points P ticks T big B W small S L large N B P W price C R P NC NR NP`, B and W the least and the
    /// greatest ticks a hundred points of an operation of BIG points or more, S
    /// and L the least and the greatest ticks of an operation of SMALL points or
    /// fewer (0 when there was none), then, over the operations of LARGE points
    /// or more, their number N, the least ticks a hundred points B with the
    /// points P of the operation that made it, and the greatest W. The
    /// greatest values include the preemption of a higher level in the middle
    /// of an operation; the least do not. The price of a point is B less the
    /// call S, a hundred over P; the call is S. Then the three prices of the
    /// model (`record`), each the greatest over its class and the operations of
    /// each class: C the call in ticks, R the row and P the point in hundredths of
    /// a tick.
    pub fn tell() {
        super::stack::watch();
        #[cfg(feature = "irq-trace")]
        if trace::fold() {
            trace::tell();
        }
        // A frame made by bands: how many, and the time from its first band to its end.
        if ENDED_DUE.swap(0, Ordering::Relaxed) != 0 {
            rt::println!(
                "service frame: 17 n {} bands {} us {}",
                FRAMES.load(Ordering::Relaxed),
                ENDED_BANDS.load(Ordering::Relaxed),
                rt::time::ticks_to_ns(ENDED_TICKS.load(Ordering::Relaxed)) / 1_000
            );
        }
        if DUE.swap(0, Ordering::Relaxed) == 0 {
            return;
        }
        if !FRAMES.load(Ordering::Relaxed).is_power_of_two() {
            return;
        }
        let zero = |v: u64| if v == u64::MAX { 0 } else { v };
        for (k, name) in KINDS.iter().zip(NAMES) {
            let calls = k.calls.load(Ordering::Relaxed);
            if calls == 0 {
                continue;
            }
            rt::println!(
                "service raster: 17 {name} calls {calls} points {} ticks {} big {} {} small {} {} large {} {} {} {} price {} {} {} {} {} {}",
                k.points.load(Ordering::Relaxed),
                k.ticks.load(Ordering::Relaxed),
                zero(k.big_best.load(Ordering::Relaxed)),
                k.big_worst.load(Ordering::Relaxed),
                zero(k.small_best.load(Ordering::Relaxed)),
                k.small_worst.load(Ordering::Relaxed),
                k.large_calls.load(Ordering::Relaxed),
                zero(k.large_best.load(Ordering::Relaxed)),
                k.large_best_points.load(Ordering::Relaxed),
                k.large_worst.load(Ordering::Relaxed),
                k.call_g.load(Ordering::Relaxed),
                k.row_g.load(Ordering::Relaxed),
                k.point_g.load(Ordering::Relaxed),
                k.call_n.load(Ordering::Relaxed),
                k.row_n.load(Ordering::Relaxed),
                k.point_n.load(Ordering::Relaxed),
            );
        }
        for (layers, s) in SPLIT.iter().enumerate() {
            let n = s.n.load(Ordering::Relaxed);
            if n == 0 {
                continue;
            }
            rt::println!(
                "service band: 17 layers {layers} n {n} outside least {} greatest {} total greatest {} compose {} ops {}",
                s.outside_least.load(Ordering::Relaxed),
                s.outside_greatest.load(Ordering::Relaxed),
                s.total_greatest.load(Ordering::Relaxed),
                s.compose_at_greatest.load(Ordering::Relaxed),
                s.ops_at_greatest.load(Ordering::Relaxed),
            );
        }
    }
}

/// The deepest the stack of the service goes, for the run of the probes under
/// -icount (feature `steps`): at the start the stack below the entry is painted
/// with a pattern (`paint`), and each step after it looks at a few words
/// (`watch`), from the lowest painted address up, for the lowest that no longer
/// holds the pattern; a new lowest is told as `service stack: 17 depth D painted
/// P` (bytes from the top of the stack, bytes painted). The words between the top
/// and the painted part (the frame of `main` and 2 KiB below it, which the
/// painting's own frames use) count as used, so the depth is at least that.
#[cfg(feature = "steps")]
pub mod stack {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

    const PATTERN: u64 = 0xA5A5_A5A5_A5A5_A5A5;
    /// The bytes painted, below the entry of the program: less than its stack, so
    /// that the guard below it is not touched.
    pub const PAINTED: usize = compositor::STACK_BYTES - 16 * 1024;
    const _: () = assert!(PAINTED + 16 * 1024 <= compositor::STACK_BYTES);
    const WORDS_A_STEP: usize = 128;

    static TOP: AtomicUsize = AtomicUsize::new(0);
    static BOTTOM: AtomicUsize = AtomicUsize::new(0);
    static LOW: AtomicUsize = AtomicUsize::new(0);
    static CURSOR: AtomicUsize = AtomicUsize::new(0);

    /// Paints the stack below the caller's frame.
    pub fn paint() {
        let sp: usize;
        // SAFETY: reads the stack pointer.
        unsafe { core::arch::asm!("mov {}, sp", out(reg) sp) };
        // The stack is right under INIT_STACK_TOP; what is above this frame is
        // in use (the frame of `main` holds the service).
        let top = abi::INIT_STACK_TOP as usize;
        let high = (sp & !15) - 2048;
        let bottom = top - PAINTED;
        let mut at = bottom;
        while at < high {
            // SAFETY: the words are of this thread's stack below its frame, free
            // of any use now, and inside the stack (PAINTED is less than its size).
            unsafe { AtomicU64::from_ptr(at as *mut u64) }.store(PATTERN, Relaxed);
            at += 8;
        }
        TOP.store(top, Relaxed);
        BOTTOM.store(bottom, Relaxed);
        LOW.store(high, Relaxed);
        CURSOR.store(bottom, Relaxed);
    }

    /// Looks at a few more words for the lowest that was written.
    pub fn watch() {
        let top = TOP.load(Relaxed);
        if top == 0 {
            return;
        }
        let low = LOW.load(Relaxed);
        let mut at = CURSOR.load(Relaxed);
        let end = (at + WORDS_A_STEP * 8).min(low);
        while at < end {
            // SAFETY: a word of the painted stack.
            if unsafe { AtomicU64::from_ptr(at as *mut u64) }.load(Relaxed) != PATTERN {
                LOW.store(at, Relaxed);
                rt::println!(
                    "service stack: 17 depth {} painted {}",
                    top - at,
                    top - BOTTOM.load(Relaxed)
                );
                CURSOR.store(BOTTOM.load(Relaxed), Relaxed);
                return;
            }
            at += 8;
        }
        CURSOR.store(
            if end >= low {
                BOTTOM.load(Relaxed)
            } else {
                end
            },
            Relaxed,
        );
    }
}

impl Pixman {
    /// Makes pixman build its tables of implementations now, in the
    /// start of the service and not in the step of its first band: one
    /// point laid over one point.
    pub fn warm() -> Pixman {
        let mut dst = Point([0; 4]);
        let src = Point([0; 4]);
        let mut target = Target {
            bytes: &mut dst.0,
            format: Px::Xrgb8888,
            stride: 4,
            width: 1,
            height: 1,
        };
        let from = Source {
            bytes: &src.0,
            format: Px::Argb8888,
            stride: 4,
            width: 1,
            height: 1,
            hint: pixman::NO_HINT,
        };
        let mut images = Images::new();
        composite(&mut images, true, &mut target, from, (0, 0), (0, 0), (1, 1));
        composite(
            &mut images,
            false,
            &mut target,
            from,
            (0, 0),
            (0, 0),
            (1, 1),
        );
        // The two images of the warm-up wrapped memory of this frame.
        drop(images);
        Pixman {
            images: Images::new(),
            refused: 0,
        }
    }

    /// The image of a window's buffer is made now (a post), so that no band
    /// pays for the first use of a surface.
    pub fn prepare(&mut self, src: &[u8], stride: u32, f: Format, size: (u32, u32), image: usize) {
        let source = Source {
            bytes: src,
            format: format(f),
            stride,
            width: size.0,
            height: size.1,
            hint: image,
        };
        if !prepare(&mut self.images, source) {
            self.refuse("a surface");
        }
    }

    /// The images made so far.
    pub fn made(&self) -> u32 {
        self.images.made()
    }

    /// The entries of the table of images looked at so far (feature `irq-trace`).
    #[cfg(feature = "irq-trace")]
    pub fn scanned(&self) -> u32 {
        self.images.scanned()
    }

    /// One operation was refused: counted, and said the first time and at
    /// every 256th.
    fn refuse(&mut self, what: &str) {
        self.refused = self.refused.wrapping_add(1);
        if self.refused % 256 == 1 {
            rt::println!(
                "compositor: pixman refused {what} ({} so far)",
                self.refused
            );
        }
    }
}

impl Raster for Pixman {
    fn fill(&mut self, fb: &mut [u8], r: Rect, rgb: u32) {
        let mut target = Target {
            bytes: fb,
            format: Px::Xrgb8888,
            stride: STRIDE,
            width: WIDTH,
            height: HEIGHT,
        };
        #[cfg(feature = "steps")]
        let began = rt::time::now();
        if !fill(&mut target, r.x, r.y, r.w, r.h, rgb) {
            self.refuse("a fill");
        }
        #[cfg(feature = "steps")]
        cost::record(
            cost::BLACK,
            u64::from(r.w),
            u64::from(r.h),
            rt::time::now() - began,
        );
    }

    fn blit(
        &mut self,
        fb: &mut [u8],
        src: &[u8],
        stride: u32,
        f: Format,
        size: (u32, u32),
        from: (u32, u32),
        to: (u32, u32),
        area: (u32, u32),
        over: bool,
        image: usize,
    ) {
        let mut target = Target {
            bytes: fb,
            format: Px::Xrgb8888,
            stride: STRIDE,
            width: WIDTH,
            height: HEIGHT,
        };
        let source = Source {
            bytes: src,
            format: format(f),
            stride,
            width: size.0,
            height: size.1,
            hint: image,
        };
        #[cfg(feature = "steps")]
        let began = rt::time::now();
        if !composite(&mut self.images, over, &mut target, source, from, to, area) {
            self.refuse("a layer");
        }
        #[cfg(feature = "steps")]
        cost::record(
            if over { cost::OVER } else { cost::COPY },
            u64::from(area.0),
            u64::from(area.1),
            rt::time::now() - began,
        );
    }

    fn element(&mut self, fb: &mut [u8], d: &Draw<'_>) {
        let mut target = Target {
            bytes: fb,
            format: Px::Xrgb8888,
            stride: STRIDE,
            width: WIDTH,
            height: HEIGHT,
        };
        #[cfg(feature = "steps")]
        let began = rt::time::now();
        if !draw(&mut self.images, &mut target, d) {
            self.refuse("an element");
        }
        #[cfg(feature = "steps")]
        cost::record(
            if d.transparency == 0 {
                cost::COPY
            } else {
                cost::OVER
            },
            u64::from(d.area.w),
            u64::from(d.area.h),
            rt::time::now() - began,
        );
    }
}

/// The A8 mask window's surface as pixman's source.
fn plane(m: compositor::Surface<'_>) -> Source<'_> {
    Source {
        bytes: m.bytes,
        format: Px::A8,
        stride: m.stride,
        width: m.size.0,
        height: m.size.1,
        hint: m.image,
    }
}

/// One element's drawing onto `target`: pixman's composite of its source
/// through its transform, with the alpha or the mask its transparency says. A
/// source with no transparency bit of its own alpha is read as XRGB8888 (its
/// alpha byte is not read, as the element's meaning has it).
fn draw(images: &mut Images, target: &mut Target<'_>, d: &Draw<'_>) -> bool {
    use proto_comp::{TRANSPARENCY_ALPHA, TRANSPARENCY_MASK, TRANSPARENCY_SOURCE};
    let t = d.transparency;
    let kind = match (d.src.format, t & TRANSPARENCY_SOURCE != 0) {
        (Format::Argb, false) => Px::Xrgb8888,
        (f, _) => format(f),
    };
    let source = Source {
        bytes: d.src.bytes,
        format: kind,
        stride: d.src.stride,
        width: d.src.size.0,
        height: d.src.size.1,
        hint: d.src.image,
    };
    let mask = match (
        d.mask,
        t & TRANSPARENCY_MASK != 0,
        t & TRANSPARENCY_ALPHA != 0,
    ) {
        (Some((m, at)), true, false) => Mask::Plane {
            source: plane(m),
            at,
        },
        (Some((m, at)), true, true) => Mask::Product {
            source: plane(m),
            at,
            alpha: d.alpha,
        },
        (_, false, true) => Mask::Alpha(d.alpha),
        (_, false, false) => Mask::None,
        // The mask bit with no mask: the band does not ask for it.
        (None, true, _) => return false,
    };
    composite_element(
        images,
        t != 0,
        target,
        source,
        d.matrix,
        d.from,
        if d.filter == proto_comp::BILINEAR {
            Filter::Bilinear
        } else {
            Filter::Nearest
        },
        mask,
        (d.area.x, d.area.y),
        (d.area.w, d.area.h),
    )
}

/// The prices of the three kinds measured on shapes of operations chosen for
/// each class, under -icount (feature `steps`), before the service takes its
/// first request: the probes' scenes make the operations of the bands, whose
/// shapes the prices themselves decide, and the classes of a narrow tall
/// operation, a tiny one and a large one of a translucent layer do not come
/// out of them. Each shape is drawn at four offsets of the target and of the
/// source (the edges before the aligned points), several times, and an
/// operation during which a thread of a higher level took the CPU off the
/// service (the count of preemptions of the thread changed) is left out and
/// counted: what is told is the thread's own work.
#[cfg(feature = "calibrate")]
pub mod calibration {
    use super::{Filter, Mask, Pixman, Px, Source, Target, composite, composite_element, fill};

    /// The scratch surfaces are two regions of the screen's own buffer (the target
    /// the service keeps, 256 pages, mapped when the screen opens): 648 by 13 points
    /// for the shapes of the width of the screen (640 and the offset of up to 3
    /// points), and the first 160 by 32 points of the same regions (a stride of 640
    /// bytes) for the others. The regions are filled before the calibration (the
    /// source with 0x40 in every byte, which is a point of alpha 0x40) and made zero
    /// after it, which is what the target holds before the first frame; the program
    /// holds no memory for them, so the steps build needs no more quota than the
    /// plain one.
    const WIDE: u32 = 648;
    const WIDE_HEIGHT: u32 = 13;
    const WIDE_STRIDE: u32 = WIDE * 4;
    const BYTES: usize = (WIDE_STRIDE * WIDE_HEIGHT) as usize;
    /// Where the two regions begin in the buffer: pages of their own.
    const DST_AT: usize = 0;
    const SRC_AT: usize = BYTES.div_ceil(4096) * 4096;
    const NARROW: u32 = 160;
    const NARROW_HEIGHT: u32 = 32;
    const NARROW_STRIDE: u32 = NARROW * 4;
    const NARROW_BYTES: usize = (NARROW_STRIDE * NARROW_HEIGHT) as usize;
    const _: () = assert!(NARROW_BYTES <= BYTES);

    /// What one class tells: the least and the greatest of its figure, the
    /// shapes of each, and how many operations counted.
    #[derive(Clone, Copy)]
    struct Spread {
        least: u64,
        least_at: (u32, u32),
        greatest: u64,
        greatest_at: (u32, u32),
        n: u64,
    }

    impl Spread {
        const fn new() -> Spread {
            Spread {
                least: u64::MAX,
                least_at: (0, 0),
                greatest: 0,
                greatest_at: (0, 0),
                n: 0,
            }
        }

        fn add(&mut self, v: u64, at: (u32, u32)) {
            if v < self.least {
                self.least = v;
                self.least_at = at;
            }
            if v >= self.greatest {
                self.greatest = v;
                self.greatest_at = at;
            }
            self.n += 1;
        }

        fn zero(&self) -> u64 {
            if self.n == 0 { 0 } else { self.least }
        }
    }

    /// The shapes, width by height, with the class each tells: 0 the call, 1 the
    /// row, 2 the point, 3 only the fit (wider than 8 points, in one row). The
    /// pairs of one width and two heights give the cost of a row at that width.
    const SHAPES: [(u32, u32, u8); 26] = [
        (1, 1, 0),
        (2, 1, 0),
        (4, 1, 0),
        (8, 1, 0),
        (16, 1, 3),
        (32, 1, 3),
        (64, 1, 3),
        (8, 8, 1),
        (8, 16, 1),
        (16, 8, 1),
        (16, 16, 1),
        (4, 16, 1),
        (4, 32, 1),
        (12, 8, 1),
        (12, 24, 1),
        (152, 8, 2),
        (152, 16, 2),
        (76, 16, 2),
        (76, 32, 2),
        (64, 16, 2),
        (64, 32, 2),
        (150, 8, 2),
        (150, 16, 2),
        (640, 1, 3),
        (640, 8, 2),
        (640, 13, 2),
    ];
    /// The timed operations after the warm-up of a plain kind: one, the run under
    /// -icount being deterministic (the calibration is bounded by the display
    /// driver's watchdog, which the service's start must keep under).
    const REPEAT: u32 = 1;
    /// How many times an operation that a higher level preempted is tried again.
    const PREEMPT_RETRIES: u32 = 4;

    /// What a kind of the elements' operations draws: nearest or bilinear, the
    /// source turned a quarter, reflected and stretched (the general path of
    /// pixman, the dearest of the geometries) or placed as it is, a laying
    /// over or a copy, and the mixing.
    #[derive(Clone, Copy)]
    pub(super) struct Recipe {
        name: &'static str,
        bilinear: bool,
        transform: Transform,
        over: bool,
        mix: Mix,
        source: Src,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Transform {
        /// As it is.
        Plain,
        /// Turned, reflected and stretched by a ratio that is no fraction of 16.16.
        General,
        /// A quarter turn with no stretch: pixman's own path for it.
        Quarter,
        /// Stretched by a fraction, no turn and no reflection: the class of the
        /// fast paths (`compositor::elements::Class::FastNearestCopy` and the
        /// rest).
        Scale,
    }

    /// The source's format: both in turn (the kinds that were measured so), or the
    /// one named.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Src {
        Both,
        Argb,
        Opaque,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mix {
        None,
        Alpha,
        Mask,
        Both,
    }

    /// The kinds the elements' operations add to the three of the plain ones
    /// (`compositor::PRICES` after the black, the copy and the laying over):
    /// each is measured on the shapes of the plain ones narrower than 160
    /// points (a dear band is a part of a line), at two offsets of the target.
    pub(super) const RECIPES: [Recipe; 21] = [
        Recipe {
            name: "scale-nearest-copy",
            bilinear: false,
            transform: Transform::General,
            over: false,
            mix: Mix::None,
            source: Src::Both,
        },
        Recipe {
            name: "scale-nearest-over",
            bilinear: false,
            transform: Transform::General,
            over: true,
            mix: Mix::None,
            source: Src::Both,
        },
        Recipe {
            name: "scale-bilinear-copy",
            bilinear: true,
            transform: Transform::General,
            over: false,
            mix: Mix::None,
            source: Src::Both,
        },
        Recipe {
            name: "scale-bilinear-over",
            bilinear: true,
            transform: Transform::General,
            over: true,
            mix: Mix::None,
            source: Src::Both,
        },
        Recipe {
            name: "rotate90",
            bilinear: false,
            transform: Transform::Quarter,
            over: false,
            mix: Mix::None,
            source: Src::Both,
        },
        Recipe {
            name: "alpha",
            bilinear: false,
            transform: Transform::Plain,
            over: true,
            mix: Mix::Alpha,
            source: Src::Both,
        },
        Recipe {
            name: "mask",
            bilinear: false,
            transform: Transform::Plain,
            over: true,
            mix: Mix::Mask,
            source: Src::Both,
        },
        Recipe {
            name: "mask-alpha",
            bilinear: false,
            transform: Transform::Plain,
            over: true,
            mix: Mix::Both,
            source: Src::Both,
        },
        Recipe {
            name: "fast-nearest-copy",
            bilinear: false,
            transform: Transform::Scale,
            over: false,
            mix: Mix::None,
            source: Src::Opaque,
        },
        Recipe {
            name: "fast-nearest-over",
            bilinear: false,
            transform: Transform::Scale,
            over: true,
            mix: Mix::None,
            source: Src::Argb,
        },
        Recipe {
            name: "fast-bilinear-copy",
            bilinear: true,
            transform: Transform::Scale,
            over: false,
            mix: Mix::None,
            source: Src::Opaque,
        },
        Recipe {
            name: "fast-bilinear-over",
            bilinear: true,
            transform: Transform::Scale,
            over: true,
            mix: Mix::None,
            source: Src::Argb,
        },
        Recipe {
            name: "fast-nearest-alpha",
            bilinear: false,
            transform: Transform::Scale,
            over: true,
            mix: Mix::Alpha,
            source: Src::Argb,
        },
        Recipe {
            name: "fast-bilinear-alpha",
            bilinear: true,
            transform: Transform::Scale,
            over: true,
            mix: Mix::Alpha,
            source: Src::Argb,
        },
        Recipe {
            name: "fast-nearest-mask",
            bilinear: false,
            transform: Transform::Scale,
            over: true,
            mix: Mix::Mask,
            source: Src::Argb,
        },
        Recipe {
            name: "fast-bilinear-mask",
            bilinear: true,
            transform: Transform::Scale,
            over: true,
            mix: Mix::Mask,
            source: Src::Argb,
        },
        Recipe {
            name: "fast-bilinear-mask-alpha",
            bilinear: true,
            transform: Transform::Scale,
            over: true,
            mix: Mix::Both,
            source: Src::Argb,
        },
        Recipe {
            name: "fast-nearest-alpha-opaque",
            bilinear: false,
            transform: Transform::Scale,
            over: true,
            mix: Mix::Alpha,
            source: Src::Opaque,
        },
        Recipe {
            name: "fast-bilinear-alpha-opaque",
            bilinear: true,
            transform: Transform::Scale,
            over: true,
            mix: Mix::Alpha,
            source: Src::Opaque,
        },
        Recipe {
            name: "fast-nearest-mask-opaque",
            bilinear: false,
            transform: Transform::Scale,
            over: true,
            mix: Mix::Mask,
            source: Src::Opaque,
        },
        Recipe {
            name: "fast-bilinear-mask-opaque",
            bilinear: true,
            transform: Transform::Scale,
            over: true,
            mix: Mix::Mask,
            source: Src::Opaque,
        },
    ];

    /// One operation of a kind: its ticks, or None when a higher level
    /// preempted the thread in the middle of it.
    fn timed(thread: &rt::handle::Handle<rt::handle::Thread>, run: impl FnOnce()) -> Option<u64> {
        let before = rt::sys::thread_ran_preempts(thread).ok()?;
        let began = rt::time::now();
        run();
        let ended = rt::time::now();
        let after = rt::sys::thread_ran_preempts(thread).ok()?;
        (after.1 == before.1).then(|| ended - began)
    }

    /// The elements' region of the screen's buffer: a source of 160 by 160
    /// points (stride 640 bytes), the mask (160 by 32, A8) after it, both past the
    /// regions of the plain kinds and the layers (`LAYERS_AT`).
    const ELEMENTS_AT: usize = 262_144;
    const ELEMENT_SRC_SIDE: u32 = 160;
    const ELEMENT_SRC_BYTES: usize = (ELEMENT_SRC_SIDE * ELEMENT_SRC_SIDE * 4) as usize;
    const ELEMENT_MASK_AT: usize = ELEMENTS_AT + ELEMENT_SRC_BYTES;
    const ELEMENT_MASK_BYTES: usize = (NARROW * NARROW_HEIGHT) as usize;

    /// The operation of a kind: pixman's call for plain ones (0 black, 1 copy,
    /// 2 over) and for a recipe of the elements' the transform, filter, mask and
    /// formats it names; `dx` is the offset of the target, `turn` of the
    /// source's format for the kinds that alternate it.
    #[allow(clippy::too_many_arguments)]
    fn operate(
        images: &mut pixman::Images,
        which: usize,
        recipe: Option<&Recipe>,
        fb: &mut [u8],
        shape: (u32, u32),
        offsets: (u32, u32, bool),
    ) {
        let (w, h) = shape;
        let (dx, sx, inside) = offsets;
        if let Some(r) = recipe {
            let (head, tail) = fb.split_at_mut(ELEMENTS_AT);
            let (src, mask) = tail.split_at_mut(ELEMENT_SRC_BYTES);
            let mut target = Target {
                bytes: &mut head[DST_AT..DST_AT + NARROW_BYTES],
                format: Px::Xrgb8888,
                stride: NARROW_STRIDE,
                width: NARROW,
                height: NARROW_HEIGHT,
            };
            // The formats alternate with the offset for the kinds that mix and name
            // no format: the source with its alpha at 0, without at 1 (both are
            // drawn).
            let argb = match r.source {
                Src::Argb => true,
                Src::Opaque => false,
                Src::Both => r.over && (r.mix == Mix::None || sx == 0),
            };
            // A scale at the edge of its source is a stretch of the whole of a
            // source (at least 2 by 2: one point is a solid colour to pixman) that is the half of the target (its samples reach past the
            // edge, so pixman pads them and does not cover the clip, the other
            // flags and the other path); inside is a part of the large source, which
            // covers the clip. The other kinds are inside or at the edge of the
            // large source.
            let edge = r.transform == Transform::Scale && !inside;
            let (src_w, src_h) = if edge {
                ((w / 2).max(2), (h / 2).max(2))
            } else {
                (ELEMENT_SRC_SIDE, ELEMENT_SRC_SIDE)
            };
            let from = Source {
                bytes: src,
                format: if argb { Px::Argb8888 } else { Px::Xrgb8888 },
                stride: ELEMENT_SRC_SIDE * 4,
                width: src_w,
                height: src_h,
                hint: 1,
            };
            let plane = Source {
                bytes: &mask[..ELEMENT_MASK_BYTES],
                format: Px::A8,
                stride: NARROW,
                width: NARROW,
                height: NARROW_HEIGHT,
                hint: 2,
            };
            let element = proto_comp::Element {
                source: 0,
                mask: 0,
                // Inside the source (the samples of the target are far from its
                // edges) or at its edge: pixman's flags, and with them the key of
                // its path, differ.
                sx: if inside { 40 << 16 } else { 0 },
                sy: if inside { 40 << 16 } else { 0 },
                sw: if r.transform == Transform::Quarter {
                    (h as i32) << 16
                } else if edge {
                    (src_w as i32) << 16
                } else if inside {
                    80 << 16
                } else {
                    (ELEMENT_SRC_SIDE as i32) << 16
                },
                sh: if r.transform == Transform::Quarter {
                    (w as i32) << 16
                } else if edge {
                    (src_h as i32) << 16
                } else if inside {
                    80 << 16
                } else {
                    (ELEMENT_SRC_SIDE as i32) << 16
                },
                dx: dx as i32,
                dy: 0,
                dw: w as i32,
                dh: h as i32,
                orient: match r.transform {
                    Transform::General => 1 | proto_comp::MIRROR,
                    Transform::Scale => 0,
                    _ => 1,
                },
                filter: u32::from(r.bilinear),
                transparency: 0,
                alpha: 100,
            };
            let matrix =
                (r.transform != Transform::Plain).then(|| compositor::elements::matrix(&element));
            let mask = match r.mix {
                Mix::None => Mask::None,
                Mix::Alpha => Mask::Alpha(100),
                Mix::Mask => Mask::Plane {
                    source: plane,
                    at: (0, 0),
                },
                Mix::Both => Mask::Product {
                    source: plane,
                    at: (0, 0),
                    alpha: 100,
                },
            };
            composite_element(
                images,
                r.over,
                &mut target,
                from,
                matrix,
                (0, 0),
                if r.bilinear {
                    Filter::Bilinear
                } else {
                    Filter::Nearest
                },
                mask,
                (dx, 0),
                (w, h),
            );
            return;
        }
        let (dst_region, rest) = fb.split_at_mut(SRC_AT);
        let (dst, src) = (&mut dst_region[DST_AT..DST_AT + BYTES], &rest[..BYTES]);
        // The width of the screen on the wide surface, the others on the narrow
        // one (the same memory).
        let (dst, src, stride, width, height) = if w > 160 {
            (dst, src, WIDE_STRIDE, WIDE, WIDE_HEIGHT)
        } else {
            (
                &mut dst[..NARROW_BYTES],
                &src[..NARROW_BYTES],
                NARROW_STRIDE,
                NARROW,
                NARROW_HEIGHT,
            )
        };
        let mut target = Target {
            bytes: dst,
            format: Px::Xrgb8888,
            stride,
            width,
            height,
        };
        let from = Source {
            bytes: src,
            format: if which == 2 {
                Px::Argb8888
            } else {
                Px::Xrgb8888
            },
            stride,
            width,
            height,
            hint: pixman::NO_HINT,
        };
        if which == 0 {
            fill(&mut target, dx, 0, w, h, 0);
        } else {
            composite(
                images,
                which == 2,
                &mut target,
                from,
                (sx, 0),
                (dx, 0),
                (w, h),
            );
        }
    }

    /// Makes the operations of every shape of one kind (0 black, 1 copy, 2
    /// over, or a recipe of the elements') and tells a line for each shape and
    /// one for the classes.
    fn kind(
        px: &mut Pixman,
        fb: &mut [u8],
        which: usize,
        recipe: Option<&Recipe>,
        name: &str,
        thread: &rt::handle::Handle<rt::handle::Thread>,
    ) {
        let (mut call, mut row, mut point) = (Spread::new(), Spread::new(), Spread::new());
        let mut preempted = 0u32;
        let (mut call_g, mut row_g) = (0u64, 0u64);
        // The offsets of the target and of the source, as many as the kind is
        // measured at (the recipes at two offsets of the target and one of the
        // source: their operations are dear).
        // The offset of the target alone matters for a kind that has a path
        // of NEON of its own (the turn of a quarter and the kinds that mix);
        // the kinds that mix are drawn from both formats of the source (the
        // second number). The rest is the general path of pixman, which does
        // not mind the alignment.
        // The kinds of the fast class are measured once after the warm-up (the run is
        // deterministic), from the source they name, at two offsets of the target
        // when their path is NEON (the source has an alpha, or no mix) and at one
        // when it is pixman's general path (an opaque source that mixes).
        let (dxs, sxs, repeat) = match recipe {
            None => (4, 4, REPEAT),
            Some(r) if r.transform == Transform::Scale => (
                if r.mix != Mix::None && r.source == Src::Opaque {
                    1
                } else {
                    2
                },
                2,
                1,
            ),
            Some(r) => (
                if r.transform == Transform::General {
                    1
                } else {
                    2
                },
                if r.mix == Mix::None { 1 } else { 2 },
                1,
            ),
        };
        // The calls first, then the rows, then the points: each class takes off
        // the greatest of those before it.
        for order in [0u8, 1, 2] {
            for &(w, h, class) in &SHAPES {
                let tells = if class == 3 { 0 } else { class };
                if tells != order {
                    continue;
                }
                // A dear kind is a part of a line: no shape wider than 160, and
                // the product of a mask and an alpha is made in a band of 16 lines.
                // The taller of the wide shapes are left out too: they cost much for
                // what the two heights at the widths of the points already tell.
                if recipe.is_some_and(|r| {
                    w > 160
                        || (r.mix == Mix::Both && h > 16)
                        || (class == 2 && (h >= 32 || (w >= 150 && h >= 16)))
                }) {
                    continue;
                }
                let (mut least, mut greatest, mut n) = (u64::MAX, 0u64, 0u64);
                for dx in 0..dxs {
                    for sx in 0..sxs {
                        // One warm-up, which makes the images pixman keeps. A scale is
                        // made inside its source (the first of the two) and at its edge.
                        let inside =
                            recipe.is_some_and(|r| r.transform == Transform::Scale && sx == 0);
                        for turn in 0..=repeat {
                            let images = &mut px.images;
                            // An operation a higher level preempted is made again.
                            let mut ticks = None;
                            for _ in 0..PREEMPT_RETRIES {
                                ticks = timed(thread, || {
                                    operate(images, which, recipe, fb, (w, h), (dx, sx, inside));
                                });
                                if ticks.is_some() || turn == 0 {
                                    break;
                                }
                                preempted += 1;
                            }
                            if turn == 0 {
                                continue;
                            }
                            let Some(ticks) = ticks else {
                                continue;
                            };
                            least = least.min(ticks);
                            greatest = greatest.max(ticks);
                            n += 1;
                            let points = u64::from(w) * u64::from(h);
                            match class {
                                0 => {
                                    call.add(ticks, (w, h));
                                    call_g = call_g.max(ticks);
                                }
                                1 => {
                                    let net = ticks.saturating_sub(call_g);
                                    let v = net * 100 / u64::from(h);
                                    row.add(v, (w, h));
                                    row_g = row_g.max(v);
                                }
                                2 => {
                                    let rows = row_g * u64::from(h) / 100;
                                    let net = ticks.saturating_sub(call_g + rows);
                                    point.add(net * 100 / points, (w, h));
                                }
                                _ => {}
                            }
                        }
                    }
                }
                if n > 0 {
                    rt::println!(
                        "service shape: 17 {name} {w} {h} least {least} greatest {greatest} n {n}"
                    );
                }
            }
        }
        rt::println!(
            "service calibration: 17 {name} call {} {} {} {} {} row {} {} {} {} {} point {} {} {} {} {} preempted {preempted}",
            call.zero(),
            call.greatest,
            call.n,
            call.greatest_at.0,
            call.greatest_at.1,
            row.zero(),
            row.greatest,
            row.n,
            row.greatest_at.0,
            row.greatest_at.1,
            point.zero(),
            point.greatest,
            point.n,
            point.greatest_at.0,
            point.greatest_at.1,
        );
    }

    /// The shapes of the bands of layers, width by height, and the counts of layers
    /// (9 is eight windows and the pointer's picture, the most the service lays).
    /// The widths are the ones a band of layers gets (a part of a line of about 45
    /// points for eight, more lines for fewer) and a few others.
    const LAYER_SHAPES: [(u32, u32); 7] = [
        (16, 1),
        (45, 1),
        (64, 1),
        (150, 1),
        (150, 4),
        (76, 8),
        (8, 8),
    ];
    const LAYER_COUNTS: [usize; 5] = [1, 2, 4, 8, 9];
    /// The windows of the bands are the size of the overload's: 320 by 200 points,
    /// a stride of 1 280 bytes, painted with points of every alpha, each from a
    /// source of its own: the sources lie at the offsets of a page in one region
    /// of the screen's buffer (a window's buffer is 256 000 bytes), so that each
    /// has an address of its own and its own image in pixman's table.
    const LAYER_WINDOW_W: u32 = 320;
    const LAYER_WINDOW_H: u32 = 200;
    const LAYER_WINDOW_BYTES: usize = (LAYER_WINDOW_W * LAYER_WINDOW_H * 4) as usize;
    const LAYER_SRC_STEP: usize = 4096;
    const LAYERS_AT: usize = 131_072;
    /// The target of the bands: 328 points by 12 lines (the band's rows lie in it
    /// from the line `y0` of the screen), in the first pages of the buffer.
    const LAYER_TARGET_W: u32 = 328;
    const LAYER_TARGET_H: u32 = 12;
    const LAYER_TARGET_BYTES: usize = (LAYER_TARGET_W * LAYER_TARGET_H * 4) as usize;
    /// The line of the window at which the bands are made (a source offset of
    /// its own), and the timed repeats of a band after the warm-up. The run
    /// before the first request is bounded: the watchdog of init kills a service
    /// silent for about 1.3 s, and the three kinds take the first half of that.
    const LAYER_ROW: u32 = 96;
    const LAYER_REPEAT: u32 = 1;
    const _: () = assert!(LAYER_TARGET_BYTES <= BYTES);

    /// The pixel operations of a band of the calibration: pixman's, on a
    /// small target of its own that holds the lines from `y0`, and no cost lines of
    /// the probes.
    struct Plain<'a> {
        images: &'a mut pixman::Images,
        target: &'a mut [u8],
        y0: u32,
    }

    impl compositor::Raster for Plain<'_> {
        fn fill(&mut self, _fb: &mut [u8], r: proto_comp::Rect, rgb: u32) {
            let mut target = Target {
                bytes: self.target,
                format: Px::Xrgb8888,
                stride: LAYER_TARGET_W * 4,
                width: LAYER_TARGET_W,
                height: LAYER_TARGET_H,
            };
            fill(&mut target, r.x, r.y - self.y0, r.w, r.h, rgb);
        }

        fn blit(
            &mut self,
            _fb: &mut [u8],
            src: &[u8],
            stride: u32,
            f: compositor::Format,
            size: (u32, u32),
            from: (u32, u32),
            to: (u32, u32),
            area: (u32, u32),
            over: bool,
            image: usize,
        ) {
            let mut target = Target {
                bytes: self.target,
                format: Px::Xrgb8888,
                stride: LAYER_TARGET_W * 4,
                width: LAYER_TARGET_W,
                height: LAYER_TARGET_H,
            };
            let source = Source {
                bytes: src,
                format: super::format(f),
                stride,
                width: size.0,
                height: size.1,
                hint: image,
            };
            composite(
                self.images,
                over,
                &mut target,
                source,
                from,
                (to.0, to.1 - self.y0),
                area,
            );
        }

        fn element(&mut self, _fb: &mut [u8], d: &compositor::Draw<'_>) {
            // The bands of the layers' calibration are plain windows: the
            // element drawing is the one of the service, on the small target.
            let mut target = Target {
                bytes: self.target,
                format: Px::Xrgb8888,
                stride: LAYER_TARGET_W * 4,
                width: LAYER_TARGET_W,
                height: LAYER_TARGET_H,
            };
            let mut shifted = *d;
            shifted.area.y -= self.y0;
            super::draw(self.images, &mut target, &shifted);
        }
    }

    /// The sources of the windows of a band of layers: a window each, from the
    /// region, at the offsets of a page.
    struct Regions<'a>(&'a [u8]);

    impl compositor::Source for Regions<'_> {
        fn pixels(&self, window: usize, _buffer: u8) -> &[u8] {
            let at = window * LAYER_SRC_STEP;
            &self.0[at..at + LAYER_WINDOW_BYTES]
        }
    }

    /// Paints the region with points of every alpha, premultiplied (no colour
    /// above its alpha): the content of a window that is drawn, where a fill of
    /// one value is the best case of a branch.
    fn paint(region: &mut [u8]) {
        let (points, _) = region.as_chunks_mut::<4>();
        for (i, point) in points.iter_mut().enumerate() {
            let h = (i as u32).wrapping_mul(2_654_435_761);
            let a = (h >> 24) as u8;
            let c = |shift: u32| (((h >> shift) & 0xFF) as u8).min(a);
            *point = [c(0), c(8), c(16), a];
        }
    }

    impl Pixman {
        /// Measures whole bands of 1, 2, 4, 8 and 9 layers laid over each other on the
        /// same rows (`compositor::compose_sized` over a scene of windows of
        /// ARGB8888, each from a source of its own), on the shapes of
        /// `LAYER_SHAPES` and the offsets of the target and of the sources, and tells
        /// a line `service shape: 17 layersN W H least L greatest G n K` for each:
        /// the ticks of the band as `compose` makes it, with the black it starts
        /// with. What it costs beyond the prices of its operations is the term of a
        /// layer (`compositor::LAYER`).
        pub fn calibrate_layers(&mut self, fb: &mut [u8]) {
            let need = LAYERS_AT + LAYER_WINDOW_BYTES + 8 * LAYER_SRC_STEP;
            if fb.len() < need {
                rt::println!("service calibration: the screen's buffer is too small for layers");
                return;
            }
            let Ok(thread) = rt::sys::self_thread() else {
                return;
            };
            let (head, tail) = fb.split_at_mut(LAYERS_AT);
            let target = &mut head[..LAYER_TARGET_BYTES];
            let len = LAYER_WINDOW_BYTES + 8 * LAYER_SRC_STEP;
            paint(&mut tail[..len]);
            let region: &[u8] = &tail[..len];
            for &count in &LAYER_COUNTS {
                for &(w, h) in &LAYER_SHAPES {
                    // The tall shapes of many layers are left out (a band of
                    // many layers is a part of a line), the ninth layer is
                    // told on the one line shapes of 64 points or more.
                    if (count >= 4 && h >= 8) || (count == 9 && (h != 1 || w < 64)) {
                        continue;
                    }
                    let (mut least, mut greatest, mut n) = (u64::MAX, 0u64, 0u64);
                    for dy in [LAYER_ROW] {
                        for dx in 4..8u32 {
                            for sx in 0..4u32 {
                                // The windows lie `sx` points to the left of the
                                // band's first column; all of them on one place.
                                let mut scene = compositor::Scene::new();
                                for i in 0..count.min(8) {
                                    let r = proto_comp::Rect {
                                        x: dx - sx,
                                        y: 0,
                                        w: LAYER_WINDOW_W,
                                        h: LAYER_WINDOW_H,
                                    };
                                    let Ok(k) =
                                        scene.create(i as u64 + 1, 1 + (i / 4) as u64, r, false, 0)
                                    else {
                                        return;
                                    };
                                    scene.set_format(k, compositor::Format::Argb);
                                    if scene.attach(k, 2, LAYER_WINDOW_W * 4).is_err()
                                        || scene.post(k, 0, &[]).is_err()
                                    {
                                        return;
                                    }
                                }
                                if count == 9 {
                                    // The ninth layer: the pointer's picture, over the band.
                                    scene.pointer_to((dx + 1) as i32, dy as i32);
                                }
                                let _ = scene.begin();
                                scene.end(true);
                                let damage = proto_comp::Rect { x: dx, y: dy, w, h };
                                for turn in 0..=LAYER_REPEAT {
                                    let mut plain = Plain {
                                        images: &mut self.images,
                                        target: &mut *target,
                                        y0: dy,
                                    };
                                    let regions = Regions(region);
                                    // The band as the service makes it: `tile` (its
                                    // cost is the band's) and the band of the shape named.
                                    let ticks = timed(&thread, || {
                                        let _ = scene.tile(damage);
                                        compositor::compose_sized(
                                            &scene,
                                            damage,
                                            compositor::Band {
                                                row: dy,
                                                col: 0,
                                                pass: 0,
                                            },
                                            (w, h),
                                            &mut [],
                                            &regions,
                                            &mut plain,
                                        );
                                    });
                                    // The first turn makes the images.
                                    if turn == 0 {
                                        continue;
                                    }
                                    if let Some(ticks) = ticks {
                                        least = least.min(ticks);
                                        greatest = greatest.max(ticks);
                                        n += 1;
                                    }
                                }
                            }
                        }
                    }
                    if n > 0 {
                        rt::println!(
                            "service shape: 17 layers{count} {w} {h} least {least} greatest {greatest} n {n}"
                        );
                    }
                }
            }
            // The target of the service holds zero before its first frame.
            target.fill(0);
            tail[..len].fill(0);
        }
    }

    impl Pixman {
        /// Measures what a call pays when pixman's cache of resolved paths has
        /// lost its key: for each kind of the elements' operations, at both
        /// variants of the flags (inside the source and at its edge), the call of
        /// one point as it is after eight calls of other keys, less the same call
        /// when it repeats (`compositor::LOOKUP_MISS_MEASURED` is the greatest).
        /// Tells a line `service lookup: 17 KIND inside I least L greatest G` for
        /// each and `service lookup: 17 greatest G`.
        pub fn calibrate_lookup(&mut self, fb: &mut [u8]) {
            /// The runs of a kind: one, the run under -icount being deterministic.
            const LOOKUP_TURNS: u32 = 1;
            let Ok(thread) = rt::sys::self_thread() else {
                return;
            };
            fb[ELEMENTS_AT..ELEMENTS_AT + ELEMENT_SRC_BYTES].fill(0x40);
            fb[ELEMENT_MASK_AT..ELEMENT_MASK_AT + ELEMENT_MASK_BYTES].fill(0x80);
            let mut greatest = 0u64;
            for (k, r) in RECIPES.iter().enumerate() {
                for inside in [false, true] {
                    let shape = if r.transform == Transform::Scale {
                        (4, 4)
                    } else {
                        (1, 1)
                    };
                    let (mut least, mut worst) = (u64::MAX, 0u64);
                    for turn in 0..LOOKUP_TURNS {
                        let images = &mut self.images;
                        // Warm: the call again and again.
                        operate(images, 3, Some(r), fb, shape, (0, 0, inside));
                        let Some(warm) = timed(&thread, || {
                            operate(images, 3, Some(r), fb, shape, (0, 0, inside));
                        }) else {
                            continue;
                        };
                        // Evicted: nine calls of other keys (the kinds that follow it),
                        // then the plain copy and laying over, then the call.
                        for i in 1..=9 {
                            let other = &RECIPES[(k + i) % RECIPES.len()];
                            operate(images, 3, Some(other), fb, shape, (0, 0, false));
                        }
                        operate(images, 1, None, fb, shape, (0, 0, false));
                        operate(images, 2, None, fb, shape, (0, 0, false));
                        let Some(cold) = timed(&thread, || {
                            operate(images, 3, Some(r), fb, shape, (0, 0, inside));
                        }) else {
                            continue;
                        };
                        let _ = turn;
                        let miss = cold.saturating_sub(warm);
                        least = least.min(miss);
                        worst = worst.max(miss);
                    }
                    if worst > 0 {
                        rt::println!(
                            "service lookup: 17 {} inside {} least {least} greatest {worst}",
                            r.name,
                            u8::from(inside)
                        );
                        greatest = greatest.max(worst);
                    }
                }
            }
            rt::println!("service lookup: 17 greatest {greatest}");
            fb[ELEMENTS_AT..ELEMENT_MASK_AT + ELEMENT_MASK_BYTES].fill(0);
        }

        /// Measures the three kinds on the shapes of the classes and tells a
        /// line each (`service calibration: 17 KIND call L G N W H row L G N W H
        /// point L G N W H preempted K`: for each class the least and the
        /// greatest figure, how many operations counted, and the shape of the
        /// greatest). The call is ticks, the row hundredths of a tick a row
        /// with the greatest call taken off, the point hundredths of a tick a
        /// point with the greatest call and the rows (at the greatest row price)
        /// taken off: the model of `compositor::PRICES`.
        pub fn calibrate(&mut self, fb: &mut [u8]) {
            if fb.len() < SRC_AT + BYTES {
                rt::println!(
                    "service calibration: the screen's buffer is too small for the scratch"
                );
                return;
            }
            fb[DST_AT..DST_AT + BYTES].fill(0);
            fb[SRC_AT..SRC_AT + BYTES].fill(0x40);
            let Ok(thread) = rt::sys::self_thread() else {
                rt::println!(
                    "service calibration: no thread of its own to read the preemptions of"
                );
                return;
            };
            for (which, name) in [(0, "black"), (1, "copy"), (2, "over")] {
                kind(self, fb, which, None, name, &thread);
            }
            if fb.len() >= ELEMENTS_AT + ELEMENT_SRC_BYTES + ELEMENT_MASK_BYTES {
                fb[ELEMENTS_AT..ELEMENTS_AT + ELEMENT_SRC_BYTES].fill(0x40);
                fb[ELEMENT_MASK_AT..ELEMENT_MASK_AT + ELEMENT_MASK_BYTES].fill(0x80);
                for r in &RECIPES {
                    kind(self, fb, 3, Some(r), r.name, &thread);
                }
                fb[ELEMENTS_AT..ELEMENT_MASK_AT + ELEMENT_MASK_BYTES].fill(0);
            }
            // The target holds zero before its first frame.
            fb[DST_AT..DST_AT + BYTES].fill(0);
            fb[SRC_AT..SRC_AT + BYTES].fill(0);
        }
    }
}
