// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The pixel operations of a band, which are pixman's (lib/pixman): the
//! rectangle of the screen's bytes black, and the points of a window's
//! buffer replacing or lying over those of the screen.

use compositor::{Format, Raster};
use pixman::{Format as Px, Images, Source, Target, composite, fill, prepare};
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

const fn format(f: Format) -> Px {
    match f {
        Format::Xrgb => Px::Xrgb8888,
        Format::Argb => Px::Argb8888,
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

    /// A band begins: its operations are counted from zero.
    pub fn band_begin() {
        BAND_OPS.store(0, Ordering::Relaxed);
        BAND_LAYERS.store(0, Ordering::Relaxed);
    }

    /// The band ended: `compose` took `compose` ticks, the band's code in all
    /// `total`.
    pub fn band_end(compose: u64, total: u64) {
        let ops = BAND_OPS.load(Ordering::Relaxed);
        let layers = (BAND_LAYERS.load(Ordering::Relaxed) as usize).min(MAX_LAYERS - 1);
        let s = &SPLIT[layers];
        let outside = compose.saturating_sub(ops);
        s.n.fetch_add(1, Ordering::Relaxed);
        s.outside_least.fetch_min(outside, Ordering::Relaxed);
        s.outside_greatest.fetch_max(outside, Ordering::Relaxed);
        // The service is one thread: the three go together.
        if total > s.total_greatest.load(Ordering::Relaxed) {
            s.total_greatest.store(total, Ordering::Relaxed);
            s.compose_at_greatest.store(compose, Ordering::Relaxed);
            s.ops_at_greatest.store(ops, Ordering::Relaxed);
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
    pub fn prepare(&mut self, src: &[u8], stride: u32, f: Format, size: (u32, u32)) {
        let source = Source {
            bytes: src,
            format: format(f),
            stride,
            width: size.0,
            height: size.1,
        };
        if !prepare(&mut self.images, source) {
            self.refuse("a surface");
        }
    }

    /// The images made so far.
    pub fn made(&self) -> u32 {
        self.images.made()
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
    fn black(&mut self, fb: &mut [u8], r: Rect) {
        let mut target = Target {
            bytes: fb,
            format: Px::Xrgb8888,
            stride: STRIDE,
            width: WIDTH,
            height: HEIGHT,
        };
        #[cfg(feature = "steps")]
        let began = rt::time::now();
        if !fill(&mut target, r.x, r.y, r.w, r.h, 0) {
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
#[cfg(feature = "steps")]
pub mod calibration {
    use super::{Pixman, Px, Source, Target, composite, fill};

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
    const REPEAT: u32 = 3;

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

    /// Makes the operations of every shape of one kind (0 black, 1 copy, 2
    /// over) and tells a line for each shape and one for the classes.
    fn kind(
        px: &mut Pixman,
        fb: &mut [u8],
        which: usize,
        name: &str,
        thread: &rt::handle::Handle<rt::handle::Thread>,
    ) {
        let (mut call, mut row, mut point) = (Spread::new(), Spread::new(), Spread::new());
        let mut preempted = 0u32;
        let (mut call_g, mut row_g) = (0u64, 0u64);
        // The calls first, then the rows, then the points: each class takes off
        // the greatest of those before it.
        for order in [0u8, 1, 2] {
            for &(w, h, class) in &SHAPES {
                let tells = if class == 3 { 0 } else { class };
                if tells != order {
                    continue;
                }
                let (mut least, mut greatest, mut n) = (u64::MAX, 0u64, 0u64);
                for dx in 0..4u32 {
                    for sx in 0..4u32 {
                        // One warm-up, which makes the images pixman keeps.
                        for turn in 0..=REPEAT {
                            let (dst_region, rest) = fb.split_at_mut(SRC_AT);
                            let (dst, src) =
                                (&mut dst_region[DST_AT..DST_AT + BYTES], &rest[..BYTES]);
                            // The width of the screen on the wide surface, the
                            // others on the narrow one (the same memory).
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
                            };
                            let images = &mut px.images;
                            let ticks = timed(thread, || {
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
                            });
                            if turn == 0 {
                                continue;
                            }
                            let Some(ticks) = ticks else {
                                preempted += 1;
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
    /// The widths are the ones a band of layers gets (a part of a line of about 100
    /// points for eight, more lines for fewer) and a few others.
    const LAYER_SHAPES: [(u32, u32); 6] = [(16, 1), (64, 1), (150, 1), (150, 4), (76, 8), (8, 8)];
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
    const LAYER_REPEAT: u32 = 2;
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
        fn black(&mut self, _fb: &mut [u8], r: proto_comp::Rect) {
            let mut target = Target {
                bytes: self.target,
                format: Px::Xrgb8888,
                stride: LAYER_TARGET_W * 4,
                width: LAYER_TARGET_W,
                height: LAYER_TARGET_H,
            };
            fill(&mut target, r.x, r.y - self.y0, r.w, r.h, 0);
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
                                            compositor::Band { row: dy, col: 0 },
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
                kind(self, fb, which, name, &thread);
            }
            // The target holds zero before its first frame.
            fb[DST_AT..DST_AT + BYTES].fill(0);
            fb[SRC_AT..SRC_AT + BYTES].fill(0);
        }
    }
}
