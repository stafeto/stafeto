// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The pixel operations of a band, which are pixman's (lib/pixman): the
//! rectangle of the screen's bytes black, and the points of a window's
//! buffer replacing or lying over those of the screen.

use compositor::{Format, Raster};
use pixman::{Format as Px, Images, Source, Target, composite, fill};
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
    use core::cell::UnsafeCell;

    /// The scratch surfaces: 160 by 32 points each, in bss (10 pages of the two).
    const WIDTH: u32 = 160;
    const HEIGHT: u32 = 32;
    const STRIDE: u32 = WIDTH * 4;
    const BYTES: usize = (STRIDE * HEIGHT) as usize;

    #[repr(align(64))]
    struct Surface(UnsafeCell<[u8; BYTES]>);
    // SAFETY: touched by the main thread, once, at the start of the service.
    unsafe impl Sync for Surface {}
    static DST: Surface = Surface(UnsafeCell::new([0; BYTES]));
    static SRC: Surface = Surface(UnsafeCell::new([0x40; BYTES]));

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

    /// The shapes of each class, width by height.
    const CALL: [(u32, u32); 4] = [(1, 1), (2, 1), (4, 1), (8, 1)];
    const ROW: [(u32, u32); 6] = [(8, 8), (8, 16), (16, 8), (16, 16), (4, 32), (12, 24)];
    const POINT: [(u32, u32); 5] = [(152, 8), (128, 16), (64, 32), (150, 16), (76, 16)];
    const REPEAT: u32 = 3;

    /// One operation of a kind at offsets (`dx`, `sx`): its ticks, or None when
    /// a higher level preempted the thread in the middle of it.
    fn timed(thread: &rt::handle::Handle<rt::handle::Thread>, run: impl FnOnce()) -> Option<u64> {
        let before = rt::sys::thread_ran_preempts(thread).ok()?;
        let began = rt::time::now();
        run();
        let ended = rt::time::now();
        let after = rt::sys::thread_ran_preempts(thread).ok()?;
        (after.1 == before.1).then(|| ended - began)
    }

    /// Makes the operations of every class of one kind (0 black, 1 copy, 2
    /// over) and tells the line.
    fn kind(
        px: &mut Pixman,
        which: usize,
        name: &str,
        thread: &rt::handle::Handle<rt::handle::Thread>,
    ) {
        let (mut call, mut row, mut point) = (Spread::new(), Spread::new(), Spread::new());
        let mut preempted = 0u32;
        let (mut call_g, mut row_g) = (0u64, 0u64);
        for class in 0..3 {
            let shapes: &[(u32, u32)] = match class {
                0 => &CALL,
                1 => &ROW,
                _ => &POINT,
            };
            for &(w, h) in shapes {
                for dx in 0..4u32 {
                    for sx in 0..4u32 {
                        // One warm-up, which makes the images pixman keeps.
                        for turn in 0..=REPEAT {
                            // SAFETY: the main thread alone touches the scratch.
                            let (dst, src) = unsafe { (&mut *DST.0.get(), &*SRC.0.get()) };
                            let mut target = Target {
                                bytes: dst,
                                format: Px::Xrgb8888,
                                stride: STRIDE,
                                width: WIDTH,
                                height: HEIGHT,
                            };
                            let from = Source {
                                bytes: src,
                                format: if which == 2 {
                                    Px::Argb8888
                                } else {
                                    Px::Xrgb8888
                                },
                                stride: STRIDE,
                                width: WIDTH,
                                height: HEIGHT,
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
                                _ => {
                                    let rows = row_g * u64::from(h) / 100;
                                    let net = ticks.saturating_sub(call_g + rows);
                                    point.add(net * 100 / points, (w, h));
                                }
                            }
                        }
                    }
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

    impl Pixman {
        /// Measures the three kinds on the shapes of the classes and tells a
        /// line each (`service calibration: 17 KIND call L G N W H row L G N W H
        /// point L G N W H preempted K`: for each class the least and the
        /// greatest figure, how many operations counted, and the shape of the
        /// greatest). The call is ticks, the row hundredths of a tick a row
        /// with the greatest call taken off, the point hundredths of a tick a
        /// point with the greatest call and the rows (at the greatest row price)
        /// taken off: the model of `compositor::PRICES`.
        pub fn calibrate(&mut self) {
            let Ok(thread) = rt::sys::self_thread() else {
                rt::println!(
                    "service calibration: no thread of its own to read the preemptions of"
                );
                return;
            };
            for (which, name) in [(0, "black"), (1, "copy"), (2, "over")] {
                kind(self, which, name, &thread);
            }
        }
    }
}
