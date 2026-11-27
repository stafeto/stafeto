// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The damage of a frame as a short list of rectangles. Two small areas far
//! from each other stay two rectangles, and the frame composes the bands of
//! each, where one bounding rectangle would hold the bands of everything
//! between them too. The list holds at most `MAX_DAMAGE` rectangles that do not
//! overlap; a rectangle that overlaps one in the list is merged into it, and a
//! rectangle that finds the list full merges the pair whose union adds the least
//! to the bands the list covers.

use crate::{BAND_ROWS, FILL, LAYER, OPAQUE, Price, band_size};
use proto_gpu::Rect;

/// The rectangles of one frame's damage at most.
pub const MAX_DAMAGE: usize = 4;

const NONE: Rect = Rect {
    x: 0,
    y: 0,
    w: 0,
    h: 0,
};

/// The bands a rectangle takes by the model of a band (`band_size`), for the
/// reference layers of a window scene: one opaque copy over the black. A scene
/// with more layers makes its bands smaller by the same rule for every
/// rectangle, so the order of the rectangles by this count holds for it too.
pub fn bands_of(r: Rect) -> u64 {
    if r.w == 0 || r.h == 0 {
        return 0;
    }
    let layers = [FILL, OPAQUE];
    let (mut calls, mut per_row, mut per_point) = (0u32, 0u32, 0u32);
    for p in layers {
        let Price {
            call, row, point, ..
        } = p;
        calls += call + LAYER;
        per_row += row;
        per_point += point;
    }
    let (cols, rows) = band_size(calls, per_row, per_point, r.w);
    let rows = rows.clamp(1, BAND_ROWS);
    u64::from(r.h.div_ceil(rows)) * u64::from(r.w.div_ceil(cols.max(1)))
}

fn area(r: Rect) -> u64 {
    u64::from(r.w) * u64::from(r.h)
}

fn overlap(a: Rect, b: Rect) -> bool {
    a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h
}

fn join(a: Rect, b: Rect) -> Rect {
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

/// What the union of `a` and `b` adds to the bands and to the area of the two
/// taken apart: the key the cheapest pair is chosen by (bands first).
fn added(a: Rect, b: Rect) -> (i64, i64) {
    let u = join(a, b);
    (
        bands_of(u) as i64 - bands_of(a) as i64 - bands_of(b) as i64,
        area(u) as i64 - area(a) as i64 - area(b) as i64,
    )
}

/// Up to `MAX_DAMAGE` rectangles that do not overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DamageList {
    rects: [Rect; MAX_DAMAGE],
    n: usize,
}

impl Default for DamageList {
    fn default() -> Self {
        Self::new()
    }
}

impl DamageList {
    pub const fn new() -> Self {
        DamageList {
            rects: [NONE; MAX_DAMAGE],
            n: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn len(&self) -> usize {
        self.n
    }

    /// The rectangles, in the order they were added (merged ones in the place of
    /// the first).
    pub fn rects(&self) -> &[Rect] {
        &self.rects[..self.n]
    }

    /// The least rectangle that holds them all.
    pub fn bounds(&self) -> Option<Rect> {
        self.rects().iter().copied().reduce(join)
    }

    /// The bands the list covers by the model (`bands_of`).
    pub fn bands(&self) -> u64 {
        self.rects().iter().map(|&r| bands_of(r)).sum()
    }

    /// Takes the list, leaving it empty.
    pub fn take(&mut self) -> DamageList {
        core::mem::take(self)
    }

    /// Adds a rectangle (an empty one is nothing). One that overlaps rectangles of
    /// the list is merged with them; one that finds the list full makes room by
    /// merging the pair that adds the least bands (then the least area).
    pub fn add(&mut self, r: Rect) {
        if r.w == 0 || r.h == 0 {
            return;
        }
        let mut r = r;
        loop {
            // Absorb every rectangle it overlaps; the union may overlap more.
            while let Some(i) = self.rects().iter().position(|&o| overlap(o, r)) {
                r = join(self.rects[i], r);
                self.remove(i);
            }
            if self.n < MAX_DAMAGE {
                self.rects[self.n] = r;
                self.n += 1;
                return;
            }
            // Full: the cheapest pair of the five (the new one and the four).
            let mut best: Option<((i64, i64), usize, usize)> = None;
            for i in 0..self.n {
                for j in i + 1..self.n {
                    let key = added(self.rects[i], self.rects[j]);
                    if best.is_none_or(|(k, _, _)| key < k) {
                        best = Some((key, i, j));
                    }
                }
                let key = added(self.rects[i], r);
                if best.is_none_or(|(k, _, _)| key < k) {
                    best = Some((key, i, self.n));
                }
            }
            let Some((_, i, j)) = best else {
                return;
            };
            if j == self.n {
                r = join(self.rects[i], r);
                self.remove(i);
            } else {
                let merged = join(self.rects[i], self.rects[j]);
                self.remove(j);
                self.remove(i);
                // The union may overlap a third rectangle: it goes in by the
                // same rules (the list has room, so this ends).
                self.add(merged);
            }
        }
    }

    /// Adds every rectangle of `other`.
    pub fn add_all(&mut self, other: &DamageList) {
        for &r in other.rects() {
            self.add(r);
        }
    }

    fn remove(&mut self, i: usize) {
        self.rects.copy_within(i + 1..self.n, i);
        self.n -= 1;
        self.rects[self.n] = NONE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(x: u32, y: u32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    #[test]
    fn far_rectangles_stay_apart() {
        let mut d = DamageList::new();
        d.add(r(0, 0, 20, 20));
        d.add(r(600, 440, 20, 20));
        assert_eq!(d.rects(), &[r(0, 0, 20, 20), r(600, 440, 20, 20)]);
        assert_eq!(d.bounds(), Some(r(0, 0, 620, 460)));
        assert!(d.bands() < bands_of(d.bounds().unwrap()));
    }

    #[test]
    fn overlapping_rectangles_merge_and_empty_ones_are_nothing() {
        let mut d = DamageList::new();
        d.add(r(10, 10, 30, 30));
        d.add(r(0, 0, 0, 5));
        d.add(r(30, 30, 30, 30));
        assert_eq!(d.rects(), &[r(10, 10, 50, 50)]);
        // One that bridges two of the list merges all three.
        let mut d = DamageList::new();
        d.add(r(0, 0, 10, 10));
        d.add(r(100, 0, 10, 10));
        d.add(r(5, 5, 100, 2));
        assert_eq!(d.rects(), &[r(0, 0, 110, 10)]);
    }

    #[test]
    fn the_fifth_merges_the_cheapest_pair() {
        let mut d = DamageList::new();
        for y in [0, 100, 200, 300] {
            d.add(r(0, y, 16, 16));
        }
        assert_eq!(d.len(), 4);
        // Near the second: that pair adds the least.
        d.add(r(0, 116, 16, 16));
        assert_eq!(d.len(), 4);
        assert!(d.rects().contains(&r(0, 100, 16, 32)));
        for y in [0, 200, 300] {
            assert!(d.rects().contains(&r(0, y, 16, 16)), "{y}");
        }
        // Far from all: two of the list that lie nearest each other merge, and
        // the new one keeps its place.
        let mut d = DamageList::new();
        for y in [0, 40, 300, 400] {
            d.add(r(0, y, 16, 16));
        }
        d.add(r(600, 460, 16, 16));
        assert_eq!(d.len(), 4);
        assert!(d.rects().contains(&r(0, 0, 16, 56)));
        assert!(d.rects().contains(&r(600, 460, 16, 16)));
    }

    #[test]
    fn the_list_never_overlaps_and_covers_what_was_added() {
        let mut d = DamageList::new();
        let mut seed = 12345u32;
        let mut next = |m: u32| {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (seed >> 8) % m
        };
        let mut all = [NONE; 40];
        for slot in &mut all {
            *slot = r(next(600), next(440), 1 + next(40), 1 + next(40));
            d.add(*slot);
            assert!(d.len() <= MAX_DAMAGE);
            for (i, a) in d.rects().iter().enumerate() {
                for b in &d.rects()[i + 1..] {
                    assert!(!overlap(*a, *b));
                }
            }
        }
        // Every point of every rectangle added is in a rectangle of the list.
        for a in all {
            for (x, y) in [(a.x, a.y), (a.x + a.w - 1, a.y + a.h - 1)] {
                assert!(
                    d.rects()
                        .iter()
                        .any(|c| x >= c.x && x < c.x + c.w && y >= c.y && y < c.y + c.h)
                );
            }
        }
    }
}
