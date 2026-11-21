// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What an element of a scene means, one point of the screen at a time: the
//! reference the drawing of the service is held to (its host tests, and the
//! probes that work out the screen a scene should show). It knows no pixman:
//! the source point a target point takes comes from the element's rational
//! geometry, and the mixing is the premultiplied "over" on bytes.
//!
//! The geometry. The source rectangle (16.16 points of the window) is turned
//! by the rotation, a quarter turn at a time clockwise, then reflected about
//! the vertical axis when the orientation says so, and the result is stretched
//! to the target rectangle. The centre of the target point at (`x`, `y`) is at
//! the fractions (2 (x - dx) + 1) / (2 dw) and (2 (y - dy) + 1) / (2 dh) of the
//! target's width and height; the inverse of the reflection and the turns gives
//! the point of the source rectangle it takes.
//!
//! Sampling. The nearest filter takes the source point that holds the centre,
//! and one on the border between two goes to the one before it, as pixman's
//! nearest does (it takes the 16.16 coordinate one unit down). The bilinear
//! filter takes the mean of the four points around the centre, with weights of
//! 7 bits, the arithmetic of pixman's C paths. A point outside the window is its
//! edge's. Mixing. A source with no transparency bit of its own alpha is opaque
//! (its alpha byte is not read); the global alpha and the mask multiply it, and
//! with an alpha or a mask the source is laid over the point below it.

use crate::{
    BILINEAR, Element, MIRROR, NO_WINDOW, ROTATION, TRANSPARENCY_ALPHA, TRANSPARENCY_MASK,
    TRANSPARENCY_SOURCE,
};

/// Whether the target point (`x`, `y`) is in the element's target rectangle.
pub const fn covers(e: &Element, x: i32, y: i32) -> bool {
    x >= e.dx
        && y >= e.dy
        && (x as i64) < e.dx as i64 + e.dw as i64
        && (y as i64) < e.dy as i64 + e.dh as i64
}

/// The coordinates in the source, in 16.16 points of the window, of the centre
/// of the target point (`x`, `y`), as the whole 16.16 numbers pixman's
/// transform makes (truncated). None when the target point is outside the
/// target rectangle.
pub fn source_at(e: &Element, x: i32, y: i32) -> Option<(i64, i64)> {
    if !covers(e, x, y) {
        return None;
    }
    let (p, q) = (
        i128::from(x) - i128::from(e.dx),
        i128::from(y) - i128::from(e.dy),
    );
    let (ad, bd) = (2 * i128::from(e.dw), 2 * i128::from(e.dh));
    let (mut an, bn) = (2 * p + 1, 2 * q + 1);
    if e.orient & MIRROR != 0 {
        an = ad - an;
    }
    // (numerator, denominator) of the fraction along each axis of the source.
    let (u, v) = match e.orient & ROTATION {
        0 => ((an, ad), (bn, bd)),
        1 => ((bn, bd), (ad - an, ad)),
        2 => ((ad - an, ad), (bd - bn, bd)),
        _ => ((bd - bn, bd), (an, ad)),
    };
    let at = |origin: i32, size: i32, (n, d): (i128, i128)| -> i64 {
        ((i128::from(origin) * d + i128::from(size) * n).div_euclid(d)) as i64
    };
    Some((at(e.sx, e.sw, u), at(e.sy, e.sh, v)))
}

/// `a * b / 255` rounded as pixman's `MUL_UN8`.
pub const fn mul(a: u32, b: u32) -> u32 {
    let t = a * b + 0x80;
    (t + (t >> 8)) >> 8
}

/// The four bytes of a point times `m` (0 to 255).
const fn scale(p: u32, m: u32) -> u32 {
    mul(p >> 24, m) << 24
        | mul((p >> 16) & 0xFF, m) << 16
        | mul((p >> 8) & 0xFF, m) << 8
        | mul(p & 0xFF, m)
}

/// The mean of the four points at (`x0`, `y0`) by the weights of the fractions
/// `fx` and `fy` (7 bits each), channel by channel.
fn bilinear(tl: u32, tr: u32, bl: u32, br: u32, fx: u32, fy: u32) -> u32 {
    let (dx, dy) = (fx << 1, fy << 1);
    let dxy = dx * dy;
    let dxiy = (dx << 8) - dxy;
    let dixy = (dy << 8) - dxy;
    let dixiy = 256 * 256 + dxy - (dy << 8) - (dx << 8);
    let mut out = 0;
    for shift in [0, 8, 16, 24] {
        let c = |p: u32| (p >> shift) & 0xFF;
        let v = (c(tl) * dixiy + c(tr) * dxiy + c(bl) * dixy + c(br) * dxy) >> 16;
        out |= v << shift;
    }
    out
}

/// The value of the source at the 16.16 coordinates (`u`, `v`) of a window of
/// `size` points, by `fetch` (the premultiplied ARGB value of a point of the
/// window), as the filter says: the point that holds them, or the mean of the
/// four around them. The points outside the window are its edge's.
pub fn at(
    filter: u32,
    (u, v): (i64, i64),
    size: (u32, u32),
    fetch: impl Fn(u32, u32) -> u32,
) -> u32 {
    let clamp = |n: i64, len: u32| n.clamp(0, i64::from(len) - 1) as u32;
    if filter != BILINEAR {
        // One 16.16 unit down, then the whole point.
        return fetch(clamp((u - 1) >> 16, size.0), clamp((v - 1) >> 16, size.1));
    }
    let (u, v) = (u - 0x8000, v - 0x8000);
    let (x0, y0) = (u >> 16, v >> 16);
    let (fx, fy) = (((u >> 9) & 127) as u32, ((v >> 9) & 127) as u32);
    let pick = |dx: i64, dy: i64| fetch(clamp(x0 + dx, size.0), clamp(y0 + dy, size.1));
    bilinear(pick(0, 0), pick(1, 0), pick(0, 1), pick(1, 1), fx, fy)
}

/// The point of the source the target point (`x`, `y`) takes (`at` of its
/// `source_at`): None when the point is outside the target rectangle.
pub fn sample(
    e: &Element,
    x: i32,
    y: i32,
    size: (u32, u32),
    fetch: impl Fn(u32, u32) -> u32,
) -> Option<u32> {
    Some(at(e.filter, source_at(e, x, y)?, size, fetch))
}

/// What the target point `below` becomes when the element lays `source` (a
/// premultiplied ARGB value, the alpha byte its own) on it, with the mask's
/// byte at the point (`mask`, 255 when the element has none): per the
/// element's transparency bits.
pub fn mix(e: &Element, source: u32, mask: u32, below: u32) -> u32 {
    let t = e.transparency;
    // Without the bit of its own alpha the source is opaque.
    let source = if t & TRANSPARENCY_SOURCE != 0 {
        source
    } else {
        source | 0xFF00_0000
    };
    if t == 0 {
        return source & 0x00FF_FFFF;
    }
    let mut m = 255;
    if t & TRANSPARENCY_MASK != 0 {
        m = mask;
    }
    if t & TRANSPARENCY_ALPHA != 0 {
        m = if t & TRANSPARENCY_MASK != 0 {
            mul(m, e.alpha)
        } else {
            e.alpha
        };
    }
    let s = if m == 255 { source } else { scale(source, m) };
    let keep = 255 - (s >> 24);
    let mut out = 0;
    for shift in [0, 8, 16] {
        let c = (mul((below >> shift) & 0xFF, keep) + ((s >> shift) & 0xFF)).min(255);
        out |= c << shift;
    }
    out
}

/// Whether the element draws nothing: no area, or the numbers do not make a
/// source.
pub const fn empty(e: &Element) -> bool {
    e.dw <= 0 || e.dh <= 0 || e.sw <= 0 || e.sh <= 0 || e.source == NO_WINDOW
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NEAREST;

    fn el() -> Element {
        Element {
            source: 0,
            mask: NO_WINDOW,
            sx: 0,
            sy: 0,
            sw: 4 << 16,
            sh: 2 << 16,
            dx: 10,
            dy: 20,
            dw: 4,
            dh: 2,
            orient: 0,
            filter: NEAREST,
            transparency: 0,
            alpha: 255,
        }
    }

    /// The value of a point: its place, to see where it came from.
    fn id(x: u32, y: u32) -> u32 {
        0xFF00_0000 | y << 8 | x
    }

    fn got(e: &Element, x: i32, y: i32) -> u32 {
        sample(e, x, y, (4, 2), id).unwrap()
    }

    #[test]
    fn a_point_outside_the_target_rectangle_takes_nothing() {
        let e = el();
        assert_eq!(sample(&e, 9, 20, (4, 2), id), None);
        assert_eq!(sample(&e, 14, 20, (4, 2), id), None);
        assert_eq!(sample(&e, 10, 22, (4, 2), id), None);
        assert!(sample(&e, 13, 21, (4, 2), id).is_some());
    }

    #[test]
    fn the_identity_takes_each_point_from_its_own_place() {
        let e = el();
        for y in 0..2 {
            for x in 0..4 {
                assert_eq!(got(&e, 10 + x, 20 + y), id(x as u32, y as u32));
            }
        }
    }

    #[test]
    fn the_four_turns_and_the_reflection_take_the_points_of_the_turned_window() {
        // A window of 4 by 2 points turned by a quarter is 2 by 4 on the screen.
        let mut e = el();
        e.dw = 2;
        e.dh = 4;
        e.orient = 1;
        // Clockwise: the top row of the window becomes the right column, read
        // from the top down by the window's left to right.
        assert_eq!(got(&e, 11, 20), id(0, 0));
        assert_eq!(got(&e, 11, 23), id(3, 0));
        assert_eq!(got(&e, 10, 20), id(0, 1));
        e.orient = 3;
        assert_eq!(got(&e, 10, 23), id(0, 0));
        assert_eq!(got(&e, 10, 20), id(3, 0));
        assert_eq!(got(&e, 11, 23), id(0, 1));
        let mut e = el();
        e.orient = 2;
        assert_eq!(got(&e, 13, 21), id(0, 0));
        assert_eq!(got(&e, 10, 20), id(3, 1));
        e.orient = MIRROR;
        assert_eq!(got(&e, 13, 20), id(0, 0));
        assert_eq!(got(&e, 10, 21), id(3, 1));
        // A reflection after a turn: the turn comes first, as the doc says.
        let mut e = el();
        e.dw = 2;
        e.dh = 4;
        e.orient = 1 | MIRROR;
        assert_eq!(got(&e, 10, 20), id(0, 0));
        assert_eq!(got(&e, 10, 23), id(3, 0));
    }

    #[test]
    fn a_stretch_up_repeats_points_and_a_stretch_down_takes_the_later_of_a_border() {
        let mut e = el();
        e.dw = 8;
        e.dh = 4;
        for x in 0..8 {
            assert_eq!(got(&e, 10 + x, 20) & 0xFF, (x / 2) as u32);
        }
        // Half the size: the centre of target point k is the border between
        // source points 2k and 2k + 1, which belongs to the one before it.
        e.dw = 2;
        e.dh = 1;
        assert_eq!(got(&e, 10, 20) & 0xFF, 0);
        assert_eq!(got(&e, 11, 20) & 0xFF, 2);
    }

    #[test]
    fn the_bilinear_filter_takes_the_flat_and_the_mean() {
        let mut e = el();
        e.filter = BILINEAR;
        e.dw = 8;
        e.dh = 4;
        // The flat: every weight sums to one.
        let flat = |_: u32, _: u32| 0xFF40_8020;
        for x in 0..8 {
            assert_eq!(sample(&e, 10 + x, 21, (4, 2), flat), Some(0xFF40_8020));
        }
        // Between points 0 and 1 of the first row, a quarter of the way.
        let ramp = |x: u32, _: u32| 0xFF00_0000 | (x * 100);
        let got = sample(&e, 11, 20, (4, 2), ramp).unwrap() & 0xFF;
        // The centre of target point 1 is at 0.75 of source point 0's edge: 0.25
        // from the centre of point 0 towards 1: 25.
        assert_eq!(got, 25);
        // The edges repeat: the first target point is the first source point.
        assert_eq!(sample(&e, 10, 20, (4, 2), ramp).unwrap() & 0xFF, 0);
    }

    #[test]
    fn the_mixes_follow_the_transparency() {
        let mut e = el();
        // None: the points are opaque and copied, an alpha byte not read.
        assert_eq!(mix(&e, 0x1020_3040, 255, 0x0011_2233), 0x0020_3040);
        // The window's own alpha: laid over, premultiplied.
        e.transparency = TRANSPARENCY_SOURCE;
        assert_eq!(mix(&e, 0xFF10_2030, 255, 0x0011_2233), 0x0010_2030);
        assert_eq!(mix(&e, 0x0000_0000, 255, 0x0011_2233), 0x0011_2233);
        // The global alpha with an opaque source.
        e.transparency = TRANSPARENCY_ALPHA;
        e.alpha = 128;
        assert_eq!(mix(&e, 0x0000_FF00, 255, 0x0000_0000), 0x0000_8000);
        // Over a point below: the below is kept by what the alpha leaves.
        assert_eq!(mix(&e, 0x0000_FF00, 255, 0x00FF_0000), 0x007F_8000);
        // The mask alone; with the alpha both multiply.
        e.transparency = TRANSPARENCY_MASK;
        assert_eq!(mix(&e, 0x00FF_FFFF, 0, 0x0001_0203), 0x0001_0203);
        assert_eq!(mix(&e, 0x00FF_FFFF, 255, 0x0001_0203), 0x00FF_FFFF);
        e.transparency = TRANSPARENCY_MASK | TRANSPARENCY_ALPHA;
        e.alpha = 0;
        assert_eq!(mix(&e, 0x00FF_FFFF, 255, 0x0001_0203), 0x0001_0203);
    }

    #[test]
    fn the_rounding_is_the_one_of_pixmans_unsigned_bytes() {
        assert_eq!(mul(255, 255), 255);
        assert_eq!(mul(128, 128), 64);
        assert_eq!(mul(0, 255), 0);
        assert_eq!(mul(1, 128), 1);
    }
}
