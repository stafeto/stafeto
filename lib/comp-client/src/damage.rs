// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The rectangles of a POST. The service takes none (the whole window) to
//! four; the library takes any number and merges more than four into their
//! bounding box. The rectangles are a hint of what changed, which the
//! service widens to its own bounding box anyway, so the merge loses no
//! point the program meant to show.

use crate::errno::EINVAL;
use crate::layout::{RECTS_MAX, Rect};

/// What goes to the service: `count` rectangles of `rects` (0 for the
/// whole window).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Merged {
    pub rects: [Rect; RECTS_MAX],
    pub count: usize,
}

impl Merged {
    pub fn as_slice(&self) -> &[Rect] {
        &self.rects[..self.count]
    }
}

/// Whether `r` is a part of a window of `width` by `height` points, neither
/// side empty. The sums are formed in 64 bits.
pub fn within(r: &Rect, width: u32, height: u32) -> bool {
    r.x >= 0
        && r.y >= 0
        && r.w > 0
        && r.h > 0
        && i64::from(r.x) + i64::from(r.w) <= i64::from(width)
        && i64::from(r.y) + i64::from(r.h) <= i64::from(height)
}

/// The rectangles for a POST of a window `width` by `height`: EINVAL for a
/// rectangle outside it or empty; none is the whole window (count 0); up to
/// 4 stay as they are; 5 or more become their bounding box.
pub fn merge(rects: &[Rect], width: u32, height: u32) -> Result<Merged, i32> {
    let mut out = Merged {
        rects: [Rect::default(); RECTS_MAX],
        count: 0,
    };
    if rects.iter().any(|r| !within(r, width, height)) {
        return Err(EINVAL);
    }
    if rects.len() <= RECTS_MAX {
        out.rects[..rects.len()].copy_from_slice(rects);
        out.count = rects.len();
        return Ok(out);
    }
    let (mut left, mut top, mut right, mut bottom) = (i32::MAX, i32::MAX, 0, 0);
    for r in rects {
        left = left.min(r.x);
        top = top.min(r.y);
        right = right.max(r.x + r.w);
        bottom = bottom.max(r.y + r.h);
    }
    out.rects[0] = Rect {
        x: left,
        y: top,
        w: right - left,
        h: bottom - top,
    };
    out.count = 1;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn r(x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect { x, y, w, h }
    }

    #[test]
    fn none_means_the_whole_window() {
        let m = merge(&[], 200, 100).unwrap();
        assert_eq!(m.count, 0);
        assert!(m.as_slice().is_empty());
    }

    #[test]
    fn up_to_four_go_as_they_are() {
        let list = [
            r(0, 0, 10, 10),
            r(20, 20, 5, 5),
            r(190, 90, 10, 10),
            r(50, 1, 2, 2),
        ];
        for n in 1..=4 {
            let m = merge(&list[..n], 200, 100).unwrap();
            assert_eq!(m.as_slice(), &list[..n]);
        }
    }

    #[test]
    fn five_merge_into_their_bounding_box() {
        let list = [
            r(10, 20, 5, 5),
            r(100, 30, 10, 10),
            r(20, 60, 4, 4),
            r(0, 50, 3, 3),
            r(150, 70, 20, 10),
        ];
        let m = merge(&list, 200, 100).unwrap();
        assert_eq!(m.as_slice(), &[r(0, 20, 170, 60)]);
        // Every merged rectangle lies inside the box.
        let b = m.rects[0];
        for q in list {
            assert!(q.x >= b.x && q.y >= b.y && q.x + q.w <= b.x + b.w && q.y + q.h <= b.y + b.h);
        }
    }

    #[test]
    fn a_rectangle_outside_or_empty_is_invalid() {
        for bad in [
            r(-1, 0, 5, 5),
            r(0, -1, 5, 5),
            r(0, 0, 0, 5),
            r(0, 0, 5, 0),
            r(0, 0, -5, 5),
            r(196, 0, 5, 5),
            r(0, 96, 5, 5),
            r(i32::MAX, 0, 5, 5),
            r(1, 1, i32::MAX, 5),
        ] {
            assert_eq!(merge(&[bad], 200, 100), Err(EINVAL), "{bad:?}");
        }
        // One bad rectangle among five spoils the call.
        let mut list = [r(0, 0, 1, 1); 5];
        list[3] = r(0, 0, 201, 1);
        assert_eq!(merge(&list, 200, 100), Err(EINVAL));
        // The whole window and the last point are inside.
        assert!(merge(&[r(0, 0, 200, 100)], 200, 100).is_ok());
        assert!(merge(&[r(199, 99, 1, 1)], 200, 100).is_ok());
    }
}
