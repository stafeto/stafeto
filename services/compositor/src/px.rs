// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The pixel operations of a band, which are pixman's (lib/pixman): the
//! rectangle of the screen's bytes black, and the points of a window's
//! buffer replacing or lying over those of the screen.

use compositor::{Format, Raster};
use pixman::{Format as Px, Source, Target, composite, fill};
use proto_comp::Rect;
use proto_gpu::{HEIGHT, STRIDE, WIDTH};

/// The operations over the screen's buffer.
pub struct Pixman;

const fn format(f: Format) -> Px {
    match f {
        Format::Xrgb => Px::Xrgb8888,
        Format::Argb => Px::Argb8888,
    }
}

impl Pixman {
    /// Makes pixman build its tables of implementations now, in the
    /// start of the service and not in the step of its first band: one
    /// point laid over one point.
    pub fn warm() -> Pixman {
        let mut dst = [0u8; 4];
        let src = [0u8; 4];
        let mut target = Target {
            bytes: &mut dst,
            format: Px::Xrgb8888,
            stride: 4,
            width: 1,
            height: 1,
        };
        let from = Source {
            bytes: &src,
            format: Px::Argb8888,
            stride: 4,
            width: 1,
            height: 1,
        };
        composite(true, &mut target, from, (0, 0), (0, 0), (1, 1));
        composite(false, &mut target, from, (0, 0), (0, 0), (1, 1));
        Pixman
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
        fill(&mut target, r.x, r.y, r.w, r.h, 0);
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
        composite(over, &mut target, source, from, to, area);
    }
}
