// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The elements of a scene (proto_comp's SCENE_COMMIT) as the service keeps
//! them: the definition of a scene, the checks of an element against the
//! windows it names, the rule for what the present operations of a band can
//! draw, the geometry that carries a rectangle of a window's points to the
//! screen through an element (the damage of a posted buffer), and the damage
//! of a scene that replaces another. All of it is pure: the windows come as
//! a function, so the host tests tabulate it.
//!
//! The geometry of an element. The source rectangle (16.16 points of the
//! window) is turned by the rotation, a quarter turn at a time clockwise,
//! then reflected about the vertical axis when the orientation says so, and
//! the result is stretched to the target rectangle. A point of the target
//! at the fraction (a, b) of its width and height takes its colour from the
//! source at the fraction below (the inverse of the turns and the
//! reflection), and `target_of` is the map the other way round.

use crate::{Format, HEIGHT, Rect, WIDTH};
use proto_comp::{
    BILINEAR, Element, MAX_ELEMENTS, MIRROR, NO_WINDOW, ROTATION, SceneCommit, TRANSPARENCY_MASK,
    TRANSPARENCY_SOURCE, union,
};

/// A scene: the flags and the background of the commit, and its elements,
/// lowest first. Two scenes are equal when what they say is: the places past
/// the last element hold what an earlier scene left there.
#[derive(Clone, Copy, Debug)]
pub struct Def {
    pub active: bool,
    /// The background, 0xAARRGGBB with the colour premultiplied by the alpha.
    pub bg: u32,
    count: usize,
    items: [Element; MAX_ELEMENTS],
}

impl PartialEq for Def {
    fn eq(&self, other: &Def) -> bool {
        self.active == other.active && self.bg == other.bg && self.elements() == other.elements()
    }
}

impl Eq for Def {}

impl Def {
    /// The scene with no element, black, composed only on request: what a
    /// context has before its first commit.
    pub const EMPTY: Def = Def {
        active: false,
        bg: 0xFF00_0000,
        count: 0,
        items: [Element::NONE; MAX_ELEMENTS],
    };

    pub fn from_commit(commit: &SceneCommit) -> Def {
        let mut def = Def::EMPTY;
        def.load(commit);
        def
    }

    /// The scene of `commit`, replacing what was here.
    pub fn load(&mut self, commit: &SceneCommit) {
        self.active = commit.flags & proto_comp::ACTIVE != 0;
        self.bg = commit.bg;
        self.count = commit.count as usize;
        self.items = commit.elements;
    }

    /// The scene of SCENE_COMMIT's body (`SceneCommit::read_into`), parsed
    /// into this place with no copy of a whole scene; the flags. What the body
    /// does not say (a refusal) leaves the place with no meaning: it is a place
    /// the caller has no scene in.
    pub fn parse(&mut self, body: proto_wire::Reader<'_>) -> Result<u32, proto_wire::Status> {
        let (flags, bg, count) = SceneCommit::read_into(body, &mut self.items)?;
        self.active = flags & proto_comp::ACTIVE != 0;
        self.bg = bg;
        self.count = count;
        Ok(flags)
    }

    /// The empty scene, in place.
    pub fn clear(&mut self) {
        self.active = false;
        self.bg = Def::EMPTY.bg;
        self.count = 0;
    }

    pub fn elements(&self) -> &[Element] {
        &self.items[..self.count]
    }

    /// The colour the screen starts with where no element covers it: the
    /// background over black (the screen is opaque).
    pub const fn fill(&self) -> u32 {
        // The colour is already multiplied by the alpha: over black it is what
        // the points say, and the alpha drops out.
        self.bg & 0x00FF_FFFF
    }

    /// Whether some element uses window `id`: it shows it, or it is its mask.
    pub fn uses(&self, id: u32) -> bool {
        self.elements()
            .iter()
            .any(|e| e.source == id || (e.transparency & TRANSPARENCY_MASK != 0 && e.mask == id))
    }
}

/// What a window is, for the checks of an element: its format and size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub format: Format,
    pub w: u32,
    pub h: u32,
}

/// Why SCENE_COMMIT is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A number out of its place: a window of the wrong format or too small
    /// for the rectangle.
    Invalid,
}

/// The checks of a scene against the windows (`window` says the shape of the
/// window with a number, or none):
///
/// - the source window, when there is one, is not of FORMAT_A8 and holds the
///   source rectangle;
/// - the mask, when the transparency has the mask bit and the window exists,
///   is of FORMAT_A8 and the size of the target rectangle (OpenWF
///   Composition 7.1.9: a mask is not stretched).
///
/// Every element the numbers allow is drawn: the service has an operation for
/// each (`Class`), and a scene whose layers cost more than a band holds is
/// drawn by a band in several steps (`compositor::Passes`).
pub fn check(def: &Def, window: impl Fn(u32) -> Option<Shape>) -> Result<(), Fault> {
    for e in def.elements() {
        if let Some(s) = window(e.source) {
            let (sx, sy, sw, sh) = (
                i64::from(e.sx),
                i64::from(e.sy),
                i64::from(e.sw),
                i64::from(e.sh),
            );
            if s.format == Format::A8
                || sx + sw > i64::from(s.w) << 16
                || sy + sh > i64::from(s.h) << 16
            {
                return Err(Fault::Invalid);
            }
        }
        if e.transparency & TRANSPARENCY_MASK != 0
            && e.mask != NO_WINDOW
            && let Some(m) = window(e.mask)
            && (m.format != Format::A8
                || i64::from(m.w) != i64::from(e.dw)
                || i64::from(m.h) != i64::from(e.dh))
        {
            return Err(Fault::Invalid);
        }
    }
    Ok(())
}

/// Whether an element shows the window's points as they are: one point of the
/// window for one of the screen (the scale of one on whole points), no turn and
/// no reflection. What a band draws of it is a copy or a laying over of the
/// points (`Raster::blit`, the operations that came first), or, with a global
/// alpha or a mask, an element's drawing with no transform.
pub fn is_plain(e: &Element) -> bool {
    e.orient == 0
        && e.sx & 0xFFFF == 0
        && e.sy & 0xFFFF == 0
        && i64::from(e.sw) == i64::from(e.dw) << 16
        && i64::from(e.sh) == i64::from(e.dh) << 16
}

/// The map of the screen's points to the window's that carries the target
/// rectangle's points through the element's reflection, turn and stretch:
/// `[a, b, c, d, e, f]` takes the centre (x, y) of a target point (in points of
/// the screen) to the window's (a x + b y + c, d x + e y + f), all in 16.16.
/// The steps are the source sides over the target sides, rounded to the
/// nearest 16.16 (a ratio that is not a fraction of 16.16 has an error of half a
/// unit a point: at most 0.005 of a point over the screen's width).
pub fn matrix(e: &Element) -> [i32; 6] {
    let (sx, sy) = (i64::from(e.sx), i64::from(e.sy));
    let (sw, sh) = (i64::from(e.sw), i64::from(e.sh));
    let (dw, dh) = (i64::from(e.dw.max(1)), i64::from(e.dh.max(1)));
    // The ratio of a source side to a target side, rounded to the nearest.
    let ratio = |s: i64, d: i64| (2 * s + d).div_euclid(2 * d);
    let m = e.orient & MIRROR != 0;
    let sign = |negative: bool| if negative { -1 } else { 1 };
    // Each source axis: its value at the target rectangle's corner, and the
    // step along the target's x (p) and y (q).
    let ((ub, up, uq), (vb, vp, vq)) = match e.orient & ROTATION {
        0 => (
            (sx + if m { sw } else { 0 }, sign(m) * ratio(sw, dw), 0),
            (sy, 0, ratio(sh, dh)),
        ),
        1 => (
            (sx, 0, ratio(sw, dh)),
            (sy + if m { 0 } else { sh }, -sign(m) * ratio(sh, dw), 0),
        ),
        2 => (
            (sx + if m { 0 } else { sw }, -sign(m) * ratio(sw, dw), 0),
            (sy + sh, 0, -ratio(sh, dh)),
        ),
        _ => (
            (sx + sw, 0, -ratio(sw, dh)),
            (sy + if m { sh } else { 0 }, sign(m) * ratio(sh, dw), 0),
        ),
    };
    let at = |base: i64, p: i64, q: i64| -> [i32; 3] {
        let origin = base - p * i64::from(e.dx) - q * i64::from(e.dy);
        let fit = |n: i64| n.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
        [fit(p), fit(q), fit(origin)]
    };
    let [a, b, c] = at(ub, up, uq);
    let [d, f, g] = at(vb, vp, vq);
    [a, b, c, d, f, g]
}

/// The kinds of operation a band charges for an element (the rows of
/// `compositor::PRICES` after the black, in this order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// A plain copy of the points (no transparency, scale of one, no turn).
    Copy = 1,
    /// A plain laying over, by the window's own alpha.
    Over = 2,
    /// A stretch, turn or reflection with the nearest point: a copy, or a laying
    /// over.
    ScaleNearestCopy = 3,
    ScaleNearestOver = 4,
    /// The same with the bilinear mean.
    ScaleBilinearCopy = 5,
    ScaleBilinearOver = 6,
    /// A copy turned a quarter or three quarters, with no stretch and no
    /// reflection, nearest point (pixman has a path of its own for it).
    Rotate90 = 7,
    /// A global alpha with a plain placing; with a mask; with both.
    Alpha = 8,
    Mask = 9,
    MaskAlpha = 10,
}

impl Class {
    /// The row of `compositor::PRICES`.
    pub const fn row(self) -> usize {
        self as usize
    }
}

/// What a band charges for an element: the operation of its geometry, and,
/// for an alpha or a mask, the operation of that besides it. A plain element
/// with an alpha or a mask is the one operation (its calibration is made with
/// no transform); one that is stretched, turned or reflected pays for the
/// stretch as a laying over, and for the alpha or the mask on top of it (the
/// sum errs high: both prices have the call, the row and the combine).
pub fn classes(e: &Element) -> (Class, Option<Class>) {
    let plain = is_plain(e);
    let bilinear = e.filter == BILINEAR;
    let t = e.transparency;
    let extra = match (
        t & TRANSPARENCY_MASK != 0,
        t & proto_comp::TRANSPARENCY_ALPHA != 0,
    ) {
        (true, true) => Some(Class::MaskAlpha),
        (true, false) => Some(Class::Mask),
        (false, true) => Some(Class::Alpha),
        (false, false) => None,
    };
    if let Some(extra) = extra {
        if plain {
            return (extra, None);
        }
        let first = if bilinear {
            Class::ScaleBilinearOver
        } else {
            Class::ScaleNearestOver
        };
        return (first, Some(extra));
    }
    let over = t & TRANSPARENCY_SOURCE != 0;
    if plain {
        return (if over { Class::Over } else { Class::Copy }, None);
    }
    let quarter = e.orient & ROTATION & 1 != 0
        && e.orient & MIRROR == 0
        && i64::from(e.sw) == i64::from(e.dh) << 16
        && i64::from(e.sh) == i64::from(e.dw) << 16
        && e.sx & 0xFFFF == 0
        && e.sy & 0xFFFF == 0;
    let class = match (bilinear, over) {
        (false, false) if quarter => Class::Rotate90,
        (false, false) => Class::ScaleNearestCopy,
        (false, true) => Class::ScaleNearestOver,
        (true, false) => Class::ScaleBilinearCopy,
        (true, true) => Class::ScaleBilinearOver,
    };
    (class, None)
}

/// The window of an element the service shows nothing of as it is: no
/// source, or the source rectangle comes out past a window of the same number
/// that is smaller (a window went and another took its place).
pub fn source_fits(e: &Element, w: u32, h: u32) -> bool {
    i64::from(e.sx) + i64::from(e.sw) <= i64::from(w) << 16
        && i64::from(e.sy) + i64::from(e.sh) <= i64::from(h) << 16
}

/// The target rectangle of an element, cut to the screen: None when nothing
/// of it is on the screen.
pub fn target_bounds(e: &Element) -> Option<Rect> {
    clip(
        i64::from(e.dx),
        i64::from(e.dy),
        i64::from(e.dx) + i64::from(e.dw),
        i64::from(e.dy) + i64::from(e.dh),
    )
}

/// The rectangle with corners (`x0`, `y0`) and (`x1`, `y1`) cut to the
/// screen.
pub fn clip(x0: i64, y0: i64, x1: i64, y1: i64) -> Option<Rect> {
    let (x0, y0) = (x0.max(0), y0.max(0));
    let (x1, y1) = (x1.min(i64::from(WIDTH)), y1.min(i64::from(HEIGHT)));
    if x0 >= x1 || y0 >= y1 {
        return None;
    }
    Some(Rect {
        x: x0 as u32,
        y: y0 as u32,
        w: (x1 - x0) as u32,
        h: (y1 - y0) as u32,
    })
}

/// The fraction of the target's width and of its height (each a numerator and
/// a denominator) a point of the source at (`u`, `v`) goes to, in 16.16
/// points from the source rectangle's corner (0 to `sw`, 0 to `sh`): the
/// rotation, then the reflection.
fn fractions(e: &Element, u: i64, v: i64) -> ((i64, i64), (i64, i64)) {
    let (sw, sh) = (i64::from(e.sw), i64::from(e.sh));
    let (mut a, b) = match e.orient & ROTATION {
        0 => ((u, sw), (v, sh)),
        1 => ((sh - v, sh), (u, sw)),
        2 => ((sw - u, sw), (sh - v, sh)),
        _ => ((v, sh), (sw - u, sw)),
    };
    if e.orient & MIRROR != 0 {
        a = (a.1 - a.0, a.1);
    }
    (a, b)
}

/// The rectangle of the screen that the points of the window's rectangle
/// `r` (in points of the window) go to through `e`: its source rectangle cut
/// to `r`, carried by the turns, the reflection and the stretch to the target,
/// outward to whole points, one point more on every side when the filter is
/// the bilinear mean (a point of the target reads the four around it), cut to
/// the screen. None when `r` meets no point of the source rectangle or the
/// result is not on the screen.
pub fn target_of(e: &Element, r: Rect) -> Option<Rect> {
    let (sx, sy) = (i64::from(e.sx), i64::from(e.sy));
    let (sw, sh) = (i64::from(e.sw), i64::from(e.sh));
    let u0 = (i64::from(r.x) << 16).max(sx) - sx;
    let v0 = (i64::from(r.y) << 16).max(sy) - sy;
    let u1 = ((i64::from(r.x) + i64::from(r.w)) << 16).min(sx + sw) - sx;
    let v1 = ((i64::from(r.y) + i64::from(r.h)) << 16).min(sy + sh) - sy;
    if u0 >= u1 || v0 >= v1 || sw == 0 || sh == 0 {
        return None;
    }
    let (dw, dh) = (i64::from(e.dw), i64::from(e.dh));
    let mut lo = (i64::MAX, i64::MAX);
    let mut hi = (i64::MIN, i64::MIN);
    for (u, v) in [(u0, v0), (u1, v0), (u0, v1), (u1, v1)] {
        let ((an, ad), (bn, bd)) = fractions(e, u, v);
        let x = i128::from(an) * i128::from(dw);
        let y = i128::from(bn) * i128::from(dh);
        let floor_x = i64::from(e.dx) + x.div_euclid(i128::from(ad)) as i64;
        let ceil_x = i64::from(e.dx) + (-(-x).div_euclid(i128::from(ad))) as i64;
        let floor_y = i64::from(e.dy) + y.div_euclid(i128::from(bd)) as i64;
        let ceil_y = i64::from(e.dy) + (-(-y).div_euclid(i128::from(bd))) as i64;
        lo = (lo.0.min(floor_x), lo.1.min(floor_y));
        hi = (hi.0.max(ceil_x), hi.1.max(ceil_y));
    }
    let margin = i64::from(e.filter == BILINEAR);
    clip(lo.0 - margin, lo.1 - margin, hi.0 + margin, hi.1 + margin)
}

/// The union of the screen's rectangles the elements of `def` that use window
/// `id` change when the window's rectangle `r` changes (a mask: its whole
/// target rectangle, for a mask is all or nothing under an element); None when
/// no element uses the window, or what they show of it is off the screen.
pub fn window_damage(def: &Def, id: u32, r: Rect) -> Option<Rect> {
    let mut sum = None;
    for e in def.elements() {
        let part = if e.source == id {
            target_of(e, r)
        } else if e.transparency & TRANSPARENCY_MASK != 0 && e.mask == id {
            target_bounds(e)
        } else {
            None
        };
        if let Some(part) = part {
            sum = Some(union(sum, part));
        }
    }
    sum
}

/// What the screen needs redrawn when `new` replaces `old`: the union of the
/// target rectangles of the elements that came, went or changed in any field
/// (the elements are compared place by place, so one inserted below moves the
/// rest, which are redrawn), the whole screen for another background or when
/// there was no scene.
pub fn scene_damage(old: Option<&Def>, new: &Def) -> Option<Rect> {
    let screen = Rect {
        x: 0,
        y: 0,
        w: WIDTH,
        h: HEIGHT,
    };
    let Some(old) = old else {
        return Some(screen);
    };
    if old.bg != new.bg {
        return Some(screen);
    }
    let (a, b) = (old.elements(), new.elements());
    let mut sum = None;
    for k in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(k), b.get(k));
        if x == y {
            continue;
        }
        for e in [x, y].into_iter().flatten() {
            if let Some(r) = target_bounds(e) {
                sum = Some(union(sum, r));
            }
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_comp::{ACTIVE, NEAREST, TRANSPARENCY_ALPHA};

    fn el(source: u32) -> Element {
        Element {
            source,
            mask: NO_WINDOW,
            sx: 0,
            sy: 0,
            sw: 100 << 16,
            sh: 50 << 16,
            dx: 10,
            dy: 20,
            dw: 100,
            dh: 50,
            orient: 0,
            filter: NEAREST,
            transparency: 0,
            alpha: 255,
        }
    }

    fn def(items: &[Element]) -> Def {
        Def::from_commit(&SceneCommit::new(ACTIVE, 0xFF00_0000, items).unwrap())
    }

    fn shape(format: Format, w: u32, h: u32) -> Option<Shape> {
        Some(Shape { format, w, h })
    }

    fn rect(x: u32, y: u32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    #[test]
    fn a_scene_keeps_its_elements_in_order_and_its_flags() {
        let d = def(&[el(1), el(2)]);
        assert!(d.active);
        assert_eq!(d.elements().len(), 2);
        assert_eq!(d.elements()[1].source, 2);
        let empty = Def::EMPTY;
        assert!(!empty.active);
        assert!(Def::EMPTY.elements().is_empty());
        assert_eq!(
            Def::from_commit(&SceneCommit::new(0, 7, &[]).unwrap()).bg,
            7
        );
    }

    #[test]
    fn a_window_is_used_as_a_source_or_as_a_mask_under_the_mask_bit() {
        let mut masked = el(1);
        masked.mask = 4;
        masked.transparency = TRANSPARENCY_MASK;
        let d = def(&[masked]);
        assert!(d.uses(1) && d.uses(4));
        assert!(!d.uses(0) && !d.uses(2));
        // A mask the transparency does not name is not used.
        let mut unnamed = el(1);
        unnamed.mask = 4;
        assert!(!def(&[unnamed]).uses(4));
        assert!(!def(&[]).uses(1));
        assert!(!def(&[el(NO_WINDOW)]).uses(0));
    }

    #[test]
    fn the_source_window_must_hold_the_rectangle_and_not_be_a_mask() {
        let d = def(&[el(1)]);
        let big = |_: u32| shape(Format::Xrgb, 100, 50);
        assert_eq!(check(&d, big), Ok(()));
        let small = |_: u32| shape(Format::Xrgb, 99, 50);
        assert_eq!(check(&d, small), Err(Fault::Invalid));
        let short = |_: u32| shape(Format::Argb, 100, 49);
        assert_eq!(check(&d, short), Err(Fault::Invalid));
        let mask = |_: u32| shape(Format::A8, 100, 50);
        assert_eq!(check(&d, mask), Err(Fault::Invalid));
        // A window that is not there is not an error: the element shows nothing.
        assert_eq!(check(&d, |_| None), Ok(()));
        // The rectangle may start inside the window.
        let mut inner = el(1);
        inner.sx = 10 << 16;
        inner.sw = 90 << 16;
        inner.dw = 90;
        assert_eq!(check(&def(&[inner]), big), Ok(()));
        inner.sw = 91 << 16;
        inner.dw = 91;
        assert_eq!(check(&def(&[inner]), big), Err(Fault::Invalid));
    }

    #[test]
    fn a_mask_is_an_a8_window_of_the_size_of_the_target() {
        let mut e = el(1);
        e.transparency = TRANSPARENCY_MASK;
        e.mask = 2;
        let d = def(&[e]);
        let with = |mask: Option<Shape>| {
            move |id: u32| match id {
                1 => shape(Format::Xrgb, 100, 50),
                2 => mask,
                _ => None,
            }
        };
        assert_eq!(check(&d, with(shape(Format::A8, 100, 50))), Ok(()));
        assert_eq!(
            check(&d, with(shape(Format::A8, 100, 49))),
            Err(Fault::Invalid)
        );
        assert_eq!(
            check(&d, with(shape(Format::A8, 101, 50))),
            Err(Fault::Invalid)
        );
        assert_eq!(
            check(&d, with(shape(Format::Xrgb, 100, 50))),
            Err(Fault::Invalid)
        );
        // A mask window that is not there is not an error: the element shows
        // nothing.
        assert_eq!(check(&d, with(None)), Ok(()));
        // The mask of an element that does not have the bit is not looked at.
        let mut plain = el(1);
        plain.mask = 2;
        assert_eq!(
            check(&def(&[plain]), with(shape(Format::Xrgb, 1, 1))),
            Ok(())
        );
    }

    #[test]
    fn every_element_the_numbers_allow_passes_the_check() {
        let window = |_: u32| shape(Format::Argb, 100, 50);
        let drawn = |change: fn(&mut Element)| {
            let mut e = el(1);
            change(&mut e);
            check(&def(&[e]), window)
        };
        assert_eq!(drawn(|_| {}), Ok(()));
        assert_eq!(drawn(|e| e.transparency = TRANSPARENCY_SOURCE), Ok(()));
        assert_eq!(drawn(|e| e.filter = BILINEAR), Ok(()));
        assert_eq!(drawn(|e| e.dx = -50), Ok(()));
        assert_eq!(drawn(|e| e.dx = 5_000), Ok(()));
        assert_eq!(drawn(|e| e.dw = 0), Ok(()));
        for what in [
            drawn(|e| e.orient = 1),
            drawn(|e| e.orient = 3 | proto_comp::MIRROR),
            drawn(|e| e.transparency = TRANSPARENCY_ALPHA),
            drawn(|e| e.transparency = TRANSPARENCY_ALPHA | TRANSPARENCY_SOURCE),
            drawn(|e| e.transparency = TRANSPARENCY_MASK),
            drawn(|e| {
                e.sx = 1 << 15;
                e.sw = 99 << 16;
                e.dw = 99;
            }),
            drawn(|e| e.dw = 50),
            drawn(|e| e.dh = 100),
        ] {
            assert_eq!(what, Ok(()));
        }
        // A number out of its place is INVALID, whichever element has it.
        let mut bad = el(2);
        bad.sw = 200 << 16;
        let both = |id: u32| match id {
            1 | 2 => shape(Format::Xrgb, 100, 50),
            _ => None,
        };
        assert_eq!(check(&def(&[el(1), bad]), both), Err(Fault::Invalid));
    }

    #[test]
    fn a_target_is_cut_to_the_screen() {
        let mut e = el(1);
        assert_eq!(target_bounds(&e), Some(rect(10, 20, 100, 50)));
        e.dx = -30;
        assert_eq!(target_bounds(&e), Some(rect(0, 20, 70, 50)));
        e.dx = 600;
        assert_eq!(target_bounds(&e), Some(rect(600, 20, 40, 50)));
        e.dx = 640;
        assert_eq!(target_bounds(&e), None);
        e.dx = -100;
        assert_eq!(target_bounds(&e), None);
        e.dx = 0;
        e.dh = 0;
        assert_eq!(target_bounds(&e), None);
    }

    #[test]
    fn a_rectangle_goes_through_a_copy_by_the_shift_alone() {
        let e = el(1);
        // The whole source is the whole target.
        assert_eq!(
            target_of(&e, rect(0, 0, 100, 50)),
            Some(rect(10, 20, 100, 50))
        );
        assert_eq!(target_of(&e, rect(5, 7, 10, 3)), Some(rect(15, 27, 10, 3)));
        // Past the source rectangle is no point of it.
        assert_eq!(target_of(&e, rect(100, 0, 10, 10)), None);
        // What sticks out is cut to the source's.
        assert_eq!(
            target_of(&e, rect(90, 40, 100, 100)),
            Some(rect(100, 60, 10, 10))
        );
        // A source rectangle that starts inside the window.
        let mut inner = el(1);
        inner.sx = 10 << 16;
        inner.sw = 50 << 16;
        inner.dw = 50;
        assert_eq!(
            target_of(&inner, rect(0, 0, 20, 10)),
            Some(rect(10, 20, 10, 10))
        );
        assert_eq!(target_of(&inner, rect(0, 0, 10, 10)), None);
    }

    #[test]
    fn a_rectangle_goes_through_a_scale_outward_and_the_bilinear_filter_adds_a_point() {
        let mut e = el(1);
        e.dw = 50;
        e.dh = 25;
        // Half size: points 10 to 19 of a line are 5 to 9.5, outward 5 to 10.
        assert_eq!(
            target_of(&e, rect(10, 10, 10, 10)),
            Some(rect(15, 25, 5, 5))
        );
        assert_eq!(target_of(&e, rect(11, 11, 1, 1)), Some(rect(15, 25, 1, 1)));
        e.filter = BILINEAR;
        assert_eq!(
            target_of(&e, rect(10, 10, 10, 10)),
            Some(rect(14, 24, 7, 7))
        );
        // Twice the size.
        let mut big = el(1);
        big.dw = 200;
        big.dh = 100;
        assert_eq!(target_of(&big, rect(1, 1, 2, 2)), Some(rect(12, 22, 4, 4)));
    }

    #[test]
    fn the_four_turns_and_the_reflection_carry_a_corner_where_the_header_says() {
        // A source 100 by 50 shown in a target of its own turned size.
        let mk = |orient: u32, dw: i32, dh: i32| {
            let mut e = el(1);
            e.orient = orient;
            e.dx = 0;
            e.dy = 0;
            e.dw = dw;
            e.dh = dh;
            e
        };
        let corner = |e: &Element| target_of(e, rect(0, 0, 10, 10)).unwrap();
        // The top left corner of the source goes to: the top left for no turn,
        // the top right for a quarter turn clockwise, the bottom right for a
        // half turn, the bottom left for three quarters.
        assert_eq!(corner(&mk(0, 100, 50)), rect(0, 0, 10, 10));
        assert_eq!(corner(&mk(1, 50, 100)), rect(40, 0, 10, 10));
        assert_eq!(corner(&mk(2, 100, 50)), rect(90, 40, 10, 10));
        assert_eq!(corner(&mk(3, 50, 100)), rect(0, 90, 10, 10));
        // The reflection swaps left and right of the turned image.
        assert_eq!(corner(&mk(MIRROR, 100, 50)), rect(90, 0, 10, 10));
        assert_eq!(corner(&mk(1 | MIRROR, 50, 100)), rect(0, 0, 10, 10));
        assert_eq!(corner(&mk(2 | MIRROR, 100, 50)), rect(0, 40, 10, 10));
        assert_eq!(corner(&mk(3 | MIRROR, 50, 100)), rect(40, 90, 10, 10));
        // The whole source fills the whole target whatever the turn.
        for orient in 0..8 {
            let (w, h) = if orient & 1 == 1 {
                (50, 100)
            } else {
                (100, 50)
            };
            assert_eq!(
                target_of(&mk(orient, w, h), rect(0, 0, 100, 50)),
                Some(rect(0, 0, w as u32, h as u32)),
                "orient {orient}"
            );
        }
    }

    #[test]
    fn the_damage_of_a_window_is_the_union_over_the_elements_that_show_it() {
        let mut a = el(1);
        a.dx = 0;
        a.dy = 0;
        let mut b = el(1);
        b.dx = 300;
        b.dy = 300;
        let other = el(2);
        let d = def(&[a, other, b]);
        assert_eq!(
            window_damage(&d, 1, rect(0, 0, 10, 10)),
            Some(rect(0, 0, 310, 310))
        );
        assert_eq!(
            window_damage(&d, 2, rect(0, 0, 10, 10)),
            Some(rect(10, 20, 10, 10))
        );
        assert_eq!(window_damage(&d, 3, rect(0, 0, 10, 10)), None);
        assert_eq!(window_damage(&def(&[]), 1, rect(0, 0, 10, 10)), None);
        // A mask changes the whole of what its element shows.
        let mut m = el(1);
        m.transparency = TRANSPARENCY_MASK;
        m.mask = 5;
        assert_eq!(
            window_damage(&def(&[m]), 5, rect(0, 0, 1, 1)),
            Some(rect(10, 20, 100, 50))
        );
    }

    #[test]
    fn a_scene_that_replaces_another_damages_what_came_went_or_changed() {
        let a = el(1);
        let mut b = el(2);
        b.dx = 300;
        b.dy = 300;
        let first = def(&[a, b]);
        // No scene before: the whole screen.
        assert_eq!(scene_damage(None, &first), Some(rect(0, 0, WIDTH, HEIGHT)));
        // The same scene: nothing.
        assert_eq!(scene_damage(Some(&first), &first), None);
        // One element moved: the old place and the new.
        let mut moved = b;
        moved.dx = 320;
        assert_eq!(
            scene_damage(Some(&first), &def(&[a, moved])),
            Some(rect(300, 300, 120, 50))
        );
        // One element on top went.
        assert_eq!(
            scene_damage(Some(&first), &def(&[a])),
            Some(rect(300, 300, 100, 50))
        );
        // One came.
        let mut c = el(3);
        c.dx = 0;
        c.dy = 0;
        assert_eq!(
            scene_damage(Some(&first), &def(&[a, b, c])),
            Some(rect(0, 0, 100, 50))
        );
        // The alpha of one changed: its target alone.
        let mut dim = a;
        dim.alpha = 100;
        assert_eq!(
            scene_damage(Some(&first), &def(&[dim, b])),
            Some(rect(10, 20, 100, 50))
        );
        // The background changed: everything. The active flag alone is not a
        // change of the picture.
        let green = Def::from_commit(&SceneCommit::new(ACTIVE, 0xFF00_8000, &[a, b]).unwrap());
        assert_eq!(
            scene_damage(Some(&first), &green),
            Some(rect(0, 0, WIDTH, HEIGHT))
        );
        let quiet = Def::from_commit(&SceneCommit::new(0, 0xFF00_0000, &[a, b]).unwrap());
        assert_eq!(scene_damage(Some(&first), &quiet), None);
    }

    #[test]
    fn the_fill_is_the_colour_of_the_background_over_black() {
        let d = Def::from_commit(&SceneCommit::new(0, 0xFF12_3456, &[]).unwrap());
        assert_eq!(d.fill(), 0x0012_3456);
        assert_eq!(Def::EMPTY.fill(), 0);
        let half = Def::from_commit(&SceneCommit::new(0, 0x8040_2010, &[]).unwrap());
        assert_eq!(half.fill(), 0x0040_2010);
    }

    #[test]
    fn a_body_is_parsed_in_place_to_the_scene_of_its_commit() {
        let c = SceneCommit::new(
            ACTIVE | proto_comp::ASK_COMMITTED,
            0xFF01_0203,
            &[el(1), el(2)],
        )
        .unwrap();
        let mut w = proto_wire::Writer::new();
        c.write(&mut w).unwrap();
        let mut r = proto_wire::Reader::new(w.as_bytes());
        proto_wire::Header::read(&mut r).unwrap();
        let mut place = Def::EMPTY;
        // Something else was here: the body replaces all of it.
        place.load(&SceneCommit::new(0, 5, &[el(3), el(4), el(5)]).unwrap());
        let flags = place.parse(r).unwrap();
        assert_eq!(flags, ACTIVE | proto_comp::ASK_COMMITTED);
        assert_eq!(place, Def::from_commit(&c));
        assert_eq!(place.elements().len(), 2);
        // A body out of its limits is a refusal of the protocol.
        let mut broken = el(1);
        broken.alpha = 300;
        let mut raw = proto_wire::Writer::new();
        SceneCommit::new(0, 0, &[broken])
            .unwrap()
            .write(&mut raw)
            .unwrap();
        let mut r = proto_wire::Reader::new(raw.as_bytes());
        proto_wire::Header::read(&mut r).unwrap();
        assert_eq!(
            place.parse(r),
            Err(proto_wire::Status::Unknown(proto_comp::INVALID))
        );
        place.clear();
        assert!(place.elements().is_empty() && !place.active);
    }
}
