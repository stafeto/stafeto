// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The drawing of elements, held to a reference on the host. The raster of
//! these tests (`Sampler`) draws an element as pixman does from the numbers a
//! band hands it (`Draw`): the 16.16 map of the target's points to the source's
//! applied to the centre of each point, the nearest point or the bilinear mean,
//! the global alpha and the mask mixed as the unsigned bytes of pixman mix them.
//! The reference (`expected`) knows none of it: it works each point of the
//! screen out from the element's geometry as fractions (`proto_comp::meaning`).
//! A frame made by the bands of the service, from the scene the service keeps,
//! must be the reference's, point for point.

use super::*;
use crate::prep;
use proto_comp::{
    BILINEAR, MIRROR, NEAREST, NO_WINDOW, TRANSPARENCY_ALPHA, TRANSPARENCY_MASK,
    TRANSPARENCY_SOURCE, meaning,
};

/// A window of the tests: its format, size and bytes (one buffer).
struct Win {
    format: Format,
    w: u32,
    h: u32,
    stride: u32,
    bytes: Vec<u8>,
}

/// The value of the point (`x`, `y`) of a window of the format: every point
/// differs from its neighbours, so a point that came from another place shows.
fn pattern(format: Format, x: u32, y: u32) -> u32 {
    let r = (x * 5 + y * 2 + 1) & 0xFF;
    let g = (y * 9 + x + 2) & 0xFF;
    let b = (x * y * 3 + x * 7 + y + 3) & 0xFF;
    match format {
        Format::Xrgb => r << 16 | g << 8 | b,
        Format::Argb => {
            // Premultiplied: no colour above the alpha.
            let a = ((x * 11 + y * 3 + 40) & 0xFF) | 0x20;
            a << 24 | r.min(a) << 16 | g.min(a) << 8 | b.min(a)
        }
        Format::A8 => (x * 17 + y * 29 + 5) & 0xFF,
    }
}

impl Win {
    fn new(format: Format, w: u32, h: u32) -> Win {
        let stride = format.line(w) as u32;
        let mut bytes = vec![0u8; (stride * h) as usize];
        for y in 0..h {
            for x in 0..w {
                let v = pattern(format, x, y);
                let at = (y * stride) as usize;
                match format {
                    Format::A8 => bytes[at + x as usize] = v as u8,
                    _ => bytes[at + 4 * x as usize..][..4].copy_from_slice(&v.to_le_bytes()),
                }
            }
        }
        Win {
            format,
            w,
            h,
            stride,
            bytes,
        }
    }

    /// The point as the source of a drawing: premultiplied ARGB, opaque for the
    /// window without alpha.
    fn argb(&self, x: u32, y: u32) -> u32 {
        point(&self.bytes, self.stride, self.format, x, y)
    }
}

/// The point (`x`, `y`) of bytes of a window of `format`: ARGB with the alpha
/// of the window's own (opaque for XRGB), or for A8 the alpha byte.
fn point(bytes: &[u8], stride: u32, format: Format, x: u32, y: u32) -> u32 {
    let at = (y * stride) as usize;
    match format {
        Format::A8 => u32::from(bytes[at + x as usize]),
        _ => {
            let v = u32::from_le_bytes(bytes[at + 4 * x as usize..][..4].try_into().unwrap());
            if format == Format::Xrgb {
                v | 0xFF00_0000
            } else {
                v
            }
        }
    }
}

struct Wins(Vec<Win>, Option<&'static prep::Table>);

impl Source for Wins {
    fn pixels(&self, window: usize, _: u8) -> &[u8] {
        &self.0[window].bytes
    }

    fn prepared(&self, slot: u8, image: u8) -> (&[u8], u32, (u32, u32), bool) {
        let t = self.1.expect("a table");
        let g = t.geometry(usize::from(slot));
        (
            t.image(usize::from(slot), image),
            g.stride(),
            (g.w, g.h),
            g.key.argb,
        )
    }
}

/// The work band of the raster of pixman (`pixman::WORK_W` by `pixman::WORK_H`).
const WORK_W: u32 = 640;
const WORK_H: u32 = 16;

/// The raster of the tests: the screen's bytes are XRGB8888. It has the work band of
/// the two steps of a mask and an alpha (a byte a point, 640 a line).
struct Sampler {
    work: Vec<u8>,
    /// The element and the area of the product in the band; the work band is lost
    /// (a product is refused) when `refuse`.
    made: Option<(u32, Rect)>,
    refuse: bool,
}

impl Sampler {
    fn new() -> Sampler {
        Sampler {
            work: vec![0; (WORK_W * WORK_H) as usize],
            made: None,
            refuse: false,
        }
    }
}

// The work band holds a band of a frame.
const _: () = assert!(WORK_W >= WIDTH && WORK_H >= BAND_ROWS);

fn put(fb: &mut [u8], x: u32, y: u32, v: u32) {
    let at = (y * STRIDE + x * 4) as usize;
    fb[at..at + 4].copy_from_slice(&(v & 0x00FF_FFFF).to_le_bytes());
}

fn get(fb: &[u8], x: u32, y: u32) -> u32 {
    let at = (y * STRIDE + x * 4) as usize;
    u32::from_le_bytes(fb[at..at + 4].try_into().unwrap()) & 0x00FF_FFFF
}

impl Raster for Sampler {
    fn fill(&mut self, fb: &mut [u8], r: Rect, rgb: u32) {
        for y in r.y..r.y + r.h {
            for x in r.x..r.x + r.w {
                put(fb, x, y, rgb);
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
        let e = Element {
            transparency: if over { TRANSPARENCY_SOURCE } else { 0 },
            ..Element::NONE
        };
        for y in 0..area.1 {
            for x in 0..area.0 {
                let s = point(src, stride, format, from.0 + x, from.1 + y);
                let below = get(fb, to.0 + x, to.1 + y);
                put(fb, to.0 + x, to.1 + y, meaning::mix(&e, s, 255, below));
            }
        }
    }

    fn product_made(&self) -> Option<(u32, Rect)> {
        self.made
    }

    fn product(
        &mut self,
        owner: (u32, Rect),
        mask: &Surface<'_>,
        at: (u32, u32),
        alpha: u8,
        size: (u32, u32),
    ) -> bool {
        if self.refuse {
            self.made = None;
            return false;
        }
        self.made = Some(owner);
        for y in 0..size.1 {
            for x in 0..size.0 {
                let m = point(mask.bytes, mask.stride, Format::A8, at.0 + x, at.1 + y);
                self.work[(y * WORK_W + x) as usize] = meaning::mul(m, u32::from(alpha)) as u8;
            }
        }
        true
    }

    fn element(&mut self, fb: &mut [u8], d: &Draw<'_>) {
        let e = Element {
            filter: d.filter,
            // The alpha is in the work band when there is one.
            transparency: if d.work {
                d.transparency & !TRANSPARENCY_ALPHA
            } else {
                d.transparency
            },
            alpha: u32::from(d.alpha),
            ..Element::NONE
        };
        for y in 0..d.area.h {
            for x in 0..d.area.w {
                let (tx, ty) = (d.area.x + x, d.area.y + y);
                let fetch =
                    |sx: u32, sy: u32| point(d.src.bytes, d.src.stride, d.src.format, sx, sy);
                let s = match d.matrix {
                    Some([a, b, c, dd, ee, f]) => {
                        let (xc, yc) = (
                            (i64::from(tx) << 16) + 0x8000,
                            (i64::from(ty) << 16) + 0x8000,
                        );
                        let u = ((i64::from(a) * xc + i64::from(b) * yc) >> 16) + i64::from(c);
                        let v = ((i64::from(dd) * xc + i64::from(ee) * yc) >> 16) + i64::from(f);
                        meaning::at(d.filter, (u, v), d.src.size, fetch)
                    }
                    None => fetch(d.from.0 + x, d.from.1 + y),
                };
                let m = match d.mask {
                    _ if d.work => u32::from(self.work[(y * WORK_W + x) as usize]),
                    Some((m, at)) => point(m.bytes, m.stride, Format::A8, at.0 + x, at.1 + y),
                    None => 255,
                };
                put(fb, tx, ty, meaning::mix(&e, s, m, get(fb, tx, ty)));
            }
        }
    }
}

/// A scene of windows (place k has the id of the window the service made) and
/// what it shows.
struct Rig {
    scene: Scene,
    wins: Wins,
}

impl Rig {
    /// Windows of the formats and sizes, each with one buffer posted.
    fn new(specs: &[(Format, u32, u32)]) -> Rig {
        let mut scene = Scene::new();
        scene.set_manager(true);
        let mut wins = Vec::new();
        for (k, &(format, w, h)) in specs.iter().enumerate() {
            let r = Rect { x: 0, y: 0, w, h };
            let i = scene
                .create(k as u64 + 1, 1 + (k / PER_CONTEXT) as u64, r, false, 0)
                .unwrap();
            scene.set_format(i, format);
            let win = Win::new(format, w, h);
            scene.attach(i, 1, win.stride).unwrap();
            scene.post(i, 0, &[]).unwrap();
            wins.push(win);
        }
        Rig {
            scene,
            wins: Wins(wins, None),
        }
    }

    fn id(&self, place: usize) -> u32 {
        self.scene.window(place).unwrap().id
    }

    /// An element of window `place` (its whole, or `source` of it in 16.16
    /// points) on the target (`dx`, `dy`, `dw`, `dh`).
    fn element(&self, place: usize, source: [i32; 4], target: [i32; 4]) -> Element {
        Element {
            source: self.id(place),
            mask: NO_WINDOW,
            sx: source[0],
            sy: source[1],
            sw: source[2],
            sh: source[3],
            dx: target[0],
            dy: target[1],
            dw: target[2],
            dh: target[3],
            orient: 0,
            filter: NEAREST,
            transparency: 0,
            alpha: 255,
        }
    }

    /// An element of the whole window `place`, scaled to `target`.
    fn whole(&self, place: usize, target: [i32; 4]) -> Element {
        let w = &self.wins.0[place];
        self.element(
            place,
            [0, 0, (w.w as i32) << 16, (w.h as i32) << 16],
            target,
        )
    }

    /// The frame the service makes of the scene `els` over `bg` (its bands, by
    /// `tile`, as the service draws them): the screen's bytes.
    fn frame(&mut self, els: &[Element], bg: u32) -> Vec<u8> {
        self.scene
            .scene_commit(&SceneCommit::new(proto_comp::ACTIVE, bg, els).unwrap())
            .unwrap();
        let d = self.scene.begin().expect("a frame");
        let mut fb = vec![0xEE; (STRIDE * HEIGHT) as usize];
        let mut at = Band {
            row: d.y,
            col: 0,
            pass: 0,
        };
        let mut sampler = Sampler::new();
        while at.row < d.y + d.h {
            at = compose(&self.scene, d, at, &mut fb, &self.wins, &mut sampler);
        }
        self.scene.end(true);
        fb
    }

    /// The screen the elements mean, point by point: no band, no matrix.
    fn expected(&self, els: &[Element], bg: u32) -> Vec<u32> {
        let mut screen = vec![bg & 0x00FF_FFFF; (WIDTH * HEIGHT) as usize];
        for e in els {
            if meaning::empty(e) {
                continue;
            }
            let Some(place) = self.scene.place_of(e.source) else {
                continue;
            };
            let src = &self.wins.0[place];
            let mask = if e.transparency & TRANSPARENCY_MASK != 0 {
                let Some(mp) = self.scene.place_of(e.mask) else {
                    continue;
                };
                let m = &self.wins.0[mp];
                if m.format != Format::A8
                    || i64::from(m.w) != i64::from(e.dw)
                    || i64::from(m.h) != i64::from(e.dh)
                {
                    continue;
                }
                Some(m)
            } else {
                None
            };
            for y in 0..HEIGHT as i32 {
                for x in 0..WIDTH as i32 {
                    let Some(s) = meaning::sample(e, x, y, (src.w, src.h), |u, v| src.argb(u, v))
                    else {
                        continue;
                    };
                    let m = mask.map_or(255, |m| m.argb((x - e.dx) as u32, (y - e.dy) as u32));
                    let at = (y as u32 * WIDTH + x as u32) as usize;
                    screen[at] = meaning::mix(e, s, m, screen[at]);
                }
            }
        }
        screen
    }

    /// The frame is the reference's; the first points that differ are said.
    fn matches(&mut self, els: &[Element], bg: u32) {
        let fb = self.frame(els, bg);
        let want = self.expected(els, bg);
        let mut wrong = Vec::new();
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                let (got, want) = (get(&fb, x, y), want[(y * WIDTH + x) as usize]);
                if got != want && wrong.len() < 5 {
                    wrong.push((x, y, got, want));
                }
            }
        }
        assert!(wrong.is_empty(), "points (x, y, got, want): {wrong:x?}");
    }
}

const XRGB: Format = Format::Xrgb;
const ARGB: Format = Format::Argb;
const A8: Format = Format::A8;
const BG: u32 = 0xFF10_2030;

/// The orientations of an element: the four turns, each with and without the
/// reflection.
const ORIENTS: [u32; 8] = [0, 1, 2, 3, MIRROR, 1 | MIRROR, 2 | MIRROR, 3 | MIRROR];

fn turned(e: Element, orient: u32, dw: i32, dh: i32) -> Element {
    // A quarter turn swaps the sides of the target.
    let (dw, dh) = if orient & 1 != 0 { (dh, dw) } else { (dw, dh) };
    Element {
        orient,
        dw,
        dh,
        ..e
    }
}

// ---------------------------------------------------------------- geometry

#[test]
fn every_orientation_of_a_copy_at_the_scale_of_one_is_the_reference() {
    for orient in ORIENTS {
        let mut rig = Rig::new(&[(XRGB, 64, 40)]);
        let e = turned(rig.whole(0, [30, 20, 64, 40]), orient, 64, 40);
        rig.matches(&[e], BG);
    }
}

#[test]
fn a_stretch_up_and_down_by_two_of_every_orientation_is_the_reference() {
    for orient in ORIENTS {
        for (dw, dh) in [(128, 80), (32, 20), (128, 40), (64, 20)] {
            let mut rig = Rig::new(&[(XRGB, 64, 40)]);
            let e = turned(rig.whole(0, [100, 50, 64, 40]), orient, dw, dh);
            rig.matches(&[e], BG);
        }
    }
}

#[test]
fn a_part_of_a_window_with_a_fraction_of_a_point_to_its_corner_is_the_reference() {
    for orient in ORIENTS {
        let mut rig = Rig::new(&[(XRGB, 64, 40)]);
        // 5.5 and 3.25 points in, 20 by 10 points on, stretched by two.
        let e = rig.element(
            0,
            [5 << 16 | 0x8000, 3 << 16 | 0x4000, 20 << 16, 10 << 16],
            [200, 100, 40, 20],
        );
        rig.matches(&[turned(e, orient, 40, 20)], BG);
    }
}

#[test]
fn an_element_cut_by_the_edges_of_the_screen_is_the_reference() {
    for orient in ORIENTS {
        for (x, y) in [(-20, -10), (620, 380), (-40, 390), (10, -30)] {
            let mut rig = Rig::new(&[(XRGB, 64, 40)]);
            let e = turned(rig.whole(0, [x, y, 128, 80]), orient, 128, 80);
            rig.matches(&[e], BG);
        }
    }
}

#[test]
fn a_target_far_from_the_origin_of_the_screen_is_the_reference() {
    let mut rig = Rig::new(&[(XRGB, 20, 10)]);
    let e = turned(rig.whole(0, [500, 300, 120, 80]), 1, 40, 60);
    rig.matches(&[e], BG);
}

#[test]
fn a_stretch_that_is_not_a_fraction_of_sixteen_bits_is_within_a_point_of_the_reference() {
    // A ratio like 3 to 7: the step is rounded to 16.16, which moves a few
    // points of the nearest filter that lie within a unit of a border. The
    // points that differ are few and their source is a neighbour.
    let mut rig = Rig::new(&[(XRGB, 63, 41)]);
    let e = rig.whole(0, [100, 60, 147, 97]);
    let fb = rig.frame(&[e], BG);
    let want = rig.expected(&[e], BG);
    let mut differ = 0;
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            differ += usize::from(get(&fb, x, y) != want[(y * WIDTH + x) as usize]);
        }
    }
    assert!(differ < 147 * 97 / 100, "{differ} points differ");
}

#[test]
fn the_matrix_is_within_the_rounding_of_its_steps_of_the_exact_map() {
    // For many geometries, the matrix puts the centre of each target point
    // within a unit of 16.16 for each point of the target's side of the exact
    // 16.16 coordinates (the rounding of the steps to the nearest).
    let sizes = [(1, 1), (7, 3), (64, 40), (63, 41), (200, 100), (640, 400)];
    for orient in ORIENTS {
        for &(sw, sh) in &sizes {
            for &(dw, dh) in &sizes {
                for (sx, sy) in [(0, 0), (3 << 16 | 0x1234, 5 << 16)] {
                    let e = Element {
                        source: 0,
                        mask: NO_WINDOW,
                        sx,
                        sy,
                        sw: sw << 16,
                        sh: sh << 16,
                        dx: -17,
                        dy: 33,
                        dw,
                        dh,
                        orient,
                        filter: NEAREST,
                        transparency: 0,
                        alpha: 255,
                    };
                    let m = elements::matrix(&e);
                    let bound = i64::from(dw.max(dh)) / 2 + 3;
                    for (x, y) in [
                        (e.dx, e.dy),
                        (e.dx + dw - 1, e.dy),
                        (e.dx, e.dy + dh - 1),
                        (e.dx + dw - 1, e.dy + dh - 1),
                        (e.dx + dw / 2, e.dy + dh / 3),
                    ] {
                        let (xc, yc) =
                            ((i64::from(x) << 16) + 0x8000, (i64::from(y) << 16) + 0x8000);
                        let u =
                            ((i64::from(m[0]) * xc + i64::from(m[1]) * yc) >> 16) + i64::from(m[2]);
                        let v =
                            ((i64::from(m[3]) * xc + i64::from(m[4]) * yc) >> 16) + i64::from(m[5]);
                        let (eu, ev) = meaning::source_at(&e, x, y).unwrap();
                        assert!(
                            (u - eu).abs() <= bound && (v - ev).abs() <= bound,
                            "{orient} {sw}x{sh} -> {dw}x{dh} at ({x}, {y}): ({u}, {v}) against ({eu}, {ev})"
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------- filters

#[test]
fn the_bilinear_filter_at_every_orientation_and_scale_is_the_reference() {
    for orient in ORIENTS {
        for (dw, dh) in [(128, 80), (32, 20), (256, 160), (64, 40)] {
            let mut rig = Rig::new(&[(XRGB, 64, 40)]);
            let mut e = turned(rig.whole(0, [60, 40, 64, 40]), orient, dw, dh);
            e.filter = BILINEAR;
            rig.matches(&[e], BG);
        }
    }
}

#[test]
fn the_bilinear_filter_of_a_window_with_an_alpha_is_the_reference() {
    let mut rig = Rig::new(&[(ARGB, 64, 40)]);
    let mut e = rig.whole(0, [60, 40, 128, 80]);
    e.filter = BILINEAR;
    e.transparency = TRANSPARENCY_SOURCE;
    rig.matches(&[e], BG);
}

// ---------------------------------------------------------- transparency

#[test]
fn each_transparency_of_a_plain_element_is_the_reference() {
    for format in [XRGB, ARGB] {
        for t in [
            0,
            TRANSPARENCY_SOURCE,
            TRANSPARENCY_ALPHA,
            TRANSPARENCY_ALPHA | TRANSPARENCY_SOURCE,
        ] {
            for alpha in [0, 1, 77, 128, 254, 255] {
                let mut rig = Rig::new(&[(format, 64, 40)]);
                let mut e = rig.whole(0, [70, 30, 64, 40]);
                e.transparency = t;
                e.alpha = alpha;
                rig.matches(&[e], BG);
            }
        }
    }
}

#[test]
fn each_transparency_of_a_stretched_and_turned_element_is_the_reference() {
    for format in [XRGB, ARGB] {
        for t in [
            0,
            TRANSPARENCY_SOURCE,
            TRANSPARENCY_ALPHA,
            TRANSPARENCY_ALPHA | TRANSPARENCY_SOURCE,
        ] {
            for (orient, filter) in [(1, NEAREST), (2 | MIRROR, BILINEAR), (0, BILINEAR)] {
                let mut rig = Rig::new(&[(format, 64, 40)]);
                let mut e = turned(rig.whole(0, [70, 30, 64, 40]), orient, 128, 80);
                e.transparency = t;
                e.alpha = 150;
                e.filter = filter;
                rig.matches(&[e], BG);
            }
        }
    }
}

#[test]
fn a_mask_with_and_without_a_global_alpha_is_the_reference() {
    for t in [TRANSPARENCY_MASK, TRANSPARENCY_MASK | TRANSPARENCY_ALPHA] {
        for format in [XRGB, ARGB] {
            for (orient, dw, dh, filter) in [
                (0, 64, 40, NEAREST),
                (0, 128, 80, NEAREST),
                (1, 80, 128, BILINEAR),
                (3 | MIRROR, 20, 32, NEAREST),
            ] {
                let (dw, dh) = (dw, dh);
                // The mask is the size of the target rectangle.
                let mut rig = Rig::new(&[(format, 64, 40), (A8, dw as u32, dh as u32)]);
                let mut e = turned(rig.whole(0, [90, 50, 64, 40]), orient, 64, 40);
                // `turned` swaps for a quarter turn: set the target by hand.
                e.dw = dw;
                e.dh = dh;
                e.filter = filter;
                e.transparency = t;
                e.alpha = 200;
                e.mask = rig.id(1);
                rig.matches(&[e], BG);
            }
        }
    }
}

#[test]
fn a_masked_element_cut_by_the_screen_takes_its_mask_from_the_place_it_is_at() {
    for (x, y) in [(-30, -20), (600, 370), (-10, 380)] {
        let mut rig = Rig::new(&[(XRGB, 64, 40), (A8, 64, 40)]);
        let mut e = rig.whole(0, [x, y, 64, 40]);
        e.transparency = TRANSPARENCY_MASK;
        e.mask = rig.id(1);
        rig.matches(&[e], BG);
    }
}

#[test]
fn a_mask_of_a_wrong_size_or_format_is_refused_and_a_missing_one_draws_nothing() {
    for (specs, mask) in [
        (vec![(XRGB, 64, 40), (A8, 63, 40)], 1),
        (vec![(XRGB, 64, 40), (A8, 64, 41)], 1),
        (vec![(XRGB, 64, 40), (XRGB, 64, 40)], 1),
    ] {
        let mut rig = Rig::new(&specs);
        let mut e = rig.whole(0, [70, 30, 64, 40]);
        e.transparency = TRANSPARENCY_MASK;
        e.mask = rig.id(mask);
        let c = SceneCommit::new(proto_comp::ACTIVE, BG, &[e]).unwrap();
        assert_eq!(rig.scene.scene_commit(&c), Err(Refusal::Invalid));
    }
    // The mask the element names is no window: nothing is drawn (the reference
    // says so too).
    let mut rig = Rig::new(&[(XRGB, 64, 40)]);
    let mut e = rig.whole(0, [70, 30, 64, 40]);
    e.transparency = TRANSPARENCY_MASK;
    let fb = rig.frame(&[e], BG);
    assert!(
        (0..HEIGHT).all(|y| (0..WIDTH).all(|x| get(&fb, x, y) == BG & 0xFF_FFFF)),
        "something was drawn"
    );
    assert_eq!(
        rig.expected(&[e], BG)[(30 * WIDTH + 70) as usize],
        BG & 0xFF_FFFF
    );
}

#[test]
fn elements_lie_over_each_other_in_their_order() {
    let mut rig = Rig::new(&[(XRGB, 64, 40), (ARGB, 40, 30), (A8, 60, 30), (XRGB, 30, 30)]);
    let below = rig.whole(0, [20, 20, 128, 80]);
    let mut half = rig.whole(1, [60, 40, 80, 60]);
    half.transparency = TRANSPARENCY_SOURCE | TRANSPARENCY_ALPHA;
    half.alpha = 160;
    half.orient = 2;
    let mut masked = rig.whole(3, [90, 60, 60, 30]);
    masked.transparency = TRANSPARENCY_MASK;
    masked.mask = rig.id(2);
    masked.filter = BILINEAR;
    let opaque = turned(rig.whole(3, [150, 100, 60, 60]), 1, 60, 60);
    rig.matches(&[below, half, masked, opaque], BG);
    // The opaque one covers a band whole: the ones under it are not drawn there.
    let mut rig = Rig::new(&[(XRGB, 64, 40), (ARGB, 40, 30)]);
    let under = rig.whole(1, [0, 0, 640, 400]);
    let cover = rig.whole(0, [0, 0, 640, 400]);
    rig.matches(&[under, cover], BG);
}

// ------------------------------------------------------------- the classes

#[test]
fn an_element_is_charged_by_its_geometry_and_its_mixing() {
    let rig = Rig::new(&[(ARGB, 64, 40)]);
    let plain = rig.whole(0, [0, 0, 64, 40]);
    let with = |f: fn(&mut Element)| {
        let mut e = plain;
        f(&mut e);
        elements::classes(&e, true)
    };
    use elements::Class::*;
    assert_eq!(elements::classes(&plain, true), (Copy, None));
    assert_eq!(with(|e| e.transparency = TRANSPARENCY_SOURCE), (Over, None));
    assert_eq!(with(|e| e.dx = -30), (Copy, None));
    // A scale by a fraction (no turn, no reflection) is the class of the fast paths.
    assert_eq!(with(|e| e.dw = 128), (FastNearestCopy, None));
    assert_eq!(with(|e| e.dh = 100), (FastNearestCopy, None));
    assert_eq!(with(|e| e.sx = 0x8000), (FastNearestCopy, None));
    assert_eq!(with(|e| e.orient = MIRROR), (ScaleNearestCopy, None));
    assert_eq!(with(|e| e.orient = 2), (ScaleNearestCopy, None));
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.filter = BILINEAR
        }),
        (FastBilinearCopy, None)
    );
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.transparency = TRANSPARENCY_SOURCE
        }),
        (FastNearestOver, None)
    );
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.transparency = TRANSPARENCY_SOURCE;
            e.filter = BILINEAR
        }),
        (FastBilinearOver, None)
    );
    // A quarter turn of the same size: its own path in pixman.
    assert_eq!(
        with(|e| {
            e.orient = 1;
            e.dw = 40;
            e.dh = 64;
        }),
        (Rotate90, None)
    );
    assert_eq!(
        with(|e| {
            e.orient = 1 | MIRROR;
            e.dw = 40;
            e.dh = 64;
        }),
        (ScaleNearestCopy, None)
    );
    // A plain element with an alpha or a mask is one operation.
    assert_eq!(with(|e| e.transparency = TRANSPARENCY_ALPHA), (Alpha, None));
    assert_eq!(
        with(|e| e.transparency = TRANSPARENCY_ALPHA | TRANSPARENCY_SOURCE),
        (Alpha, None)
    );
    assert_eq!(with(|e| e.transparency = TRANSPARENCY_MASK), (Mask, None));
    assert_eq!(
        with(|e| e.transparency = TRANSPARENCY_MASK | TRANSPARENCY_ALPHA),
        (MaskAlpha, None)
    );
    // A scaled one with a mix is one operation of its own.
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.transparency = TRANSPARENCY_MASK;
        }),
        (FastNearestMaskOpaque, None)
    );
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.transparency = TRANSPARENCY_MASK | TRANSPARENCY_SOURCE;
        }),
        (FastNearestMask, None)
    );
    // The same from a window with no alpha channel: the source is opaque.
    let xrgb = |t: u32| {
        let mut e = plain;
        e.dw = 128;
        e.transparency = t;
        elements::classes(&e, false)
    };
    // A laying over of an opaque source is a copy to pixman: its path and its key.
    assert_eq!(xrgb(TRANSPARENCY_SOURCE), (FastNearestCopy, None));
    let argb_over = {
        let mut e = plain;
        e.dw = 128;
        e.transparency = TRANSPARENCY_SOURCE;
        elements::classes(&e, true)
    };
    assert_eq!(argb_over, (FastNearestOver, None));
    assert_eq!(
        xrgb(TRANSPARENCY_MASK | TRANSPARENCY_SOURCE),
        (FastNearestMaskOpaque, None)
    );
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.filter = BILINEAR;
            e.transparency = TRANSPARENCY_ALPHA | TRANSPARENCY_SOURCE;
        }),
        (FastBilinearAlpha, None)
    );
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.filter = BILINEAR;
            e.transparency = TRANSPARENCY_MASK | TRANSPARENCY_ALPHA | TRANSPARENCY_SOURCE;
        }),
        (FastBilinearMaskAlpha, None)
    );
    // The others with both are priced as the general class: a layer of the fast
    // one would not fit a step with the miss of the lookup.
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.filter = BILINEAR;
            e.transparency = TRANSPARENCY_MASK | TRANSPARENCY_ALPHA;
        }),
        (ScaleBilinearOver, Some(MaskAlpha))
    );
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.transparency = TRANSPARENCY_MASK | TRANSPARENCY_ALPHA | TRANSPARENCY_SOURCE;
        }),
        (ScaleNearestOver, Some(MaskAlpha))
    );
    // A turned or reflected one pays for the stretch and for the extra.
    assert_eq!(
        with(|e| {
            e.orient = 2;
            e.dw = 128;
            e.transparency = TRANSPARENCY_MASK;
        }),
        (ScaleNearestOver, Some(Mask))
    );
    assert_eq!(
        with(|e| {
            e.orient = 3;
            e.dw = 40;
            e.dh = 64;
            e.filter = BILINEAR;
            e.transparency = TRANSPARENCY_ALPHA;
        }),
        (ScaleBilinearOver, Some(Alpha))
    );
}

#[test]
fn the_fast_class_is_the_diagonal_matrix_with_positive_steps_that_the_element_makes() {
    // Every orientation and reflection, a stretch up and down on each axis, and
    // the source's corner at a fraction: the class is the fast one exactly when
    // `elements::matrix` is a diagonal with positive steps, and no turn or
    // reflection is.
    let rig = Rig::new(&[(ARGB, 64, 40)]);
    let sizes = [
        (64, 40),
        (128, 80),
        (30, 17),
        (64, 80),
        (7, 40),
        (40, 64),
        (1, 1),
    ];
    let (mut fast, mut general) = (0, 0);
    for orient in 0..8 {
        for &(dw, dh) in &sizes {
            for corner in [0, 0x8000] {
                let mut e = rig.whole(0, [3, 4, dw, dh]);
                e.orient = orient;
                e.sx = corner;
                if elements::is_plain(&e) {
                    continue;
                }
                let m = elements::matrix(&e);
                let diagonal = m[1] == 0 && m[3] == 0 && m[0] > 0 && m[4] > 0;
                let (class, _) = elements::classes(&e, true);
                let is_fast = class.row() >= elements::Class::FastNearestCopy.row();
                assert_eq!(is_fast, diagonal, "orient {orient} to {dw} by {dh}: {m:?}");
                if diagonal {
                    // No turn and no reflection: the orientation is 0.
                    assert_eq!(orient, 0, "{m:?}");
                    fast += 1;
                } else {
                    general += 1;
                }
            }
        }
    }
    assert!(
        fast >= 10 && general >= 40,
        "{fast} fast, {general} general"
    );
}

/// The dearest element of the tests: a mask and an alpha over the target
/// 128 by 80 with the bilinear mean, the source (64 by 40) twice as large
/// (`k` of four windows, the mask `k` of four A8 windows of that size).
fn dear(rig: &Rig, k: usize, at: (i32, i32)) -> Element {
    let mut e = rig.whole(k % 4, [at.0, at.1, 128, 80]);
    e.filter = BILINEAR;
    e.transparency = TRANSPARENCY_MASK | TRANSPARENCY_ALPHA;
    e.mask = rig.id(4 + k % 4);
    e.alpha = 100 + 10 * k as u32;
    e
}

fn dear_rig() -> Rig {
    let mut specs = vec![(XRGB, 64, 40); 4];
    specs.extend(vec![(A8, 128, 80); 4]);
    Rig::new(&specs)
}

#[test]
fn a_scene_of_dear_elements_is_taken_and_drawn_in_groups_as_the_reference_has_it() {
    let mut rig = dear_rig();
    // Six of the dearest over one place and across it: a band cannot hold the
    // calls of all of them, so a place is drawn in several steps.
    let mut els: Vec<Element> = (0..6)
        .map(|k| dear(&rig, k, (40 + 12 * k as i32, 30 + 7 * k as i32)))
        .collect();
    let mut over = rig.whole(1, [60, 50, 128, 80]);
    over.transparency = TRANSPARENCY_ALPHA | TRANSPARENCY_SOURCE;
    over.alpha = 150;
    over.orient = 2;
    els.push(over);
    rig.matches(&els, BG);
    // And the groups are what the plan says: more than one, none past the
    // calls of a group unless it is one element.
    let d = rig.scene.working().copied().unwrap();
    let plan = rig.scene.passes(&d, Rect::SCREEN);
    assert!(plan.groups >= 2, "{} groups", plan.groups);
    for g in 0..plan.groups {
        let n = (0..els.len())
            .filter(|&k| plan.group_of(k) == Some(g))
            .count();
        assert!(
            n == 1 || plan.cost[g].calls <= GROUP_CALLS,
            "group {g}: {n} elements"
        );
    }
}

/// The dearest element over the whole screen: a bilinear stretch with a mask and an
/// alpha, the mask a window of the screen's size (four sources, four masks).
fn dear_full(rig: &Rig, k: usize) -> Element {
    let mut e = rig.whole(k % 4, [0, 0, 640, 400]);
    e.filter = BILINEAR;
    e.transparency = TRANSPARENCY_MASK | TRANSPARENCY_ALPHA;
    e.mask = rig.id(4 + k % 4);
    e.alpha = 100 + 5 * k as u32;
    e
}

#[test]
fn sixteen_of_the_dearest_over_the_screen_make_steps_under_the_gate_by_the_model() {
    let mut specs = vec![(XRGB, 64, 40); 4];
    specs.extend(vec![(A8, 640, 400); 4]);
    let mut rig = Rig::new(&specs);
    let els: Vec<Element> = (0..MAX_ELEMENTS).map(|k| dear_full(&rig, k)).collect();
    assert_eq!(els.len(), 16);
    rig.scene.pointer_to(0, 0);
    rig.scene
        .scene_commit(&SceneCommit::new(proto_comp::ACTIVE, BG, &els).unwrap())
        .unwrap();
    rig.scene.begin().expect("a frame");
    // The smallest place of a frame, one point, where every element lies over the
    // others, the pointer's picture on them and the black under them: every step of
    // it, the black's included, is under the gate by the model with the 1 080
    // ticks a step spends around the band.
    let d = Rect {
        x: 0,
        y: 0,
        w: 1,
        h: 1,
    };
    let mut at = Band::default();
    let mut fb = vec![0u8; (STRIDE * HEIGHT) as usize];
    let (mut steps, mut worst) = (0, 0);
    let mut made = None;
    while at.row < d.y + d.h {
        let mut model = StepCost {
            elements: els.len() as u32,
            made,
            ..StepCost::default()
        };
        at = compose(&rig.scene, d, at, &mut fb, &rig.wins, &mut model);
        made = model.made;
        worst = worst.max(model.ticks());
        steps += 1;
    }
    rig.scene.end(true);
    assert!(
        worst <= u64::from(BAND_GATE - 1_080),
        "a step costs {worst} by the model"
    );
    // One step for each element, the black's apart, and the pointer's; the
    // elements with a mask and an alpha that are stretched are two steps each
    // (16 of them): 34.
    assert_eq!(steps, 34, "{steps} steps, worst {worst}");
}

/// Walks the frame of the scene committed in `rig` over `d` as the service does,
/// each step through a `StepCost` raster, and checks the key of the model: every
/// layer a step draws is in the price of its group (the calls, the lines and the
/// points the band's size was worked out from), so a step costs no more than
/// BAND_TICKS by the model (the least band, one point, may). The bands of a group
/// lie in its rectangle. Returns the steps, in all and of each group.
fn walk_priced(rig: &Rig, d: Rect) -> (u32, Vec<u32>) {
    let def = rig.scene.working().copied().unwrap();
    let plan = rig.scene.passes(&def, d);
    let mut each = vec![0u32; plan.groups];
    let mut at = Band::default();
    let mut fb = vec![0u8; (STRIDE * HEIGHT) as usize];
    let mut steps = 0;
    let mut first_step = 0;
    let mut made = None;
    while at.row < d.y + d.h {
        let g = (at.pass & !PHASE) as usize;
        let second = at.pass & PHASE != 0;
        let r = plan.cost[g].rect;
        let (w, h) = plan.band(g);
        let mut model = StepCost {
            elements: plan.elements,
            made,
            ..StepCost::default()
        };
        let next = compose(&rig.scene, d, at, &mut fb, &rig.wins, &mut model);
        made = model.made;
        let ticks = model.ticks() + u64::from(SCENE_STEP);
        let limit = if (w, h) == (1, 1) {
            u64::from(BAND_GATE - 1_080)
        } else {
            u64::from(BAND_TICKS)
        };
        assert!(
            ticks <= limit,
            "step {steps} of group {g} ({w} x {h}) costs {ticks} by the model, over {limit}"
        );
        assert!(
            model.layers as usize
                <= plan.members_of(g) + usize::from(plan.pointer_group() == Some(g)),
            "step {steps} of group {g} draws {} layers",
            model.layers
        );
        assert!(
            at.row.max(r.y) >= r.y && at.row.max(r.y) < r.y + r.h,
            "step {steps} of group {g} starts at row {} outside {r:?}",
            at.row
        );
        // The first step of two is no dearer than the second: the band the second
        // allows holds the first.
        if plan.is_two_step(g) {
            assert_eq!(plan.members_of(g), 1, "a group of two steps is one element");
            if second {
                assert!(
                    ticks >= first_step,
                    "step {steps} of group {g}: {ticks} < {first_step}"
                );
            } else {
                first_step = ticks;
            }
        }
        each[g] += 1;
        steps += 1;
        at = next;
    }
    (steps, each)
}

#[test]
fn every_layer_a_step_draws_is_in_the_price_of_its_step() {
    let mut specs = vec![(XRGB, 64, 40), (ARGB, 40, 30), (XRGB, 160, 100)];
    specs.extend(vec![(A8, 640, 400), (A8, 300, 200), (A8, 60, 40)]);
    let mut rig = Rig::new(&specs);
    let mut els = Vec::new();
    // A transparent window over the screen, a turn, a bilinear stretch with a
    // mask and an alpha, a mask alone, a nearest stretch laid over, a plain copy
    // and a small bilinear one: wide and narrow, near and far apart.
    let mut a = rig.whole(2, [0, 0, 640, 400]);
    a.transparency = TRANSPARENCY_ALPHA;
    a.alpha = 120;
    els.push(a);
    let mut r = rig.whole(0, [100, 50, 100, 64]);
    r.orient = 1;
    els.push(r);
    let mut b = rig.whole(2, [300, 150, 300, 200]);
    b.filter = BILINEAR;
    b.transparency = TRANSPARENCY_MASK | TRANSPARENCY_ALPHA;
    b.mask = rig.id(4);
    b.alpha = 200;
    els.push(b);
    let mut m = rig.whole(0, [20, 300, 60, 40]);
    m.transparency = TRANSPARENCY_MASK;
    m.mask = rig.id(5);
    els.push(m);
    let mut o = rig.whole(1, [400, 20, 120, 90]);
    o.transparency = TRANSPARENCY_SOURCE;
    els.push(o);
    els.push(rig.whole(0, [500, 300, 64, 40]));
    let mut t = rig.whole(1, [10, 10, 20, 15]);
    t.filter = BILINEAR;
    t.transparency = TRANSPARENCY_SOURCE;
    els.push(t);
    rig.scene.pointer_to(310, 160);
    rig.scene
        .scene_commit(&SceneCommit::new(proto_comp::ACTIVE, BG, &els).unwrap())
        .unwrap();
    // One frame is taken; the walks are over damages of the test's own.
    rig.scene.begin().expect("a frame");
    for d in [
        Rect::SCREEN,
        Rect {
            x: 90,
            y: 40,
            w: 300,
            h: 140,
        },
        Rect {
            x: 305,
            y: 155,
            w: 7,
            h: 9,
        },
    ] {
        let (steps, each) = walk_priced(&rig, d);
        assert!(steps as usize >= each.len(), "{steps} steps over {d:?}");
    }
    rig.scene.end(true);
}

#[test]
fn a_group_draws_in_bands_over_the_rectangle_of_its_elements_only() {
    // The scene of the plan: a window over the screen with a global alpha, a turn,
    // and a bilinear stretch with a mask over a part of the screen. The dear
    // element's group walks 320 by 200, no more (the band of the dearest layer
    // took the whole screen's width before: 298 000 steps).
    let mut rig = Rig::new(&[
        (XRGB, 640, 400),
        (XRGB, 200, 100),
        (ARGB, 160, 100),
        (A8, 320, 200),
    ]);
    let mut full = rig.whole(0, [0, 0, 640, 400]);
    full.transparency = TRANSPARENCY_ALPHA;
    full.alpha = 128;
    let mut turn = rig.whole(1, [100, 50, 200, 100]);
    turn.orient = 2;
    let mut dear = rig.whole(2, [300, 150, 320, 200]);
    dear.filter = BILINEAR;
    dear.transparency = TRANSPARENCY_MASK | TRANSPARENCY_SOURCE;
    dear.mask = rig.id(3);
    let els = [full, turn, dear];
    rig.scene
        .scene_commit(&SceneCommit::new(proto_comp::ACTIVE, BG, &els).unwrap())
        .unwrap();
    let d = rig.scene.begin().expect("a frame");
    let def = rig.scene.working().copied().unwrap();
    let plan = rig.scene.passes(&def, d);
    // The black, three elements (each dear enough to be alone), no pointer.
    assert_eq!(plan.groups, 4);
    assert!(plan.is_black(0));
    let g = plan.group_of(2).unwrap();
    assert_eq!(
        (plan.cost[g].rect.w, plan.cost[g].rect.h),
        (320, 200),
        "{:?}",
        plan.cost[g].rect
    );
    let (steps, each) = walk_priced(&rig, d);
    rig.scene.end(true);
    assert_eq!(each[g] as usize, {
        let (w, h) = plan.band(g);
        (320usize.div_ceil(w as usize)) * (200usize.div_ceil(h as usize))
    });
    assert!(steps < 6_000, "{steps} steps, {each:?}");
}

#[test]
fn a_step_of_a_scene_with_a_pointer_draws_the_pointer_in_the_last_step_of_a_place() {
    let mut rig = dear_rig();
    let els: Vec<Element> = (0..4).map(|k| dear(&rig, k, (0, 0))).collect();
    rig.scene.pointer_to(10, 10);
    let fb = rig.frame(&els, BG);
    // The pointer's picture is over the elements: the point it covers is not
    // what the elements alone make.
    let plain = {
        let mut rig = dear_rig();
        rig.frame(&els, BG)
    };
    assert_ne!(get(&fb, 12, 12), get(&plain, 12, 12));
}

/// What the model charges for the calls of a step, from what the raster is asked.
#[derive(Default)]
struct StepCost {
    calls: u32,
    centi: u64,
    layers: u32,
    /// The elements of the scene that show something over the damage.
    elements: u32,
    /// The element and the area of the last product.
    made: Option<(u32, Rect)>,
}

impl StepCost {
    fn add(&mut self, p: Price, area: (u32, u32)) {
        self.calls += p.call;
        self.centi += u64::from(p.row) * u64::from(area.1)
            + u64::from(p.point) * u64::from(area.0) * u64::from(area.1);
    }

    fn ticks(&self) -> u64 {
        u64::from(self.calls)
            + u64::from(BAND_FIXED)
            + u64::from(ELEMENT_TERM) * u64::from(self.elements)
            + u64::from(LAYER) * u64::from(self.layers)
            + self.centi.div_ceil(100)
    }
}

impl Raster for StepCost {
    fn fill(&mut self, _: &mut [u8], r: Rect, _: u32) {
        self.add(FILL, (r.w, r.h));
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
        self.layers += 1;
        self.calls += p.miss;
        self.add(p, area);
    }

    fn product(
        &mut self,
        owner: (u32, Rect),
        _: &Surface<'_>,
        _: (u32, u32),
        _: u8,
        size: (u32, u32),
    ) -> bool {
        self.made = Some(owner);
        // The first step of an element of two steps: the product of a mask and an
        // alpha over the band's area (the price of a mask with an alpha; its own call
        // and its miss).
        let p = PRICES[elements::Class::MaskAlpha.row()];
        self.layers += 1;
        self.calls += p.miss;
        self.add(p, size);
        true
    }

    fn product_made(&self) -> Option<(u32, Rect)> {
        self.made
    }

    fn element(&mut self, _: &mut [u8], d: &Draw<'_>) {
        // The classes by what the raster is told (a turn of a quarter is read as
        // a general transform, which errs high).
        let t = d.transparency;
        let area = (d.area.w, d.area.h);
        let (first, extra) = elements::class_of(elements::Shape4 {
            scale: d.matrix.map(|m| elements::is_scale(&m)),
            quarter: false,
            bilinear: d.filter == BILINEAR,
            over: t & TRANSPARENCY_SOURCE != 0,
            argb: d.src.format == Format::Argb,
            mask: t & TRANSPARENCY_MASK != 0,
            alpha: t & TRANSPARENCY_ALPHA != 0,
        });
        // The second step of an element of two steps has the product made: the mask only.
        let extra = if d.work {
            Some(elements::Class::Mask)
        } else {
            extra
        };
        let p = PRICES[first.row()];
        self.layers += 1;
        self.calls += p.miss;
        self.add(p, area);
        if let Some(x) = extra {
            // The alpha or the mask is in the one call: rows and points.
            let x = PRICES[x.row()];
            self.add(x, area);
            self.calls -= x.call;
        }
    }
}

#[test]
fn every_element_of_the_scene_is_a_term_of_a_step_whether_it_shows_or_not() {
    let mut rig = Rig::new(&[(XRGB, 64, 40), (XRGB, 64, 40)]);
    // One far from the damage, one under an opaque element that covers it.
    let far = rig.whole(0, [500, 300, 64, 40]);
    let under = rig.whole(0, [0, 0, 64, 40]);
    let cover = rig.whole(1, [0, 0, 640, 400]);
    let els = [far, under, cover];
    rig.scene
        .scene_commit(&SceneCommit::new(proto_comp::ACTIVE, BG, &els).unwrap())
        .unwrap();
    rig.scene.begin().unwrap();
    let def = rig.scene.working().copied().unwrap();
    let d = Rect {
        x: 0,
        y: 0,
        w: 100,
        h: 100,
    };
    assert_eq!(rig.scene.passes(&def, d).elements, 3);
    rig.scene.end(true);
}

/// A scene of two elements of two steps (a stretch with a mask and an alpha, by a
/// turn of a half, so no fast path) side by side.
fn two_of_two_steps() -> (Rig, Vec<Element>) {
    let rig = Rig::new(&[(XRGB, 64, 40), (XRGB, 64, 40), (A8, 128, 80), (A8, 128, 80)]);
    let mut a = rig.whole(0, [10, 10, 128, 80]);
    a.orient = 2;
    a.transparency = TRANSPARENCY_MASK | TRANSPARENCY_ALPHA;
    a.mask = rig.id(2);
    a.alpha = 150;
    let mut b = rig.whole(1, [200, 10, 128, 80]);
    b.orient = 2;
    b.transparency = TRANSPARENCY_MASK | TRANSPARENCY_ALPHA;
    b.mask = rig.id(3);
    b.alpha = 90;
    (rig, vec![a, b])
}

#[test]
fn a_second_step_that_finds_the_product_of_another_element_goes_back_to_its_first() {
    let (mut rig, els) = two_of_two_steps();
    rig.scene
        .scene_commit(&SceneCommit::new(proto_comp::ACTIVE, BG, &els).unwrap())
        .unwrap();
    let d = rig.scene.begin().expect("a frame");
    let def = rig.scene.working().copied().unwrap();
    let plan = rig.scene.passes(&def, d);
    let (ga, gb) = (plan.group_of(0).unwrap(), plan.group_of(1).unwrap());
    assert!(plan.is_two_step(ga) && plan.is_two_step(gb) && ga != gb);
    let mut fb = vec![0xEE; (STRIDE * HEIGHT) as usize];
    let mut sampler = Sampler::new();
    // The first step of the first element's first band.
    let ra = plan.cost[ga].rect;
    let at = Band {
        row: ra.y,
        col: ra.x - d.x,
        pass: ga as u32,
    };
    let next = compose(&rig.scene, d, at, &mut fb, &rig.wins, &mut sampler);
    assert_eq!(next.pass, ga as u32 | PHASE);
    // The group numbers shift between the steps: the second step is asked of the
    // other element's group, for the band the product was not made for.
    let rb = plan.cost[gb].rect;
    let wrong = Band {
        row: rb.y,
        col: rb.x - d.x,
        pass: gb as u32 | PHASE,
    };
    let before = fb.clone();
    let back = compose(&rig.scene, d, wrong, &mut fb, &rig.wins, &mut sampler);
    assert_eq!(
        back,
        Band {
            pass: gb as u32,
            ..wrong
        }
    );
    assert_eq!(fb, before, "nothing is drawn through another's product");
    rig.scene.end(true);
}

#[test]
fn a_product_that_is_refused_leaves_its_band_undrawn_and_the_frame_goes_on() {
    let (mut rig, els) = two_of_two_steps();
    rig.scene
        .scene_commit(&SceneCommit::new(proto_comp::ACTIVE, BG, &els).unwrap())
        .unwrap();
    let d = rig.scene.begin().expect("a frame");
    let mut fb = vec![0xEE; (STRIDE * HEIGHT) as usize];
    let mut sampler = Sampler::new();
    sampler.refuse = true;
    let mut at = Band::default();
    let mut steps = 0;
    while at.row < d.y + d.h {
        at = compose(&rig.scene, d, at, &mut fb, &rig.wins, &mut sampler);
        steps += 1;
        assert!(steps < 10_000, "the frame does not end");
    }
    // The elements are not drawn: the point inside the first is the black's.
    assert_eq!(get(&fb, 70, 50), BG & 0xFF_FFFF);
    rig.scene.end(true);
}

// ---------------------------------------------------------------- prepared images

/// The maker of the images of the tests: each point of the area is the one the
/// reference's sampler takes from the window through the element's map.
struct RefMaker;

impl prep::Maker for RefMaker {
    fn make(
        &mut self,
        dst: &mut [u8],
        stride: u32,
        argb: bool,
        _: (u32, u32),
        e: &Element,
        src: &prep::Surface2<'_>,
        area: Rect,
    ) {
        let [a, b, c, d, ee, f] = elements::matrix(e);
        for y in area.y..area.y + area.h {
            for x in area.x..area.x + area.w {
                let (xc, yc) = ((i64::from(x) << 16) + 0x8000, (i64::from(y) << 16) + 0x8000);
                let u = ((i64::from(a) * xc + i64::from(b) * yc) >> 16) + i64::from(c);
                let v = ((i64::from(d) * xc + i64::from(ee) * yc) >> 16) + i64::from(f);
                let fetch = |sx: u32, sy: u32| point(src.bytes, src.stride, src.format, sx, sy);
                let mut s = meaning::at(e.filter, (u, v), src.size, fetch);
                if !argb {
                    s |= 0xFF00_0000;
                }
                let at = (y * stride + x * 4) as usize;
                dst[at..at + 4].copy_from_slice(&s.to_le_bytes());
            }
        }
    }
}

struct WinReads<'a>(&'a [Win]);

impl prep::Reads for WinReads<'_> {
    fn read(&self, place: usize, _: u8, _: usize) -> &[u8] {
        &self.0[place].bytes
    }
}

impl Rig {
    /// The rig with the elements that turn or stretch drawn from prepared images
    /// (the windows told to the table as a POST tells them).
    fn prepared(specs: &[(Format, u32, u32)]) -> Rig {
        let table: &'static prep::Table = Box::leak(Box::new(prep::Table::new()));
        let pool: &'static mut [u8] = Box::leak(vec![0u8; prep::POOL_BYTES].into_boxed_slice());
        table.set_pool(pool.as_mut_ptr());
        let mut rig = Rig::new(specs);
        rig.scene.set_prep(table);
        rig.wins.1 = Some(table);
        for i in 0..specs.len() {
            rig.scene.note_post(i, 0, &[], 28);
        }
        rig
    }

    fn table(&self) -> &'static prep::Table {
        self.wins.1.expect("a table")
    }

    /// The worker makes every image that waits, as the thread would, and the
    /// screen is damaged where they show.
    fn drain(&mut self) {
        let t = self.table();
        let mut job = prep::Job::NONE;
        let reads = WinReads(&self.wins.0);
        while let Some((slot, _)) = t.next(&job) {
            match t.piece(&mut job, slot, &mut RefMaker, &reads) {
                prep::Pass::More => {}
                _ => {
                    t.let_go();
                }
            }
        }
        while let Some(drawn) = t.take_drawn() {
            self.scene.images_drawn(&[drawn]);
        }
    }

    /// A frame over `fb` (kept from frame to frame): false when the scene had
    /// nothing to draw.
    fn render(&mut self, fb: &mut [u8]) -> bool {
        let Some(d) = self.scene.begin() else {
            return false;
        };
        let mut at = Band {
            row: d.y,
            col: 0,
            pass: 0,
        };
        let mut sampler = Sampler::new();
        while at.row < d.y + d.h {
            at = compose(&self.scene, d, at, fb, &self.wins, &mut sampler);
        }
        self.scene.end(true);
        true
    }

    fn commit(&mut self, els: &[Element], bg: u32) -> Result<(), Refusal> {
        self.scene
            .scene_commit(&SceneCommit::new(proto_comp::ACTIVE, bg, els).unwrap())
    }

    /// The points of the screen that differ from the reference's (the first few).
    fn wrong(&self, fb: &[u8], els: &[Element], bg: u32) -> Vec<(u32, u32, u32, u32)> {
        let want = self.expected(els, bg);
        let mut wrong = Vec::new();
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                let (got, want) = (get(fb, x, y), want[(y * WIDTH + x) as usize]);
                if got != want && wrong.len() < 5 {
                    wrong.push((x, y, got, want));
                }
            }
        }
        wrong
    }
}

/// A scene drawn from the prepared images is the reference's, as one drawn by the
/// bands through the transform is.
fn prepared_matches(specs: &[(Format, u32, u32)], els: &[Element]) {
    let mut rig = Rig::prepared(specs);
    rig.commit(els, BG).unwrap();
    rig.drain();
    let mut fb = vec![0xEE; (STRIDE * HEIGHT) as usize];
    assert!(rig.render(&mut fb));
    let wrong = rig.wrong(&fb, els, BG);
    assert!(wrong.is_empty(), "points (x, y, got, want): {wrong:x?}");
}

#[test]
fn a_prepared_element_of_every_orientation_scale_and_filter_is_the_reference() {
    for format in [XRGB, ARGB] {
        for orient in ORIENTS {
            for (dw, dh) in [(128, 80), (32, 20), (128, 40), (64, 20)] {
                for filter in [NEAREST, BILINEAR] {
                    let mut rig = Rig::prepared(&[(format, 64, 40)]);
                    let mut e = turned(rig.whole(0, [100, 50, 64, 40]), orient, dw, dh);
                    e.filter = filter;
                    if format == ARGB {
                        e.transparency = TRANSPARENCY_SOURCE;
                    }
                    rig.commit(&[e], BG).unwrap();
                    rig.drain();
                    let mut fb = vec![0xEE; (STRIDE * HEIGHT) as usize];
                    assert!(rig.render(&mut fb));
                    let wrong = rig.wrong(&fb, &[e], BG);
                    assert!(
                        wrong.is_empty(),
                        "{format:?} {orient} {dw}x{dh} {filter}: {wrong:x?}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_prepared_element_with_an_alpha_or_a_mask_is_the_reference() {
    for transparency in [
        TRANSPARENCY_ALPHA,
        TRANSPARENCY_MASK,
        TRANSPARENCY_MASK | TRANSPARENCY_ALPHA,
    ] {
        for orient in [0, 1, 3 | MIRROR] {
            let rig = Rig::new(&[(XRGB, 64, 40), (A8, 128, 80)]);
            let mut e = turned(rig.whole(0, [100, 50, 64, 40]), orient, 128, 80);
            e.transparency = transparency;
            e.alpha = 150;
            if transparency & TRANSPARENCY_MASK != 0 {
                e.mask = rig.id(1);
            }
            let mut e = turned(e, orient, 128, 80);
            e.dw = if orient & 1 != 0 { 80 } else { 128 };
            e.dh = if orient & 1 != 0 { 128 } else { 80 };
            // The mask is a window of the target's size.
            let rig = Rig::new(&[(XRGB, 64, 40), (A8, e.dw as u32, e.dh as u32)]);
            e.source = rig.id(0);
            e.mask = if transparency & TRANSPARENCY_MASK != 0 {
                rig.id(1)
            } else {
                NO_WINDOW
            };
            prepared_matches(&[(XRGB, 64, 40), (A8, e.dw as u32, e.dh as u32)], &[e]);
        }
    }
}

#[test]
fn a_scene_waits_to_be_taken_until_its_images_are_made() {
    let mut rig = Rig::prepared(&[(XRGB, 64, 40)]);
    let e = turned(rig.whole(0, [100, 50, 64, 40]), 1, 64, 40);
    rig.commit(&[e], BG).unwrap();
    // The worker has not run: the scene is not taken, so no frame shows it with the
    // element missing.
    let mut fb = vec![0xEE; (STRIDE * HEIGHT) as usize];
    rig.render(&mut fb);
    assert!(rig.scene.working().is_none());
    // The image is made and the screen is damaged: the next frame has the whole scene.
    rig.drain();
    assert!(rig.render(&mut fb));
    assert!(rig.scene.working().is_some());
    assert!(rig.wrong(&fb, &[e], BG).is_empty());
}

#[test]
fn a_scene_whose_window_has_posted_nothing_is_taken_without_waiting() {
    // The window is not told to the table: its image cannot be made yet, so the scene
    // does not wait for it (the element shows nothing until the window posts).
    let table: &'static prep::Table = Box::leak(Box::new(prep::Table::new()));
    let pool: &'static mut [u8] = Box::leak(vec![0u8; prep::POOL_BYTES].into_boxed_slice());
    table.set_pool(pool.as_mut_ptr());
    let mut rig = Rig::new(&[(XRGB, 64, 40)]);
    rig.scene.set_prep(table);
    rig.wins.1 = Some(table);
    let e = turned(rig.whole(0, [100, 50, 64, 40]), 1, 64, 40);
    rig.commit(&[e], BG).unwrap();
    let mut fb = vec![0xEE; (STRIDE * HEIGHT) as usize];
    assert!(rig.render(&mut fb));
    assert!(rig.scene.working().is_some());
}

#[test]
fn a_post_is_drawn_into_the_image_the_frame_does_not_hold_and_the_latest_wins() {
    let mut rig = Rig::prepared(&[(XRGB, 64, 40)]);
    let e = turned(rig.whole(0, [100, 50, 64, 40]), 1, 64, 40);
    rig.commit(&[e], BG).unwrap();
    rig.drain();
    let mut fb = vec![0xEE; (STRIDE * HEIGHT) as usize];
    assert!(rig.render(&mut fb));
    // Two more posts before a frame: only the last shows, and the window's points
    // are read once, from the latest.
    for round in 1..=2u8 {
        for b in rig.wins.0[0].bytes.iter_mut() {
            *b = b.wrapping_add(round * 37);
        }
        let i = 0;
        // The window has one buffer: a post waits for its free (the frame freed it).
        rig.scene
            .post(
                i,
                0,
                &[Rect {
                    x: 0,
                    y: 0,
                    w: 64,
                    h: 40,
                }],
            )
            .ok();
        rig.scene.note_post(
            i,
            0,
            &[Rect {
                x: 0,
                y: 0,
                w: 64,
                h: 40,
            }],
            28,
        );
    }
    rig.drain();
    assert!(rig.render(&mut fb));
    assert!(rig.wrong(&fb, &[e], BG).is_empty());
}

#[test]
fn the_worker_waits_for_a_frame_that_holds_the_image_it_would_draw_in() {
    let mut rig = Rig::prepared(&[(XRGB, 64, 40)]);
    let e = turned(rig.whole(0, [100, 50, 64, 40]), 1, 64, 40);
    rig.commit(&[e], BG).unwrap();
    rig.drain();
    let t = rig.table();
    let slot = (0..prep::SLOTS).find(|&s| t.used(s)).unwrap();
    // A frame holds the front; a second image is published; the next post finds
    // the other image the frame's.
    let held = t.frame_take(slot).unwrap();
    rig.scene.note_post(0, 0, &[], 28);
    rig.drain();
    assert_ne!(t.front_of(slot), Some(held));
    rig.scene.note_post(0, 0, &[], 28);
    let mut job = prep::Job::NONE;
    let reads = WinReads(&rig.wins.0);
    assert_eq!(
        t.piece(&mut job, slot, &mut RefMaker, &reads),
        prep::Pass::Blocked
    );
    t.let_go();
    assert!(!t.work_waits());
    // The frame ends: the slot wants the worker again.
    t.frame_release(slot);
    assert!(t.unblock());
    assert!(t.work_waits());
}

#[test]
fn a_commit_that_does_not_fit_the_pool_is_refused_with_a_limit() {
    // Two images of 1500 by 700 points are 8.4 MiB.
    let mut rig = Rig::prepared(&[(XRGB, 64, 40)]);
    let e = turned(rig.whole(0, [0, 0, 64, 40]), 0, 1500, 700);
    assert_eq!(rig.commit(&[e], BG), Err(Refusal::Limit));
    // And the scene that was there is as it was: a smaller one still commits.
    let ok = turned(rig.whole(0, [0, 0, 64, 40]), 1, 64, 40);
    assert_eq!(rig.commit(&[ok], BG), Ok(()));
}

#[test]
fn the_images_of_a_scene_that_goes_are_let_go_and_those_of_one_that_stays_are_kept() {
    let mut rig = Rig::prepared(&[(XRGB, 64, 40)]);
    let a = turned(rig.whole(0, [100, 50, 64, 40]), 1, 64, 40);
    rig.commit(&[a], BG).unwrap();
    rig.drain();
    let t = rig.table();
    let used = t.pages_used();
    assert!(used > 0);
    let mut fb = vec![0xEE; (STRIDE * HEIGHT) as usize];
    assert!(rig.render(&mut fb));
    // The element moves: the same image.
    let moved = Element {
        dx: 300,
        dy: 200,
        ..a
    };
    rig.commit(&[moved], BG).unwrap();
    assert_eq!(t.pages_used(), used);
    assert!(rig.render(&mut fb));
    assert!(rig.wrong(&fb, &[moved], BG).is_empty());
    // A scene with no element needing an image lets them go.
    let plain = rig.whole(0, [10, 10, 64, 40]);
    rig.commit(&[plain], BG).unwrap();
    assert!(rig.render(&mut fb));
    assert_eq!(t.pages_used(), 0);
}
