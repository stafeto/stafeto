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

struct Wins(Vec<Win>);

impl Source for Wins {
    fn pixels(&self, window: usize, _: u8) -> &[u8] {
        &self.0[window].bytes
    }
}

/// The raster of the tests: the screen's bytes are XRGB8888.
struct Sampler;

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

    fn element(&mut self, fb: &mut [u8], d: &Draw<'_>) {
        let e = Element {
            filter: d.filter,
            transparency: d.transparency,
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
            wins: Wins(wins),
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
        let mut at = Band { row: d.y, col: 0 };
        while at.row < d.y + d.h {
            at = compose(&self.scene, d, at, &mut fb, &self.wins, &mut Sampler);
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
        elements::classes(&e)
    };
    use elements::Class::*;
    assert_eq!(elements::classes(&plain), (Copy, None));
    assert_eq!(with(|e| e.transparency = TRANSPARENCY_SOURCE), (Over, None));
    assert_eq!(with(|e| e.dx = -30), (Copy, None));
    assert_eq!(with(|e| e.dw = 128), (ScaleNearestCopy, None));
    assert_eq!(with(|e| e.orient = MIRROR), (ScaleNearestCopy, None));
    assert_eq!(with(|e| e.orient = 2), (ScaleNearestCopy, None));
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.filter = BILINEAR
        }),
        (ScaleBilinearCopy, None)
    );
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.transparency = TRANSPARENCY_SOURCE
        }),
        (ScaleNearestOver, None)
    );
    assert_eq!(
        with(|e| {
            e.dw = 128;
            e.transparency = TRANSPARENCY_SOURCE;
            e.filter = BILINEAR
        }),
        (ScaleBilinearOver, None)
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
    // A stretched one pays for the stretch and for the extra.
    assert_eq!(
        with(|e| {
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

/// The model's charge for an element in a band of `w` by `h` points, in ticks.
fn charge(e: &Element, w: u32, h: u32) -> u64 {
    let (first, second) = elements::classes(e);
    let mut centi = 0u64;
    let mut ticks = u64::from(LAYER);
    for class in [Some(first), second].into_iter().flatten() {
        let p = PRICES[class.row()];
        ticks += u64::from(p.call);
        centi += u64::from(p.row) * u64::from(h) + u64::from(p.point) * u64::from(w) * u64::from(h);
    }
    ticks + centi.div_ceil(100)
}

/// The dearest element of the tests: a mask and an alpha over the whole
/// screen with the bilinear mean (source `k` of four, mask `k` of four).
fn dear(rig: &Rig, k: usize) -> Element {
    let mut e = rig.whole(k % 4, [0, 0, 640, 400]);
    e.filter = BILINEAR;
    e.transparency = TRANSPARENCY_MASK | TRANSPARENCY_ALPHA;
    e.mask = rig.id(4 + k % 4);
    e.alpha = 100;
    e
}

fn dear_rig() -> Rig {
    let mut specs = vec![(XRGB, 64, 40); 4];
    specs.extend(vec![(A8, 640, 400); 4]);
    Rig::new(&specs)
}

#[test]
fn a_scene_whose_calls_no_band_could_hold_is_unsupported_and_one_that_fits_is_not() {
    let mut rig = dear_rig();
    // Sixteen of the dearest: the calls alone are past the band.
    let els: Vec<Element> = (0..16).map(|k| dear(&rig, k)).collect();
    let c = SceneCommit::new(proto_comp::ACTIVE, BG, &els).unwrap();
    assert_eq!(rig.scene.scene_commit(&c), Err(Refusal::Unsupported));
    // As many as the floor allows are taken, one more is not.
    let fits = (1..=16)
        .take_while(|&n| {
            let c = SceneCommit::new(proto_comp::ACTIVE, BG, &els[..n]).unwrap();
            rig.scene.scene_commit(&c).is_ok()
        })
        .count();
    assert!((2..16).contains(&fits), "{fits}");
    // The numbers are found wrong before the scene is found dear.
    let mut bad = els.clone();
    bad[15].sw = 1 << 30;
    let c = SceneCommit::new(proto_comp::ACTIVE, BG, &bad).unwrap();
    assert_eq!(rig.scene.scene_commit(&c), Err(Refusal::Invalid));
    // Sixteen copies are taken: only one is drawn at a point.
    let copies: Vec<Element> = (0..16)
        .map(|k| rig.whole(k % 4, [0, 0, 640, 400]))
        .collect();
    let c = SceneCommit::new(proto_comp::ACTIVE, BG, &copies).unwrap();
    assert_eq!(rig.scene.scene_commit(&c), Ok(()));
}

#[test]
fn every_band_of_the_dearest_scene_costs_at_most_the_band_ticks_by_the_model() {
    let mut rig = dear_rig();
    let mut els: Vec<Element> = Vec::new();
    for k in 0..16 {
        els.push(dear(&rig, k));
        let c = SceneCommit::new(proto_comp::ACTIVE, BG, &els).unwrap();
        if rig.scene.scene_commit(&c).is_err() {
            els.pop();
            break;
        }
    }
    assert!(els.len() >= 2);
    rig.scene
        .scene_commit(&SceneCommit::new(proto_comp::ACTIVE, BG, &els).unwrap())
        .unwrap();
    let d = rig.scene.begin().expect("a frame");
    let mut bands = 0;
    let mut at = Band { row: d.y, col: 0 };
    let mut fb = vec![0u8; (STRIDE * HEIGHT) as usize];
    while at.row < d.y + d.h {
        let (bw, bh) = rig.scene.tile(d);
        let w = bw.min(d.w - at.col);
        let h = bh.min(d.y + d.h - at.row);
        let mut cost = u64::from(FILL.call) + u64::from(BAND_FIXED);
        cost += (u64::from(FILL.row) * u64::from(h)
            + u64::from(FILL.point) * u64::from(w) * u64::from(h))
        .div_ceil(100);
        for e in &els {
            if rig.scene.element_place(e).is_some() {
                cost += charge(e, w, h);
            }
        }
        assert!(
            cost <= u64::from(BAND_TICKS),
            "a band {w} by {h} at {at:?} costs {cost} by the model"
        );
        at = compose(&rig.scene, d, at, &mut fb, &rig.wins, &mut Counting);
        bands += 1;
    }
    rig.scene.end(true);
    // A dear scene stretches over many bands: the cap of a period (47 bands)
    // spreads it over periods.
    assert!(bands > 47, "{bands} bands");
}

/// A raster that draws nothing.
struct Counting;

impl Raster for Counting {
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
        _: usize,
    ) {
    }
    fn element(&mut self, _: &mut [u8], _: &Draw<'_>) {}
}
