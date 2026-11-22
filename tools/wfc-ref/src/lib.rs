// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The host reference of `cargo xtask wfc-probe`. The demo (`apps/wfc-demo`)
//! shows three scenes, A, B and D, of three elements each over three windows: two
//! patterns that `tests/wfc-producer` draws (`pattern_a`, `pattern_b`) and a
//! mask of A8 that the demo draws (`mask`). The reference builds the scenes
//! through the crate `wfc` with the same calls as the demo (so the matrices,
//! the 16.16 numbers and the records are the library's) and draws each point
//! by `proto_comp::meaning`, which knows no band and no matrix. The pictures
//! and the places in `scene` are the same numbers `wfc-demo.c` and
//! `wfc-producer.c` have; the table of the scenes is in `SCENES`.

use proto_comp::{Element, FORMAT_A8, FORMAT_XRGB8888, SceneCommit, TRANSPARENCY_MASK, meaning};
use proto_wire::Status;
use wfc::consts::*;
use wfc::{Service, Setup, StreamInfo, Wfc};

pub const WIDTH: usize = 640;
pub const HEIGHT: usize = 400;

/// The windows' ids in the reference (the demo has the service's own).
pub const P1: u32 = 1;
pub const P2: u32 = 2;
pub const M: u32 = 3;

pub const P1_SIZE: (u32, u32) = (100, 200);
pub const P2_SIZE: (u32, u32) = (160, 100);
pub const M_SIZE: (u32, u32) = (160, 100);

/// The first pattern (`pattern_a` of wfc-producer.c), 0x00RRGGBB.
pub fn pattern_a(x: u32, y: u32) -> u32 {
    let r = x * 255 / 99;
    let g = y * 255 / 199;
    let b = (x * 3 + y * 5) & 0xFF;
    r << 16 | g << 8 | b
}

/// The second pattern (`pattern_b` of wfc-producer.c).
pub fn pattern_b(x: u32, y: u32) -> u32 {
    let r = if (x / 8 + y / 8) & 1 == 1 { 240 } else { 16 };
    let g = x * 255 / 159;
    let b = y * 255 / 99;
    r << 16 | g << 8 | b
}

/// The mask's byte (`mask_value` of wfc-demo.c): a disc with a half ring.
pub fn mask(x: u32, y: u32) -> u32 {
    let dx = x as i32 - 80;
    let dy = y as i32 - 50;
    let d2 = dx * dx + dy * dy;
    if d2 <= 40 * 40 {
        255
    } else if d2 <= 50 * 50 {
        128
    } else {
        0
    }
}

/// One element of a scene as the demo sets it.
struct Spec {
    window: u32,
    src: [f32; 4],
    rotation: i32,
    flip: bool,
    filter: i32,
    transparency: i32,
    alpha: i32,
    mask: bool,
    dst: [i32; 4],
}

const A: [Spec; 3] = [
    Spec {
        window: P1,
        src: [0.0, 0.0, 100.0, 200.0],
        rotation: ROTATION_90,
        flip: false,
        filter: SCALE_FILTER_NONE,
        transparency: 0,
        alpha: 255,
        mask: false,
        dst: [20, 20, 200, 100],
    },
    Spec {
        window: P2,
        src: [0.0, 0.0, 160.0, 100.0],
        rotation: ROTATION_0,
        flip: false,
        filter: SCALE_FILTER_FASTER,
        transparency: 5,
        alpha: 200,
        mask: true,
        dst: [300, 150, 160, 100],
    },
    Spec {
        window: P1,
        src: [10.0, 20.0, 40.0, 60.0],
        rotation: ROTATION_0,
        flip: false,
        filter: SCALE_FILTER_FASTER,
        transparency: 1,
        alpha: 128,
        mask: false,
        dst: [40, 230, 80, 120],
    },
];

const B: [Spec; 3] = [
    Spec {
        window: P1,
        src: [20.0, 30.0, 60.0, 120.0],
        rotation: ROTATION_90,
        flip: false,
        filter: SCALE_FILTER_NONE,
        transparency: 0,
        alpha: 255,
        mask: false,
        dst: [200, 40, 120, 60],
    },
    Spec {
        window: P2,
        src: [0.0, 0.0, 160.0, 100.0],
        rotation: ROTATION_0,
        flip: false,
        filter: SCALE_FILTER_NONE,
        transparency: 4,
        alpha: 255,
        mask: true,
        dst: [20, 200, 160, 100],
    },
    Spec {
        window: P1,
        src: [10.0, 20.0, 50.0, 60.0],
        rotation: ROTATION_0,
        flip: true,
        filter: SCALE_FILTER_NONE,
        transparency: 1,
        alpha: 255,
        mask: false,
        dst: [460, 150, 50, 60],
    },
];

/// Scene D: the bilinear filter, committed once.
const D: [Spec; 3] = [
    Spec {
        window: P2,
        src: [0.0, 0.0, 80.0, 50.0],
        rotation: ROTATION_0,
        flip: false,
        filter: SCALE_FILTER_BETTER,
        transparency: 0,
        alpha: 255,
        mask: false,
        dst: [20, 20, 160, 100],
    },
    Spec {
        window: P1,
        src: [0.0, 0.0, 100.0, 200.0],
        rotation: ROTATION_0,
        flip: true,
        filter: SCALE_FILTER_BETTER,
        transparency: 0,
        alpha: 255,
        mask: false,
        dst: [300, 40, 50, 100],
    },
    Spec {
        window: P1,
        src: [10.0, 20.0, 60.0, 120.0],
        rotation: ROTATION_270,
        flip: false,
        filter: SCALE_FILTER_BETTER,
        transparency: 1,
        alpha: 128,
        mask: false,
        dst: [400, 200, 120, 60],
    },
];

/// The scenes: the background (0xRRGGBBAA, as `wfcSetContextAttribi` has it)
/// and the elements, lowest first. Index 2 is scene D.
const SCENES: [(i32, &[Spec; 3]); 3] = [
    (0x2030_40FFu32 as i32, &A),
    (0x4020_10FFu32 as i32, &B),
    (0x1828_18FFu32 as i32, &D),
];

/// A service that keeps the last scene it was given.
#[derive(Default)]
struct Keep {
    last: Option<SceneCommit>,
}

impl Service for Keep {
    fn scene_commit(&mut self, c: &SceneCommit) -> Result<(), Status> {
        self.last = Some(*c);
        Ok(())
    }
    fn scene_compose(&mut self, _: u32) -> Result<(), Status> {
        Ok(())
    }
    fn wait(&mut self, _: u64) -> Result<(), Status> {
        Ok(())
    }
    fn clear(&mut self, _: u64) {}
    fn pause(&mut self) -> Result<(), Status> {
        Ok(())
    }
    fn claim_screen(&mut self) -> bool {
        true
    }
    fn release_screen(&mut self) {}
}

/// The record of scene `which` (0 for A, 1 for B, 2 for D), built through the
/// library's calls as the demo makes them, and the background.
pub fn scene(which: usize) -> SceneCommit {
    let (bg, specs) = SCENES[which];
    let mut svc = Keep::default();
    let mut w = Wfc::create_device(0, &[], Setup::VIRTIO).expect("device");
    let dev = w.device();
    let ctx = w.create_on_screen_context(dev, 0, &[], &mut svc);
    assert!(ctx != 0);
    let info = |id, size: (u32, u32), format| StreamInfo {
        id,
        width: size.0,
        height: size.1,
        format,
    };
    let s1 = w.create_source_from_stream(dev, ctx, Some(info(P1, P1_SIZE, FORMAT_XRGB8888)), &[]);
    let s2 = w.create_source_from_stream(dev, ctx, Some(info(P2, P2_SIZE, FORMAT_XRGB8888)), &[]);
    let m = w.create_mask_from_stream(dev, ctx, Some(info(M, M_SIZE, FORMAT_A8)), &[]);
    w.set_context_attrib_i(dev, ctx, CONTEXT_BG_COLOR, bg);
    let mut below = 0;
    for spec in specs {
        let e = w.create_element(dev, ctx, &[]);
        let source = if spec.window == P1 { s1 } else { s2 };
        w.set_element_attrib_i(dev, e, ELEMENT_SOURCE, source as i32);
        w.set_element_attrib_fv(dev, e, ELEMENT_SOURCE_RECTANGLE, Some(&spec.src));
        w.set_element_attrib_iv(dev, e, ELEMENT_DESTINATION_RECTANGLE, Some(&spec.dst));
        w.set_element_attrib_i(dev, e, ELEMENT_SOURCE_ROTATION, spec.rotation);
        w.set_element_attrib_i(dev, e, ELEMENT_SOURCE_FLIP, i32::from(spec.flip));
        w.set_element_attrib_i(dev, e, ELEMENT_SOURCE_SCALE_FILTER, spec.filter);
        w.set_element_attrib_i(dev, e, ELEMENT_TRANSPARENCY_TYPES, spec.transparency);
        w.set_element_attrib_i(dev, e, ELEMENT_GLOBAL_ALPHA, spec.alpha);
        if spec.mask {
            w.set_element_attrib_i(dev, e, ELEMENT_MASK, m as i32);
        }
        w.insert_element(dev, e, below);
        below = e;
    }
    assert_eq!(w.get_error(dev), 0, "the demo's calls are all accepted");
    w.commit(dev, ctx, false, &mut svc);
    assert_eq!(w.get_error(dev), 0, "the commit is consistent");
    svc.last.expect("a scene was committed")
}

/// The window `id` as a drawing source: its size and the point, premultiplied
/// ARGB for the colour windows and the byte for the mask.
/// A window as a source: its size and the value of a point.
type Source = ((u32, u32), fn(u32, u32) -> u32);

fn window(id: u32) -> Source {
    match id {
        P1 => (P1_SIZE, |x, y| pattern_a(x, y) | 0xFF00_0000),
        P2 => (P2_SIZE, |x, y| pattern_b(x, y) | 0xFF00_0000),
        _ => (M_SIZE, mask),
    }
}

/// The frame scene `which` shows: 640 by 400 points, 0x00RRGGBB, row after row.
pub fn frame(which: usize) -> Vec<u32> {
    let record = scene(which);
    let bg = record.bg & 0x00FF_FFFF;
    let elements: Vec<Element> = record.elements().to_vec();
    let mut out = Vec::with_capacity(WIDTH * HEIGHT);
    for y in 0..HEIGHT as i32 {
        for x in 0..WIDTH as i32 {
            let mut value = bg;
            for e in &elements {
                if !meaning::covers(e, x, y) {
                    continue;
                }
                let (size, point) = window(e.source);
                let m = if e.transparency & TRANSPARENCY_MASK != 0 {
                    mask((x - e.dx) as u32, (y - e.dy) as u32)
                } else {
                    255
                };
                if let Some(s) = meaning::sample(e, x, y, size, point) {
                    value = meaning::mix(e, s, m, value);
                }
            }
            out.push(value & 0x00FF_FFFF);
        }
    }
    out
}

/// The CRC-32 of a frame's colours as the monitor takes it: the red, green and
/// blue bytes of each point, row after row.
pub fn crc(frame: &[u32]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for p in frame {
        for b in [(p >> 16) as u8, (p >> 8) as u8, *p as u8] {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    0xEDB8_8320 ^ (crc >> 1)
                } else {
                    crc >> 1
                };
            }
        }
    }
    !crc
}

/// The CRCs of scenes A, B and D.
pub fn crcs() -> [u32; 3] {
    [crc(&frame(0)), crc(&frame(1)), crc(&frame(2))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scenes_have_three_elements_each_with_their_kinds() {
        for which in 0..2 {
            let s = scene(which);
            assert_eq!(s.count, 3);
            assert_eq!(s.flags, 0);
        }
        // A stretches with the nearest filter, B flips, D is bilinear and flips.
        let a0 = scene(0);
        assert_ne!(a0.elements[2].dw, a0.elements[2].sw >> 16);
        assert_eq!(
            scene(1).elements[2].orient & proto_comp::MIRROR,
            proto_comp::MIRROR
        );
        let d = scene(2);
        assert_eq!(d.count, 3);
        assert!(
            d.elements
                .iter()
                .take(3)
                .all(|e| e.filter == proto_comp::BILINEAR)
        );
        assert_eq!(
            d.elements[1].orient & proto_comp::MIRROR,
            proto_comp::MIRROR
        );
        let a = scene(0);
        assert_eq!(a.elements[1].transparency, 5);
        assert_eq!(a.elements[1].mask, M);
        assert_ne!(a.elements[0].orient, 0);
        let b = scene(1);
        assert_eq!(b.elements[1].transparency, 4);
        assert_ne!(b.elements[0].orient, 0);
    }

    #[test]
    fn the_two_frames_differ_and_draw_something_over_the_background() {
        let [a, b, d] = [frame(0), frame(1), frame(2)];
        assert_ne!(crc(&a), crc(&b));
        assert_ne!(crc(&a), crc(&d));
        assert!(d.iter().any(|&p| p != 0x0018_2818));
        assert!(a.iter().any(|&p| p != 0x0020_3040));
        assert!(b.iter().any(|&p| p != 0x0040_2010));
        // The corner no element reaches is the background.
        assert_eq!(a[WIDTH * 399 + 639], 0x0020_3040);
        assert_eq!(b[WIDTH * 399], 0x0040_2010 & 0x00FF_FFFF);
    }

    #[test]
    fn the_crcs_are_stable() {
        assert_eq!(crcs(), crcs());
    }
}
