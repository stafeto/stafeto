// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the paced client draws in a period and what it posts. A stripe of
//! colour moves down the window by `STEP_ROWS` rows each period, so every
//! frame differs from the one before in exactly two stripes (where it was and
//! where it is): the rectangle the client posts. In the scene F the whole
//! window changes, and the client posts all of it.

use crate::phases::Scene;

/// The window of the scene P (place and size) and of the scene F.
pub const P_RECT: Rect = Rect {
    x: 40,
    y: 40,
    w: 160,
    h: 100,
};
pub const F_RECT: Rect = Rect {
    x: 0,
    y: 0,
    w: 640,
    h: 400,
};

/// The rows the stripe is high, and how far it moves in a period.
pub const STRIPE_ROWS: u32 = 10;
pub const STEP_ROWS: u32 = 7;

/// A rectangle of the window's own points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

/// The window of a scene, or none for a scene with no window of the compositor's
/// second revision (the nothing, and the first revision's).
pub const fn window_of(scene: Scene) -> Option<Rect> {
    match scene {
        Scene::P => Some(P_RECT),
        Scene::F => Some(F_RECT),
        Scene::None | Scene::D => None,
    }
}

/// The first row of the stripe in the period `step` of a window `h` rows high:
/// it moves down by `STEP_ROWS` and starts again at the top, and never leaves
/// the window.
pub const fn stripe_top(step: u64, h: u32) -> u32 {
    ((step * STEP_ROWS as u64) % (h - STRIPE_ROWS + 1) as u64) as u32
}

/// The colour of the point (`x`, `y`) in the period `step`: the stripe is
/// bright, the rest a slow gradient, so no two frames are alike and a posted
/// rectangle that is too small shows.
pub fn colour(step: u64, x: u32, y: u32, h: u32) -> u32 {
    let top = stripe_top(step, h);
    let in_stripe = y >= top && y < top + STRIPE_ROWS;
    if in_stripe {
        0x00FF_C020 | ((step as u32 & 0x3F) << 8)
    } else {
        0x0010_2040 | ((x & 0xFF) << 8) | (y & 0xFF)
    }
}

/// The rectangle that covers what differs between the frame of period
/// `step - 1` and the frame of `step` (the stripe where it was and where it is,
/// as one rectangle across the whole width). The whole window in the first
/// period and for a scene whose whole window moves.
pub fn damage(scene: Scene, step: u64) -> Option<Rect> {
    let window = window_of(scene)?;
    if step == 0 || scene == Scene::F {
        return Some(Rect {
            x: 0,
            y: 0,
            w: window.w,
            h: window.h,
        });
    }
    let before = stripe_top(step - 1, window.h);
    let now = stripe_top(step, window.h);
    // The stripes are the rows [top, top + STRIPE_ROWS); the rectangle spans
    // from the first row of either to the last of either.
    let low = before.min(now);
    let high = before.max(now) + STRIPE_ROWS;
    Some(Rect {
        x: 0,
        y: low,
        w: window.w,
        h: high - low,
    })
}

/// The rows the client must paint into the buffer it uses for the period
/// `step`: with two buffers that buffer holds the frame of `step - 2`, so it
/// differs from the frame of `step` where either of the two steps changed
/// something: the union of the damage of `step - 1` and of `step`.
pub fn redraw(scene: Scene, step: u64) -> Option<Rect> {
    let now = damage(scene, step)?;
    if step < 2 {
        return Some(Rect {
            x: 0,
            y: 0,
            w: now.w,
            h: window_of(scene)?.h,
        });
    }
    let before = damage(scene, step - 1)?;
    let top = now.y.min(before.y);
    let bottom = (now.y + now.h).max(before.y + before.h);
    Some(Rect {
        x: 0,
        y: top,
        w: now.w,
        h: bottom - top,
    })
}

/// The points of the window in the period `step`, row by row (for the tests and
/// for the client's drawing).
pub fn frame(scene: Scene, step: u64, out: &mut [u32]) {
    let Some(window) = window_of(scene) else {
        return;
    };
    for y in 0..window.h {
        for x in 0..window.w {
            if let Some(p) = out.get_mut((y * window.w + x) as usize) {
                *p = colour(step, x, y, window.h);
            }
        }
    }
}

/// The time of the post of the period `k` of a client that declared
/// `interval` periods: the start of the period's own start plus half an
/// interval is not needed, the client posts on the start of its period and the
/// service takes it on the next one. `t0` is the start of period 0.
pub const fn post_time(t0: u64, period: u64, interval: u32, k: u64) -> u64 {
    t0 + k * interval as u64 * period
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(scene: Scene, step: u64) -> Vec<u32> {
        let window = window_of(scene).unwrap();
        let mut v = vec![0; (window.w * window.h) as usize];
        frame(scene, step, &mut v);
        v
    }

    /// The rectangle posted covers every point that differs from the frame
    /// before (the rule of POST).
    #[test]
    fn the_rectangle_covers_what_changed_in_the_scene_p() {
        for step in 1..60 {
            let (a, b) = (frames(Scene::P, step - 1), frames(Scene::P, step));
            let r = damage(Scene::P, step).unwrap();
            for y in 0..P_RECT.h {
                for x in 0..P_RECT.w {
                    let at = (y * P_RECT.w + x) as usize;
                    if a[at] != b[at] {
                        let inside = x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h;
                        assert!(inside, "step {step}: ({x}, {y}) changed outside {r:?}");
                    }
                }
            }
        }
    }

    /// Two buffers painted only in the rows `redraw` names, alternately, are
    /// the frame of each step: the client may skip the rest.
    #[test]
    fn two_buffers_painted_in_the_redraw_rows_hold_the_frames() {
        for scene in [Scene::P, Scene::F] {
            let window = window_of(scene).unwrap();
            let size = (window.w * window.h) as usize;
            let mut buffers = [vec![0u32; size], vec![0u32; size]];
            for step in 0..120u64 {
                let b = (step % 2) as usize;
                let r = redraw(scene, step).unwrap();
                for y in r.y..r.y + r.h {
                    for x in r.x..r.x + r.w {
                        buffers[b][(y * window.w + x) as usize] = colour(step, x, y, window.h);
                    }
                }
                assert_eq!(buffers[b], frames(scene, step), "{scene:?} step {step}");
            }
        }
    }

    #[test]
    fn the_rectangle_stays_inside_the_window_and_is_small_in_p() {
        for step in 1..200 {
            let r = damage(Scene::P, step).unwrap();
            assert!(r.w > 0 && r.h > 0);
            assert!(r.x + r.w <= P_RECT.w && r.y + r.h <= P_RECT.h, "{r:?}");
        }
        // Without a wrap the rectangle is the two stripes and what lies between.
        let r = damage(Scene::P, 1).unwrap();
        assert_eq!((r.y, r.h), (0, STEP_ROWS + STRIPE_ROWS));
    }

    #[test]
    fn the_scene_f_posts_all_of_the_window_each_period() {
        for step in [0, 1, 5] {
            assert_eq!(
                damage(Scene::F, step),
                Some(Rect {
                    x: 0,
                    y: 0,
                    w: 640,
                    h: 400
                })
            );
        }
    }

    #[test]
    fn the_first_period_posts_all_of_the_window() {
        assert_eq!(
            damage(Scene::P, 0),
            Some(Rect {
                x: 0,
                y: 0,
                w: 160,
                h: 100
            })
        );
    }

    #[test]
    fn a_scene_with_no_window_has_nothing_to_post() {
        assert_eq!(damage(Scene::None, 3), None);
        assert_eq!(damage(Scene::D, 3), None);
        assert_eq!(window_of(Scene::D), None);
    }

    #[test]
    fn every_frame_is_unlike_the_one_before() {
        for step in 1..40 {
            assert_ne!(frames(Scene::P, step - 1), frames(Scene::P, step));
        }
    }

    #[test]
    fn a_declared_interval_spaces_the_posts() {
        let (t0, period) = (1000, 16);
        assert_eq!(post_time(t0, period, 1, 3), 1048);
        assert_eq!(post_time(t0, period, 2, 3), 1096);
        assert_eq!(post_time(t0, period, 4, 0), 1000);
    }
}
