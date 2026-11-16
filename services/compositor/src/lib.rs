// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the composition service decides, apart from the calls it makes:
//! the windows and their buffers (`Scene`) and the putting together of the
//! screen from them (`compose`). Everything here builds for the host too,
//! where `cargo test -p compositor` exercises it.
//!
//! A window is a rectangle of the screen with up to three buffers. A
//! buffer is free (the client draws in it), posted (the client gave it up)
//! or taken (a frame reads it, or the screen shows it). A frame takes the
//! posted buffer of every window at its start: that is the whole of the
//! "taking" of the design, one step. The frame is then made in bands of a
//! few lines, a step each; the buffer the taken one replaced on the screen
//! is free once the frame is shown. The windows that have nothing taken
//! yet show nothing.

#![cfg_attr(not(test), no_std)]

use proto_comp::{BUFFERS, MAX_RECTS, Rect, union};
use proto_gpu::{HEIGHT, STRIDE, WIDTH};

/// The windows at once, and the windows of one context.
pub const MAX_WINDOWS: usize = 8;
// The places a mask of `u8` names (`Scene::create`).
const _: () = assert!(MAX_WINDOWS <= 8);
pub const PER_CONTEXT: usize = 4;
/// The lines of one band of a frame: one step of the service. The step
/// stays under 0.8 of term B (xtask).
pub const BAND_ROWS: u32 = 8;

/// The state of a buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Buf {
    Free,
    Posted,
    Taken,
}

/// Why a call of the scene is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The table of windows, or the context's share, is full.
    Limit,
    /// The rectangle, the number or the size is wrong.
    Invalid,
    /// The buffer is not free, or the window has its buffers.
    Busy,
    /// The call is not for this window (a POST before ATTACH, a FLUSH of a
    /// window that has buffers of its own, or the other way round).
    NotAllowed,
}

/// One window.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    pub label: u64,
    pub ctx: u64,
    pub rect: Rect,
    /// The window of a program that knows no windows (OPEN of proto_gpu):
    /// the whole screen, one buffer the service made.
    pub legacy: bool,
    pub seq: u32,
    pub stride: u32,
    /// The buffers attached, 0 before ATTACH.
    pub attached: u8,
    pub bufs: [Buf; BUFFERS],
    pub posted: Option<u8>,
    /// What the screen shows of the window, once something was taken.
    pub current: Option<u8>,
    /// The buffer the last take replaced: free when the frame is shown.
    pub retired: Option<u8>,
    /// Whether the frame in progress took something of this window.
    pub in_frame: bool,
}

/// What a finished frame frees of a window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ended {
    pub freed: Option<u8>,
    pub in_frame: bool,
}

/// The windows, the damage to be shown and the frame's state.
pub struct Scene {
    windows: [Option<Window>; MAX_WINDOWS],
    damage: Option<Rect>,
    frame: bool,
    seq: u32,
    created: u32,
    frames: u32,
}

impl Default for Scene {
    fn default() -> Scene {
        Scene::new()
    }
}

/// The whole screen.
pub const SCREEN: Rect = Rect {
    x: 0,
    y: 0,
    w: WIDTH,
    h: HEIGHT,
};

impl Scene {
    pub const fn new() -> Scene {
        Scene {
            windows: [None; MAX_WINDOWS],
            damage: None,
            frame: false,
            seq: 0,
            created: 0,
            frames: 0,
        }
    }

    pub fn window(&self, i: usize) -> Option<&Window> {
        self.windows.get(i).and_then(Option::as_ref)
    }

    /// The place of the window with `label`.
    pub fn find(&self, label: u64) -> Option<usize> {
        self.windows
            .iter()
            .position(|w| w.is_some_and(|w| w.label == label))
    }

    /// The windows alive, those ever made and the frames shown.
    pub fn open(&self) -> u32 {
        self.windows.iter().flatten().count() as u32
    }

    pub fn created(&self) -> u32 {
        self.created
    }

    pub fn frames(&self) -> u32 {
        self.frames
    }

    /// Whether a frame is in progress or damage waits for one.
    pub fn busy(&self) -> bool {
        self.frame || self.damage.is_some()
    }

    pub fn framing(&self) -> bool {
        self.frame
    }

    /// Whether a legacy window lives.
    pub fn has_legacy(&self) -> bool {
        self.windows.iter().flatten().any(|w| w.legacy)
    }

    /// A window of context `ctx` at `rect`: its place, which is none of the
    /// places the bits of `taken` name (a place whose mappings are still
    /// going). Limit when the table or the context's share is full, Invalid
    /// for a rectangle outside the screen.
    pub fn create(
        &mut self,
        label: u64,
        ctx: u64,
        rect: Rect,
        legacy: bool,
        taken: u8,
    ) -> Result<usize, Refusal> {
        if !rect.within(WIDTH, HEIGHT) {
            return Err(Refusal::Invalid);
        }
        let mine = self
            .windows
            .iter()
            .flatten()
            .filter(|w| w.ctx == ctx)
            .count();
        if mine >= PER_CONTEXT {
            return Err(Refusal::Limit);
        }
        let place = self
            .windows
            .iter()
            .enumerate()
            .position(|(i, w)| w.is_none() && taken & (1 << i) == 0)
            .ok_or(Refusal::Limit)?;
        self.seq = self.seq.wrapping_add(1);
        self.created += 1;
        self.windows[place] = Some(Window {
            label,
            ctx,
            rect,
            legacy,
            seq: self.seq,
            stride: if legacy { STRIDE } else { 0 },
            attached: u8::from(legacy),
            bufs: [Buf::Free; BUFFERS],
            posted: None,
            current: None,
            retired: None,
            in_frame: false,
        });
        Ok(place)
    }

    /// The buffers of window `i`: `count` of them with `stride`, which
    /// must hold the window's lines. Once.
    pub fn attach(&mut self, i: usize, count: u8, stride: u32) -> Result<(), Refusal> {
        let w = self
            .windows
            .get_mut(i)
            .and_then(Option::as_mut)
            .ok_or(Refusal::Invalid)?;
        if w.attached != 0 {
            return Err(Refusal::Busy);
        }
        if count == 0 || count as usize > BUFFERS || u64::from(stride) < u64::from(w.rect.w) * 4 {
            return Err(Refusal::Invalid);
        }
        w.attached = count;
        w.stride = stride;
        Ok(())
    }

    /// The window's places that `rects` change, on the screen; the whole
    /// window for none. Invalid for a rectangle outside the window.
    fn changed(rect: Rect, rects: &[Rect]) -> Result<Rect, Refusal> {
        if rects.is_empty() {
            return Ok(rect);
        }
        let mut sum = None;
        for r in rects {
            if !r.within(rect.w, rect.h) {
                return Err(Refusal::Invalid);
            }
            sum = Some(union(
                sum,
                Rect {
                    x: rect.x + r.x,
                    y: rect.y + r.y,
                    w: r.w,
                    h: r.h,
                },
            ));
        }
        Ok(sum.unwrap_or(rect))
    }

    fn add_damage(&mut self, r: Rect) {
        self.damage = Some(union(self.damage, r));
    }

    /// POST of buffer `buffer` of window `i` with the changed `rects`: the
    /// buffer a posted one it replaced ("the latest wins"), which is free
    /// at once.
    pub fn post(&mut self, i: usize, buffer: u8, rects: &[Rect]) -> Result<Option<u8>, Refusal> {
        if rects.len() > MAX_RECTS {
            return Err(Refusal::Invalid);
        }
        let w = self
            .windows
            .get_mut(i)
            .and_then(Option::as_mut)
            .ok_or(Refusal::Invalid)?;
        if w.legacy || w.attached == 0 {
            return Err(Refusal::NotAllowed);
        }
        if buffer >= w.attached {
            return Err(Refusal::Invalid);
        }
        if w.bufs[buffer as usize] != Buf::Free {
            return Err(Refusal::Busy);
        }
        let damage = Scene::changed(w.rect, rects)?;
        w.bufs[buffer as usize] = Buf::Posted;
        let replaced = w.posted.replace(buffer);
        if let Some(j) = replaced {
            w.bufs[j as usize] = Buf::Free;
        }
        self.add_damage(damage);
        Ok(replaced)
    }

    /// FLUSH of the legacy window `i`: its one buffer, whose changed
    /// rectangle is `rect` in window coordinates.
    pub fn flush(&mut self, i: usize, rect: Rect) -> Result<(), Refusal> {
        let w = self
            .windows
            .get_mut(i)
            .and_then(Option::as_mut)
            .ok_or(Refusal::Invalid)?;
        if !w.legacy {
            return Err(Refusal::NotAllowed);
        }
        let damage = Scene::changed(w.rect, &[rect])?;
        w.posted = Some(0);
        self.add_damage(damage);
        Ok(())
    }

    /// The window `i` goes: its place on the screen is to be shown again.
    pub fn destroy(&mut self, i: usize) -> Option<Window> {
        let w = self.windows.get_mut(i)?.take()?;
        // A window of the first revision always has its line to say.
        if w.legacy || w.current.is_some() || w.posted.is_some() {
            self.add_damage(w.rect);
        }
        Some(w)
    }

    /// Starts a frame when none is in progress and damage waits: the
    /// damage, clipped to the screen. Each window's posted buffer is taken.
    pub fn begin(&mut self) -> Option<Rect> {
        if self.frame {
            return None;
        }
        let d = self.damage.take()?;
        let x1 = (d.x + d.w).min(WIDTH);
        let y1 = (d.y + d.h).min(HEIGHT);
        if d.x >= x1 || d.y >= y1 {
            return None;
        }
        for w in self.windows.iter_mut().flatten() {
            let Some(b) = w.posted.take() else {
                continue;
            };
            if w.legacy {
                w.current = Some(0);
            } else {
                w.retired = w.current.replace(b);
                w.bufs[b as usize] = Buf::Taken;
            }
            w.in_frame = true;
        }
        self.frame = true;
        Some(Rect {
            x: d.x,
            y: d.y,
            w: x1 - d.x,
            h: y1 - d.y,
        })
    }

    /// The frame is shown (or failed): what it frees of each window.
    pub fn end(&mut self, shown: bool) -> [Ended; MAX_WINDOWS] {
        let mut out = [Ended::default(); MAX_WINDOWS];
        for (w, e) in self.windows.iter_mut().zip(out.iter_mut()) {
            let Some(w) = w else {
                continue;
            };
            e.in_frame = core::mem::take(&mut w.in_frame);
            if let Some(r) = w.retired.take() {
                w.bufs[r as usize] = Buf::Free;
                e.freed = Some(r);
            }
        }
        self.frame = false;
        if shown {
            self.frames += 1;
        }
        out
    }

    /// The windows with something to show, bottom first.
    fn order(&self) -> ([u8; MAX_WINDOWS], usize) {
        let mut at = [0u8; MAX_WINDOWS];
        let mut n = 0;
        for (i, w) in self.windows.iter().enumerate() {
            if w.is_some_and(|w| w.current.is_some()) {
                // Insertion by `seq`: the oldest first.
                let seq = |k: u8| self.windows[k as usize].map_or(0, |w| w.seq);
                let mut p = n;
                while p > 0 && seq(at[p - 1]) > seq(i as u8) {
                    at[p] = at[p - 1];
                    p -= 1;
                }
                at[p] = i as u8;
                n += 1;
            }
        }
        (at, n)
    }
}

/// Where the pixels of a window's buffer are.
pub trait Source {
    /// The bytes of buffer `buffer` of window `window`: at least `stride`
    /// times the window's height.
    fn pixels(&self, window: usize, buffer: u8) -> &[u8];
}

/// One band of the frame, from line `row` of `damage`: the lines
/// `row..row + BAND_ROWS` (to the damage's end) of the damage's columns
/// are made in `fb`, the screen's bytes. The topmost window that covers
/// the band whole is its base, and the windows above it lie over it; a
/// band no window covers whole starts black. The next line to make, which
/// is the damage's end when the frame is done.
pub fn compose(scene: &Scene, damage: Rect, row: u32, fb: &mut [u8], src: &impl Source) -> u32 {
    let y0 = row.max(damage.y);
    let y1 = (y0 + BAND_ROWS).min(damage.y + damage.h);
    let (x0, x1) = (damage.x, damage.x + damage.w);
    if y0 >= y1 {
        return damage.y + damage.h;
    }
    let (order, n) = scene.order();
    let window = |k: u8| scene.window(k as usize).copied();
    // The topmost window over the whole band.
    let base = order[..n].iter().rposition(|&k| {
        window(k).is_some_and(|w| {
            w.rect.x <= x0
                && w.rect.x + w.rect.w >= x1
                && w.rect.y <= y0
                && w.rect.y + w.rect.h >= y1
        })
    });
    if base.is_none() {
        for y in y0..y1 {
            let at = (y * STRIDE + x0 * 4) as usize;
            fb[at..at + ((x1 - x0) * 4) as usize].fill(0);
        }
    }
    for &k in &order[base.unwrap_or(0)..n] {
        let Some(w) = window(k) else {
            continue;
        };
        let Some(b) = w.current else {
            continue;
        };
        let (wx0, wx1) = (x0.max(w.rect.x), x1.min(w.rect.x + w.rect.w));
        let (wy0, wy1) = (y0.max(w.rect.y), y1.min(w.rect.y + w.rect.h));
        if wx0 >= wx1 || wy0 >= wy1 {
            continue;
        }
        let pixels = src.pixels(k as usize, b);
        let len = ((wx1 - wx0) * 4) as usize;
        for y in wy0..wy1 {
            let from = ((y - w.rect.y) * w.stride + (wx0 - w.rect.x) * 4) as usize;
            let to = (y * STRIDE + wx0 * 4) as usize;
            fb[to..to + len].copy_from_slice(&pixels[from..from + len]);
        }
    }
    y1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: u32, y: u32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    /// Buffers of fixed bytes, a byte value for each window and buffer.
    struct Flat(Vec<Vec<u8>>);

    impl Source for Flat {
        fn pixels(&self, window: usize, buffer: u8) -> &[u8] {
            &self.0[window * BUFFERS + buffer as usize]
        }
    }

    fn flat(fill: &[(usize, u8, u8, usize)]) -> Flat {
        let mut v = vec![Vec::new(); MAX_WINDOWS * BUFFERS];
        for &(w, b, value, bytes) in fill {
            v[w * BUFFERS + b as usize] = vec![value; bytes];
        }
        Flat(v)
    }

    fn make(scene: &mut Scene, label: u64, ctx: u64, r: Rect, count: u8) -> usize {
        let i = scene.create(label, ctx, r, false, 0).unwrap();
        scene.attach(i, count, r.w * 4).unwrap();
        i
    }

    /// Runs one whole frame into `fb`.
    fn frame(scene: &mut Scene, fb: &mut [u8], src: &impl Source) -> [Ended; MAX_WINDOWS] {
        let d = scene.begin().expect("a frame");
        let mut row = d.y;
        while row < d.y + d.h {
            row = compose(scene, d, row, fb, src);
        }
        scene.end(true)
    }

    fn screen() -> Vec<u8> {
        vec![0xEE; (STRIDE * HEIGHT) as usize]
    }

    fn at(fb: &[u8], x: u32, y: u32) -> u8 {
        fb[(y * STRIDE + x * 4) as usize]
    }

    #[test]
    fn a_window_needs_the_screen_and_its_context_a_share() {
        let mut s = Scene::new();
        assert_eq!(
            s.create(1, 7, rect(600, 0, 41, 10), false, 0),
            Err(Refusal::Invalid)
        );
        assert_eq!(
            s.create(1, 7, rect(0, 0, 0, 10), false, 0),
            Err(Refusal::Invalid)
        );
        for k in 0..PER_CONTEXT as u64 {
            s.create(k, 7, rect(0, 0, 10, 10), false, 0).unwrap();
        }
        assert_eq!(
            s.create(9, 7, rect(0, 0, 10, 10), false, 0),
            Err(Refusal::Limit)
        );
        // Another context has its own share, until the table is full.
        for k in 0..(MAX_WINDOWS - PER_CONTEXT) as u64 {
            s.create(100 + k, 8, rect(0, 0, 10, 10), false, 0).unwrap();
        }
        assert_eq!(
            s.create(200, 9, rect(0, 0, 10, 10), false, 0),
            Err(Refusal::Limit)
        );
        assert_eq!(s.open(), MAX_WINDOWS as u32);
        assert_eq!(s.created(), MAX_WINDOWS as u32);
    }

    #[test]
    fn a_taken_place_is_not_given() {
        let mut s = Scene::new();
        let a = s.create(1, 1, rect(0, 0, 8, 8), false, 0).unwrap();
        assert_eq!(a, 0);
        s.destroy(a);
        // Place 0 is free in the scene but its pages are still going.
        let b = s.create(2, 1, rect(0, 0, 8, 8), false, 0b1).unwrap();
        assert_eq!(b, 1);
        assert_eq!(s.create(3, 1, rect(0, 0, 8, 8), false, 0b11).unwrap(), 2);
        let all = u8::MAX;
        assert_eq!(
            s.create(4, 2, rect(0, 0, 8, 8), false, all),
            Err(Refusal::Limit)
        );
        assert_eq!(s.create(5, 2, rect(0, 0, 8, 8), false, 0).unwrap(), 0);
    }

    #[test]
    fn attach_is_once_and_checks_the_stride() {
        let mut s = Scene::new();
        let i = s.create(1, 1, rect(0, 0, 100, 10), false, 0).unwrap();
        assert_eq!(s.attach(i, 0, 400), Err(Refusal::Invalid));
        assert_eq!(s.attach(i, 4, 400), Err(Refusal::Invalid));
        assert_eq!(s.attach(i, 2, 399), Err(Refusal::Invalid));
        assert_eq!(s.post(i, 0, &[]), Err(Refusal::NotAllowed));
        assert_eq!(s.attach(i, 2, 400), Ok(()));
        assert_eq!(s.attach(i, 2, 400), Err(Refusal::Busy));
        assert_eq!(s.attach(5, 1, 400), Err(Refusal::Invalid));
    }

    #[test]
    fn a_post_checks_the_buffer_the_rectangles_and_the_state() {
        let mut s = Scene::new();
        let i = make(&mut s, 1, 1, rect(10, 20, 100, 50), 2);
        assert_eq!(s.post(i, 2, &[]), Err(Refusal::Invalid));
        assert_eq!(s.post(i, 0, &[rect(0, 0, 101, 1)]), Err(Refusal::Invalid));
        assert_eq!(s.post(i, 0, &[rect(0, 0, 0, 1)]), Err(Refusal::Invalid));
        assert_eq!(
            s.post(i, 0, &[rect(0, 0, 1, 1); MAX_RECTS + 1]),
            Err(Refusal::Invalid)
        );
        // The refusals left nothing posted and no damage.
        assert!(!s.busy());
        assert_eq!(s.post(i, 0, &[]), Ok(None));
        assert!(s.busy());
        assert_eq!(s.post(i, 0, &[]), Err(Refusal::Busy));
        // The latest wins: buffer 1 replaces the posted 0, which is free.
        assert_eq!(s.post(i, 1, &[rect(5, 5, 10, 10)]), Ok(Some(0)));
        assert_eq!(
            s.window(i).unwrap().bufs,
            [Buf::Free, Buf::Posted, Buf::Free]
        );
        assert_eq!(s.post(5, 0, &[]), Err(Refusal::Invalid));
    }

    #[test]
    fn the_damage_is_the_union_of_the_posts_in_screen_coordinates() {
        let mut s = Scene::new();
        let i = make(&mut s, 1, 1, rect(10, 20, 100, 50), 2);
        s.post(i, 0, &[rect(0, 0, 5, 5), rect(90, 40, 10, 10)])
            .unwrap();
        s.post(i, 1, &[rect(50, 0, 1, 1)]).unwrap();
        assert_eq!(s.begin(), Some(rect(10, 20, 100, 50)));
    }

    #[test]
    fn a_frame_takes_the_posted_buffer_and_frees_the_replaced_one_when_shown() {
        let mut s = Scene::new();
        let i = make(&mut s, 1, 1, rect(0, 0, 4, 4), 2);
        let src = flat(&[(i, 0, 1, 64), (i, 1, 2, 64)]);
        let mut fb = screen();
        s.post(i, 0, &[]).unwrap();
        assert!(!s.window(i).unwrap().in_frame);
        let ended = frame(&mut s, &mut fb, &src);
        assert_eq!(
            ended[i],
            Ended {
                freed: None,
                in_frame: true
            }
        );
        assert_eq!(at(&fb, 0, 0), 1);
        assert_eq!(
            s.window(i).unwrap().bufs,
            [Buf::Taken, Buf::Free, Buf::Free]
        );
        // The next post is taken: buffer 0 goes free only with the frame.
        s.post(i, 1, &[]).unwrap();
        let d = s.begin().unwrap();
        assert_eq!(s.window(i).unwrap().bufs[0], Buf::Taken);
        let mut row = d.y;
        while row < d.y + d.h {
            row = compose(&s, d, row, &mut fb, &src);
        }
        let ended = s.end(true);
        assert_eq!(
            ended[i],
            Ended {
                freed: Some(0),
                in_frame: true
            }
        );
        assert_eq!(at(&fb, 0, 0), 2);
        assert_eq!(
            s.window(i).unwrap().bufs,
            [Buf::Free, Buf::Taken, Buf::Free]
        );
        assert_eq!(s.frames(), 2);
        assert!(!s.busy());
    }

    #[test]
    fn a_post_during_a_frame_waits_for_the_next() {
        let mut s = Scene::new();
        let i = make(&mut s, 1, 1, rect(0, 0, 4, 4), 2);
        s.post(i, 0, &[]).unwrap();
        s.begin().unwrap();
        assert!(s.framing());
        assert_eq!(s.begin(), None);
        s.post(i, 1, &[]).unwrap();
        assert_eq!(s.begin(), None);
        let ended = s.end(true);
        assert!(ended[i].in_frame);
        assert!(s.busy());
        assert!(s.begin().is_some());
    }

    #[test]
    fn a_frame_that_failed_counts_no_frame() {
        let mut s = Scene::new();
        let i = make(&mut s, 1, 1, rect(0, 0, 4, 4), 1);
        s.post(i, 0, &[]).unwrap();
        s.begin().unwrap();
        s.end(false);
        assert_eq!(s.frames(), 0);
    }

    #[test]
    fn the_newest_window_is_on_top_and_a_black_screen_stays_black() {
        let mut s = Scene::new();
        let a = make(&mut s, 1, 1, rect(0, 0, 20, 20), 1);
        let b = make(&mut s, 2, 1, rect(10, 10, 20, 20), 1);
        let src = flat(&[(a, 0, 0xA, 20 * 20 * 4), (b, 0, 0xB, 20 * 20 * 4)]);
        let mut fb = screen();
        s.post(a, 0, &[]).unwrap();
        s.post(b, 0, &[]).unwrap();
        frame(&mut s, &mut fb, &src);
        assert_eq!(at(&fb, 5, 5), 0xA);
        assert_eq!(at(&fb, 15, 15), 0xB);
        assert_eq!(at(&fb, 25, 25), 0xB);
        // Inside the damage and under no window: black: the old 0xEE is gone.
        assert_eq!(at(&fb, 25, 5), 0);
        // Outside the damage: untouched.
        assert_eq!(at(&fb, 40, 40), 0xEE);
    }

    #[test]
    fn a_window_that_goes_is_painted_out() {
        let mut s = Scene::new();
        let a = make(&mut s, 1, 1, rect(0, 0, 8, 8), 1);
        let src = flat(&[(a, 0, 0xA, 8 * 8 * 4)]);
        let mut fb = screen();
        s.post(a, 0, &[]).unwrap();
        frame(&mut s, &mut fb, &src);
        assert_eq!(at(&fb, 3, 3), 0xA);
        assert!(!s.busy());
        let gone = s.destroy(a).unwrap();
        assert_eq!(gone.label, 1);
        assert!(s.busy());
        frame(&mut s, &mut fb, &src);
        assert_eq!(at(&fb, 3, 3), 0);
        assert_eq!(s.open(), 0);
        assert_eq!(s.find(1), None);
        assert!(s.destroy(a).is_none());
    }

    #[test]
    fn a_window_that_never_posted_leaves_no_damage_when_it_goes() {
        let mut s = Scene::new();
        let a = make(&mut s, 1, 1, rect(0, 0, 8, 8), 1);
        s.destroy(a);
        assert!(!s.busy());
    }

    #[test]
    fn the_legacy_window_flushes_its_one_buffer() {
        let mut s = Scene::new();
        let i = s.create(1, 1, SCREEN, true, 0).unwrap();
        assert!(s.has_legacy());
        assert_eq!(s.window(i).unwrap().stride, STRIDE);
        assert_eq!(s.post(i, 0, &[]), Err(Refusal::NotAllowed));
        assert_eq!(s.flush(i, rect(0, 0, 641, 1)), Err(Refusal::Invalid));
        let src = flat(&[(i, 0, 7, (STRIDE * HEIGHT) as usize)]);
        let mut fb = screen();
        s.flush(i, rect(100, 100, 50, 10)).unwrap();
        s.flush(i, rect(120, 100, 50, 10)).unwrap();
        let d = s.begin().unwrap();
        assert_eq!(d, rect(100, 100, 70, 10));
        let mut row = d.y;
        while row < d.y + d.h {
            row = compose(&s, d, row, &mut fb, &src);
        }
        let ended = s.end(true);
        assert_eq!(
            ended[i],
            Ended {
                freed: None,
                in_frame: true
            }
        );
        assert_eq!(at(&fb, 100, 100), 7);
        assert_eq!(at(&fb, 169, 109), 7);
        assert_eq!(at(&fb, 170, 100), 0xEE);
        assert_eq!(at(&fb, 99, 100), 0xEE);
        // A native window refuses FLUSH.
        let n = make(&mut s, 2, 1, rect(0, 0, 4, 4), 1);
        assert_eq!(s.flush(n, rect(0, 0, 1, 1)), Err(Refusal::NotAllowed));
    }

    #[test]
    fn a_band_is_a_few_lines_and_the_frame_ends_at_the_damage() {
        let mut s = Scene::new();
        let i = s.create(1, 1, SCREEN, true, 0).unwrap();
        let src = flat(&[(i, 0, 1, (STRIDE * HEIGHT) as usize)]);
        let mut fb = screen();
        s.flush(i, SCREEN).unwrap();
        let d = s.begin().unwrap();
        let mut bands = 0;
        let mut row = d.y;
        while row < d.y + d.h {
            let next = compose(&s, d, row, &mut fb, &src);
            assert_eq!(next, (row + BAND_ROWS).min(HEIGHT));
            row = next;
            bands += 1;
        }
        assert_eq!(bands, HEIGHT.div_ceil(BAND_ROWS));
        assert_eq!(row, HEIGHT);
        // A band past the damage is a no-op that says the frame is done.
        assert_eq!(compose(&s, d, HEIGHT, &mut fb, &src), HEIGHT);
        s.end(true);
    }

    #[test]
    fn the_covering_window_is_the_base_and_nothing_under_it_is_read() {
        let mut s = Scene::new();
        // A window under with no readable pixels (an empty source) and a
        // covering one above: the band never reads the one under.
        let a = make(&mut s, 1, 1, rect(0, 0, 8, 8), 1);
        let b = make(&mut s, 2, 1, rect(0, 0, 16, 16), 1);
        let src = flat(&[(b, 0, 9, 16 * 16 * 4)]);
        let mut fb = screen();
        s.post(b, 0, &[]).unwrap();
        s.post(a, 0, &[]).unwrap();
        // `a` has a posted buffer too but its source is empty: it is the
        // older one, under `b`, and `b` covers the band whole.
        let d = s.begin().unwrap();
        assert_eq!(d, rect(0, 0, 16, 16));
        let mut row = d.y;
        while row < d.y + d.h {
            row = compose(&s, d, row, &mut fb, &src);
        }
        assert_eq!(at(&fb, 2, 2), 9);
        s.end(true);
    }
}
