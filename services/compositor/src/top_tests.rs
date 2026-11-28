// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The top-window protocol of the scene: SET_TEXT, SIZE, CONFIGURE, CLOSE, LINK,
//! the manager's own windows and their tier.

use super::*;
use proto_comp::{CREATE, STATE_MAXIMIZED, STATES, TEXT_APP, TEXT_TITLE};

fn rect(x: u32, y: u32, w: u32, h: u32) -> Rect {
    Rect { x, y, w, h }
}

/// A window of context `ctx` of `r` with `count` buffers of a screen's worth
/// (the capacity is the whole screen), the way a client that can be resized
/// attaches.
fn big(s: &mut Scene, label: u64, ctx: u64, r: Rect, manager: bool) -> usize {
    let i = s.create_as(label, ctx, r, false, 0, manager).unwrap();
    s.attach_sized(i, 3, WIDTH * 4, u64::from(WIDTH) * u64::from(HEIGHT) * 4)
        .unwrap();
    i
}

fn shown(s: &mut Scene, i: usize) {
    s.post(i, 0, &[]).unwrap();
    s.begin().unwrap();
    s.end(true);
}

fn manager_events(s: &mut Scene) -> Vec<Event> {
    let mut out = [Event::default(); 32];
    let (n, _) = s.take_manager_events(&mut out);
    out[..n].to_vec()
}

fn events(s: &mut Scene, i: usize) -> Vec<Event> {
    let mut out = [Event::default(); 32];
    let (n, _) = s.take_events(i, &mut out);
    out[..n].to_vec()
}

#[test]
fn the_manager_holds_eight_windows_and_the_others_four() {
    let mut s = Scene::new();
    for k in 0..MANAGER_SHARE as u64 {
        s.create_as(k, 1, rect(0, 0, 10, 10), false, 0, true)
            .unwrap();
    }
    assert_eq!(
        s.create_as(99, 1, rect(0, 0, 10, 10), false, 0, true),
        Err(Refusal::Limit),
        "the ninth of the manager"
    );
    // The share is the context's: another context has four of the places left.
    for k in 0..PER_CONTEXT as u64 {
        s.create(100 + k, 2, rect(0, 0, 10, 10), false, 0).unwrap();
    }
    assert_eq!(
        s.create(200, 2, rect(0, 0, 10, 10), false, 0),
        Err(Refusal::Limit)
    );
    assert_eq!(s.open(), (MANAGER_SHARE + PER_CONTEXT) as u32);
}

#[test]
fn the_capacity_is_what_the_smallest_buffer_holds() {
    let mut s = Scene::new();
    let a = s.create(1, 1, rect(0, 0, 100, 50), false, 0).unwrap();
    assert_eq!(s.info(a).unwrap().cap_w, 0, "none before ATTACH");
    assert_eq!(s.set_size(a, 10, 10, 0), Err(Refusal::NotAllowed));
    // A stride of 800 bytes (200 points), and 40 000 bytes a buffer (50 lines).
    s.attach_sized(a, 2, 800, 40_000).unwrap();
    let info = s.info(a).unwrap();
    assert_eq!((info.cap_w, info.cap_h), (200, 50));
    assert_eq!(s.buffer_lines(a), 50);
    // A window without ATTACH's bytes is its own size.
    let b = s.create(2, 1, rect(0, 0, 30, 20), false, 0).unwrap();
    s.attach(b, 1, 120).unwrap();
    let info = s.info(b).unwrap();
    assert_eq!((info.cap_w, info.cap_h), (30, 20));
}

#[test]
fn a_size_is_refused_past_the_buffers_the_screen_the_serial_and_the_kind() {
    let mut s = Scene::new();
    let a = s.create(1, 1, rect(600, 10, 20, 20), false, 0).unwrap();
    s.attach_sized(a, 1, 800, 800 * 50).unwrap();
    // Wider than a stride holds, higher than the lines hold.
    assert_eq!(s.set_size(a, 201, 20, 0), Err(Refusal::Invalid));
    assert_eq!(s.set_size(a, 20, 51, 0), Err(Refusal::Invalid));
    assert_eq!(s.set_size(a, 0, 20, 0), Err(Refusal::Invalid));
    assert_eq!(s.set_size(a, 20, 0, 0), Err(Refusal::Invalid));
    // Inside the buffers but past the screen at the window's place (x 600).
    assert_eq!(s.set_size(a, 41, 20, 0), Err(Refusal::Invalid));
    assert_eq!(s.set_size(a, 40, 20, 0), Ok(()));
    // No CONFIGURE gave serial 1.
    assert_eq!(s.set_size(a, 20, 20, 1), Err(Refusal::Invalid));
    s.configure(a, 30, 30, 0).unwrap();
    assert_eq!(s.set_size(a, 30, 30, 1), Ok(()));
    assert_eq!(s.set_size(a, 30, 30, 2), Err(Refusal::Invalid));
    // The first revision, a mask, and a window with no buffers yet.
    let l = s.create(2, 2, SCREEN, true, 0).unwrap();
    assert_eq!(s.set_size(l, 10, 10, 0), Err(Refusal::NotAllowed));
    let m = s.create(3, 3, rect(0, 0, 8, 8), false, 0).unwrap();
    s.set_format(m, Format::A8);
    s.attach(m, 1, 8).unwrap();
    assert_eq!(s.set_size(m, 8, 8, 0), Err(Refusal::NotAllowed));
    let n = s.create(4, 4, rect(0, 0, 8, 8), false, 0).unwrap();
    assert_eq!(s.set_size(n, 8, 8, 0), Err(Refusal::NotAllowed));
    assert_eq!(s.set_size(9, 8, 8, 0), Err(Refusal::Invalid));
}

#[test]
fn the_window_has_the_new_size_when_a_frame_takes_the_buffer_that_carries_it() {
    let mut s = Scene::new();
    s.set_manager(true);
    let a = big(&mut s, 1, 1, rect(100, 50, 200, 100), false);
    shown(&mut s, a);
    let id = s.window(a).unwrap().id;
    manager_events(&mut s);
    // SIZE alone changes nothing the screen or the window show.
    s.set_size(a, 300, 150, 0).unwrap();
    assert_eq!(s.window(a).unwrap().rect, rect(100, 50, 200, 100));
    assert_eq!(s.posted_size(a), (300, 150));
    assert_eq!(s.begin(), None, "no damage: SIZE is not a change");
    // POST: the damage is the old rectangle with the new one, the window is
    // still the old size until the frame takes the buffer.
    s.post(a, 1, &[rect(0, 0, 300, 10)]).unwrap();
    assert_eq!(s.window(a).unwrap().rect, rect(100, 50, 200, 100));
    assert!(manager_events(&mut s).is_empty());
    assert_eq!(s.begin(), Some(rect(100, 50, 300, 150)));
    assert_eq!(s.window(a).unwrap().rect, rect(100, 50, 300, 150));
    s.end(true);
    assert_eq!(
        manager_events(&mut s),
        [Event::at(RESIZED, a as u16, id as i32, 300, 150)]
    );
    assert_eq!(s.posted_size(a), (300, 150));
    // A later POST keeps the size and tells nothing.
    s.post(a, 0, &[rect(0, 0, 300, 150)]).unwrap();
    assert_eq!(s.begin(), Some(rect(100, 50, 300, 150)));
    s.end(true);
    assert!(manager_events(&mut s).is_empty());
}

#[test]
fn a_shrinking_window_damages_the_old_rectangle_and_the_rectangles_are_in_the_new_size() {
    let mut s = Scene::new();
    let a = big(&mut s, 1, 1, rect(10, 10, 200, 100), false);
    shown(&mut s, a);
    s.set_size(a, 50, 40, 0).unwrap();
    // A rectangle of the old size is outside the new one.
    assert_eq!(s.post(a, 1, &[rect(0, 0, 200, 100)]), Err(Refusal::Invalid));
    // The refused POST left the size to be carried by the next.
    assert_eq!(s.posted_size(a), (50, 40));
    s.post(a, 1, &[rect(0, 0, 50, 40)]).unwrap();
    assert_eq!(s.begin(), Some(rect(10, 10, 200, 100)));
    assert_eq!(s.window(a).unwrap().rect, rect(10, 10, 50, 40));
}

#[test]
fn a_second_size_before_the_post_replaces_the_first_and_a_replaced_post_keeps_the_size() {
    let mut s = Scene::new();
    let a = big(&mut s, 1, 1, rect(0, 0, 100, 100), false);
    shown(&mut s, a);
    s.set_size(a, 150, 150, 0).unwrap();
    s.set_size(a, 120, 80, 0).unwrap();
    s.post(a, 1, &[]).unwrap();
    // Another buffer replaces it before the taking: the size stays with the
    // posted buffer, as the client drew it.
    s.post(a, 2, &[]).unwrap();
    s.begin().unwrap();
    assert_eq!(s.window(a).unwrap().rect, rect(0, 0, 120, 80));
}

#[test]
fn a_move_keeps_the_window_inside_the_screen_with_the_size_it_will_have() {
    let mut s = Scene::new();
    let a = big(&mut s, 1, 1, rect(0, 0, 100, 100), false);
    shown(&mut s, a);
    s.set_size(a, 200, 100, 0).unwrap();
    assert_eq!(s.move_to(a, 500, 0), Err(Refusal::Invalid));
    assert_eq!(s.move_to(a, 440, 0), Ok(()));
    s.post(a, 1, &[]).unwrap();
    // A move after the POST and before the taking damages both places and
    // the new size at the new place.
    s.move_to(a, 300, 100).unwrap();
    let d = s.begin().unwrap();
    assert!(d.x <= 100 && d.x + d.w >= 500 && d.y + d.h >= 200, "{d:?}");
    assert_eq!(s.window(a).unwrap().rect, rect(300, 100, 200, 100));
}

#[test]
fn a_title_and_a_kind_are_kept_and_the_manager_is_told_of_a_change_only() {
    let mut s = Scene::new();
    s.set_manager(true);
    let a = big(&mut s, 1, 1, rect(0, 0, 10, 10), false);
    let id = s.window(a).unwrap().id;
    manager_events(&mut s);
    s.set_text(a, TEXT_TITLE, b"Editor").unwrap();
    s.set_text(a, TEXT_APP, b"edit").unwrap();
    s.set_text(a, TEXT_TITLE, b"Editor").unwrap();
    assert_eq!(
        manager_events(&mut s),
        [
            Event::at(TITLE, a as u16, id as i32, 1, 0),
            Event::at(TITLE, a as u16, id as i32, 2, 0)
        ]
    );
    let info = s.info(a).unwrap();
    assert_eq!((info.title(), info.app()), (&b"Editor"[..], &b"edit"[..]));
    s.set_text(a, TEXT_TITLE, b"").unwrap();
    assert_eq!(s.info(a).unwrap().title_len, 0);
    assert_eq!(manager_events(&mut s).len(), 1);
    assert_eq!(s.set_text(a, 3, b"x"), Err(Refusal::Invalid));
    assert_eq!(s.set_text(a, 1, &[b'x'; 65]), Err(Refusal::Invalid));
    assert_eq!(s.set_text(9, 1, b"x"), Err(Refusal::Invalid));
    // A window that goes takes its texts: the next one at its place has none.
    s.destroy(a);
    let b = big(&mut s, 2, 1, rect(0, 0, 10, 10), false);
    assert_eq!(b, a);
    assert_eq!(s.info(b).unwrap().title_len, 0);
}

#[test]
fn configure_and_close_go_to_the_ring_of_the_window() {
    let mut s = Scene::new();
    let a = big(&mut s, 1, 1, rect(0, 0, 10, 10), false);
    s.configure(a, 300, 200, STATE_MAXIMIZED).unwrap();
    s.configure(a, 0, 0, 0).unwrap();
    s.close_request(a).unwrap();
    assert_eq!(
        events(&mut s, a),
        [
            Event::at(CONFIGURE, 1, 1, 300, 200),
            Event::at(CONFIGURE, 0, 2, 0, 0),
            Event::new(CLOSE_REQUEST, 0, 0)
        ]
    );
    assert_eq!(s.configure(a, WIDTH + 1, 10, 0), Err(Refusal::Invalid));
    assert_eq!(s.configure(a, 10, 0, 0), Err(Refusal::Invalid));
    assert_eq!(s.configure(a, 10, 10, 8), Err(Refusal::Invalid));
    assert_eq!(s.configure(a, WIDTH, HEIGHT, STATES), Ok(()));
    let l = s.create(2, 2, SCREEN, true, 0).unwrap();
    assert_eq!(s.configure(l, 10, 10, 0), Err(Refusal::NotAllowed));
    assert_eq!(s.close_request(l), Err(Refusal::NotAllowed));
    assert_eq!(s.close_request(9), Err(Refusal::Invalid));
    // The delivery is told.
    assert_eq!(s.delivered().windows & (1 << a), 1 << a);
}

/// A client window with its frame (a window of the manager) linked: both
/// shown, the frame under the client.
fn pair(s: &mut Scene) -> (usize, usize) {
    let c = big(s, 1, 1, rect(100, 100, 200, 150), false);
    let f = big(s, 2, 2, rect(96, 76, 208, 178), true);
    shown(s, c);
    shown(s, f);
    s.link(c, Some(f)).unwrap();
    (c, f)
}

#[test]
fn a_link_ties_a_frame_to_its_window_and_only_the_manager_s_windows_may_be_frames() {
    let mut s = Scene::new();
    let c = big(&mut s, 1, 1, rect(100, 100, 50, 50), false);
    let o = big(&mut s, 2, 1, rect(0, 0, 50, 50), false);
    let f = big(&mut s, 3, 2, rect(96, 76, 58, 78), true);
    let g = big(&mut s, 4, 2, rect(0, 0, 10, 10), true);
    assert_eq!(
        s.link(c, Some(o)),
        Err(Refusal::Invalid),
        "not the manager's"
    );
    assert_eq!(
        s.link(f, Some(g)),
        Err(Refusal::Invalid),
        "a leader of the manager"
    );
    assert_eq!(s.link(c, Some(c)), Err(Refusal::Invalid));
    assert_eq!(s.link(c, Some(9)), Err(Refusal::Invalid));
    assert_eq!(s.link(9, Some(f)), Err(Refusal::Invalid));
    s.link(c, Some(f)).unwrap();
    assert_eq!(
        s.link(c, Some(g)),
        Err(Refusal::Invalid),
        "one frame a window"
    );
    assert_eq!(
        s.link(o, Some(f)),
        Err(Refusal::Invalid),
        "one window a frame"
    );
    let info = s.info(c).unwrap();
    assert_eq!(
        info.flags & proto_comp::INFO_LEADER,
        proto_comp::INFO_LEADER
    );
    let info = s.info(f).unwrap();
    assert_eq!(
        info.flags,
        proto_comp::INFO_FOLLOWER | proto_comp::INFO_MANAGER
    );
    // Unlinking.
    s.link(c, None).unwrap();
    assert_eq!(s.info(c).unwrap().flags, 0);
    s.link(c, Some(g)).unwrap();
}

#[test]
fn a_move_of_the_window_moves_its_frame_in_the_same_call() {
    let mut s = Scene::new();
    let (c, f) = pair(&mut s);
    s.begin();
    s.end(true);
    s.move_to(c, 150, 120).unwrap();
    assert_eq!(s.window(c).unwrap().rect, rect(150, 120, 200, 150));
    assert_eq!(s.window(f).unwrap().rect, rect(146, 96, 208, 178));
    // One frame shows both places.
    let d = s.begin().unwrap();
    assert!(d.x <= 96 && d.y <= 76 && d.x + d.w >= 354 && d.y + d.h >= 274);
}

#[test]
fn a_move_that_takes_either_off_the_screen_moves_nothing() {
    let mut s = Scene::new();
    let (c, f) = pair(&mut s);
    s.begin();
    s.end(true);
    // The frame reaches 4 points left of the window: a window at x 2 would
    // leave the frame at x -2.
    assert_eq!(s.move_to(c, 2, 120), Err(Refusal::Invalid));
    assert_eq!(s.window(c).unwrap().rect, rect(100, 100, 200, 150));
    assert_eq!(s.window(f).unwrap().rect, rect(96, 76, 208, 178));
    // The frame ends below the window: a window at y 280 puts the frame off the
    // bottom edge, though the window fits.
    assert_eq!(s.move_to(c, 100, 260), Err(Refusal::Invalid));
    assert_eq!(s.window(c).unwrap().rect, rect(100, 100, 200, 150));
    assert_eq!(s.window(f).unwrap().rect, rect(96, 76, 208, 178));
    assert!(s.begin().is_none(), "nothing changed on the screen");
    // The frame alone may move on its own.
    s.move_to(f, 90, 70).unwrap();
    assert_eq!(s.window(c).unwrap().rect, rect(100, 100, 200, 150));
}

#[test]
fn a_raise_puts_the_pair_on_top_with_the_frame_directly_under() {
    let mut s = Scene::new();
    let (c, f) = pair(&mut s);
    let other = big(&mut s, 3, 3, rect(110, 110, 50, 50), false);
    shown(&mut s, other);
    let (order, n) = s.by_depth();
    assert_eq!(order[n - 1] as usize, other);
    s.raise(c).unwrap();
    let (order, n) = s.by_depth();
    assert_eq!(&order[n - 2..n], [f as u8, c as u8]);
    // No window lies between them or above.
    assert_eq!(s.hit(120, 120), Some(c));
    assert_eq!(s.hit(98, 80), Some(f));
    // Raising the frame raises the pair.
    s.raise(other).unwrap();
    s.raise(f).unwrap();
    let (order, n) = s.by_depth();
    assert_eq!(&order[n - 2..n], [f as u8, c as u8]);
    // The focus goes to the window of a pair, never to the frame.
    s.focus_on(f).unwrap();
    assert_eq!(s.focus(), Some(c));
}

#[test]
fn a_click_on_the_frame_gives_the_focus_and_the_top_to_the_window_and_the_frame_holds_the_button() {
    let mut s = Scene::new();
    let (c, f) = pair(&mut s);
    let other = big(&mut s, 3, 3, rect(110, 110, 50, 50), false);
    shown(&mut s, other);
    s.focus_on(other).unwrap();
    events(&mut s, c);
    events(&mut s, f);
    events(&mut s, other);
    s.pointer_to(98, 80);
    s.button(0x110, true);
    assert_eq!(s.focus(), Some(c));
    let (order, n) = s.by_depth();
    assert_eq!(&order[n - 2..n], [f as u8, c as u8]);
    // The frame gets the button with its own coordinates, the window none.
    assert!(events(&mut s, f).contains(&Event::at(BUTTON, 0x110, 1, 2, 4)));
    assert!(events(&mut s, c).iter().all(|e| e.kind != BUTTON));
    // The moves go to the frame while the button is held, wherever they are.
    s.pointer_to(200, 200);
    assert!(events(&mut s, f).contains(&Event::at(MOVE, 0, 0, 104, 124)));
    s.button(0x110, false);
    assert!(events(&mut s, f).contains(&Event::at(BUTTON, 0x110, 0, 104, 124)));
}

#[test]
fn hiding_and_showing_the_window_hides_and_shows_its_frame() {
    let mut s = Scene::new();
    let (c, f) = pair(&mut s);
    s.begin();
    s.end(true);
    s.set_visible(c, false).unwrap();
    assert!(!s.window(f).unwrap().visible);
    assert_eq!(s.hit(98, 80), None);
    s.begin().unwrap();
    s.end(true);
    s.set_visible(c, true).unwrap();
    assert!(s.window(f).unwrap().visible);
    assert_eq!(s.hit(98, 80), Some(f));
}

#[test]
fn the_window_going_hides_its_frame_and_ends_the_link_and_the_frame_going_leaves_the_window() {
    let mut s = Scene::new();
    s.set_manager(true);
    let (c, f) = pair(&mut s);
    let id = s.window(c).unwrap().id;
    manager_events(&mut s);
    s.destroy(c);
    assert!(!s.window(f).unwrap().visible);
    assert_eq!(s.info(f).unwrap().flags, proto_comp::INFO_MANAGER);
    assert_eq!(
        manager_events(&mut s),
        [Event::new(CLOSE, c as u16, id as i32)]
    );
    let (c, f) = pair(&mut s);
    s.destroy(f);
    assert_eq!(s.info(c).unwrap().flags, 0);
    assert!(s.window(c).unwrap().visible);
    // The frame of a window that went is free to follow another.
    let g = big(&mut s, 9, 2, rect(0, 0, 10, 10), true);
    s.link(c, Some(g)).unwrap();
}

#[test]
fn the_windows_of_the_manager_that_follow_none_lie_above_all_others() {
    let mut s = Scene::new();
    let panel = big(&mut s, 1, 1, rect(0, 0, 640, 24), true);
    let a = big(&mut s, 2, 2, rect(0, 0, 200, 200), false);
    shown(&mut s, panel);
    shown(&mut s, a);
    // The client was made and shown later, and the panel is still above it.
    let (order, n) = s.by_depth();
    assert_eq!(order[n - 1] as usize, panel);
    assert_eq!(s.hit(10, 10), Some(panel));
    s.raise(a).unwrap();
    s.focus_on(a).unwrap();
    assert_eq!(s.hit(10, 10), Some(panel));
    let (order, n) = s.by_depth();
    assert_eq!(&order[n - 2..n], [a as u8, panel as u8]);
    // A second window of the manager raised goes above the first.
    let menu = big(&mut s, 3, 1, rect(0, 0, 100, 100), true);
    shown(&mut s, menu);
    assert_eq!(s.hit(10, 10), Some(menu));
    s.raise(panel).unwrap();
    assert_eq!(s.hit(10, 10), Some(panel));
    // The focus passes to the topmost window that may have it.
    s.focus_on(panel).unwrap();
    assert_eq!(s.focus(), Some(panel));
}

#[test]
fn the_manager_hears_of_a_window_of_its_own_like_any() {
    let mut s = Scene::new();
    s.set_manager(true);
    let a = big(&mut s, 1, 1, rect(0, 0, 10, 10), true);
    assert_eq!(
        manager_events(&mut s),
        [Event::new(CREATE, a as u16, s.window(a).unwrap().id as i32)]
    );
}
