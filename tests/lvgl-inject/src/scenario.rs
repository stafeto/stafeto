// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The scenario of the LVGL demo: the places of its widgets and the 22 events
//! that press them. The places are those of `ports/lvgl/scene.h` (the demo,
//! the reference program on the host and this program read one source in
//! turn), and a host test of xtask parses that file and holds every number
//! here to it. The file has no dependency, so xtask includes it with `#[path]`.

/// One event as the compositor's INJECT takes it: `kind` (1 KEY, 2 MOVE, 3
/// BUTTON), `code`, `value`, and the place `x`, `y` on the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
    pub x: i32,
    pub y: i32,
}

pub const KEY: u16 = 1;
pub const MOVE: u16 = 2;
pub const BUTTON: u16 = 3;
/// Linux's BTN_LEFT, and the keys of h and i.
pub const BTN_LEFT: u16 = 0x110;
pub const KEY_H: u16 = 35;
pub const KEY_I: u16 = 23;

// The places of `scene.h`.
pub const BUTTON_X: i32 = 20;
pub const BUTTON_Y: i32 = 120;
pub const BUTTON_W: i32 = 140;
pub const BUTTON_H: i32 = 44;
pub const CHECK_X: i32 = 20;
pub const CHECK_Y: i32 = 190;
pub const SWITCH_X: i32 = 200;
pub const SWITCH_Y: i32 = 186;
pub const SWITCH_W: i32 = 60;
pub const SWITCH_H: i32 = 30;
pub const SLIDER_X: i32 = 20;
pub const SLIDER_Y: i32 = 250;
pub const SLIDER_W: i32 = 400;
pub const SLIDER_H: i32 = 20;
pub const AREA_X: i32 = 20;
pub const AREA_Y: i32 = 300;
pub const AREA_W: i32 = 400;
pub const AREA_H: i32 = 44;

/// Where each click lands: the middle of the button, a point inside the
/// check box (10 points in), the middle of the switch, three quarters along
/// the slider, the middle of the text area.
pub const BUTTON_AT: (i32, i32) = (BUTTON_X + BUTTON_W / 2, BUTTON_Y + BUTTON_H / 2);
/// The second click on the button lands at another point of it: the
/// compositor makes no event for a motion to the place the pointer is at, so a
/// second move to BUTTON_AT would be dropped.
pub const BUTTON_AGAIN: (i32, i32) = (BUTTON_AT.0 + 10, BUTTON_AT.1 + 4);
pub const CHECK_AT: (i32, i32) = (CHECK_X + 10, CHECK_Y + 10);
pub const SWITCH_AT: (i32, i32) = (SWITCH_X + SWITCH_W / 2, SWITCH_Y + SWITCH_H / 2);
pub const SLIDER_AT: (i32, i32) = (SLIDER_X + SLIDER_W * 3 / 4, SLIDER_Y + SLIDER_H / 2);
pub const AREA_AT: (i32, i32) = (AREA_X + AREA_W / 2, AREA_Y + AREA_H / 2);

/// The number of events, and of those that change state (a button or a key
/// going down or up; a MOVE only moves the point).
pub const EVENTS: usize = 22;
pub const CHANGES: usize = 16;

const fn mv((x, y): (i32, i32)) -> Row {
    Row {
        kind: MOVE,
        code: 0,
        value: 0,
        x,
        y,
    }
}

const fn button(value: i32, (x, y): (i32, i32)) -> Row {
    Row {
        kind: BUTTON,
        code: BTN_LEFT,
        value,
        x,
        y,
    }
}

const fn key(code: u16, value: i32) -> Row {
    Row {
        kind: KEY,
        code,
        value,
        x: 0,
        y: 0,
    }
}

/// The scenario, in the order it is injected: the button twice (at two
/// points), the check box, the switch, the slider, the text area (each a move, a press and a
/// release), then h and i.
pub const ROWS: [Row; EVENTS] = [
    mv(BUTTON_AT),
    button(1, BUTTON_AT),
    button(0, BUTTON_AT),
    mv(BUTTON_AGAIN),
    button(1, BUTTON_AGAIN),
    button(0, BUTTON_AGAIN),
    mv(CHECK_AT),
    button(1, CHECK_AT),
    button(0, CHECK_AT),
    mv(SWITCH_AT),
    button(1, SWITCH_AT),
    button(0, SWITCH_AT),
    mv(SLIDER_AT),
    button(1, SLIDER_AT),
    button(0, SLIDER_AT),
    mv(AREA_AT),
    button(1, AREA_AT),
    button(0, AREA_AT),
    key(KEY_H, 1),
    key(KEY_H, 0),
    key(KEY_I, 1),
    key(KEY_I, 0),
];

/// How many rows change state: every row but a MOVE.
pub const fn changes() -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < ROWS.len() {
        if ROWS[i].kind != MOVE {
            n += 1;
        }
        i += 1;
    }
    n
}
