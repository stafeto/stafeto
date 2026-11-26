// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The structures and constants of `<stafeto/window.h>`, as the C header
//! lays them out. The `const` assertions below fix each size, alignment and
//! offset; the header holds the same numbers in `_Static_assert`s, so a
//! change of one side without the other does not build.

use core::mem::{align_of, offset_of, size_of};

/// `STAFETO_WINDOW_XRGB8888`, `STAFETO_WINDOW_ARGB8888` and
/// `STAFETO_WINDOW_A8`: the numbers of `proto_comp::FORMAT_XRGB8888`,
/// `FORMAT_ARGB8888` and `FORMAT_A8`.
pub const XRGB8888: u32 = 1;
pub const ARGB8888: u32 = 3;
pub const A8: u32 = 4;

/// The bytes of a line of `width` points of `format` (`proto_comp::line_bytes`).
pub const fn line_bytes(format: u32, width: u32) -> Option<u32> {
    proto_comp::line_bytes(format, width)
}
/// `STAFETO_WINDOW_BUFFERS_MAX`, `_RECTS_MAX` and `_EVENTS_MAX`.
pub const BUFFERS_MAX: usize = 3;
pub const RECTS_MAX: usize = 4;
pub const EVENTS_MAX: usize = 32;
/// The bit of `stafeto_window_wait` that says the ring holds events
/// (`STAFETO_WINDOW_EVENTS`); the bits 0 to 2 are the buffers
/// (`STAFETO_WINDOW_BUFFER(k)`, `1 << k`).
pub const EVENTS: u32 = 1 << 3;
/// The mask of the bits the service sends: buffers 0 to 2 and the events.
pub const BITS: u32 = 0xf;
/// `STAFETO_WINDOW_EVENTS_LOST`.
pub const EVENTS_LOST: u32 = 1;
/// `STAFETO_WINDOW_EVENT_KEY` and the others: the kinds of `proto_comp`.
pub const EVENT_KEY: u16 = 1;
pub const EVENT_MOVE: u16 = 2;
pub const EVENT_BUTTON: u16 = 3;
pub const EVENT_FOCUS_IN: u16 = 4;
pub const EVENT_FOCUS_OUT: u16 = 5;

/// `struct stafeto_screen`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Screen {
    pub width: u32,
    pub height: u32,
    pub format: u32,
    pub flags: u32,
    pub reserved: [u32; 4],
}

/// `struct stafeto_window`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
    pub buffers: u32,
    pub generation: u32,
    pub pixels: [usize; BUFFERS_MAX],
}

/// `struct stafeto_rect`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// `struct stafeto_window_event`: the 16 bytes of `proto_comp::Event`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowEvent {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
    pub x: i32,
    pub y: i32,
}

const _: () = {
    assert!(size_of::<Screen>() == 32 && align_of::<Screen>() == 4);
    assert!(offset_of!(Screen, height) == 4 && offset_of!(Screen, format) == 8);
    assert!(offset_of!(Screen, flags) == 12 && offset_of!(Screen, reserved) == 16);
    assert!(size_of::<Window>() == 48 && align_of::<Window>() == 8);
    assert!(offset_of!(Window, height) == 4);
    assert!(offset_of!(Window, stride) == 8);
    assert!(offset_of!(Window, format) == 12);
    assert!(offset_of!(Window, buffers) == 16);
    assert!(offset_of!(Window, generation) == 20);
    assert!(offset_of!(Window, pixels) == 24);
    assert!(size_of::<Rect>() == 16 && align_of::<Rect>() == 4);
    assert!(offset_of!(Rect, y) == 4 && offset_of!(Rect, w) == 8 && offset_of!(Rect, h) == 12);
    assert!(size_of::<WindowEvent>() == proto_comp::EVENT_LEN && align_of::<WindowEvent>() == 4);
    assert!(offset_of!(WindowEvent, code) == 2);
    assert!(offset_of!(WindowEvent, value) == 4);
    assert!(offset_of!(WindowEvent, x) == 8);
    assert!(offset_of!(WindowEvent, y) == 12);
    // The numbers of the protocol.
    assert!(XRGB8888 == proto_comp::FORMAT_XRGB8888);
    assert!(ARGB8888 == proto_comp::FORMAT_ARGB8888);
    assert!(A8 == proto_comp::FORMAT_A8);
    assert!(BUFFERS_MAX == proto_comp::BUFFERS);
    assert!(RECTS_MAX == proto_comp::MAX_RECTS);
    assert!(EVENTS_MAX == proto_comp::MAX_EVENTS);
    assert!(EVENTS as u64 == proto_comp::EVENTS_BIT);
    assert!(EVENTS_LOST == proto_comp::LOST);
    assert!(EVENT_KEY == proto_comp::KEY);
    assert!(EVENT_MOVE == proto_comp::MOVE);
    assert!(EVENT_BUTTON == proto_comp::BUTTON);
    assert!(EVENT_FOCUS_IN == proto_comp::FOCUS_IN);
    assert!(EVENT_FOCUS_OUT == proto_comp::FOCUS_OUT);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_of_a_mask_is_a_byte_a_point_rounded_to_four() {
        assert_eq!(line_bytes(A8, 1), Some(4));
        assert_eq!(line_bytes(A8, 4), Some(4));
        assert_eq!(line_bytes(A8, 5), Some(8));
        assert_eq!(line_bytes(A8, 640), Some(640));
        assert_eq!(line_bytes(A8, u32::MAX), None);
        assert_eq!(line_bytes(XRGB8888, 640), Some(2560));
        assert_eq!(line_bytes(ARGB8888, 3), Some(12));
        assert_eq!(line_bytes(XRGB8888, u32::MAX), None);
    }
}
