// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The structures and refusals of `<stafeto/manager.h>`, the window manager's
//! calls on the composition service's MANAGE operations, as logic with no
//! kernel call in it. The `const` assertions fix each layout; the header holds
//! the same numbers in `_Static_assert`s.

use crate::errno;
use core::mem::{align_of, offset_of, size_of};
use proto_comp::{Info, TEXT_MAX, WindowRecord};
use proto_wire::Status;

/// `STAFETO_MANAGER_WINDOWS_MAX`: the most windows LIST gives
/// (`proto_comp::STATS_WINDOWS`, the service's `MAX_WINDOWS`).
pub const WINDOWS_MAX: usize = 16;
/// `STAFETO_MANAGER_NO_WINDOW`: the follower of LINK that breaks the link.
pub const NO_WINDOW: u32 = proto_comp::NO_WINDOW;
/// `STAFETO_MANAGER_EVENT_CREATE`, `_CLOSE`, `_TITLE` and `_RESIZED`: the kinds
/// of the manager's ring that no window's ring has.
pub const EVENT_CREATE: u16 = proto_comp::CREATE;
pub const EVENT_CLOSE: u16 = proto_comp::CLOSE;
pub const EVENT_TITLE: u16 = proto_comp::TITLE;
pub const EVENT_RESIZED: u16 = proto_comp::RESIZED;
/// `STAFETO_MANAGER_TITLE` and `_APP_ID`: what a TITLE event's `x` says
/// changed.
pub const CHANGED_TITLE: i32 = 1;
pub const CHANGED_APP: i32 = 2;
/// `STAFETO_MANAGER_SHOWN` and `_FOCUSED`: the flags of a listed window.
pub const SHOWN: u32 = proto_comp::SHOWN;
pub const FOCUSED: u32 = proto_comp::FOCUSED;
/// `STAFETO_MANAGER_INFO_LEGACY` and the others: the flags of `info`.
pub const INFO_LEGACY: u32 = proto_comp::INFO_LEGACY;
pub const INFO_ARGB: u32 = proto_comp::INFO_ARGB;
pub const INFO_LEADER: u32 = proto_comp::INFO_LEADER;
pub const INFO_FOLLOWER: u32 = proto_comp::INFO_FOLLOWER;
pub const INFO_OWN: u32 = proto_comp::INFO_MANAGER;

/// `struct stafeto_manager_window`: a record of LIST (28 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManagerWindow {
    pub id: u32,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub flags: u32,
    pub depth: u32,
}

impl From<WindowRecord> for ManagerWindow {
    fn from(r: WindowRecord) -> ManagerWindow {
        ManagerWindow {
            id: r.id,
            x: r.x,
            y: r.y,
            w: r.w,
            h: r.h,
            flags: r.flags,
            depth: r.depth,
        }
    }
}

/// `struct stafeto_manager_info`: the flags, the capacity and the two texts of
/// a window, each as a C string.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagerInfo {
    pub flags: u32,
    pub cap_w: u32,
    pub cap_h: u32,
    pub title: [u8; TEXT_MAX + 1],
    pub app_id: [u8; TEXT_MAX + 1],
    pub reserved: [u8; 2],
}

impl From<&Info> for ManagerInfo {
    fn from(i: &Info) -> ManagerInfo {
        let mut out = ManagerInfo {
            flags: i.flags,
            cap_w: i.cap_w,
            cap_h: i.cap_h,
            title: [0; TEXT_MAX + 1],
            app_id: [0; TEXT_MAX + 1],
            reserved: [0; 2],
        };
        out.title[..i.title_len].copy_from_slice(i.title());
        out.app_id[..i.app_len].copy_from_slice(i.app());
        out
    }
}

/// The errno of the status a manager's call came back with: NOT_ALLOWED (the
/// session has no manager's mark) is EPERM, BUSY (another session holds the
/// subscription) EBUSY, INVALID (no such window, a size or place the service
/// does not take) EINVAL, REVOKED and NO_DEVICE ENODEV; the others as a
/// window's call has them.
pub fn status(status: Status) -> i32 {
    match status {
        Status::Unknown(proto_comp::NOT_ALLOWED) => errno::EPERM,
        other => errno::status(other),
    }
}

const _: () = {
    assert!(size_of::<ManagerWindow>() == proto_comp::WINDOW_RECORD);
    assert!(align_of::<ManagerWindow>() == 4);
    assert!(offset_of!(ManagerWindow, x) == 4 && offset_of!(ManagerWindow, y) == 8);
    assert!(offset_of!(ManagerWindow, w) == 12 && offset_of!(ManagerWindow, h) == 16);
    assert!(offset_of!(ManagerWindow, flags) == 20 && offset_of!(ManagerWindow, depth) == 24);
    assert!(size_of::<ManagerInfo>() == 144 && align_of::<ManagerInfo>() == 4);
    assert!(offset_of!(ManagerInfo, cap_w) == 4 && offset_of!(ManagerInfo, cap_h) == 8);
    assert!(offset_of!(ManagerInfo, title) == 12);
    assert!(offset_of!(ManagerInfo, app_id) == 77);
    assert!(offset_of!(ManagerInfo, reserved) == 142);
    assert!(WINDOWS_MAX == proto_comp::STATS_WINDOWS);
    assert!(CHANGED_TITLE == 1 && CHANGED_APP == 2);
};

#[cfg(test)]
mod tests {
    use super::*;
    use proto_comp::code;

    #[test]
    fn a_record_of_list_is_the_c_structure() {
        let record = WindowRecord {
            id: 7,
            x: 1,
            y: 2,
            w: 3,
            h: 4,
            flags: SHOWN | FOCUSED,
            depth: 5,
        };
        let window = ManagerWindow::from(record);
        assert_eq!(
            [
                window.id,
                window.x,
                window.y,
                window.w,
                window.h,
                window.flags,
                window.depth
            ],
            [7, 1, 2, 3, 4, 3, 5]
        );
    }

    #[test]
    fn the_texts_of_info_are_c_strings() {
        let mut info = Info {
            flags: INFO_ARGB,
            cap_w: 640,
            cap_h: 400,
            title_len: 5,
            app_len: TEXT_MAX,
            title: [0; TEXT_MAX],
            app: [b'a'; TEXT_MAX],
        };
        info.title[..5].copy_from_slice(b"hello");
        let out = ManagerInfo::from(&info);
        assert_eq!(out.flags, INFO_ARGB);
        assert_eq!((out.cap_w, out.cap_h), (640, 400));
        assert_eq!(&out.title[..6], b"hello\0");
        assert!(out.title[6..].iter().all(|&b| b == 0));
        // The longest text still ends in a NUL.
        assert!(out.app_id[..TEXT_MAX].iter().all(|&b| b == b'a'));
        assert_eq!(out.app_id[TEXT_MAX], 0);
    }

    #[test]
    fn the_managers_refusals_have_their_errno() {
        assert_eq!(status(code(proto_comp::NOT_ALLOWED)), errno::EPERM);
        assert_eq!(status(code(proto_comp::BUSY)), errno::EBUSY);
        assert_eq!(status(code(proto_comp::INVALID)), errno::EINVAL);
        assert_eq!(status(code(proto_comp::REVOKED)), errno::ENODEV);
        assert_eq!(status(Status::Ok), 0);
        assert_eq!(status(Status::BadSize), errno::EIO);
    }
}
