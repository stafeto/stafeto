// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The image of the desk (`boot-desk.img`, xtask desk-probe): the services of
//! the POSIX programs, the display driver, the keyboard's driver, the tablet's
//! driver, the compositor with both devices, and the window manager `desk`, a
//! process of POSIX with the manager's mark (`table::COMP_POSIX_MANAGERS`). Until
//! the manager of the desk exists (steps 5 and 6 of the plan of M1), the record
//! runs the C probe of the manager's calls (`tests/posix-manager`), which
//! subscribes, frames the window of a client it starts, and answers the keys and
//! the pointer.
//!
//! The keyboard is the transport 15 at 0xa001e00 on the page 0xa001000 (INTID
//! 63) and the tablet the transport 6 at 0xa000c00 on the page 0xa000000 (INTID
//! 54), so each device has a page of its own to map: the two transports 15 and 13
//! of the other images share a page, which a table gives to one record. The page
//! 0xa000000 is the network card's in the images that have one (transport 7); this
//! image has none. QEMU puts both with `-device
//! virtio-keyboard-device,bus=virtio-mmio-bus.15` and `-device
//! virtio-tablet-device,bus=virtio-mmio-bus.6` (xtask `qemu::KEYBOARD` and
//! `qemu::DESK_TABLET`). The display service has 0xa002000 and the entropy driver
//! 0xa003000.
//!
//! The compositor is the record of the images that take keys with the pointer's
//! driver as well: its connections are `display`, `input` (the keyboard) and
//! `pointer` (the tablet).
//!
//! Levels (plan of M1, section 5): the manager runs at 22 under the ceiling 23, where
//! the holders of the locks of the POSIX layer run, below the compositor (32), the
//! display driver (33) and the input drivers (34), and below the POSIX services.
//! The record has no budget: the image has no tasks of real time, and the manager
//! is held back only by threads at its own level or below.

use super::ramfs::{PIPE, POSIX, POSIX_ABI_TABLE, PROCS_QUOTA, RAM_FIFO_CLOCKED};
use super::{Record, comp, entropy, focus, input};
use crate::PAGE;

/// The pages of the window buffers the manager and the clients it starts have
/// open at once, as in `window.rs`: a resizable XRGB8888 window of 640 by 400
/// is 250 pages a buffer (two buffers, 500) and the small windows add about 40.
/// The manager's record and the POSIX service's record, which pays for the
/// clients, carry it.
const WINDOW_PAGES: u64 = 540;

/// The compositor of the desk: the display driver, the keyboard's driver and the
/// tablet's driver.
pub const COMPOSITOR: Record = Record {
    connects: &["display", "input", "pointer"],
    ..comp::COMPOSITOR
};

/// The window manager: a process of POSIX at level 22, ceiling 23 (the program is
/// the C probe of the manager's calls until `apps/desk` takes its place).
pub const DESK: Record = Record {
    name: "desk",
    program: "posix-manager",
    args: b"posix-manager\0",
    connects: &["ramfs", "pipe", "clock", "posix", "entropy", "gpu"],
    priority: 22,
    ceiling: 23,
    root: true,
    quota: PROCS_QUOTA + WINDOW_PAGES * PAGE,
    ..POSIX
};

/// The desk image's table.
pub const TABLE: &[Record] = &[
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 3 * PROCS_QUOTA + (384 + WINDOW_PAGES) * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    comp::DISPLAY,
    input::INPUT,
    focus::DESK_POINTER,
    COMPOSITOR,
    DESK,
    entropy::RNG,
    entropy::ENTROPY,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> &'static Record {
        TABLE.iter().find(|r| r.name == name).unwrap()
    }

    /// The keyboard and the tablet have pages of their own and no other record
    /// has either page.
    #[test]
    fn the_keyboard_and_the_tablet_map_pages_of_their_own() {
        let keyboard = named("input").windows;
        let tablet = named("pointer").windows;
        assert_eq!((keyboard.len(), tablet.len()), (1, 1));
        assert_eq!(keyboard[0].base, 0x0a00_1000);
        assert_eq!(tablet[0].base, 0x0a00_0000);
        assert_eq!(
            named("pointer").args,
            &focus::DESK_TRANSPORT.to_le_bytes()[..]
        );
        assert_eq!(focus::DESK_TRANSPORT, 0x0a00_0000 + 6 * 0x200);
        assert_eq!(named("pointer").bindings[0].line, 48 + 6);
        for record in TABLE
            .iter()
            .filter(|r| r.name != "input" && r.name != "pointer")
        {
            assert!(
                record
                    .windows
                    .iter()
                    .all(|w| w.base != keyboard[0].base && w.base != tablet[0].base),
                "{} maps a page of an input device",
                record.name
            );
        }
    }

    /// The compositor reads both devices, and the manager is a process of POSIX
    /// at the levels of the plan.
    #[test]
    fn the_compositor_has_both_devices_and_the_manager_the_plans_levels() {
        assert_eq!(named("gpu").connects, &["display", "input", "pointer"]);
        let desk = named("desk");
        assert!(desk.is_posix());
        assert_eq!((desk.priority, desk.ceiling), (22, 23));
        assert!(desk.budgets.is_empty());
        assert!(desk.connects.contains(&"gpu"));
        let at = |name: &str| TABLE.iter().position(|r| r.name == name).unwrap();
        assert!(at("input") < at("gpu") && at("pointer") < at("gpu") && at("gpu") < at("desk"));
    }

    /// The manager's mark goes to `desk`, though it is a process of POSIX, by its
    /// name; the others of the image have none.
    #[test]
    fn the_manager_has_the_mark_and_no_other_record_does() {
        assert_eq!(
            crate::table::comp_mark(named("desk"), b"gpu"),
            Some(crate::table::COMP_MANAGER_MARK)
        );
        assert_eq!(crate::table::comp_mark(named("desk"), b"clock"), None);
        for record in TABLE.iter().filter(|r| r.name != "desk") {
            assert_eq!(
                crate::table::comp_mark(record, b"gpu"),
                None,
                "{}",
                record.name
            );
        }
    }
}
