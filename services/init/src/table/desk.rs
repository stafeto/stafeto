// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The image of the desk (`boot-desk.img`, xtask desk-probe): the services of
//! the POSIX programs, the display driver, the keyboard's driver, the tablet's
//! driver, the compositor with both devices, and the window manager `desk`, a
//! process of POSIX with the manager's mark (`table::COMP_POSIX_MANAGERS`). The
//! record `desk` runs the manager (`apps/desk`, `ports/desk`) and restarts it
//! whenever it ends (`Restart::Always`): a manager that restarts frames the
//! windows that are open, as the new ones. Its arguments start three clients of
//! the probe (`tests/desk-client`) one after the other, the third of which
//! ignores a request to close, and make the manager print the list of the
//! windows after each change (`--trace`); the probe of the desk (xtask
//! `desk-probe`) drives the pointer and the keyboard and reads those lines. The
//! C probe of the manager's calls (`tests/posix-manager`, xtask `desk-probe
//! --api`) runs in the same record under the name `desk` in an image of its own.
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

use super::ramfs::{PIPE, POSIX, POSIX_ABI_TABLE, RAM_FIFO_CLOCKED};
use super::{Record, Restart, comp, entropy, focus, input};
use crate::PAGE;

/// The quota of the manager, and of each program it starts (a child gets its
/// parent's quota). The manager's pages are those of its windows and a little
/// else: the panel (640 by 24 points) and each frame (the size of the window it
/// frames and its edges: 408 by 328 points is 131 pages a buffer) are objects of
/// its own, 45 pages for the panel with what the manager holds at the start and
/// 262 for each frame (`desk: memory` lines of the probe: 45, 307, 569, 831 and
/// 1 093 own pages with the panel and one to four frames). With a quota of 1 000
/// pages the manager held the panel and three frames (831 pages) and left the
/// fourth out (ENOMEM, the window stays without a frame), so what it has besides
/// its windows is under 169 pages. 2 200 pages hold the panel and seven frames
/// (45 + 7 * 262 = 1 879 pages) with 321 over, twice what the manager holds
/// besides them. A frame the quota does not hold is left out, whatever its size.
const QUOTA: u64 = 2200 * PAGE;

/// The programs the manager starts at once and the room one more needs.
const CHILDREN: u64 = 4;

/// The compositor of the desk: the display driver, the keyboard's driver and the
/// tablet's driver.
pub const COMPOSITOR: Record = Record {
    connects: &["display", "input", "pointer"],
    ..comp::COMPOSITOR
};

/// The arguments of the manager: the list of the windows after each change, and
/// the three clients of the probe, each started when the one before has its
/// window (APPID,PATH,NAME,X,Y,W,H,COLOUR[,stubborn]). `gamma` ignores a request
/// to close.
const ARGS: &[u8] = b"desk\0--trace\0\
--spawn\0alpha,/bin/desk-client,alpha,60,80,200,120,C04040\0\
--spawn\0beta,/bin/desk-client,beta,300,105,220,140,40A040\0\
--spawn\0gamma,/bin/desk-client,gamma,100,230,180,100,4040C0,stubborn\0";

/// The window manager: a process of POSIX at level 22, ceiling 23, restarted
/// whenever it ends.
pub const DESK: Record = Record {
    name: "desk",
    program: "desk",
    args: ARGS,
    connects: &["ramfs", "pipe", "clock", "posix", "entropy", "gpu"],
    priority: 22,
    ceiling: 23,
    root: true,
    restart: Restart::Always,
    quota: QUOTA,
    ..POSIX
};

/// The desk image's table.
pub const TABLE: &[Record] = &[
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + CHILDREN * QUOTA + 384 * PAGE,
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

/// The arguments of the manager of the run with a panel, six frames of 408 by 328 points and six
/// clients of 400 by 300: 13 windows (the panel and the frames are the manager's, seven of the
/// eight places it has). The names are short and the program is `/bin/dc` (the image's copy of
/// the client), for the own arguments of a record hold 240 bytes at most.
pub const MANY_ARGS: &[u8] = b"desk\0--trace\0\
--spawn\0a,/bin/dc,a,4,26,400,300,A0\0\
--spawn\0b,/bin/dc,b,4,26,400,300,B0\0\
--spawn\0c,/bin/dc,c,4,26,400,300,C0\0\
--spawn\0d,/bin/dc,d,4,26,400,300,D0\0\
--spawn\0e,/bin/dc,e,4,26,400,300,E0\0\
--spawn\0f,/bin/dc,f,4,26,400,300,F0\0";

/// The same with a second window (`x`) for two of the clients: eight windows of clients, the
/// manager's panel and seven frames (its eight places), sixteen windows, the eighth frame
/// refused.
pub const SIXTEEN_ARGS: &[u8] = b"desk\0--trace\0\
--spawn\0a,/bin/dc,a,4,26,400,300,A0\0\
--spawn\0b,/bin/dc,b,4,26,400,300,B0\0\
--spawn\0c,/bin/dc,c,4,26,400,300,C0\0\
--spawn\0d,/bin/dc,d,4,26,400,300,D0\0\
--spawn\0e,/bin/dc,e,4,26,400,300,E0,x\0\
--spawn\0f,/bin/dc,f,4,26,400,300,F0,x\0";

const _: () = assert!(MANY_ARGS.len() <= 240 && SIXTEEN_ARGS.len() <= 240);

/// The table of the run with six clients of 400 by 300 (xtask desk-probe many).
pub const MANY_TABLE: &[Record] = &[
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 6 * QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    comp::DISPLAY,
    input::INPUT,
    focus::DESK_POINTER,
    COMPOSITOR,
    Record {
        args: MANY_ARGS,
        ..DESK
    },
    entropy::RNG,
    entropy::ENTROPY,
];

/// The table of the run with eight windows of clients of 400 by 300 (xtask desk-probe sixteen).
pub const SIXTEEN_TABLE: &[Record] = &[
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 6 * QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    comp::DISPLAY,
    input::INPUT,
    focus::DESK_POINTER,
    COMPOSITOR,
    Record {
        args: SIXTEEN_ARGS,
        ..DESK
    },
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

    /// The record restarts the manager whenever it ends, and its arguments are the
    /// manager's: the trace and the three clients of the probe, each a file of the
    /// image, the last one a client that ignores a request to close.
    #[test]
    fn the_manager_restarts_and_starts_the_clients_of_the_probe() {
        let desk = named("desk");
        assert_eq!(desk.restart, Restart::Always);
        assert_eq!(desk.program, "desk");
        let args: Vec<&str> = desk
            .args
            .split(|&b| b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| std::str::from_utf8(a).unwrap())
            .collect();
        assert_eq!(&args[..2], ["desk", "--trace"]);
        let specs: Vec<&str> = args[2..].chunks(2).map(|c| c[1]).collect();
        assert_eq!(specs.len(), 3);
        for (flag, spec) in args[2..].chunks(2).map(|c| (c[0], c[1])) {
            assert_eq!(flag, "--spawn");
            let fields: Vec<&str> = spec.split(',').collect();
            assert_eq!(fields[1], "/bin/desk-client");
            assert_eq!(
                fields[0], fields[2],
                "the application id is the window's name"
            );
        }
        assert!(specs[2].ends_with(",stubborn"));
    }

    /// The quota holds the panel and seven frames of 408 by 328 points with what
    /// the manager holds besides them, and the process service's pool holds the
    /// manager's children at the same quota (the measures are in the comment of
    /// `QUOTA`).
    #[test]
    fn the_quota_holds_the_panel_and_seven_frames_and_the_pool_the_children() {
        let desk = named("desk");
        assert!(desk.quota >= (45 + 7 * 262 + 169) * PAGE);
        let service = named("posix");
        assert!(service.quota >= POSIX_ABI_TABLE[1].quota + CHILDREN * desk.quota);
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
