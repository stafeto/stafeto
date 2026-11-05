// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the image of the probe of F-Stack on its loopback
//! (`cargo xtask fstack-probe`): the shell's table with a larger quota for
//! the shell's commands, since `fstack-probe` carries a whole TCP/IP stack
//! (its zones, a thousand connections, 16 MiB through the loopback). No
//! network service: the stack has its own loopback interface.

use super::Record;
use super::ramfs::{BUSYBOX_DIALOG_POOL, BUSYBOX_DIALOG_TABLE, POSIX_ABI_TABLE};
use crate::PAGE;

/// The quota of the launcher, which the shell and `fstack-probe` get: the
/// probe's stack takes its memory as the process's own.
pub const FSTACK_COMMAND_QUOTA: u64 = 16384 * PAGE;

// FSTACK_TABLE copies the shell's records by number.
const _: () = assert!(BUSYBOX_DIALOG_TABLE.len() == 9);

/// The process service: the shell's pool and four quotas of the larger
/// size, which a child takes from the pool whole: the launcher, the shell,
/// the shell's child that execs the probe, and one to spare.
const PROCESS_SERVICE: Record = Record {
    quota: POSIX_ABI_TABLE[1].quota + BUSYBOX_DIALOG_POOL + 4 * FSTACK_COMMAND_QUOTA,
    ..BUSYBOX_DIALOG_TABLE[2]
};

const LAUNCHER: Record = Record {
    quota: FSTACK_COMMAND_QUOTA,
    ..BUSYBOX_DIALOG_TABLE[5]
};

/// The shell's table with the quotas above.
pub const FSTACK_TABLE: &[Record] = &[
    BUSYBOX_DIALOG_TABLE[0],
    BUSYBOX_DIALOG_TABLE[1],
    PROCESS_SERVICE,
    BUSYBOX_DIALOG_TABLE[3],
    BUSYBOX_DIALOG_TABLE[4],
    LAUNCHER,
    BUSYBOX_DIALOG_TABLE[6],
    BUSYBOX_DIALOG_TABLE[7],
    BUSYBOX_DIALOG_TABLE[8],
];

/// The image of the probe of F-Stack on the second network device
/// (`cargo xtask fstack-probe device`): the table of the image with both
/// network devices, with the larger quota for the shell's commands, as above
/// (the pool of the process service holds the four quotas of the shell's
/// image and not the sixteen of the commands of the image with the network:
/// the network service needs the memory).
const DEVICE_PROCESS_SERVICE: Record = Record {
    quota: POSIX_ABI_TABLE[1].quota + BUSYBOX_DIALOG_POOL + 4 * FSTACK_COMMAND_QUOTA,
    ..super::net::NET_TWO_TABLE[2]
};

const DEVICE_LAUNCHER: Record = Record {
    quota: FSTACK_COMMAND_QUOTA,
    ..super::net::NET_TWO_TABLE[5]
};

pub const FSTACK_DEVICE_TABLE: &[Record] = &[
    super::net::NET_TWO_TABLE[0],
    super::net::NET_TWO_TABLE[1],
    DEVICE_PROCESS_SERVICE,
    super::net::NET_TWO_TABLE[3],
    super::net::NET_TWO_TABLE[4],
    DEVICE_LAUNCHER,
    super::net::NET_TWO_TABLE[6],
    super::net::NET_TWO_TABLE[7],
    super::net::NET_TWO_TABLE[8],
    super::net::NET_TWO_TABLE[9],
];
