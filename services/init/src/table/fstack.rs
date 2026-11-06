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

/// The quota of the launcher in the images of nginx on the stack, which the
/// shell and its commands get too: the master of `nginx-fast` (6 MB of code
/// and read-only data, the settings, the shared zones) and its worker (the
/// zones of FreeBSD, the hashes, the wheel of callouts, the heap of the
/// copies below the threshold, nginx's pools and buffers, OpenSSL under
/// HTTP/2) run beside the shell.
pub const FAST_COMMAND_QUOTA: u64 = 8192 * PAGE;

/// The process service of the image of nginx on the stack: the pool of the
/// shell's image and five quotas of a command, for the shell, the master,
/// the worker, the new worker of a reload and a command of the probe.
const FAST_PROCESS_SERVICE: Record = Record {
    quota: POSIX_ABI_TABLE[1].quota + BUSYBOX_DIALOG_POOL + 5 * FAST_COMMAND_QUOTA,
    ..super::net::NET_TWO_TABLE[2]
};

const FAST_LAUNCHER: Record = Record {
    quota: FAST_COMMAND_QUOTA,
    ..super::net::NET_TWO_TABLE[5]
};

/// The image with both network devices on QEMU and `nginx-fast` (`cargo
/// xtask fast-probe nginx`).
pub const FAST_NGINX_TABLE: &[Record] = &[
    super::net::NET_TWO_TABLE[0],
    super::net::NET_TWO_TABLE[1],
    FAST_PROCESS_SERVICE,
    super::net::NET_TWO_TABLE[3],
    super::net::NET_TWO_TABLE[4],
    FAST_LAUNCHER,
    super::net::NET_TWO_TABLE[6],
    super::net::NET_TWO_TABLE[7],
    super::net::NET_TWO_TABLE[8],
    super::net::NET_TWO_TABLE[9],
];

const FAST_VZ_PROCESS_SERVICE: Record = Record {
    quota: POSIX_ABI_TABLE[1].quota + BUSYBOX_DIALOG_POOL + 5 * FAST_COMMAND_QUOTA,
    ..super::net::NET_VZ2_TABLE[2]
};

const FAST_VZ_LAUNCHER: Record = Record {
    quota: FAST_COMMAND_QUOTA,
    ..super::net::NET_VZ2_TABLE[5]
};

/// The same on Apple VZ (`cargo xtask net-vz --fast --nginx`).
pub const FAST_NGINX_VZ_TABLE: &[Record] = &[
    super::net::NET_VZ2_TABLE[0],
    super::net::NET_VZ2_TABLE[1],
    FAST_VZ_PROCESS_SERVICE,
    super::net::NET_VZ2_TABLE[3],
    super::net::NET_VZ2_TABLE[4],
    FAST_VZ_LAUNCHER,
    super::net::NET_VZ2_TABLE[6],
    super::net::NET_VZ2_TABLE[7],
    super::net::NET_VZ2_TABLE[8],
    super::net::NET_VZ2_TABLE[9],
];

/// The grant of the images of scale (`proto_init::Grant`): the children of
/// fork of the master of `nginx-fast`, the file the loader opens from
/// `/bin/nginx-fast`, get the quota of the grant and the master keeps the
/// quota of a command. On QEMU of the check (`-m 1024`) 128 MiB, on Apple
/// VZ (2 GiB) 768 MiB, which hold 100 000 connections: about 3.5 KiB each
/// and 102 MiB of the worker's own. There are two places: the worker, and
/// the new worker of a reload while the old one ends. The master of these
/// images forks workers alone (`daemon off`, no cache manager), so the two
/// places go to workers.
pub const SCALE_GRANT_PAGES: u32 = 32_768;
pub const SCALE_GRANT_PAGES_VZ: u32 = 196_608;
pub const SCALE_GRANT_PLACES: u32 = 2;
const SCALE_GRANT: [u8; proto_init::GRANT_LEN] =
    proto_init::Grant::bytes(SCALE_GRANT_PAGES, SCALE_GRANT_PLACES, "/bin/nginx-fast");
const SCALE_GRANT_VZ: [u8; proto_init::GRANT_LEN] =
    proto_init::Grant::bytes(SCALE_GRANT_PAGES_VZ, SCALE_GRANT_PLACES, "/bin/nginx-fast");

/// The process service of an image of scale: the pool of the image of
/// nginx on the stack and the places of the grant. The pages of the grant
/// are in the pool but not set apart: another child may take them first,
/// and a fork of the worker then ends with NO_MEMORY (the image of scale
/// starts nothing else that big).
const fn scale_process_service(base: Record, pages: u32, args: &'static [u8]) -> Record {
    Record {
        quota: base.quota + SCALE_GRANT_PLACES as u64 * pages as u64 * PAGE,
        args,
        ..base
    }
}

const SCALE_PROCESS_SERVICE: Record =
    scale_process_service(FAST_PROCESS_SERVICE, SCALE_GRANT_PAGES, &SCALE_GRANT);
const SCALE_VZ_PROCESS_SERVICE: Record = scale_process_service(
    FAST_VZ_PROCESS_SERVICE,
    SCALE_GRANT_PAGES_VZ,
    &SCALE_GRANT_VZ,
);

/// The image of nginx on the stack on QEMU with the grant of the worker
/// (`cargo xtask fast-probe scale`).
pub const FAST_SCALE_TABLE: &[Record] = &[
    FAST_NGINX_TABLE[0],
    FAST_NGINX_TABLE[1],
    SCALE_PROCESS_SERVICE,
    FAST_NGINX_TABLE[3],
    FAST_NGINX_TABLE[4],
    FAST_NGINX_TABLE[5],
    FAST_NGINX_TABLE[6],
    FAST_NGINX_TABLE[7],
    FAST_NGINX_TABLE[8],
    FAST_NGINX_TABLE[9],
];

/// The same on Apple VZ.
pub const FAST_SCALE_VZ_TABLE: &[Record] = &[
    FAST_NGINX_VZ_TABLE[0],
    FAST_NGINX_VZ_TABLE[1],
    SCALE_VZ_PROCESS_SERVICE,
    FAST_NGINX_VZ_TABLE[3],
    FAST_NGINX_VZ_TABLE[4],
    FAST_NGINX_VZ_TABLE[5],
    FAST_NGINX_VZ_TABLE[6],
    FAST_NGINX_VZ_TABLE[7],
    FAST_NGINX_VZ_TABLE[8],
    FAST_NGINX_VZ_TABLE[9],
];
