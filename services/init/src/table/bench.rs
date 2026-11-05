// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the image of the measurement of stage P7
//! (`boot-net-bench.img`, `cargo xtask linux-guest check`): the shell with
//! the network service on Apple VZ (`net::NET_VZ_TABLE`) with one change,
//! the CPUs of the shell and of the processes it starts, nginx among them:
//! all four (`BENCH_CPUS`), as the Linux guest it is measured against has
//! them. The network service stays on the boot CPU (`NETD_CPUS`), where
//! every shared interrupt line is delivered, and the other services keep
//! the CPUs of the services (`GENERAL_CPUS`).
//!
//! The image has no tasks of realtime, so the SMP decision of 2026-10-17
//! (ordinary processes on CPUs 0 and 1, CPUs 2 and 3 for realtime) does not
//! apply to it; every other image keeps it, and a test below keeps
//! `BENCH_CPUS` out of their tables.

use super::net::NET_VZ_TABLE;
use super::{BENCH_CPUS, Record};

/// The launcher of the shell: the process service gives the shell and its
/// children the CPUs of the record that started them.
pub const BENCH_LAUNCHER: Record = Record {
    cpus: BENCH_CPUS,
    ..NET_VZ_TABLE[5]
};

/// The image of the shell with the network service on VZ, with the shell's
/// processes on all four CPUs.
pub const BENCH_VZ_TABLE: &[Record] = &[
    NET_VZ_TABLE[0],
    NET_VZ_TABLE[1],
    NET_VZ_TABLE[2],
    NET_VZ_TABLE[3],
    NET_VZ_TABLE[4],
    BENCH_LAUNCHER,
    NET_VZ_TABLE[6],
    NET_VZ_TABLE[7],
    NET_VZ_TABLE[8],
    NET_VZ_TABLE[9],
];
const _: () = assert!(NET_VZ_TABLE.len() == 10);
