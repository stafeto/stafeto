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

use super::net::{NET_LAUNCHER, NET_VZ_TABLE};
use super::{BENCH_CPUS, Record};

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The launcher of the shell: the process service gives the shell and its
/// children the CPUs of the record that started them.
pub const BENCH_LAUNCHER: Record = Record {
    cpus: BENCH_CPUS,
    ..NET_LAUNCHER
};

const fn bench_table() -> [Record; 10] {
    assert!(NET_VZ_TABLE.len() == 10);
    let mut out = [NET_VZ_TABLE[0]; 10];
    let mut at = 0;
    let mut launchers = 0;
    while at < 10 {
        out[at] = if str_eq(NET_VZ_TABLE[at].name, NET_LAUNCHER.name) {
            launchers += 1;
            BENCH_LAUNCHER
        } else {
            NET_VZ_TABLE[at]
        };
        at += 1;
    }
    assert!(launchers == 1);
    out
}

const TABLE: [Record; 10] = bench_table();

/// The image of the shell with the network service on VZ, with the shell's
/// processes on all four CPUs: the record of `NET_LAUNCHER` by name, so that
/// a reordered `NET_VZ_TABLE` never puts the mask on another service.
pub const BENCH_VZ_TABLE: &[Record] = &TABLE;
