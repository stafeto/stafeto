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
//!
//! `boot-net-bench-fast.img` (the row F1) is the image of nginx on the
//! stack on VZ (`fstack::FAST_NGINX_VZ_TABLE`, both network devices) with the
//! same one change: the launcher of the shell on the four CPUs.

use super::fstack::{FAST_NGINX_VZ_TABLE, FAST_SWITCH_VZ_TABLE};
use super::net::{NET_LAUNCHER, NET_VZ_TABLE};
use super::{BENCH_CPUS, BENCH_PINNED_CPUS, Record};

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

/// The same launcher on CPUs 1 to 3 (`BENCH_PINNED_CPUS`).
pub const BENCH_PINNED_LAUNCHER: Record = Record {
    cpus: BENCH_PINNED_CPUS,
    ..NET_LAUNCHER
};

/// Every record on the boot CPU but those on every CPU (the process service).
const fn on_cpu_0(table: [Record; 10]) -> [Record; 10] {
    let mut out = table;
    let mut at = 0;
    while at < 10 {
        if out[at].cpus != super::ALL_CPUS {
            out[at].cpus = 0b0001;
        }
        at += 1;
    }
    out
}

/// `table` with the record of the shell's launcher (found by its name) on
/// the CPUs `cpus`; the launcher keeps the quota of the table it came from.
const fn with_launcher<const N: usize>(table: &[Record], cpus: u8) -> [Record; N] {
    assert!(table.len() == N);
    let mut out = [table[0]; N];
    let mut at = 0;
    let mut launchers = 0;
    while at < N {
        out[at] = if str_eq(table[at].name, NET_LAUNCHER.name) {
            launchers += 1;
            Record { cpus, ..table[at] }
        } else {
            table[at]
        };
        at += 1;
    }
    assert!(launchers == 1);
    out
}

const TABLE: [Record; 10] = with_launcher(NET_VZ_TABLE, BENCH_CPUS);
const PINNED: [Record; 10] = with_launcher(NET_VZ_TABLE, BENCH_PINNED_CPUS);
const CPU0: [Record; 10] = on_cpu_0(with_launcher(NET_VZ_TABLE, BENCH_CPUS));
const FAST_TABLE: [Record; 10] = with_launcher(FAST_NGINX_VZ_TABLE, BENCH_CPUS);
const FAST_SWITCH_TABLE: [Record; 10] = with_launcher(FAST_SWITCH_VZ_TABLE, BENCH_CPUS);

/// The image of the shell with the network service on VZ, with the shell's
/// processes on all four CPUs: the record of `NET_LAUNCHER` by name, so that
/// a reordered `NET_VZ_TABLE` never puts the mask on another service.
pub const BENCH_VZ_TABLE: &[Record] = &TABLE;

/// The same image with the shell's processes on CPUs 1 to 3: nginx's workers
/// never run on the CPU of the network service.
pub const BENCH_PINNED_VZ_TABLE: &[Record] = &PINNED;

/// The same image with every program but the process service on CPU 0, the
/// CPU of the network service: every call of a program to it is a call on its
/// own CPU.
pub const BENCH_CPU0_VZ_TABLE: &[Record] = &CPU0;

/// The image of nginx on the stack on VZ with the shell's processes on all
/// four CPUs (the row F1).
pub const BENCH_FAST_VZ_TABLE: &[Record] = &FAST_TABLE;

/// The same on the switch: one device, the shell's processes on all four CPUs (the row F1s).
pub const BENCH_FAST_SWITCH_VZ_TABLE: &[Record] = &FAST_SWITCH_TABLE;
