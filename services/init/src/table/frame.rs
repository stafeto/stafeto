// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The image for the measurements of the frame time (`boot-frame.img` and
//! `boot-frame-steps.img`, xtask frame-loads): the screen, a disk and the
//! network together, with the programs that load them (tests/frame-load, the
//! role `load` of tests/data-probe and the role `L` of tests/net-probe).
//!
//! What runs: the services of POSIX that need no process (the RAM files, the
//! pipes, the terminal service and the console's driver) and the entropy
//! service the network service wants, the network service on QEMU's user
//! network with the budgets of this image (`FRAME_NETD_BUDGETS`), the disk
//! service of the Virtio disk under the name `datadisk` and the data file
//! service over it, the display driver and the compositor (60 Hz, its
//! default), and the loads. There is no shell and no process service: nothing
//! in the image starts a program but init, and every load is a record. The
//! loads are natives at the levels of the POSIX processes, which stand below
//! the services in the same way; the services of POSIX are there for what
//! they cost the levels above them (their budgets), with no process to call
//! them. The table has all the 16 records init allows.
//!
//! The network service's budgets are the finding of the analysis of the
//! frame time: the table of the network (`net::NETD_BUDGETS`) gives the
//! service 60 % of CPU 0 (the switch thread 40 %, the stack 20 %), and above
//! the composition service (32) it leaves no frame of the smallest window the
//! room it needs in a period of 16.7 ms. This image gives the switch thread
//! 150 us of each millisecond and the stack 75 us, 22.5 % of CPU 0 in all
//! (`FRAME_NETD_PPM`); the levels do not change, the policy of the image does.
//! On a machine with several CPUs the display driver and the compositor stand
//! on CPU 1, where the network service's switch thread (a budget of CPU 0)
//! is not; with one CPU the mask falls back to it.
//!
//! The programs that keep time (the conductor, the paced client, the client of
//! the first revision) are clients at 31, the loads of files and network at 30
//! and the CPU load at 29, so that a loop that never sleeps keeps off the
//! processor none of the others: they sleep until their phases (`frame_load::phases`) and
//! work while the phase lasts. `frame-load` (the conductor) holds the input
//! session of the compositor (`COMP_INJECTORS`).

use super::entropy::ENTROPY;
use super::pkg::{BLK_DATADISK, DATAFS};
use super::ramfs::{BUSYBOX_DIALOG_TABLE, PIPE, RAM_LEGACY, TTY};
use super::{Budget, Kind, NET_SERVICE, Record, Restart, Shares, Wait, comp, net};
use crate::PAGE;

/// The budgets of the network service in this image: the switch thread 150 us
/// and the stack of CPU 0 75 us of each millisecond (22.5 % of CPU 0), the
/// stack of CPU 1 75 us (7.5 % of CPU 1).
pub const FRAME_NETD_BUDGETS: &[Budget] = &[
    Budget {
        name: "switch",
        cpu: 0,
        c_ns: 150_000,
        t_ns: 1_000_000,
        low: 1,
    },
    Budget {
        name: "stack0",
        cpu: 0,
        c_ns: 75_000,
        t_ns: 1_000_000,
        low: 1,
    },
    Budget {
        name: "stack1",
        cpu: 1,
        c_ns: 75_000,
        t_ns: 1_000_000,
        low: 1,
    },
];

/// The share of CPU 0 the network service's budgets take, in parts per
/// million: the figure the analysis of the frame time uses.
pub const FRAME_NETD_PPM: u64 = 225_000;

/// The CPUs of the display driver and the compositor: CPU 1 where there is
/// one (the switch thread of the network service has a budget on CPU 0).
pub const SCREEN_CPUS: u8 = 0b0010;

/// The network service of this image.
pub const NETD: Record = Record {
    budgets: FRAME_NETD_BUDGETS,
    ..net::NETD_QEMU
};

/// The entropy service from the boot seed alone: the image drives no device of
/// random bytes (the table is full, and the seed is what the network service's
/// sessions need).
const ENTROPY_SEED: Record = Record {
    connects: &[],
    ..ENTROPY
};

/// The display driver and the compositor on `SCREEN_CPUS`.
const DISPLAY: Record = Record {
    cpus: SCREEN_CPUS,
    ..comp::DISPLAY
};
const COMPOSITOR: Record = Record {
    cpus: SCREEN_CPUS,
    ..comp::COMPOSITOR
};

/// What every program of the image is: a client at 31 with a session of one
/// service. The clients that must run on time (the conductor, the paced
/// client, the client of the first revision) stand at 31, above the loads of
/// files and network at 30, and those above the CPU loop at 29. A higher number
/// runs first and a thread runs until it blocks or one above it wakes, so a
/// loop that never sleeps keeps off the processor every thread at its own level
/// or below it. The service at 32 stands above all of them.
const LOAD: Record = Record {
    name: "frame-load",
    program: "frame-load",
    kind: Kind::Client,
    priority: 31,
    ceiling: 31,
    quota: 64 * PAGE,
    handle_limit: 32,
    restart: Restart::Never,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &["gpu"],
    args: b"ctl",
    dma: &[],
    quiesce: &[],
    start: &[],
    release: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: super::GENERAL_CPUS,
    waits: &[],
    budgets: &[],
    free: 0,
    broken_after: None,
};

/// The conductor: the input session of the compositor (the record's name is in
/// `COMP_INJECTORS`), the counters of each phase.
pub const CTL: Record = LOAD;

/// The paced client: two buffers of the whole screen (two objects of 250
/// pages) and the window over them, and its stack.
pub const DRAW: Record = Record {
    name: "frame-draw",
    args: b"draw",
    quota: 640 * PAGE,
    ..LOAD
};

/// The client of the first revision: the driver's pool, mapped for writing
/// (250 pages the service gives it), and its stack.
pub const LEGACY: Record = Record {
    name: "frame-legacy",
    args: b"legacy",
    quota: 384 * PAGE,
    ..LOAD
};

/// The CPU load: a loop at 29, below every other program of the image, with no
/// session.
pub const CPU: Record = Record {
    name: "frame-cpu",
    args: b"cpu",
    priority: 29,
    ceiling: 29,
    connects: &[],
    ..LOAD
};

/// The file load: the mode `load` of the data probe, on the data file service.
pub const FILES: Record = Record {
    name: "frame-files",
    program: "data-probe",
    args: b"load",
    priority: 30,
    ceiling: 30,
    connects: &["datafs"],
    waits: &[Wait {
        service: "datafs",
        deadline_ms: 30_000,
    }],
    ..LOAD
};

/// The network load: the role `L` of the network probe.
pub const NET: Record = Record {
    name: "frame-net",
    program: "net-probe",
    args: b"L",
    priority: 30,
    ceiling: 30,
    connects: &[NET_SERVICE],
    ..LOAD
};

/// The table of the image: the console's driver, the RAM files, the pipes, the
/// terminal service and the entropy service (from the boot seed alone: the
/// image has no device for it), then the network, disk, display and loads. The
/// table holds MAX_RECORDS records and has all of them.
pub const TABLE: &[Record] = &[
    BUSYBOX_DIALOG_TABLE[0],
    RAM_LEGACY,
    PIPE,
    TTY,
    ENTROPY_SEED,
    NETD,
    BLK_DATADISK,
    DATAFS,
    DISPLAY,
    COMPOSITOR,
    CTL,
    DRAW,
    LEGACY,
    CPU,
    FILES,
    NET,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> &'static Record {
        TABLE.iter().find(|r| r.name == name).unwrap()
    }

    /// The table is a good table and its budgets pass `check_budgets`.
    #[test]
    fn the_table_is_good() {
        let found = crate::table::check(TABLE);
        assert!(found.is_ok(), "{found:?}");
    }

    /// The network service's budgets are the ones the analysis of the frame
    /// time uses: 150 us and 75 us of each millisecond on CPU 0, 22.5 %, and
    /// the same literals as `xtask::frame` will compute its bound with.
    #[test]
    fn the_network_service_has_the_budgets_of_the_analysis() {
        let on_cpu0: u64 = FRAME_NETD_BUDGETS
            .iter()
            .filter(|b| b.cpu == 0)
            .map(|b| b.share_ppm())
            .sum();
        assert_eq!(on_cpu0, FRAME_NETD_PPM);
        assert_eq!(FRAME_NETD_BUDGETS[0].name, "switch");
        assert_eq!(
            (FRAME_NETD_BUDGETS[0].c_ns, FRAME_NETD_BUDGETS[0].t_ns),
            (150_000, 1_000_000)
        );
        assert_eq!(
            (FRAME_NETD_BUDGETS[1].c_ns, FRAME_NETD_BUDGETS[1].t_ns),
            (75_000, 1_000_000)
        );
        // The table of the network gives it 60 % of CPU 0: a record of this
        // image must not carry those budgets.
        let table_cpu0: u64 = net::NETD_BUDGETS
            .iter()
            .filter(|b| b.cpu == 0)
            .map(|b| b.share_ppm())
            .sum();
        assert_eq!(table_cpu0, 600_000);
        assert_eq!(named(NET_SERVICE).budgets, FRAME_NETD_BUDGETS);
    }

    /// The share of CPU 0 all the budgets of the image take, with what the
    /// table check keeps for init: the figure the report of the step gives.
    #[test]
    fn the_budgets_of_cpu_0_take_a_third() {
        let ppm: u64 = TABLE
            .iter()
            .flat_map(|r| r.budgets.iter())
            .filter(|b| b.cpu == 0)
            .map(|b| b.share_ppm())
            .sum();
        // netd 22.5 + ramfs 5 + pipe, tty and the console 1.5 each + datafs 1.
        assert_eq!(ppm, 225_000 + 50_000 + 3 * 15_000 + 10_000, "{ppm}");
    }

    /// The compositor needs the display driver and calls nothing above it, and
    /// the loads call the compositor, the data service or the network service
    /// and nothing else.
    #[test]
    fn the_compositor_and_the_loads_connect_as_designed() {
        assert_eq!(named("gpu").connects, &["display"]);
        assert_eq!(named("display").connects, comp::DISPLAY.connects);
        for (load, connects) in [
            ("frame-load", &["gpu"][..]),
            ("frame-draw", &["gpu"]),
            ("frame-legacy", &["gpu"]),
            ("frame-cpu", &[]),
            ("frame-files", &["datafs"]),
            ("frame-net", &["net"]),
        ] {
            assert_eq!(named(load).connects, connects, "{load}");
        }
        // The compositor stands on CPU 1, away from the switch thread's CPU.
        assert_eq!(named("gpu").cpus, SCREEN_CPUS);
        assert_eq!(named("display").cpus, SCREEN_CPUS);
        assert_ne!(named(NET_SERVICE).budgets[0].cpu, 1);
        // The clients that keep time stand above the loads, and the service
        // of the screen above both: a loop that never sleeps must not keep
        // the paced client off the processor.
        let level = |n: &str| (named(n).priority, named(n).ceiling);
        for timed in ["frame-load", "frame-draw", "frame-legacy"] {
            assert_eq!(level(timed), (31, 31), "{timed}");
        }
        for load in ["frame-files", "frame-net"] {
            assert_eq!(level(load), (30, 30), "{load}");
        }
        assert_eq!(level("frame-cpu"), (29, 29));
        assert!(named("gpu").priority > 31);
    }

    /// The conductor is the one input session; the others have none.
    #[test]
    fn the_conductor_alone_has_the_input_session() {
        let marked: Vec<&str> = TABLE
            .iter()
            .filter(|r| crate::table::COMP_INJECTORS.contains(&r.name))
            .map(|r| r.name)
            .collect();
        assert_eq!(marked, ["frame-load"]);
    }

    /// The services above the compositor with no budget: each puts one sign of
    /// life and one step of init into a period, which the bound of the frame
    /// time counts (8 000 ticks each). The list is part of the contract of the
    /// image: a service added above 32 with no budget changes the bound.
    #[test]
    fn the_services_above_the_compositor_without_a_budget_are_counted() {
        let above: Vec<&str> = TABLE
            .iter()
            .filter(|r| matches!(r.kind, Kind::Service(_)))
            .filter(|r| r.priority > 32 && r.budgets.is_empty())
            .map(|r| r.name)
            .collect();
        assert_eq!(above, ["entropy", "datadisk", "display"]);
    }
}
