// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The composition service (services/compositor) and the image of its probe
//! (tests/comp-probe): the display driver (`DISPLAY`, the record of
//! `gpu::GPU` under the name `display`) has the compositor as its one
//! client, and the compositor takes the name `gpu`, so that a program that
//! connects to `gpu` (the launcher of the games image, the probes, the
//! place `Display` of every process) meets the compositor and sees no
//! other change. The compositor is the driver's client by `connects`
//! (and the input service's where the image has one: `COMPOSITOR_KEYS`),
//! and the driver names no input service, so the focus is the compositor's
//! to hand out.
//!
//! The compositor holds the one buffer of the screen the driver gave it,
//! the buffers of its windows' clients (mapped for reading) and, for a
//! program that knows no windows, the driver's pool (a source of the driver's,
//! mapped for reading and writing, whose handle goes to that program): the
//! pool is the driver's object and its pages are the driver's, so the quota
//! holds the service's program (about 57 pages with pixman, which the windows
//! are put together by), the arena of pixman's allocations (8 pages), the
//! rings of events (3 pages), the tables of its mappings and its 64 KiB stack.
//! The 250 pages of a buffer of its own that the quota held until the direct
//! frame are gone. The base image keeps `INIT_RESERVE_PAGES` free after its
//! services started (`cargo xtask pkg-identity`) and init gives the pool of
//! the process service the rest of its quota (`INIT_SLACK_PAGES`,
//! `POOL_MIN_PAGES` in `base.rs`): a change of this record's quota goes into
//! or comes out of that pool by itself.
//!
//! Level 32 (design of graphics, 'Processes'): above the processes of POSIX
//! (31 and below), whose clients call it, and below the driver (33) and the
//! input service (34), which it calls; the services at 40 and above never
//! call it.

use super::gpu;
use super::{GENERAL_CPUS, Kind, Record, Restart, Shares};
use crate::PAGE;
use crate::watch::Watch;

const MS: u64 = 1_000_000;

/// The display driver as the images with a compositor have it: the record
/// of the driver without a connection to the input service.
pub const DISPLAY: Record = Record {
    name: "display",
    ..gpu::GPU
};

/// The compositor, under the name its clients connect to.
pub const COMPOSITOR: Record = Record {
    name: "gpu",
    program: "compositor",
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 1000 * MS,
    }),
    priority: 32,
    ceiling: 32,
    quota: 150 * PAGE,
    handle_limit: 128,
    restart: Restart::Always,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &["display"],
    args: &[],
    dma: &[],
    quiesce: &[],
    start: &[],
    release: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
    budgets: &[],
    free: 0,
    broken_after: None,
};

/// The compositor of the images that take keys: it asks the input service
/// for the focus of the window of the first revision.
pub const COMPOSITOR_KEYS: Record = Record {
    connects: &["display", "input"],
    ..COMPOSITOR
};

/// The own arguments of the compositor's record that keep the free run, the
/// frame as soon as the device is ready (a period of 0; the cap is not read):
/// two words of 8 bytes. The image that measures the frames a second of the
/// path (`doom-measure`) uses them, so that its series stays comparable; every
/// other image takes the defaults of the frame clock (60 Hz).
pub const FREE_RUN: &[u8] = &[0; 16];

/// The compositor of the images that take keys, in the free run.
pub const COMPOSITOR_KEYS_FREE: Record = Record {
    args: FREE_RUN,
    ..COMPOSITOR_KEYS
};

/// The probe (role `w`): a window of its own with two buffers, a pattern,
/// then another buffer; it ends holding the window. The quota is the
/// buffers it makes (four objects of 63 pages, a small one and a second
/// window's 10) and its stack.
pub const PROBE: Record = Record {
    name: "comp-probe",
    program: "comp-probe",
    kind: Kind::Client,
    priority: 30,
    ceiling: 30,
    quota: 640 * PAGE,
    handle_limit: 48,
    restart: Restart::Never,
    console: true,
    log: false,
    trace: false,
    windows: &[],
    bindings: &[],
    connects: &["gpu"],
    args: b"w",
    dma: &[],
    quiesce: &[],
    start: &[],
    release: &[],
    trusted: false,
    root: false,
    shares: Shares::CREATOR,
    cpus: GENERAL_CPUS,
    waits: &[],
    budgets: &[],
    free: 0,
    broken_after: None,
};

/// The second probe (role `l`): waits for the first one's window to go,
/// then asks for the screen as a program of the first revision does.
const PROBE_B: Record = Record {
    name: "comp-probe-b",
    args: b"l",
    ..PROBE
};

/// The third probe (role `x`): waits until the second one's window is shown
/// directly from its pool, then puts a window of its own over it and ends.
const PROBE_C: Record = Record {
    name: "comp-probe-c",
    args: b"x",
    ..PROBE
};

/// The fourth probe (role `s`): holds a scene. It waits until the others are
/// done, then commits scenes of windows of its own (`table::COMP_SCENES` gives
/// its session the scene's mark).
const PROBE_S: Record = Record {
    name: "comp-probe-s",
    args: b"s",
    ..PROBE
};

/// The compositor of the images of the probes that calibrate the prices of its bands
/// before its first request (the feature `calibrate`: about 1.3 s of the CPU at its
/// level): the same record with a deadline of 4 s for its start (the period stays).
pub const PROBE_COMPOSITOR: Record = Record {
    kind: Kind::Service(Watch {
        period_ns: 250 * MS,
        deadline_ns: 4000 * MS,
    }),
    ..COMPOSITOR
};

/// The probe's image on QEMU.
pub const TABLE: &[Record] = &[DISPLAY, PROBE_COMPOSITOR, PROBE, PROBE_B, PROBE_C, PROBE_S];

#[cfg(test)]
mod tests {
    use super::*;

    /// The calibrating compositor of the probes differs in its deadline alone, and a
    /// deadline holds at least three periods.
    #[test]
    fn the_calibrating_compositor_differs_in_its_deadline_alone() {
        let (Kind::Service(a), Kind::Service(b)) = (PROBE_COMPOSITOR.kind, COMPOSITOR.kind) else {
            panic!("services");
        };
        assert_eq!(a.period_ns, b.period_ns);
        assert!(a.deadline_ns > b.deadline_ns);
        assert!(a.deadline_ns / 3 >= a.period_ns);
        assert_eq!(PROBE_COMPOSITOR.quota, COMPOSITOR.quota);
        assert_eq!(PROBE_COMPOSITOR.connects, COMPOSITOR.connects);
    }

    /// The free run is two zero words as the service reads them; the record
    /// is the compositor of the keys image with only those arguments changed.
    #[test]
    fn the_free_run_record_differs_in_its_arguments_alone() {
        assert_eq!(FREE_RUN.len(), 16);
        assert!(FREE_RUN.iter().all(|b| *b == 0));
        assert_eq!(COMPOSITOR_KEYS_FREE.args, FREE_RUN);
        assert_eq!(COMPOSITOR_KEYS_FREE.connects, COMPOSITOR_KEYS.connects);
        assert_eq!(COMPOSITOR_KEYS_FREE.quota, COMPOSITOR_KEYS.quota);
        assert_eq!(COMPOSITOR_KEYS_FREE.name, "gpu");
        assert!(COMPOSITOR_KEYS.args.is_empty());
    }
}
