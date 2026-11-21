// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The image of the scene demo and its probe (apps/wfc-demo, the C functions of
//! `<WF/wfc.h>` in a static program): the services of the POSIX probes, the
//! display driver, the compositor (under the name `gpu`) and the demo, the
//! holder of the scene (`table::COMP_SCENES` gives its session the scene's
//! mark). The demo starts the producers (/bin/wfc-producer) with `posix_spawn`,
//! whose sessions are clones with no mark, so they are windows of ordinary
//! contexts. The table of `window` with the demo as its program. The demo and
//! each child it spawns inherit the record's quota, so the process service's
//! pool holds four of them: the two producers, the child that checks it has no
//! device, and one more.

use super::ramfs::{PIPE, POSIX, POSIX_ABI_TABLE, PROCS_QUOTA, RAM_FIFO_CLOCKED};
use super::{Record, comp, entropy};
use crate::PAGE;

const fn table(args: &'static [u8]) -> [Record; 9] {
    [
        RAM_FIFO_CLOCKED,
        Record {
            quota: POSIX_ABI_TABLE[1].quota + 4 * PROCS_QUOTA + 384 * PAGE,
            ..POSIX_ABI_TABLE[1]
        },
        POSIX_ABI_TABLE[2],
        PIPE,
        comp::DISPLAY,
        comp::COMPOSITOR,
        Record {
            name: "wfc-demo",
            program: "wfc-demo",
            args,
            connects: &["ramfs", "pipe", "clock", "posix", "entropy", "gpu"],
            root: true,
            quota: PROCS_QUOTA,
            ..POSIX
        },
        entropy::RNG,
        entropy::ENTROPY,
    ]
}

/// The probe: the checks, 100 commits and 100 changes with the pauses the host
/// takes its screenshots in.
pub const TABLE: &[Record] = &table(b"wfc-demo\0--probe\0");

/// The probe under -icount: no pauses, the services' steps counted.
pub const STEPS_TABLE: &[Record] = &table(b"wfc-demo\0--probe\0--quick\0");
