// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The image of the display demo and its probe (apps/wfd-demo, the C
//! functions of `<WF/wfd.h>` in a static program): the services of the POSIX
//! probes, the display driver and the demo, which starts its own file once,
//! and whose copy takes the screen from the driver itself. There is no
//! composition service in the image: the process's `Display` session, which
//! the name `gpu` gives it, leads to the driver. The table of `posix-display`
//! with the demo as its program.

use super::ramfs::{PIPE, POSIX, POSIX_ABI_TABLE, PROCS_QUOTA, RAM_FIFO_CLOCKED};
use super::{Record, entropy};
use crate::PAGE;

const fn table(args: &'static [u8]) -> [Record; 8] {
    [
        RAM_FIFO_CLOCKED,
        Record {
            quota: POSIX_ABI_TABLE[1].quota + 3 * PROCS_QUOTA + 384 * PAGE,
            ..POSIX_ABI_TABLE[1]
        },
        POSIX_ABI_TABLE[2],
        PIPE,
        super::gpu::GPU,
        Record {
            name: "wfd-demo",
            program: "wfd-demo",
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

/// The probe: the checks, 100 frames and 100 moves with the pauses the host
/// takes its screenshots in.
pub const TABLE: &[Record] = &table(b"wfd-demo\0--probe\0");

/// The probe under -icount: no pauses, the driver's steps counted.
pub const STEPS_TABLE: &[Record] = &table(b"wfd-demo\0--probe\0--quick\0");
