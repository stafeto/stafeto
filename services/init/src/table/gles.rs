// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The image of the cube in a pbuffer (apps/gles-cube, `--pbuffer`): the
//! services of the POSIX probes and the cube, which draws with Mesa's softpipe
//! driver into a surface of EGL that has no window, so the image holds no
//! display driver and no compositor. The cube's quota is above 64 MiB, so the
//! loader grows its room for memory to 1 GiB (P6b-4a): the GLSL compiler and
//! the images of softpipe need tens of MiB, and the program itself, with Mesa
//! linked in, is 10 MiB or more.

use super::ramfs::{PIPE, POSIX, POSIX_ABI_TABLE, RAM_FIFO_CLOCKED};
use super::{Record, comp, entropy};
use crate::PAGE;

/// The cube's quota: 128 MiB.
const CUBE_QUOTA: u64 = 128 * 1024 * 1024;

/// The pbuffer probe: the cube draws ten frames and reads each back.
pub const PBUFFER_TABLE: &[Record] = &[
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + CUBE_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    Record {
        name: "gles-cube",
        program: "gles-cube",
        args: b"gles-cube\0--pbuffer\0--ascii\0\x33\0",
        connects: &["ramfs", "pipe", "clock", "posix", "entropy"],
        root: true,
        quota: CUBE_QUOTA,
        ..POSIX
    },
    entropy::RNG,
    entropy::ENTROPY,
];

/// The window probe (xtask gles-window): the services of the POSIX probes, the
/// display driver and the compositor (under the name `gpu`, which the cube's
/// place `Display` meets) and the cube, which starts its own file once: the
/// copy that draws makes a window, forks and swaps into it. The pool of the
/// process service holds the quota of the copy a spawn makes and of the child
/// of its fork, 128 MiB each.
pub const WINDOW_TABLE: &[Record] = &[
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + 2 * CUBE_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    comp::DISPLAY,
    comp::COMPOSITOR,
    Record {
        name: "gles-cube",
        program: "gles-cube",
        args: b"gles-cube\0--window\0--size\0\x31\x36\x30\0--frames\0\x36\0",
        connects: &["ramfs", "pipe", "clock", "posix", "entropy", "gpu"],
        root: true,
        quota: CUBE_QUOTA,
        ..POSIX
    },
    entropy::RNG,
    entropy::ENTROPY,
];

/// The quota of the dEQP program: the framework, Mesa and its GLSL compiler
/// are 20 MiB of code and data before the first case, and a case of the EGL
/// module makes contexts and surfaces of a few MiB.
const DEQP_QUOTA: u64 = 256 * 1024 * 1024;

/// dEQP (xtask deqp): the services of the pbuffer probe and one module of
/// VK-GL-CTS (EGL, GLES2, GLES3 or GLES31), which the image names `deqp`. The arguments of a batch of cases are the lines of
/// /etc/deqp.args in the image (tests/deqp/platform/tcuStafetoMain.cpp), so
/// the table holds none.
pub const DEQP_TABLE: &[Record] = &[
    RAM_FIFO_CLOCKED,
    Record {
        quota: POSIX_ABI_TABLE[1].quota + DEQP_QUOTA + 384 * PAGE,
        ..POSIX_ABI_TABLE[1]
    },
    POSIX_ABI_TABLE[2],
    PIPE,
    Record {
        name: "deqp",
        program: "deqp",
        args: b"deqp\0",
        connects: &["ramfs", "pipe", "clock", "posix", "entropy"],
        root: true,
        quota: DEQP_QUOTA,
        ..POSIX
    },
    entropy::RNG,
    entropy::ENTROPY,
];

const fn scene_table(args: &'static [u8]) -> [Record; 9] {
    [
        RAM_FIFO_CLOCKED,
        Record {
            quota: POSIX_ABI_TABLE[1].quota + 3 * CUBE_QUOTA + 384 * PAGE,
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
            quota: CUBE_QUOTA,
            ..POSIX
        },
        entropy::RNG,
        entropy::ENTROPY,
    ]
}

/// The probe of the graphics of Mesa (xtask gles-probe): the demo of scenes
/// (`table::COMP_SCENES` gives its session the scene's mark) starts the cube
/// and the field of cubes, each with the quota it inherits from the demo's
/// record, 128 MiB, and shows their windows. The process service's pool holds
/// three such quotas: the cube, its child that forks and swaps, and the field.
pub const TABLE: &[Record] = &scene_table(b"wfc-demo\0--gles\0");

/// The probe under -icount: no pauses, the services' steps counted.
pub const STEPS_TABLE: &[Record] = &scene_table(b"wfc-demo\0--gles\0--quick\0");
