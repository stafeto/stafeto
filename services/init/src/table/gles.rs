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
use super::{Record, entropy};
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
