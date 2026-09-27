// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the boot image that ships (spec 13.4): empty in milestone
//! 1.4c. Init checks it, says that the services started and serves its
//! channel; the UART driver and the shell come into it in 1.4d.

use super::Record;

pub const TABLE: &[Record] = &[];
