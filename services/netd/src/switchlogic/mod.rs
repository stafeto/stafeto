// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the switch decides, apart from the device and the threads (note
//! Sh4): the consumers' rings (`ring`), the tables (`tables`), where a
//! frame goes and what a consumer may send (`route`), and the commands
//! between the stack thread and the switch thread (`commands`), and which
//! frames carry a sum a stack need not check (`sums`). Nothing
//! here allocates or touches a device; the host tests run all of it.

pub mod commands;
pub mod ring;
pub mod route;
pub mod sums;
pub mod tables;
