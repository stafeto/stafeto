// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the loads of the frame-time probe decide, apart from the calls they
//! make. The loads (the programs `frame-load` in its roles, the role `L` of
//! `net-probe` and the role `load` of `data-probe`) run through the phases of
//! one schedule, and all of them read it from here, so a phase starts and ends
//! for every load at the same moment of the guest's clock:
//!
//! - `phases`: the phases, the scene and the loads of each, and where each lies
//!   on the clock;
//! - `paint`: what the paced client draws in each period and the rectangle it
//!   posts;
//! - `loads`: the loop of the file load and the pieces of the network load;
//! - `report`: the lines the conductor prints.
//!
//! Everything builds for the host, where `cargo test -p frame-load` runs it.

#![cfg_attr(not(test), no_std)]

pub mod loads;
pub mod paint;
pub mod phases;
pub mod report;
