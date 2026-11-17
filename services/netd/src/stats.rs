// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the switch counts, for the stack's report: shared by the switch thread of the Virtio
//! kinds (`switch.rs`) and the routed side of the ENA kind (`routed.rs`).

use crate::switchlogic::route::Reason;
use core::sync::atomic::AtomicU32;

/// The counters of the switch the stack prints.
pub struct Stats {
    pub consumers: AtomicU32,
    pub flows: AtomicU32,
    pub unconfirmed: AtomicU32,
    pub evicted: AtomicU32,
    pub expired: AtomicU32,
    pub rx_full: AtomicU32,
    pub tx_refused: AtomicU32,
    /// Frames turned back into the tables (the hairpin), and frames to the device whose
    /// destination is the shared address (the turn takes them all: stays 0).
    pub hairpin: AtomicU32,
    #[cfg_attr(not(feature = "probe"), allow(dead_code))]
    pub own_to_device: AtomicU32,
    pub drops: [AtomicU32; 7],
    pub refused_by: [AtomicU32; Reason::COUNT],
    /// The frames of the wire for consumers, and the frames of consumers sent.
    pub rx_consumer: AtomicU32,
    pub tx_consumer: AtomicU32,
    /// The frames of the wire each consumer got (the probe reads the share of each worker).
    pub rx_by: [AtomicU32; 8],
    /// Parked SYNs handed to a member that joined.
    pub park_given: AtomicU32,
    /// Packets of the loopback network routed through the tables (R-2b).
    pub looped: AtomicU32,
    /// Memberships ended by LEAVE.
    pub left: AtomicU32,
    /// Steps that found a consumer's entries waiting for the next period (the budget spent).
    pub budget_waits: AtomicU32,
    /// Frames of TCP the device completes the sum of, frames of the wire whose sum the device
    /// checked (and the stack or consumer need not), and frames whose sum the switch completed
    /// in software for a device without the offload.
    pub sum_tx: AtomicU32,
    pub sum_rx: AtomicU32,
    pub sum_soft: AtomicU32,
    /// Frames of the wire dropped because the lane of the instance they were for had no room.
    pub lane_full: AtomicU32,
    /// Merged frames the device handed over, the segments they were cut into, and the merged
    /// frames dropped whole (no plan, a sum the device did not check, a length past the chain).
    pub merged: AtomicU32,
    pub cut: AtomicU32,
    pub merged_dropped: AtomicU32,
    /// The longest merged frame seen, in bytes after the header.
    pub merged_max: AtomicU32,
    /// Frames for the stack dropped because the pool of its buffers was empty.
    pub pool_empty: AtomicU32,
    /// Frames of the segmentation offload given to the device, the chunks they were copied in,
    /// and the entries that waited for buffers of sending (counted once each).
    pub tso: AtomicU32,
    pub tso_chunks: AtomicU32,
    pub tso_waits: AtomicU32,
}

impl Stats {
    pub const fn new() -> Stats {
        Stats {
            consumers: AtomicU32::new(0),
            flows: AtomicU32::new(0),
            unconfirmed: AtomicU32::new(0),
            evicted: AtomicU32::new(0),
            expired: AtomicU32::new(0),
            rx_full: AtomicU32::new(0),
            tx_refused: AtomicU32::new(0),
            hairpin: AtomicU32::new(0),
            own_to_device: AtomicU32::new(0),
            drops: [const { AtomicU32::new(0) }; 7],
            refused_by: [const { AtomicU32::new(0) }; Reason::COUNT],
            rx_consumer: AtomicU32::new(0),
            tx_consumer: AtomicU32::new(0),
            rx_by: [const { AtomicU32::new(0) }; 8],
            park_given: AtomicU32::new(0),
            looped: AtomicU32::new(0),
            left: AtomicU32::new(0),
            budget_waits: AtomicU32::new(0),
            sum_tx: AtomicU32::new(0),
            sum_rx: AtomicU32::new(0),
            sum_soft: AtomicU32::new(0),
            lane_full: AtomicU32::new(0),
            merged: AtomicU32::new(0),
            cut: AtomicU32::new(0),
            merged_dropped: AtomicU32::new(0),
            merged_max: AtomicU32::new(0),
            pool_empty: AtomicU32::new(0),
            tso: AtomicU32::new(0),
            tso_chunks: AtomicU32::new(0),
            tso_waits: AtomicU32::new(0),
        }
    }
}

impl Default for Stats {
    fn default() -> Stats {
        Stats::new()
    }
}
