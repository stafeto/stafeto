// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the display service decides (spec 3, 3.1 to 3.5), apart from the
//! device and the calls it makes: the commands of the Virtio GPU in 2D mode
//! and their answers (`commands`), who owns the screen (`owner`), and where
//! its DMA object holds the queue and the buffers of the commands
//! (`dma`). Everything here builds for the host too, where `cargo test -p
//! virtio-gpu` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod commands;
pub mod owner;

/// The service's DMA object (`dma`, 16 pages, contiguous and uncached):
/// the control queue takes the first QUEUE_PAGES, and the commands and
/// their answers lie in the page after them, at the offsets below.
/// Uncached: no cache maintenance, only the barriers of the queue.
pub mod dma {
    use crate::commands::{COMMAND_MAX, INFO_REPLY};

    pub const PAGES: usize = 16;
    pub const PAGE: usize = virtio_mmio::PAGE;
    /// The queue of 16 entries takes three pages at most (descriptors, the
    /// driver's ring, the device's ring).
    pub const QUEUE_PAGES: usize = 4;
    /// The entries of the control queue. A show takes two chains of two
    /// descriptors, the setup one chain of two: 16 is room for all.
    pub const QUEUE_SIZE: usize = 16;
    /// The page of the commands.
    pub const STAGE_PAGE: usize = QUEUE_PAGES;
    /// A command and its answer: two of each are with the device at a time
    /// (the transfer and the flush of one show).
    pub const COMMAND_AT: [usize; 2] = [0, 64];
    pub const ANSWER_AT: [usize; 2] = [128, 192];
    /// The answer to GET_DISPLAY_INFO.
    pub const INFO_AT: usize = 512;

    const _: () = assert!(COMMAND_AT[1] - COMMAND_AT[0] >= COMMAND_MAX);
    const _: () = assert!(ANSWER_AT[0] >= COMMAND_AT[1] + COMMAND_MAX);
    const _: () = assert!(ANSWER_AT[1] - ANSWER_AT[0] >= crate::commands::HEADER);
    const _: () = assert!(INFO_AT >= ANSWER_AT[1] + crate::commands::HEADER);
    const _: () = assert!(INFO_AT + INFO_REPLY <= PAGE);
    const _: () = assert!(PAGES.is_power_of_two() && QUEUE_PAGES < PAGES);
}
