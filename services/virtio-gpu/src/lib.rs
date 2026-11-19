// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What the display service decides (spec 3, 3.1 to 3.5), apart from the
//! device and the calls it makes: the commands of the Virtio GPU in 2D mode
//! and their answers (`commands`), who owns the screen and what is cleared
//! when it goes back (`owner`), the order of the device's setup (`setup`),
//! and where its DMA object holds the queues and the buffers of the
//! commands (`dma`). Everything here builds for the host too, where `cargo
//! test -p virtio-gpu` exercises it.

#![cfg_attr(not(test), no_std)]

pub mod commands;
pub mod layers;
pub mod owner;
pub mod setup;

/// The service's DMA object (`dma`, 16 pages, contiguous and uncached):
/// the two queues take the first QUEUE_PAGES, and the commands and their
/// answers lie in the page after them, at the offsets below.
/// Uncached: no cache maintenance, only the barriers of the queue.
pub mod dma {
    use crate::commands::{COMMAND_MAX, CURSOR_COMMAND, HEADER, INFO_REPLY};

    pub const PAGES: usize = 16;
    pub const PAGE: usize = virtio_mmio::PAGE;
    /// The control queue and the cursor queue, 16 entries each (the device
    /// gives both 16 places), take four pages each at most: descriptors
    /// and the driver's ring, the device's ring.
    pub const QUEUE_PAGES: usize = 8;
    /// The entries of the control queue. A show takes up to three chains
    /// of two descriptors, the setup one chain of two: 16 is room for all.
    pub const QUEUE_SIZE: usize = 16;
    /// The entries of the cursor queue: one chain of one descriptor is
    /// with the device at a time.
    pub const CURSOR_QUEUE_SIZE: usize = 16;
    /// The page of the commands.
    pub const STAGE_PAGE: usize = QUEUE_PAGES;
    /// A command and its answer: three of each are with the device at a
    /// time (the transfer, the scanout and the flush of one show).
    pub const COMMAND_AT: [usize; 3] = [0, 64, 128];
    pub const ANSWER_AT: [usize; 3] = [192, 256, 320];
    /// The command of the cursor queue, whose chain has no answer.
    pub const CURSOR_AT: usize = 384;
    /// The answer to GET_DISPLAY_INFO.
    pub const INFO_AT: usize = 512;

    const _: () = assert!(COMMAND_AT[1] - COMMAND_AT[0] >= COMMAND_MAX);
    const _: () = assert!(COMMAND_AT[2] - COMMAND_AT[1] >= COMMAND_MAX);
    const _: () = assert!(ANSWER_AT[0] >= COMMAND_AT[2] + COMMAND_MAX);
    const _: () = assert!(ANSWER_AT[1] - ANSWER_AT[0] >= crate::commands::HEADER);
    const _: () = assert!(ANSWER_AT[2] - ANSWER_AT[1] >= crate::commands::HEADER);
    const _: () = assert!(CURSOR_AT >= ANSWER_AT[2] + HEADER);
    const _: () = assert!(INFO_AT >= CURSOR_AT + CURSOR_COMMAND);
    const _: () = assert!(INFO_AT + INFO_REPLY <= PAGE);
    const _: () = assert!(PAGES.is_power_of_two() && QUEUE_PAGES < PAGES);
    // The page of the commands is after the queues and the commands are
    // aligned to eight bytes for the device.
    const _: () = assert!(STAGE_PAGE == QUEUE_PAGES && STAGE_PAGE < PAGES);
    const _: () = assert!(
        COMMAND_AT[0].is_multiple_of(8)
            && COMMAND_AT[1].is_multiple_of(8)
            && COMMAND_AT[2].is_multiple_of(8)
            && ANSWER_AT[0].is_multiple_of(8)
            && ANSWER_AT[1].is_multiple_of(8)
            && ANSWER_AT[2].is_multiple_of(8)
            && CURSOR_AT.is_multiple_of(8)
            && INFO_AT.is_multiple_of(8)
    );
    const _: () = assert!(CURSOR_QUEUE_SIZE.is_power_of_two() && QUEUE_SIZE.is_power_of_two());
}
