// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The thread of the service that maps and unmaps the objects of layers: `rt::mapper` with the
//! windows and the label of ramfs. The kernel maps an object in portions of 16 pages with
//! points of preemption, so a layer of tens of megabytes takes a long call; the main thread of
//! the service must not wait for it.

use rt::abi::{Access, Error, Rights};
use rt::handle::{Channel, Handle, Memory, Process};
use rt::sys;

/// The label of the notification that an order is done.
pub const LABEL: u64 = 0x4c41_5952;
/// The window of layer record `index`: 64 windows of 1 GiB above the windows of the service.
pub const WINDOW: usize = 0x60_0000_0000;
pub const WINDOW_SIZE: u64 = 1 << 30;
/// The thread's message buffer, the page after that of the main thread.
const BUFFER: usize = rt::abi::INIT_MSGBUF as usize + 4096;

pub const fn window(index: usize) -> usize {
    WINDOW + index * WINDOW_SIZE as usize
}

/// The main thread's side.
pub struct Mapper {
    inner: rt::mapper::Mapper,
}

impl Mapper {
    /// Starts the thread in `process`. It tells `channel`, the service's channel, with NOTIFY
    /// and `LABEL` at `level`.
    pub fn start(
        process: &Handle<Process>,
        channel: &Handle<Channel>,
        level: u8,
    ) -> Result<Mapper, Error> {
        let tell = sys::handle_label(channel, Rights::NOTIFY, LABEL, level)?;
        // The thread tells through the copy for the life of the service.
        let tell = core::mem::ManuallyDrop::new(tell);
        let inner = rt::mapper::Mapper::start(process, &tell, 1, BUFFER)?;
        Ok(Mapper { inner })
    }

    /// Whether the cell is free for an order.
    pub fn idle(&self) -> bool {
        self.inner.idle()
    }

    /// Maps `memory` read-only at `at`, working at `level`. The caller keeps `memory` until the
    /// outcome is taken.
    pub fn map(
        &self,
        level: u8,
        memory: &Handle<Memory>,
        size: u64,
        at: usize,
    ) -> Result<(), Error> {
        self.inner.map(level, memory, 0, size, at, Access::Read)
    }

    /// Takes `size` bytes at `at` out of the space.
    pub fn unmap(&self, level: u8, size: u64, at: usize) -> Result<(), Error> {
        self.inner.unmap(level, size, at)
    }

    /// The outcome of the order once the thread did it.
    pub fn take(&self) -> Option<Result<(), Error>> {
        self.inner.take()
    }
}
