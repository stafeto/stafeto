// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use core::sync::atomic::{AtomicU64, Ordering};
use proto_fs::Timestamp;
use proto_wire::Status;
use ramfs::time_source::Mode;
use rt::handle::{Channel, Handle, Memory, Process};
use rt::{abi::Access, sys};

/// Separate from boot-image, data and temporary READ_INTO mappings.
const ADDRESS: usize = 0x5c_0000_0000;

pub struct TimeSource {
    memory: Option<Handle<Memory>>,
}

impl TimeSource {
    pub fn attach(
        mode: Mode,
        parent: &Handle<Channel>,
        process: &Handle<Process>,
    ) -> Result<Self, Status> {
        let memory = match mode {
            Mode::Legacy => None,
            Mode::Clocked => {
                let memory = posix_clock::Client::connect(parent)?.page()?;
                sys::mem_map(
                    process,
                    &memory,
                    0,
                    proto_clock::page::SIZE as u64,
                    ADDRESS,
                    Access::Read,
                )
                .map_err(Status::Kernel)?;
                Some(memory)
            }
        };
        Ok(Self { memory })
    }

    pub fn read_once(&self) -> Result<Option<Timestamp>, Status> {
        let now = rt::time::ticks_to_ns(rt::time::now());
        if self.memory.is_none() {
            return Ok(Some(Timestamp::legacy_ns(now)));
        }
        ramfs::time_source::read_timestamp_once(
            |offset, ordering: Ordering| {
                // SAFETY: PAGE validated Memory/rights/size before this read-only
                // mapping. The six offsets are aligned within it; self owns Memory.
                unsafe { &*((ADDRESS + offset) as *const AtomicU64) }.load(ordering)
            },
            now,
        )
    }

    /// Each unstable startup attempt yields before reading again; Ready follows
    /// one complete snapshot. The mapped page remains owned across the yield.
    pub fn initial(&self) -> Result<Timestamp, Status> {
        loop {
            if let Some(timestamp) = self.read_once()? {
                return Ok(timestamp);
            }
            sys::yield_now().map_err(Status::Kernel)?;
        }
    }
}

impl ramfs::change::Clock for TimeSource {
    fn read_once(&self) -> Result<Option<Timestamp>, Status> {
        TimeSource::read_once(self)
    }
}
