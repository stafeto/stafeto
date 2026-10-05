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

    /// A private probe publishes through the real Clock service between the
    /// first sequence load and the remaining five loads of this read-only PAGE.
    #[cfg(feature = "open-finalize-clock-probe")]
    pub fn read_gated(&self, gate: Option<ClockGate>) -> Result<Option<Timestamp>, Status> {
        let Some(gate) = gate else {
            return self.read_once();
        };
        if self.memory.is_none() {
            return Err(Status::BadSize);
        }
        let now = rt::time::ticks_to_ns(rt::time::now());
        let mut first = true;
        let mut failure = None;
        let result = ramfs::time_source::read_timestamp_once(
            |offset, ordering: Ordering| {
                // SAFETY: the same validated read-only PAGE and aligned offsets
                // as read_once; the genuine helper owns no writable PAGE mapping.
                let value = unsafe { &*((ADDRESS + offset) as *const AtomicU64) }.load(ordering);
                if first {
                    first = false;
                    let mut request = proto_wire::Writer::new();
                    let sent = request
                        .u32(gate.key.slot)
                        .and_then(|()| request.u64(gate.key.generation))
                        .and_then(|()| request.u64(gate.job))
                        .and_then(|()| {
                            let reply = sys::send(&gate.channel, request.as_bytes())
                                .map_err(Status::Kernel)?;
                            let mut bytes = [0; rt::abi::MESSAGE_MAX];
                            if !reply.handles.is_empty()
                                || reply.bytes(&mut bytes) != proto_wire::reply(Status::Ok)
                            {
                                return Err(Status::BadSize);
                            }
                            Ok(())
                        });
                    if let Err(error) = sent {
                        failure = Some(error);
                    }
                }
                value
            },
            now,
        );
        if let Some(error) = failure {
            return Err(error);
        }
        result
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

/// All fields are captured from the authenticated session before offering the
/// helper capability. A matching Finish consumes this custody before IPC.
#[cfg(feature = "open-finalize-clock-probe")]
pub struct ClockGate {
    pub owner: u64,
    pub key: proto_fs::OpenKey,
    pub job: u64,
    pub stamp: ramfs::authority::Stamp,
    pub channel: Handle<Channel>,
}
