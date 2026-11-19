// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The times of files: the page of CLOCK_REALTIME of the clock service, read with no call before each
//! job (`datafs::server::Server::set_now`). A machine with no clock service (the tables of the
//! probes of the volume) has no page: the times are then the monotonic count of the machine, in
//! nanoseconds since it started, which only grows. They are small numbers (the volume then reads as
//! if it were made in January 1970) and they differ between boots; a machine with the clock stamps
//! the date.

use core::sync::atomic::{AtomicU64, Ordering};
use proto_clock::page::{self, Anchor};
use rt::abi::Access;
use rt::handle::{Channel, Handle, Memory, Process};
use rt::sys;

/// Where the worker maps the page of the clock, read-only (the worker's own area, after the
/// buffer of the disk service and the stack).
const ADDRESS: usize = 0x58_3000_0000;

pub struct Clock {
    memory: Option<Handle<Memory>>,
    /// The last anchor read whole: a read that finds the page being written uses it again.
    anchor: Option<Anchor>,
    /// The last time given, so that a time never goes back.
    last: i64,
}

impl Clock {
    pub const fn new() -> Self {
        Self {
            memory: None,
            anchor: None,
            last: 0,
        }
    }

    /// Connects to the clock service through init (a table with no such service refuses, and the
    /// monotonic count stands in) and maps its page. True when the page is there.
    pub fn attach(&mut self, parent: &Handle<Channel>, process: &Handle<Process>) -> bool {
        let Ok(client) = posix_clock::Client::connect(parent) else {
            return false;
        };
        let Ok(memory) = client.page() else {
            return false;
        };
        let mapped = sys::mem_map(
            process,
            &memory,
            0,
            page::SIZE as u64,
            ADDRESS,
            Access::Read,
        );
        if mapped.is_err() {
            return false;
        }
        self.memory = Some(memory);
        true
    }

    fn load(offset: usize, ordering: Ordering) -> u64 {
        // SAFETY: `attach` mapped the page read-only at ADDRESS; the offsets of the page are aligned
        // u64 words inside it, and the memory is the clock's, mapped for the life of the process.
        unsafe { &*((ADDRESS + offset) as *const AtomicU64) }.load(ordering)
    }

    /// The present moment in nanoseconds since the Unix epoch (or since boot with no clock).
    pub fn now_ns(&mut self) -> i64 {
        let mono = rt::time::ticks_to_ns(rt::time::now());
        let value = if self.memory.is_some() {
            if let Some(anchor) = page::read_anchor_once(Self::load) {
                self.anchor = Some(anchor);
            }
            self.anchor
                .and_then(|a| a.realtime_ns(mono))
                .and_then(|ns| i64::try_from(ns).ok())
        } else {
            None
        };
        let now = value.unwrap_or_else(|| i64::try_from(mono).unwrap_or(i64::MAX));
        self.last = self.last.max(now);
        self.last
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}
