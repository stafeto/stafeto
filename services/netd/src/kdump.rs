// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The time stamps of the kernel (the feature `trace`, on a kernel built with
//! the feature `stamps`) in the dump of the rings: after the ring of the
//! service, each `posix-net stat` gives the next part of the rings of the
//! CPUs as lines `tr k<cpu> <point> <ticks> <key>` (hexadecimal; the points of
//! abi::STAMP_*), and the line `tr k done` ends them. The first part freezes
//! the rings of the kernel, so that what the idle CPUs write during the long
//! dump does not wear out what the load made. After the records of a CPU
//! comes the line `tr k<cpu> 0 <records made> <records given>`, with which the
//! reader counts what the console lost. A kernel without the stamps refuses
//! the call: the line `tr k none`.

use core::fmt::Write;
use rt::Handle;
use rt::handle::Resource;

/// The CPUs of the machines the images of the measurement run on.
const CPUS: u64 = 4;

/// Where the dump of the kernel's rings stands.
pub struct KernelDump {
    /// The system resource with KSTATS, if init gave the service one.
    resource: Option<Handle<Resource>>,
    frozen: bool,
    done: bool,
    cpu: u64,
    next: u64,
    /// The records of this CPU's ring given so far.
    given: u64,
}

struct Line {
    bytes: [u8; 64],
    len: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len + s.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(core::fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

impl KernelDump {
    pub fn new(resource: Option<Handle<Resource>>) -> KernelDump {
        KernelDump {
            resource,
            frozen: false,
            done: false,
            cpu: 0,
            next: 0,
            given: 0,
        }
    }

    /// Stops the rings of the kernel, once.
    pub fn freeze(&mut self) {
        if let Some(resource) = self.resource.as_ref().filter(|_| !self.frozen) {
            let mut records = [[0; 2]; abi::STAMPS_BATCH];
            let _ = rt::sys::stamps_read(resource, 0, 0, true, &mut records);
        }
        self.frozen = true;
    }

    /// Whether the rings of the service have gone and the kernel's are next.
    pub fn is_open(&self) -> bool {
        self.resource.is_some() && !self.done
    }

    /// Up to `max` lines of the rings, from where the last part stopped, to
    /// `emit`; true when `tr k done` or `tr k none` was given.
    pub fn part(&mut self, max: usize, mut emit: impl FnMut(&str)) -> bool {
        let Some(resource) = self.resource.as_ref() else {
            return true;
        };
        let mut lines = 0;
        while lines < max && self.cpu < CPUS {
            let mut records = [[0; 2]; abi::STAMPS_BATCH];
            let batch =
                match rt::sys::stamps_read(resource, self.cpu, self.next, false, &mut records) {
                    Ok(batch) => batch,
                    Err(_) if self.cpu == 0 => {
                        emit("tr k none");
                        self.done = true;
                        return true;
                    }
                    // A CPU that is not up: the rings of the CPUs below it are all.
                    Err(_) => {
                        self.cpu = CPUS;
                        break;
                    }
                };
            for &[ticks, word] in records
                .iter()
                .take(batch.count as usize)
                .skip(batch.torn as usize)
            {
                let mut line = Line {
                    bytes: [0; 64],
                    len: 0,
                };
                let _ = write!(
                    line,
                    "tr k{} {:x} {ticks:x} {:x}",
                    self.cpu,
                    (word >> 32) & 0xff,
                    word & 0xffff_ffff
                );
                if let Ok(text) = core::str::from_utf8(&line.bytes[..line.len]) {
                    emit(text);
                }
                lines += 1;
                self.given += 1;
            }
            self.next = batch.next;
            if batch.count == 0 || batch.next >= batch.head {
                let mut line = Line {
                    bytes: [0; 64],
                    len: 0,
                };
                let _ = write!(line, "tr k{} 0 {:x} {:x}", self.cpu, batch.head, self.given);
                if let Ok(text) = core::str::from_utf8(&line.bytes[..line.len]) {
                    emit(text);
                }
                self.cpu += 1;
                self.next = 0;
                self.given = 0;
            }
        }
        if self.cpu >= CPUS {
            emit("tr k done");
            self.done = true;
        }
        self.done
    }
}
