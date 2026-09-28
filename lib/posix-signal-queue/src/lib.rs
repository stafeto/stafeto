// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Sole-owner signal storage. No callbacks, allocation, native handles or locks.
//! The owner authenticates producers and reserves a retained reply before accept.
#![no_std]
pub use posix_types::SigInfo;

pub const REALTIME_MIN: i32 = 32;
pub const SIGNAL_MAX: i32 = 64;
pub const DEFAULT_CAPACITY: usize = 128;
const _: () = assert!(DEFAULT_CAPACITY >= 32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Process,
    Signal,
    Thread,
    Full,
    Exhausted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destination {
    Process,
    Thread(u64),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Keep the first source information for this signal and destination.
    Coalesce,
    /// Retain every occurrence, including values for ordinary signal numbers.
    Queue,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    process: u32,
    serial: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub ticket: Ticket,
    pub destination: Destination,
    pub info: SigInfo,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enqueued {
    pub ticket: Ticket,
    pub inserted: bool,
}

pub const fn bit(signal: i32) -> Result<u64, Error> {
    if signal < 1 || signal > SIGNAL_MAX {
        Err(Error::Signal)
    } else {
        Ok(1u64 << (signal - 1))
    }
}

/// One prepaid pool for every pending signal in one process. An application
/// owner chooses the limit and accounts for this storage before accepting sends.
/// Selection is bounded O(N); mutation requires the owner's exclusive borrow.
pub struct Pending<const N: usize> {
    process: u32,
    entries: [Option<Delivery>; N],
    used: usize,
    next: Option<u64>,
}
impl<const N: usize> Pending<N> {
    /// Initialize once for the owner's authenticated positive native PID. Keep
    /// this pool for that process lifetime; native PIDs do not repeat within a boot.
    pub const fn new(process: u32) -> Result<Self, Error> {
        if process == 0 || process > i32::MAX as u32 {
            return Err(Error::Process);
        }
        Ok(Self {
            process,
            entries: [None; N],
            used: 0,
            next: Some(1),
        })
    }
    pub const fn len(&self) -> usize {
        self.used
    }
    pub const fn is_empty(&self) -> bool {
        self.used == 0
    }
    pub const fn available(&self) -> usize {
        N - self.used
    }
    /// Validation and capacity checks precede mutation. Coalescing preserves
    /// the original ticket/source even when no free storage or serial remains.
    pub fn enqueue(
        &mut self,
        destination: Destination,
        info: SigInfo,
        mode: Mode,
    ) -> Result<Enqueued, Error> {
        bit(info.si_signo)?;
        if destination == Destination::Thread(0) {
            return Err(Error::Thread);
        }
        if mode == Mode::Coalesce
            && let Some(entry) = self
                .entries
                .iter()
                .flatten()
                .filter(|entry| {
                    entry.destination == destination && entry.info.si_signo == info.si_signo
                })
                .min_by_key(|entry| entry.ticket.serial)
        {
            return Ok(Enqueued {
                ticket: entry.ticket,
                inserted: false,
            });
        }
        let Some(index) = self.entries.iter().position(Option::is_none) else {
            return Err(Error::Full);
        };
        let ticket = Ticket {
            process: self.process,
            serial: self.next.ok_or(Error::Exhausted)?,
        };
        self.next = ticket.serial.checked_add(1);
        self.entries[index] = Some(Delivery {
            ticket,
            destination,
            info,
        });
        self.used += 1;
        Ok(Enqueued {
            ticket,
            inserted: true,
        })
    }
    fn visible(entry: &Delivery, thread: u64) -> bool {
        entry.destination == Destination::Process
            || entry.destination == Destination::Thread(thread)
    }
    /// The eligible set can represent a sigwait set or the complement of the
    /// current mask. Selection never removes a signal or assigns a process signal.
    /// Ordinary/realtime ordering is defined here as lowest number first;
    /// equal-number occurrences retain FIFO across recycled storage slots.
    pub fn peek(&self, thread: u64, eligible: u64) -> Result<Option<Delivery>, Error> {
        if thread == 0 {
            return Err(Error::Thread);
        }
        Ok(self
            .entries
            .iter()
            .flatten()
            .filter(|entry| {
                Self::visible(entry, thread)
                    && bit(entry.info.si_signo).expect("validated queued signal") & eligible != 0
            })
            .min_by_key(|entry| (entry.info.si_signo, entry.ticket.serial))
            .copied())
    }
    /// Copy the entire selected snapshot into the retained result before reply.
    /// A consumed, discarded or recycled ticket cannot consume another signal.
    pub fn accept(&mut self, ticket: Ticket) -> Option<Delivery> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.ticket == ticket))?;
        let entry = self.entries[index].take();
        self.used -= 1;
        entry
    }
    pub fn pending(&self, thread: u64, blocked: u64) -> Result<u64, Error> {
        if thread == 0 {
            return Err(Error::Thread);
        }
        Ok(self
            .entries
            .iter()
            .flatten()
            .filter(|entry| Self::visible(entry, thread))
            .fold(0, |set, entry| {
                set | bit(entry.info.si_signo).expect("validated queued signal")
            })
            & blocked)
    }
    fn discard(&mut self, matches: impl Fn(&Delivery) -> bool) -> usize {
        let mut removed = 0;
        for slot in &mut self.entries {
            if slot.as_ref().is_some_and(&matches) {
                *slot = None;
                removed += 1;
            }
        }
        self.used -= removed;
        removed
    }
    /// A process disposition change to ignore discards all occurrences.
    pub fn discard_signal(&mut self, signal: i32) -> Result<usize, Error> {
        bit(signal)?;
        Ok(self.discard(|entry| entry.info.si_signo == signal))
    }
    /// A dying thread leaves process pending state available to surviving threads.
    pub fn discard_thread(&mut self, thread: u64) -> Result<usize, Error> {
        if thread == 0 {
            return Err(Error::Thread);
        }
        Ok(self.discard(|entry| entry.destination == Destination::Thread(thread)))
    }
}

#[cfg(test)]
mod tests;
