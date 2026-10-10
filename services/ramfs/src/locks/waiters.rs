// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Sixteen sleeping registrations retain exact receipt identity and FIFO order.

use super::{Kind, Range, wait_receipts::Id};
use crate::storage::{Root, Token};

pub const CAPACITY: usize = 16;
pub const ROOT_SHARE: usize = 4;
const NONE: u8 = CAPACITY as u8;
const PORTION: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationToken {
    slot: u8,
    receipt: Id,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Sleeping,
    Ready,
    Running,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Input {
    pub receipt: Id,
    pub root: Root,
    pub inode: Token,
    pub range: Range,
    pub kind: Kind,
}

#[derive(Clone, Copy)]
struct Registration {
    input: Input,
    phase: Phase,
    previous: u8,
    next: u8,
}

pub struct Pool {
    records: [Option<Registration>; CAPACITY],
    occupied: u16,
    head: u8,
    tail: u8,
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Pool {
    pub const fn new() -> Self {
        Self {
            records: [None; CAPACITY],
            occupied: 0,
            head: NONE,
            tail: NONE,
        }
    }

    /// Initialize every field directly in permanent storage.
    ///
    /// # Safety
    /// `destination` exclusively owns aligned writable uninitialized Self storage.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: all fields receive valid values in the caller's allocation.
        unsafe {
            let records =
                core::ptr::addr_of_mut!((*destination).records).cast::<Option<Registration>>();
            for index in 0..CAPACITY {
                records.add(index).write(None);
            }
            core::ptr::addr_of_mut!((*destination).occupied).write(0);
            core::ptr::addr_of_mut!((*destination).head).write(NONE);
            core::ptr::addr_of_mut!((*destination).tail).write(NONE);
        }
    }

    pub fn count(&self) -> usize {
        self.occupied.count_ones() as usize
    }

    /// Duplicate registration preserves its existing place and FIFO links.
    /// The receipt already owns all inode/root pins; this pool adds none.
    pub fn register(&mut self, input: Input) -> Result<RegistrationToken, u32> {
        if input.root.generation == 0 || input.inode.generation == 0 {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let mut root_count = 0;
        for (slot, record) in self.records.iter().enumerate() {
            if let Some(record) = record {
                if record.input.receipt == input.receipt {
                    if record.input != input {
                        return Err(proto_fs::INVALID_ARGUMENT);
                    }
                    return Ok(RegistrationToken {
                        slot: slot as u8,
                        receipt: input.receipt,
                    });
                }
                root_count += usize::from(record.input.root == input.root);
            }
        }
        if root_count >= ROOT_SHARE || self.occupied == u16::MAX {
            return Err(proto_fs::NO_LOCKS);
        }
        let slot = (!self.occupied).trailing_zeros() as u8;
        self.records[slot as usize] = Some(Registration {
            input,
            phase: Phase::Sleeping,
            previous: self.tail,
            next: NONE,
        });
        if self.tail == NONE {
            self.head = slot;
        } else {
            self.records[self.tail as usize]
                .as_mut()
                .expect("occupied FIFO tail")
                .next = slot;
        }
        self.tail = slot;
        self.occupied |= 1 << slot;
        Ok(RegistrationToken {
            slot,
            receipt: input.receipt,
        })
    }

    fn record(&self, token: RegistrationToken) -> Result<&Registration, u32> {
        self.records
            .get(token.slot as usize)
            .and_then(Option::as_ref)
            .filter(|record| record.input.receipt == token.receipt)
            .ok_or(proto_fs::OPEN_RETIRED)
    }

    fn record_mut(&mut self, token: RegistrationToken) -> Result<&mut Registration, u32> {
        self.records
            .get_mut(token.slot as usize)
            .and_then(Option::as_mut)
            .filter(|record| record.input.receipt == token.receipt)
            .ok_or(proto_fs::OPEN_RETIRED)
    }

    pub fn snapshot(&self, token: RegistrationToken) -> Result<(Input, Phase), u32> {
        let record = self.record(token)?;
        Ok((record.input, record.phase))
    }

    pub fn ready(&mut self, token: RegistrationToken) -> Result<(), u32> {
        let record = self.record_mut(token)?;
        if record.phase != Phase::Running {
            record.phase = Phase::Ready;
        }
        Ok(())
    }

    pub fn run(&mut self, token: RegistrationToken) -> Result<Input, u32> {
        let record = self.record_mut(token)?;
        if record.phase != Phase::Ready {
            return Err(proto_fs::JOBS_FULL);
        }
        record.phase = Phase::Running;
        Ok(record.input)
    }

    /// A genuine conflicting attempt returns to sleep without moving to the tail.
    pub fn sleep(&mut self, token: RegistrationToken) -> Result<(), u32> {
        let record = self.record_mut(token)?;
        if record.phase != Phase::Running {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        record.phase = Phase::Sleeping;
        Ok(())
    }

    /// The caller has retained a canonical terminal receipt before freeing this slot.
    pub fn complete(&mut self, token: RegistrationToken) -> Result<Input, u32> {
        let record = *self.record(token)?;
        if record.previous == NONE {
            self.head = record.next;
        } else {
            self.records[record.previous as usize]
                .as_mut()
                .expect("occupied FIFO predecessor")
                .next = record.next;
        }
        if record.next == NONE {
            self.tail = record.previous;
        } else {
            self.records[record.next as usize]
                .as_mut()
                .expect("occupied FIFO successor")
                .previous = record.previous;
        }
        self.records[token.slot as usize] = None;
        self.occupied &= !(1 << token.slot);
        Ok(record.input)
    }

    /// A cursor owns its copied full keys; every result is revalidated before use.
    pub fn cursor(&self) -> Cursor {
        Cursor {
            next: (self.head != NONE).then(|| {
                let record = self.records[self.head as usize].expect("occupied FIFO head");
                RegistrationToken {
                    slot: self.head,
                    receipt: record.input.receipt,
                }
            }),
        }
    }

    /// Visit at most eight FIFO entries. Retirement invalidates a cursor instead
    /// of granting authority to a reused slot; the caller restarts its bounded scan.
    pub fn scan(
        &self,
        cursor: &mut Cursor,
        mut visit: impl FnMut(RegistrationToken, Input, Phase),
    ) -> Result<usize, u32> {
        let mut visited = 0;
        while visited < PORTION {
            let Some(token) = cursor.next else {
                break;
            };
            let record = self.record(token)?;
            cursor.next = if record.next == NONE {
                None
            } else {
                let next = self.records[record.next as usize].expect("occupied FIFO successor");
                Some(RegistrationToken {
                    slot: record.next,
                    receipt: next.input.receipt,
                })
            };
            visit(token, record.input, record.phase);
            visited += 1;
        }
        Ok(visited)
    }
}

pub struct Cursor {
    next: Option<RegistrationToken>,
}

impl Cursor {
    pub fn done(&self) -> bool {
        self.next.is_none()
    }
}
