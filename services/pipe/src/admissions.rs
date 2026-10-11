// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use proto_pipe::{BrokerPrepare, Endpoint, NAMED_MAX, NamedPhase, NamedReply, NamedTicket, OWN};

pub const WAIT_LABEL: u64 = OWN | 0xfffe;
pub struct Admission<H> {
    pub owner: u64,
    pub root: u64,
    pub creator: u64,
    pub open: NamedTicket,
    pub broker: u64,
    pub capture: Option<BrokerPrepare>,
    pub phase: NamedPhase,
    pub result: u32,
    pub endpoint: Endpoint,
    pub cap_label: u64,
    pub handle: Option<H>,
}
impl<H> Admission<H> {
    pub fn preparing(&self) -> Option<BrokerPrepare> {
        (self.phase == NamedPhase::Preparing)
            .then_some(self.capture)
            .flatten()
    }
    /// Terminal failures preserve their saved result; an active candidate is retired once.
    pub fn cancel(&mut self) -> Option<Endpoint> {
        if matches!(self.phase, NamedPhase::Failed | NamedPhase::Cancelled) {
            return None;
        }
        let endpoint = core::mem::take(&mut self.endpoint);
        self.phase = NamedPhase::Cancelled;
        self.handle = None;
        Some(endpoint)
    }

    pub fn reply(&self, ticket: NamedTicket) -> NamedReply {
        NamedReply {
            ticket,
            phase: self.phase,
            result: self.result,
            endpoint: self.endpoint,
        }
    }
}

/// Metadata shares admission credits with ordinary long operations. Each
/// occupied record retains at most one original capability or notification.
pub struct Admissions<H> {
    list: [Option<Admission<H>>; NAMED_MAX],
    generations: [u64; NAMED_MAX],
    free: [u8; NAMED_MAX],
    free_len: usize,
    live: usize,
    retiring: u128,
    issued: u64,
}
impl<H> Default for Admissions<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H> Admissions<H> {
    pub const fn new() -> Self {
        let mut free = [0; NAMED_MAX];
        let mut i = 0;
        while i < NAMED_MAX {
            free[i] = (NAMED_MAX - 1 - i) as u8;
            i += 1;
        }
        Self {
            list: [const { None }; NAMED_MAX],
            generations: [0; NAMED_MAX],
            free,
            free_len: NAMED_MAX,
            live: 0,
            retiring: 0,
            issued: 0,
        }
    }
    pub fn count(&self) -> usize {
        self.live
    }
    pub fn find(&self, owner: u64, open: NamedTicket) -> Option<NamedTicket> {
        self.list.iter().enumerate().find_map(|(slot, item)| {
            item.as_ref()
                .filter(|r| r.owner == owner && r.open == open)
                .map(|_| NamedTicket {
                    slot: slot as u32,
                    generation: self.generations[slot],
                })
        })
    }
    pub fn reservations(&self, owner: u64) -> usize {
        self.list
            .iter()
            .flatten()
            .filter(|r| {
                r.owner == owner && !matches!(r.phase, NamedPhase::Failed | NamedPhase::Cancelled)
            })
            .count()
    }
    pub fn give(&mut self, owner: u64, root: u64, open: NamedTicket) -> Option<NamedTicket> {
        while self.free_len != 0 {
            self.free_len -= 1;
            let slot = usize::from(self.free[self.free_len]);
            let Some(generation) = self.generations[slot].checked_add(1) else {
                continue;
            };
            self.generations[slot] = generation;
            self.list[slot] = Some(Admission {
                owner,
                root,
                creator: owner,
                open,
                broker: 0,
                capture: None,
                phase: NamedPhase::Witness,
                result: 0,
                endpoint: Endpoint::default(),
                cap_label: 0,
                handle: None,
            });
            self.live += 1;
            return Some(NamedTicket {
                slot: slot as u32,
                generation,
            });
        }
        None
    }
    pub fn get(&self, ticket: NamedTicket) -> Option<&Admission<H>> {
        let slot = ticket.slot as usize;
        if self.generations.get(slot).copied()? != ticket.generation {
            return None;
        }
        self.list.get(slot)?.as_ref()
    }
    pub fn get_mut(&mut self, ticket: NamedTicket) -> Option<&mut Admission<H>> {
        let slot = ticket.slot as usize;
        if self.generations.get(slot).copied()? != ticket.generation {
            return None;
        }
        self.list.get_mut(slot)?.as_mut()
    }
    pub fn free(&mut self, ticket: NamedTicket) -> Option<Admission<H>> {
        self.get(ticket)?;
        let slot = ticket.slot as usize;
        let value = self.list[slot].take()?;
        self.retiring &= !(1 << slot);
        self.free[self.free_len] = slot as u8;
        self.free_len += 1;
        self.live -= 1;
        Some(value)
    }
    pub fn fresh_label(&mut self) -> Option<u64> {
        self.issued = self.issued.checked_add(1)?;
        if self.issued >= 1 << 47 {
            return None;
        }
        // Clone places are below 320, so the reserved low 16 bits never name one.
        Some(OWN | (self.issued << 16) | 0xffff)
    }
    pub fn waiter(ticket: NamedTicket) -> (u64, u64) {
        (
            WAIT_LABEL | (u64::from(ticket.slot) << 16),
            ticket.generation,
        )
    }
    pub fn from_waiter(label: u64, generation: u64) -> Option<NamedTicket> {
        if label & (OWN | 0xffff) != WAIT_LABEL {
            return None;
        }
        let slot = ((label & !OWN) >> 16) as u32;
        (slot < NAMED_MAX as u32).then_some(NamedTicket { slot, generation })
    }
    pub fn alive(&self, label: u64, generation: u64) -> bool {
        Self::from_waiter(label, generation)
            .and_then(|ticket| self.get(ticket))
            .is_some_and(|r| r.phase == NamedPhase::Waiting)
    }
    pub fn broker_ticket(
        &self,
        broker: u64,
        client: u64,
        open: NamedTicket,
    ) -> Option<NamedTicket> {
        self.list.iter().enumerate().find_map(|(slot, item)| {
            item.as_ref()
                .filter(|r| {
                    r.broker == broker
                        && r.capture
                            .is_some_and(|body| body.client == client && body.open == open)
                })
                .map(|_| NamedTicket {
                    slot: slot as u32,
                    generation: self.generations[slot],
                })
        })
    }
    pub fn retire(&mut self, owner: u64) {
        for (slot, item) in self.list.iter().enumerate() {
            if item.as_ref().is_some_and(|r| r.owner == owner) {
                self.retiring |= 1 << slot;
            }
        }
    }
    pub fn cleanup_due(&self) -> bool {
        self.retiring != 0
    }
    pub fn cleanup_ticket(&self) -> Option<NamedTicket> {
        (self.retiring != 0).then(|| {
            let slot = self.retiring.trailing_zeros() as usize;
            NamedTicket {
                slot: slot as u32,
                generation: self.generations[slot],
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelling_captured_preparation_prevents_allocation_on_query_replay() {
        let mut records = Admissions::<()>::new();
        let open = NamedTicket {
            slot: 32,
            generation: 0x2_0000_0001,
        };
        let ticket = records.give(10, 20, open).unwrap();
        let body = BrokerPrepare {
            ticket,
            client: 44,
            open,
            inode: NamedTicket {
                slot: 7,
                generation: 99,
            },
            flags: 0,
        };
        let record = records.get_mut(ticket).unwrap();
        record.capture = Some(body);
        record.broker = 55;
        record.phase = NamedPhase::Preparing;
        assert_eq!(record.preparing(), Some(body));
        assert_eq!(record.cancel(), Some(Endpoint::default()));
        assert_eq!(record.cancel(), None);
        assert_eq!(record.reply(ticket).phase, NamedPhase::Cancelled);
        let mut pipes = Box::new(crate::Pipes::new());
        if let Some(replayed) = records.get(ticket).unwrap().preparing() {
            pipes
                .reserve_named(
                    crate::NamedInode {
                        broker: 55,
                        inode: replayed.inode,
                    },
                    10,
                    20,
                    replayed.flags,
                )
                .unwrap();
        }
        assert_eq!(pipes.live(), 0);
        assert_eq!(records.broker_ticket(55, 44, open), Some(ticket));
        assert_eq!(records.reservations(10), 0);
        assert_eq!(records.count(), 1);
        records.free(ticket).unwrap();
        assert_eq!(records.count(), 0);
    }

    #[test]
    fn exact_generation_owner_and_broker_capture_survive_replay_and_slot_reuse() {
        let mut records = Admissions::<()>::new();
        let open = NamedTicket {
            slot: 34,
            generation: 0x1_0000_0001,
        };
        let ticket = records.give(10, 20, open).unwrap();
        assert_eq!(records.find(10, open), Some(ticket));
        assert_eq!(records.find(11, open), None);
        let capture = BrokerPrepare {
            ticket,
            client: 44,
            open,
            inode: NamedTicket {
                slot: 7,
                generation: 99,
            },
            flags: 0,
        };
        let record = records.get_mut(ticket).unwrap();
        record.capture = Some(capture);
        record.broker = 55;
        record.phase = NamedPhase::Waiting;
        assert_eq!(records.broker_ticket(55, 44, open), Some(ticket));
        assert_eq!(records.broker_ticket(56, 44, open), None);
        assert_eq!(records.broker_ticket(55, 45, open), None);
        let waiter = Admissions::<()>::waiter(ticket);
        assert!(records.alive(waiter.0, waiter.1));
        records.retire(11);
        assert!(!records.cleanup_due());
        records.retire(10);
        assert_eq!(records.cleanup_ticket(), Some(ticket));
        records.free(ticket).unwrap();
        let newer = records.give(10, 20, open).unwrap();
        assert_eq!(ticket.slot, newer.slot);
        assert_ne!(ticket.generation, newer.generation);
        assert!(records.get(ticket).is_none());
        assert!(!records.alive(waiter.0, waiter.1));
        assert_eq!(records.count(), 1);
        assert!(!records.cleanup_due());
        assert_ne!(records.fresh_label(), records.fresh_label());
    }
}
