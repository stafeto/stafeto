// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;
use proto_pipe::{APPEND, NAMED_ROOT_MAX, NO_READER, NamedTicket};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamedInode {
    pub broker: u64,
    pub inode: NamedTicket,
}

#[derive(Clone, Copy)]
pub(super) struct Description {
    generation: u64,
    refs: u16,
    ring: u8,
    flags: u32,
    root: u64,
    attached: bool,
    ticket: NamedTicket,
    owner: u64,
}
impl Description {
    pub(super) const FREE: Self = Self {
        generation: 0,
        refs: 0,
        ring: 0,
        flags: 0,
        root: 0,
        attached: false,
        ticket: NamedTicket {
            slot: 0,
            generation: 0,
        },
        owner: 0,
    };
}

impl Pipes {
    fn named_description(&self, endpoint: Endpoint) -> Result<&Description, u32> {
        if !endpoint.is_named() {
            return Err(BAD_FD);
        }
        let record = self.named_descriptions.get(endpoint.slot()).ok_or(BAD_FD)?;
        if record.refs == 0 || record.generation != endpoint.generation {
            return Err(BAD_FD);
        }
        Ok(record)
    }
    fn resolve_endpoint(
        &self,
        held: &Held,
        endpoint: Endpoint,
        write: Option<bool>,
    ) -> Result<(usize, usize, bool), u32> {
        if endpoint.is_sock() {
            return Err(BAD_FD);
        }
        if !endpoint.is_named() {
            if endpoint.generation != 0 {
                return Err(BAD_FD);
            }
            let (index, end) = split(held, endpoint.id, write)?;
            return Ok((index, end, self.pipes[index].ends[end].nonblock));
        }
        if !held.holds(endpoint.id) {
            return Err(BAD_FD);
        }
        let record = self.named_description(endpoint)?;
        let end = usize::from(record.flags & WRITE_END != 0);
        if !record.attached || write.is_some_and(|w| w != (end == 1)) {
            return Err(BAD_FD);
        }
        Ok((usize::from(record.ring), end, record.flags & NONBLOCK != 0))
    }

    /// Reserve one paid description and an exact inode's shared ring.
    pub fn reserve_named(
        &mut self,
        key: NamedInode,
        creator: u64,
        root: u64,
        flags: u32,
    ) -> Result<Endpoint, u32> {
        if flags & !(NONBLOCK | WRITE_END | APPEND) != 0 {
            return Err(INVALID);
        }
        if self
            .named_descriptions
            .iter()
            .filter(|d| d.refs != 0 && d.root == root)
            .count()
            >= NAMED_ROOT_MAX
        {
            return Err(NFILE);
        }
        let slot = self
            .named_descriptions
            .iter()
            .position(|d| d.refs == 0 && d.generation != u64::MAX)
            .ok_or(NFILE)?;
        let ring = if let Some(index) = self
            .pipes
            .iter()
            .position(|p| p.live && p.named == Some(key))
        {
            index
        } else {
            if self
                .pipes
                .iter()
                .filter(|p| p.live && p.creator == creator)
                .count()
                >= CREATED_MAX
            {
                return Err(MFILE);
            }
            if self
                .pipes
                .iter()
                .filter(|p| p.live && p.root == root)
                .count()
                >= ROOT_PIPES
            {
                return Err(NFILE);
            }
            let index = self.pipes.iter().position(|p| !p.live).ok_or(NFILE)?;
            self.pipes[index] = Pipe {
                live: true,
                creator,
                root,
                head: 0,
                len: 0,
                ends: [End::NONE; 2],
                named: Some(key),
                grants: 0,
            };
            index
        };
        self.pipes[ring].grants += 1;
        let generation = self.named_descriptions[slot].generation + 1;
        self.named_descriptions[slot] = Description {
            generation,
            refs: 1,
            ring: ring as u8,
            flags,
            root,
            attached: false,
            ticket: NamedTicket {
                slot: 0,
                generation: 0,
            },
            owner: 0,
        };
        Ok(Endpoint::named(slot as u32, generation))
    }

    /// Attach the candidate end; pending counterparts participate in rendezvous.
    pub fn attach_named(&mut self, endpoint: Endpoint, wakes: &mut Wakes) -> Result<bool, u32> {
        let record = *self.named_description(endpoint)?;
        let index = usize::from(record.ring);
        let end = usize::from(record.flags & WRITE_END != 0);
        if !record.attached {
            if end == 1 && record.flags & NONBLOCK != 0 && self.pipes[index].ends[0].refs == 0 {
                return Err(NO_READER);
            }
            self.named_descriptions[endpoint.slot()].attached = true;
            self.pipes[index].grants -= 1;
            self.pipes[index].ends[end].refs += 1;
            wakes.list = self.pipes[index].ends[1 - end].waiters;
        }
        Ok((end == 0 && record.flags & NONBLOCK != 0) || self.pipes[index].ends[1 - end].refs != 0)
    }

    pub fn named_ready(&self, endpoint: Endpoint) -> Result<bool, u32> {
        let record = self.named_description(endpoint)?;
        let end = usize::from(record.flags & WRITE_END != 0);
        Ok(record.attached
            && ((end == 0 && record.flags & NONBLOCK != 0)
                || self.pipes[usize::from(record.ring)].ends[1 - end].refs != 0))
    }

    /// Publish the reservation once; replay is handled by its paid receipt.
    pub fn take_named(&self, held: &mut Held, endpoint: Endpoint) -> Result<(), u32> {
        self.named_description(endpoint)?;
        if held.holds(endpoint.id) {
            return Err(BAD_FD);
        }
        if held.count() == HELD_MAX {
            return Err(MFILE);
        }
        held.add(endpoint.id as usize);
        Ok(())
    }

    pub fn ack_named(
        &mut self,
        held: &mut Held,
        owner: u64,
        ticket: NamedTicket,
        endpoint: Endpoint,
    ) -> Result<(), u32> {
        self.take_named(held, endpoint)?;
        let record = &mut self.named_descriptions[endpoint.slot()];
        record.ticket = ticket;
        record.owner = owner;
        Ok(())
    }
    pub fn ack_endpoint(&self, held: &Held, owner: u64, ticket: NamedTicket) -> Option<Endpoint> {
        self.named_descriptions
            .iter()
            .enumerate()
            .find_map(|(slot, record)| {
                let endpoint = Endpoint::named(slot as u32, record.generation);
                (record.refs != 0
                    && record.owner == owner
                    && record.ticket == ticket
                    && held.holds(endpoint.id))
                .then_some(endpoint)
            })
    }

    fn unref_named(&mut self, slot: usize, count: u16, wakes: &mut Wakes) {
        let record = self.named_descriptions[slot];
        debug_assert!(record.refs >= count);
        self.named_descriptions[slot].refs -= count;
        let index = usize::from(record.ring);
        let end = usize::from(record.flags & WRITE_END != 0);
        if record.attached {
            self.unref(2 * index + end, count, wakes);
        } else {
            debug_assert_eq!(count, 1);
            self.pipes[index].grants -= 1;
            if self.pipes[index].grants == 0 && self.pipes[index].ends.iter().all(|e| e.refs == 0) {
                self.pipes[index] = Pipe::FREE;
            }
        }
    }

    pub fn cancel_named(&mut self, endpoint: Endpoint, wakes: &mut Wakes) -> Result<(), u32> {
        self.named_description(endpoint)?;
        self.unref_named(endpoint.slot(), 1, wakes);
        Ok(())
    }
    pub fn close_endpoint(
        &mut self,
        held: &mut Held,
        endpoint: Endpoint,
        wakes: &mut Wakes,
    ) -> Result<(), u32> {
        if endpoint.is_sock() {
            return self.sock_close(held, endpoint, wakes);
        }
        if !endpoint.is_named() {
            return self.close(held, endpoint.id, wakes);
        }
        self.resolve_endpoint(held, endpoint, None)?;
        held.remove(endpoint.id as usize);
        self.unref_named(endpoint.slot(), 1, wakes);
        Ok(())
    }
    pub(super) fn named_step(&mut self, wakes: &mut Wakes) -> bool {
        if self.named_dirty == 0 {
            return false;
        }
        let slot = self.named_dirty.trailing_zeros() as usize;
        self.named_dirty &= !(1 << slot);
        let count = core::mem::take(&mut self.named_dropping[slot]);
        self.unref_named(slot, count, wakes);
        self.named_dirty != 0
    }

    pub fn clone_endpoints(&mut self, held: &Held, endpoints: &[Endpoint]) -> Result<Held, u32> {
        let mut out = Held::default();
        for &endpoint in endpoints {
            if endpoint.is_sock() {
                self.sock_slot(held, endpoint)?;
            } else {
                self.resolve_endpoint(held, endpoint, None)?;
            }
            out.add(endpoint.id as usize);
        }
        if out.count() > HELD_MAX {
            return Err(MFILE);
        }
        for id in out.descriptions() {
            if id & NAMED_END == 0 && id & SOCK_END != 0 {
                self.sockets.s[(id & !SOCK_END) as usize].refs += 1;
            } else if id & NAMED_END != 0 {
                let slot = (id & !NAMED_END) as usize;
                let record = &mut self.named_descriptions[slot];
                record.refs += 1;
                self.pipes[usize::from(record.ring)].ends
                    [usize::from(record.flags & WRITE_END != 0)]
                .refs += 1;
            } else {
                let (index, write) = proto_pipe::end_of(id);
                self.pipes[index].ends[write as usize].refs += 1;
            }
        }
        Ok(out)
    }

    pub fn read_endpoint(
        &mut self,
        held: &Held,
        endpoint: Endpoint,
        out: &mut [u8],
        wakes: &mut Wakes,
    ) -> Result<Option<usize>, u32> {
        if endpoint.is_sock() {
            return self.sock_read(held, endpoint, out, wakes);
        }
        let (index, end, nonblock) = self.resolve_endpoint(held, endpoint, Some(false))?;
        self.read_at(index, end, nonblock, out, wakes)
    }
    pub fn write_endpoint(
        &mut self,
        held: &Held,
        endpoint: Endpoint,
        bytes: &[u8],
        wakes: &mut Wakes,
    ) -> Result<Option<usize>, u32> {
        if endpoint.is_sock() {
            return self.sock_write(held, endpoint, bytes, wakes);
        }
        let (index, end, nonblock) = self.resolve_endpoint(held, endpoint, Some(true))?;
        self.write_at(index, end, nonblock, bytes, wakes)
    }
    pub fn flags_endpoint(&self, held: &Held, endpoint: Endpoint) -> Result<u32, u32> {
        if endpoint.is_sock() {
            return self.sock_flags(held, endpoint);
        }
        if !endpoint.is_named() {
            return self.flags(held, endpoint.id);
        }
        self.resolve_endpoint(held, endpoint, None)?;
        Ok(self.named_description(endpoint)?.flags)
    }
    pub fn set_flags_endpoint(
        &mut self,
        held: &Held,
        endpoint: Endpoint,
        flags: u32,
    ) -> Result<(), u32> {
        if endpoint.is_sock() {
            return self.sock_set_flags(held, endpoint, flags);
        }
        if !endpoint.is_named() {
            return self.set_flags(held, endpoint.id, flags);
        }
        self.resolve_endpoint(held, endpoint, None)?;
        if flags & !(NONBLOCK | APPEND) != 0 {
            return Err(INVALID);
        }
        let record = &mut self.named_descriptions[endpoint.slot()];
        record.flags = (record.flags & WRITE_END) | flags;
        Ok(())
    }
    pub fn stat_endpoint(&self, held: &Held, endpoint: Endpoint) -> Result<(u32, u32), u32> {
        if endpoint.is_sock() {
            return self.sock_stat(held, endpoint);
        }
        let (index, _, _) = self.resolve_endpoint(held, endpoint, None)?;
        Ok((index as u32, u32::from(self.pipes[index].len)))
    }
    pub fn queue_end(&self, endpoint: Endpoint) -> Result<u32, u32> {
        if endpoint.is_sock() {
            return Ok(DESCRIPTIONS as u32 + endpoint.slot() as u32);
        }
        if !endpoint.is_named() {
            return Ok(endpoint.id);
        }
        let record = self.named_description(endpoint)?;
        Ok(2 * u32::from(record.ring) + u32::from(record.flags & WRITE_END != 0))
    }
    pub fn readiness_endpoint(&self, held: &Held, endpoint: Endpoint) -> u32 {
        self.watch_endpoint(held, endpoint)
            .map_or(proto_wire::watch::NVAL, |(_, ready)| ready)
    }

    /// One exact held-description lookup supplies its canonical queue and readiness.
    pub fn watch_endpoint(&self, held: &Held, endpoint: Endpoint) -> Result<(u32, u32), u32> {
        if endpoint.is_sock() {
            let slot = self.sock_slot(held, endpoint)?;
            return Ok((DESCRIPTIONS as u32 + slot as u32, self.sock_readiness(slot)));
        }
        if !endpoint.is_named() {
            if endpoint.generation != 0 {
                return Err(BAD_FD);
            }
            let (index, end) = split(held, endpoint.id, None)?;
            return Ok((endpoint.id, self.readiness_at(index, end)));
        }
        let (index, end, _) = self.resolve_endpoint(held, endpoint, None)?;
        Ok(((2 * index + end) as u32, self.readiness_at(index, end)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> NamedInode {
        NamedInode {
            broker: 7,
            inode: NamedTicket {
                slot: 4,
                generation: 0x1_0000_0001,
            },
        }
    }
    fn ticket() -> NamedTicket {
        NamedTicket {
            slot: 1,
            generation: 0x2_0000_0001,
        }
    }

    #[test]
    fn watch_lookup_checks_custody_and_generation_before_readiness() {
        use proto_wire::watch;
        let mut p = Box::new(Pipes::new());
        let mut held = Held::default();
        let mut wakes = Wakes::default();
        let (rd, wr) = p.create(&mut held, 1, 1, 0).unwrap();
        let read = Endpoint::anonymous(rd);
        assert_eq!(p.watch_endpoint(&held, read), Ok((rd, 0)));
        assert_eq!(
            p.watch_endpoint(
                &held,
                Endpoint {
                    generation: 1,
                    ..read
                }
            ),
            Err(BAD_FD)
        );
        p.close(&mut held, wr, &mut wakes).unwrap();
        assert_eq!(
            p.watch_endpoint(&held, read),
            Ok((rd, watch::READ | watch::HUP))
        );
        let named = p.reserve_named(key(), 2, 1, NONBLOCK).unwrap();
        assert_eq!(p.watch_endpoint(&held, named), Err(BAD_FD));
        p.attach_named(named, &mut wakes).unwrap();
        p.take_named(&mut held, named).unwrap();
        let queue = p.queue_end(named).unwrap();
        assert_eq!(
            p.watch_endpoint(&held, named),
            Ok((queue, watch::READ | watch::HUP))
        );
        p.close_endpoint(&mut held, named, &mut wakes).unwrap();
        let fresh = p.reserve_named(key(), 2, 1, NONBLOCK).unwrap();
        p.attach_named(fresh, &mut wakes).unwrap();
        p.take_named(&mut held, fresh).unwrap();
        assert_eq!(named.slot(), fresh.slot());
        assert_ne!(named.generation, fresh.generation);
        assert_eq!(p.watch_endpoint(&held, named), Err(BAD_FD));
        assert_eq!(p.readiness_endpoint(&held, named), watch::NVAL);
    }

    #[test]
    fn rendezvous_grants_and_independent_flags_preserve_shared_data() {
        let mut p = Box::new(Pipes::new());
        let mut w = Wakes::default();
        let mut held = Held::default();
        let read = p.reserve_named(key(), 1, 1, 0).unwrap();
        assert!(!p.attach_named(read, &mut w).unwrap());
        let write = p.reserve_named(key(), 2, 1, WRITE_END).unwrap();
        assert!(p.attach_named(write, &mut w).unwrap());
        assert!(p.named_ready(read).unwrap());
        p.ack_named(&mut held, 1, ticket(), read).unwrap();
        p.ack_named(
            &mut held,
            1,
            NamedTicket {
                slot: 2,
                ..ticket()
            },
            write,
        )
        .unwrap();
        let other = p.reserve_named(key(), 3, 1, NONBLOCK).unwrap();
        assert!(p.attach_named(other, &mut w).unwrap());
        p.take_named(&mut held, other).unwrap();
        p.set_flags_endpoint(&held, read, APPEND).unwrap();
        assert_eq!(p.flags_endpoint(&held, other), Ok(NONBLOCK));
        assert_eq!(p.flags_endpoint(&held, read), Ok(APPEND));
        assert_eq!(p.write_endpoint(&held, write, b"abc", &mut w), Ok(Some(3)));
        let mut out = [0; 3];
        assert_eq!(p.read_endpoint(&held, other, &mut out, &mut w), Ok(Some(3)));
        assert_eq!(&out, b"abc");
        assert_eq!(p.ack_endpoint(&held, 1, ticket()), Some(read));
        assert_eq!(p.ack_endpoint(&held, 2, ticket()), None);
        p.close_endpoint(&mut held, write, &mut w).unwrap();
        assert_eq!(p.read_endpoint(&held, read, &mut out, &mut w), Ok(Some(0)));
        p.close_endpoint(&mut held, read, &mut w).unwrap();
        p.close_endpoint(&mut held, other, &mut w).unwrap();
        assert_eq!(p.live(), 0);
    }

    #[test]
    fn cancelled_grant_retains_original_ring_and_reused_description_rejects_old_generation() {
        let mut p = Box::new(Pipes::new());
        let mut held = Held::default();
        let mut w = Wakes::default();
        let grant = p.reserve_named(key(), 1, 1, WRITE_END | NONBLOCK).unwrap();
        assert_eq!(p.attach_named(grant, &mut w), Err(NO_READER));
        assert_eq!(p.live(), 1);
        p.cancel_named(grant, &mut w).unwrap();
        assert_eq!(p.live(), 0);
        let read = p.reserve_named(key(), 1, 1, NONBLOCK).unwrap();
        assert_eq!(grant.id, read.id);
        assert_ne!(grant.generation, read.generation);
        p.attach_named(read, &mut w).unwrap();
        p.take_named(&mut held, read).unwrap();
        assert_eq!(p.flags_endpoint(&held, grant), Err(BAD_FD));
        assert_eq!(p.readiness_endpoint(&held, grant), proto_wire::watch::NVAL);
        assert_eq!(p.clone_endpoints(&held, &[grant]), Err(BAD_FD));
        let mut child = p.clone_endpoints(&held, &[read, read]).unwrap();
        assert_eq!(child.count(), 1);
        p.close_endpoint(&mut held, read, &mut w).unwrap();
        assert_eq!(p.live(), 1);
        assert!(p.gone(&mut child));
        assert!(!p.step(&mut w));
        assert_eq!(p.live(), 0);
    }

    #[test]
    fn independent_named_descriptions_preserve_existing_anonymous_capacity() {
        let mut p = Box::new(Pipes::new());
        let mut owners = [Held::default(); 4];
        for index in 0..63 {
            let owner = index / CREATED_MAX;
            p.create(&mut owners[owner], owner as u64 + 1, owner as u64 + 1, 0)
                .unwrap();
        }
        let mut named = Held::default();
        let mut wakes = Wakes::default();
        for _ in 0..3 {
            let endpoint = p.reserve_named(key(), 5, 5, NONBLOCK).unwrap();
            assert!(p.attach_named(endpoint, &mut wakes).unwrap());
            p.take_named(&mut named, endpoint).unwrap();
        }
        assert_eq!(p.live(), PIPES);
        assert_eq!(named.count(), 3);
        assert_eq!(owners.iter().map(Held::count).sum::<usize>(), 126);
        assert_eq!(p.create(&mut named, 5, 5, 0), Err(NFILE));
    }

    #[test]
    fn named_description_root_budget_keeps_ring_original_payer() {
        let mut p = Box::new(Pipes::new());
        let mut endpoints = Vec::new();
        for _ in 0..NAMED_ROOT_MAX {
            endpoints.push(p.reserve_named(key(), 10, 20, NONBLOCK).unwrap());
        }
        assert_eq!(p.reserve_named(key(), 10, 20, NONBLOCK), Err(NFILE));
        for _ in NAMED_ROOT_MAX..NAMED_MAX {
            endpoints.push(p.reserve_named(key(), 30, 40, NONBLOCK).unwrap());
        }
        assert_eq!(p.live(), 1);
        assert_eq!(p.reserve_named(key(), 50, 60, NONBLOCK), Err(NFILE));
        let mut wakes = Wakes::default();
        for &endpoint in &endpoints[..NAMED_ROOT_MAX] {
            p.cancel_named(endpoint, &mut wakes).unwrap();
        }
        let remaining = endpoints[NAMED_ROOT_MAX];
        let ring = &p.pipes[usize::from(p.named_description(remaining).unwrap().ring)];
        assert_eq!((ring.creator, ring.root), (10, 20));
        assert_eq!(p.live(), 1);
        for &endpoint in &endpoints[NAMED_ROOT_MAX..] {
            p.cancel_named(endpoint, &mut wakes).unwrap();
        }
        assert_eq!(p.live(), 0);
        let fresh = p.reserve_named(key(), 50, 60, NONBLOCK).unwrap();
        let ring = &p.pipes[usize::from(p.named_description(fresh).unwrap().ring)];
        assert_eq!((ring.creator, ring.root), (50, 60));
    }

    #[test]
    fn named_atomic_write_refusal_preserves_data_and_other_writer_reference() {
        let mut p = Box::new(Pipes::new());
        let mut held = Held::default();
        let mut wakes = Wakes::default();
        let read = p.reserve_named(key(), 1, 1, NONBLOCK).unwrap();
        p.attach_named(read, &mut wakes).unwrap();
        p.take_named(&mut held, read).unwrap();
        let writers: Vec<_> = (0..2)
            .map(|_| {
                let endpoint = p.reserve_named(key(), 1, 1, WRITE_END | NONBLOCK).unwrap();
                p.attach_named(endpoint, &mut wakes).unwrap();
                p.take_named(&mut held, endpoint).unwrap();
                endpoint
            })
            .collect();
        let bytes = [0x5a; ATOMIC];
        for _ in 0..(CAPACITY / ATOMIC - 1) {
            assert_eq!(
                p.write_endpoint(&held, writers[0], &bytes, &mut wakes),
                Ok(Some(ATOMIC))
            );
        }
        assert_eq!(
            p.write_endpoint(&held, writers[0], &bytes[..ATOMIC / 2], &mut wakes),
            Ok(Some(ATOMIC / 2))
        );
        let before = p.stat_endpoint(&held, read).unwrap().1;
        assert_eq!(
            p.write_endpoint(&held, writers[1], &[0x33; ATOMIC], &mut wakes),
            Err(AGAIN)
        );
        assert_eq!(p.stat_endpoint(&held, read).unwrap().1, before);
        let mut out = [0; CAPACITY];
        assert_eq!(
            p.read_endpoint(&held, read, &mut out, &mut wakes),
            Ok(Some(before as usize))
        );
        assert!(out[..before as usize].iter().all(|&b| b == 0x5a));
        p.close_endpoint(&mut held, writers[0], &mut wakes).unwrap();
        assert_eq!(
            p.read_endpoint(&held, read, &mut out, &mut wakes),
            Err(AGAIN)
        );
        assert_eq!(
            p.write_endpoint(&held, writers[1], &bytes, &mut wakes),
            Ok(Some(ATOMIC))
        );
        p.close_endpoint(&mut held, writers[1], &mut wakes).unwrap();
        assert_eq!(
            p.read_endpoint(&held, read, &mut out, &mut wakes),
            Ok(Some(ATOMIC))
        );
        assert_eq!(
            p.read_endpoint(&held, read, &mut out, &mut wakes),
            Ok(Some(0))
        );
    }

    #[test]
    fn nine_independent_read_descriptions_subscribe_once_and_each_reports_ready() {
        let mut p = Box::new(Pipes::new());
        let mut held = Held::default();
        let mut wakes = Wakes::default();
        let mut set = proto_pipe::WatchSet::new();
        set.len = 9;
        let mut queues = [0; proto_wire::watch::MAX];
        for (i, queue) in queues.iter_mut().enumerate().take(set.len) {
            let endpoint = p.reserve_named(key(), 1, 1, NONBLOCK).unwrap();
            p.attach_named(endpoint, &mut wakes).unwrap();
            p.take_named(&mut held, endpoint).unwrap();
            set.items[i] = proto_wire::watch::Item {
                description: endpoint.id,
                events: proto_wire::watch::IN,
            };
            set.generations[i] = endpoint.generation;
            *queue = p.queue_end(endpoint).unwrap() as u8;
        }
        let writer = p.reserve_named(key(), 1, 1, WRITE_END | NONBLOCK).unwrap();
        p.attach_named(writer, &mut wakes).unwrap();
        p.take_named(&mut held, writer).unwrap();
        assert_eq!(set.endpoints().count(), 9);
        assert!(!set.ready(|e| p.readiness_endpoint(&held, e)).any());
        let unique: Vec<_> = crate::watches::unique_queues(&queues[..set.len]).collect();
        assert_eq!(unique.len(), 1);
        for &queue in &unique {
            p.wait_new(queue, (1, 100), |_| true).unwrap();
        }
        for key in 0..WAITERS - 1 {
            p.wait_new(unique[0], (2, key as u64), |_| true).unwrap();
        }
        assert_eq!(p.wait_new(unique[0], (2, 99), |_| true), Err(AGAIN));
        p.write_endpoint(&held, writer, b"x", &mut wakes).unwrap();
        let ready = set.ready(|e| p.readiness_endpoint(&held, e));
        assert_eq!(&ready.events[..set.len], &[proto_wire::watch::IN; 9]);
        for i in 0..set.len {
            assert_eq!(set.endpoint(i).generation, set.generations[i]);
        }
    }

    #[test]
    fn named_and_anonymous_holds_share_session_limit() {
        let mut p = Box::new(Pipes::new());
        let mut held = Held::default();
        for _ in 0..15 {
            p.create(&mut held, 1, 1, 0).unwrap();
        }
        let a = p.reserve_named(key(), 1, 1, NONBLOCK).unwrap();
        let b = p.reserve_named(key(), 1, 1, NONBLOCK).unwrap();
        let c = p.reserve_named(key(), 1, 1, NONBLOCK).unwrap();
        let mut wakes = Wakes::default();
        for endpoint in [a, b, c] {
            p.attach_named(endpoint, &mut wakes).unwrap();
        }
        p.take_named(&mut held, a).unwrap();
        p.take_named(&mut held, b).unwrap();
        assert_eq!(p.take_named(&mut held, c), Err(MFILE));
        assert_eq!(held.count(), HELD_MAX);
        p.cancel_named(c, &mut wakes).unwrap();
    }
}
