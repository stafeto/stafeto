// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tables of the switch (note Sh4, 3.5): a byte per port and protocol
//! (0 the stack, 1..=32 a group, `BLOCK_MARK` + c the ephemeral block of
//! consumer c), the groups, the consumers and the flows. Only the switch
//! thread writes them; the stack thread asks through the command ring
//! (`commands.rs`), and a debug build checks the thread of every write.

use super::ring::{ConsumerRing, Poll, Violation};
use super::route::Reason;
use crate::demux::PROBE_LIMIT;
use crate::ports::{EPHEMERAL_FIRST, PortMap, Proto};
use core::hash::Hasher;
#[allow(deprecated)] // SipHasher is in core and has no replacement there.
use core::hash::SipHasher;

pub const MAX_CONSUMERS: usize = 8;
pub const MAX_GROUPS: usize = 32;
pub const MAX_MEMBERS: usize = 8;
/// The port-table value of consumer c's block is `BLOCK_MARK + c`.
pub const BLOCK_MARK: u8 = 64;
pub const BLOCK_PORTS: u16 = 512;
const BLOCKS: usize = 32;
/// Seconds a block rests after its consumer left (TIME-WAIT outlives the process).
pub const QUARANTINE: u32 = 60;

pub const FIN_OUT: u16 = 1;
pub const FIN_IN: u16 = 2;
/// A RST the consumer sent: the connection is over.
pub const RST: u16 = 4;
/// A RST that came for the consumer's flow. The switch sees no sequence numbers, so it
/// cannot tell a blind RST (RFC 5961 makes the stack ignore it) from a true one; the next
/// segment of the flow in either direction takes the mark off, a true RST has none after it.
pub const RST_PEER: u16 = 16;
/// The flow was made by a SYN nobody has confirmed yet (see `Flows`).
pub const UNCONFIRMED: u16 = 8;
/// Seconds an unconfirmed flow lives: shorter than the stack's SYN-ACK retries, longer than a round trip.
pub const EMBRYO_AGE: u32 = 30;
pub const CLOSING_AGE: u32 = 10;
pub const IDLE_AGE: u32 = 7500;
pub const SWEEP_STEP: usize = 256;
const EMPTY: u8 = 0xff;

/// What a flow is found by: the peer's address and port and our port (our
/// address is the one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowKey {
    pub peer: [u8; 4],
    pub peer_port: u16,
    pub own_port: u16,
}

impl FlowKey {
    fn bytes(&self) -> [u8; 8] {
        let mut b = [0; 8];
        b[..4].copy_from_slice(&self.peer);
        b[4..6].copy_from_slice(&self.peer_port.to_le_bytes());
        b[6..].copy_from_slice(&self.own_port.to_le_bytes());
        b
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Flow {
    key: [u8; 8],
    pub consumer: u8,
    pub generation: u8,
    pub flags: u16,
    pub seen: u32,
}
const _: () = assert!(core::mem::size_of::<Flow>() == 16);

impl Flow {
    pub const EMPTY: Flow = Flow {
        key: [0; 8],
        consumer: EMPTY,
        generation: 0,
        flags: 0,
        seen: 0,
    };
    fn is_empty(&self) -> bool {
        self.consumer == EMPTY
    }
    pub fn closing(&self) -> bool {
        self.flags & (RST | RST_PEER) != 0 || self.flags & (FIN_OUT | FIN_IN) == FIN_OUT | FIN_IN
    }
}

/// Open addressing with linear probing over caller-given places, at most
/// half full, a chain of at most `PROBE_LIMIT`, SipHash-2-4 under a secret.
///
/// A flow made by a SYN of the wire or of the stack is unconfirmed: nobody
/// has shown that the sender can read our answer. It is confirmed by the
/// first segment of the peer that has ACK and no SYN, RST, or by any
/// segment of the consumer but a SYN-ACK. Unconfirmed flows live
/// `EMBRYO_AGE` seconds, are at most a quarter of the table, and a new SYN
/// takes the place of the oldest one in its chain when the table, the
/// share or the chain is full. Confirmed flows are never evicted.
pub struct Flows<'a> {
    slots: &'a mut [Flow],
    keys: (u64, u64),
    used: usize,
    unconfirmed: usize,
    cursor: usize,
    /// Unconfirmed flows a newer SYN took the place of.
    pub evicted: u32,
    /// Unconfirmed flows the sweep removed after `EMBRYO_AGE`.
    pub expired: u32,
}

impl<'a> Flows<'a> {
    pub fn new(slots: &'a mut [Flow], secret: &[u8; 16]) -> Flows<'a> {
        slots.fill(Flow::EMPTY);
        let k = |r: &[u8]| u64::from_le_bytes(r.try_into().expect("8 bytes"));
        Flows {
            slots,
            keys: (k(&secret[..8]), k(&secret[8..])),
            used: 0,
            unconfirmed: 0,
            cursor: 0,
            evicted: 0,
            expired: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.used
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    pub fn capacity(&self) -> usize {
        self.slots.len() / 2
    }

    /// Unconfirmed flows now.
    pub fn unconfirmed(&self) -> usize {
        self.unconfirmed
    }

    /// Most unconfirmed flows at once: a quarter of the table.
    pub fn unconfirmed_limit(&self) -> usize {
        self.capacity() / 4
    }

    #[allow(deprecated)]
    pub fn hash(&self, key: &FlowKey) -> u64 {
        let mut h = SipHasher::new_with_keys(self.keys.0, self.keys.1);
        h.write(&key.bytes());
        h.finish()
    }

    #[allow(deprecated)]
    fn home(&self, key: &[u8; 8]) -> usize {
        let mut h = SipHasher::new_with_keys(self.keys.0, self.keys.1);
        h.write(key);
        (h.finish() % self.slots.len() as u64) as usize
    }

    pub fn get(&mut self, i: usize) -> &mut Flow {
        &mut self.slots[i]
    }

    pub fn find(&self, key: &FlowKey) -> Option<usize> {
        let (key, n) = (key.bytes(), self.slots.len());
        let home = self.home(&key);
        for d in 0..PROBE_LIMIT {
            let i = (home + d) % n;
            let f = &self.slots[i];
            if f.is_empty() {
                return None;
            }
            if f.key == key {
                return Some(i);
            }
        }
        None
    }

    /// A new flow; None when the table is half full or the chain would pass the limit.
    pub fn insert(
        &mut self,
        key: &FlowKey,
        consumer: u8,
        generation: u8,
        now: u32,
    ) -> Option<usize> {
        if self.used >= self.capacity() {
            return None;
        }
        self.place(key, consumer, generation, now, 0)
    }

    fn place(
        &mut self,
        key: &FlowKey,
        consumer: u8,
        generation: u8,
        now: u32,
        flags: u16,
    ) -> Option<usize> {
        let (key, n) = (key.bytes(), self.slots.len());
        let home = self.home(&key);
        for d in 0..PROBE_LIMIT {
            let i = (home + d) % n;
            if self.slots[i].is_empty() {
                self.slots[i] = Flow {
                    key,
                    consumer,
                    generation,
                    flags,
                    seen: now,
                };
                self.used += 1;
                self.unconfirmed += usize::from(flags & UNCONFIRMED != 0);
                return Some(i);
            }
        }
        None
    }

    /// A new unconfirmed flow. When the table, the unconfirmed share or the
    /// chain is full the oldest unconfirmed flow of the chain goes first (it
    /// is returned for the owner's books, also when the new flow found no
    /// place after all). The first is None when nothing could be made.
    pub fn insert_embryo(
        &mut self,
        key: &FlowKey,
        consumer: u8,
        generation: u8,
        now: u32,
    ) -> (Option<usize>, Option<Flow>) {
        let home = self.home(&key.bytes());
        let n = self.slots.len();
        let chain_full = (0..PROBE_LIMIT).all(|d| !self.slots[(home + d) % n].is_empty());
        let mut evicted = None;
        if self.used >= self.capacity()
            || self.unconfirmed >= self.unconfirmed_limit()
            || chain_full
        {
            let Some(i) = self.oldest_embryo(home, now) else {
                return (None, None);
            };
            evicted = Some(self.slots[i]);
            self.remove_at(i);
            self.evicted += 1;
        }
        (
            self.place(key, consumer, generation, now, UNCONFIRMED),
            evicted,
        )
    }

    /// The oldest unconfirmed flow in the chain that starts at `home`.
    fn oldest_embryo(&self, home: usize, now: u32) -> Option<usize> {
        let n = self.slots.len();
        let mut best: Option<(usize, u32)> = None;
        for d in 0..PROBE_LIMIT {
            let i = (home + d) % n;
            let f = &self.slots[i];
            if f.is_empty() {
                break;
            }
            let age = now.wrapping_sub(f.seen);
            if f.flags & UNCONFIRMED != 0 && best.is_none_or(|b| age > b.1) {
                best = Some((i, age));
            }
        }
        best.map(|b| b.0)
    }

    /// The peer or the consumer showed the flow is real.
    pub fn confirm(&mut self, i: usize) {
        let f = &mut self.slots[i];
        if f.flags & UNCONFIRMED != 0 {
            f.flags &= !UNCONFIRMED;
            self.unconfirmed -= 1;
        }
    }

    /// Gives the flow at `i` to a new owner (a SYN that finds a dead flow);
    /// `embryo` starts it unconfirmed.
    pub fn reassign(&mut self, i: usize, consumer: u8, generation: u8, now: u32, embryo: bool) {
        self.confirm(i);
        let f = &mut self.slots[i];
        let flags = if embryo { UNCONFIRMED } else { 0 };
        (f.consumer, f.generation, f.flags, f.seen) = (consumer, generation, flags, now);
        self.unconfirmed += usize::from(embryo);
    }

    /// Takes the entry at `i` out, shifting back the chain behind it.
    pub fn remove_at(&mut self, i: usize) {
        let n = self.slots.len();
        self.unconfirmed -= usize::from(self.slots[i].flags & UNCONFIRMED != 0);
        let (mut hole, mut j) = (i, i);
        loop {
            j = (j + 1) % n;
            if self.slots[j].is_empty() {
                break;
            }
            let home = self.home(&self.slots[j].key);
            if (j + n - home) % n >= (j + n - hole) % n {
                self.slots[hole] = self.slots[j];
                hole = j;
            }
        }
        self.slots[hole] = Flow::EMPTY;
        self.used -= 1;
    }

    /// Looks at `SWEEP_STEP` places from where the last call stopped and
    /// removes flows of dead consumers (the generation is not the live
    /// one), closing ones older than `CLOSING_AGE` and idle ones.
    pub fn sweep(&mut self, now: u32, consumers: &mut [Option<Consumer>; MAX_CONSUMERS]) {
        for _ in 0..SWEEP_STEP {
            let f = self.slots[self.cursor];
            if !f.is_empty() {
                let owner = consumers
                    .get_mut(usize::from(f.consumer))
                    .and_then(Option::as_mut)
                    .filter(|c| c.generation == f.generation);
                let age = now.wrapping_sub(f.seen);
                let embryo = f.flags & UNCONFIRMED != 0 && age > EMBRYO_AGE;
                if owner.is_none() || embryo || (f.closing() && age > CLOSING_AGE) || age > IDLE_AGE
                {
                    self.expired += u32::from(embryo);
                    if let Some(c) = owner {
                        c.flows = c.flows.saturating_sub(1);
                    }
                    self.remove_at(self.cursor);
                    continue;
                }
            }
            self.cursor = (self.cursor + 1) % self.slots.len();
        }
    }
}

pub struct Consumer {
    pub ring: ConsumerRing,
    pub generation: u8,
    pub block: u16,
    pub flows: u32,
    arp_second: u32,
    arp_count: u32,
}

impl Consumer {
    /// ARP requests are at most 10 a second.
    pub fn arp_allowed(&mut self, now: u32) -> bool {
        if self.arp_second != now {
            (self.arp_second, self.arp_count) = (now, 0);
        }
        self.arp_count += 1;
        self.arp_count <= 10
    }

    pub fn in_block(&self, port: u16) -> bool {
        port.wrapping_sub(self.block) < BLOCK_PORTS
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Group {
    pub proto: Proto,
    pub first: u16,
    pub count: u8,
    pub holders: u16,
    /// (consumer, generation)
    pub members: [Option<(u8, u8)>; MAX_MEMBERS],
}

/// The address of device 0, as the switch knows it.
#[derive(Clone, Copy, Debug)]
pub struct Own {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub prefix: u8,
}

/// Checks the thread that writes the tables (debug builds): after `claim`
/// only that thread may.
pub struct Guard {
    tag: fn() -> u32,
    owner: Option<u32>,
}

impl Guard {
    pub fn check(&self) {
        debug_assert!(
            self.owner.is_none_or(|o| o == (self.tag)()),
            "a table is written outside the switch thread"
        );
    }
}

pub struct Tables<'a> {
    pub own: Own,
    /// Seconds, set by the switch at each step.
    pub now: u32,
    ports: &'a mut [u8],
    pub groups: [Option<Group>; MAX_GROUPS],
    pub consumers: [Option<Consumer>; MAX_CONSUMERS],
    pub flows: Flows<'a>,
    pub refused: [u32; Reason::COUNT],
    pub guard: Guard,
}

impl<'a> Tables<'a> {
    /// `ports` is 2 x 65 536 bytes (TCP then UDP), zeroed; `tag` names the calling thread.
    pub fn new(own: Own, ports: &'a mut [u8], flows: Flows<'a>, tag: fn() -> u32) -> Tables<'a> {
        assert!(ports.len() == 2 * 65536);
        ports.fill(0);
        Tables {
            own,
            now: 0,
            ports,
            groups: [None; MAX_GROUPS],
            consumers: [const { None }; MAX_CONSUMERS],
            flows,
            refused: [0; Reason::COUNT],
            guard: Guard { tag, owner: None },
        }
    }

    /// The calling thread is the switch from now on.
    pub fn claim(&mut self) {
        self.guard.owner = Some((self.guard.tag)());
    }

    fn at(proto: Proto, port: u16) -> usize {
        usize::from(proto == Proto::Udp) * 65536 + usize::from(port)
    }

    pub fn port(&self, proto: Proto, port: u16) -> u8 {
        self.ports[Self::at(proto, port)]
    }

    fn mark(&mut self, proto: Proto, first: u16, count: u16, v: u8) {
        assert!(u32::from(first) + u32::from(count) <= 65536);
        let at = Self::at(proto, first);
        self.ports[at..at + usize::from(count)].fill(v);
    }

    pub fn group(&self, number: u8) -> Option<&Group> {
        self.groups
            .get(usize::from(number).wrapping_sub(1))?
            .as_ref()
    }

    /// Whether consumer `c` of generation `g` is there and its ring whole.
    pub fn live(&self, c: u8, g: u8) -> bool {
        self.consumers
            .get(usize::from(c))
            .and_then(Option::as_ref)
            .is_some_and(|x| x.generation == g && !x.ring.is_broken())
    }

    pub fn attach(&mut self, c: u8, generation: u8, ring: ConsumerRing, block: u16) -> bool {
        self.guard.check();
        if u32::from(block) + u32::from(BLOCK_PORTS) > 65536 {
            return false;
        }
        let Some(slot @ None) = self.consumers.get_mut(usize::from(c)) else {
            return false;
        };
        *slot = Some(Consumer {
            ring,
            generation,
            block,
            flows: 0,
            arp_second: 0,
            arp_count: 0,
        });
        for proto in [Proto::Tcp, Proto::Udp] {
            self.mark(proto, block, BLOCK_PORTS, BLOCK_MARK + c);
        }
        true
    }

    /// Takes the consumer out of its groups and its block; its flows die with its generation.
    pub fn detach(&mut self, c: u8) -> Option<u8> {
        self.guard.check();
        let gone = self.consumers.get_mut(usize::from(c))?.take()?;
        for g in self.groups.iter_mut().flatten() {
            g.members
                .iter_mut()
                .filter(|m| m.is_some_and(|m| m.0 == c))
                .for_each(|m| *m = None);
        }
        for proto in [Proto::Tcp, Proto::Udp] {
            self.mark(proto, gone.block, BLOCK_PORTS, 0);
        }
        Some(gone.generation)
    }

    /// Group `number` holds the ports, or one more holder when it holds them already.
    pub fn hold(&mut self, number: u8, proto: Proto, first: u16, count: u8) -> bool {
        self.guard.check();
        if first == 0 || u32::from(first) + u32::from(count) > 65536 || count == 0 {
            return false;
        }
        let Some(slot) = self.groups.get_mut(usize::from(number).wrapping_sub(1)) else {
            return false;
        };
        match slot {
            Some(g) if (g.proto, g.first, g.count) == (proto, first, count) => g.holders += 1,
            Some(_) => return false,
            None => {
                *slot = Some(Group {
                    proto,
                    first,
                    count,
                    holders: 1,
                    members: [None; MAX_MEMBERS],
                });
                self.mark(proto, first, u16::from(count), number);
            }
        }
        true
    }

    /// One holder less; the last one takes the group and its ports.
    pub fn release(&mut self, number: u8) {
        self.guard.check();
        let Some(slot) = self.groups.get_mut(usize::from(number).wrapping_sub(1)) else {
            return;
        };
        if let Some(g) = slot {
            g.holders -= 1;
            if g.holders == 0 {
                let (proto, first, count) = (g.proto, g.first, u16::from(g.count));
                *slot = None;
                self.mark(proto, first, count, 0);
            }
        }
    }

    pub fn join(&mut self, number: u8, c: u8) -> bool {
        self.guard.check();
        let generation = match self.consumers.get(usize::from(c)).and_then(Option::as_ref) {
            Some(x) => x.generation,
            None => return false,
        };
        let Some(Some(g)) = self.groups.get_mut(usize::from(number).wrapping_sub(1)) else {
            return false;
        };
        if g.members.iter().flatten().any(|m| m.0 == c) {
            return true;
        }
        let Some(free) = g.members.iter_mut().find(|m| m.is_none()) else {
            return false;
        };
        *free = Some((c, generation));
        true
    }

    pub fn leave(&mut self, number: u8, c: u8) {
        self.guard.check();
        if let Some(Some(g)) = self.groups.get_mut(usize::from(number).wrapping_sub(1)) {
            g.members
                .iter_mut()
                .filter(|m| m.is_some_and(|m| m.0 == c))
                .for_each(|m| *m = None);
        }
    }

    /// The one read of every ring's indices for this step; `broke` hears the rings that broke.
    pub fn poll_rings(&mut self, mut broke: impl FnMut(u8, Violation)) {
        self.guard.check();
        for (c, slot) in self.consumers.iter_mut().enumerate() {
            if let Some(Poll::Broke(v)) = slot.as_mut().map(|x| x.ring.poll()) {
                broke(c as u8, v);
            }
        }
    }

    /// A new unconfirmed flow for a SYN; false when there is no room. The owner of a
    /// flow it took the place of gets its count back.
    pub fn insert_embryo(&mut self, key: &FlowKey, consumer: u8, generation: u8) -> bool {
        self.guard.check();
        let (slot, evicted) = self
            .flows
            .insert_embryo(key, consumer, generation, self.now);
        if let Some(f) = evicted {
            if let Some(c) = self
                .consumers
                .get_mut(usize::from(f.consumer))
                .and_then(Option::as_mut)
                .filter(|c| c.generation == f.generation)
            {
                c.flows = c.flows.saturating_sub(1);
            }
        }
        slot.is_some()
    }

    /// One sweep step at the time the switch last set. The switch calls it
    /// after each batch of frames; when no frames come it must be called
    /// from an idle timer too (Sh4b2: every 100 ms, with `sweep_at`), or
    /// unconfirmed and dead flows stay while the line is quiet.
    pub fn sweep(&mut self) {
        self.guard.check();
        self.flows.sweep(self.now, &mut self.consumers);
    }

    /// `sweep` at time `now`, for the idle timer.
    pub fn sweep_at(&mut self, now: u32) {
        self.now = now;
        self.sweep();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Block {
    Free,
    Held,
    Rest(u32),
}

/// The stack side's books of the consumer numbers, their generations and
/// the 512-port blocks of the ephemeral range: a block is held in the
/// port registry while it is in use and for `QUARANTINE` seconds after.
pub struct Blocks {
    state: [Block; BLOCKS],
    owner: [Option<usize>; MAX_CONSUMERS],
    generation: [u8; MAX_CONSUMERS],
}

impl Blocks {
    pub const fn new() -> Blocks {
        Blocks {
            state: [Block::Free; BLOCKS],
            owner: [None; MAX_CONSUMERS],
            generation: [0; MAX_CONSUMERS],
        }
    }

    fn first(b: usize) -> u16 {
        EPHEMERAL_FIRST + (b as u16) * BLOCK_PORTS
    }

    fn ports(b: usize) -> impl Iterator<Item = u16> {
        let first = Self::first(b);
        (0..BLOCK_PORTS).map(move |i| first + i)
    }

    /// Frees the blocks whose rest is over.
    pub fn expire(&mut self, map: &mut PortMap, now: u32) {
        for (b, s) in self.state.iter_mut().enumerate() {
            if matches!(*s, Block::Rest(until) if now.wrapping_sub(until) < u32::MAX / 2) {
                Self::ports(b).for_each(|p| map.release(p));
                *s = Block::Free;
            }
        }
    }

    /// A consumer number, its new generation (never 0) and the first port of its block.
    pub fn alloc(&mut self, map: &mut PortMap, now: u32) -> Option<(u8, u8, u16)> {
        self.expire(map, now);
        let c = self.owner.iter().position(Option::is_none)?;
        let b = (0..BLOCKS)
            .rev()
            .find(|&b| self.state[b] == Block::Free && Self::ports(b).all(|p| !map.held(p)))?;
        Self::ports(b).for_each(|p| map.hold(p));
        self.state[b] = Block::Held;
        self.owner[c] = Some(b);
        self.generation[c] = self.generation[c].checked_add(1).unwrap_or(1);
        Some((c as u8, self.generation[c], Self::first(b)))
    }

    /// The consumer left: its number is free, its block rests.
    pub fn release(&mut self, c: u8, now: u32) {
        if let Some(b) = self.owner.get_mut(usize::from(c)).and_then(Option::take) {
            self.state[b] = Block::Rest(now + QUARANTINE);
        }
    }
}

impl Default for Blocks {
    fn default() -> Blocks {
        Blocks::new()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::switchlogic::ring::tests::Rig;
    use proto_net::switch::Layout;

    pub const SECRET: [u8; 16] = *b"0123456789abcdef";
    pub const OWN: Own = Own {
        ip: [10, 0, 2, 15],
        mac: [0x52, 0x54, 0, 1, 2, 3],
        prefix: 24,
    };

    pub fn tag() -> u32 {
        std::thread_local!(static ID: u32 = {
            static NEXT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
            NEXT.fetch_add(1, Ordering::Relaxed)
        });
        ID.with(|i| *i)
    }
    use core::sync::atomic::Ordering;

    /// Three consumers (blocks 49152, 49664, 50176; 64 cells each in FILL), TCP group 1 on
    /// 8080 and UDP group 2 on 5353, both with members 0 and 1.
    pub fn with_flows<R>(places: usize, f: impl FnOnce(&mut Tables<'_>, &[Rig]) -> R) -> R {
        let rigs: Vec<Rig> = (0..3)
            .map(|_| Rig::new(Layout::new(256, 64).unwrap()))
            .collect();
        let (mut ports, mut mem) = (vec![0u8; 131072], vec![Flow::EMPTY; places]);
        let mut t = Tables::new(OWN, &mut ports, Flows::new(&mut mem, &SECRET), tag);
        for (c, rig) in rigs.iter().enumerate() {
            rig.fill(&(0..64).collect::<Vec<_>>());
            assert!(t.attach(c as u8, 1, rig.ring(), 49152 + 512 * c as u16));
        }
        assert!(t.hold(1, Proto::Tcp, 8080, 1) && t.hold(2, Proto::Udp, 5353, 1));
        for g in [1, 2] {
            assert!(t.join(g, 0) && t.join(g, 1));
        }
        t.poll_rings(|_, _| panic!("a ring broke"));
        f(&mut t, &rigs)
    }

    pub fn with<R>(f: impl FnOnce(&mut Tables<'_>, &[Rig]) -> R) -> R {
        with_flows(4096, f)
    }

    /// A fixed-seed xorshift for the tests that throw hostile values.
    pub struct Rng(pub u64);

    impl Rng {
        pub fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    pub fn key(n: u32) -> FlowKey {
        FlowKey {
            peer: [1, 2, 3, 4],
            peer_port: n as u16,
            own_port: (n >> 16) as u16,
        }
    }

    #[test]
    fn flows_insert_find_and_remove_keep_the_chains() {
        let mut mem = vec![Flow::EMPTY; 64];
        let mut f = Flows::new(&mut mem, &SECRET);
        for n in 0..32 {
            assert!(f.insert(&key(n), 1, 1, 0).is_some(), "{n}");
        }
        assert_eq!(f.insert(&key(99), 1, 1, 0), None, "half full");
        for n in (0..32).step_by(2) {
            f.remove_at(f.find(&key(n)).unwrap());
        }
        assert_eq!(f.len(), 16);
        for n in 0..32 {
            assert_eq!(f.find(&key(n)).is_some(), n % 2 == 1, "{n}");
        }
    }

    #[test]
    fn a_chain_past_the_limit_is_not_made() {
        let mut mem = vec![Flow::EMPTY; 4096];
        let mut f = Flows::new(&mut mem, &SECRET);
        let mut refused = false;
        for n in 0..2048 {
            refused |= f.insert(&key(n), 0, 1, 0).is_none();
            assert!(n == 0 || f.find(&key(n)).is_some() || refused);
        }
        assert!(f.len() <= 2048);
    }

    fn consumers_with(c: u8, generation: u8) -> [Option<Consumer>; MAX_CONSUMERS] {
        let rig = Rig::new(Layout::new(256, 64).unwrap());
        let mut t: [Option<Consumer>; MAX_CONSUMERS] = [const { None }; MAX_CONSUMERS];
        t[usize::from(c)] = Some(Consumer {
            ring: rig.ring(),
            generation,
            block: 49152,
            flows: 3,
            arp_second: 0,
            arp_count: 0,
        });
        std::mem::forget(rig);
        t
    }

    #[test]
    fn the_sweep_removes_closing_dead_and_idle_flows_in_steps() {
        let mut mem = vec![Flow::EMPTY; 1024];
        let mut f = Flows::new(&mut mem, &SECRET);
        let mut cs = consumers_with(2, 5);
        let at = |f: &mut Flows, n, c, g, t| f.insert(&key(n), c, g, t).unwrap();
        at(&mut f, 1, 2, 5, 20000);
        let closing = at(&mut f, 2, 2, 5, 20000);
        f.get(closing).flags = FIN_IN | FIN_OUT;
        let reset = at(&mut f, 3, 2, 5, 20000);
        f.get(reset).flags = RST;
        let half = at(&mut f, 4, 2, 5, 20000);
        f.get(half).flags = FIN_IN;
        at(&mut f, 5, 2, 4, 20000); // a stale generation
        at(&mut f, 6, 3, 1, 20000); // a consumer that is not there
        at(&mut f, 7, 2, 5, 20000 - IDLE_AGE - 1);
        for _ in 0..4 {
            f.sweep(20011, &mut cs);
        }
        assert_eq!(f.len(), 2);
        assert!(f.find(&key(1)).is_some() && f.find(&key(4)).is_some());
        assert_eq!(
            cs[2].as_ref().unwrap().flows,
            0,
            "closing, reset and idle left the count"
        );
        // Closing flows rest 10 s: not yet removed at 1010.
        let mut g = Flows::new(&mut mem, &SECRET);
        let i = g.insert(&key(8), 2, 5, 20000).unwrap();
        g.get(i).flags = RST;
        for _ in 0..8 {
            g.sweep(20010, &mut cs);
        }
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn ports_groups_and_blocks_are_marked_and_unmarked() {
        let (mut ports, mut mem) = (vec![0u8; 131072], vec![Flow::EMPTY; 64]);
        let mut t = Tables::new(OWN, &mut ports, Flows::new(&mut mem, &SECRET), tag);
        let rig = Rig::new(Layout::new(256, 64).unwrap());
        assert!(t.attach(3, 1, rig.ring(), 50176));
        assert!(!t.attach(3, 1, rig.ring(), 50176), "taken");
        assert_eq!(t.port(Proto::Udp, 50176 + 511), BLOCK_MARK + 3);
        assert_eq!(t.port(Proto::Tcp, 50176 + 512), 0);
        assert!(!t.hold(3, Proto::Tcp, 65535, 2), "past the last port");
        assert!(!t.hold(3, Proto::Tcp, 0, 1) && !t.hold(3, Proto::Tcp, 80, 0));
        assert!(
            !t.attach(4, 1, rig.ring(), 65535),
            "a block past the last port"
        );
        assert!(t.hold(1, Proto::Tcp, 8080, 2));
        assert!(t.hold(1, Proto::Tcp, 8080, 2), "a second holder");
        assert!(!t.hold(1, Proto::Tcp, 80, 1));
        assert_eq!((t.port(Proto::Tcp, 8081), t.port(Proto::Udp, 8081)), (1, 0));
        assert!(t.join(1, 3) && t.join(1, 3) && !t.join(1, 4) && !t.join(2, 3));
        assert_eq!(t.group(1).unwrap().members.iter().flatten().count(), 1);
        t.release(1);
        assert_eq!(t.port(Proto::Tcp, 8080), 1, "one holder left");
        t.release(1);
        assert_eq!((t.port(Proto::Tcp, 8080), t.group(1).is_none()), (0, true));
        assert!(t.hold(2, Proto::Udp, 53, 1) && t.join(2, 3));
        assert_eq!(t.detach(3), Some(1));
        assert_eq!(t.port(Proto::Udp, 50176), 0);
        assert!(t.group(2).unwrap().members.iter().all(Option::is_none));
        assert_eq!(t.detach(3), None);
    }

    #[test]
    fn eight_blocks_and_a_minute_of_rest_after_a_consumer_leaves() {
        let (mut b, mut map) = (Blocks::new(), PortMap::new());
        let firsts: Vec<u16> = (0..8).map(|_| b.alloc(&mut map, 100).unwrap().2).collect();
        assert!(b.alloc(&mut map, 100).is_none(), "eight consumers at most");
        assert!(
            firsts
                .iter()
                .all(|f| (49152..65536).contains(&(u32::from(*f) + 511)) && f % 512 == 0)
        );
        assert!(map.held(firsts[0]) && map.held(firsts[0] + 511));
        b.release(2, 200);
        let (c, g, first) = b.alloc(&mut map, 259).unwrap();
        assert_eq!(c, 2);
        assert_ne!(first, firsts[2], "the block rests until 260");
        assert_eq!(g, 2, "a new generation for the number");
        assert!(map.held(firsts[2]));
        b.release(c, 259);
        b.expire(&mut map, 260);
        assert!(!map.held(firsts[2]) && !map.held(firsts[2] + 511));
        assert_eq!(b.alloc(&mut map, 260).map(|a| a.2), Some(firsts[2]));
    }

    #[test]
    fn a_block_with_a_port_the_stack_uses_is_skipped() {
        let (mut b, mut map) = (Blocks::new(), PortMap::new());
        map.hold(65535);
        assert_eq!(b.alloc(&mut map, 0).unwrap().2, 64512);
    }

    #[test]
    fn the_stack_thread_cannot_write_a_table_outside_the_ring() {
        let (mut ports, mut mem) = (vec![0u8; 131072], vec![Flow::EMPTY; 64]);
        let mut t = Tables::new(OWN, &mut ports, Flows::new(&mut mem, &SECRET), tag);
        t.hold(1, Proto::Tcp, 80, 1);
        t.claim();
        t.hold(2, Proto::Tcp, 81, 1);
        let t = std::sync::Mutex::new(t);
        let other = std::thread::scope(|s| {
            s.spawn(|| {
                let mut t = t.lock().unwrap_or_else(|e| e.into_inner());
                t.hold(3, Proto::Tcp, 82, 1)
            })
            .join()
        });
        assert_eq!(
            other.is_err(),
            cfg!(debug_assertions),
            "a write from another thread panics in a debug build"
        );
    }
}
