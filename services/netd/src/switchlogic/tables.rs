// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tables of the switch (note Sh4, 3.5): a byte per port and protocol
//! (0 the stack, 1..=32 a group, `BLOCK_MARK` + c the ephemeral block of
//! consumer c, the consumers of the service's own process (the stack instances) counted
//! after those of the programs), the groups, the consumers and the flows. Only the switch
//! thread writes them; the stack thread asks through the command ring
//! (`commands.rs`), and a debug build checks the thread of every write.

use super::ring::{ConsumerRing, Poll, Violation};
use super::route::Reason;
use crate::demux::PROBE_LIMIT;
use crate::ports::{Claims, EPHEMERAL_FIRST, PortMap, Proto};
use core::hash::Hasher;
#[allow(deprecated)] // SipHasher is in core and has no replacement there.
use core::hash::SipHasher;

pub const MAX_CONSUMERS: usize = 8;
/// The stack instances of the service itself (internal consumers, `Internal`): instance k has
/// the number `INTERNAL_BASE + k` wherever a consumer's number is kept (flows, group members,
/// the marks of the port table), above those of the processes.
pub const MAX_INSTANCES: usize = 4;
pub const INTERNAL_BASE: u8 = MAX_CONSUMERS as u8;
pub const MAX_GROUPS: usize = 32;
pub const MAX_MEMBERS: usize = 8;
/// The port-table value of consumer c's block is `BLOCK_MARK + c`.
pub const BLOCK_MARK: u8 = 64;
/// The value `port` answers for a port the stack instance k holds in the claims
/// (`ports::Claims`) and the table itself leaves at 0: `OWN_MARK + k`.
pub const OWN_MARK: u8 = 128;
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
/// The flow is counted in `Group::flows` of the group that owns its port.
pub const GROUPED: u16 = 32;
/// The flow was made by a SYN nobody has confirmed yet (see `Flows`).
pub const UNCONFIRMED: u16 = 8;
/// Seconds an unconfirmed flow lives: shorter than the stack's SYN-ACK retries, longer than a round trip.
pub const EMBRYO_AGE: u32 = 30;
pub const CLOSING_AGE: u32 = 10;
pub const IDLE_AGE: u32 = 7500;
pub const SWEEP_STEP: usize = 128;
/// The flows one sweep step removes at most.
pub const SWEEP_REMOVALS: usize = 32;
const EMPTY: u8 = 0xff;

/// SYNs parked per group while no member is live (note Sh4, 3.4).
pub const PARK_PER_GROUP: usize = 16;
/// Bytes of a parked frame: a SYN has no data, so Ethernet, IP and TCP headers with options fit.
pub const PARK_FRAME: usize = 128;
/// Milliseconds a SYN waits for a member before it is dropped (the peer repeats it after 1 s).
pub const PARK_MS: u32 = 500;
/// Places the park needs.
pub const PARK_SLOTS: usize = MAX_GROUPS * PARK_PER_GROUP;
/// The least time between two looks at the park for SYNs past their term (ms): a look is a
/// pass over every place, which does not belong in each step.
pub const PARK_SCAN_MS: u32 = 16;

/// What a flow is found by: the peer's address and port and our port (our
/// address is the one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowKey {
    pub peer: [u8; 4],
    pub peer_port: u16,
    pub own_port: u16,
}

impl FlowKey {
    pub fn bytes(&self) -> [u8; 8] {
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
    pub generation: u32,
    pub seen: u32,
    pub flags: u16,
    pub consumer: u8,
}
const _: () = assert!(core::mem::size_of::<Flow>() == 20);

impl Flow {
    pub const EMPTY: Flow = Flow {
        key: [0; 8],
        generation: 0,
        seen: 0,
        flags: 0,
        consumer: EMPTY,
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
    rounds: u32,
    /// Unconfirmed flows a newer SYN took the place of.
    pub evicted: u32,
    /// Unconfirmed flows the sweep removed after `EMBRYO_AGE`.
    pub expired: u32,
}

impl<'a> Flows<'a> {
    pub fn new(slots: &'a mut [Flow], secret: &[u8; 16]) -> Flows<'a> {
        assert!(slots.len() >= 2, "a flow table has room for two flows");
        slots.fill(Flow::EMPTY);
        let k = |r: &[u8]| u64::from_le_bytes(r.try_into().expect("8 bytes"));
        Flows {
            slots,
            keys: (k(&secret[..8]), k(&secret[8..])),
            used: 0,
            unconfirmed: 0,
            cursor: 0,
            rounds: 0,
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
        generation: u32,
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
        generation: u32,
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
                    generation,
                    seen: now,
                    flags,
                    consumer,
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
        generation: u32,
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
    pub fn reassign(&mut self, i: usize, consumer: u8, generation: u32, now: u32, embryo: bool) {
        self.confirm(i);
        let f = &mut self.slots[i];
        let flags = f.flags & GROUPED | if embryo { UNCONFIRMED } else { 0 };
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
    /// one), closing ones older than `CLOSING_AGE`, unconfirmed ones older
    /// than `EMBRYO_AGE` and idle ones.
    ///
    /// At most `SWEEP_REMOVALS` flows go in one call; each removal shifts the chain behind it
    /// (at the half fill of the table about a dozen places, 24 at the most before a
    /// lookup gives up), so the work of a call is bounded, and the walk goes on in the next.
    pub fn sweep(&mut self, now: u32, books: &mut Books) {
        let mut removed = 0;
        for _ in 0..SWEEP_STEP {
            let f = self.slots[self.cursor];
            if !f.is_empty() {
                let age = now.wrapping_sub(f.seen);
                let embryo = f.flags & UNCONFIRMED != 0 && age > EMBRYO_AGE;
                if !books.owner_live(&f)
                    || embryo
                    || (f.closing() && age > CLOSING_AGE)
                    || age > IDLE_AGE
                {
                    self.expired += u32::from(embryo);
                    books.gone(&f);
                    self.remove_at(self.cursor);
                    removed += 1;
                    if removed >= SWEEP_REMOVALS {
                        return;
                    }
                    continue;
                }
            }
            self.cursor = (self.cursor + 1) % self.slots.len();
            self.rounds = self.rounds.wrapping_add(u32::from(self.cursor == 0));
        }
    }

    /// Full passes of the sweep over the table so far. A flow that is dead when this
    /// reads `r` is gone when it reads `r + 2`.
    pub fn rounds(&self) -> u32 {
        self.rounds
    }
}

/// What the removal of a flow touches: the books of its owner and its group.
pub struct Books<'b> {
    consumers: &'b mut [Option<Consumer>; MAX_CONSUMERS],
    instances: &'b mut [Option<Internal>; MAX_INSTANCES],
    groups: &'b mut [Option<Group>; MAX_GROUPS],
    ports: &'b mut [u8],
    freed: &'b mut u32,
}

impl Books<'_> {
    fn owner_live(&self, f: &Flow) -> bool {
        match instance_of(f.consumer) {
            Some(k) => self.instances[k]
                .as_ref()
                .is_some_and(|x| x.generation == f.generation),
            None => self
                .consumers
                .get(usize::from(f.consumer))
                .and_then(Option::as_ref)
                .is_some_and(|c| c.generation == f.generation),
        }
    }

    /// The flow is leaving the table: its owner and its group have one flow less, and a
    /// draining group that has none left is freed.
    fn gone(&mut self, f: &Flow) {
        if self.owner_live(f) {
            let flows = match instance_of(f.consumer) {
                Some(k) => self.instances[k].as_mut().map(|x| &mut x.flows),
                None => self.consumers[usize::from(f.consumer)]
                    .as_mut()
                    .map(|c| &mut c.flows),
            };
            if let Some(n) = flows {
                *n = n.saturating_sub(1);
            }
        }
        if f.flags & GROUPED == 0 {
            return;
        }
        let own_port = u16::from_le_bytes([f.key[6], f.key[7]]);
        let number = self.ports[Tables::at(Proto::Tcp, own_port)];
        let Some(Some(g)) = self.groups.get_mut(usize::from(number).wrapping_sub(1)) else {
            return;
        };
        g.flows = g.flows.saturating_sub(1);
        if g.draining && g.flows == 0 {
            self.free(number);
        }
    }

    /// Takes the group and its ports, and tells the stack (`Tables::freed`).
    fn free(&mut self, number: u8) {
        if let Some(g) = self.groups[usize::from(number) - 1].take() {
            mark_ports(self.ports, g.proto, g.first, u16::from(g.count), 0);
            *self.freed |= 1 << (number - 1);
        }
    }
}

/// The books of a `Tables` borrowed without its flows.
macro_rules! books {
    ($t:expr) => {
        Books {
            consumers: &mut $t.consumers,
            instances: &mut $t.instances,
            groups: &mut $t.groups,
            ports: &mut *$t.ports,
            freed: &mut $t.freed,
        }
    };
}

fn mark_ports(ports: &mut [u8], proto: Proto, first: u16, count: u16, v: u8) {
    assert!(u32::from(first) + u32::from(count) <= 65536);
    let at = Tables::at(proto, first);
    ports[at..at + usize::from(count)].fill(v);
}

pub struct Consumer {
    pub ring: ConsumerRing,
    pub generation: u32,
    pub block: u16,
    pub flows: u32,
    /// The raw handle of the consumer's channel the switch wakes it with.
    pub wake: u64,
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

/// The place of the internal consumer a consumer number stands for (`INTERNAL_BASE` + k).
pub fn instance_of(id: u8) -> Option<usize> {
    let k = usize::from(id.checked_sub(INTERNAL_BASE)?);
    (k < MAX_INSTANCES).then_some(k)
}

/// A stack instance of the service as a consumer of the switch: the thread that runs it takes
/// its frames as numbers of buffers through its own set of rings (`switch::Lane`), so it has no
/// ring of cells and no copy. It holds an ephemeral block, owns the flows of the connections
/// its queues took, and is a member of the groups of the listening ports it waits on, as a
/// process is.
#[derive(Clone, Copy, Debug)]
pub struct Internal {
    pub generation: u32,
    /// The first port of its block of outgoing ports, when it has one.
    pub block: Option<u16>,
    pub flows: u32,
}

/// A parked SYN: the flow key it names, when it came (ms) and its bytes.
#[derive(Clone, Copy)]
pub struct ParkSlot {
    key: [u8; 8],
    at: u32,
    /// 0 for a free place.
    len: u8,
    frame: [u8; PARK_FRAME],
}

impl ParkSlot {
    pub const EMPTY: ParkSlot = ParkSlot {
        key: [0; 8],
        at: 0,
        len: 0,
        frame: [0; PARK_FRAME],
    };
}

#[derive(Clone, Copy, Debug)]
pub struct Group {
    pub proto: Proto,
    pub first: u16,
    pub count: u8,
    pub holders: u32,
    /// Every holder let go but flows of the port are still there: no new SYN comes in, the
    /// flows go on, and the group is freed when the last one is gone.
    pub draining: bool,
    /// Flows of the group's port in the table (TCP).
    pub flows: u32,
    /// (consumer, generation)
    pub members: [Option<(u8, u32)>; MAX_MEMBERS],
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
    /// Milliseconds (wrapping), set with `now`; the park keeps its time in them.
    pub now_ms: u32,
    ports: &'a mut [u8],
    /// The park of SYNs: `PARK_PER_GROUP` places per group, empty when parking is off.
    park: &'a mut [ParkSlot],
    parked: u32,
    /// SYNs waiting in each group, so that a step looks only at the groups that have some.
    park_count: [u8; MAX_GROUPS],
    park_scan_ms: u32,
    pub park_expired: u32,
    pub park_dropped: u32,
    /// Memberships ended by LEAVE (not by a consumer's departure).
    pub left: u32,
    pub groups: [Option<Group>; MAX_GROUPS],
    pub consumers: [Option<Consumer>; MAX_CONSUMERS],
    pub instances: [Option<Internal>; MAX_INSTANCES],
    pub flows: Flows<'a>,
    /// The ports the instances hold (`ports::CLAIMS`): what the table has no byte for steers
    /// to the instance that holds the port. None without instances to claim.
    claims: Option<&'static Claims>,
    /// The generation the next attached instance gets (a place that is attached again never
    /// shares a generation with its earlier life, so its old flows are not its own).
    next_generation: u32,
    pub refused: [u32; Reason::COUNT],
    /// Groups freed that the stack has not been told of (bit n - 1 is group n); `commands::poll`
    /// sends `Back::Freed` and clears the bit.
    pub freed: u32,
    /// The last round of the sweep the stack was told (`commands::poll`).
    pub swept_told: u32,
    /// Answers for the stack whose ring was full (`commands::send`).
    pub owed: [Option<super::commands::Back>; 16],
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
            now_ms: 0,
            ports,
            park: &mut [],
            parked: 0,
            park_count: [0; MAX_GROUPS],
            park_scan_ms: 0,
            park_expired: 0,
            park_dropped: 0,
            left: 0,
            groups: [None; MAX_GROUPS],
            consumers: [const { None }; MAX_CONSUMERS],
            instances: [None; MAX_INSTANCES],
            flows,
            claims: None,
            next_generation: 1,
            refused: [0; Reason::COUNT],
            freed: 0,
            swept_told: 0,
            owed: [None; 16],
            guard: Guard { tag, owner: None },
        }
    }

    /// Turns parking on with `slots` (`PARK_SLOTS` of them).
    pub fn set_park(&mut self, slots: &'a mut [ParkSlot]) {
        assert!(slots.len() == PARK_SLOTS);
        slots.fill(ParkSlot::EMPTY);
        self.park = slots;
        self.parked = 0;
        self.park_count = [0; MAX_GROUPS];
    }

    /// SYNs waiting now.
    pub fn parked(&self) -> u32 {
        self.parked
    }

    fn park_range(group: u8) -> core::ops::Range<usize> {
        let at = (usize::from(group) - 1) * PARK_PER_GROUP;
        at..at + PARK_PER_GROUP
    }

    /// Parks the SYN `frame` of `key` for group `group`: a repeat of the same key replaces the
    /// earlier one, a full group takes the place of no one (false, the peer repeats the SYN).
    pub fn park(&mut self, group: u8, key: &FlowKey, frame: &[u8]) -> bool {
        self.guard.check();
        if self.park.is_empty()
            || frame.len() > PARK_FRAME
            || !(1..=MAX_GROUPS as u8).contains(&group)
        {
            return false;
        }
        let (now, k) = (self.now_ms, key.bytes());
        let range = Self::park_range(group);
        let places = &mut self.park[range];
        let at = places
            .iter()
            .position(|p| p.len != 0 && p.key == k)
            .or_else(|| places.iter().position(|p| p.len == 0));
        let Some(at) = at else {
            self.park_dropped += 1;
            return false;
        };
        if places[at].len == 0 {
            self.parked += 1;
            self.park_count[usize::from(group) - 1] += 1;
        }
        let p = &mut places[at];
        p.key = k;
        p.at = now;
        p.len = frame.len() as u8;
        p.frame[..frame.len()].copy_from_slice(frame);
        true
    }

    /// Drops the SYNs that waited `PARK_MS`, looking at the places at most every `PARK_SCAN_MS`.
    pub fn expire_parked(&mut self) {
        self.guard.check();
        if self.parked == 0 || self.now_ms.wrapping_sub(self.park_scan_ms) < PARK_SCAN_MS {
            return;
        }
        self.park_scan_ms = self.now_ms;
        for (i, p) in self.park.iter_mut().enumerate() {
            if p.len != 0 && self.now_ms.wrapping_sub(p.at) >= PARK_MS {
                p.len = 0;
                self.parked -= 1;
                self.park_count[i / PARK_PER_GROUP] -= 1;
                self.park_expired += 1;
            }
        }
    }

    /// Whether group `number` has a member that is live and has room for a new connection (the
    /// cells and the flows `route` asks of it), which a parked SYN can go to.
    fn park_fits(&self, number: u8) -> bool {
        let limit = (self.flows.capacity() / 2) as u32;
        self.group(number).is_some_and(|g| {
            !g.draining
                && g.members.iter().flatten().any(|m| {
                    self.live(m.0, m.1)
                        && match instance_of(m.0) {
                            Some(k) => self.instances[k].is_some_and(|x| x.flows < limit),
                            None => self.consumers[usize::from(m.0)].as_ref().is_some_and(|c| {
                                c.ring.fill_avail() >= super::route::MIN_FILL && c.flows < limit
                            }),
                        }
                })
        })
    }

    /// Takes one parked SYN out, the lowest group number first, from a group that has a member
    /// that can take it now (live, with cells and room for a flow: a SYN whose group is full
    /// stays parked until its term, and is not routed to be dropped); its bytes go to `out` and
    /// their count is returned.
    pub fn park_take(&mut self, out: &mut [u8; PARK_FRAME]) -> Option<usize> {
        self.guard.check();
        if self.parked == 0 {
            return None;
        }
        for number in 1..=MAX_GROUPS as u8 {
            if self.park_count[usize::from(number) - 1] == 0 || !self.park_fits(number) {
                continue;
            }
            // The one that waited longest.
            let now = self.now_ms;
            let at = Self::park_range(number)
                .filter(|&i| self.park[i].len != 0)
                .max_by_key(|&i| now.wrapping_sub(self.park[i].at))?;
            let p = &mut self.park[at];
            let n = usize::from(p.len);
            out[..n].copy_from_slice(&p.frame[..n]);
            p.len = 0;
            self.parked -= 1;
            self.park_count[usize::from(number) - 1] -= 1;
            return Some(n);
        }
        None
    }

    /// The calling thread is the switch from now on.
    pub fn claim(&mut self) {
        self.guard.owner = Some((self.guard.tag)());
    }

    fn at(proto: Proto, port: u16) -> usize {
        usize::from(proto == Proto::Udp) * 65536 + usize::from(port)
    }

    /// The start of the port table (TCP then UDP, 65 536 bytes each), for the stack thread's
    /// single-byte reads.
    pub fn ports_ptr(&self) -> *const u8 {
        self.ports.as_ptr()
    }

    /// The mark of `port`: the table's byte, or `OWN_MARK` + k for a port with no byte that
    /// attached instance k holds.
    pub fn port(&self, proto: Proto, port: u16) -> u8 {
        let mark = self.ports[Self::at(proto, port)];
        if mark != 0 {
            return mark;
        }
        let held = self.claims.and_then(|c| c.owner(proto, port));
        match held {
            Some(k)
                if self
                    .instances
                    .get(usize::from(k))
                    .is_some_and(Option::is_some) =>
            {
                OWN_MARK + k
            }
            _ => 0,
        }
    }

    /// The instances' ports are read from `claims` from now on.
    pub fn set_claims(&mut self, claims: &'static Claims) {
        self.claims = Some(claims);
    }

    fn mark(&mut self, proto: Proto, first: u16, count: u16, v: u8) {
        mark_ports(self.ports, proto, first, count, v);
    }

    pub fn group(&self, number: u8) -> Option<&Group> {
        self.groups
            .get(usize::from(number).wrapping_sub(1))?
            .as_ref()
    }

    /// Whether consumer `c` of generation `g` is there and its ring whole.
    pub fn live(&self, c: u8, g: u32) -> bool {
        match instance_of(c) {
            Some(k) => self.instances[k].is_some_and(|x| x.generation == g),
            None => self
                .consumers
                .get(usize::from(c))
                .and_then(Option::as_ref)
                .is_some_and(|x| x.generation == g && !x.ring.is_broken()),
        }
    }

    /// The generation of consumer `c`, a process or an instance.
    fn generation_of(&self, c: u8) -> Option<u32> {
        match instance_of(c) {
            Some(k) => self.instances[k].map(|x| x.generation),
            None => self
                .consumers
                .get(usize::from(c))
                .and_then(Option::as_ref)
                .map(|x| x.generation),
        }
    }

    /// The count of flows of consumer `c`, a process or an instance.
    pub fn owner_flows(&mut self, c: u8) -> Option<&mut u32> {
        match instance_of(c) {
            Some(k) => self.instances[k].as_mut().map(|x| &mut x.flows),
            None => self
                .consumers
                .get_mut(usize::from(c))
                .and_then(Option::as_mut)
                .map(|x| &mut x.flows),
        }
    }

    /// Instance `k` is a consumer from now on, with a block of outgoing ports of its own when
    /// `block` names one: the ports of the block go to it (`BLOCK_MARK` + its number in the
    /// port table). It gets a generation no earlier life of any place had; None for a place
    /// that is taken or absent, or a block that does not fit or meets a port another owner
    /// has marked.
    pub fn attach_instance(&mut self, k: usize, block: Option<u16>) -> Option<u32> {
        self.guard.check();
        if block.is_some_and(|b| u32::from(b) + u32::from(BLOCK_PORTS) > 65536) {
            return None;
        }
        if let Some(b) = block {
            let free = [Proto::Tcp, Proto::Udp].into_iter().all(|proto| {
                let at = Self::at(proto, b);
                self.ports[at..at + usize::from(BLOCK_PORTS)]
                    .iter()
                    .all(|&m| m == 0)
            });
            if !free {
                return None;
            }
        }
        let generation = self.next_generation;
        let Some(slot @ None) = self.instances.get_mut(k) else {
            return None;
        };
        // Zero is no generation (a flow of the empty place would match it).
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        *slot = Some(Internal {
            generation,
            block,
            flows: 0,
        });
        if let Some(b) = block {
            for proto in [Proto::Tcp, Proto::Udp] {
                self.mark(proto, b, BLOCK_PORTS, BLOCK_MARK + INTERNAL_BASE + k as u8);
            }
        }
        Some(generation)
    }

    /// Takes instance `k` out of its groups and its block, as `detach` does a process.
    pub fn detach_instance(&mut self, k: usize) -> bool {
        self.guard.check();
        let Some(gone) = self.instances.get_mut(k).and_then(Option::take) else {
            return false;
        };
        let id = INTERNAL_BASE + k as u8;
        for g in self.groups.iter_mut().flatten() {
            g.members
                .iter_mut()
                .filter(|m| m.is_some_and(|m| m.0 == id))
                .for_each(|m| *m = None);
        }
        if let Some(b) = gone.block {
            for proto in [Proto::Tcp, Proto::Udp] {
                self.mark(proto, b, BLOCK_PORTS, 0);
            }
        }
        true
    }

    pub fn attach(&mut self, c: u8, generation: u32, ring: ConsumerRing, block: u16) -> bool {
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
            wake: 0,
            arp_second: 0,
            arp_count: 0,
        });
        for proto in [Proto::Tcp, Proto::Udp] {
            self.mark(proto, block, BLOCK_PORTS, BLOCK_MARK + c);
        }
        true
    }

    /// Takes the consumer out of its groups and its block; its flows die with its generation.
    pub fn detach(&mut self, c: u8) -> Option<u32> {
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
        // A port an instance holds cannot be a group's.
        let claimed = self.claims.is_some_and(|c| {
            (first..first + u16::from(count)).any(|p| c.owner(proto, p).is_some())
        });
        let Some(slot) = self.groups.get_mut(usize::from(number).wrapping_sub(1)) else {
            return false;
        };
        match slot {
            Some(g) if g.draining => return false,
            Some(g) if (g.proto, g.first, g.count) == (proto, first, count) => {
                let Some(h) = g.holders.checked_add(1) else {
                    return false;
                };
                g.holders = h;
            }
            Some(_) => return false,
            None => {
                let at = Self::at(proto, first);
                if self.ports[at..at + usize::from(count)]
                    .iter()
                    .any(|&b| b != 0)
                {
                    return false;
                }
                if claimed {
                    return false;
                }
                *slot = Some(Group {
                    proto,
                    first,
                    count,
                    holders: 1,
                    draining: false,
                    flows: 0,
                    members: [None; MAX_MEMBERS],
                });
                self.mark(proto, first, u16::from(count), number);
            }
        }
        true
    }

    /// One holder less. The last one ends the group: at once when no flow of its port is
    /// there, else the group drains (see `Group::draining`). Either way `freed` says when
    /// the stack may let go of the port.
    pub fn release(&mut self, number: u8) {
        self.guard.check();
        let Some(Some(g)) = self.groups.get_mut(usize::from(number).wrapping_sub(1)) else {
            return;
        };
        if g.draining {
            return;
        }
        g.holders = g.holders.saturating_sub(1);
        if g.holders > 0 {
            return;
        }
        if g.flows == 0 {
            books!(self).free(number);
        } else {
            g.draining = true;
            g.members = [None; MAX_MEMBERS];
        }
    }

    pub fn join(&mut self, number: u8, c: u8) -> bool {
        self.guard.check();
        let Some(generation) = self.generation_of(c) else {
            return false;
        };
        let Some(Some(g)) = self.groups.get_mut(usize::from(number).wrapping_sub(1)) else {
            return false;
        };
        if g.draining {
            return false;
        }
        if g.members.iter().flatten().any(|m| m.0 == c) {
            return true;
        }
        let Some(free) = g.members.iter_mut().find(|m| m.is_none()) else {
            return false;
        };
        *free = Some((c, generation));
        true
    }

    /// Consumer `c` stops being a member of group `number` (its description was closed): new
    /// SYNs go to the others, or wait in the park. Flows it has go on.
    pub fn leave(&mut self, number: u8, c: u8) {
        self.guard.check();
        if let Some(Some(g)) = self.groups.get_mut(usize::from(number).wrapping_sub(1)) {
            for m in g.members.iter_mut().filter(|m| m.is_some_and(|m| m.0 == c)) {
                *m = None;
                self.left += 1;
            }
        }
    }

    /// The one read of every ring's indices for this step; `broke` hears the rings that broke.
    /// The address of device 0 changed: on a new lease the flows of every consumer end (their
    /// generations move on, the sweep removes the entries), and the address is the new one.
    pub fn set_address(&mut self, ip: [u8; 4], prefix: u8) {
        self.guard.check();
        assert!(prefix <= 32);
        if self.own.ip != [0; 4] && self.own.ip != ip {
            for (c, slot) in self.consumers.iter_mut().enumerate() {
                let Some(x) = slot else { continue };
                x.generation = x.generation.checked_add(1).unwrap_or(1);
                for g in self.groups.iter_mut().flatten() {
                    for m in g.members.iter_mut().flatten().filter(|m| m.0 == c as u8) {
                        m.1 = x.generation;
                    }
                }
            }
            for (k, slot) in self.instances.iter_mut().enumerate() {
                let Some(x) = slot else { continue };
                x.generation = x.generation.checked_add(1).unwrap_or(1);
                let id = INTERNAL_BASE + k as u8;
                for g in self.groups.iter_mut().flatten() {
                    for m in g.members.iter_mut().flatten().filter(|m| m.0 == id) {
                        m.1 = x.generation;
                    }
                }
            }
        }
        (self.own.ip, self.own.prefix) = (ip, prefix);
    }

    pub fn poll_rings(&mut self, mut broke: impl FnMut(u8, Violation)) {
        self.guard.check();
        for (c, slot) in self.consumers.iter_mut().enumerate() {
            if let Some(Poll::Broke(v)) = slot.as_mut().map(|x| x.ring.poll()) {
                broke(c as u8, v);
            }
        }
    }

    /// A new unconfirmed flow for a SYN to port-table value `mark`; false when there is no
    /// room. An evicted flow gives its owner and its group their count back.
    pub fn insert_embryo(
        &mut self,
        key: &FlowKey,
        consumer: u8,
        generation: u32,
        mark: u8,
    ) -> bool {
        self.guard.check();
        let (slot, evicted) = self
            .flows
            .insert_embryo(key, consumer, generation, self.now);
        if let Some(f) = evicted {
            books!(self).gone(&f);
        }
        if let Some(i) = slot {
            self.tag_group(i, mark);
        }
        slot.is_some()
    }

    /// The flow at `i` belongs to the group `mark` names (if it names one): counted once.
    pub fn tag_group(&mut self, i: usize, mark: u8) {
        let f = self.flows.get(i);
        if f.flags & GROUPED == 0
            && let Some(Some(g)) = self.groups.get_mut(usize::from(mark).wrapping_sub(1))
        {
            f.flags |= GROUPED;
            g.flows += 1;
        }
    }

    /// One sweep step at the time the switch last set. The switch calls it
    /// after each batch of frames; when no frames come it must be called
    /// from an idle timer too (Sh4b2: every 100 ms, with `sweep_at`), or
    /// unconfirmed and dead flows stay while the line is quiet.
    pub fn sweep(&mut self) {
        self.guard.check();
        let mut books = books!(self);
        self.flows.sweep(self.now, &mut books);
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

/// Where a consumer number is on its way back to use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Number {
    Free,
    /// The consumer left; the switch has not said `Detached` yet.
    Leaving,
    /// Free again once the sweep reached this round (`Back::Swept`): by then no flow of the
    /// old consumer is left in the table.
    Until(u32),
}

/// The registry of ports the blocks are held in: one map, or the pair of maps (TCP and UDP)
/// the service keeps.
pub trait Registry {
    fn held(&self, port: u16) -> bool;
    /// False, and nothing held, when the port is held by another instance.
    fn hold(&mut self, port: u16) -> bool;
    fn release(&mut self, port: u16);
    /// Whether none of the `count` ports from `first` is held. The maps answer a run of the
    /// ephemeral range a word of 64 ports at a time (a step of the service stays short).
    fn free_run(&self, first: u16, count: u16) -> bool {
        (0..count).all(|i| !self.held(first + i))
    }
    /// False, and nothing held, when one port of the run is held by another instance.
    fn hold_run(&mut self, first: u16, count: u16) -> bool {
        for i in 0..count {
            if !self.hold(first + i) {
                (0..i).for_each(|j| self.release(first + j));
                return false;
            }
        }
        true
    }
    fn release_run(&mut self, first: u16, count: u16) {
        (0..count).for_each(|i| self.release(first + i));
    }
}

impl Registry for PortMap {
    fn free_run(&self, first: u16, count: u16) -> bool {
        PortMap::free_run(self, first, count)
    }
    fn hold_run(&mut self, first: u16, count: u16) -> bool {
        PortMap::hold_run(self, first, count)
    }
    fn release_run(&mut self, first: u16, count: u16) {
        PortMap::release_run(self, first, count)
    }
    fn held(&self, port: u16) -> bool {
        PortMap::held(self, port)
    }
    fn hold(&mut self, port: u16) -> bool {
        PortMap::hold(self, port)
    }
    fn release(&mut self, port: u16) {
        PortMap::release(self, port)
    }
}

/// A block of ports is the same ports on TCP and on UDP.
pub struct Both<'a>(pub &'a mut PortMap, pub &'a mut PortMap);

impl Registry for Both<'_> {
    fn free_run(&self, first: u16, count: u16) -> bool {
        self.0.free_run(first, count) && self.1.free_run(first, count)
    }
    fn hold_run(&mut self, first: u16, count: u16) -> bool {
        if !self.0.hold_run(first, count) {
            return false;
        }
        if !self.1.hold_run(first, count) {
            self.0.release_run(first, count);
            return false;
        }
        true
    }
    fn release_run(&mut self, first: u16, count: u16) {
        self.0.release_run(first, count);
        self.1.release_run(first, count);
    }
    fn held(&self, port: u16) -> bool {
        self.0.held(port) || self.1.held(port)
    }
    fn hold(&mut self, port: u16) -> bool {
        if !self.0.hold(port) {
            return false;
        }
        if !self.1.hold(port) {
            self.0.release(port);
            return false;
        }
        true
    }
    fn release(&mut self, port: u16) {
        self.0.release(port);
        self.1.release(port);
    }
}

/// The stack side's books of the consumer numbers, their generations and
/// the 512-port blocks of the ephemeral range: a block is held in the
/// port registry while it is in use and for `QUARANTINE` seconds after.
/// A number is given out again only after the sweep has gone over the
/// flow table twice since the switch detached it, and its generation
/// (u32, never 0) is a new one each time.
pub struct Blocks {
    state: [Block; BLOCKS],
    owner: [Option<usize>; MAX_CONSUMERS],
    generation: [u32; MAX_CONSUMERS],
    number: [Number; MAX_CONSUMERS],
    swept: u32,
}

impl Blocks {
    pub const fn new() -> Blocks {
        Blocks {
            state: [Block::Free; BLOCKS],
            owner: [None; MAX_CONSUMERS],
            generation: [0; MAX_CONSUMERS],
            number: [Number::Free; MAX_CONSUMERS],
            swept: 0,
        }
    }

    /// Consumer numbers in use (a consumer that left and whose answer is awaited is not).
    pub fn in_use(&self) -> usize {
        self.owner.iter().flatten().count()
    }

    /// The number of the round of the sweep the stack last heard of.
    pub fn swept_round(&self) -> u32 {
        self.swept
    }

    fn first(b: usize) -> u16 {
        EPHEMERAL_FIRST + (b as u16) * BLOCK_PORTS
    }

    /// Frees the blocks whose rest is over.
    pub fn expire(&mut self, map: &mut impl Registry, now: u32) {
        for (b, s) in self.state.iter_mut().enumerate() {
            if matches!(*s, Block::Rest(until) if now.wrapping_sub(until) < u32::MAX / 2) {
                map.release_run(Self::first(b), BLOCK_PORTS);
                *s = Block::Free;
            }
        }
    }

    fn usable(&self, c: usize) -> bool {
        self.owner[c].is_none()
            && match self.number[c] {
                Number::Free => true,
                Number::Leaving => false,
                Number::Until(r) => self.swept.wrapping_sub(r) < u32::MAX / 2,
            }
    }

    /// A consumer number, its new generation (never 0) and the first port of its block.
    pub fn alloc(&mut self, map: &mut impl Registry, now: u32) -> Option<(u8, u32, u16)> {
        self.alloc_except(map, now, 0)
    }

    /// `alloc` without the numbers in the mask `busy` (the stack's ring of that consumer is
    /// still mapped).
    pub fn alloc_except(
        &mut self,
        map: &mut impl Registry,
        now: u32,
        busy: u8,
    ) -> Option<(u8, u32, u16)> {
        self.expire(map, now);
        let c = (0..MAX_CONSUMERS).find(|&c| busy & (1 << c) == 0 && self.usable(c))?;
        // A block another instance takes between the check and the hold is skipped.
        let b = (0..BLOCKS).rev().find(|&b| {
            self.state[b] == Block::Free
                && map.free_run(Self::first(b), BLOCK_PORTS)
                && map.hold_run(Self::first(b), BLOCK_PORTS)
        })?;
        self.state[b] = Block::Held;
        self.owner[c] = Some(b);
        self.number[c] = Number::Free;
        self.generation[c] = self.generation[c].checked_add(1).unwrap_or(1);
        Some((c as u8, self.generation[c], Self::first(b)))
    }

    /// The consumer left: its block rests and its number waits for the switch's answer.
    pub fn release(&mut self, c: u8, now: u32) {
        if let Some(b) = self.owner.get_mut(usize::from(c)).and_then(Option::take) {
            self.state[b] = Block::Rest(now + QUARANTINE);
            self.number[usize::from(c)] = Number::Leaving;
        }
    }

    /// `Back::Detached { consumer, round, .. }`: the number may come back when the sweep has
    /// gone over the table twice from `round` (a pass that was half done does not count).
    pub fn detached(&mut self, c: u8, round: u32) {
        if let Some(n) = self
            .number
            .get_mut(usize::from(c))
            .filter(|n| **n == Number::Leaving)
        {
            *n = Number::Until(round.wrapping_add(2));
        }
    }

    /// `Back::Swept { round }`.
    pub fn swept(&mut self, round: u32) {
        self.swept = round;
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
        pub fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
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

    fn consumers_with(c: u8, generation: u32) -> [Option<Consumer>; MAX_CONSUMERS] {
        let rig = Rig::new(Layout::new(256, 64).unwrap());
        let mut t: [Option<Consumer>; MAX_CONSUMERS] = [const { None }; MAX_CONSUMERS];
        t[usize::from(c)] = Some(Consumer {
            ring: rig.ring(),
            generation,
            block: 49152,
            flows: 3,
            wake: 0,
            arp_second: 0,
            arp_count: 0,
        });
        std::mem::forget(rig);
        t
    }

    fn sweep(f: &mut Flows, now: u32, cs: &mut [Option<Consumer>; MAX_CONSUMERS]) {
        let (mut groups, mut ports, mut freed) = ([None; MAX_GROUPS], vec![0u8; 131072], 0);
        let mut instances = [None; MAX_INSTANCES];
        let mut books = Books {
            consumers: cs,
            instances: &mut instances,
            groups: &mut groups,
            ports: &mut ports,
            freed: &mut freed,
        };
        f.sweep(now, &mut books);
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
        for _ in 0..8 {
            sweep(&mut f, 20011, &mut cs);
        }
        assert_eq!(f.len(), 2);
        assert!(f.find(&key(1)).is_some() && f.find(&key(4)).is_some());
        assert_eq!(
            cs[2].as_ref().unwrap().flows,
            0,
            "closing, reset and idle left the count"
        );
        // Closing flows rest 10 s: not yet removed at 20,010 (age 10).
        let mut g = Flows::new(&mut mem, &SECRET);
        let i = g.insert(&key(8), 2, 5, 20000).unwrap();
        g.get(i).flags = RST;
        for _ in 0..8 {
            sweep(&mut g, 20010, &mut cs);
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
        b.detached(2, 0);
        b.swept(2);
        let (c, g, first) = b.alloc(&mut map, 259).unwrap();
        assert_eq!(c, 2);
        assert_ne!(first, firsts[2], "the block rests until 260");
        assert_eq!(g, 2, "a new generation for the number");
        assert!(map.held(firsts[2]));
        b.release(c, 259);
        b.expire(&mut map, 260);
        assert!(!map.held(firsts[2]) && !map.held(firsts[2] + 511));
        b.detached(c, 2);
        b.swept(4);
        assert_eq!(b.alloc(&mut map, 260).map(|a| a.2), Some(firsts[2]));
    }

    #[test]
    fn a_number_comes_back_only_after_two_rounds_of_the_sweep_since_its_detach() {
        let (mut b, mut map) = (Blocks::new(), PortMap::new());
        for _ in 0..8 {
            b.alloc(&mut map, 0).unwrap();
        }
        b.release(5, 0);
        assert!(
            b.alloc(&mut map, 1000).is_none(),
            "the switch has not answered"
        );
        b.detached(5, 7);
        b.swept(8);
        assert!(
            b.alloc(&mut map, 1000).is_none(),
            "half a round does not count"
        );
        b.swept(9);
        assert_eq!(b.alloc(&mut map, 1000).map(|a| a.0), Some(5));
        // A number that never left is not given twice, and an answer to nothing is ignored.
        b.detached(5, 0);
        b.detached(6, 0);
        b.swept(100);
        assert!(b.alloc(&mut map, 1000).is_none());
    }

    #[test]
    fn generations_of_a_number_never_repeat_nor_are_zero() {
        let (mut b, mut map) = (Blocks::new(), PortMap::new());
        let mut last = 0;
        for round in 0..1000u32 {
            let (c, g, _) = b.alloc(&mut map, round * 100).unwrap();
            assert_eq!((c, g), (0, last + 1));
            last = g;
            b.release(c, round * 100);
            b.detached(c, round);
            b.swept(round + 2);
        }
        b.generation[0] = u32::MAX;
        b.swept(10_000);
        b.number[0] = Number::Free;
        assert_eq!(b.alloc(&mut map, 200_000).unwrap().1, 1, "wraps over 0");
    }

    #[test]
    fn a_block_with_a_port_the_stack_uses_is_skipped() {
        let (mut b, mut map) = (Blocks::new(), PortMap::new());
        map.hold(65535);
        assert_eq!(b.alloc(&mut map, 0).unwrap().2, 64512);
    }

    /// The TCP and UDP maps of instances 0 and 1 over one set of claims (boxed: a map is
    /// large).
    fn instance_maps() -> [Box<PortMap>; 4] {
        let claims: &'static crate::ports::Claims =
            Box::leak(Box::new(crate::ports::Claims::new()));
        [
            (0, Proto::Tcp),
            (0, Proto::Udp),
            (1, Proto::Tcp),
            (1, Proto::Udp),
        ]
        .map(|(who, proto)| {
            let mut map = Box::new(PortMap::new());
            map.share(claims, who, proto);
            map
        })
    }

    #[test]
    fn a_consumer_block_is_out_of_reach_of_the_ports_of_the_other_instances() {
        let [mut t0, mut u0, mut t1, u1] = instance_maps();
        let mut b = Blocks::new();
        let (_, _, first) = b.alloc(&mut Both(&mut t0, &mut u0), 0).unwrap();
        for port in [first, first + 200, first + 511] {
            assert!(t1.held(port) && u1.held(port));
            assert!(!t1.hold(port));
        }
        // Instance 1's choice of a port keeps out of the block.
        for offset in [0, 1, u32::from(first - EPHEMERAL_FIRST), 12345] {
            let port = crate::ports::ephemeral(offset, 0, &t1).unwrap();
            assert!(port < first || port - first >= BLOCK_PORTS);
        }
    }

    #[test]
    fn a_block_is_not_given_over_the_ports_of_another_instance() {
        let [mut t0, mut u0, mut t1, _] = instance_maps();
        let mut b = Blocks::new();
        // Instance 1 holds a port in every block but the second one from the start.
        for n in (0..BLOCKS as u16).filter(|n| *n != 1) {
            assert!(t1.hold(EPHEMERAL_FIRST + n * BLOCK_PORTS + 17));
        }
        let (_, _, first) = b.alloc(&mut Both(&mut t0, &mut u0), 0).unwrap();
        assert_eq!(first, EPHEMERAL_FIRST + BLOCK_PORTS);
        assert!(b.alloc(&mut Both(&mut t0, &mut u0), 0).is_none());
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

    #[test]
    fn one_sweep_step_removes_at_most_its_cap() {
        with_flows(512, |t, _| {
            // Unconfirmed flows made at time 0 are all expired at time 100.
            t.now = 0;
            let mut made = 0;
            for n in 0..128 {
                made += usize::from(t.insert_embryo(&key(n), 0, 1, 1));
            }
            assert!(made > SWEEP_REMOVALS, "{made} flows");
            t.now = 100;
            let mut most = 0;
            for _ in 0..64 {
                let before = t.flows.len();
                t.sweep();
                most = most.max(before - t.flows.len());
            }
            assert!(most > 0 && most <= SWEEP_REMOVALS, "{most} at most");
            assert_eq!(t.flows.len(), 0);
        });
    }

    #[test]
    fn a_new_address_ends_the_flows_of_every_consumer_and_a_first_one_does_not() {
        with_flows(256, |t, _| {
            let c = {
                let k = key(1);
                assert!(t.flows.insert(&k, 0, 1, 0).is_some());
                0
            };
            assert!(t.live(c, 1));
            t.set_address([10, 0, 2, 15], 24);
            assert!(t.live(c, 1), "the same address changes nothing");
            t.set_address([10, 0, 3, 7], 24);
            assert!(!t.live(c, 1), "the old generation is dead");
            assert!(t.live(c, 2));
            assert!(
                t.group(1)
                    .unwrap()
                    .members
                    .iter()
                    .flatten()
                    .all(|m| m.1 == 2 || m.0 == 2)
            );
            let mut empty = Own { ip: [0; 4], ..OWN };
            empty.prefix = 0;
            t.own = empty;
            t.set_address([10, 0, 3, 8], 24);
            assert!(t.live(c, 2), "from no address nothing ends");
        });
    }

    #[test]
    #[should_panic]
    fn a_prefix_above_32_is_refused_by_the_tables() {
        with_flows(256, |t, _| t.set_address([10, 0, 0, 1], 33));
    }

    #[test]
    fn holders_are_counted_in_32_bits() {
        with_flows(256, |t, _| {
            for _ in 0..70_000 {
                assert!(t.hold(1, Proto::Tcp, 8080, 1));
            }
            assert_eq!(t.group(1).unwrap().holders, 70_001);
        });
    }

    #[test]
    fn an_instance_takes_a_free_place_and_a_block_that_fits_and_gives_both_back() {
        with(|t, _| {
            assert_eq!(
                t.attach_instance(MAX_INSTANCES, None),
                None,
                "no such place"
            );
            assert_eq!(
                t.attach_instance(0, Some(65535)),
                None,
                "the block runs off the ports"
            );
            assert_eq!(t.attach_instance(0, Some(51200)), Some(1));
            assert_eq!(t.attach_instance(0, None), None, "the place is taken");
            for proto in [Proto::Tcp, Proto::Udp] {
                assert_eq!(t.port(proto, 51200), BLOCK_MARK + INTERNAL_BASE);
                assert_eq!(
                    t.port(proto, 51200 + BLOCK_PORTS - 1),
                    BLOCK_MARK + INTERNAL_BASE
                );
                assert_eq!(t.port(proto, 51200 + BLOCK_PORTS), 0);
            }
            assert!(t.live(INTERNAL_BASE, 1) && !t.live(INTERNAL_BASE, 2));
            assert!(!t.live(INTERNAL_BASE + 1, 1), "an empty place is not live");
            assert!(t.hold(3, Proto::Tcp, 9000, 1) && t.join(3, INTERNAL_BASE));
            assert!(!t.join(3, INTERNAL_BASE + 1), "an empty place cannot join");
            assert!(t.detach_instance(0));
            assert_eq!(t.port(Proto::Tcp, 51200), 0);
            assert!(
                !t.group(3)
                    .unwrap()
                    .members
                    .iter()
                    .flatten()
                    .any(|m| m.0 == INTERNAL_BASE)
            );
            // The place is free again, with a generation of its own: nothing of the
            // first life (its flows, its group memberships) is the new one's.
            let again = t.attach_instance(0, None).expect("the place is free again");
            assert_ne!(again, 1);
            assert!(!t.live(INTERNAL_BASE, 1) && t.live(INTERNAL_BASE, again));
        });
    }

    #[test]
    fn a_block_that_meets_ports_another_owner_marked_is_refused() {
        with(|t, _| {
            // Instance 0 holds the block; instance 1 asks for one that overlaps its end.
            assert!(t.attach_instance(0, Some(51200)).is_some());
            assert_eq!(
                t.attach_instance(1, Some(51200 + BLOCK_PORTS - 1)),
                None,
                "one port of the first block"
            );
            assert!(t.instances[1].is_none(), "nothing was taken");
            assert!(t.attach_instance(1, Some(51200 + BLOCK_PORTS)).is_some());
            // A group's port inside the block asked for is no free block either.
            assert!(t.hold(7, Proto::Udp, 40000, 1));
            assert_eq!(t.attach_instance(2, Some(40000 - 7)), None);
        });
    }

    #[test]
    fn the_ports_the_instances_hold_steer_to_them_and_leave_with_them() {
        let claims: &'static Claims = Box::leak(Box::new(Claims::new()));
        with(|t, _| {
            t.set_claims(claims);
            assert!(claims.claim(Proto::Tcp, 8085, 1));
            assert_eq!(
                t.port(Proto::Tcp, 8085),
                0,
                "instance 1 is not attached yet"
            );
            assert!(t.attach_instance(1, None).is_some());
            assert_eq!(t.port(Proto::Tcp, 8085), OWN_MARK + 1);
            assert_eq!(t.port(Proto::Udp, 8085), 0, "the other protocol");
            // A group cannot hold ports the table has no byte for but an instance has.
            assert!(t.detach_instance(1));
            assert_eq!(
                t.port(Proto::Tcp, 8085),
                0,
                "an instance that left steers nothing"
            );
        });
    }
}
