// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stack thread's books of the switch that need no system call: who owns a consumer
//! number, the groups of ports the registry holds for the switch, how many pages of rings
//! one step maps, and the small rules the review of Sh4b2 asked for. They build for the host,
//! where `cargo test -p netd` runs them; `consumers.rs` and `switch.rs` call them.

use crate::ports::{Binding, PortMap, Proto};
use crate::spsc::Spsc;
use crate::switchlogic::tables::{MAX_CONSUMERS, MAX_GROUPS};

/// The ports of a group, `first` to `first + count - 1`, without a sum that can pass 65 535
/// in 16 bits (`first` 65 535 and `count` 1 is a whole group).
pub fn hold_ports(first: u16, count: u8) -> core::ops::RangeInclusive<u16> {
    let last = u32::from(first) + u32::from(count).saturating_sub(1);
    first..=last.min(65535) as u16
}

/// A consumer a session holds: its number and the generation the number had when it was
/// given. A number given again has another generation, so a session that kept the old pair
/// reaches nothing of the new consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mine {
    pub number: u8,
    pub generation: u32,
}

/// The generations of the consumer numbers that are in use.
pub struct Owners {
    generation: [Option<u32>; MAX_CONSUMERS],
}

impl Owners {
    pub const fn new() -> Owners {
        Owners {
            generation: [None; MAX_CONSUMERS],
        }
    }

    pub fn give(&mut self, number: u8, generation: u32) -> Mine {
        self.generation[usize::from(number)] = Some(generation);
        Mine { number, generation }
    }

    pub fn drop_number(&mut self, number: u8) {
        self.generation[usize::from(number)] = None;
    }

    /// Whether `mine` still names the consumer that holds its number.
    pub fn is_current(&self, mine: Mine) -> bool {
        self.generation
            .get(usize::from(mine.number))
            .copied()
            .flatten()
            == Some(mine.generation)
    }
}

impl Default for Owners {
    fn default() -> Owners {
        Owners::new()
    }
}

/// How a consumer that leaves gets out of the switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leave {
    /// The switch never had the ring: its number is free at once.
    Free,
    /// The switch has it: it is asked to detach, and answers.
    Detach,
}

/// The way out of a consumer whose ring the switch was given (`given`) or not.
pub const fn leave_by(given: bool) -> Leave {
    if given { Leave::Detach } else { Leave::Free }
}

/// The pages of rings that one step of the stack maps or unmaps in all: a step of the stack
/// is bound, and a page costs the kernel about 140 ticks.
pub struct Chunks {
    left: u64,
}

impl Chunks {
    pub const fn new(pages: u64) -> Chunks {
        Chunks { left: pages }
    }

    /// All `want` pages from what is left for this step, or nothing: a ring is mapped and
    /// unmapped in whole pieces.
    pub fn take(&mut self, want: u64) -> bool {
        if want > self.left {
            return false;
        }
        self.left -= want;
        true
    }
}

/// A group of ports the registry holds for the switch: from a PORT_HOLD to the switch's
/// `Back::Freed`. All zeros is an unused slot.
#[derive(Clone, Copy, Default)]
pub struct Hold {
    pub used: bool,
    /// 6 or 17.
    pub proto: u8,
    pub count: u8,
    pub first: u16,
    /// Both holders set SO_REUSEPORT, and the effective user that did.
    pub shared: bool,
    pub uid: u32,
    /// Descriptions that hold the group (places); the last one letting go ends it.
    pub holders: u32,
    /// The switch refused the group: its ports are free, and the slot stays until the
    /// descriptions that name it have closed (their closes must not reach a later group).
    pub failed: bool,
}

impl Hold {
    /// What the registry compares a bind to `port` with: the group is a listening socket on
    /// every address.
    pub fn binding(&self, port: u16) -> Option<Binding> {
        let inside =
            port >= self.first && u32::from(port) < u32::from(self.first) + u32::from(self.count);
        (self.used && !self.failed && inside).then_some(Binding {
            proto: self.proto(),
            address: [0; 4],
            port,
            listening: true,
            connected: false,
            reuse: false,
            share_uid: self.shared.then_some(self.uid),
        })
    }

    pub fn proto(&self) -> Proto {
        if self.proto == 6 {
            Proto::Tcp
        } else {
            Proto::Udp
        }
    }
}

/// The groups, and the descriptions of ports that closed and whose group has not been told.
pub struct Holds {
    pub list: [Hold; MAX_GROUPS],
    /// A count for each group (u32: a flood of closes cannot saturate it).
    due: [u32; MAX_GROUPS],
}

impl Holds {
    pub const fn new() -> Holds {
        Holds {
            list: [Hold {
                used: false,
                proto: 0,
                count: 0,
                first: 0,
                shared: false,
                uid: 0,
                holders: 0,
                failed: false,
            }; MAX_GROUPS],
            due: [0; MAX_GROUPS],
        }
    }

    /// The group (0-based) of the same ports that shares them with this user.
    pub fn same(&self, proto: u8, first: u16, count: u8, shared: bool, uid: u32) -> Option<usize> {
        self.list.iter().position(|h| {
            h.used
                && !h.failed
                && h.holders > 0
                && (h.proto, h.first, h.count) == (proto, first, count)
                && shared
                && h.shared
                && h.uid == uid
        })
    }

    pub fn free_slot(&self) -> Option<usize> {
        self.list.iter().position(|h| !h.used)
    }

    /// A description joined group `group` (1-based): one more holder, or a new group whose
    /// ports the registry takes.
    pub fn add(&mut self, group: u8, h: Hold, ports: &mut PortMap) {
        let book = &mut self.list[usize::from(group) - 1];
        if book.used {
            book.holders += 1;
        } else {
            *book = Hold {
                used: true,
                holders: 1,
                ..h
            };
            for port in hold_ports(h.first, h.count) {
                ports.hold(port);
            }
        }
    }

    /// The group is gone from the switch's tables: the slot and the ports go.
    pub fn freed(&mut self, group: u8, tcp: &mut PortMap, udp: &mut PortMap) {
        let book = &mut self.list[usize::from(group) - 1];
        if !book.used || book.failed {
            return;
        }
        let (proto, first, count) = (book.proto(), book.first, book.count);
        *book = Hold::default();
        self.due[usize::from(group) - 1] = 0;
        let map = if proto == Proto::Tcp { tcp } else { udp };
        for port in hold_ports(first, count) {
            map.release(port);
        }
    }

    /// The switch refused the group's HOLD: it has no tables for it, so no `Freed` will come.
    /// The ports are free at once; the slot goes when the descriptions that name it have
    /// closed (`told`), so that a close never counts against a group made later in the slot.
    pub fn failed(&mut self, group: u8, tcp: &mut PortMap, udp: &mut PortMap) {
        let book = &mut self.list[usize::from(group) - 1];
        if !book.used || book.failed {
            return;
        }
        book.failed = true;
        let map = if book.proto() == Proto::Tcp { tcp } else { udp };
        for port in hold_ports(book.first, book.count) {
            map.release(port);
        }
        if book.holders == 0 {
            *book = Hold::default();
        }
    }

    /// Whether the switch has to hear of closes of this group (it has the group).
    pub fn switch_has(&self, group: u8) -> bool {
        let h = &self.list[usize::from(group) - 1];
        h.used && !h.failed
    }

    /// A description of group `group` (1-based) closed: its group is to hear of it. Not
    /// counted when the group is gone.
    pub fn closed(&mut self, group: u8) {
        let g = usize::from(group) - 1;
        if self.list[g].used {
            self.due[g] += 1;
        }
    }

    /// The next group (1-based) with closes to tell, and takes one of them from the count.
    pub fn next_due(&mut self) -> Option<u8> {
        let g = self.due.iter().position(|&n| n > 0)?;
        Some(g as u8 + 1)
    }

    pub fn told(&mut self, group: u8) {
        let g = usize::from(group) - 1;
        self.due[g] = self.due[g].saturating_sub(1);
        let h = &mut self.list[g];
        h.holders = h.holders.saturating_sub(1);
        if h.failed && h.holders == 0 {
            *h = Hold::default();
        }
    }

    pub fn due_of(&self, group: u8) -> u32 {
        self.due[usize::from(group) - 1]
    }
}

impl Default for Holds {
    fn default() -> Holds {
        Holds::new()
    }
}

/// Whether PORT_HOLD may take these ports: none is inside a block of ephemeral ports a
/// consumer holds (the registry reserves the block, and a group there would be taken from
/// under it).
pub fn ports_free_of_blocks(map: &PortMap, first: u16, count: u8) -> bool {
    hold_ports(first, count).all(|p| !map.is_reserved(p))
}

/// The address the switch was last told, and whether a new one is still to be told. The
/// command ring can be full; the address stays due until a push succeeds.
pub struct AddressSync {
    told: ([u8; 4], u8),
}

impl AddressSync {
    pub const fn new() -> AddressSync {
        AddressSync { told: ([0; 4], 0) }
    }

    pub fn due(&self, now: ([u8; 4], u8)) -> bool {
        self.told != now
    }

    /// The push of `now` succeeded.
    pub fn done(&mut self, now: ([u8; 4], u8)) {
        self.told = now;
    }
}

impl Default for AddressSync {
    fn default() -> AddressSync {
        AddressSync::new()
    }
}

/// For each consumer number, the generation and DONE head the switch last woke it for. A new
/// consumer on a number starts from nothing, whatever the last one left.
pub struct Woken {
    seen: [(u32, u32); MAX_CONSUMERS],
}

impl Woken {
    pub const fn new() -> Woken {
        Woken {
            seen: [(0, 0); MAX_CONSUMERS],
        }
    }

    /// Whether DONE head `head` of consumer `c` of generation `generation` is news.
    pub fn news(&mut self, c: usize, generation: u32, head: u32) -> bool {
        let (g, h) = self.seen[c];
        let from = if g == generation { h } else { 0 };
        self.seen[c] = (generation, head);
        head != from
    }
}

impl Default for Woken {
    fn default() -> Woken {
        Woken::new()
    }
}

/// Puts `word` in `ring`; false when it is full (the caller drops the frame and gives its
/// buffer back: a full ring of frames for the stack is no fault of the books).
pub fn offer<const N: usize>(ring: &Spsc<N>, word: u32) -> bool {
    ring.push(word)
}

/// Whether a consumer's frame has to wait: it holds its share of the queue (`inflight` of
/// `cap`), or no buffer is free.
pub const fn blocked(inflight: usize, cap: usize, free: usize) -> bool {
    inflight >= cap || free == 0
}

/// Whether the switch has work now: a consumer has a frame in its TX ring that is not
/// blocked (a blocked one waits for the 1 ms timer or a returned buffer), or a command waits.
pub fn has_work(
    consumers: impl IntoIterator<Item = (bool, usize)>,
    cap: usize,
    free: usize,
    commands: bool,
) -> bool {
    commands
        || consumers
            .into_iter()
            .any(|(pending, inflight)| pending && !blocked(inflight, cap, free))
}

/// Whether a step that has taken `taken` frames may take another: the first `base` go
/// whatever the time, the rest only while the step is short.
pub const fn may_take(taken: usize, base: usize, over_soft: bool) -> bool {
    taken < base || !over_soft
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_at_port_65535_has_that_port_and_no_wrapped_ones() {
        assert_eq!(hold_ports(65535, 1).collect::<Vec<_>>(), [65535]);
        assert_eq!(hold_ports(65530, 6).count(), 6);
        assert_eq!(hold_ports(80, 3).collect::<Vec<_>>(), [80, 81, 82]);
        let mut holds = Holds::new();
        let (mut tcp, mut udp) = (PortMap::new(), PortMap::new());
        let h = Hold {
            proto: 6,
            count: 1,
            first: 65535,
            ..Hold::default()
        };
        holds.add(1, h, &mut tcp);
        assert!(tcp.held(65535) && !tcp.held(0));
        holds.freed(1, &mut tcp, &mut udp);
        assert!(!tcp.held(65535) && !tcp.held(0));
    }

    #[test]
    fn a_session_with_an_old_pair_does_not_reach_the_new_consumer() {
        let mut owners = Owners::new();
        let old = owners.give(2, 7);
        assert!(owners.is_current(old));
        owners.drop_number(2);
        assert!(!owners.is_current(old));
        let new = owners.give(2, 8);
        assert!(!owners.is_current(old));
        assert!(owners.is_current(new));
    }

    #[test]
    fn a_ring_the_switch_never_had_frees_its_number_at_once() {
        assert_eq!(leave_by(false), Leave::Free);
        assert_eq!(leave_by(true), Leave::Detach);
    }

    #[test]
    fn eight_rings_share_one_chunk_per_step() {
        let mut step = Chunks::new(64);
        let got: Vec<bool> = (0..8).map(|_| step.take(64)).collect();
        assert_eq!(got.iter().filter(|g| **g).count(), 1);
        assert!(got[0]);
        assert!(!step.take(1));
        // A piece larger than what is left takes nothing.
        let mut step = Chunks::new(64);
        assert!(!step.take(65) && step.take(64));
        // A ring's last piece of 8 pages leaves room for another of 56.
        let mut step = Chunks::new(64);
        assert!(step.take(8) && step.take(56) && !step.take(1));
    }

    #[test]
    fn a_hold_inside_a_block_is_refused() {
        let mut map = PortMap::new();
        let first = crate::ports::EPHEMERAL_FIRST;
        assert!(ports_free_of_blocks(&map, first + 1000, 4));
        map.hold_run(first + 512, 512);
        assert!(!ports_free_of_blocks(&map, first + 600, 1));
        assert!(!ports_free_of_blocks(&map, first + 510, 4));
        assert!(ports_free_of_blocks(&map, first + 1024, 4));
    }

    #[test]
    fn a_failed_hold_gives_back_its_group_every_time() {
        let mut holds = Holds::new();
        let (mut tcp, mut udp) = (PortMap::new(), PortMap::new());
        for _ in 0..(MAX_GROUPS + 1) {
            let slot = holds
                .free_slot()
                .expect("a slot is free after each failure");
            let h = Hold {
                proto: 6,
                count: 2,
                first: 8000,
                ..Hold::default()
            };
            holds.add(slot as u8 + 1, h, &mut tcp);
            assert!(tcp.held(8000));
            holds.failed(slot as u8 + 1, &mut tcp, &mut udp);
            assert!(!tcp.held(8000) && !tcp.held(8001));
            // The description of the failed group closes: the slot is free again, and a
            // close that comes late reaches nothing.
            holds.closed(slot as u8 + 1);
            assert!(!holds.switch_has(slot as u8 + 1));
            let g = holds.next_due().expect("the close is due");
            holds.told(g);
        }
        assert!(holds.list.iter().all(|h| !h.used));
    }

    #[test]
    fn closes_of_descriptions_are_counted_exactly() {
        let mut holds = Holds::new();
        let mut tcp = PortMap::new();
        let h = Hold {
            proto: 6,
            count: 1,
            first: 80,
            ..Hold::default()
        };
        holds.add(1, h, &mut tcp);
        for _ in 1..300 {
            holds.add(1, h, &mut tcp);
        }
        for _ in 0..300 {
            holds.closed(1);
        }
        assert_eq!(holds.due_of(1), 300);
        let mut told = 0;
        while let Some(g) = holds.next_due() {
            holds.told(g);
            told += 1;
        }
        assert_eq!(told, 300);
        assert_eq!(holds.list[0].holders, 0);
    }

    #[test]
    fn an_address_stays_due_until_a_push_succeeds() {
        let mut sync = AddressSync::new();
        let now = ([10, 0, 2, 15], 24);
        assert!(sync.due(now));
        // The push failed: nothing is recorded, so the next try finds it due.
        assert!(sync.due(now));
        sync.done(now);
        assert!(!sync.due(now));
        assert!(sync.due(([10, 0, 2, 16], 24)));
    }

    #[test]
    fn a_new_consumer_on_a_number_is_woken_for_the_same_head() {
        let mut woken = Woken::new();
        assert!(woken.news(1, 5, 3));
        assert!(!woken.news(1, 5, 3));
        // The next consumer of number 1 gets a frame at once: its head is 3 as the last one's.
        assert!(woken.news(1, 6, 3));
        assert!(!woken.news(1, 6, 3));
    }

    #[test]
    fn a_full_ring_of_frames_for_the_stack_refuses_without_ending_the_service() {
        let ring = Spsc::<256>::new();
        assert!((0..256).all(|i| offer(&ring, i)));
        assert!(!offer(&ring, 256));
        assert_eq!(ring.len(), 256);
    }

    #[test]
    fn blocked_consumers_give_the_switch_no_work() {
        let cap = 10;
        // One consumer waits and holds its whole share: the switch has nothing to run.
        assert!(!has_work([(true, 10)], cap, 5, false));
        // No buffer is free: nothing to run.
        assert!(!has_work([(true, 0)], cap, 0, false));
        // A consumer with room works; a command always works.
        assert!(has_work([(true, 3)], cap, 5, false));
        assert!(has_work([(false, 0)], cap, 5, true));
        assert!(!has_work([(false, 0)], cap, 5, false));
    }

    #[test]
    fn a_step_past_its_soft_time_stops_after_the_base_frames() {
        assert!(may_take(0, 3, true) && may_take(2, 3, true));
        assert!(!may_take(3, 3, true));
        assert!(may_take(3, 3, false) && may_take(7, 3, false));
    }
}
