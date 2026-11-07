// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The stack thread's side of the switch's consumers (note Sh4, sections 3.2, 3.5, 4 and 5):
//! ATTACH, PORT_HOLD and JOIN, the books of the consumer numbers and of the groups of ports,
//! and the answers of the switch thread (`Back`). The stack decides (sessions, the registry
//! of ports, numbers, generations, blocks) and asks the switch thread through
//! `switch::command`; only the switch thread writes the tables.
//!
//! ATTACH is open to every session with a place of `Net` (the audit of Sh4b1, I2): the
//! number of consumers is bound by `switch N` in `netd.conf`, a consumer sees only its own
//! frames, and what it sends is checked by the switch. PORT_HOLD takes the superuser for
//! ports below 1024, once, at the call, as BIND does.

use crate::net::{Client, Net};
use crate::switch;
use crate::{Driver, dma};
use abi::{Access, Error, Rights};
use netd::books::{
    Chunks, Hold, Leave, Mappings, Owners, hold_ports, leave_by, ports_free_of_blocks,
};
use netd::ports::{Binding, Proto, conflicts};
use netd::switchlogic::commands::{Back, Command};
use netd::switchlogic::tables::{BLOCK_PORTS, Blocks, Both, MAX_CONSUMERS};
use proto_net::switch::{self as sw, Attached};
use proto_net::{Config, code};
use proto_wire::Status;
use rt::handle::{Channel, Handle, Memory, Outgoing};
use rt::service::{Answer, Request, Session};
use rt::sys;
use virtio_mmio::PAGE;

type Sess = Session<Client, 0>;

/// The rights a consumer's ring object and channel must carry.
const RING_NEEDS: Rights = Rights(Rights::MAP_READ.0 | Rights::MAP_WRITE.0);
/// The label of the copies of the switch's channel consumers get (their number is added).
const GATE_LABEL: u64 = 0x5357_0000;

/// A consumer the stack thread keeps: its channel (the switch wakes it with a copy of the raw
/// handle) until the switch has said it is out of its tables.
struct Entry {
    notify: Handle<Channel>,
    /// The bytes of the ring object, and how many of them are mapped (the kernel's map
    /// and unmap take about 140 ticks a page under -icount, so a ring of 1 288 pages is
    /// mapped and unmapped `MAP_CHUNK` pages in a step).
    size: u64,
    /// The mappings reserved for the ring (`Mappings`).
    chunks: u32,
    mapped: u64,
    /// The ring object, until all of it is mapped.
    ring: Option<Handle<Memory>>,
    /// The command that gives the ring to the switch, once all of it is mapped.
    pending: Option<Command>,
    /// The switch has the ring (the command went into its ring of commands).
    given: bool,
    /// The consumer left (its session went, or its ring broke) and the switch was told.
    leaving: bool,
    /// The ring is being taken out of the map (the switch is done with it).
    unmapping: bool,
}

/// The pages of a ring mapped or unmapped in one step of the stack (the bound of a step
/// is 18 369 ticks; a page costs 140).
const MAP_CHUNK: u64 = 64;

/// The stack side's books of the switch.
pub struct Side {
    /// `switch N` of `netd.conf`.
    pub max: u8,
    pub blocks: Blocks,
    entries: [Option<Entry>; MAX_CONSUMERS],
    /// The generation of each consumer number in use: a session's pair that does not match
    /// names a consumer that has gone.
    pub owners: Owners,
    /// Consumers whose DETACH did not fit in the ring of commands.
    detach_due: u8,
    /// A copy of the switch's channel with NOTIFY and DUPLICATE, which the copies for the
    /// consumers are made of.
    gate: Option<Handle<Channel>>,
    /// The level the labelled copies' sessions run at.
    level: u8,
}

/// The priority of the sessions of the copies of the switch's channel that consumers hold: no
/// higher than a ceiling of the processes of POSIX (31 in the tables), since the kernel hands
/// a copy only to a holder whose ceiling covers its priority.
pub const GATE_PRIORITY: u8 = 31;

impl Side {
    pub fn new(max: u8, gate: Option<Handle<Channel>>, level: u8) -> Side {
        Side {
            max,
            blocks: Blocks::new(),
            entries: [const { None }; MAX_CONSUMERS],
            owners: Owners::new(),
            detach_due: 0,
            gate,
            level,
        }
    }
}

fn refuse(c: u32) -> Answer {
    Answer::Status(code(c))
}

fn limit() -> Answer {
    Answer::Status(Status::Kernel(Error::LimitReached))
}

fn seconds() -> u32 {
    (crate::net::now_ns() / 1_000_000_000) as u32
}

impl Driver<'_> {
    /// The notification `bits` to every consumer that is attached.
    pub(crate) fn tell_consumers(&self, bits: u64) {
        for e in self.side.entries.iter().flatten().filter(|e| !e.leaving) {
            let _ = sys::notify(&e.notify, bits);
        }
    }

    /// ATTACH (the table of `proto_net::switch`).
    pub(crate) fn attach(&mut self, s: &mut Sess, r: &mut Request<'_>) -> Answer {
        // A service with no switch (`switch 0`, the images of the second device) has no such
        // method; the layer then claims the device as before.
        if self.side.max == 0 {
            return Answer::Status(Status::UnknownMethod);
        }
        let layout = match sw::read_attach(r.body()) {
            Ok(layout) => layout,
            Err(status) => return Answer::Status(status),
        };
        if r.handles.len() != 2 {
            return Answer::Status(Status::BadSize);
        }
        let rights = |i: usize| r.handles.info(i).map_or(Rights::NONE, |(_, rights)| rights);
        if rights(0).0 & RING_NEEDS.0 != RING_NEEDS.0 || rights(1).0 & Rights::NOTIFY.0 == 0 {
            return refuse(proto_net::INVALID);
        }
        let (Ok(ring), Ok(notify)) = (r.handles.take::<Memory>(0), r.handles.take::<Channel>(1))
        else {
            return refuse(proto_net::INVALID);
        };
        if s.data.consumer.is_some() || self.side.blocks.in_use() >= usize::from(self.side.max) {
            return limit();
        }
        let Some(lease) = self.stack.lease else {
            return refuse(proto_net::NET_DOWN);
        };
        // An object of `mem_create` with every page its own.
        let size = layout.total() as u64;
        match sys::memory_info(&ring) {
            Ok(info) if info.size >= size && info.pages * PAGE as u64 >= size => {}
            _ => return refuse(proto_net::INVALID),
        }
        let Some(gate) = self.side.gate.as_ref() else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        let now = seconds();
        let mut both = Both(&mut self.net.tcp_ports, &mut self.net.udp_ports);
        let busy = (0..MAX_CONSUMERS).fold(0u8, |m, c| {
            m | u8::from(self.side.entries[c].is_some()) << c
        });
        // The mappings of the ring are counted up front: a ring that does not fit the budget is
        // refused here, and a late `mem_map` never fails a consumer that was told OK.
        let chunks = Mappings::for_ring(size, PAGE as u64, MAP_CHUNK);
        if !self.net.buffers.mappings().reserve(chunks) {
            return limit();
        }
        let Some((c, generation, block)) = self.side.blocks.alloc_except(&mut both, now, busy)
        else {
            self.net.buffers.mappings().release(chunks);
            return limit();
        };

        let at = dma::consumer_at(usize::from(c));
        let giveup = |side: &mut Side| {
            side.blocks.release(c, now);
            let swept = side.blocks.swept_round();
            side.blocks.detached(c, swept);
        };
        let label = GATE_LABEL | u64::from(c);
        let copy = match sys::handle_label(
            gate,
            Rights(Rights::NOTIFY.0 | Rights::TRANSFER.0),
            label,
            self.side.level,
        ) {
            Ok(copy) => copy,
            Err(error) => {
                rt::println!("net: switch attach: labelling the gate: {error:?}");
                self.net.buffers.mappings().release(chunks);
                giveup(&mut self.side);
                return Answer::Status(Status::Kernel(error));
            }
        };
        let attach = Command::Attach {
            consumer: c,
            generation,
            base: at,
            rx_slots: layout.rx_slots as u16,
            tx_slots: layout.tx_slots as u16,
            block,
            wake: notify.raw().0,
        };
        let reply = Attached {
            consumer: u32::from(c),
            generation,
            config: Config {
                address: lease.address,
                prefix: u32::from(lease.prefix),
                gateway: lease.gateway,
                dns: lease.dns,
                mac: self.mac,
            },
            block_first: u32::from(block),
            block_count: u32::from(BLOCK_PORTS),
        };
        if reply.write(r.reply()).is_err() {
            self.net.buffers.mappings().release(chunks);
            giveup(&mut self.side);
            return Answer::Status(Status::BadSize);
        }
        // The ring is mapped in the steps that follow, and the switch is given it then: the
        // consumer writes its FILL ring and waits for frames meanwhile.
        self.side.entries[usize::from(c)] = Some(Entry {
            notify,
            size,
            chunks,
            mapped: 0,
            ring: Some(ring),
            pending: Some(attach),
            given: false,
            leaving: false,
            unmapping: false,
        });
        s.data.consumer = Some(self.side.owners.give(c, generation));
        self.tell(crate::BACK);
        Answer::Reply([copy.erase()].into())
    }

    /// One chunk of the mapping of each ring that is not mapped yet; when a ring is whole the
    /// switch is given it. True when work is left.
    fn map_step(&mut self, step: &mut Chunks) -> bool {
        let Some(process) = self.net.process.as_deref() else {
            return false;
        };
        let mut left = false;
        let mut failed = 0u8;
        for c in 0..MAX_CONSUMERS {
            let Some(e) = self.side.entries[c].as_mut() else {
                continue;
            };
            if e.leaving || e.unmapping {
                continue;
            }
            if e.mapped < e.size {
                let at = dma::consumer_at(c);
                let Some(ring) = e.ring.as_ref() else {
                    continue;
                };
                let len = (e.size - e.mapped).min(MAP_CHUNK * PAGE as u64);
                // One chunk in all the rings in a step: a ring that finds it spent waits.
                if !step.take(len / PAGE as u64) {
                    left = true;
                    continue;
                }
                if let Err(error) = sys::mem_map(
                    process,
                    ring,
                    e.mapped,
                    len,
                    at + e.mapped as usize,
                    Access::ReadWrite,
                ) {
                    rt::println!("net: switch attach: mapping the ring of {c}: {error:?}");
                    let _ = sys::notify(&e.notify, sw::WAKE_BROKEN);
                    failed |= 1 << c;
                    left = true;
                    continue;
                }
                e.mapped += len;
                left = true;
                if e.mapped == e.size {
                    // The mappings keep the object.
                    e.ring = None;
                }
                continue;
            }
            if let Some(cmd) = e.pending
                && switch::command(cmd)
            {
                e.pending = None;
                e.given = true;
            } else if e.pending.is_some() {
                left = true;
            }
        }
        for c in 0..MAX_CONSUMERS as u8 {
            if failed & (1 << c) != 0 {
                self.leave(c);
            }
        }
        left
    }

    /// One chunk of the unmapping of each ring the switch is done with. True when work is left.
    fn unmap_step(&mut self, step: &mut Chunks) -> bool {
        let Some(process) = self.net.process.as_deref() else {
            return false;
        };
        let mut left = false;
        for c in 0..MAX_CONSUMERS {
            let Some(e) = self.side.entries[c].as_mut() else {
                continue;
            };
            if !e.unmapping {
                continue;
            }
            if e.mapped > 0 {
                // The pieces go as they were mapped: the kernel unmaps inside one mapping.
                let chunk = MAP_CHUNK * PAGE as u64;
                let from = (e.mapped - 1) / chunk * chunk;
                let len = e.mapped - from;
                if !step.take(len / PAGE as u64) {
                    left = true;
                    continue;
                }
                // SAFETY: the switch thread has said the ring is out of its tables (`Detached`
                // or `Refused`) or never had it, and reads it no more.
                if let Err(error) =
                    unsafe { sys::mem_unmap(process, dma::consumer_at(c) + from as usize, len) }
                {
                    rt::println!("net: switch: unmapping the ring of {c}: {error:?}");
                }
                e.mapped = from;
            }
            if e.mapped > 0 {
                left = true;
            } else {
                let chunks = e.chunks;
                self.net.buffers.mappings().release(chunks);
                self.side.entries[c] = None;
            }
        }
        left
    }

    /// PORT_HOLD (the table of `proto_net::switch`).
    pub(crate) fn port_hold(&mut self, s: &mut Sess, r: &mut Request<'_>) -> Answer {
        if self.side.max == 0 {
            return Answer::Status(Status::UnknownMethod);
        }
        let hold = match sw::read_port_hold(r.body()) {
            Ok(hold) => hold,
            Err(status) => return Answer::Status(status),
        };
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        let Ok(identity) = r.handles.take::<Channel>(0) else {
            return refuse(proto_net::NOT_ALLOWED);
        };
        // Vouched for once, here: the user is not asked again (as `bind` of Linux).
        let Some(uid) = self.net.vouch(identity) else {
            return refuse(proto_net::NOT_ALLOWED);
        };
        if hold.first < 1024 && uid != 0 {
            return refuse(proto_net::NOT_ALLOWED);
        }
        if s.data.held.count() >= crate::net::OPEN_MAX {
            return refuse(proto_net::MFILE);
        }
        let proto = if hold.protocol == 6 {
            Proto::Tcp
        } else {
            Proto::Udp
        };
        let (first, count) = (hold.first as u16, hold.count as u8);
        let shared = hold.flags & sw::REUSEPORT != 0;
        // The group of the same ports whose holder shares them with this user.
        let same = self
            .net
            .holds
            .same(hold.protocol as u8, first, count, shared, uid);
        if same.is_none() {
            // Ports inside the block of a consumer's temporary ports are not for a group:
            // the switch would refuse them and the group would stay in the books.
            if !ports_free_of_blocks(self.net.ports(proto), first, count) {
                return refuse(proto_net::IN_USE);
            }
            for port in hold_ports(first, count) {
                let new = Binding {
                    proto,
                    address: [0; 4],
                    port,
                    listening: true,
                    connected: false,
                    reuse: false,
                    share_uid: shared.then_some(uid),
                };
                if conflicts(&new, self.net.bindings(port, usize::MAX, true)) {
                    return refuse(proto_net::IN_USE);
                }
            }
        }
        let group = match same {
            Some(g) => g,
            None => match self.net.holds.free_slot() {
                Some(g) => g,
                None => return limit(),
            },
        } as u8
            + 1;
        let Some(place) = self.net.hold_place(proto, group) else {
            return refuse(proto_net::NO_BUFFERS);
        };
        let command = Command::Hold {
            group,
            proto,
            first,
            count,
        };
        if !switch::command(command) {
            self.net.places.free(place);
            self.net.socks[place] = crate::net::Sock::EMPTY;
            return limit();
        }
        let book = Hold {
            proto: hold.protocol as u8,
            count,
            first,
            shared,
            uid,
            ..Hold::default()
        };
        let Net {
            holds,
            tcp_ports,
            udp_ports,
            ..
        } = &mut *self.net;
        holds.add(
            group,
            book,
            if proto == Proto::Tcp {
                tcp_ports
            } else {
                udp_ports
            },
        );
        self.net.places.hold(place);
        s.data.held.add(place);
        match sw::write_place_reply(self.net.places.name(place), r.reply()) {
            Ok(()) => Answer::Reply(Outgoing::new()),
            Err(status) => Answer::Status(status),
        }
    }

    /// JOIN (the table of `proto_net::switch`): the session's consumer becomes a member of the
    /// group the description names. The description is the session's own (a place it holds),
    /// so the number of a place of another session gives nothing.
    pub(crate) fn join(&mut self, s: &mut Sess, r: &mut Request<'_>) -> Answer {
        let place = match sw::read_join(r.body()) {
            Ok(place) => place,
            Err(status) => return Answer::Status(status),
        };
        if !r.handles.is_empty() {
            return Answer::Status(Status::BadSize);
        }
        // The pair of the session names the consumer it attached; once that one is gone the
        // session has none, whoever holds the number now.
        let Some(mine) = s.data.consumer.filter(|m| self.side.owners.is_current(*m)) else {
            return refuse(proto_net::INVALID);
        };
        let c = mine.number;
        let Some(i) = self.net.find_any(&s.data.held, place) else {
            return refuse(proto_net::BAD_FD);
        };
        let group = self.net.socks[i].hold;
        if group == 0 {
            return refuse(proto_net::BAD_FD);
        }
        // A LEAVE this session owes for the group (it closed its last description a moment ago)
        // would undo the join that follows it.
        self.net.holds.cancel_leave(group, mine);
        if !switch::command(Command::Join { group, consumer: c }) {
            return refuse(proto_net::BUSY);
        }
        Answer::Status(Status::Ok)
    }

    /// The session of a consumer went: the consumer leaves the switch.
    pub(crate) fn consumer_gone(&mut self, s: &mut Sess) {
        if let Some(mine) = s.data.consumer.take()
            && self.side.owners.is_current(mine)
        {
            self.leave(mine.number);
        }
    }

    /// The consumer `c` leaves: its block rests, its number waits for the switch's answer,
    /// and the switch is asked to take it out of the tables.
    fn leave(&mut self, c: u8) {
        let Some(Some(e)) = self.side.entries.get_mut(usize::from(c)) else {
            return;
        };
        if core::mem::replace(&mut e.leaving, true) {
            return;
        }
        self.side.owners.drop_number(c);
        self.side.blocks.release(c, seconds());
        if leave_by(e.given) == Leave::Free {
            // The switch never had the ring: no flow of it, the number is free at once.
            let swept = self.side.blocks.swept_round();
            self.side.blocks.detached(c, swept);
            self.start_unmap(c);
            return;
        }
        if !switch::command(Command::Detach { consumer: c }) {
            self.side.detach_due |= 1 << c;
            self.tell(crate::BACK);
        }
    }

    /// The ring of consumer `c` goes out of the service's map in the steps that follow, and
    /// its channel closes with its entry.
    fn start_unmap(&mut self, c: u8) {
        if let Some(Some(e)) = self.side.entries.get_mut(usize::from(c)) {
            e.unmapping = true;
            e.pending = None;
            e.ring = None;
        }
        self.tell(crate::BACK);
    }

    /// The step of the answers: what the switch thread told the stack, and the commands that
    /// did not fit before.
    pub(crate) fn back_step(&mut self) {
        rt::service::step_own();
        switch::INNER.back_told.seen();
        for c in 0..MAX_CONSUMERS as u8 {
            if self.side.detach_due & (1 << c) != 0
                && switch::command(Command::Detach { consumer: c })
            {
                self.side.detach_due &= !(1 << c);
            }
        }
        self.drain_releases();
        let mut taken = 0;
        while taken < 16 {
            let Some(back) = switch::COMMANDS.to_stack.pop() else {
                break;
            };
            taken += 1;
            self.answer(back);
        }
        // One chunk of pages in all in a step, to map or to unmap.
        let mut chunks = Chunks::new(MAP_CHUNK);
        let mapping = self.map_step(&mut chunks);
        let unmapping = self.unmap_step(&mut chunks);
        let address = self.switch_address();
        if taken == 16 || self.side.detach_due != 0 || mapping || unmapping || address {
            self.tell(crate::BACK);
        }
        let now = seconds();
        let mut both = Both(&mut self.net.tcp_ports, &mut self.net.udp_ports);
        self.side.blocks.expire(&mut both, now);
    }

    fn answer(&mut self, back: Back) {
        match back {
            Back::Detached {
                consumer, round, ..
            } => {
                self.side.blocks.detached(consumer, round);
                self.start_unmap(consumer);
            }
            Back::Refused { consumer, .. } => {
                // The switch never had the ring: the number is free at once.
                if let Some(Some(e)) = self.side.entries.get(usize::from(consumer)) {
                    let _ = sys::notify(&e.notify, sw::WAKE_BROKEN);
                }
                self.side.blocks.release(consumer, seconds());
                let swept = self.side.blocks.swept_round();
                self.side.blocks.detached(consumer, swept);
                self.start_unmap(consumer);
            }
            Back::Swept { round } => self.side.blocks.swept(round),
            Back::Broken {
                consumer,
                violation,
            } => {
                rt::println!("net: switch ring broken {consumer} ({violation:?})");
                if let Some(Some(e)) = self.side.entries.get(usize::from(consumer)) {
                    let _ = sys::notify(&e.notify, sw::WAKE_BROKEN);
                }
                self.leave(consumer);
            }
            Back::Freed { group } => {
                let net = &mut *self.net;
                net.holds
                    .freed(group, &mut net.tcp_ports, &mut net.udp_ports);
            }
            Back::Failed { group } => {
                rt::println!("net: switch refused a command for group {group}");
                let net = &mut *self.net;
                net.holds
                    .failed(group, &mut net.tcp_ports, &mut net.udp_ports);
            }
        }
    }

    /// The descriptions of ports that closed: the switch is told, one holder each, and the
    /// consumers that closed their last description of a group leave it.
    pub(crate) fn drain_releases(&mut self) {
        while let Some((group, mine)) = self.net.holds.next_leave() {
            // A consumer that is gone (or whose number is another's now) has nothing to leave.
            let wanted = self.side.owners.is_current(mine) && self.net.holds.switch_has(group);
            if wanted
                && !switch::command(Command::Leave {
                    group,
                    consumer: mine.number,
                })
            {
                self.tell(crate::BACK);
                return;
            }
            self.net.holds.leave_told(group, mine);
        }
        while let Some(group) = self.net.holds.next_due() {
            if self.net.holds.switch_has(group) && !switch::command(Command::Release { group }) {
                self.tell(crate::BACK);
                return;
            }
            self.net.holds.told(group);
        }
    }
}
