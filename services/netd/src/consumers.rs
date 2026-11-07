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

use crate::net::Client;
use crate::switch;
use crate::{Driver, dma};
use abi::{Access, Error, Rights};
use netd::ports::{Binding, Proto, conflicts};
use netd::switchlogic::commands::{Back, Command};
use netd::switchlogic::tables::{BLOCK_PORTS, Blocks, Both, MAX_CONSUMERS, MAX_GROUPS};
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

/// A group of ports the registry holds for the switch: from a PORT_HOLD to the switch's
/// `Back::Freed`. All zeros is an unused slot.
#[derive(Clone, Copy)]
pub struct Hold {
    used: bool,
    /// 6 or 17.
    proto: u8,
    count: u8,
    first: u16,
    /// Both holders set SO_REUSEPORT, and the effective user that did.
    shared: bool,
    uid: u32,
    /// Descriptions that hold the group (places); the last one letting go ends it.
    holders: u32,
}

impl Hold {
    /// What the registry compares a bind to `port` with: the group is a listening socket on
    /// every address.
    pub fn binding(&self, port: u16) -> Option<Binding> {
        let inside =
            port >= self.first && u32::from(port) < u32::from(self.first) + u32::from(self.count);
        (self.used && inside).then_some(Binding {
            proto: if self.proto == 6 {
                Proto::Tcp
            } else {
                Proto::Udp
            },
            address: [0; 4],
            port,
            listening: true,
            connected: false,
            reuse: false,
            share_uid: self.shared.then_some(self.uid),
        })
    }

    fn proto(&self) -> Proto {
        if self.proto == 6 {
            Proto::Tcp
        } else {
            Proto::Udp
        }
    }
}

/// A consumer the stack thread keeps: its channel (the switch wakes it with a copy of the raw
/// handle) until the switch has said it is out of its tables.
struct Entry {
    notify: Handle<Channel>,
    /// The bytes of the ring object mapped for it.
    size: u64,
    /// The consumer left (its session went, or its ring broke) and the switch was told.
    leaving: bool,
}

/// The stack side's books of the switch.
pub struct Side {
    /// `switch N` of `netd.conf`.
    pub max: u8,
    pub blocks: Blocks,
    entries: [Option<Entry>; MAX_CONSUMERS],
    /// Consumers whose DETACH did not fit in the ring of commands.
    detach_due: u8,
    /// A copy of the switch's channel with NOTIFY and DUPLICATE, which the copies for the
    /// consumers are made of.
    gate: Option<Handle<Channel>>,
    /// The level the labelled copies' sessions run at.
    level: u8,
}

impl Side {
    pub fn new(max: u8, gate: Option<Handle<Channel>>, level: u8) -> Side {
        Side {
            max,
            blocks: Blocks::new(),
            entries: [const { None }; MAX_CONSUMERS],
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
        if self.side.max == 0
            || s.data.consumer.is_some()
            || self.side.blocks.in_use() >= usize::from(self.side.max)
        {
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
        let (Some(process), Some(gate)) = (self.net.process.as_deref(), self.side.gate.as_ref())
        else {
            return Answer::Status(Status::Kernel(Error::BadState));
        };
        let now = seconds();
        let mut both = Both(&mut self.net.tcp_ports, &mut self.net.udp_ports);
        let Some((c, generation, block)) = self.side.blocks.alloc(&mut both, now) else {
            return limit();
        };
        let at = dma::consumer_at(usize::from(c));
        let giveup = |side: &mut Side| {
            side.blocks.release(c, now);
            let swept = side.blocks.swept_round();
            side.blocks.detached(c, swept);
        };
        if let Err(error) = sys::mem_map(process, &ring, 0, size, at, Access::ReadWrite) {
            giveup(&mut self.side);
            return Answer::Status(Status::Kernel(error));
        }
        // The mapping keeps the object.
        drop(ring);
        let label = GATE_LABEL | u64::from(c);
        let copy = match sys::handle_label(gate, Rights::NOTIFY, label, self.side.level) {
            Ok(copy) => copy,
            Err(error) => {
                // SAFETY: the switch has not been told of the ring.
                let _ = unsafe { sys::mem_unmap(process, at, size) };
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
        if !switch::command(attach) {
            // SAFETY: the switch has not been told of the ring.
            let _ = unsafe { sys::mem_unmap(process, at, size) };
            giveup(&mut self.side);
            return limit();
        }
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
            // The switch has the ring: it goes the way of a consumer that left.
            self.side.entries[usize::from(c)] = Some(Entry {
                notify,
                size,
                leaving: false,
            });
            s.data.consumer = Some(c);
            return Answer::Status(Status::BadSize);
        }
        self.side.entries[usize::from(c)] = Some(Entry {
            notify,
            size,
            leaving: false,
        });
        s.data.consumer = Some(c);
        Answer::Reply([copy.erase()].into())
    }

    /// PORT_HOLD (the table of `proto_net::switch`).
    pub(crate) fn port_hold(&mut self, s: &mut Sess, r: &mut Request<'_>) -> Answer {
        let hold = match sw::read_port_hold(r.body()) {
            Ok(hold) => hold,
            Err(status) => return Answer::Status(status),
        };
        if r.handles.len() != 1 {
            return Answer::Status(Status::BadSize);
        }
        if self.side.max == 0 {
            return limit();
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
        let same = self.net.holds.iter().position(|h| {
            h.used
                && h.holders > 0
                && (h.proto, h.first, h.count) == (hold.protocol as u8, first, count)
                && shared
                && h.shared
                && h.uid == uid
        });
        if same.is_none() {
            for port in first..first + u16::from(count) {
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
            None => match self.net.holds.iter().position(|h| !h.used) {
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
        let book = &mut self.net.holds[usize::from(group) - 1];
        if book.used {
            book.holders += 1;
        } else {
            *book = Hold {
                used: true,
                proto: hold.protocol as u8,
                count,
                first,
                shared,
                uid,
                holders: 1,
            };
            for port in first..first + u16::from(count) {
                self.net.ports(proto).hold(port);
            }
        }
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
        let Some(c) = s.data.consumer else {
            return refuse(proto_net::INVALID);
        };
        let Some(i) = self.net.find_any(&s.data.held, place) else {
            return refuse(proto_net::BAD_FD);
        };
        let group = self.net.socks[i].hold;
        if group == 0 {
            return refuse(proto_net::BAD_FD);
        }
        if !switch::command(Command::Join { group, consumer: c }) {
            return refuse(proto_net::BUSY);
        }
        Answer::Status(Status::Ok)
    }

    /// The session of a consumer went: the consumer leaves the switch.
    pub(crate) fn consumer_gone(&mut self, s: &mut Sess) {
        if let Some(c) = s.data.consumer.take() {
            self.leave(c);
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
        self.side.blocks.release(c, seconds());
        if !switch::command(Command::Detach { consumer: c }) {
            self.side.detach_due |= 1 << c;
            self.tell(crate::BACK);
        }
    }

    /// Takes the ring of consumer `c` out of the service's map and closes its channel.
    fn unmap(&mut self, c: u8) {
        let Some(e) = self.side.entries[usize::from(c)].take() else {
            return;
        };
        if let Some(process) = self.net.process.as_deref() {
            // SAFETY: the switch thread has said the ring is out of its tables (`Detached` or
            // `Refused`) and reads it no more.
            let _ = unsafe { sys::mem_unmap(process, dma::consumer_at(usize::from(c)), e.size) };
        }
        drop(e);
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
        if taken == 16 || self.side.detach_due != 0 {
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
                self.unmap(consumer);
            }
            Back::Refused { consumer, .. } => {
                // The switch never had the ring: the number is free at once.
                if let Some(Some(e)) = self.side.entries.get(usize::from(consumer)) {
                    let _ = sys::notify(&e.notify, sw::WAKE_BROKEN);
                }
                self.side.blocks.release(consumer, seconds());
                let swept = self.side.blocks.swept_round();
                self.side.blocks.detached(consumer, swept);
                self.unmap(consumer);
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
                let book = &mut self.net.holds[usize::from(group) - 1];
                if book.used {
                    let (proto, first, count) = (book.proto(), book.first, book.count);
                    *book = Hold {
                        used: false,
                        proto: 0,
                        count: 0,
                        first: 0,
                        shared: false,
                        uid: 0,
                        holders: 0,
                    };
                    for port in first..first + u16::from(count) {
                        self.net.ports(proto).release(port);
                    }
                }
            }
            Back::Failed { group } => {
                rt::println!("net: switch refused a command for group {group}");
            }
        }
    }

    /// The descriptions of ports that closed: the switch is told, one holder each.
    pub(crate) fn drain_releases(&mut self) {
        for g in 0..MAX_GROUPS {
            while self.net.release_due[g] > 0 {
                if !switch::command(Command::Release { group: g as u8 + 1 }) {
                    self.tell(crate::BACK);
                    return;
                }
                self.net.release_due[g] -= 1;
                let h = &mut self.net.holds[g];
                h.holders = h.holders.saturating_sub(1);
            }
        }
    }
}
