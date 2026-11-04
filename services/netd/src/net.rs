// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The sockets of the service (spec 6, 3.3): the table of descriptions with
//! the smoltcp socket of each, the buffers they share out of one pool, the
//! registry of ports, the long operations that wait and the sessions that
//! hold descriptions. `calls.rs` has the methods of the protocol; this has
//! what they share: the lifetime of a description, what a socket is ready
//! for, and the pass that tells the operations which wait.
//!
//! Every table lives in the service's `.bss` (`Tables` in main.rs), filled
//! in place, so the stack of the program stays small. The pool of buffers
//! takes a page only when a socket touches it.

use crate::stack::Stack;
use core::mem::{ManuallyDrop, MaybeUninit};
use netd::places::{Held, Places, SOCKETS_LIMIT, SOCKETS_MAX, State};
use netd::ports::{Binding, PortMap, Proto};
use proto_net::sockets::{self, opt};
use proto_net::{Address, INET};
use proto_wire::clones::Clones;
use proto_wire::watch;
use rt::handle::{Channel, Handle};
use rt::service::{LongOps, LongSession};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Duration;

/// The sessions of the service's channel: room for the records of the
/// process service and the services beside them, as the pipe service has.
pub const SESSIONS: usize = 320;
/// The live clones of one root at most.
pub const ROOT_CLONES: usize = 255;
/// The long operations that wait in the service at most.
pub const OPERATIONS: usize = 128;
/// The descriptions one session holds: a process cannot hold more.
pub const OPEN_MAX: usize = 64;
/// The sockets of the queue of `listen` at most.
pub const BACKLOG_MAX: usize = 16;
/// The bytes of a buffer of one direction of a TCP socket, and the packets
/// and bytes of one direction of a UDP socket.
pub const BUFFER: usize = 16 * 1024;
const PACKETS: usize = 16;
/// How long a stream no session holds may close, in nanoseconds: smoltcp's
/// FIN-WAIT-2 has no end of its own.
pub const ORPHAN_NS: u64 = 60_000_000_000;
/// How long a `connect` may wait for the peer (smoltcp repeats the SYN for
/// ever without a timeout).
pub const CONNECT_NS: u64 = 75_000_000_000;
/// The interval of the probes of KEEPALIVE (RFC 1122, 4.2.3.6).
const KEEPALIVE_NS: u64 = 7_200_000_000_000;
/// The orphans one step of the deadline looks at.
const SWEEP: usize = 8;
/// The sessions that went and still hold descriptions at most; a session
/// past that lets go of its descriptions at once.
pub const DEPARTING: usize = 8;
/// The descriptions the steps of departure let go of in one step.
pub const GONE_PORTION: usize = 8;

/// The label tag of the sessions Clone makes: none of init's labels.
pub const OWN: u64 = proto_pipe::OWN;

/// What the service keeps for a client.
#[derive(Default)]
pub struct Client {
    pub held: Held,
    pub long: LongSession,
    /// Whether the session took the descriptions Clone made it with.
    pub claimed: bool,
    /// The label of init's client whose process this chain of clones
    /// belongs to: the clones of one root are counted together.
    pub root: u64,
}

/// A clone that sent nothing yet: its label, its descriptions and its root.
pub type Birth = (u64, Held, u64);

/// How a stream's connection stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conn {
    /// No `connect` is under way (a socket that never connected, or one
    /// whose connect failed).
    None,
    /// The SYN is out since the time in nanoseconds.
    Connecting(u64),
    /// The handshake is done.
    Done,
}

/// A description's socket.
#[derive(Clone, Copy)]
pub struct Sock {
    pub proto: Proto,
    pub handle: Option<SocketHandle>,
    pub nonblock: bool,
    pub reuse: bool,
    pub keepalive: bool,
    pub nodelay: bool,
    pub broadcast: bool,
    pub shut_rd: bool,
    pub shut_wr: bool,
    /// The stream took a FIN from the peer.
    pub saw_fin: bool,
    pub bound: bool,
    pub address: [u8; 4],
    pub port: u16,
    pub listening: bool,
    pub conn: Conn,
    /// The peer of a datagram socket after `connect`.
    pub peer: Option<([u8; 4], u16)>,
    /// The deferred error (`SO_ERROR`): a code of the protocol, or 0.
    pub error: u32,
    /// For a listening description: the places of its queue.
    pub members: [u16; BACKLOG_MAX],
    pub member_count: u8,
    /// The long operations that wait on the description, by their index.
    pub waiters: u128,
    /// When the last session let go of a stream.
    pub orphan_at: u64,
}

impl Sock {
    pub const EMPTY: Sock = Sock {
        proto: Proto::Tcp,
        handle: None,
        nonblock: false,
        reuse: false,
        keepalive: false,
        nodelay: false,
        broadcast: false,
        shut_rd: false,
        shut_wr: false,
        saw_fin: false,
        bound: false,
        address: [0; 4],
        port: 0,
        listening: false,
        conn: Conn::None,
        peer: None,
        error: 0,
        members: [0; BACKLOG_MAX],
        member_count: 0,
        waiters: 0,
        orphan_at: 0,
    };
}

/// What a long operation waits for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Connect,
    Accept,
    Send,
    Recv,
    Watch,
}

/// Where an operation waits: its key, its client, its kind and the place of
/// its description.
#[derive(Clone, Copy)]
pub struct OpInfo {
    pub key: u64,
    pub label: u64,
    pub kind: Kind,
    pub place: u16,
}

impl OpInfo {
    pub const EMPTY: OpInfo = OpInfo {
        key: 0,
        label: 0,
        kind: Kind::Connect,
        place: 0,
    };
}

/// The index of an operation, from its key.
pub fn op_index(key: u64) -> usize {
    ((key & 0xffff_ffff) - 1) as usize
}

/// A set of places, one bit each.
#[derive(Clone, Copy, Default)]
pub struct Mask([u64; SOCKETS_MAX / 64]);

impl Mask {
    pub fn set(&mut self, i: usize) {
        self.0[i / 64] |= 1 << (i % 64);
    }

    pub fn clear(&mut self, i: usize) {
        self.0[i / 64] &= !(1 << (i % 64));
    }

    pub fn has(&self, i: usize) -> bool {
        self.0[i / 64] >> (i % 64) & 1 != 0
    }

    /// The lowest place at or after `from`.
    pub fn next(&self, from: usize) -> Option<usize> {
        (from..SOCKETS_MAX).find(|&i| self.has(i))
    }
}

/// The counters of the probe's line.
#[derive(Clone, Copy, Default)]
pub struct Counters {
    /// Members of a queue that `accept` could not replace.
    pub listen_short: u64,
}

/// The sockets of the service.
pub struct Net {
    pub places: Places<SOCKETS_MAX>,
    pub socks: [Sock; SOCKETS_MAX],
    /// The buffers: place i uses `pool[i]`, the first half for receiving
    /// and the second for sending.
    pool: [[u8; 2 * BUFFER]; SOCKETS_MAX],
    /// The packet records of a datagram socket: place i, then the two
    /// directions.
    udp_meta: [[MaybeUninit<udp::PacketMetadata>; 2 * PACKETS]; SOCKETS_MAX],
    pub tcp_ports: PortMap,
    pub udp_ports: PortMap,
    pub ops: LongOps<OPERATIONS>,
    pub info: [OpInfo; OPERATIONS],
    pub watches: [watch::Set; OPERATIONS],
    pub clones: Clones<SESSIONS>,
    pub births: [Option<Birth>; SESSIONS],
    departing: [Held; DEPARTING],
    /// The places that have operations waiting, the streams that connect and
    /// those no session holds.
    pub attention: Mask,
    pub connecting: Mask,
    pub orphans: Mask,
    sweep_at: usize,
    /// The secret of the choice of ports and its counter (RFC 6056).
    key: [u8; 16],
    counter: u32,
    /// The interface's external address, when it has one.
    pub external: Option<[u8; 4]>,
    /// The connection to init, for the notary session.
    parent: Option<ManuallyDrop<Handle<Channel>>>,
    /// The service's channel, which its own sessions are copies of, and the
    /// level of the service.
    pub channel: ManuallyDrop<Handle<Channel>>,
    pub level: u8,
    notary: Option<Handle<Channel>>,
    /// A step of the stack is due (a request changed a socket): the loop
    /// tells itself.
    pub step_due: bool,
    pub counters: Counters,
}

/// The time in nanoseconds of the guest.
pub fn now_ns() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

fn duration(ns: u64) -> Duration {
    Duration::from_micros(ns / 1000)
}

impl Net {
    /// The tables as they start, in place in the zeroed `.bss`: only what is
    /// not all zeros is written, so the pool of 8 MiB takes no page.
    ///
    /// # Safety
    /// `at` is valid for writes, exclusive and zeroed.
    #[inline(never)]
    pub unsafe fn initialize_at(
        at: *mut Net,
        key: [u8; 16],
        parent: &Handle<Channel>,
        channel: &Handle<Channel>,
        level: u8,
    ) {
        use core::ptr::addr_of_mut;
        // SAFETY: each field is in bounds and written once; `parent` is
        // borrowed for the service's life, which never closes it here.
        unsafe {
            addr_of_mut!((*at).places).write(Places::new());
            rt::bss::fill(addr_of_mut!((*at).socks), Sock::EMPTY);
            rt::bss::fill(addr_of_mut!((*at).info), OpInfo::EMPTY);
            LongOps::initialize_at(addr_of_mut!((*at).ops));
            rt::bss::fill_none(addr_of_mut!((*at).births));
            addr_of_mut!((*at).key).write(key);
            addr_of_mut!((*at).parent).write(Some(Handle::borrowed(parent.raw())));
            addr_of_mut!((*at).notary).write(None);
            addr_of_mut!((*at).channel).write(Handle::borrowed(channel.raw()));
            addr_of_mut!((*at).external).write(None);
            addr_of_mut!((*at).level).write(level);
        }
    }

    /// The addresses of the interface, as the registry sees them: the
    /// external one when there is a lease.
    pub fn own_address(&self, address: [u8; 4]) -> bool {
        address == [0; 4] || address == [127, 0, 0, 1] || self.external == Some(address)
    }

    // ----- the places -----

    /// The smoltcp socket for place `i`.
    fn make_socket(&mut self, stack: &mut Stack<'static>, i: usize, proto: Proto) -> SocketHandle {
        let base = self.pool[i].as_mut_ptr();
        // SAFETY: the pool's chunk `i` belongs to the socket of place `i`
        // alone, which is removed before the place is free; the pool lives
        // as long as the service.
        let (rx, tx) = unsafe {
            (
                core::slice::from_raw_parts_mut(base, BUFFER),
                core::slice::from_raw_parts_mut(base.add(BUFFER), BUFFER),
            )
        };
        match proto {
            Proto::Tcp => stack.tcp_add(rx, tx),
            Proto::Udp => {
                let meta = self.udp_meta[i].as_mut_ptr().cast::<udp::PacketMetadata>();
                for k in 0..2 * PACKETS {
                    // SAFETY: the record `k` of place `i` is in bounds.
                    unsafe { meta.add(k).write(udp::PacketMetadata::EMPTY) };
                }
                // SAFETY: as above, the records belong to place `i`.
                let (rx_meta, tx_meta) = unsafe {
                    (
                        core::slice::from_raw_parts_mut(meta, PACKETS),
                        core::slice::from_raw_parts_mut(meta.add(PACKETS), PACKETS),
                    )
                };
                stack.udp_add(
                    udp::PacketBuffer::new(rx_meta, rx),
                    udp::PacketBuffer::new(tx_meta, tx),
                )
            }
        }
    }

    /// A place in `state`, with its smoltcp socket of `proto`. At the limit
    /// the oldest stream in TIME-WAIT is evicted first. None when the table
    /// is full.
    pub fn new_place(
        &mut self,
        stack: &mut Stack<'static>,
        state: State,
        proto: Proto,
    ) -> Option<usize> {
        if self.places.used() >= SOCKETS_LIMIT && !self.evict(stack) {
            return None;
        }
        let i = self.places.allocate(state)?;
        let handle = self.make_socket(stack, i, proto);
        self.socks[i] = Sock {
            proto,
            handle: Some(handle),
            ..Sock::EMPTY
        };
        Some(i)
    }

    /// Frees the oldest stream in TIME-WAIT that no session holds.
    fn evict(&mut self, stack: &mut Stack<'static>) -> bool {
        let mut oldest: Option<usize> = None;
        let mut at = 0;
        while let Some(i) = self.orphans.next(at) {
            at = i + 1;
            let waiting = self.socks[i]
                .handle
                .is_some_and(|h| stack.tcp(h).state() == tcp::State::TimeWait);
            if waiting && oldest.is_none_or(|o| self.socks[i].orphan_at < self.socks[o].orphan_at) {
                oldest = Some(i);
            }
        }
        match oldest {
            Some(i) => {
                self.release_place(stack, i);
                true
            }
            None => false,
        }
    }

    /// The place goes: its smoltcp socket, its port when no other holds it,
    /// its entry in the table.
    pub fn release_place(&mut self, stack: &mut Stack<'static>, i: usize) {
        let sock = self.socks[i];
        if let Some(handle) = sock.handle {
            if sock.proto == Proto::Tcp {
                stack.tcp(handle).abort();
            }
            stack.drop_socket(handle);
        }
        self.socks[i] = Sock::EMPTY;
        self.attention.clear(i);
        self.connecting.clear(i);
        self.orphans.clear(i);
        self.places.free(i);
        if sock.bound && sock.port != 0 && !self.port_held(sock.proto, sock.port) {
            self.ports(sock.proto).release(sock.port);
        }
    }

    pub fn ports(&mut self, proto: Proto) -> &mut PortMap {
        match proto {
            Proto::Tcp => &mut self.tcp_ports,
            Proto::Udp => &mut self.udp_ports,
        }
    }

    /// Whether a description other than the members of a queue holds the
    /// port.
    fn port_held(&self, proto: Proto, port: u16) -> bool {
        (0..SOCKETS_MAX).any(|i| {
            let s = &self.socks[i];
            matches!(self.places.state(i), State::Live | State::Orphan)
                && s.bound
                && s.proto == proto
                && s.port == port
        })
    }

    /// The bindings the registry compares a new bind with.
    pub fn bindings(&self, skip: usize) -> impl Iterator<Item = Binding> + '_ {
        (0..SOCKETS_MAX).filter_map(move |i| {
            let s = &self.socks[i];
            let live = matches!(self.places.state(i), State::Live | State::Orphan);
            (i != skip && live && s.bound).then_some(Binding {
                proto: s.proto,
                address: s.address,
                port: s.port,
                listening: s.listening,
                connected: s.conn != Conn::None,
                reuse: s.reuse,
            })
        })
    }

    /// An ephemeral port for a connection from `local` to `remote`, held in
    /// the registry; None after the tries.
    pub fn ephemeral(
        &mut self,
        proto: Proto,
        local: [u8; 4],
        remote: ([u8; 4], u16),
    ) -> Option<u16> {
        let offset = netd::ports::offset(&self.key, proto, local, remote.0, remote.1);
        self.counter = self.counter.wrapping_add(1);
        let counter = self.counter;
        let map = match proto {
            Proto::Tcp => &self.tcp_ports,
            Proto::Udp => &self.udp_ports,
        };
        let port = netd::ports::ephemeral(offset, counter, |p| !map.held(p))?;
        self.ports(proto).hold(port);
        Some(port)
    }

    /// The description `d` of a session that holds it.
    pub fn find(&self, held: &Held, d: u32) -> Option<usize> {
        self.places.find(d).filter(|&i| held.has(i))
    }

    /// Lets a session go of place `i`: the last one closes the description.
    pub fn release(&mut self, stack: &mut Stack<'static>, i: usize) {
        if self.places.release(i) == 0 {
            self.close(stack, i);
        }
    }

    /// No session holds the description: the operations that wait on it are
    /// told (they find it gone), and the socket closes.
    fn close(&mut self, stack: &mut Stack<'static>, i: usize) {
        self.tell_all(i);
        let sock = self.socks[i];
        if sock.listening {
            for k in 0..usize::from(sock.member_count) {
                let m = usize::from(sock.members[k]);
                self.release_place(stack, m);
            }
            self.release_place(stack, i);
            return;
        }
        match (sock.proto, sock.handle) {
            (Proto::Tcp, Some(handle)) => {
                let t = stack.tcp(handle);
                if matches!(
                    t.state(),
                    tcp::State::Closed | tcp::State::Listen | tcp::State::SynSent
                ) {
                    self.release_place(stack, i);
                } else {
                    t.close();
                    self.places.set_state(i, State::Orphan);
                    self.socks[i].orphan_at = now_ns();
                    self.socks[i].waiters = 0;
                    self.orphans.set(i);
                    self.connecting.clear(i);
                    self.attention.clear(i);
                    self.step_due = true;
                }
            }
            _ => self.release_place(stack, i),
        }
    }

    /// The streams no session holds, a few at a time: one that is closed is
    /// free, one past ORPHAN_NS is aborted.
    pub fn sweep(&mut self, stack: &mut Stack<'static>, now: u64) {
        let mut seen = 0;
        let mut at = self.sweep_at;
        for _ in 0..2 {
            while seen < SWEEP {
                let Some(i) = self.orphans.next(at) else {
                    break;
                };
                at = i + 1;
                seen += 1;
                let closed = self.socks[i]
                    .handle
                    .is_none_or(|h| stack.tcp(h).state() == tcp::State::Closed);
                if closed || now.saturating_sub(self.socks[i].orphan_at) >= ORPHAN_NS {
                    self.release_place(stack, i);
                }
            }
            if seen >= SWEEP {
                break;
            }
            at = 0;
        }
        self.sweep_at = at;
    }

    /// Whether streams wait for the sweep.
    pub fn orphans_wait(&self) -> bool {
        self.orphans.next(0).is_some()
    }

    // ----- the sessions that went -----

    /// A session that went (or a clone that was never taken) lets go of its
    /// descriptions in steps. True when a step of departure is due.
    pub fn depart(&mut self, stack: &mut Stack<'static>, held: Held) -> bool {
        if held.count() == 0 {
            return false;
        }
        match self.departing.iter_mut().find(|h| h.count() == 0) {
            Some(slot) => {
                *slot = held;
                true
            }
            None => {
                let mut held = held;
                while let Some(i) = held.next(0) {
                    held.remove(i);
                    self.release(stack, i);
                }
                false
            }
        }
    }

    /// One step of departure: GONE_PORTION descriptions let go of. True when
    /// more are left.
    pub fn depart_step(&mut self, stack: &mut Stack<'static>) -> bool {
        let mut left = GONE_PORTION;
        for n in 0..DEPARTING {
            while left > 0 {
                let Some(i) = self.departing[n].next(0) else {
                    break;
                };
                self.departing[n].remove(i);
                self.release(stack, i);
                left -= 1;
            }
        }
        self.departing.iter().any(|h| h.count() > 0)
    }

    // ----- what a socket is ready for -----

    /// Brings the state of a connecting stream up to date: the handshake
    /// done, or failed (REFUSED, or TIMEOUT after CONNECT_NS).
    pub fn sync(&mut self, stack: &mut Stack<'static>, i: usize, now: u64) {
        let Some(handle) = self.socks[i].handle else {
            return;
        };
        if self.socks[i].proto != Proto::Tcp || self.socks[i].listening {
            return;
        }
        let t = stack.tcp(handle);
        let state = t.state();
        if matches!(
            state,
            tcp::State::CloseWait
                | tcp::State::LastAck
                | tcp::State::Closing
                | tcp::State::TimeWait
        ) {
            self.socks[i].saw_fin = true;
        }
        if let Conn::Connecting(since) = self.socks[i].conn {
            match state {
                tcp::State::SynSent | tcp::State::SynReceived => {}
                tcp::State::Closed => {
                    let late = now.saturating_sub(since) >= CONNECT_NS - 1_000_000_000;
                    self.socks[i].error = if late {
                        proto_net::TIMEOUT
                    } else {
                        proto_net::REFUSED
                    };
                    self.socks[i].conn = Conn::None;
                    self.connecting.clear(i);
                }
                _ => {
                    t.set_timeout(None);
                    if self.socks[i].keepalive {
                        t.set_keep_alive(Some(duration(KEEPALIVE_NS)));
                    }
                    self.socks[i].conn = Conn::Done;
                    self.connecting.clear(i);
                }
            }
        }
    }

    /// The events of a watch (`proto_wire::watch`) that hold for place `i`.
    pub fn events(&mut self, stack: &mut Stack<'static>, i: usize, now: u64) -> u32 {
        self.sync(stack, i, now);
        let s = self.socks[i];
        let mut ev = 0;
        if s.error != 0 {
            ev |= watch::ERR;
        }
        let Some(handle) = s.handle else {
            // A listening description: ready to accept when a member is.
            if s.listening && self.accept_ready(stack, i).is_some() {
                ev |= watch::IN | watch::RDNORM;
            }
            return ev;
        };
        match s.proto {
            Proto::Tcp => {
                let t = stack.tcp(handle);
                if s.conn == Conn::Done {
                    if t.can_recv() || !t.may_recv() || s.shut_rd {
                        ev |= watch::IN | watch::RDNORM;
                    }
                    if t.can_send() && !s.shut_wr {
                        ev |= watch::OUT | watch::WRNORM;
                    }
                    if t.state() == tcp::State::Closed || (s.shut_wr && !t.may_recv()) {
                        ev |= watch::HUP;
                    }
                } else if !matches!(s.conn, Conn::Connecting(_)) {
                    // Never connected, or the connect failed.
                    ev |= watch::OUT | watch::HUP;
                }
            }
            Proto::Udp => {
                let u = stack.udp(handle);
                if u.can_recv() {
                    ev |= watch::IN | watch::RDNORM;
                }
                if u.can_send() {
                    ev |= watch::OUT | watch::WRNORM;
                }
            }
        }
        ev
    }

    /// The member of the queue of listening place `i` that has a connection:
    /// its index in the queue.
    pub fn accept_ready(&self, stack: &mut Stack<'static>, i: usize) -> Option<usize> {
        let s = &self.socks[i];
        (0..usize::from(s.member_count)).find(|&k| {
            let m = &self.socks[usize::from(s.members[k])];
            m.handle.is_some_and(|h| {
                matches!(
                    stack.tcp(h).state(),
                    tcp::State::Established | tcp::State::CloseWait
                )
            })
        })
    }

    // ----- the operations that wait -----

    /// The operation with index `idx` waits no more: its places forget it.
    pub fn forget_op(&mut self, idx: usize) {
        let info = self.info[idx];
        let bit = 1u128 << idx;
        if info.kind == Kind::Watch {
            let set = self.watches[idx];
            for item in &set.items[..set.len] {
                if let Some(i) = self.places.find(item.description) {
                    self.socks[i].waiters &= !bit;
                }
            }
        } else {
            self.socks[usize::from(info.place)].waiters &= !bit;
        }
        self.info[idx] = OpInfo::EMPTY;
    }

    /// Tells every operation that waits on place `i` that something changed
    /// (the description closed): each finds out on its next take.
    fn tell_all(&mut self, i: usize) {
        let mut mask = self.socks[i].waiters;
        while mask != 0 {
            let idx = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            let info = self.info[idx];
            self.ops.tell(info.label, info.key);
        }
    }

    /// The pass after a step: for each place with waiting operations, the
    /// ones whose condition holds are told. Stale waiters (their operation
    /// went with its session) are dropped.
    pub fn wake(&mut self, stack: &mut Stack<'static>, now: u64) {
        let mut at = 0;
        let mut seen: u128 = 0;
        while let Some(i) = self.attention.next(at) {
            at = i + 1;
            let ev = self.events(stack, i, now);
            let mut mask = self.socks[i].waiters;
            while mask != 0 {
                let idx = mask.trailing_zeros() as usize;
                let bit = 1u128 << idx;
                mask &= mask - 1;
                let info = self.info[idx];
                if !self.ops.waits(info.label, info.key) {
                    self.socks[i].waiters &= !bit;
                    continue;
                }
                let ready = match info.kind {
                    Kind::Connect => !matches!(self.socks[i].conn, Conn::Connecting(_)),
                    Kind::Accept => ev & (watch::IN | watch::ERR) != 0,
                    Kind::Send => ev & (watch::OUT | watch::ERR | watch::HUP) != 0,
                    Kind::Recv => ev & (watch::IN | watch::ERR | watch::HUP) != 0,
                    Kind::Watch => {
                        if seen & bit != 0 {
                            false
                        } else {
                            seen |= bit;
                            self.watch_ready(stack, idx, now).any()
                        }
                    }
                };
                if ready {
                    self.ops.tell(info.label, info.key);
                }
            }
            if self.socks[i].waiters == 0 {
                self.attention.clear(i);
            }
        }
    }

    /// The events of the watch with index `idx`, one word for each item.
    pub fn watch_ready(
        &mut self,
        stack: &mut Stack<'static>,
        idx: usize,
        now: u64,
    ) -> watch::Ready {
        let set = self.watches[idx];
        let mut ready = watch::Ready {
            len: set.len,
            events: [0; watch::MAX],
        };
        for (out, item) in ready.events[..set.len].iter_mut().zip(&set.items) {
            let ev = match self.places.find(item.description) {
                Some(i) => self.events(stack, i, now),
                None => watch::NVAL,
            };
            *out = ev & (item.events | watch::ALWAYS);
        }
        ready
    }

    // ----- the options -----

    /// Applies the options of a description to its smoltcp socket.
    pub fn apply_options(&mut self, stack: &mut Stack<'static>, i: usize) {
        let s = self.socks[i];
        if let (Proto::Tcp, Some(handle)) = (s.proto, s.handle) {
            let t = stack.tcp(handle);
            t.set_nagle_enabled(!s.nodelay);
            t.set_keep_alive(s.keepalive.then(|| duration(KEEPALIVE_NS)));
        }
    }

    /// The value of the option `name`, None for a name the service does not
    /// have.
    pub fn option(&mut self, i: usize, name: u32) -> Option<u32> {
        let s = &mut self.socks[i];
        Some(match name {
            opt::REUSEADDR => u32::from(s.reuse),
            opt::TYPE => match s.proto {
                Proto::Tcp => sockets::STREAM,
                Proto::Udp => sockets::DGRAM,
            },
            opt::ERROR => core::mem::take(&mut s.error),
            opt::RCVBUF | opt::SNDBUF => BUFFER as u32,
            opt::ACCEPTCONN => u32::from(s.listening),
            opt::DOMAIN => INET,
            opt::KEEPALIVE => u32::from(s.keepalive),
            opt::BROADCAST => u32::from(s.broadcast),
            opt::NODELAY => u32::from(s.nodelay),
            opt::NONBLOCK => u32::from(s.nonblock),
            _ => return None,
        })
    }

    // ----- the notary session -----

    /// The notary session with the process service, asked of init at the
    /// first use.
    pub fn notary(&mut self) -> Option<&Handle<Channel>> {
        if self.notary.is_none() {
            let parent = self.parent.as_ref()?;
            self.notary = rt::service::connect(parent, "posix").ok();
        }
        self.notary.as_ref()
    }

    /// The address of place `i` as the service names it.
    pub fn name(&self, stack: &mut Stack<'static>, i: usize, peer: bool) -> Option<Address> {
        let s = &self.socks[i];
        if let (Proto::Tcp, Some(handle)) = (s.proto, s.handle) {
            let t = stack.tcp(handle);
            let end = if peer {
                t.remote_endpoint()
            } else {
                t.local_endpoint()
            };
            if let Some(end) = end {
                let smoltcp::wire::IpAddress::Ipv4(a) = end.addr;
                return Some(Address::v4(a.octets(), u32::from(end.port)));
            }
        }
        if peer {
            return s.peer.map(|(a, p)| Address::v4(a, u32::from(p)));
        }
        Some(Address::v4(s.address, u32::from(s.port)))
    }
}
