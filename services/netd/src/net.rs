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

use crate::stack::{GROUP, GROUPS, Sh, Stack};
use core::mem::{ManuallyDrop, MaybeUninit};
use netd::demux::{Demux, Key};
use netd::frames::Dest;
use netd::places::{Held, Places, SOCKETS_LIMIT, SOCKETS_MAX, State};
use netd::ports::{Binding, PortMap, Proto};
use netd::ring::{OrphanQueue, WakeBudget};
use proto_net::sockets::{self, opt};
use proto_net::{Address, INET};
use proto_wire::clones::Clones;
use proto_wire::watch;
use rt::handle::{Channel, Handle};
use rt::service::{LongOps, LongSession};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Duration;

fn peer_of(end: smoltcp::wire::IpEndpoint) -> ([u8; 4], u16) {
    let smoltcp::wire::IpAddress::Ipv4(a) = end.addr;
    (a.octets(), end.port)
}

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
/// The orphans one step of the sweep looks at.
const SWEEP: usize = 4;
/// How long an aborted stream waits for its RST, in nanoseconds.
const RST_NS: u64 = 1_000_000_000;
/// The streams `evict` looks at.
const EVICT: usize = 8;
/// The sessions that went and still hold descriptions at most: a session
/// has one entry, so the table is as long as the sessions are. Past that (a
/// session that went twice before the first entry drained) the descriptions
/// are let go of at once.
pub const DEPARTING: usize = SESSIONS;
/// The descriptions the steps of departure let go of in one step.
pub const GONE_PORTION: usize = 8;
/// The aborted streams one step of departure looks at.
const RST_CHECKS: usize = 4 * GONE_PORTION;

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
    pub handle: Option<Sh>,
    /// What the table of destinations finds this socket by.
    pub key: Option<Key>,
    pub nonblock: bool,
    pub reuse: bool,
    pub keepalive: bool,
    pub nodelay: bool,
    pub broadcast: bool,
    pub shut_rd: bool,
    pub shut_wr: bool,
    /// The stream took a FIN from the peer.
    pub saw_fin: bool,
    /// For a socket of the queue of a listening description: the place of
    /// that description (NO_PLACE for any other socket).
    pub listener: u16,
    /// The stream was aborted and keeps its place until the pass of its group
    /// has sent the RST.
    pub rst_pending: bool,
    pub bound: bool,
    /// The socket holds its port in the registry (a member of a queue shares
    /// the listening description's).
    pub port_held: bool,
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
        key: None,
        nonblock: false,
        reuse: false,
        keepalive: false,
        nodelay: false,
        broadcast: false,
        shut_rd: false,
        shut_wr: false,
        saw_fin: false,
        listener: NO_PLACE,
        rst_pending: false,
        bound: false,
        port_held: false,
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

/// The index of an operation, from its key: None for a key no operation of
/// the table has (a client may send any).
pub fn op_index(key: u64) -> Option<usize> {
    netd::ring::op_index(key, OPERATIONS)
}

/// The place that means no place in `Sock::listener`.
pub const NO_PLACE: u16 = u16::MAX;

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
        if from >= SOCKETS_MAX {
            return None;
        }
        let mut word = from / 64;
        let mut bits = self.0[word] & (!0u64 << (from % 64));
        loop {
            if bits != 0 {
                return Some(word * 64 + bits.trailing_zeros() as usize);
            }
            word += 1;
            if word == self.0.len() {
                return None;
            }
            bits = self.0[word];
        }
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
    /// The entries of `departing` that hold descriptions, a bit each.
    departing_used: [u64; DEPARTING.div_ceil(64)],
    /// The places that have operations waiting, the streams that connect and
    /// those no session holds.
    pub attention: Mask,
    pub connecting: Mask,
    pub orphans: Mask,
    /// The streams no session holds, oldest first (place and the time they
    /// were let go of); an entry whose place has since gone is skipped.
    orphan_queue: OrphanQueue<SOCKETS_MAX>,
    /// The aborted streams that wait for their RST to go out.
    rst_wait: Mask,
    /// The members of the queue of a closed listening description that wait
    /// to be let go of, a few a step.
    release_queue: Mask,
    /// The operations whose description closed, which the step of waking
    /// tells.
    closed_ops: u128,
    /// The table that steers a frame to its socket.
    pub demux: Demux,
    /// The groups with work for the pass of sending, and those the step
    /// touched (a bit each), for the step of waking.
    pub due: u64,
    pub touched: u64,
    /// The groups whose pass of sending ran since the last step of waking.
    pub passed: u64,
    /// The service is asked for a step of departure or of waking.
    pub cleanup_wanted: bool,
    pub wake_wanted: bool,
    /// The places whose waiting operations the step of waking looks at.
    pub wake_due: Mask,
    wake_cursor: usize,
    /// Where the walk over the aborted streams resumes.
    rst_cursor: usize,
    /// The operations (by index) that were told and have not taken since:
    /// telling again costs a call of the kernel and tells nothing.
    pub told: u128,
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
    /// The listening description a SYN was just routed to.
    syn_listener: Option<usize>,
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
        demux_key: [u8; 16],
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
            Demux::initialize_at(addr_of_mut!((*at).demux), &demux_key);
            addr_of_mut!((*at).parent).write(Some(Handle::borrowed(parent.raw())));
            addr_of_mut!((*at).notary).write(None);
            addr_of_mut!((*at).channel).write(Handle::borrowed(channel.raw()));
            addr_of_mut!((*at).external).write(None);
            addr_of_mut!((*at).syn_listener).write(None);
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
    fn make_socket(&mut self, stack: &mut Stack<'static>, i: usize, proto: Proto) -> Sh {
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
            Proto::Tcp => stack.tcp_add(i, rx, tx),
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
                    i,
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

    /// Frees a stream that has closed, or else the oldest in TIME-WAIT, among
    /// the first EVICT entries of the streams no session holds (the oldest are
    /// first).
    fn evict(&mut self, stack: &mut Stack<'static>) -> bool {
        let live = Self::live_orphan(&self.places, &self.socks);
        let _ = self.orphan_queue.front(live);
        let mut chosen: Option<usize> = None;
        for k in 0..self.orphan_queue.len().min(EVICT) {
            let Some((i, at)) = self.orphan_queue.get(k) else {
                break;
            };
            if !self.orphan_live(i, at) {
                continue;
            }
            let state = self.socks[i].handle.map(|h| stack.tcp(h).state());
            // A stream that has closed is free at once.
            if state.is_none_or(|s| s == tcp::State::Closed) && !self.socks[i].rst_pending {
                self.release_place(stack, i);
                return true;
            }
            if state == Some(tcp::State::TimeWait) && chosen.is_none() {
                chosen = Some(i);
            }
        }
        match chosen {
            Some(i) => {
                self.release_place(stack, i);
                true
            }
            None => false,
        }
    }

    /// Whether the queue's entry (`i`, `at`) is still the stream let go of at
    /// `at`.
    fn orphan_live(&self, i: usize, at: u64) -> bool {
        self.places.state(i) == State::Orphan && self.socks[i].orphan_at == at
    }

    /// The test of an entry of the queue, over the tables it reads.
    fn live_orphan<'a>(
        places: &'a Places<SOCKETS_MAX>,
        socks: &'a [Sock; SOCKETS_MAX],
    ) -> impl Fn(usize, u64) -> bool + 'a {
        move |i, at| places.state(i) == State::Orphan && socks[i].orphan_at == at
    }

    /// A stream no session holds, to be swept in its time.
    fn orphan_push(&mut self, i: usize, at: u64) {
        let live = Self::live_orphan(&self.places, &self.socks);
        self.orphan_queue.push(i, at, live);
    }

    /// The oldest stream no session holds that is still one.
    fn orphan_front(&mut self) -> Option<(usize, u64)> {
        let live = Self::live_orphan(&self.places, &self.socks);
        self.orphan_queue.front(live)
    }

    fn orphan_pop(&mut self) {
        self.orphan_queue.pop();
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
        if let Some(key) = sock.key {
            self.demux.remove(&key);
        }
        self.rst_wait.clear(i);
        self.wake_due.clear(i);
        self.attention.clear(i);
        self.connecting.clear(i);
        self.orphans.clear(i);
        self.places.free(i);
        if sock.port_held {
            self.ports(sock.proto).release(sock.port);
        }
    }

    pub fn ports(&mut self, proto: Proto) -> &mut PortMap {
        match proto {
            Proto::Tcp => &mut self.tcp_ports,
            Proto::Udp => &mut self.udp_ports,
        }
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
        self.touch(i);
        let sock = self.socks[i];
        if sock.listening {
            // The queue is let go of a few sockets a step, with the RST of
            // the connections nobody accepted.
            for k in 0..usize::from(sock.member_count) {
                self.release_queue.set(usize::from(sock.members[k]));
            }
            self.release_place(stack, i);
            self.cleanup_wanted = true;
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
                    let at = now_ns();
                    self.socks[i].orphan_at = at;
                    self.socks[i].waiters = 0;
                    self.orphans.set(i);
                    self.orphan_push(i, at);
                    self.connecting.clear(i);
                    self.attention.clear(i);
                    self.step_due = true;
                }
            }
            _ => self.release_place(stack, i),
        }
    }

    /// The streams no session holds, oldest first, a few at a time: one that
    /// has closed is free, one past ORPHAN_NS is aborted (with its RST). A
    /// step looks at SWEEP of them; true when the queue goes on.
    pub fn sweep(&mut self, stack: &mut Stack<'static>, now: u64) -> bool {
        for _ in 0..SWEEP {
            let Some((i, at)) = self.orphan_front() else {
                return false;
            };
            if self.socks[i].rst_pending {
                // Its RST is on the way.
                return false;
            }
            let closed = self.socks[i]
                .handle
                .is_none_or(|h| stack.tcp(h).state() == tcp::State::Closed);
            if closed {
                self.orphan_pop();
                self.release_place(stack, i);
            } else if now.saturating_sub(at) >= ORPHAN_NS {
                self.orphan_pop();
                self.abort_place(stack, i);
            } else {
                return false;
            }
        }
        !self.orphan_queue.is_empty()
    }

    /// The stream of place `i` is aborted: its RST goes out with the next
    /// pass of its group, and the place is free after it. A socket that has
    /// nothing to reset is free at once.
    pub fn abort_place(&mut self, stack: &mut Stack<'static>, i: usize) {
        let Some(handle) = self.socks[i].handle else {
            self.release_place(stack, i);
            return;
        };
        if self.socks[i].proto != Proto::Tcp
            || matches!(
                stack.tcp(handle).state(),
                tcp::State::Closed
                    | tcp::State::Listen
                    | tcp::State::SynSent
                    | tcp::State::TimeWait
            )
        {
            self.release_place(stack, i);
            return;
        }
        stack.tcp(handle).abort();
        self.rst_wait.set(i);
        let sock = &mut self.socks[i];
        sock.rst_pending = true;
        sock.orphan_at = now_ns();
        sock.waiters = 0;
        sock.listener = NO_PLACE;
        self.places.set_state(i, State::Orphan);
        self.release_queue.clear(i);
        self.connecting.clear(i);
        self.attention.clear(i);
        self.touch(i);
        self.step_due = true;
    }

    /// Whether streams wait for the sweep.
    pub fn orphans_wait(&self) -> bool {
        !self.orphan_queue.is_empty()
    }

    // ----- the sessions that went -----

    /// A session that went (or a clone that was never taken) lets go of its
    /// descriptions in steps. True when a step of departure is due.
    pub fn depart(&mut self, stack: &mut Stack<'static>, held: Held) -> bool {
        if held.count() == 0 {
            return false;
        }
        let free = (0..DEPARTING).find(|&n| self.departing_used[n / 64] >> (n % 64) & 1 == 0);
        match free {
            Some(n) => {
                self.departing[n] = held;
                self.departing_used[n / 64] |= 1 << (n % 64);
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

    /// One step of departure: at most GONE_PORTION places let go of, the
    /// descriptions of the sessions that went and the members of the queues
    /// of closed listening descriptions. True when more are left.
    pub fn depart_step(&mut self, stack: &mut Stack<'static>) -> bool {
        let mut left = GONE_PORTION;
        'entries: for word in 0..self.departing_used.len() {
            while self.departing_used[word] != 0 {
                if left == 0 {
                    break 'entries;
                }
                let n = word * 64 + self.departing_used[word].trailing_zeros() as usize;
                match self.departing[n].next(0) {
                    Some(i) => {
                        self.departing[n].remove(i);
                        self.release(stack, i);
                        left -= 1;
                    }
                    None => self.departing_used[word] &= !(1 << (n % 64)),
                }
            }
        }
        while left > 0 {
            let Some(m) = self.release_queue.next(0) else {
                break;
            };
            self.release_queue.clear(m);
            self.abort_place(stack, m);
            left -= 1;
        }
        // The aborted streams whose RST has gone out, a share of them in a
        // step. One whose RST has not gone stays: the pass of its group asks
        // for the next step, and the time limit does when no pass comes.
        let marks = self.rst_wait;
        let mut cursor = self.rst_cursor;
        let finished = netd::ring::walk_round(
            &mut cursor,
            RST_CHECKS,
            |from| marks.next(from),
            |m| {
                // A RST that cannot go for a second (no neighbour, no buffer)
                // is given up: the place is not held for ever.
                let sent = self.socks[m]
                    .handle
                    .is_none_or(|h| stack.tcp(h).remote_endpoint().is_none())
                    || now_ns().saturating_sub(self.socks[m].orphan_at) > RST_NS;
                if !sent {
                    return true;
                }
                if left == 0 {
                    return false;
                }
                self.socks[m].rst_pending = false;
                self.release_place(stack, m);
                left -= 1;
                true
            },
        );
        self.rst_cursor = cursor;
        if left < GONE_PORTION {
            self.step_due = true;
        }
        self.departing_used.iter().any(|&w| w != 0)
            || self.release_queue.next(0).is_some()
            || !finished
    }

    /// Whether aborted streams wait for their RST.
    pub fn rst_waiting(&self) -> bool {
        self.rst_wait.next(0).is_some()
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
        self.told &= !bit;
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

    /// The operations that wait on place `i` are told (by the step of
    /// waking, a few at a time) that the description closed: each finds out on
    /// its next take.
    fn tell_all(&mut self, i: usize) {
        self.closed_ops |= self.socks[i].waiters;
        if self.closed_ops != 0 {
            self.wake_wanted = true;
        }
    }

    // ----- the groups of sockets -----

    /// The group of place `i` has work for the next pass of sending, and its
    /// operations are looked at by the next step of waking.
    pub fn touch(&mut self, i: usize) {
        let bit = 1u64 << (i / GROUP);
        self.due |= bit;
        self.touched |= bit;
    }

    /// Every group has work: an address changed or a neighbour answered.
    pub fn touch_all(&mut self) {
        let all = if GROUPS == 64 {
            u64::MAX
        } else {
            (1u64 << GROUPS) - 1
        };
        self.due |= all;
    }

    /// Gives the key to the socket of place `i` in the table of destinations.
    pub fn register(&mut self, i: usize, key: Key) {
        if self.socks[i].key.is_none() && self.demux.insert(key, i) {
            self.socks[i].key = Some(key);
        }
    }

    /// The place a received frame is for, None for the set of the service.
    /// A SYN to a listening description goes to the first socket of its
    /// queue that is still listening; `adopt` runs after the stack took it.
    pub fn route(&mut self, stack: &mut Stack<'static>, dest: Dest) -> Option<usize> {
        match dest {
            Dest::Service | Dest::Arp => None,
            Dest::Tcp {
                local,
                local_port,
                remote,
                remote_port,
                syn,
            } => {
                let conn = Key::Conn {
                    local,
                    local_port,
                    remote,
                    remote_port,
                };
                if let Some(place) = self.demux.find(&conn) {
                    return Some(place);
                }
                if !syn {
                    return None;
                }
                let listener = [local, [0; 4]].into_iter().find_map(|address| {
                    self.demux.find(&Key::Bound {
                        tcp: true,
                        address,
                        port: local_port,
                    })
                })?;
                let sock = self.socks[listener];
                let member = (0..usize::from(sock.member_count))
                    .map(|k| usize::from(sock.members[k]))
                    .find(|&m| {
                        self.socks[m]
                            .handle
                            .is_some_and(|h| stack.tcp(h).state() == tcp::State::Listen)
                    })?;
                self.syn_listener = Some(listener);
                Some(member)
            }
            Dest::Udp {
                local,
                local_port,
                broadcast,
            } => {
                let addresses = if broadcast {
                    [[0; 4], local]
                } else {
                    [local, [0; 4]]
                };
                addresses.into_iter().find_map(|address| {
                    self.demux.find(&Key::Bound {
                        tcp: false,
                        address,
                        port: local_port,
                    })
                })
            }
        }
    }

    /// After the stack took a SYN for a listening description: the sockets of
    /// its queue that left LISTEN get the key of their connection, and one
    /// that went back to LISTEN (a reset) loses it.
    pub fn adopt(&mut self, stack: &mut Stack<'static>) {
        let Some(listener) = self.syn_listener.take() else {
            return;
        };
        let sock = self.socks[listener];
        for k in 0..usize::from(sock.member_count) {
            let m = usize::from(sock.members[k]);
            let Some(handle) = self.socks[m].handle else {
                continue;
            };
            let t = stack.tcp(handle);
            if t.state() == tcp::State::Listen {
                if let Some(key) = self.socks[m].key.take() {
                    self.demux.remove(&key);
                }
            } else if self.socks[m].key.is_none()
                && let (Some(local), Some(remote)) = (t.local_endpoint(), t.remote_endpoint())
            {
                let (local, remote) = (peer_of(local), peer_of(remote));
                self.register(
                    m,
                    Key::Conn {
                        local: local.0,
                        local_port: local.1,
                        remote: remote.0,
                        remote_port: remote.1,
                    },
                );
            }
        }
    }

    /// After a step of the stack: the places of the groups it touched that
    /// have operations waiting or a connection under way are for the step of
    /// waking, and so is the listening description of a socket of a queue (its
    /// ACCEPT and WATCH wait on that place). A stream that was aborted is free
    /// once the pass of its group has sent the RST.
    pub fn schedule_wake(&mut self) {
        // An aborted stream is let go of by the step of departure once its RST
        // has really gone out (smoltcp forgets the connection after the
        // single RST): the pass of its group is the time to look.
        let mut passed = core::mem::take(&mut self.passed);
        while passed != 0 && self.rst_wait.next(0).is_some() {
            let g = passed.trailing_zeros() as usize;
            passed &= passed - 1;
            if (g * GROUP..(g + 1) * GROUP).any(|i| self.rst_wait.has(i)) {
                self.cleanup_wanted = true;
            }
        }
        let mut groups = core::mem::take(&mut self.touched);
        while groups != 0 {
            let g = groups.trailing_zeros() as usize;
            groups &= groups - 1;
            for i in g * GROUP..(g + 1) * GROUP {
                if self.attention.has(i) || self.connecting.has(i) {
                    self.wake_due.set(i);
                }
                let listener = usize::from(self.socks[i].listener);
                if listener != usize::from(NO_PLACE) && self.attention.has(listener) {
                    self.wake_due.set(listener);
                }
            }
        }
    }

    /// Whether the step of waking has places or operations left.
    pub fn wake_pending(&self) -> bool {
        self.wake_due.next(0).is_some() || self.closed_ops != 0
    }

    /// The step of waking: for the places in `wake_due`, in turn, the
    /// operations whose condition holds are told, within the share of the
    /// step (WAKE_TELLS notifications, WAKE_CHECKS checks). A place not
    /// finished stays. True when places are left.
    pub fn wake(&mut self, stack: &mut Stack<'static>, now: u64) -> bool {
        let mut budget = WakeBudget::new();
        // The operations whose description closed.
        while self.closed_ops != 0 && budget.take_tell() {
            let idx = self.closed_ops.trailing_zeros() as usize;
            self.closed_ops &= self.closed_ops - 1;
            let info = self.info[idx];
            self.ops.tell(info.label, info.key);
        }
        if self.closed_ops != 0 {
            return true;
        }
        let mut at = self.wake_cursor;
        'places: while let Some(i) = self.wake_due.next(at).or_else(|| self.wake_due.next(0)) {
            at = i + 1;
            if !budget.take_check() {
                break;
            }
            let ev = self.events(stack, i, now);
            let mut mask = self.socks[i].waiters;
            while mask != 0 {
                let idx = mask.trailing_zeros() as usize;
                let bit = 1u128 << idx;
                mask &= mask - 1;
                // An operation told already waits for its take: it costs
                // nothing, so that the rest of the place is reached.
                if self.told & bit != 0 {
                    continue;
                }
                let info = self.info[idx];
                if !self.ops.waits(info.label, info.key) {
                    self.socks[i].waiters &= !bit;
                    continue;
                }
                if !budget.take_check() {
                    self.wake_cursor = i;
                    break 'places;
                }
                let ready = match info.kind {
                    Kind::Connect => !matches!(self.socks[i].conn, Conn::Connecting(_)),
                    Kind::Accept => ev & (watch::IN | watch::ERR) != 0,
                    Kind::Send => ev & (watch::OUT | watch::ERR | watch::HUP) != 0,
                    Kind::Recv => ev & (watch::IN | watch::ERR | watch::HUP) != 0,
                    Kind::Watch => {
                        // A watch of many items costs more checks.
                        let more = self.watches[idx].len / 8;
                        if !budget.take_checks(more) {
                            self.wake_cursor = i;
                            break 'places;
                        }
                        self.watch_item_ready(idx, i, ev)
                    }
                };
                if ready && self.told & bit == 0 {
                    if !budget.take_tell() {
                        self.wake_cursor = i;
                        break 'places;
                    }
                    self.told |= bit;
                    self.ops.tell(info.label, info.key);
                }
            }
            if self.socks[i].waiters == 0 {
                self.attention.clear(i);
            }
            self.wake_due.clear(i);
            if at >= SOCKETS_MAX {
                at = 0;
            }
        }
        self.wake_pending()
    }

    /// Whether an item of the watch with index `idx` that names place `i`
    /// holds, given the events `ev` of the place.
    fn watch_item_ready(&self, idx: usize, i: usize, ev: u32) -> bool {
        let set = &self.watches[idx];
        set.items[..set.len].iter().any(|item| {
            self.places.find(item.description) == Some(i) && ev & (item.events | watch::ALWAYS) != 0
        })
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
