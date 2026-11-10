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

use crate::stack::{GROUP, GROUPS, GroupSet, Sh, Stack};
use core::mem::{ManuallyDrop, MaybeUninit};
use netd::buffers::Buffers;
use netd::chains::PortChains;
use netd::demux::{Demux, Key};
use netd::frames::Dest;
use netd::interest::Interests;
use netd::owners::Owners;
use netd::passes::Passes;
use netd::places::{Held, Places, SOCKETS_LIMIT, SOCKETS_MAX, State, orphan_is_over};
use netd::ports::{Binding, PortMap, Proto};
use netd::reuse::{Groups, NO_GROUP};
use netd::ring::{OrphanQueue, WakeBudget};
use proto_net::sockets::{self, opt};
use proto_net::{Address, INET};
use proto_wire::clones::Clones;
use proto_wire::watch;
use rt::handle::{Channel, Handle, Process};
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
pub const OPEN_MAX: usize = 1024;
/// The sockets of the queue of `listen` at most.
pub const BACKLOG_MAX: usize = 16;
/// The bytes of a buffer of one direction of a TCP socket, and the packets
/// and bytes of one direction of a UDP socket: the first `FULL_PLACES` places
/// have `BUFFER` bytes a direction, the others `SMALL_BUFFER` (1 280 sockets
/// of 16 KiB a side would be 40 MiB). Places are given from the lowest, so
/// while fewer than `FULL_PLACES` sockets are open every one has the full buffer.
pub const BUFFER: usize = 16 * 1024;
pub const SMALL_BUFFER: usize = 4 * 1024;
pub const FULL_PLACES: usize = 256;
const SMALL_PLACES: usize = SOCKETS_MAX - FULL_PLACES;
const PACKETS: usize = 16;

/// The bytes of a direction of the buffers of place `i`.
pub const fn buffer_of(i: usize) -> usize {
    if i < FULL_PLACES {
        BUFFER
    } else {
        SMALL_BUFFER
    }
}
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
/// The groups of sockets `schedule_wake` looks at in one step.
const SCHEDULE_GROUPS: usize = 16;
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
    /// The entry of the session's shared buffer (BUFFER) in `Net::buffers`.
    pub buffer: Option<u8>,
    /// The consumer number of the switch the session attached (ATTACH).
    pub consumer: Option<netd::books::Mine>,
}

pub use netd::births::Birth;

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
    /// SO_REUSEPORT before BIND, and the group the socket is in.
    pub reuseport: bool,
    /// For a listening description: how many sockets of its queue are in
    /// LISTEN as the service last counted them (kept up to date by the calls
    /// and by `adopt`), and when it last looked at them all.
    pub room: u8,
    pub room_at: u64,
    /// The effective user that bound the socket with SO_REUSEPORT.
    pub uid: u32,
    pub group: u8,
    /// SO_LINGER (0 off, else `opt::LINGER_ON` and the seconds) and the
    /// timeouts of SO_RCVTIMEO and SO_SNDTIMEO in milliseconds (0 for none).
    pub linger: u32,
    pub rcvtimeo: u32,
    pub sndtimeo: u32,
    pub shut_rd: bool,
    pub shut_wr: bool,
    /// The stream took a FIN from the peer.
    pub saw_fin: bool,
    /// For a socket of the queue of a listening description: the place of
    /// that description (NO_PLACE for any other socket).
    pub listener: u16,
    /// The socket of a queue counts in the owner of its set (the queue of a
    /// member of a group).
    pub owns_set: bool,
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
    /// For a description of a port (PORT_HOLD): the number of its group (1 to 32). The
    /// description has no smoltcp socket and answers no socket call.
    pub hold: u8,
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
        reuseport: false,
        room: 0,
        room_at: 0,
        uid: 0,
        group: NO_GROUP,
        linger: 0,
        rcvtimeo: 0,
        sndtimeo: 0,
        shut_rd: false,
        shut_wr: false,
        saw_fin: false,
        listener: NO_PLACE,
        owns_set: false,
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
        hold: 0,
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
    /// A `close` of a stream with a linger time waits for the data it sent to
    /// be acknowledged: `OpInfo::place` is the orphan's place.
    Linger,
    /// A wait on an interest set: `OpInfo::place` is the index of the set.
    Epoll,
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

/// The event RDHUP of epoll: the peer closed its sending side. A watch asks
/// for it as `watch::RDHUP` (a poll with POLLRDHUP), the same bit.
pub const RDHUP: u32 = proto_net::sockets::epoll::RDHUP;
const _: () = assert!(RDHUP == watch::RDHUP);

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
    /// SYNs dropped for want of room in the queue of a listening description.
    pub syn_dropped: u64,
    /// Queue sockets of a member of a group that found no set without the
    /// queue sockets of another member: the queue is shorter.
    pub set_barred: u64,
    /// SYNs taken by a queue socket of a listening description other than
    /// the one chosen. Stays 0.
    pub syn_stray: u64,
    /// Closed streams no session held whose four a new SYN took over before the sweep.
    pub orphan_reused: u64,
    /// The pages charged to the service when the first and the sixty-fourth
    /// shared buffer were mapped (builds with the feature `probe`).
    #[cfg(feature = "probe")]
    pub buffers_used: [u64; 2],
    /// The most bytes one request with a cell copied (builds with the
    /// feature `probe`): never more than the portion.
    #[cfg(feature = "probe")]
    pub largest_copy: u64,
}

/// The sockets of the service.
pub struct Net {
    pub places: Places<SOCKETS_MAX>,
    pub socks: [Sock; SOCKETS_MAX],
    /// The buffers: place i below `FULL_PLACES` uses `pool_full[i]`, the others
    /// `pool_small[i - FULL_PLACES]`; the first half for receiving and the
    /// second for sending.
    pool_full: [[u8; 2 * BUFFER]; FULL_PLACES],
    pool_small: [[u8; 2 * SMALL_BUFFER]; SMALL_PLACES],
    /// The packet records of a datagram socket: place i, then the two
    /// directions.
    udp_meta: [[MaybeUninit<udp::PacketMetadata>; 2 * PACKETS]; SOCKETS_MAX],
    /// The bound places, in a chain for each port.
    pub chains: PortChains<SOCKETS_MAX>,
    /// The bound places that are connected and do not listen: a bind that
    /// may share the port (SO_REUSEADDR) has no need to look at them, so the
    /// accepted connections of a busy server are not walked.
    pub connected: PortChains<SOCKETS_MAX>,
    pub tcp_ports: PortMap,
    pub udp_ports: PortMap,
    pub ops: LongOps<OPERATIONS>,
    pub info: [OpInfo; OPERATIONS],
    /// The time limit of each operation that has one (SO_RCVTIMEO,
    /// SO_SNDTIMEO, SO_LINGER) in nanoseconds, the operations that have one
    /// and the operations whose time ran out, a bit each.
    pub op_deadline: [u64; OPERATIONS],
    pub timed: u128,
    pub expired: u128,
    /// The `Linger` operations whose place went: they are over.
    pub lingered: u128,
    /// An operation with a time limit was made since the loop last looked:
    /// the timer may need to be set earlier.
    pub deadline_new: bool,
    /// The groups of ports of the switch (PORT_HOLD): what the registry compares a bind with,
    /// until the switch says the group is gone (`Back::Freed`).
    pub holds: netd::books::Holds,
    /// The SO_REUSEPORT groups.
    pub groups: Groups,
    /// The owners of the sets of places (queue sockets of the members of
    /// groups).
    pub owners: Owners<GROUPS, { SOCKETS_LIMIT.div_ceil(64) }>,
    /// The passes of EXPORT that wait for ADOPT.
    pub passes: Passes,
    /// The frame `route` just looked at is a SYN to a full queue: the loop
    /// drops it and the stack never sees it.
    pub drop_frame: bool,
    pub watches: [watch::Set; OPERATIONS],
    pub clones: Clones<SESSIONS>,
    /// The interest sets of epoll and the records of the places.
    pub interest: Interests<SOCKETS_MAX>,
    pub births: [Option<Birth>; SESSIONS],
    departing: [Held; DEPARTING],
    /// The operations of each departing session that wait still: a step of
    /// departure lets go of a portion of them before the places.
    departing_long: [LongSession; DEPARTING],
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
    pub closed_ops: u128,
    /// The table that steers a frame to its socket.
    pub demux: Demux,
    /// The groups with work for the pass of sending, and those the step
    /// touched (a bit each), for the step of waking.
    pub due: GroupSet,
    pub touched: GroupSet,
    /// Where `schedule_wake` goes on, so that groups above the first few are
    /// reached when the lower ones are touched again in every step.
    schedule_cursor: usize,
    /// The groups whose pass of sending ran since the last step of waking.
    pub passed: GroupSet,
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
    /// The service's own process, which the shared buffers are mapped into.
    pub process: Option<ManuallyDrop<Handle<Process>>>,
    /// The shared buffers of the sessions, and the bytes that went through
    /// them since the start.
    pub buffers: Buffers,
    pub buffered: u64,
    notary: Option<Handle<Channel>>,
    /// A step of the stack is due (a request changed a socket): the loop
    /// tells itself.
    pub step_due: bool,
    /// A request asked for the profile's totals (`GETOPT BUFFERED`, which
    /// `posix-net stat` makes); the service prints them after the request.
    #[cfg(any(feature = "profile", feature = "probe", feature = "trace"))]
    pub profile_due: bool,
    /// A request is being handled (builds with the feature `probe`: the step of
    /// waking is the one that tells the waits of a set, never a request).
    #[cfg(feature = "probe")]
    pub in_request: bool,
    pub counters: Counters,
    /// The socket of a queue a SYN was just routed to, and the listening
    /// description it was chosen for.
    syn_member: Option<(usize, usize)>,
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
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn initialize_at(
        at: *mut Net,
        key: [u8; 16],
        demux_key: [u8; 16],
        parent: &Handle<Channel>,
        channel: &Handle<Channel>,
        level: u8,
        process: &Handle<Process>,
        buffers: u16,
    ) {
        use core::ptr::addr_of_mut;
        // SAFETY: each field is in bounds and written once; `parent` is
        // borrowed for the service's life, which never closes it here.
        unsafe {
            addr_of_mut!((*at).places).write(Places::new());
            rt::bss::fill(addr_of_mut!((*at).socks), Sock::EMPTY);
            rt::bss::fill(addr_of_mut!((*at).info), OpInfo::EMPTY);
            addr_of_mut!((*at).groups).write(Groups::new());
            addr_of_mut!((*at).owners).write(Owners::new());
            addr_of_mut!((*at).passes).write(Passes::new());
            LongOps::initialize_at(addr_of_mut!((*at).ops));
            rt::bss::fill_none(addr_of_mut!((*at).births));
            Interests::initialize_at(addr_of_mut!((*at).interest));
            rt::bss::fill(addr_of_mut!((*at).departing_long), LongSession::default());
            addr_of_mut!((*at).key).write(key);
            Demux::initialize_at(addr_of_mut!((*at).demux), &demux_key);
            addr_of_mut!((*at).parent).write(Some(Handle::borrowed(parent.raw())));
            addr_of_mut!((*at).notary).write(None);
            #[cfg(any(feature = "profile", feature = "probe", feature = "trace"))]
            addr_of_mut!((*at).profile_due).write(false);
            addr_of_mut!((*at).channel).write(Handle::borrowed(channel.raw()));
            addr_of_mut!((*at).external).write(None);
            addr_of_mut!((*at).syn_member).write(None);
            addr_of_mut!((*at).level).write(level);
            addr_of_mut!((*at).process).write(Some(Handle::borrowed(process.raw())));
            addr_of_mut!((*at).buffers).write(Buffers::new(buffers));
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
        let size = buffer_of(i);
        let base = if i < FULL_PLACES {
            self.pool_full[i].as_mut_ptr()
        } else {
            self.pool_small[i - FULL_PLACES].as_mut_ptr()
        };
        // SAFETY: the pool's chunk of place `i` belongs to the socket of place
        // `i` alone, which is removed before the place is free; the pool lives
        // as long as the service.
        let (rx, tx) = unsafe {
            (
                core::slice::from_raw_parts_mut(base, size),
                core::slice::from_raw_parts_mut(base.add(size), size),
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
        self.place_for(stack, state, proto, None)
    }

    /// As `new_place`; for a queue socket of the member `queue.0` of a group,
    /// whose queue stands in the places `queue.1[..queue.2]` already, the
    /// place is in a set that no other member's queue sockets stand in.
    pub fn place_for(
        &mut self,
        stack: &mut Stack<'static>,
        state: State,
        proto: Proto,
        queue: Option<(usize, [u16; BACKLOG_MAX], usize)>,
    ) -> Option<usize> {
        if self.places.used() >= SOCKETS_LIMIT && !self.evict(stack) {
            return None;
        }
        let i = match queue {
            None => self.places.allocate(state)?,
            Some((listener, own, count)) => {
                let owners = &self.owners;
                let own_sets = own[..count]
                    .iter()
                    .map(|&m| usize::from(m) / GROUP)
                    .filter(|&set| owners.allowed(set, listener));
                let i = self
                    .places
                    .allocate_in(state, own_sets, owners.barred().as_slice());
                if i.is_none() && self.places.used() < SOCKETS_LIMIT {
                    self.counters.set_barred += 1;
                    if self.counters.set_barred == 1 {
                        rt::println!(
                            "netd: set_barred: no set without another member's queue sockets"
                        );
                    }
                }
                i?
            }
        };
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
        self.lingers_over(sock.waiters);
        if let Some(handle) = sock.handle {
            if sock.proto == Proto::Tcp {
                stack.tcp(handle).abort();
            }
            stack.drop_socket(handle);
        }
        self.chains.unlink(i);
        self.connected.unlink(i);
        self.leave_queue(i);
        self.socks[i] = Sock::EMPTY;
        if let Some(key) = sock.key {
            self.demux.remove(&key);
        }
        if sock.group != NO_GROUP {
            self.leave_group(sock.group, i, sock.key);
        }
        self.interest.drop_place(i, None);
        self.rst_wait.clear(i);
        self.wake_due.clear(i);
        self.attention.clear(i);
        self.connecting.clear(i);
        self.orphans.clear(i);
        self.places.free(i);
        if sock.port_held {
            self.ports(sock.proto).release(sock.port);
        }
        if sock.hold != 0 {
            self.holds.closed(sock.hold);
            self.cleanup_wanted = true;
        }
    }

    /// The socket of place `i` is no longer a socket of a queue: its set loses
    /// one of the sockets that make its owner.
    pub fn leave_queue(&mut self, i: usize) {
        if core::mem::take(&mut self.socks[i].owns_set) {
            self.owners.release(i / GROUP);
        }
        self.socks[i].listener = NO_PLACE;
    }

    /// The place `i` left the group `k`; when it held the key of the group in
    /// the table of destinations, the next member that listens takes it over.
    fn leave_group(&mut self, k: u8, i: usize, key: Option<Key>) {
        let k = usize::from(k);
        self.groups.leave(k, i);
        let Some(key @ Key::Bound { tcp: true, .. }) = key else {
            return;
        };
        let next = self
            .groups
            .members(k)
            .iter()
            .map(|&m| usize::from(m))
            .find(|&m| self.socks[m].listening && self.socks[m].key.is_none());
        if let Some(m) = next {
            self.register(m, key);
        }
    }

    /// The operations in `waiters` that wait for a `close` to finish on a
    /// place that goes are over.
    fn lingers_over(&mut self, mut waiters: u128) {
        while waiters != 0 {
            let idx = waiters.trailing_zeros() as usize;
            let bit = 1u128 << idx;
            waiters &= waiters - 1;
            if self.info[idx].kind == Kind::Linger {
                self.lingered |= bit;
                self.closed_ops |= bit;
                self.wake_wanted = true;
            }
        }
    }

    pub fn ports(&mut self, proto: Proto) -> &mut PortMap {
        match proto {
            Proto::Tcp => &mut self.tcp_ports,
            Proto::Udp => &mut self.udp_ports,
        }
    }

    /// The bindings the registry compares a new bind with.
    pub fn bindings(
        &self,
        port: u16,
        skip: usize,
        with_connected: bool,
    ) -> impl Iterator<Item = Binding> + '_ {
        let connected = with_connected.then(|| self.connected.chain(port));
        let held = self.holds.list.iter().filter_map(move |h| h.binding(port));
        self.chains
            .chain(port)
            .chain(connected.into_iter().flatten())
            .filter_map(move |i| {
                let s = &self.socks[i];
                let live = matches!(self.places.state(i), State::Live | State::Orphan);
                (i != skip && live && s.bound).then_some(Binding {
                    proto: s.proto,
                    address: s.address,
                    port: s.port,
                    listening: s.listening,
                    connected: s.conn != Conn::None,
                    reuse: s.reuse,
                    share_uid: s.reuseport.then_some(s.uid),
                })
            })
            .chain(held)
    }

    /// Puts the bound place `i` in the chain of its port that its state asks
    /// for: connected and not listening, or the other.
    pub fn rechain(&mut self, i: usize) {
        let s = &self.socks[i];
        if !s.bound {
            return;
        }
        let port = s.port;
        if s.conn != Conn::None && !s.listening {
            self.chains.unlink(i);
            self.connected.link(i, port);
        } else {
            self.connected.unlink(i);
            self.chains.link(i, port);
        }
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
        let port = netd::ports::ephemeral(offset, counter, map)?;
        self.ports(proto).hold(port);
        Some(port)
    }

    /// The description `d` of a session that holds it.
    pub fn find(&self, held: &Held, d: u32) -> Option<usize> {
        self.find_any(held, d).filter(|&i| self.socks[i].hold == 0)
    }

    /// As `find`, and a description of a port too (close, export).
    pub fn find_any(&self, held: &Held, d: u32) -> Option<usize> {
        self.places.find(d).filter(|&i| held.has(i))
    }

    /// A place for a description of the ports of group `group`: no smoltcp socket.
    pub fn hold_place(&mut self, proto: Proto, group: u8) -> Option<usize> {
        if self.places.used() >= SOCKETS_LIMIT {
            return None;
        }
        let i = self.places.allocate(State::Live)?;
        self.socks[i] = Sock {
            proto,
            hold: group,
            ..Sock::EMPTY
        };
        Some(i)
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
                } else if t.recv_queue() > 0 || sock.linger == opt::LINGER_ON {
                    // A close with bytes nobody read resets the connection
                    // (RFC 1122, 4.2.2.13): the peer's next send fails. So
                    // does a close with SO_LINGER on and a time of 0.
                    self.abort_place(stack, i);
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

    /// Bytes that arrive for a stream nobody holds any more (its CLOSE came
    /// first) reset the connection (RFC 1122, 4.2.2.13): the peer's next send
    /// fails at once and not after the window of the orphan has filled.
    pub fn reset_data_after_close(&mut self, stack: &mut Stack<'static>, i: usize) {
        if self.places.state(i) != State::Orphan
            || self.socks[i].rst_pending
            || self.socks[i].proto != Proto::Tcp
        {
            return;
        }
        let Some(handle) = self.socks[i].handle else {
            return;
        };
        let t = stack.tcp(handle);
        if matches!(t.state(), tcp::State::FinWait1 | tcp::State::FinWait2) && t.recv_queue() > 0 {
            self.abort_place(stack, i);
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
        self.leave_queue(i);
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
    /// operations and its descriptions in steps. True when a step of
    /// departure is due.
    pub fn depart(&mut self, stack: &mut Stack<'static>, held: Held, long: LongSession) -> bool {
        if held.count() == 0 && long.is_empty() {
            return false;
        }
        let free = (0..DEPARTING).find(|&n| self.departing_used[n / 64] >> (n % 64) & 1 == 0);
        match free {
            Some(n) => {
                self.departing[n] = held;
                self.departing_long[n] = long;
                self.departing_used[n / 64] |= 1 << (n % 64);
                true
            }
            None => {
                let mut long = long;
                while self.release_ops(&mut long) {}
                let mut held = held;
                while let Some(i) = held.next(0) {
                    held.remove(i);
                    self.release(stack, i);
                }
                false
            }
        }
    }

    /// One step of departure: at most ABANDON_PORTION operations of the
    /// sessions that went let go of, then at most GONE_PORTION places, the
    /// descriptions of those sessions and the members of the queues of closed
    /// listening descriptions. True when more are left.
    pub fn depart_step(&mut self, stack: &mut Stack<'static>) -> bool {
        // One shared buffer of a session that went is unmapped first.
        let buffers_left = self.unmap_retired();
        let mut ops_left = netd::ring::ABANDON_PORTION;
        'operations: for word in 0..self.departing_used.len() {
            let mut bits = self.departing_used[word];
            while bits != 0 {
                if ops_left == 0 {
                    break 'operations;
                }
                let n = word * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let mut long = core::mem::take(&mut self.departing_long[n]);
                while ops_left > 0 && !long.is_empty() {
                    let Some(key) = self.ops.first(&long) else {
                        break;
                    };
                    if let Some(idx) = op_index(key) {
                        self.forget_op(idx);
                    }
                    self.ops.gone_some(&mut long, 1);
                    ops_left -= 1;
                }
                self.departing_long[n] = long;
            }
        }
        let mut left = GONE_PORTION;
        'entries: for word in 0..self.departing_used.len() {
            while self.departing_used[word] != 0 {
                if left == 0 {
                    break 'entries;
                }
                let n = word * 64 + self.departing_used[word].trailing_zeros() as usize;
                if !self.departing_long[n].is_empty() {
                    // Its operations are not all let go of: the places wait.
                    break 'entries;
                }
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
        let sets_left = self.interest.depart_step();
        self.departing_used.iter().any(|&w| w != 0)
            || buffers_left
            || self.release_queue.next(0).is_some()
            || sets_left
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
        // A stream that was open and closed with no FIN of the peer and no
        // shutdown of ours was reset: a deferred error, once (`SO_ERROR`).
        let s = &mut self.socks[i];
        if s.conn == Conn::Done
            && state == tcp::State::Closed
            && !s.saw_fin
            && !s.shut_wr
            && s.error == 0
        {
            s.error = proto_net::RESET;
            self.interest.changed(i);
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
                    self.rechain(i);
                    self.connecting.clear(i);
                }
                _ => {
                    t.set_timeout(None);
                    if self.socks[i].keepalive {
                        t.set_keep_alive(Some(duration(KEEPALIVE_NS)));
                    }
                    self.socks[i].conn = Conn::Done;
                    self.rechain(i);
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
                    if !t.may_recv() {
                        ev |= RDHUP;
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
        self.timed &= !bit;
        self.expired &= !bit;
        self.lingered &= !bit;
        if info.kind == Kind::Epoll {
            self.interest.remove_waiter(usize::from(info.place), idx);
        } else if info.kind == Kind::Watch {
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
        self.due.set(i / GROUP);
        self.touched.set(i / GROUP);
    }

    /// Every group has work: an address changed or a neighbour answered.
    pub fn touch_all(&mut self) {
        self.due.set_below(GROUPS);
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
                // A new SYN on the four of a stream that no session holds and
                // that is in TIME-WAIT or closed (and waits for the sweep to
                // free it) ends that stream and goes to the listening description
                // as any other (RFC 1122, 4.2.2.13 allows a new connection on
                // the four when its sequence number is higher; smoltcp does
                // not give the service the next number the orphan expects, so
                // any SYN does). The orphan is let go of only when a socket of
                // a queue takes the SYN.
                let existing = self.demux.find(&conn);
                let orphan = match existing {
                    Some(place) if syn && self.reusable_orphan(stack, place) => Some(place),
                    Some(place) => return Some(place),
                    None => None,
                };
                if !syn {
                    return None;
                }
                let lead = [local, [0; 4]].into_iter().find_map(|address| {
                    self.demux.find(&Key::Bound {
                        tcp: true,
                        address,
                        port: local_port,
                    })
                });
                let Some(lead) = lead else {
                    return orphan;
                };
                let Some((member, listener)) = self.pick_member(stack, lead) else {
                    // A queue with no room drops the SYN: the peer sends it
                    // again after its timeout, as it does to a busy server.
                    self.drop_frame = true;
                    self.counters.syn_dropped += 1;
                    return None;
                };
                if let Some(place) = orphan {
                    if self.socks[place]
                        .handle
                        .is_some_and(|h| stack.tcp(h).state() == tcp::State::Closed)
                    {
                        self.counters.orphan_reused += 1;
                    }
                    self.release_place(stack, place);
                }
                self.syn_member = Some((member, listener));
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

    /// Whether place `i` is a stream that no session holds and that is over:
    /// it waits out TIME-WAIT, or it has closed and only waits for the sweep to
    /// free its place (a stream whose peer reset it, or whose last
    /// acknowledgement just came). A new SYN on its four starts a new stream.
    fn reusable_orphan(&self, stack: &mut Stack<'static>, i: usize) -> bool {
        if self.places.state(i) != State::Orphan {
            return false;
        }
        let Some(handle) = self.socks[i].handle else {
            return false;
        };
        let state = stack.tcp(handle).state();
        orphan_is_over(
            state == tcp::State::TimeWait,
            state == tcp::State::Closed,
            self.socks[i].rst_pending,
        )
    }

    /// The first socket of the queue of listening place `listener` that
    /// still listens.
    fn listening_member(&self, stack: &mut Stack<'static>, listener: usize) -> Option<usize> {
        let sock = &self.socks[listener];
        (0..usize::from(sock.member_count))
            .map(|k| usize::from(sock.members[k]))
            .find(|&m| {
                self.socks[m]
                    .handle
                    .is_some_and(|h| stack.tcp(h).state() == tcp::State::Listen)
            })
    }

    /// How long a listening description that has counted no room is believed
    /// before its queue is counted again (a socket of the queue that went back
    /// to LISTEN with a reset is not seen otherwise), in nanoseconds.
    const ROOM_TRUST_NS: u64 = 10_000_000;

    /// The count of the sockets of the queue of `listener` that listen,
    /// counted over the whole queue when it says none and is old. True when
    /// it was counted.
    fn refresh_room(
        socks: &mut [Sock; SOCKETS_MAX],
        stack: &mut Stack<'static>,
        listener: usize,
        now: u64,
    ) -> bool {
        let s = &socks[listener];
        if s.room > 0 || now.saturating_sub(s.room_at) < Self::ROOM_TRUST_NS {
            return false;
        }
        let count = (0..usize::from(s.member_count))
            .filter(|&k| {
                socks[usize::from(s.members[k])]
                    .handle
                    .is_some_and(|h| stack.tcp(h).state() == tcp::State::Listen)
            })
            .count();
        let s = &mut socks[listener];
        s.room = count as u8;
        s.room_at = now;
        true
    }

    /// The listening description whose queue gets the SYN, and the socket of
    /// that queue: of the listening description `lead`, or of the member of
    /// its group the circle comes to that listens and has room. A queue
    /// without room costs no look at its sockets, and at most one queue is
    /// counted again for a SYN.
    fn pick_member(&mut self, stack: &mut Stack<'static>, lead: usize) -> Option<(usize, usize)> {
        let now = now_ns();
        let group = self.socks[lead].group;
        let listener = if group == NO_GROUP {
            Self::refresh_room(&mut self.socks, stack, lead, now);
            (self.socks[lead].room > 0).then_some(lead)
        } else {
            let socks = &mut self.socks;
            let mut counted = false;
            self.groups.pick(usize::from(group), |m| {
                if !socks[m].listening {
                    return false;
                }
                if !counted {
                    counted = Self::refresh_room(socks, stack, m, now);
                }
                socks[m].room > 0
            })
        }?;
        let member = self.listening_member(stack, listener);
        if member.is_none() {
            // The count was behind: none listens.
            let s = &mut self.socks[listener];
            s.room = 0;
            s.room_at = now;
        }
        member.map(|m| (m, listener))
    }

    /// After the stack took a SYN for a listening description: the stack hands
    /// it to the first socket in LISTEN of the set that holds the socket
    /// `route` named. The sets keep the queue sockets of the members of a group
    /// apart (`owners`), so that is a socket of the chosen member's queue;
    /// one of another description is counted in `syn_stray` and still gets the
    /// connection's key. Each socket of a queue in the set that left LISTEN
    /// gets the key of its connection, and one that went back to LISTEN (a
    /// reset) loses it.
    pub fn adopt(&mut self, stack: &mut Stack<'static>) {
        let Some((member, chosen)) = self.syn_member.take() else {
            return;
        };
        let group = member / GROUP;
        for m in group * GROUP..(group + 1) * GROUP {
            if self.socks[m].listener == NO_PLACE {
                continue;
            }
            let Some(handle) = self.socks[m].handle else {
                continue;
            };
            let t = stack.tcp(handle);
            if t.state() == tcp::State::Listen {
                if let Some(key) = self.socks[m].key.take() {
                    self.demux.remove(&key);
                    let queue = usize::from(self.socks[m].listener);
                    self.socks[queue].room = self.socks[queue].room.saturating_add(1);
                }
            } else if self.socks[m].key.is_none()
                && let (Some(local), Some(remote)) = (t.local_endpoint(), t.remote_endpoint())
            {
                let (local, remote) = (peer_of(local), peer_of(remote));
                let queue = usize::from(self.socks[m].listener);
                if queue != chosen {
                    // The sets keep the queues of the members apart, so this
                    // is a fault of the placing.
                    self.counters.syn_stray += 1;
                    if self.counters.syn_stray == 1 {
                        rt::println!(
                            "netd: syn_stray: a SYN went to a queue other than the chosen one"
                        );
                    }
                }
                self.socks[queue].room = self.socks[queue].room.saturating_sub(1);
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
        let passed = self.passed.take();
        if self.rst_wait.next(0).is_some() {
            let mut at = 0;
            while let Some(g) = passed.next(at) {
                at = g + 1;
                if (g * GROUP..(g + 1) * GROUP).any(|i| self.rst_wait.has(i)) {
                    self.cleanup_wanted = true;
                    break;
                }
            }
        }
        // At most SCHEDULE_GROUPS groups in a step: a burst of requests touches
        // every group, and the walk over all of them in one step took 13 500
        // ticks at 1 280 places. The rest wait for the next step.
        let mut left = SCHEDULE_GROUPS;
        while let Some(g) = self.touched.next_wrapping(self.schedule_cursor) {
            if left == 0 {
                self.step_due = true;
                break;
            }
            left -= 1;
            self.schedule_cursor = g + 1;
            self.touched.clear(g);
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
        self.wake_due.next(0).is_some() || self.closed_ops != 0 || self.interest.due != 0
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
            if self.interest.watched(i) {
                // Each record on the place is a check of the step.
                if !budget.take_checks(self.interest.on_place(i)) {
                    self.wake_cursor = i;
                    break;
                }
                self.interest.scan(i, ev);
            }
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
                    Kind::Epoll => false,
                    Kind::Linger => self.linger_done(stack, i),
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
            if self.socks[i].waiters == 0 && !self.interest.watched(i) {
                self.attention.clear(i);
            }
            self.wake_due.clear(i);
            if at >= SOCKETS_MAX {
                at = 0;
            }
        }
        self.tell_sets(&mut budget);
        self.wake_pending()
    }

    /// Whether the data a `close` waits for is acknowledged: the stream is past
    /// FIN-WAIT-1 and the closing states that wait for the ACK of our FIN.
    pub fn linger_done(&self, stack: &mut Stack<'static>, i: usize) -> bool {
        self.socks[i].handle.is_none_or(|h| {
            matches!(
                stack.tcp(h).state(),
                tcp::State::FinWait2 | tcp::State::TimeWait | tcp::State::Closed
            )
        })
    }

    /// The operations with a time limit that ran out are told, a few in each
    /// step of waking (by the mask of the operations whose description closed,
    /// which that step tells within its share).
    pub fn expire(&mut self, now: u64) {
        let mut mask = self.timed & !self.expired;
        while mask != 0 {
            let idx = mask.trailing_zeros() as usize;
            let bit = 1u128 << idx;
            mask &= mask - 1;
            if self.op_deadline[idx] <= now {
                self.expired |= bit;
                self.closed_ops |= bit;
                self.wake_wanted = true;
            }
        }
    }

    /// The nearest time limit of the operations that wait, in nanoseconds.
    pub fn next_deadline(&self) -> Option<u64> {
        let mut mask = self.timed & !self.expired;
        let mut next: Option<u64> = None;
        while mask != 0 {
            let idx = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            let at = self.op_deadline[idx];
            next = Some(next.map_or(at, |n| n.min(at)));
        }
        next
    }

    /// The sets with ready records whose waiting operations are told, within
    /// the notifications the step has left. A set whose operations are all
    /// told (or that has none) is not due any more.
    fn tell_sets(&mut self, budget: &mut WakeBudget) {
        while self.interest.due != 0 {
            let k = self.interest.due.trailing_zeros() as usize;
            let mut mask = self.interest.waiters(k);
            while mask != 0 {
                let idx = mask.trailing_zeros() as usize;
                let bit = 1u128 << idx;
                mask &= mask - 1;
                if self.told & bit != 0 {
                    continue;
                }
                let info = self.info[idx];
                if !self.ops.waits(info.label, info.key) {
                    self.interest.remove_waiter(k, idx);
                    continue;
                }
                if !budget.take_tell() {
                    return;
                }
                self.told |= bit;
                #[cfg(feature = "probe")]
                if self.in_request {
                    rt::println!("net: tell from a request");
                }
                self.ops.tell(info.label, info.key);
            }
            self.interest.due &= !(1 << k);
        }
    }

    /// Whether the records of the interest sets look at place `i` or at the
    /// listening description a socket of its queue belongs to.
    pub fn watched_by_frames(&self, i: usize) -> bool {
        if self.interest.is_empty() {
            return false;
        }
        let listener = usize::from(self.socks[i].listener);
        self.interest.watched(i)
            || (listener != usize::from(NO_PLACE) && self.interest.watched(listener))
    }

    /// What a frame may change in place `i` for the records by edge: the
    /// state of a stream and the bytes it holds for reading.
    pub fn frame_mark(&self, stack: &mut Stack<'static>, i: usize) -> (u8, usize) {
        match (self.socks[i].proto, self.socks[i].handle) {
            (Proto::Tcp, Some(h)) => {
                let t = stack.tcp(h);
                (t.state() as u8, t.recv_queue())
            }
            _ => (0, 0),
        }
    }

    /// A frame came for place `i` that held `before` and holds `after`: new
    /// bytes or a new state are a change for the records of the place and of
    /// the listening description a socket of its queue belongs to. A frame
    /// of acknowledgements alone changes nothing: a datagram always does.
    pub fn arrived(&mut self, i: usize, before: (u8, usize), after: (u8, usize)) {
        if self.socks[i].proto == Proto::Tcp && before.0 == after.0 && after.1 <= before.1 {
            return;
        }
        self.interest.changed(i);
        let listener = usize::from(self.socks[i].listener);
        if listener != usize::from(NO_PLACE) {
            self.interest.changed(listener);
        }
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
            opt::RCVBUF | opt::SNDBUF => buffer_of(i) as u32,
            opt::ACCEPTCONN => u32::from(s.listening),
            opt::DOMAIN => INET,
            opt::KEEPALIVE => u32::from(s.keepalive),
            opt::BROADCAST => u32::from(s.broadcast),
            opt::NODELAY => u32::from(s.nodelay),
            opt::NONBLOCK => u32::from(s.nonblock),
            opt::REUSEPORT if s.proto == Proto::Tcp => u32::from(s.reuseport),
            opt::LINGER => s.linger,
            opt::RCVTIMEO => s.rcvtimeo,
            opt::SNDTIMEO => s.sndtimeo,
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
