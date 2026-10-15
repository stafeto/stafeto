// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The sockets of the service (Ф9): AF_UNIX and the loopback of AF_INET,
//! streams and datagrams. A socket is a description of the third kind
//! (`SOCK_END | slot`) with a buffer of RING bytes for what it receives.
//! Two connected streams point at each other (a slot and its generation);
//! what a socket sends goes into the buffer of its peer, so the data of a
//! closed peer is gone and the one that is left reads the end of the data
//! after what the buffer holds. A datagram is a record in the receiver's
//! buffer with the sender's address; a datagram socket finds its receiver by
//! the port or the file node of its address. Every socket has one list of
//! operations that wait; any change wakes the list of the peer.
//! Descriptions sent as SCM_RIGHTS stay referenced by the message
//! (`Anc`) until they are received or the socket that holds them goes; a
//! socket that goes gives its messages' references to `limbo`, which `step`
//! lets go of one at a time. Every operation is O(1) or bounded by
//! SOCKETS, FDS_MAX or the size of one message.

use super::*;
use proto_pipe::ipc::MQ_KIND;
use proto_pipe::sock::{
    ADDR_INET, ADDR_MAX, ADDR_NONE, ADDR_UNIX, Addr, BACKLOG_MAX, BAD_TYPE, CONNECTED, DGRAM,
    DONTWAIT, FDS_MAX, IN_USE, INET, NO_BUFFERS, NO_DESTINATION, NO_FAMILY, NO_OPTION,
    NOT_CONNECTED, NOT_SOCKET, NOT_SUPPORTED, OOB, OPT_ACCEPTCONN, OPT_ATMARK, OPT_BROADCAST,
    OPT_DOMAIN, OPT_ERROR, OPT_KEEPALIVE, OPT_RCVBUF, OPT_REUSEADDR, OPT_SNDBUF, OPT_TYPE,
    OUT_CTRUNC, OUT_TRUNC, PEEK, REFUSED, RING, SEND_MAX, STREAM, TOO_BIG, TOO_MANY_REFS, UNIX,
};
use proto_wire::{Reader, Writer};

/// The live sockets one session made at most.
pub const SOCK_CREATED_MAX: usize = 20;
/// The live sockets one root has at most, a pending connection among them.
pub const ROOT_SOCKS: usize = 28;
/// The messages with descriptions one socket holds at most.
const ANC_MAX: usize = 4;
/// The descriptions in flight in the service at most.
pub const INFLIGHT_MAX: usize = 64;
/// The first and the number of the ports `bind` gives for port 0.
const PORT_FIRST: u32 = 49152;
const PORT_COUNT: u32 = 16384;
/// A write of this many bytes or fewer goes whole or waits, as a pipe's.
const ATOMIC_SEND: usize = ATOMIC;

/// The descriptions a message carries and where in the receiver's stream
/// (the count of bytes before, or of datagrams) they belong.
#[derive(Clone, Copy)]
struct Anc {
    at: u32,
    n: u8,
    ids: [u32; FDS_MAX],
}

impl Anc {
    const NONE: Anc = Anc {
        at: 0,
        n: 0,
        ids: [0; FDS_MAX],
    };
}

#[derive(Clone, Copy)]
pub(super) struct Sock {
    live: bool,
    era: u32,
    /// The sessions that hold it, the connections that wait for an accept,
    /// and the messages in flight.
    pub(super) refs: u16,
    nonblock: bool,
    domain: u32,
    kind: u32,
    reuse: bool,
    keepalive: bool,
    broadcast: bool,
    rcvbuf: u32,
    sndbuf: u32,
    creator: u64,
    root: u64,
    waiters: End,
    bound: bool,
    local: Addr,
    peer_addr: Addr,
    listening: bool,
    backlog: u8,
    queue: [u8; BACKLOG_MAX],
    queued: u8,
    peer: Option<(u8, u32)>,
    /// Connected once (a stream) or with a default destination (datagrams).
    connected: bool,
    /// The peer sends no more (it shut its writing or went).
    rx_eof: bool,
    /// The peer receives no more (it shut its reading or went).
    tx_broken: bool,
    rd_shut: bool,
    wr_shut: bool,
    head: u16,
    len: u16,
    /// The bytes (a stream) or datagrams received and sent up to now.
    rx_total: u32,
    tx_total: u32,
    anc: [Anc; ANC_MAX],
    anc_len: u8,
    /// An out-of-band byte of the peer, taken by a receive with OOB, and
    /// where in the stream (the bytes received before it) its mark is.
    oob: bool,
    oob_byte: u8,
    oob_at: u32,
    /// How many messages in flight carry this socket.
    flying: u16,
}

impl Sock {
    const FREE: Sock = Sock {
        live: false,
        era: 0,
        refs: 0,
        nonblock: false,
        domain: 0,
        kind: 0,
        reuse: false,
        keepalive: false,
        broadcast: false,
        rcvbuf: RING as u32,
        sndbuf: RING as u32,
        creator: 0,
        root: 0,
        waiters: End::NONE,
        bound: false,
        local: Addr::NONE,
        peer_addr: Addr::NONE,
        listening: false,
        backlog: 0,
        queue: [0; BACKLOG_MAX],
        queued: 0,
        peer: None,
        connected: false,
        rx_eof: false,
        tx_broken: false,
        rd_shut: false,
        wr_shut: false,
        head: 0,
        len: 0,
        rx_total: 0,
        tx_total: 0,
        anc: [Anc::NONE; ANC_MAX],
        anc_len: 0,
        oob: false,
        oob_byte: 0,
        oob_at: 0,
        flying: 0,
    };
}

/// The sockets, their buffers and the work left after sessions went.
pub struct Sockets {
    pub(super) s: [Sock; SOCKETS],
    rings: [[u8; RING]; SOCKETS],
    pub(super) dropping: [u16; SOCKETS],
    pub(super) dirty: u64,
    /// The descriptions of messages whose socket went, to let go of.
    limbo: [u32; INFLIGHT_MAX],
    limbo_len: usize,
    inflight: usize,
    port: u32,
}

impl Sockets {
    pub const fn new() -> Self {
        Self {
            s: [Sock::FREE; SOCKETS],
            rings: [[0; RING]; SOCKETS],
            dropping: [0; SOCKETS],
            dirty: 0,
            limbo: [0; INFLIGHT_MAX],
            limbo_len: 0,
            inflight: 0,
            port: 0,
        }
    }

    /// Whether `step` has work.
    pub fn due(&self) -> bool {
        self.dirty != 0 || self.limbo_len != 0
    }

    /// The operations that wait at the queue `queue` (DESCRIPTIONS + slot).
    pub(super) fn queue(&mut self, queue: u32) -> Result<&mut End, u32> {
        let slot = (queue as usize)
            .checked_sub(DESCRIPTIONS)
            .filter(|&slot| slot < SOCKETS)
            .ok_or(BAD_FD)?;
        let s = &mut self.s[slot];
        if !s.live {
            return Err(BAD_FD);
        }
        Ok(&mut s.waiters)
    }

    fn peer_of(&self, i: usize) -> Option<usize> {
        let (p, era) = self.s[i].peer?;
        let p = usize::from(p);
        (self.s[p].live && self.s[p].era == era).then_some(p)
    }

    fn room(&self, i: usize) -> usize {
        RING - usize::from(self.s[i].len)
    }

    /// `out.len()` bytes of the buffer of `i` from `offset` after its head.
    fn peek(&self, i: usize, offset: usize, out: &mut [u8]) {
        let start = (usize::from(self.s[i].head) + offset) % RING;
        let first = out.len().min(RING - start);
        out[..first].copy_from_slice(&self.rings[i][start..start + first]);
        let rest = out.len() - first;
        out[first..].copy_from_slice(&self.rings[i][..rest]);
    }

    /// `bytes` at the tail of the buffer of `i`; the room was checked.
    fn put(&mut self, i: usize, bytes: &[u8]) {
        let tail = (usize::from(self.s[i].head) + usize::from(self.s[i].len)) % RING;
        let first = bytes.len().min(RING - tail);
        self.rings[i][tail..tail + first].copy_from_slice(&bytes[..first]);
        self.rings[i][..bytes.len() - first].copy_from_slice(&bytes[first..]);
        self.s[i].len += bytes.len() as u16;
    }

    fn drop_front(&mut self, i: usize, n: usize) {
        let s = &mut self.s[i];
        s.head = ((usize::from(s.head) + n) % RING) as u16;
        s.len -= n as u16;
    }

    /// The message `anc` is out of flight.
    fn unfly(&mut self, anc: &Anc) {
        for &id in &anc.ids[..usize::from(anc.n)] {
            if id & SOCK_END != 0 {
                let s = &mut self.s[(id & !SOCK_END) as usize];
                s.flying = s.flying.saturating_sub(1);
            }
        }
    }

    fn anc_pop(&mut self, i: usize) -> Anc {
        let s = &mut self.s[i];
        let first = s.anc[0];
        s.anc.copy_within(1.., 0);
        s.anc_len -= 1;
        s.anc[usize::from(s.anc_len)] = Anc::NONE;
        first
    }

    fn limbo_push(&mut self, id: u32) {
        debug_assert!(self.limbo_len < INFLIGHT_MAX);
        if self.limbo_len < INFLIGHT_MAX {
            self.limbo[self.limbo_len] = id;
            self.limbo_len += 1;
        }
    }
}

impl Default for Sockets {
    fn default() -> Self {
        Self::new()
    }
}

/// What a receive gives besides the bytes it copied into the caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvOut {
    pub n: usize,
    pub flags: u32,
    pub fds: [u32; FDS_MAX],
    pub nfds: usize,
    pub from: Addr,
}

impl RecvOut {
    const fn new(n: usize) -> Self {
        Self {
            n,
            flags: 0,
            fds: [0; FDS_MAX],
            nfds: 0,
            from: Addr::NONE,
        }
    }
}

impl Pipes {
    /// The slot of the description of the third kind `endpoint`, which
    /// `held` holds: a socket or an open message queue.
    pub(super) fn desc_slot(&self, held: &Held, endpoint: Endpoint) -> Result<usize, u32> {
        if !endpoint.is_sock() || !held.holds(endpoint.id) {
            return Err(BAD_FD);
        }
        let slot = endpoint.slot();
        if !self.sockets.s[slot].live {
            return Err(BAD_FD);
        }
        Ok(slot)
    }

    /// The slot of the socket `endpoint`, which `held` holds: NOT_SOCKET for
    /// an open message queue.
    pub(super) fn sock_slot(&self, held: &Held, endpoint: Endpoint) -> Result<usize, u32> {
        let slot = self.desc_slot(held, endpoint)?;
        if self.sockets.s[slot].kind == MQ_KIND {
            return Err(NOT_SOCKET);
        }
        Ok(slot)
    }

    /// A description for an open message queue `queue` (its slot and era
    /// in the table of queues) with the access `access` (0 read, 1 write,
    /// 2 both). The limits are a socket's.
    pub(super) fn mq_alloc(
        &mut self,
        held: &mut Held,
        creator: u64,
        root: u64,
        nonblock: bool,
        access: u32,
        queue: (u8, u32),
    ) -> Result<u32, u32> {
        if held.count() + 1 > HELD_MAX
            || self.live_socks(|s| s.creator == creator && s.refs != 0) >= SOCK_CREATED_MAX
        {
            return Err(MFILE);
        }
        if self.live_socks(|s| s.root == root) >= ROOT_SOCKS {
            return Err(NFILE);
        }
        let i = self.sockets.s.iter().position(|s| !s.live).ok_or(NFILE)?;
        let era = self.sockets.s[i].era.wrapping_add(1);
        self.sockets.s[i] = Sock {
            live: true,
            era,
            refs: 1,
            nonblock,
            domain: access,
            kind: MQ_KIND,
            creator,
            root,
            peer: Some(queue),
            ..Sock::FREE
        };
        self.sockets.dropping[i] = 0;
        let id = SOCK_END | i as u32;
        held.add(id as usize);
        Ok(id)
    }

    /// The open message queue `endpoint` names: its description's slot, its
    /// queue (slot and era), its access and its NONBLOCK.
    pub(super) fn mq_slot(
        &self,
        held: &Held,
        endpoint: Endpoint,
    ) -> Result<(usize, (u8, u32), u32, bool), u32> {
        let i = self.desc_slot(held, endpoint)?;
        let s = &self.sockets.s[i];
        match s.peer {
            Some(queue) if s.kind == MQ_KIND => Ok((i, queue, s.domain, s.nonblock)),
            _ => Err(BAD_FD),
        }
    }

    pub(super) fn mq_set_nonblock(&mut self, i: usize, nonblock: bool) {
        self.sockets.s[i].nonblock = nonblock;
    }

    fn live_socks(&self, f: impl Fn(&Sock) -> bool) -> usize {
        self.sockets.s.iter().filter(|s| s.live && f(s)).count()
    }

    fn sock_alloc(
        &mut self,
        creator: u64,
        root: u64,
        domain: u32,
        kind: u32,
        nonblock: bool,
    ) -> Result<usize, u32> {
        if !(domain == UNIX || domain == INET) {
            return Err(NO_FAMILY);
        }
        if !(kind == STREAM || kind == DGRAM) {
            return Err(INVALID);
        }
        if self.live_socks(|s| s.root == root) >= ROOT_SOCKS {
            return Err(NFILE);
        }
        let i = self.sockets.s.iter().position(|s| !s.live).ok_or(NFILE)?;
        let era = self.sockets.s[i].era.wrapping_add(1);
        self.sockets.s[i] = Sock {
            live: true,
            era,
            refs: 1,
            nonblock,
            domain,
            kind,
            creator,
            root,
            ..Sock::FREE
        };
        self.sockets.dropping[i] = 0;
        Ok(i)
    }

    /// CREATE of a socket: its description number.
    pub fn sock_create(
        &mut self,
        held: &mut Held,
        creator: u64,
        root: u64,
        domain: u32,
        kind: u32,
        flags: u32,
    ) -> Result<u32, u32> {
        if flags & !NONBLOCK != 0 {
            return Err(INVALID);
        }
        if held.count() + 1 > HELD_MAX
            || self.live_socks(|s| s.creator == creator && s.refs != 0) >= SOCK_CREATED_MAX
        {
            return Err(MFILE);
        }
        let i = self.sock_alloc(creator, root, domain, kind, flags & NONBLOCK != 0)?;
        let id = SOCK_END | i as u32;
        held.add(id as usize);
        Ok(id)
    }

    /// A connected pair of sockets of AF_UNIX.
    pub fn sock_pair(
        &mut self,
        held: &mut Held,
        creator: u64,
        root: u64,
        domain: u32,
        kind: u32,
        flags: u32,
    ) -> Result<(u32, u32), u32> {
        if domain != UNIX {
            return Err(NOT_SUPPORTED);
        }
        if flags & !NONBLOCK != 0 {
            return Err(INVALID);
        }
        if held.count() + 2 > HELD_MAX
            || self.live_socks(|s| s.creator == creator && s.refs != 0) + 2 > SOCK_CREATED_MAX
        {
            return Err(MFILE);
        }
        if self.live_socks(|s| s.root == root) + 2 > ROOT_SOCKS {
            return Err(NFILE);
        }
        let a = self.sock_alloc(creator, root, domain, kind, flags & NONBLOCK != 0)?;
        let b = match self.sock_alloc(creator, root, domain, kind, flags & NONBLOCK != 0) {
            Ok(b) => b,
            Err(code) => {
                self.sockets.s[a] = Sock {
                    era: self.sockets.s[a].era,
                    ..Sock::FREE
                };
                return Err(code);
            }
        };
        self.link(a, b);
        self.link(b, a);
        for i in [a, b] {
            held.add((SOCK_END | i as u32) as usize);
        }
        Ok((SOCK_END | a as u32, SOCK_END | b as u32))
    }

    fn link(&mut self, a: usize, b: usize) {
        let era = self.sockets.s[b].era;
        let s = &mut self.sockets.s[a];
        s.peer = Some((b as u8, era));
        s.connected = true;
    }

    /// A port no socket of the same kind has, or None after a few tries.
    fn free_port(&mut self, kind: u32) -> Option<u16> {
        for _ in 0..4 {
            let port = PORT_FIRST + self.sockets.port % PORT_COUNT;
            self.sockets.port = self.sockets.port.wrapping_add(1);
            if !self.port_used(kind, port as u16) {
                return Some(port as u16);
            }
        }
        None
    }

    fn port_used(&self, kind: u32, port: u16) -> bool {
        self.sockets.s.iter().any(|s| {
            s.live && s.domain == INET && s.kind == kind && s.bound && s.local.port == port
        })
    }

    fn autobind(&mut self, i: usize) -> Result<(), u32> {
        let s = &self.sockets.s[i];
        if s.bound || s.domain != INET {
            return Ok(());
        }
        let port = self.free_port(s.kind).ok_or(IN_USE)?;
        let s = &mut self.sockets.s[i];
        s.local = Addr::inet(port);
        s.bound = true;
        Ok(())
    }

    /// Whether `addr` is of the family of socket `i`.
    fn family_ok(&self, i: usize, addr: &Addr) -> bool {
        match self.sockets.s[i].domain {
            INET => addr.kind == ADDR_INET,
            _ => addr.kind == ADDR_UNIX,
        }
    }

    pub fn sock_bind(&mut self, held: &Held, endpoint: Endpoint, addr: Addr) -> Result<(), u32> {
        let i = self.sock_slot(held, endpoint)?;
        if self.sockets.s[i].bound || self.sockets.s[i].listening {
            return Err(INVALID);
        }
        if !self.family_ok(i, &addr) {
            return Err(NO_FAMILY);
        }
        let kind = self.sockets.s[i].kind;
        if addr.kind == ADDR_INET {
            if addr.port == 0 {
                return self.autobind(i);
            }
            if self.port_used(kind, addr.port) {
                return Err(IN_USE);
            }
        } else {
            if addr.node == 0 {
                return Err(INVALID);
            }
            // A node that a socket of the past still names was made anew:
            // the old binding is stale.
            for j in 0..SOCKETS {
                let o = &mut self.sockets.s[j];
                if j != i && o.live && o.domain == UNIX && o.bound && o.local.node == addr.node {
                    o.bound = false;
                    o.local = Addr::NONE;
                }
            }
        }
        let s = &mut self.sockets.s[i];
        s.local = addr;
        s.bound = true;
        Ok(())
    }

    pub fn sock_listen(
        &mut self,
        held: &Held,
        endpoint: Endpoint,
        backlog: u32,
    ) -> Result<(), u32> {
        let i = self.sock_slot(held, endpoint)?;
        let s = &self.sockets.s[i];
        if s.kind != STREAM {
            return Err(NOT_SUPPORTED);
        }
        if s.connected {
            return Err(INVALID);
        }
        if !s.bound {
            if s.domain == INET {
                self.autobind(i)?;
            } else {
                return Err(INVALID);
            }
        }
        let s = &mut self.sockets.s[i];
        s.listening = true;
        s.backlog = backlog.clamp(1, BACKLOG_MAX as u32) as u8;
        Ok(())
    }

    /// The socket `addr` names for a socket `i` of the kind `kind`.
    fn lookup(&self, i: usize, addr: &Addr) -> Option<usize> {
        let (domain, kind) = (self.sockets.s[i].domain, self.sockets.s[i].kind);
        (0..SOCKETS).find(|&j| {
            let o = &self.sockets.s[j];
            o.live
                && o.bound
                && o.domain == domain
                && o.kind == kind
                && match domain {
                    INET => o.local.port == addr.port,
                    _ => o.local.node == addr.node,
                }
        })
    }

    /// The socket `addr` names, bound for socket `i`'s kind: REFUSED for
    /// none, and for a file node that a socket of the other kind has, the
    /// mismatch of types.
    fn find(&self, i: usize, addr: &Addr) -> Result<usize, u32> {
        if let Some(t) = self.lookup(i, addr) {
            return Ok(t);
        }
        if self.sockets.s[i].domain == UNIX
            && self
                .sockets
                .s
                .iter()
                .any(|o| o.live && o.bound && o.domain == UNIX && o.local.node == addr.node)
        {
            return Err(BAD_TYPE);
        }
        Err(REFUSED)
    }

    pub fn sock_connect(
        &mut self,
        held: &Held,
        endpoint: Endpoint,
        addr: Addr,
        wakes: &mut Wakes,
    ) -> Result<(), u32> {
        let i = self.sock_slot(held, endpoint)?;
        if self.sockets.s[i].kind == DGRAM {
            return self.dgram_connect(i, addr);
        }
        let s = &self.sockets.s[i];
        if s.connected {
            return Err(CONNECTED);
        }
        if s.listening {
            return Err(INVALID);
        }
        if !self.family_ok(i, &addr) {
            return Err(NO_FAMILY);
        }
        let l = self.find(i, &addr)?;
        if !self.sockets.s[l].listening || self.sockets.s[l].queued >= self.sockets.s[l].backlog {
            return Err(REFUSED);
        }
        self.autobind(i)?;
        let (domain, root) = (self.sockets.s[i].domain, self.sockets.s[i].root);
        let server = self.sock_alloc(0, root, domain, STREAM, false)?;
        let local = self.sockets.s[l].local;
        let from = self.sockets.s[i].local;
        {
            let t = &mut self.sockets.s[server];
            t.bound = true;
            t.local = local;
            t.peer_addr = from;
        }
        self.link(i, server);
        self.link(server, i);
        self.sockets.s[i].peer_addr = local;
        let n = usize::from(self.sockets.s[l].queued);
        self.sockets.s[l].queue[n] = server as u8;
        self.sockets.s[l].queued += 1;
        wakes.add(self.sockets.s[l].waiters.waiters);
        Ok(())
    }

    fn dgram_connect(&mut self, i: usize, addr: Addr) -> Result<(), u32> {
        if addr.kind == ADDR_NONE {
            let s = &mut self.sockets.s[i];
            s.peer = None;
            s.connected = false;
            s.peer_addr = Addr::NONE;
            return Ok(());
        }
        if !self.family_ok(i, &addr) {
            return Err(NO_FAMILY);
        }
        let t = self.find(i, &addr)?;
        self.autobind(i)?;
        self.link(i, t);
        self.sockets.s[i].peer_addr = self.sockets.s[t].local;
        Ok(())
    }

    /// ACCEPT: the next connection of the listening socket, now a socket of
    /// the session `held`; None to wait.
    pub fn sock_accept(
        &mut self,
        held: &mut Held,
        endpoint: Endpoint,
        creator: u64,
        root: u64,
    ) -> Result<Option<(u32, Addr)>, u32> {
        let i = self.sock_slot(held, endpoint)?;
        let s = &self.sockets.s[i];
        if !s.listening {
            return Err(INVALID);
        }
        if s.queued == 0 {
            return if s.nonblock { Err(AGAIN) } else { Ok(None) };
        }
        if held.count() + 1 > HELD_MAX
            || self.live_socks(|o| o.creator == creator && o.refs != 0) >= SOCK_CREATED_MAX
        {
            return Err(MFILE);
        }
        let t = usize::from(s.queue[0]);
        let s = &mut self.sockets.s[i];
        s.queue.copy_within(1.., 0);
        s.queued -= 1;
        let n = usize::from(s.queued);
        s.queue[n] = 0;
        let peer_addr = {
            let t = &mut self.sockets.s[t];
            t.creator = creator;
            t.root = root;
            t.peer_addr
        };
        let id = SOCK_END | t as u32;
        held.add(id as usize);
        Ok(Some((id, peer_addr)))
    }

    pub fn sock_shutdown(
        &mut self,
        held: &Held,
        endpoint: Endpoint,
        how: u32,
        wakes: &mut Wakes,
    ) -> Result<(), u32> {
        let i = self.sock_slot(held, endpoint)?;
        if how > 2 {
            return Err(INVALID);
        }
        if !self.sockets.s[i].connected {
            return Err(NOT_CONNECTED);
        }
        let peer = self.sockets.peer_of(i);
        if how != 0 {
            self.sockets.s[i].wr_shut = true;
            if let Some(p) = peer {
                self.sockets.s[p].rx_eof = true;
                wakes.add(self.sockets.s[p].waiters.waiters);
            }
        }
        if how != 1 {
            self.sockets.s[i].rd_shut = true;
            if let Some(p) = peer {
                self.sockets.s[p].tx_broken = true;
                wakes.add(self.sockets.s[p].waiters.waiters);
            }
            wakes.add(self.sockets.s[i].waiters.waiters);
        }
        Ok(())
    }

    /// The address of the socket (`peer` false) or of its peer.
    pub fn sock_name(&self, held: &Held, endpoint: Endpoint, peer: bool) -> Result<Addr, u32> {
        let i = self.sock_slot(held, endpoint)?;
        let s = &self.sockets.s[i];
        if !peer {
            return Ok(s.local);
        }
        if !s.connected {
            return Err(NOT_CONNECTED);
        }
        Ok(s.peer_addr)
    }

    pub fn sock_option(
        &mut self,
        held: &Held,
        endpoint: Endpoint,
        option: u32,
        set: bool,
        value: u32,
    ) -> Result<u32, u32> {
        let i = self.sock_slot(held, endpoint)?;
        let s = &mut self.sockets.s[i];
        let flag = |on: &mut bool| {
            if set {
                *on = value != 0;
            }
            u32::from(*on)
        };
        let size = |size: &mut u32| {
            if set {
                *size = value.clamp(256, RING as u32);
            }
            *size
        };
        match option {
            OPT_REUSEADDR => Ok(flag(&mut s.reuse)),
            OPT_KEEPALIVE => Ok(flag(&mut s.keepalive)),
            OPT_BROADCAST => Ok(flag(&mut s.broadcast)),
            OPT_RCVBUF => Ok(size(&mut s.rcvbuf)),
            OPT_SNDBUF => Ok(size(&mut s.sndbuf)),
            OPT_TYPE | OPT_ERROR | OPT_ACCEPTCONN | OPT_DOMAIN | OPT_ATMARK if set => {
                Err(NO_OPTION)
            }
            OPT_TYPE => Ok(s.kind),
            OPT_ERROR => Ok(0),
            OPT_ACCEPTCONN => Ok(u32::from(s.listening)),
            OPT_ATMARK => Ok(u32::from(s.oob && s.oob_at == s.rx_total)),
            OPT_DOMAIN => Ok(s.domain),
            _ => Err(NO_OPTION),
        }
    }

    /// The descriptions `ids` of `held` that can travel: pipe ends and
    /// sockets the session holds.
    fn travelers(&self, held: &Held, ids: &[u32]) -> Result<(), u32> {
        for &id in ids {
            if id & NAMED_END != 0 {
                return Err(NOT_SUPPORTED);
            }
            if !held.holds(id) {
                return Err(BAD_FD);
            }
        }
        Ok(())
    }

    fn desc_ref(&mut self, id: u32) {
        if id & SOCK_END != 0 {
            self.sockets.s[(id & !SOCK_END) as usize].refs += 1;
        } else {
            let (index, write) = proto_pipe::end_of(id);
            self.pipes[index].ends[write as usize].refs += 1;
        }
    }

    fn desc_unref(&mut self, id: u32, wakes: &mut Wakes) {
        let mut mine = Wakes::default();
        if id & SOCK_END != 0 {
            self.sock_unref((id & !SOCK_END) as usize, 1, &mut mine);
        } else {
            self.unref(id as usize, 1, &mut mine);
        }
        wakes.merge(&mine);
    }

    /// SEND: the bytes put (None to wait), the descriptions of `fds` and the
    /// destination `to` (NONE for the connected peer).
    #[allow(clippy::too_many_arguments)]
    pub fn sock_send(
        &mut self,
        held: &Held,
        endpoint: Endpoint,
        flags: u32,
        fds: &[u32],
        to: &Addr,
        bytes: &[u8],
        wakes: &mut Wakes,
    ) -> Result<Option<usize>, u32> {
        let i = self.sock_slot(held, endpoint)?;
        let nonblock = self.sockets.s[i].nonblock || flags & DONTWAIT != 0;
        if self.sockets.s[i].kind == DGRAM && bytes.len() > SEND_MAX {
            return Err(TOO_BIG);
        }
        if !fds.is_empty() {
            if self.sockets.s[i].domain != UNIX {
                return Err(NOT_SUPPORTED);
            }
            if bytes.is_empty() {
                return Err(INVALID);
            }
            self.travelers(held, fds)?;
        }
        if flags & OOB != 0 && (!fds.is_empty() || bytes.is_empty()) {
            return Err(INVALID);
        }
        if self.sockets.s[i].kind == STREAM {
            self.stream_send(i, nonblock, flags & OOB != 0, fds, to, bytes, wakes)
        } else if flags & OOB != 0 {
            Err(NOT_SUPPORTED)
        } else {
            self.dgram_send(i, nonblock, fds, to, bytes, wakes)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn stream_send(
        &mut self,
        i: usize,
        nonblock: bool,
        oob: bool,
        fds: &[u32],
        to: &Addr,
        bytes: &[u8],
        wakes: &mut Wakes,
    ) -> Result<Option<usize>, u32> {
        let s = &self.sockets.s[i];
        if to.kind != ADDR_NONE {
            return Err(if s.connected {
                CONNECTED
            } else {
                NOT_SUPPORTED
            });
        }
        if !s.connected {
            return Err(NOT_CONNECTED);
        }
        if s.wr_shut || s.tx_broken {
            return Err(BROKEN);
        }
        let Some(p) = self.sockets.peer_of(i) else {
            return Err(BROKEN);
        };
        // The last byte of an out-of-band send is the byte itself, apart
        // from the stream.
        let (bytes, oob_byte) = match (oob, bytes.split_last()) {
            (true, Some((last, rest))) => (rest, Some(*last)),
            _ => (bytes, None),
        };
        let room = self.sockets.room(p);
        let n = if bytes.len() <= ATOMIC_SEND {
            if room >= bytes.len() { bytes.len() } else { 0 }
        } else {
            room.min(bytes.len())
        };
        if n == 0 && !bytes.is_empty() {
            return if nonblock { Err(AGAIN) } else { Ok(None) };
        }
        if !fds.is_empty() {
            match self.enqueue_fds(p, fds) {
                Err(AGAIN) if !nonblock => return Ok(None),
                other => other?,
            }
        }
        self.sockets.put(p, &bytes[..n]);
        self.sockets.s[p].tx_total = self.sockets.s[p].tx_total.wrapping_add(n as u32);
        if let Some(byte) = oob_byte {
            let o = &mut self.sockets.s[p];
            o.oob = true;
            o.oob_byte = byte;
            o.oob_at = o.tx_total;
        }
        wakes.add(self.sockets.s[p].waiters.waiters);
        Ok(Some(n + usize::from(oob_byte.is_some())))
    }

    /// The message of `fds` for `p`: AGAIN where its list of messages or the
    /// service's room for descriptions in flight is full.
    fn enqueue_fds(&mut self, p: usize, fds: &[u32]) -> Result<(), u32> {
        // A socket cannot travel in its own message, with descriptions of its
        // own in flight, or to a socket that travels itself: such a cycle
        // would keep its sockets for ever.
        for &id in fds {
            if id & SOCK_END != 0 {
                let s = (id & !SOCK_END) as usize;
                if s == p || self.sockets.s[s].anc_len != 0 || self.sockets.s[p].flying != 0 {
                    return Err(TOO_MANY_REFS);
                }
            }
        }
        if usize::from(self.sockets.s[p].anc_len) >= ANC_MAX {
            return Err(AGAIN);
        }
        if self.sockets.inflight + fds.len() > INFLIGHT_MAX {
            return Err(NO_BUFFERS);
        }
        let mut anc = Anc {
            at: self.sockets.s[p].tx_total,
            n: fds.len() as u8,
            ids: [0; FDS_MAX],
        };
        for (slot, &id) in anc.ids.iter_mut().zip(fds) {
            *slot = id;
            self.desc_ref(id);
            if id & SOCK_END != 0 {
                self.sockets.s[(id & !SOCK_END) as usize].flying += 1;
            }
        }
        self.sockets.inflight += fds.len();
        let s = &mut self.sockets.s[p];
        s.anc[usize::from(s.anc_len)] = anc;
        s.anc_len += 1;
        Ok(())
    }

    fn dgram_send(
        &mut self,
        i: usize,
        nonblock: bool,
        fds: &[u32],
        to: &Addr,
        bytes: &[u8],
        wakes: &mut Wakes,
    ) -> Result<Option<usize>, u32> {
        let target = if to.kind != ADDR_NONE {
            if !self.family_ok(i, to) {
                return Err(NO_FAMILY);
            }
            match self.lookup(i, to) {
                Some(t) => Some(t),
                // A port nobody listens at: the datagram is lost, as on a
                // network; a file node nobody is bound to refuses.
                None if self.sockets.s[i].domain == INET => return Ok(Some(bytes.len())),
                None => return Err(REFUSED),
            }
        } else if self.sockets.s[i].connected {
            Some(self.sockets.peer_of(i).ok_or(REFUSED)?)
        } else {
            return Err(NO_DESTINATION);
        };
        let t = target.ok_or(REFUSED)?;
        if self.sockets.s[i].wr_shut {
            return Err(BROKEN);
        }
        self.autobind(i)?;
        let from = self.sockets.s[i].local;
        let mut header = Writer::new();
        from.write(&mut header).map_err(|_| INVALID)?;
        let addr = header.as_bytes();
        let total = 4 + addr.len() + bytes.len();
        if self.sockets.s[t].rd_shut {
            return Ok(Some(bytes.len()));
        }
        if self.sockets.room(t) < total {
            return if self.sockets.s[i].domain == INET {
                Ok(Some(bytes.len()))
            } else if nonblock {
                Err(AGAIN)
            } else {
                // Waits at the receiver, whose reads tell it.
                Ok(None)
            };
        }
        if !fds.is_empty() {
            match self.enqueue_fds(t, fds) {
                Err(AGAIN) if !nonblock => return Ok(None),
                other => other?,
            }
        }
        let mut record = [0u8; 4];
        record[..2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        record[2..].copy_from_slice(&(addr.len() as u16).to_le_bytes());
        self.sockets.put(t, &record);
        self.sockets.put(t, addr);
        self.sockets.put(t, bytes);
        self.sockets.s[t].tx_total = self.sockets.s[t].tx_total.wrapping_add(1);
        wakes.add(self.sockets.s[t].waiters.waiters);
        Ok(Some(bytes.len()))
    }

    /// The queue a send that waits is told at: the receiver's, for a
    /// datagram, whose reads free the room; else the socket's own.
    pub fn send_queue(&self, held: &Held, endpoint: Endpoint, to: &Addr) -> Result<u32, u32> {
        let i = self.sock_slot(held, endpoint)?;
        let target = if self.sockets.s[i].kind != DGRAM {
            None
        } else if to.kind != ADDR_NONE {
            self.lookup(i, to)
        } else {
            self.sockets.peer_of(i)
        };
        Ok(DESCRIPTIONS as u32 + target.unwrap_or(i) as u32)
    }

    /// RECV into `out`: None to wait. The descriptions that arrive join
    /// `held`; `max_fds` of them at most, the rest are let go of.
    pub fn sock_recv(
        &mut self,
        held: &mut Held,
        endpoint: Endpoint,
        flags: u32,
        out: &mut [u8],
        max_fds: usize,
        wakes: &mut Wakes,
    ) -> Result<Option<RecvOut>, u32> {
        let i = self.sock_slot(held, endpoint)?;
        let nonblock = self.sockets.s[i].nonblock || flags & DONTWAIT != 0;
        let peek = flags & PEEK != 0;
        let s = &self.sockets.s[i];
        if s.listening {
            return Err(INVALID);
        }
        if flags & OOB != 0 {
            if s.kind != STREAM || !s.oob {
                return Err(INVALID);
            }
            if out.is_empty() {
                return Ok(Some(RecvOut::new(0)));
            }
            out[0] = s.oob_byte;
            if !peek {
                self.sockets.s[i].oob = false;
            }
            return Ok(Some(RecvOut::new(1)));
        }
        if s.rd_shut {
            return Ok(Some(RecvOut::new(0)));
        }
        if s.len == 0 {
            if s.rx_eof {
                return Ok(Some(RecvOut::new(0)));
            }
            if !s.connected && s.kind == STREAM {
                return Err(NOT_CONNECTED);
            }
            return if nonblock { Err(AGAIN) } else { Ok(None) };
        }
        // The next message: the bytes it gives, how much of the buffer it
        // takes, whether it is cut, and its sender.
        let mut result;
        let consume;
        let skip; // bytes of the buffer before the data (a datagram's header)
        let has_fds = s.anc_len > 0 && s.anc[0].at == s.rx_total;
        if s.kind == STREAM {
            let mut n = out.len().min(usize::from(s.len));
            // The bytes stop at the mark of an out-of-band byte, and where
            // the next message with descriptions starts.
            if s.oob && s.oob_at != s.rx_total {
                n = n.min(s.oob_at.wrapping_sub(s.rx_total) as usize);
            }
            let next = usize::from(has_fds);
            if usize::from(s.anc_len) > next {
                let at = s.anc[next].at.wrapping_sub(s.rx_total) as usize;
                if at > 0 {
                    n = n.min(at);
                }
            }
            result = RecvOut::new(n);
            consume = n;
            skip = 0;
        } else {
            let mut record = [0u8; 4];
            self.sockets.peek(i, 0, &mut record);
            let payload = usize::from(u16::from_le_bytes([record[0], record[1]]));
            let addr_len = usize::from(u16::from_le_bytes([record[2], record[3]]));
            let mut raw = [0u8; ADDR_MAX];
            self.sockets.peek(i, 4, &mut raw[..addr_len]);
            let from = Addr::read(&mut Reader::new(&raw[..addr_len])).map_err(|_| INVALID)?;
            let n = payload.min(out.len());
            result = RecvOut::new(n);
            result.from = from;
            if payload > n {
                result.flags |= OUT_TRUNC;
            }
            consume = 4 + addr_len + payload;
            skip = 4 + addr_len;
        }
        let mut deliver = [0u32; FDS_MAX];
        let mut count = 0;
        if has_fds && !peek {
            let anc = s.anc[0];
            let fresh = anc.ids[..usize::from(anc.n)]
                .iter()
                .take(max_fds)
                .filter(|&&id| !held.holds(id))
                .count();
            if held.count() + fresh > HELD_MAX {
                return Err(MFILE);
            }
        }
        self.sockets.peek(i, skip, &mut out[..result.n]);
        if !peek {
            self.sockets.drop_front(i, consume);
            let s = &mut self.sockets.s[i];
            let step = if s.kind == STREAM { consume as u32 } else { 1 };
            s.rx_total = s.rx_total.wrapping_add(step);
            if has_fds {
                let anc = self.sockets.anc_pop(i);
                self.sockets.unfly(&anc);
                self.sockets.inflight -= usize::from(anc.n);
                for (k, &id) in anc.ids[..usize::from(anc.n)].iter().enumerate() {
                    if k >= max_fds {
                        result.flags |= OUT_CTRUNC;
                        self.sockets.limbo_push(id);
                        self.sockets.inflight += 1;
                    } else if held.holds(id) {
                        // The session has it: this reference goes.
                        self.sockets.limbo_push(id);
                        self.sockets.inflight += 1;
                        deliver[count] = id;
                        count += 1;
                    } else {
                        held.add(id as usize);
                        deliver[count] = id;
                        count += 1;
                    }
                }
            }
            if let Some(p) = self.sockets.peer_of(i) {
                wakes.add(self.sockets.s[p].waiters.waiters);
            }
            if self.sockets.s[i].kind == DGRAM {
                // Senders that wait for room in this buffer wait here.
                wakes.add(self.sockets.s[i].waiters.waiters);
            }
        }
        result.fds = deliver;
        result.nfds = count;
        Ok(Some(result))
    }

    /// Plain `read` of a socket.
    pub(super) fn sock_read(
        &mut self,
        held: &Held,
        endpoint: Endpoint,
        out: &mut [u8],
        wakes: &mut Wakes,
    ) -> Result<Option<usize>, u32> {
        let mut scratch = *held;
        let got = self.sock_recv(&mut scratch, endpoint, 0, out, 0, wakes)?;
        Ok(got.map(|r| r.n))
    }

    /// Plain `write` of a socket.
    pub(super) fn sock_write(
        &mut self,
        held: &Held,
        endpoint: Endpoint,
        bytes: &[u8],
        wakes: &mut Wakes,
    ) -> Result<Option<usize>, u32> {
        self.sock_send(held, endpoint, 0, &[], &Addr::NONE, bytes, wakes)
    }

    pub(super) fn sock_flags(&self, held: &Held, endpoint: Endpoint) -> Result<u32, u32> {
        let i = self.desc_slot(held, endpoint)?;
        Ok(proto_pipe::RDWR
            | if self.sockets.s[i].nonblock {
                NONBLOCK
            } else {
                0
            })
    }

    pub(super) fn sock_set_flags(
        &mut self,
        held: &Held,
        endpoint: Endpoint,
        flags: u32,
    ) -> Result<(), u32> {
        let i = self.desc_slot(held, endpoint)?;
        if flags & !NONBLOCK != 0 {
            return Err(INVALID);
        }
        self.sockets.s[i].nonblock = flags & NONBLOCK != 0;
        Ok(())
    }

    pub(super) fn sock_stat(&self, held: &Held, endpoint: Endpoint) -> Result<(u32, u32), u32> {
        let i = self.desc_slot(held, endpoint)?;
        Ok((PIPES as u32 + i as u32, u32::from(self.sockets.s[i].len)))
    }

    pub(super) fn sock_readiness(&self, i: usize) -> u32 {
        use proto_wire::watch;
        let s = &self.sockets.s[i];
        if s.kind == MQ_KIND {
            // Not waited for: a queue's changes do not wake a poll.
            return watch::NVAL;
        }
        let mut ready = 0;
        if s.len != 0 || s.rx_eof || s.rd_shut || (s.listening && s.queued != 0) {
            ready |= watch::READ;
        }
        if s.oob {
            ready |= watch::PRI;
        }
        if s.rx_eof && s.tx_broken {
            ready |= watch::HUP;
        }
        if s.kind == DGRAM {
            ready |= watch::WRITE;
        } else if s.connected {
            if !(s.wr_shut || s.tx_broken)
                && self
                    .sockets
                    .peer_of(i)
                    .is_some_and(|p| self.sockets.room(p) != 0)
            {
                ready |= watch::WRITE;
            }
        } else if !s.listening {
            ready |= watch::WRITE | watch::HUP;
        }
        ready
    }

    pub(super) fn sock_close(
        &mut self,
        held: &mut Held,
        endpoint: Endpoint,
        wakes: &mut Wakes,
    ) -> Result<(), u32> {
        let i = self.desc_slot(held, endpoint)?;
        held.remove(endpoint.id as usize);
        self.sock_unref(i, 1, wakes);
        Ok(())
    }

    /// `count` references of socket `i` go; its last frees it.
    pub(super) fn sock_unref(&mut self, i: usize, count: u16, wakes: &mut Wakes) {
        let s = &mut self.sockets.s[i];
        debug_assert!(s.refs >= count, "the references of a socket");
        s.refs = s.refs.saturating_sub(count);
        if s.refs != 0 || !s.live {
            return;
        }
        if s.kind == MQ_KIND {
            // An open message queue: the queue loses an opener.
            let queue = s.peer;
            s.live = false;
            s.peer = None;
            if let Some(queue) = queue {
                self.mq_closed(i, queue, wakes);
            }
            return;
        }
        wakes.add(s.waiters.waiters);
        s.waiters = End::NONE;
        s.live = false;
        // The connections nobody accepted go, each in a step of its own.
        let queued = usize::from(s.queued);
        let queue = s.queue;
        let peer = s.peer;
        let anc = s.anc;
        let anc_len = usize::from(s.anc_len);
        s.queued = 0;
        s.anc_len = 0;
        s.peer = None;
        for &q in &queue[..queued] {
            self.sockets.dropping[usize::from(q)] += 1;
            self.sockets.dirty |= 1 << q;
        }
        if let Some((p, era)) = peer {
            let p = usize::from(p);
            let o = &mut self.sockets.s[p];
            if o.live && o.era == era {
                o.peer = None;
                o.rx_eof = true;
                o.tx_broken = true;
                wakes.add(o.waiters.waiters);
            }
        }
        for a in &anc[..anc_len] {
            self.sockets.unfly(a);
            for &id in &a.ids[..usize::from(a.n)] {
                self.sockets.limbo_push(id);
            }
        }
    }

    /// One step of what sessions that went left: a socket they held, or a
    /// description a message held.
    pub(super) fn sock_step(&mut self, wakes: &mut Wakes) {
        if self.sockets.dirty != 0 {
            let i = self.sockets.dirty.trailing_zeros() as usize;
            self.sockets.dirty &= !(1 << i);
            let count = core::mem::take(&mut self.sockets.dropping[i]);
            self.sock_unref(i, count, wakes);
        } else if self.sockets.limbo_len != 0 {
            self.sockets.limbo_len -= 1;
            let id = self.sockets.limbo[self.sockets.limbo_len];
            self.sockets.inflight -= 1;
            self.desc_unref(id, wakes);
        }
    }

    /// The sockets in use.
    pub fn live_sockets(&self) -> usize {
        self.live_socks(|_| true)
    }

    /// The descriptions in flight.
    pub fn in_flight(&self) -> usize {
        self.sockets.inflight
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_wire::watch;

    fn pipes() -> Box<Pipes> {
        Box::new(Pipes::new())
    }

    fn sock(id: u32) -> Endpoint {
        Endpoint::anonymous(id)
    }

    fn make(p: &mut Pipes, held: &mut Held, domain: u32, kind: u32) -> Endpoint {
        sock(p.sock_create(held, 1, 1, domain, kind, 0).unwrap())
    }

    fn inet(port: u16) -> Addr {
        Addr::inet(port)
    }

    fn woke(w: &Wakes) -> Vec<Waiter> {
        w.iter().collect()
    }

    /// A listening stream on `port` and a connected client; the server's end.
    fn stream_pair(p: &mut Pipes, held: &mut Held, port: u16) -> (Endpoint, Endpoint, Endpoint) {
        let mut w = Wakes::default();
        let l = make(p, held, INET, STREAM);
        p.sock_bind(held, l, inet(port)).unwrap();
        p.sock_listen(held, l, 1).unwrap();
        let c = make(p, held, INET, STREAM);
        p.sock_connect(held, c, inet(port), &mut w).unwrap();
        let (s, _) = p.sock_accept(held, l, 1, 1).unwrap().unwrap();
        (l, c, sock(s))
    }

    #[test]
    fn a_stream_carries_bytes_and_ends_with_the_peer() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let (_, c, s) = stream_pair(&mut p, &mut held, 5000);
        assert_eq!(p.sock_write(&held, s, b"hello", &mut w), Ok(Some(5)));
        let mut out = [0; 16];
        assert_eq!(p.sock_read(&held, c, &mut out, &mut w), Ok(Some(5)));
        assert_eq!(&out[..5], b"hello");
        assert_eq!(p.sock_read(&held, c, &mut out, &mut w), Ok(None));
        // The name of the client is the peer of the accepted socket.
        let name = p.sock_name(&held, c, false).unwrap();
        assert_eq!(p.sock_name(&held, s, true), Ok(name));
        assert_eq!(p.sock_name(&held, c, true), Ok(inet(5000)));
        assert!(name.port >= 49152);
        p.sock_close(&mut held, s, &mut w).unwrap();
        assert_eq!(p.sock_read(&held, c, &mut out, &mut w), Ok(Some(0)));
        assert_eq!(p.sock_write(&held, c, b"x", &mut w), Err(BROKEN));
        assert_eq!(p.readiness_endpoint(&held, c), watch::READ | watch::HUP);
    }

    #[test]
    fn the_data_of_a_closed_sender_is_still_read() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let (_, c, s) = stream_pair(&mut p, &mut held, 5001);
        p.sock_write(&held, s, b"abc", &mut w).unwrap();
        p.sock_close(&mut held, s, &mut w).unwrap();
        let mut out = [0; 8];
        assert_eq!(p.sock_read(&held, c, &mut out, &mut w), Ok(Some(3)));
        assert_eq!(p.sock_read(&held, c, &mut out, &mut w), Ok(Some(0)));
    }

    #[test]
    fn an_out_of_band_byte_has_a_mark_in_the_stream() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let (_, c, s) = stream_pair(&mut p, &mut held, 5005);
        let option = |p: &mut Pipes, h: &Held, e| p.sock_option(h, e, OPT_ATMARK, false, 0);
        assert_eq!(option(&mut p, &held, c), Ok(0));
        let send = |p: &mut Pipes, flags, bytes: &[u8], w: &mut Wakes| {
            p.sock_send(&held, s, flags, &[], &Addr::NONE, bytes, w)
        };
        assert_eq!(send(&mut p, 0, b"ab", &mut w), Ok(Some(2)));
        assert_eq!(send(&mut p, OOB, b"X", &mut w), Ok(Some(1)));
        assert_eq!(send(&mut p, 0, b"cd", &mut w), Ok(Some(2)));
        assert_eq!(send(&mut p, OOB, b"", &mut w), Err(INVALID));
        assert_eq!(option(&mut p, &held, c), Ok(0));
        assert_eq!(
            p.readiness_endpoint(&held, c),
            watch::READ | watch::WRITE | watch::PRI,
            "the byte is an exceptional condition"
        );
        let mut out = [0; 8];
        let got = p.sock_recv(&mut held, c, 0, &mut out, 0, &mut w);
        assert_eq!(
            got.map(|g| g.map(|g| g.n)),
            Ok(Some(2)),
            "stops at the mark"
        );
        assert_eq!(option(&mut p, &held, c), Ok(1));
        let got = p.sock_recv(&mut held, c, OOB, &mut out, 0, &mut w);
        assert_eq!((got.map(|g| g.map(|g| g.n)), out[0]), (Ok(Some(1)), b'X'));
        assert_eq!(option(&mut p, &held, c), Ok(0));
        assert_eq!(
            p.sock_recv(&mut held, c, OOB, &mut out, 0, &mut w),
            Err(INVALID)
        );
        let got = p.sock_recv(&mut held, c, 0, &mut out, 0, &mut w);
        assert_eq!(got.map(|g| g.map(|g| g.n)), Ok(Some(2)));
        // A datagram socket has none.
        let d = make(&mut p, &mut held, INET, DGRAM);
        assert_eq!(
            p.sock_send(&held, d, OOB, &[], &inet(1), b"x", &mut w),
            Err(NOT_SUPPORTED)
        );
    }

    #[test]
    fn shutdown_ends_one_direction() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let (_, c, s) = stream_pair(&mut p, &mut held, 5002);
        p.sock_shutdown(&held, s, 1, &mut w).unwrap();
        let mut out = [0; 4];
        assert_eq!(p.sock_read(&held, c, &mut out, &mut w), Ok(Some(0)));
        assert_eq!(p.sock_write(&held, s, b"x", &mut w), Err(BROKEN));
        // The other direction still works.
        assert_eq!(p.sock_write(&held, c, b"y", &mut w), Ok(Some(1)));
        assert_eq!(p.sock_read(&held, s, &mut out, &mut w), Ok(Some(1)));
        p.sock_shutdown(&held, s, 0, &mut w).unwrap();
        assert_eq!(p.sock_write(&held, c, b"z", &mut w), Err(BROKEN));
        assert_eq!(
            p.sock_shutdown(&held, sock(SOCK_END | 39), 2, &mut w),
            Err(BAD_FD)
        );
    }

    #[test]
    fn a_connect_waits_in_the_queue_of_the_listener() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let l = make(&mut p, &mut held, INET, STREAM);
        p.sock_bind(&held, l, inet(5003)).unwrap();
        assert_eq!(p.sock_listen(&held, sock(l.id), 0), Ok(()));
        assert_eq!(p.sock_accept(&mut held, l, 1, 1), Ok(None));
        p.wait_new(DESCRIPTIONS as u32 + l.slot() as u32, (7, 1), |_| true)
            .unwrap();
        let c = make(&mut p, &mut held, INET, STREAM);
        p.sock_connect(&held, c, inet(5003), &mut w).unwrap();
        assert_eq!(woke(&w), [(7, 1)]);
        assert_eq!(
            p.readiness_endpoint(&held, l),
            watch::READ,
            "a listener with a connection is readable"
        );
        // The backlog is one: a second connection is refused.
        let c2 = make(&mut p, &mut held, INET, STREAM);
        assert_eq!(p.sock_connect(&held, c2, inet(5003), &mut w), Err(REFUSED));
        assert_eq!(p.sock_connect(&held, c2, inet(5999), &mut w), Err(REFUSED));
        let (s, from) = p.sock_accept(&mut held, l, 1, 1).unwrap().unwrap();
        assert_eq!(from, p.sock_name(&held, c, false).unwrap());
        assert_eq!(p.sock_write(&held, sock(s), b"k", &mut w), Ok(Some(1)));
        // Closing a listener sends its unaccepted connections away.
        p.sock_connect(&held, c2, inet(5003), &mut w).unwrap();
        p.sock_close(&mut held, l, &mut w).unwrap();
        while p.sockets.due() {
            p.sock_step(&mut w);
        }
        let mut out = [0; 2];
        assert_eq!(p.sock_read(&held, c2, &mut out, &mut w), Ok(Some(0)));
    }

    #[test]
    fn ports_are_given_and_kept_apart() {
        let mut p = pipes();
        let mut held = Held::default();
        let a = make(&mut p, &mut held, INET, STREAM);
        let b = make(&mut p, &mut held, INET, STREAM);
        let u = make(&mut p, &mut held, INET, DGRAM);
        p.sock_bind(&held, a, inet(0)).unwrap();
        let port = p.sock_name(&held, a, false).unwrap().port;
        assert!(port >= 49152);
        assert_eq!(p.sock_bind(&held, b, inet(port)), Err(IN_USE));
        // A datagram socket has its own ports.
        p.sock_bind(&held, u, inet(port)).unwrap();
        assert_eq!(p.sock_bind(&held, a, inet(7)), Err(INVALID));
        assert_eq!(
            p.sock_bind(&held, b, Addr::unix(5, b"/x").unwrap()),
            Err(NO_FAMILY)
        );
    }

    #[test]
    fn datagrams_keep_their_bounds_and_name_the_sender() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let a = make(&mut p, &mut held, INET, DGRAM);
        let b = make(&mut p, &mut held, INET, DGRAM);
        p.sock_bind(&held, a, inet(6000)).unwrap();
        p.sock_bind(&held, b, inet(6001)).unwrap();
        assert_eq!(
            p.sock_send(&held, a, 0, &[], &inet(6001), b"one", &mut w),
            Ok(Some(3))
        );
        assert_eq!(
            p.sock_send(&held, a, 0, &[], &inet(6001), b"second", &mut w),
            Ok(Some(6))
        );
        let mut out = [0; 4];
        let got = p
            .sock_recv(&mut held, b, 0, &mut out, 0, &mut w)
            .unwrap()
            .unwrap();
        assert_eq!((got.n, got.from, &out[..3]), (3, inet(6000), &b"one"[..]));
        // A short buffer cuts the datagram and says so.
        let got = p
            .sock_recv(&mut held, b, 0, &mut out, 0, &mut w)
            .unwrap()
            .unwrap();
        assert_eq!((got.n, got.flags), (4, OUT_TRUNC));
        assert_eq!(&out, b"seco");
        assert_eq!(p.sock_recv(&mut held, b, 0, &mut out, 0, &mut w), Ok(None));
        // No destination, and a port nobody has: lost.
        assert_eq!(
            p.sock_send(&held, a, 0, &[], &Addr::NONE, b"x", &mut w),
            Err(NO_DESTINATION)
        );
        assert_eq!(
            p.sock_send(&held, a, 0, &[], &inet(1), b"x", &mut w),
            Ok(Some(1))
        );
        // A connected socket sends to its peer, and an unbound sender gets a port.
        let c = make(&mut p, &mut held, INET, DGRAM);
        p.sock_connect(&held, c, inet(6000), &mut w).unwrap();
        assert_eq!(p.sock_name(&held, c, true), Ok(inet(6000)));
        assert_eq!(p.sock_write(&held, c, b"hi", &mut w), Ok(Some(2)));
        let got = p
            .sock_recv(&mut held, a, 0, &mut out, 0, &mut w)
            .unwrap()
            .unwrap();
        assert_eq!(got.from, p.sock_name(&held, c, false).unwrap());
        assert!(got.from.port >= 49152);
        assert_eq!(
            p.sock_send(&held, a, 0, &[], &inet(6001), &[0; SEND_MAX + 1], &mut w),
            Err(TOO_BIG)
        );
    }

    #[test]
    fn a_full_buffer_makes_a_stream_writer_wait() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let (_, c, s) = stream_pair(&mut p, &mut held, 5004);
        let big = [7u8; SEND_MAX];
        let mut total = 0;
        loop {
            match p.sock_write(&held, s, &big, &mut w) {
                Ok(Some(n)) => total += n,
                Ok(None) => break,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(total, RING);
        p.sock_set_flags(&held, s, NONBLOCK).unwrap();
        assert_eq!(p.sock_write(&held, s, b"x", &mut w), Err(AGAIN));
        assert_eq!(p.readiness_endpoint(&held, s) & watch::WRITE, 0);
        let mut out = [0; 100];
        let mut w2 = Wakes::default();
        // A read by c wakes whoever waits at s, the peer.
        p.wait_new(DESCRIPTIONS as u32 + s.slot() as u32, (9, 9), |_| true)
            .unwrap();
        assert_eq!(p.sock_read(&held, c, &mut out, &mut w2), Ok(Some(100)));
        assert_eq!(woke(&w2), [(9, 9)]);
        assert_eq!(p.readiness_endpoint(&held, s) & watch::WRITE, watch::WRITE);
    }

    #[test]
    fn socketpair_is_connected_both_ways() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let (a, b) = p.sock_pair(&mut held, 1, 1, UNIX, STREAM, 0).unwrap();
        let (a, b) = (sock(a), sock(b));
        p.sock_write(&held, a, b"ping", &mut w).unwrap();
        let mut out = [0; 8];
        assert_eq!(p.sock_read(&held, b, &mut out, &mut w), Ok(Some(4)));
        p.sock_write(&held, b, b"pong", &mut w).unwrap();
        assert_eq!(p.sock_read(&held, a, &mut out, &mut w), Ok(Some(4)));
        assert_eq!(
            p.sock_pair(&mut held, 1, 1, INET, STREAM, 0),
            Err(NOT_SUPPORTED)
        );
        let (c, d) = p.sock_pair(&mut held, 1, 1, UNIX, DGRAM, 0).unwrap();
        p.sock_write(&held, sock(c), b"d1", &mut w).unwrap();
        p.sock_write(&held, sock(c), b"d2", &mut w).unwrap();
        let got = p
            .sock_recv(&mut held, sock(d), 0, &mut out, 0, &mut w)
            .unwrap()
            .unwrap();
        assert_eq!((got.n, &out[..2]), (2, &b"d1"[..]));
    }

    #[test]
    fn unix_names_find_the_socket_of_a_node() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let l = make(&mut p, &mut held, UNIX, STREAM);
        let name = Addr::unix(42, b"/tmp/s").unwrap();
        assert_eq!(p.sock_listen(&held, l, 1), Err(INVALID));
        p.sock_bind(&held, l, name).unwrap();
        p.sock_listen(&held, l, 2).unwrap();
        let c = make(&mut p, &mut held, UNIX, STREAM);
        p.sock_connect(&held, c, name, &mut w).unwrap();
        let (s, from) = p.sock_accept(&mut held, l, 1, 1).unwrap().unwrap();
        assert_eq!(from, Addr::NONE);
        assert_eq!(p.sock_name(&held, sock(s), false), Ok(name));
        assert_eq!(p.sock_name(&held, c, true), Ok(name));
        // A datagram socket at the same node is of another kind.
        let d = make(&mut p, &mut held, UNIX, DGRAM);
        assert_eq!(p.sock_connect(&held, d, name, &mut w), Err(BAD_TYPE));
        let c2 = make(&mut p, &mut held, UNIX, STREAM);
        assert_eq!(
            p.sock_connect(&held, c2, Addr::unix(43, b"/none").unwrap(), &mut w),
            Err(REFUSED)
        );
        // A node made anew takes the name from the stale socket.
        let n = make(&mut p, &mut held, UNIX, STREAM);
        p.sock_bind(&held, n, name).unwrap();
        assert_eq!(p.sock_name(&held, l, false), Ok(Addr::NONE));
    }

    #[test]
    fn descriptions_cross_in_a_message_and_the_sender_may_close_first() {
        let mut p = pipes();
        let mut a = Held::default();
        let mut w = Wakes::default();
        // The pair's two sockets, one in each session.
        let (x, y) = p.sock_pair(&mut a, 1, 1, UNIX, STREAM, 0).unwrap();
        let moved = p.clone_endpoints(&a, &[sock(y)]).unwrap();
        let mut b = moved;
        p.sock_close(&mut a, sock(y), &mut w).unwrap();
        let (rd, wr) = p.create(&mut a, 1, 1, 0).unwrap();
        assert_eq!(
            p.sock_send(&a, sock(x), 0, &[wr], &Addr::NONE, b"f", &mut w),
            Ok(Some(1))
        );
        assert_eq!(p.in_flight(), 1);
        // The sender lets the write end go: the message keeps it.
        p.close(&mut a, wr, &mut w).unwrap();
        let mut out = [0; 4];
        let got = p
            .sock_recv(&mut b, sock(y), 0, &mut out, 4, &mut w)
            .unwrap()
            .unwrap();
        assert_eq!((got.n, got.nfds), (1, 1));
        assert_eq!(p.in_flight(), 0);
        let fd = got.fds[0];
        assert!(b.holds(fd));
        // The reader of the pipe sees data written through the received end.
        let mut w2 = Wakes::default();
        assert_eq!(p.write(&b, fd, b"via", &mut w2), Ok(Some(3)));
        assert_eq!(p.read(&a, rd, &mut out, &mut w2), Ok(Some(3)));
        // Another message, whose socket goes with it still in flight.
        let (rd2, wr2) = p.create(&mut a, 1, 1, 0).unwrap();
        p.sock_send(&a, sock(x), 0, &[wr2], &Addr::NONE, b"g", &mut w)
            .unwrap();
        p.close(&mut a, wr2, &mut w).unwrap();
        p.sock_close(&mut a, sock(x), &mut w).unwrap();
        assert!(p.gone(&mut b));
        while p.step(&mut w) {}
        // Nobody holds the write end any more: the reader sees the end.
        assert_eq!(p.read(&a, rd2, &mut out, &mut w), Ok(Some(0)));
        assert_eq!(p.in_flight(), 0);
        assert_eq!(p.live_sockets(), 0);
    }

    #[test]
    fn what_cannot_travel_is_refused_and_a_stream_message_is_not_merged() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let (a, b) = p.sock_pair(&mut held, 1, 1, UNIX, STREAM, 0).unwrap();
        let (rd, wr) = p.create(&mut held, 1, 1, 0).unwrap();
        assert_eq!(
            p.sock_send(&held, sock(a), 0, &[99], &Addr::NONE, b"x", &mut w),
            Err(BAD_FD)
        );
        assert_eq!(
            p.sock_send(
                &held,
                sock(a),
                0,
                &[NAMED_END | 1],
                &Addr::NONE,
                b"x",
                &mut w
            ),
            Err(NOT_SUPPORTED)
        );
        assert_eq!(
            p.sock_send(&held, sock(a), 0, &[wr], &Addr::NONE, b"", &mut w),
            Err(INVALID)
        );
        p.sock_write(&held, sock(a), b"abc", &mut w).unwrap();
        p.sock_send(&held, sock(a), 0, &[rd], &Addr::NONE, b"def", &mut w)
            .unwrap();
        let mut out = [0; 16];
        let got = p
            .sock_recv(&mut held, sock(b), 0, &mut out, 4, &mut w)
            .unwrap()
            .unwrap();
        assert_eq!(
            (got.n, got.nfds),
            (3, 0),
            "stops before the message with a fd"
        );
        let got = p
            .sock_recv(&mut held, sock(b), 0, &mut out, 0, &mut w)
            .unwrap()
            .unwrap();
        assert_eq!(
            (got.n, got.nfds, got.flags),
            (3, 0, OUT_CTRUNC),
            "fds the caller cannot take go"
        );
        assert_eq!(p.in_flight(), 1);
        while p.step(&mut w) {}
        assert_eq!(p.in_flight(), 0);
        // The messages with descriptions one socket holds are bounded.
        for _ in 0..ANC_MAX {
            p.sock_send(&held, sock(a), 0, &[rd], &Addr::NONE, b"m", &mut w)
                .unwrap();
        }
        // A blocking send waits for the reader; a non-blocking one is refused.
        assert_eq!(
            p.sock_send(&held, sock(a), 0, &[rd], &Addr::NONE, b"m", &mut w),
            Ok(None)
        );
        assert_eq!(
            p.sock_send(&held, sock(a), DONTWAIT, &[rd], &Addr::NONE, b"m", &mut w),
            Err(AGAIN)
        );
        assert_eq!(p.in_flight(), ANC_MAX);
    }

    #[test]
    fn a_cycle_of_sockets_in_flight_is_refused() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let (x, y) = p.sock_pair(&mut held, 1, 1, UNIX, STREAM, 0).unwrap();
        let (x, y) = (sock(x), sock(y));
        // y in a message to y itself.
        assert_eq!(
            p.sock_send(&held, x, 0, &[y.id], &Addr::NONE, b"c", &mut w),
            Err(TOO_MANY_REFS)
        );
        // y holds an unread message with a description: y cannot travel.
        let (u, v) = p.sock_pair(&mut held, 1, 1, UNIX, STREAM, 0).unwrap();
        let (u, v) = (sock(u), sock(v));
        let (rd, wr) = p.create(&mut held, 1, 1, 0).unwrap();
        let _ = rd;
        p.sock_send(&held, x, 0, &[wr], &Addr::NONE, b"1", &mut w)
            .unwrap();
        assert_eq!(
            p.sock_send(&held, u, 0, &[y.id], &Addr::NONE, b"2", &mut w),
            Err(TOO_MANY_REFS)
        );
        // A socket in flight cannot receive one: n travels to v, and m,
        // its peer, cannot carry u to it.
        let (m, n) = p.sock_pair(&mut held, 1, 1, UNIX, STREAM, 0).unwrap();
        let (m, n) = (sock(m), sock(n));
        assert_eq!(
            p.sock_send(&held, u, 0, &[n.id], &Addr::NONE, b"3", &mut w),
            Ok(Some(1))
        );
        assert_eq!(
            p.sock_send(&held, m, 0, &[u.id], &Addr::NONE, b"4", &mut w),
            Err(TOO_MANY_REFS)
        );
        let _ = v;
        // Everything goes with the sockets.
        for e in [x, y, u, v, m, n] {
            p.sock_close(&mut held, e, &mut w).unwrap();
        }
        while p.work_due() {
            p.step(&mut w);
        }
        assert_eq!((p.live_sockets(), p.in_flight()), (0, 0));
    }

    #[test]
    fn a_blocking_datagram_send_to_a_full_buffer_waits_at_the_receiver() {
        let mut p = pipes();
        let mut held = Held::default();
        let mut w = Wakes::default();
        let (c, d) = p.sock_pair(&mut held, 1, 1, UNIX, DGRAM, 0).unwrap();
        let (c, d) = (sock(c), sock(d));
        let big = [1u8; SEND_MAX];
        let mut sent = 0;
        while let Ok(Some(_)) = p.sock_write(&held, c, &big, &mut w) {
            sent += 1;
        }
        assert!(sent >= 4);
        assert_eq!(p.sock_write(&held, c, &big, &mut w), Ok(None));
        assert_eq!(
            p.send_queue(&held, c, &Addr::NONE),
            Ok(DESCRIPTIONS as u32 + d.slot() as u32)
        );
        p.sock_set_flags(&held, c, NONBLOCK).unwrap();
        assert_eq!(p.sock_write(&held, c, &big, &mut w), Err(AGAIN));
        p.wait_new(DESCRIPTIONS as u32 + d.slot() as u32, (4, 4), |_| true)
            .unwrap();
        let mut out = [0; SEND_MAX];
        let mut w2 = Wakes::default();
        assert!(
            p.sock_recv(&mut held, d, 0, &mut out, 0, &mut w2)
                .unwrap()
                .is_some()
        );
        assert_eq!(woke(&w2), [(4, 4)], "the read tells the waiting sender");
    }

    #[test]
    fn the_limits_hold() {
        let mut p = pipes();
        let mut held = Held::default();
        for _ in 0..SOCK_CREATED_MAX {
            p.sock_create(&mut held, 1, 1, INET, STREAM, 0).unwrap();
        }
        assert_eq!(p.sock_create(&mut held, 1, 1, INET, STREAM, 0), Err(MFILE));
        let mut other = Held::default();
        for _ in 0..ROOT_SOCKS - SOCK_CREATED_MAX {
            p.sock_create(&mut other, 2, 1, INET, STREAM, 0).unwrap();
        }
        assert_eq!(
            p.sock_create(&mut other, 6, 1, INET, STREAM, 0),
            Err(NFILE),
            "the root has its share"
        );
        let mut third = Held::default();
        for n in 0..SOCKETS - ROOT_SOCKS {
            p.sock_create(&mut third, 10 + n as u64 / 8, 3, INET, STREAM, 0)
                .unwrap();
        }
        assert_eq!(p.sock_create(&mut third, 4, 3, INET, STREAM, 0), Err(NFILE));
        assert_eq!(
            p.sock_create(&mut third, 5, 5, 9, STREAM, 0),
            Err(NO_FAMILY)
        );
        assert_eq!(p.sock_create(&mut third, 5, 5, INET, 7, 0), Err(INVALID));
        assert_eq!(p.live_sockets(), SOCKETS);
        let mut w = Wakes::default();
        assert!(p.gone(&mut held));
        while p.step(&mut w) {}
        assert_eq!(p.live_sockets(), SOCKETS - SOCK_CREATED_MAX);
    }

    #[test]
    fn options_report_and_keep_what_they_were_given() {
        let mut p = pipes();
        let mut held = Held::default();
        let s = make(&mut p, &mut held, INET, STREAM);
        let get = |p: &mut Pipes, o| p.sock_option(&held, s, o, false, 0);
        assert_eq!(get(&mut p, OPT_REUSEADDR), Ok(0));
        assert_eq!(get(&mut p, OPT_TYPE), Ok(STREAM));
        assert_eq!(get(&mut p, OPT_ERROR), Ok(0));
        assert_eq!(get(&mut p, OPT_ACCEPTCONN), Ok(0));
        assert_eq!(p.sock_option(&held, s, OPT_REUSEADDR, true, 1), Ok(1));
        assert_eq!(p.sock_option(&held, s, OPT_REUSEADDR, false, 0), Ok(1));
        assert_eq!(
            p.sock_option(&held, s, OPT_RCVBUF, true, 1 << 20),
            Ok(RING as u32)
        );
        assert_eq!(p.sock_option(&held, s, OPT_TYPE, true, 1), Err(NO_OPTION));
        assert_eq!(p.sock_option(&held, s, 99, false, 0), Err(NO_OPTION));
    }
}
