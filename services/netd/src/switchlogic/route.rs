// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Where a frame goes (note Sh4, table 3.4) and what a consumer may send
//! (section 4). A frame of the wire, a frame of the stack and a frame a
//! consumer sent for the shared address (the hairpin, R-2a) all go through
//! `route`. The keys of the flows: `route` looks the flow up from the side
//! of the receiver (peer = the frame's source, own port = its destination
//! port), `check_tx` from the side of the sender (peer = the frame's
//! destination, own port = its source port). Own address is one, so a
//! frame from consumer A to a group with member B finds A's flow at the
//! send check and B's flow at steering: the keys differ in the ports.

use super::tables::{
    BLOCK_MARK, FIN_IN, FIN_OUT, FlowKey, MAX_GROUPS, RST, RST_PEER, Tables, UNCONFIRMED,
};
use crate::ports::Proto;
use proto_net::switch::{DONE_ARP_COPY, DONE_ICMP_ERROR, FRAME_MAX};
use virtio_net::frames::{
    ETHERNET_HEADER, ETHERTYPE_ARP, ETHERTYPE_IPV4, IPV4_PROTO_ICMP, IPV4_PROTO_TCP,
    IPV4_PROTO_UDP, packet,
};

/// Cells of FILL a member needs for a new connection.
pub const MIN_FILL: u32 = 32;
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RSTBIT: u8 = 0x04;
const ACK: u8 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Wire,
    Stack,
    Consumer(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// An ARP reply that names our own address as the sender.
    Forged,
    /// A frame of the wire whose source is our own address.
    Spoofed,
    /// A frame of the wire whose source no host on the wire has: "this host", loopback,
    /// multicast and above, the broadcast of the subnet.
    Bogus,
    /// Every member of the group is short of cells.
    AllFull,
    /// The group has holders but no live member (until the park of SYNs exists the SYN is
    /// dropped and the client repeats it, as when the listening queue of Linux waits).
    NoMember,
    /// The flow table has no room for the connection.
    FlowsFull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Stack,
    Consumer {
        consumer: u8,
        flags: u16,
    },
    /// An ARP reply: the stack and a copy to every consumer.
    ArpAll,
    Drop(Why),
}

/// Why a frame of a consumer is refused; the counters are indexed by it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Length,
    SrcMac,
    DstMac,
    ArpKind,
    ArpSender,
    ArpRate,
    Ipv4,
    Fragment,
    SrcAddr,
    DstAddr,
    Tcp,
    Udp,
    Proto,
    Flows,
}

impl Reason {
    pub const COUNT: usize = Reason::Flows as usize + 1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Send,
    /// For the shared address: goes through `route` and never to the device.
    Hairpin,
    Refuse(Reason),
}

struct Ip<'a> {
    proto: u8,
    src: [u8; 4],
    dst: [u8; 4],
    part: &'a [u8],
    fragment: bool,
    /// The header has options (more than 20 bytes).
    options: bool,
}

fn ipv4(frame: &[u8]) -> Option<Ip<'_>> {
    let p = packet(frame)?;
    let ip = &frame[ETHERNET_HEADER..];
    Some(Ip {
        proto: p.protocol,
        src: ip[12..16].try_into().ok()?,
        dst: ip[16..20].try_into().ok()?,
        part: &ip[p.header..p.end],
        fragment: !p.first_fragment,
        options: p.header != 20,
    })
}

fn ports(part: &[u8]) -> (u16, u16) {
    (
        u16::from_be_bytes([part[0], part[1]]),
        u16::from_be_bytes([part[2], part[3]]),
    )
}

fn is_arp(frame: &[u8]) -> bool {
    frame.len() >= ETHERNET_HEADER + 28 && frame[12..14] == ETHERTYPE_ARP
}

fn arp_oper(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[20], frame[21]])
}

/// Whether a frame of the stack is a turn: TCP or UDP, whole, to the shared address.
pub fn faces_own(t: &Tables, frame: &[u8]) -> bool {
    ipv4(frame).is_some_and(|ip| {
        !ip.fragment
            && ip.dst == t.own.ip
            && t.own.ip != [0; 4]
            && matches!(ip.proto, IPV4_PROTO_TCP | IPV4_PROTO_UDP)
    })
}

/// Where a received frame goes.
pub fn route(t: &mut Tables, frame: &[u8], from: Source) -> Decision {
    t.guard.check();
    if frame.len() >= ETHERNET_HEADER && frame[12..14] == ETHERTYPE_ARP {
        if is_arp(frame) && arp_oper(frame) == 2 {
            return if frame[28..32] == t.own.ip {
                Decision::Drop(Why::Forged)
            } else {
                Decision::ArpAll
            };
        }
        return Decision::Stack;
    }
    let Some(ip) = ipv4(frame) else {
        return Decision::Stack;
    };
    if ip.fragment || t.own.ip == [0; 4] || ip.dst != t.own.ip {
        return Decision::Stack;
    }
    if from == Source::Wire && ip.src == t.own.ip {
        return Decision::Drop(Why::Spoofed);
    }
    if from == Source::Wire && !unicast_elsewhere(t, ip.src) {
        return Decision::Drop(Why::Bogus);
    }
    match ip.proto {
        IPV4_PROTO_ICMP => icmp(t, &ip),
        IPV4_PROTO_UDP if ip.part.len() >= 8 => udp(t, &ip),
        IPV4_PROTO_TCP if ip.part.len() >= 20 => tcp(t, &ip),
        _ => Decision::Stack,
    }
}

fn to(consumer: u8, flags: u16) -> Decision {
    Decision::Consumer { consumer, flags }
}

/// The owner of the ephemeral block a port-table value marks, when it is there.
fn block_owner(t: &Tables, mark: u8) -> Option<u8> {
    let c = mark.checked_sub(BLOCK_MARK)?;
    t.consumers
        .get(usize::from(c))
        .and_then(Option::as_ref)
        .filter(|x| !x.ring.is_broken())?;
    Some(c)
}

enum Pick {
    NoLive,
    Full,
    One(u8, u32),
}

/// A member of group `number` by `hash`, among the live ones with at least
/// `min_fill` cells (and room for a flow when `flows` asks for one).
fn pick(t: &Tables, number: u8, hash: u64, min_fill: u32, flows: bool) -> Pick {
    let Some(g) = t.group(number).filter(|g| !g.draining) else {
        return Pick::NoLive;
    };
    let limit = (t.flows.capacity() / 2) as u32;
    let live = |m: &&(u8, u32)| t.live(m.0, m.1);
    let fits = |m: &&(u8, u32)| {
        let c = t.consumers[usize::from(m.0)].as_ref().expect("live");
        c.ring.fill_avail() >= min_fill && !(flows && c.flows >= limit)
    };
    let n = g.members.iter().flatten().filter(live).filter(fits).count();
    if n == 0 {
        return if g.members.iter().flatten().any(|m| live(&m)) {
            Pick::Full
        } else {
            Pick::NoLive
        };
    }
    let m = g
        .members
        .iter()
        .flatten()
        .filter(live)
        .filter(fits)
        .nth((hash % n as u64) as usize);
    m.map_or(Pick::NoLive, |m| Pick::One(m.0, m.1))
}

fn udp(t: &mut Tables, ip: &Ip) -> Decision {
    let (sport, dport) = ports(ip.part);
    if dport == 68 {
        return Decision::Stack;
    }
    let mark = t.port(Proto::Udp, dport);
    if let Some(c) = block_owner(t, mark) {
        return to(c, 0);
    }
    let key = FlowKey {
        peer: ip.src,
        peer_port: sport,
        own_port: dport,
    };
    match pick(t, mark, t.flows.hash(&key), 0, false) {
        Pick::One(c, _) => to(c, 0),
        _ => Decision::Stack,
    }
}

fn tcp(t: &mut Tables, ip: &Ip) -> Decision {
    let (sport, dport) = ports(ip.part);
    let flags = ip.part[13];
    let syn = flags & (SYN | ACK) == SYN;
    let mark = t.port(Proto::Tcp, dport);
    let group = (1..=MAX_GROUPS as u8).contains(&mark);
    if !group && block_owner(t, mark).is_none() {
        return Decision::Stack;
    }
    let key = FlowKey {
        peer: ip.src,
        peer_port: sport,
        own_port: dport,
    };
    let found = t.flows.find(&key);
    if let Some(i) = found {
        let f = *t.flows.get(i);
        // A live owner keeps the flow, a SYN included: it is a member of the group, and a
        // forged SYN must not hand the connection to another one.
        if t.live(f.consumer, f.generation) {
            note(t, i, flags, FIN_IN);
            return to(f.consumer, 0);
        }
    }
    if !group || !syn {
        return Decision::Stack;
    }
    let (c, generation) = match pick(t, mark, t.flows.hash(&key), MIN_FILL, true) {
        Pick::NoLive if t.group(mark).is_some_and(|g| !g.draining && g.holders > 0) => {
            return Decision::Drop(Why::NoMember);
        }
        Pick::NoLive => return Decision::Stack,
        Pick::Full => return Decision::Drop(Why::AllFull),
        Pick::One(c, g) => (c, g),
    };
    let now = t.now;
    match found {
        Some(i) => t.flows.reassign(i, c, generation, now, true),
        None if !t.insert_embryo(&key, c, generation, mark) => {
            return Decision::Drop(Why::FlowsFull);
        }
        None => {}
    }
    if let Some(x) = t.consumers[usize::from(c)].as_mut() {
        x.flows += 1;
    }
    to(c, 0)
}

/// The time and the marks of a segment that belongs to flow `i`.
fn note(t: &mut Tables, i: usize, flags: u8, fin: u16) {
    let peer = fin == FIN_IN;
    let confirms = if peer {
        flags & (SYN | ACK | RSTBIT) == ACK
    } else {
        flags & (SYN | ACK) != SYN | ACK
    };
    if confirms {
        t.flows.confirm(i);
    }
    let now = t.now;
    let f = t.flows.get(i);
    // An unconfirmed flow ages from its SYN: repeating the SYN does not keep it.
    if f.flags & UNCONFIRMED == 0 {
        f.seen = now;
    }
    if flags & (SYN | ACK) == SYN && peer {
        f.flags &= !(RST | RST_PEER | FIN_IN | FIN_OUT);
    }
    if flags & RSTBIT != 0 {
        f.flags |= if peer { RST_PEER } else { RST };
    } else {
        f.flags &= !RST_PEER;
    }
    if flags & FIN != 0 {
        f.flags |= fin;
    }
}

/// An ICMP error goes to the owner of the flow or port the header it carries names.
fn icmp(t: &mut Tables, ip: &Ip) -> Decision {
    let part = ip.part;
    if part.len() < 8 + 20 + 8 || !matches!(part[0], 3 | 11) {
        return Decision::Stack;
    }
    let inner = &part[8..];
    let ihl = usize::from(inner[0] & 15) * 4;
    if inner[0] >> 4 != 4 || ihl < 20 || inner.len() < ihl + 8 || inner[12..16] != t.own.ip {
        return Decision::Stack;
    }
    let (sport, dport) = ports(&inner[ihl..]);
    let key = FlowKey {
        peer: inner[16..20].try_into().expect("4 bytes"),
        peer_port: dport,
        own_port: sport,
    };
    match inner[9] {
        IPV4_PROTO_TCP => match t.flows.find(&key) {
            Some(i) => {
                let f = *t.flows.get(i);
                if t.live(f.consumer, f.generation) {
                    to(f.consumer, DONE_ICMP_ERROR)
                } else {
                    Decision::Stack
                }
            }
            None => Decision::Stack,
        },
        IPV4_PROTO_UDP => {
            let mark = t.port(Proto::Udp, sport);
            if let Some(c) = block_owner(t, mark) {
                return to(c, DONE_ICMP_ERROR);
            }
            match pick(t, mark, t.flows.hash(&key), 0, false) {
                Pick::One(c, _) => to(c, DONE_ICMP_ERROR),
                _ => Decision::Stack,
            }
        }
        _ => Decision::Stack,
    }
}

/// Carries out a decision on the consumers: the frame goes into the rings
/// it is for. True when the stack wants it too.
pub fn deliver(t: &mut Tables, d: Decision, frame: &[u8]) -> bool {
    match d {
        Decision::Consumer { consumer, flags } => {
            if let Some(c) = t.consumers[usize::from(consumer)].as_mut() {
                c.ring.deliver(frame, flags);
            }
            false
        }
        Decision::ArpAll => {
            for c in t
                .consumers
                .iter_mut()
                .flatten()
                .filter(|c| !c.ring.is_broken())
            {
                c.ring.deliver(frame, DONE_ARP_COPY);
            }
            true
        }
        Decision::Stack => true,
        Decision::Drop(_) => false,
    }
}

fn refuse(r: Reason) -> Verdict {
    Verdict::Refuse(r)
}

/// Whether a consumer may send `frame` (a copy in the switch's buffer).
pub fn check_tx(t: &mut Tables, c: u8, frame: &[u8]) -> Verdict {
    t.guard.check();
    let v = verdict(t, c, frame);
    if let Verdict::Refuse(r) = v {
        t.refused[r as usize] += 1;
        if let Some(x) = t.consumers[usize::from(c)].as_mut() {
            x.ring.refused = x.ring.refused.wrapping_add(1);
        }
    }
    v
}

fn verdict(t: &mut Tables, c: u8, frame: &[u8]) -> Verdict {
    if !(ETHERNET_HEADER..=FRAME_MAX).contains(&frame.len()) {
        return refuse(Reason::Length);
    }
    if frame[6..12] != t.own.mac {
        return refuse(Reason::SrcMac);
    }
    let broadcast = frame[..6] == [0xff; 6];
    if frame[0] & 1 != 0 && !broadcast {
        return refuse(Reason::DstMac);
    }
    if frame[12..14] == ETHERTYPE_ARP {
        return arp_tx(t, c, frame);
    }
    if frame[12..14] != ETHERTYPE_IPV4 || broadcast {
        return refuse(if broadcast {
            Reason::DstMac
        } else {
            Reason::Proto
        });
    }
    let Some(ip) = ipv4(frame) else {
        return refuse(Reason::Ipv4);
    };
    if ip.fragment {
        return refuse(Reason::Fragment);
    }
    // Options (source routes, record route) are never sent by the stack of a consumer.
    if ip.options {
        return refuse(Reason::Ipv4);
    }
    if ip.src != t.own.ip || t.own.ip == [0; 4] {
        return refuse(Reason::SrcAddr);
    }
    if ip.dst != t.own.ip && !unicast_elsewhere(t, ip.dst) {
        return refuse(Reason::DstAddr);
    }
    let ok = match ip.proto {
        IPV4_PROTO_TCP if ip.part.len() >= 20 => tcp_tx(t, c, &ip),
        IPV4_PROTO_UDP if ip.part.len() >= 8 => udp_tx(t, c, &ip),
        IPV4_PROTO_TCP | IPV4_PROTO_UDP => Err(Reason::Ipv4),
        _ => Err(Reason::Proto),
    };
    match ok {
        // A turn to the ports of the stack's DHCP client and its server side is refused.
        Ok(())
            if ip.dst == t.own.ip
                && ip.proto == IPV4_PROTO_UDP
                && matches!(ports(ip.part).1, 67 | 68) =>
        {
            refuse(Reason::Udp)
        }
        Ok(()) if ip.dst == t.own.ip => Verdict::Hairpin,
        Ok(()) => Verdict::Send,
        Err(r) => refuse(r),
    }
}

/// A destination that is no broadcast, multicast, loopback or "this host".
fn unicast_elsewhere(t: &Tables, dst: [u8; 4]) -> bool {
    let d = u32::from_be_bytes(dst);
    let mask = u32::MAX
        .checked_shl(32 - u32::from(t.own.prefix))
        .unwrap_or(0);
    let directed = t.own.prefix < 31 && d == u32::from_be_bytes(t.own.ip) | !mask;
    !(dst[0] == 0 || dst[0] == 127 || dst[0] >= 224 || directed)
}

fn arp_tx(t: &mut Tables, c: u8, frame: &[u8]) -> Verdict {
    if !is_arp(frame) || frame[14..20] != [0, 1, 8, 0, 6, 4] || arp_oper(frame) != 1 {
        return refuse(Reason::ArpKind);
    }
    if frame[22..28] != t.own.mac || frame[28..32] != t.own.ip {
        return refuse(Reason::ArpSender);
    }
    let now = t.now;
    match t.consumers[usize::from(c)].as_mut() {
        Some(x) => {
            if x.arp_allowed(now) {
                Verdict::Send
            } else {
                refuse(Reason::ArpRate)
            }
        }
        None => refuse(Reason::ArpRate),
    }
}

fn tcp_tx(t: &mut Tables, c: u8, ip: &Ip) -> Result<(), Reason> {
    let (sport, dport) = ports(ip.part);
    let flags = ip.part[13];
    let syn = flags & (SYN | ACK) == SYN;
    let Some(me) = t.consumers[usize::from(c)].as_ref() else {
        return Err(Reason::Tcp);
    };
    let (generation, in_block, owned) = (me.generation, me.in_block(sport), me.flows);
    let key = FlowKey {
        peer: ip.dst,
        peer_port: dport,
        own_port: sport,
    };
    let now = t.now;
    if let Some(i) = t.flows.find(&key) {
        let f = *t.flows.get(i);
        let mine = f.consumer == c && f.generation == generation;
        if mine && !(f.closing() && syn) {
            note(t, i, flags, FIN_OUT);
            return Ok(());
        }
        let free = mine || !t.live(f.consumer, f.generation);
        if !(syn && in_block && free) {
            return Err(Reason::Tcp);
        }
        t.flows.reassign(i, c, generation, now, false);
        if !mine {
            t.consumers[usize::from(c)].as_mut().expect("there").flows += 1;
        }
        return Ok(());
    }
    if !(syn && in_block) {
        return Err(Reason::Tcp);
    }
    if owned >= (t.flows.capacity() / 2) as u32
        || t.flows.insert(&key, c, generation, now).is_none()
    {
        return Err(Reason::Flows);
    }
    t.consumers[usize::from(c)].as_mut().expect("there").flows += 1;
    Ok(())
}

fn udp_tx(t: &mut Tables, c: u8, ip: &Ip) -> Result<(), Reason> {
    let sport = ports(ip.part).0;
    let mark = t.port(Proto::Udp, sport);
    let member = t.group(mark).is_some_and(|g| {
        g.proto == Proto::Udp
            && g.members
                .iter()
                .flatten()
                .any(|m| m.0 == c && t.live(m.0, m.1))
    });
    if member || mark == BLOCK_MARK + c {
        Ok(())
    } else {
        Err(Reason::Udp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::switchlogic::ring::tests::Rig;
    use crate::switchlogic::tables::tests::{OWN, Rng, with, with_flows};
    use proto_net::switch as sw;

    const PEER: [u8; 4] = [203, 0, 113, 9];
    const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 9];
    const OWN_IP: [u8; 4] = OWN.ip;

    fn ip_frame(
        src: ([u8; 6], [u8; 4]),
        dst: ([u8; 6], [u8; 4]),
        proto: u8,
        part: &[u8],
    ) -> Vec<u8> {
        let mut f = [dst.0.as_slice(), &src.0, &[8, 0]].concat();
        let total = (20 + part.len()) as u16;
        f.extend([
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0x40,
            0,
            64,
            proto,
            0,
            0,
        ]);
        f.extend([src.1, dst.1].concat());
        f.extend(part);
        f
    }

    fn tcp_part(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = [sport.to_be_bytes(), dport.to_be_bytes()].concat();
        p.extend([0; 9]);
        p.extend([flags, 0, 0, 0, 0, 0, 0]);
        p
    }

    fn udp_part(sport: u16, dport: u16) -> Vec<u8> {
        [
            &sport.to_be_bytes()[..],
            &dport.to_be_bytes(),
            &[0, 12, 0, 0],
            &[1, 2, 3, 4],
        ]
        .concat()
    }

    const ME: ([u8; 6], [u8; 4]) = (OWN.mac, OWN_IP);
    const THEM: ([u8; 6], [u8; 4]) = (PEER_MAC, PEER);

    fn wire_tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        ip_frame(THEM, ME, 6, &tcp_part(sport, dport, flags))
    }
    fn wire_udp(sport: u16, dport: u16) -> Vec<u8> {
        ip_frame(THEM, ME, 17, &udp_part(sport, dport))
    }
    fn out_tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        ip_frame(ME, THEM, 6, &tcp_part(sport, dport, flags))
    }
    fn out_udp(sport: u16, dport: u16) -> Vec<u8> {
        ip_frame(ME, THEM, 17, &udp_part(sport, dport))
    }
    fn hair_tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        ip_frame(ME, ME, 6, &tcp_part(sport, dport, flags))
    }
    fn arp(oper: u8, sender_mac: [u8; 6], sender_ip: [u8; 4]) -> Vec<u8> {
        let mut f = [
            &[0xff; 6][..],
            &sender_mac,
            &[8, 6],
            &[0, 1, 8, 0, 6, 4, 0, oper],
        ]
        .concat();
        f.extend([sender_mac.as_slice(), &sender_ip, &[0; 6], &[10, 0, 2, 99]].concat());
        f
    }
    fn icmp_error(
        kind: u8,
        proto: u8,
        inner_src: [u8; 4],
        inner_dst: [u8; 4],
        sp: u16,
        dp: u16,
    ) -> Vec<u8> {
        let inner = ip_frame(
            ME,
            THEM,
            proto,
            &[&sp.to_be_bytes()[..], &dp.to_be_bytes(), &[0; 4]].concat(),
        );
        let mut inner = inner[14..].to_vec();
        inner[12..16].copy_from_slice(&inner_src);
        inner[16..20].copy_from_slice(&inner_dst);
        ip_frame(
            THEM,
            ME,
            1,
            &[&[kind, 1, 0, 0, 0, 0, 0, 0], inner.as_slice()].concat(),
        )
    }

    const SYN: u8 = 2;
    const SYN_ACK: u8 = 0x12;
    const ACK_: u8 = 0x10;
    const BLOCK0: u16 = 49152;
    const BLOCK2: u16 = 50176;

    fn who(d: Decision) -> u8 {
        match d {
            Decision::Consumer { consumer, .. } => consumer,
            other => panic!("{other:?}"),
        }
    }

    // ----- table 3.4, one test for a row -----

    #[test]
    fn arp_request_goes_to_the_stack() {
        with(|t, _| {
            assert_eq!(
                route(t, &arp(1, PEER_MAC, PEER), Source::Wire),
                Decision::Stack
            );
        });
    }

    #[test]
    fn arp_reply_goes_to_the_stack_and_a_copy_to_every_consumer() {
        with(|t, rigs| {
            let f = arp(2, PEER_MAC, PEER);
            let d = route(t, &f, Source::Wire);
            assert_eq!(d, Decision::ArpAll);
            assert!(deliver(t, d, &f), "the stack takes it too");
            for rig in rigs {
                let (done, bytes) = rig.done(0);
                assert_eq!((done.flags, bytes), (sw::DONE_ARP_COPY, f.clone()));
            }
            // A forgery with our own address as the sender is dropped.
            assert_eq!(
                route(t, &arp(2, PEER_MAC, OWN_IP), Source::Wire),
                Decision::Drop(Why::Forged)
            );
        });
    }

    #[test]
    fn what_is_not_for_the_shared_address_goes_to_the_stack() {
        with(|t, _| {
            let to_peer = ip_frame(THEM, THEM, 6, &tcp_part(1, 8080, SYN));
            let dhcp = ip_frame(THEM, ([0xff; 6], [255; 4]), 17, &udp_part(67, 68));
            let mut fragment = wire_tcp(1, 8080, SYN);
            fragment[14 + 6] = 0x20;
            let mut bad = wire_tcp(1, 8080, SYN);
            bad[14] = 0x65;
            for f in [
                to_peer,
                dhcp,
                fragment,
                bad,
                wire_tcp(1, 8080, SYN)[..30].to_vec(),
            ] {
                assert_eq!(route(t, &f, Source::Wire), Decision::Stack);
            }
            assert!(t.flows.is_empty());
            let spoofed = ip_frame(ME, ME, 6, &tcp_part(1, 8080, SYN));
            assert_eq!(
                route(t, &spoofed, Source::Wire),
                Decision::Drop(Why::Spoofed)
            );
        });
    }

    #[test]
    fn icmp_echo_and_errors_without_a_flow_go_to_the_stack() {
        with(|t, _| {
            let echo = ip_frame(THEM, ME, 1, &[8, 0, 0, 0, 0, 1, 0, 1]);
            assert_eq!(route(t, &echo, Source::Wire), Decision::Stack);
            let unknown = icmp_error(3, 6, OWN_IP, PEER, BLOCK0, 80);
            assert_eq!(route(t, &unknown, Source::Wire), Decision::Stack);
            let foreign_src = icmp_error(3, 6, PEER, OWN_IP, BLOCK0, 80);
            assert_eq!(route(t, &foreign_src, Source::Wire), Decision::Stack);
        });
    }

    #[test]
    fn an_icmp_error_goes_to_the_owner_of_the_embedded_flow() {
        with(|t, rigs| {
            assert_eq!(check_tx(t, 2, &out_tcp(BLOCK2, 80, SYN)), Verdict::Send);
            for kind in [3, 11] {
                let f = icmp_error(kind, 6, OWN_IP, PEER, BLOCK2, 80);
                let d = route(t, &f, Source::Wire);
                assert_eq!(
                    d,
                    Decision::Consumer {
                        consumer: 2,
                        flags: sw::DONE_ICMP_ERROR
                    }
                );
                deliver(t, d, &f);
            }
            assert_eq!(rigs[2].done(1).0.flags, sw::DONE_ICMP_ERROR);
            // UDP: by the port of the sender, a block or a group.
            let blocked = icmp_error(3, 17, OWN_IP, PEER, BLOCK2 + 7, 53);
            assert_eq!(who(route(t, &blocked, Source::Wire)), 2);
            let grouped = icmp_error(3, 17, OWN_IP, PEER, 5353, 53);
            assert!(who(route(t, &grouped, Source::Wire)) < 2);
        });
    }

    #[test]
    fn udp_goes_to_a_member_by_hash_without_a_flow_and_else_to_the_stack() {
        with(|t, _| {
            assert_eq!(route(t, &wire_udp(67, 68), Source::Wire), Decision::Stack);
            assert_eq!(
                route(t, &wire_udp(1000, 9999), Source::Wire),
                Decision::Stack
            );
            let mut seen = [0; 2];
            for sport in 1000..1200 {
                seen[usize::from(who(route(t, &wire_udp(sport, 5353), Source::Wire)))] += 1;
            }
            assert!(seen[0] > 40 && seen[1] > 40, "{seen:?}");
            let again = route(t, &wire_udp(1000, 5353), Source::Wire);
            assert_eq!(again, route(t, &wire_udp(1000, 5353), Source::Wire));
            assert!(t.flows.is_empty());
            assert_eq!(who(route(t, &wire_udp(53, BLOCK2 + 3), Source::Wire)), 2);
        });
    }

    #[test]
    fn tcp_without_a_group_goes_to_the_stack() {
        with(|t, _| {
            for flags in [SYN, ACK_] {
                assert_eq!(
                    route(t, &wire_tcp(1000, 22, flags), Source::Wire),
                    Decision::Stack
                );
            }
        });
    }

    #[test]
    fn a_syn_to_a_group_takes_a_member_by_hash_and_makes_the_flow() {
        with(|t, _| {
            let mut seen = [0; 2];
            for sport in 1000..1100 {
                let c = who(route(t, &wire_tcp(sport, 8080, SYN), Source::Wire));
                seen[usize::from(c)] += 1;
            }
            assert!(seen[0] > 20 && seen[1] > 20, "{seen:?}");
            assert_eq!(t.flows.len(), 100);
            assert_eq!(
                t.consumers[0].as_ref().unwrap().flows + t.consumers[1].as_ref().unwrap().flows,
                100
            );
        });
    }

    #[test]
    fn segments_follow_their_flow_and_a_non_syn_without_one_goes_to_the_stack() {
        with(|t, _| {
            let first = who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire));
            for flags in [ACK_, 0x18, 0x11] {
                assert_eq!(
                    who(route(t, &wire_tcp(1234, 8080, flags), Source::Wire)),
                    first
                );
            }
            assert_eq!(
                route(t, &wire_tcp(1235, 8080, ACK_), Source::Wire),
                Decision::Stack
            );
            assert_eq!(t.flows.len(), 1);
        });
    }

    #[test]
    fn a_syn_skips_members_short_of_cells_and_waits_for_none_when_all_are() {
        with(|t, rigs| {
            for _ in 0..40 {
                t.consumers[0].as_mut().unwrap().ring.deliver(b"x", 0);
            }
            assert!(t.consumers[0].as_ref().unwrap().ring.fill_avail() < MIN_FILL);
            for sport in 1000..1050 {
                assert_eq!(who(route(t, &wire_tcp(sport, 8080, SYN), Source::Wire)), 1);
            }
            // An old flow of the short member still gets its segments.
            for _ in 0..40 {
                t.consumers[1].as_mut().unwrap().ring.deliver(b"x", 0);
            }
            assert_eq!(
                route(t, &wire_tcp(5000, 8080, SYN), Source::Wire),
                Decision::Drop(Why::AllFull)
            );
            rigs[1].fill(&[1; 40]);
            t.poll_rings(|_, _| {});
            assert_eq!(who(route(t, &wire_tcp(5000, 8080, SYN), Source::Wire)), 1);
        });
    }

    #[test]
    fn a_group_without_live_members_drops_the_syn_while_it_has_holders() {
        with(|t, _| {
            t.leave(1, 0);
            t.leave(1, 1);
            assert_eq!(
                route(t, &wire_tcp(1, 8080, SYN), Source::Wire),
                Decision::Drop(Why::NoMember)
            );
            t.join(1, 0);
            t.detach(0);
            assert_eq!(
                route(t, &wire_tcp(1, 8080, SYN), Source::Wire),
                Decision::Drop(Why::NoMember)
            );
        });
    }

    #[test]
    fn a_dead_flow_is_replaced_by_the_next_syn_and_a_stale_one_gets_no_segments() {
        with(|t, rigs| {
            let c = who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire));
            let other = 1 - c;
            // The member goes and comes back with a new generation: the old flow is dead.
            t.detach(c);
            assert!(t.attach(
                c,
                2,
                rigs[usize::from(c)].ring(),
                49152 + 512 * u16::from(c)
            ));
            assert_eq!(
                route(t, &wire_tcp(1234, 8080, ACK_), Source::Wire),
                Decision::Stack
            );
            t.join(1, c);
            rigs[usize::from(c)].fill(&[0; 40]);
            t.poll_rings(|_, _| {});
            let d = route(t, &wire_tcp(1234, 8080, SYN), Source::Wire);
            assert!(who(d) == c || who(d) == other);
            assert_eq!(
                who(route(t, &wire_tcp(1234, 8080, ACK_), Source::Wire)),
                who(d)
            );
            assert_eq!(t.flows.len(), 1, "the entry is reused");
        });
    }

    #[test]
    fn tcp_on_a_block_port_follows_the_flow_or_goes_to_the_stack() {
        with(|t, _| {
            assert_eq!(
                route(t, &wire_tcp(80, BLOCK2 + 9, SYN_ACK), Source::Wire),
                Decision::Stack
            );
            assert_eq!(check_tx(t, 2, &out_tcp(BLOCK2 + 9, 80, SYN)), Verdict::Send);
            assert_eq!(
                who(route(t, &wire_tcp(80, BLOCK2 + 9, SYN_ACK), Source::Wire)),
                2
            );
            assert_eq!(
                route(t, &wire_tcp(81, BLOCK2 + 9, SYN_ACK), Source::Wire),
                Decision::Stack
            );
        });
    }

    #[test]
    fn rst_and_fin_from_both_sides_close_the_flow_and_a_syn_reuses_it() {
        with(|t, _| {
            let c = who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire));
            let i = t
                .flows
                .find(&FlowKey {
                    peer: PEER,
                    peer_port: 1234,
                    own_port: 8080,
                })
                .unwrap();
            route(t, &wire_tcp(1234, 8080, 0x11), Source::Wire);
            assert!(!t.flows.get(i).closing());
            assert_eq!(check_tx(t, c, &out_tcp(8080, 1234, 0x11)), Verdict::Send);
            assert!(t.flows.get(i).closing());
            assert_eq!(who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire)), c);
            assert!(!t.flows.get(i).closing(), "a SYN starts the flow again");
            route(t, &wire_tcp(1234, 8080, 0x04), Source::Wire);
            assert!(t.flows.get(i).closing());
        });
    }

    #[test]
    fn a_consumer_holds_at_most_half_of_the_flows_and_a_full_table_drops_the_syn() {
        with_flows(64, |t, _| {
            assert_eq!(t.flows.capacity(), 32);
            let mut sent = 0;
            for sport in 0..40 {
                if check_tx(t, 2, &out_tcp(BLOCK2 + sport, 80, SYN)) == Verdict::Send {
                    sent += 1;
                }
            }
            assert_eq!(sent, 16);
            assert_eq!(t.refused[Reason::Flows as usize], 24);
            let mut taken = 0;
            for sport in 0..40 {
                taken += u32::from(matches!(
                    route(t, &wire_tcp(sport, 8080, SYN), Source::Wire),
                    Decision::Consumer { .. }
                ));
            }
            assert!(
                taken > 0 && taken <= 16,
                "a member at its limit gets no new SYN: {taken}"
            );
        });
    }

    fn wire_from(src: [u8; 4], sport: u16, flags: u8) -> Vec<u8> {
        ip_frame((PEER_MAC, src), ME, 6, &tcp_part(sport, 8080, flags))
    }

    fn random_source(r: &mut Rng) -> [u8; 4] {
        let v = r.next().to_le_bytes();
        // A host of the wire: not 0/8, 10/8 (the subnet), 127/8 or 224/4 and above.
        [1 + (v[0] % 9), v[1], v[2], v[3]]
    }

    #[test]
    fn a_flood_of_syns_from_random_addresses_leaves_room_and_the_confirmed_flows() {
        with_flows(256, |t, _| {
            let (cap, limit) = (t.flows.capacity(), t.flows.unconfirmed_limit());
            assert_eq!((cap, limit), (128, 32));
            // Real connections: the SYN, then the ACK that ends the handshake.
            let real: Vec<([u8; 4], u8)> = (0..6)
                .map(|n| {
                    let src = [198, 51, 100, n];
                    let c = who(route(t, &wire_from(src, 5000, SYN), Source::Wire));
                    assert_eq!(who(route(t, &wire_from(src, 5000, ACK_), Source::Wire)), c);
                    (src, c)
                })
                .collect();
            assert_eq!(t.flows.unconfirmed(), 0);
            let mut rng = Rng(0x9e3779b97f4a7c15);
            for _ in 0..10 * cap {
                let (src, sport) = (random_source(&mut rng), rng.next() as u16);
                route(t, &wire_from(src, sport, SYN), Source::Wire);
                assert!(t.flows.unconfirmed() <= limit);
                assert!(t.flows.len() <= cap);
            }
            assert!(t.flows.evicted > 0 && t.flows.unconfirmed() > 0);
            for (src, c) in &real {
                let d = route(t, &wire_from(*src, 5000, ACK_), Source::Wire);
                assert_eq!(who(d), *c, "an established flow survives");
            }
            let honest = route(t, &wire_from([203, 0, 113, 77], 4000, SYN), Source::Wire);
            assert!(matches!(honest, Decision::Consumer { .. }), "{honest:?}");
            let honest_ack = wire_from([203, 0, 113, 77], 4000, ACK_);
            assert_eq!(who(route(t, &honest_ack, Source::Wire)), who(honest));
        });
    }

    #[test]
    fn an_unconfirmed_flow_goes_after_thirty_seconds_and_a_repeated_syn_does_not_keep_it() {
        with_flows(256, |t, _| {
            t.now = 1000;
            let syn = |t: &mut Tables, n: u8| {
                route(t, &wire_from([198, 51, 100, n], 5000, SYN), Source::Wire)
            };
            syn(t, 1);
            let c2 = who(syn(t, 2));
            let ack = wire_from([198, 51, 100, 2], 5000, ACK_);
            assert_eq!(who(route(t, &ack, Source::Wire)), c2);
            t.now = 1020;
            syn(t, 1);
            assert_eq!(t.flows.unconfirmed(), 1);
            t.now = 1029;
            t.sweep();
            assert_eq!(t.flows.unconfirmed(), 1, "not yet");
            t.sweep_at(1031);
            assert_eq!((t.flows.unconfirmed(), t.flows.len()), (0, 1));
            assert_eq!(t.flows.expired, 1);
            let owned = |t: &Tables| t.consumers.iter().flatten().map(|c| c.flows).sum::<u32>();
            assert_eq!(
                owned(t),
                1,
                "the owner of the expired flow has its count back"
            );
        });
    }

    #[test]
    fn a_consumer_segment_but_a_syn_ack_confirms() {
        with(|t, _| {
            let c = who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire));
            assert_eq!(t.flows.unconfirmed(), 1);
            assert_eq!(check_tx(t, c, &out_tcp(8080, 1234, SYN_ACK)), Verdict::Send);
            assert_eq!(t.flows.unconfirmed(), 1, "the SYN-ACK does not");
            route(t, &wire_tcp(1234, 8080, 0x04), Source::Wire);
            route(t, &wire_tcp(1234, 8080, SYN), Source::Wire);
            assert_eq!(
                t.flows.unconfirmed(),
                1,
                "a RST or a SYN of the wire does not"
            );
            assert_eq!(check_tx(t, c, &out_tcp(8080, 1234, 0x18)), Verdict::Send);
            assert_eq!(t.flows.unconfirmed(), 0);
        });
    }

    #[test]
    fn syns_from_addresses_no_host_of_the_wire_has_make_no_flow() {
        with(|t, _| {
            for src in [
                [127, 0, 0, 1],
                [0, 0, 0, 0],
                [0, 1, 2, 3],
                [224, 0, 0, 5],
                [240, 1, 1, 1],
                [255; 4],
                [10, 0, 2, 255],
            ] {
                assert_eq!(
                    route(t, &wire_from(src, 5000, SYN), Source::Wire),
                    Decision::Drop(Why::Bogus),
                    "{src:?}"
                );
                let udp = ip_frame((PEER_MAC, src), ME, 17, &udp_part(1000, 5353));
                assert_eq!(route(t, &udp, Source::Wire), Decision::Drop(Why::Bogus));
            }
            assert!(t.flows.is_empty());
        });
    }

    fn flags_of(t: &mut Tables, sport: u16) -> u16 {
        let key = FlowKey {
            peer: PEER,
            peer_port: sport,
            own_port: 8080,
        };
        let i = t.flows.find(&key).unwrap();
        t.flows.get(i).flags
    }

    #[test]
    fn a_rst_of_the_wire_is_cleared_by_the_next_segment_of_either_side() {
        with(|t, _| {
            let c = who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire));
            assert_eq!(check_tx(t, c, &out_tcp(8080, 1234, SYN_ACK)), Verdict::Send);
            route(t, &wire_tcp(1234, 8080, ACK_), Source::Wire);
            // A blind RST, then the stack's challenge ACK and the peer's real segment.
            route(t, &wire_tcp(1234, 8080, 0x04), Source::Wire);
            assert_ne!(flags_of(t, 1234) & RST_PEER, 0);
            assert_eq!(check_tx(t, c, &out_tcp(8080, 1234, ACK_)), Verdict::Send);
            assert_eq!(
                flags_of(t, 1234) & (RST | RST_PEER),
                0,
                "the consumer's ACK"
            );
            route(t, &wire_tcp(1234, 8080, 0x04), Source::Wire);
            assert_eq!(who(route(t, &wire_tcp(1234, 8080, ACK_), Source::Wire)), c);
            assert_eq!(flags_of(t, 1234) & (RST | RST_PEER), 0, "the peer's ACK");
            // Two RSTs in a row stay marked.
            route(t, &wire_tcp(1234, 8080, 0x04), Source::Wire);
            route(t, &wire_tcp(1234, 8080, 0x04), Source::Wire);
            assert!(
                t.flows
                    .get(
                        t.flows
                            .find(&FlowKey {
                                peer: PEER,
                                peer_port: 1234,
                                own_port: 8080
                            })
                            .unwrap()
                    )
                    .closing()
            );
        });
    }

    #[test]
    fn a_syn_after_a_rst_keeps_the_owner_and_the_count() {
        with(|t, _| {
            let c = who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire));
            let before = t.consumers[usize::from(c)].as_ref().unwrap().flows;
            route(t, &wire_tcp(1234, 8080, 0x04), Source::Wire);
            for _ in 0..5 {
                assert_eq!(who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire)), c);
            }
            assert_eq!(t.consumers[usize::from(c)].as_ref().unwrap().flows, before);
            assert_eq!(t.flows.len(), 1);
            assert_eq!(flags_of(t, 1234) & (RST | RST_PEER), 0);
        });
    }

    #[test]
    fn a_rst_of_the_consumer_closes_the_flow_for_good() {
        with(|t, _| {
            let c = who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire));
            assert_eq!(check_tx(t, c, &out_tcp(8080, 1234, 0x04)), Verdict::Send);
            assert_ne!(flags_of(t, 1234) & RST, 0);
            route(t, &wire_tcp(1234, 8080, ACK_), Source::Wire);
            assert_ne!(flags_of(t, 1234) & RST, 0, "an ACK does not reopen it");
            t.now = 100;
            (0..128).for_each(|_| t.sweep());
            assert!(t.flows.is_empty(), "a closed flow goes after its rest");
        });
    }

    #[test]
    fn a_released_group_drains_its_flows_and_is_freed_when_the_last_is_gone() {
        with(|t, _| {
            let c = who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire));
            route(t, &wire_tcp(1234, 8080, ACK_), Source::Wire);
            assert_eq!(t.group(1).unwrap().flows, 1);
            t.release(1);
            assert!(t.group(1).unwrap().draining);
            assert_eq!(
                (t.port(Proto::Tcp, 8080), t.freed),
                (1, 0),
                "the port stays"
            );
            // The flow goes on; a new SYN is the stack's (RST); nothing can join or hold.
            assert_eq!(who(route(t, &wire_tcp(1234, 8080, ACK_), Source::Wire)), c);
            assert_eq!(
                route(t, &wire_tcp(1300, 8080, SYN), Source::Wire),
                Decision::Stack
            );
            assert!(!t.join(1, 2) && !t.hold(1, Proto::Tcp, 8080, 1));
            assert!(!t.hold(5, Proto::Tcp, 8080, 1), "the port is not free yet");
            assert_eq!(check_tx(t, c, &out_tcp(8080, 1234, ACK_)), Verdict::Send);
            // The flow ends: both FINs, a rest, the sweep.
            route(t, &wire_tcp(1234, 8080, 0x11), Source::Wire);
            assert_eq!(check_tx(t, c, &out_tcp(8080, 1234, 0x11)), Verdict::Send);
            t.now = 50;
            (0..128).for_each(|_| t.sweep());
            assert!(t.flows.is_empty() && t.group(1).is_none());
            assert_eq!((t.port(Proto::Tcp, 8080), t.freed), (0, 1));
            assert!(t.hold(5, Proto::Tcp, 8080, 1));
        });
    }

    #[test]
    fn a_released_group_without_flows_is_freed_at_once_and_a_udp_group_always() {
        with(|t, _| {
            t.release(1);
            assert!(t.group(1).is_none() && t.freed == 1);
            route(t, &wire_udp(1000, 5353), Source::Wire);
            t.release(2);
            assert!(t.group(2).is_none() && t.freed == 3);
            assert_eq!(t.port(Proto::Udp, 5353), 0);
        });
    }

    #[test]
    fn an_evicted_flow_leaves_its_group_count() {
        with_flows(64, |t, _| {
            for n in 0..40 {
                route(t, &wire_from([198, 51, 100, n], 5000, SYN), Source::Wire);
            }
            assert_eq!(t.group(1).unwrap().flows as usize, t.flows.len());
        });
    }

    #[test]
    fn a_flow_of_an_old_consumer_does_not_revive_after_many_attach_cycles_without_a_sweep() {
        with(|t, rigs| {
            let c = who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire));
            let rig = &rigs[usize::from(c)];
            let block = 49152 + 512 * u16::from(c);
            assert_eq!(check_tx(t, c, &out_tcp(8080, 1234, ACK_)), Verdict::Send);
            let mut fresh = Vec::new();
            for g in 2..=600u32 {
                assert!(t.detach(c).is_some());
                fresh.push(Rig::new(rig.layout));
                fresh.last().unwrap().fill(&[0; 40]);
                assert!(t.attach(c, g, fresh.last().unwrap().ring(), block));
                t.poll_rings(|_, _| {});
            }
            t.join(1, c);
            assert!(!t.live(c, 1) && t.live(c, 600));
            assert_eq!(
                route(t, &wire_tcp(1234, 8080, ACK_), Source::Wire),
                Decision::Stack,
                "the old flow is not live"
            );
            assert_eq!(refused(t, c, &out_tcp(8080, 1234, ACK_)), Reason::Tcp);
            assert_eq!(refused(t, c, &out_tcp(8080, 1234, 0x04)), Reason::Tcp);
        });
    }

    // ----- hostile values -----

    /// The frame with `n` bytes of IPv4 options (NOPs) after the 20-byte header.
    fn with_options(f: &[u8], n: usize) -> Vec<u8> {
        let mut f = f.to_vec();
        f[14] = 0x45 + (n / 4) as u8;
        let total = u16::from_be_bytes([f[16], f[17]]) + n as u16;
        f[16..18].copy_from_slice(&total.to_be_bytes());
        f.splice(34..34, vec![1; n]);
        f
    }

    #[test]
    fn ipv4_options_move_the_transport_part_in_both_directions() {
        with(|t, _| {
            let syn = with_options(&wire_tcp(1234, 8080, SYN), 8);
            let c = who(route(t, &syn, Source::Wire));
            let ack = with_options(&wire_tcp(1234, 8080, ACK_), 4);
            assert_eq!(who(route(t, &ack, Source::Wire)), c);
            // The consumer's own frames carry no options: refused whatever they hide.
            let tx = with_options(&out_tcp(8080, 1234, ACK_), 4);
            assert_eq!(refused(t, c, &tx), Reason::Ipv4);
            // Options that run past the packet are no packet.
            let mut wire = with_options(&wire_tcp(1234, 8080, ACK_), 4);
            wire[14] = 0x4f;
            assert_eq!(route(t, &wire, Source::Wire), Decision::Stack);
            let mut long = with_options(&out_tcp(8080, 1234, ACK_), 4);
            long[14] = 0x4f;
            assert_eq!(refused(t, c, &long), Reason::Ipv4);
        });
    }

    #[test]
    fn a_vlan_tag_makes_a_frame_no_ipv4_and_an_icmp_with_a_short_inner_header_goes_to_the_stack() {
        with(|t, _| {
            let mut tagged = out_tcp(BLOCK0, 80, SYN);
            tagged[12..14].copy_from_slice(&[0x81, 0x00]);
            assert_eq!(refused(t, 0, &tagged), Reason::Proto);
            let mut wire = wire_tcp(1234, 8080, SYN);
            wire[12..14].copy_from_slice(&[0x81, 0x00]);
            assert_eq!(route(t, &wire, Source::Wire), Decision::Stack);
            assert!(t.flows.is_empty());
            assert_eq!(check_tx(t, 2, &out_tcp(BLOCK2, 80, SYN)), Verdict::Send);
            let good = icmp_error(3, 6, OWN_IP, PEER, BLOCK2, 80);
            assert_eq!(who(route(t, &good, Source::Wire)), 2);
            // The embedded header claims options the packet does not carry, or ends in
            // fewer than 8 bytes after its own header.
            let mut long_ihl = good.clone();
            long_ihl[14 + 20 + 8] = 0x4f;
            assert_eq!(route(t, &long_ihl, Source::Wire), Decision::Stack);
            for cut in 1..=8 {
                let mut short = good.clone();
                short.truncate(good.len() - cut);
                let total = (short.len() - 14) as u16;
                short[16..18].copy_from_slice(&total.to_be_bytes());
                assert_eq!(route(t, &short, Source::Wire), Decision::Stack, "{cut}");
            }
        });
    }

    #[test]
    fn blind_rsts_at_random_four_tuples_make_no_flow_and_leave_the_established_ones() {
        with(|t, _| {
            let real: Vec<([u8; 4], u8)> = (0..10)
                .map(|n| {
                    let src = [198, 51, 100, n];
                    let c = who(route(t, &wire_from(src, 5000, SYN), Source::Wire));
                    route(t, &wire_from(src, 5000, ACK_), Source::Wire);
                    (src, c)
                })
                .collect();
            let mut rng = Rng(0x2545f4914f6cdd1d);
            for _ in 0..20_000 {
                let (src, sport) = (random_source(&mut rng), rng.next() as u16);
                let rst = rng.below(3) as u8 * 0x10 + 4;
                route(t, &wire_from(src, sport, rst), Source::Wire);
            }
            assert_eq!(t.flows.len(), real.len());
            for (src, c) in real {
                assert_eq!(who(route(t, &wire_from(src, 5000, ACK_), Source::Wire)), c);
            }
        });
    }

    fn samples() -> Vec<Vec<u8>> {
        vec![
            wire_tcp(1234, 8080, SYN),
            wire_tcp(1234, 8080, ACK_),
            wire_udp(1000, 5353),
            out_tcp(BLOCK2, 80, SYN),
            out_tcp(8080, 1234, SYN_ACK),
            out_udp(5353, 9),
            hair_tcp(BLOCK2, 8080, SYN),
            icmp_error(3, 6, OWN_IP, PEER, BLOCK2, 80),
            icmp_error(11, 17, OWN_IP, PEER, 5353, 53),
            arp(2, PEER_MAC, PEER),
            arp(1, OWN.mac, OWN_IP),
        ]
    }

    /// A sample with up to six bytes spoilt, cut short or stretched.
    fn mutant(rng: &mut Rng, samples: &[Vec<u8>]) -> Vec<u8> {
        let mut f = samples[rng.below(samples.len())].clone();
        for _ in 0..rng.below(7) {
            // Half of the hits land in the Ethernet and IP headers and the first transport bytes.
            let span = if rng.below(2) == 0 {
                48.min(f.len())
            } else {
                f.len()
            };
            let at = rng.below(span);
            f[at] = match rng.below(4) {
                0 => 0,
                1 => 0xff,
                _ => rng.next() as u8,
            };
        }
        match rng.below(4) {
            0 => f.truncate(rng.below(f.len() + 1)),
            1 => {
                let more = rng.below(1700);
                f.extend((0..more).map(|_| rng.next() as u8));
            }
            _ => {}
        }
        f
    }

    #[test]
    fn route_deliver_and_check_tx_hold_their_invariants_on_hostile_frames() {
        let samples = samples();
        with_flows(1024, |t, rigs| {
            let mut rng = Rng(0x853c49e6748fea9b);
            let mut sent = [0u32; 3];
            for round in 0..60_000u32 {
                if round % 50 == 0 {
                    for (c, rig) in rigs.iter().enumerate() {
                        let done = rig.mem().load(sw::DONE_HEAD);
                        rig.mem().store(sw::DONE_TAIL, done);
                        let avail = t.consumers[c].as_ref().unwrap().ring.fill_avail();
                        rig.fill(&vec![0; 64 - avail as usize]);
                    }
                    t.poll_rings(|_, _| panic!("a ring broke"));
                    t.now = round / 50;
                    t.sweep();
                }
                let f = mutant(&mut rng, &samples);
                for from in [Source::Wire, Source::Stack, Source::Consumer(1)] {
                    let d = route(t, &f, from);
                    if let (Decision::Consumer { consumer, .. }, Some(ip)) = (d, ipv4(&f)) {
                        assert!(usize::from(consumer) < 3);
                        assert!(!ip.fragment && ip.dst == OWN_IP);
                        if from == Source::Wire {
                            assert!(ip.src != OWN_IP, "a wire frame with our address");
                            assert!(unicast_elsewhere(t, ip.src), "{:?}", ip.src);
                        }
                    }
                    if matches!(d, Decision::Consumer { .. }) && ipv4(&f).is_none() {
                        panic!("a frame that is no IPv4 went to a consumer: {f:?}");
                    }
                    deliver(t, d, &f);
                }
                for c in 0..3u8 {
                    let v = check_tx(t, c, &f);
                    if !matches!(v, Verdict::Send | Verdict::Hairpin) {
                        continue;
                    }
                    sent[usize::from(c)] += 1;
                    assert!((14..=sw::FRAME_MAX).contains(&f.len()));
                    assert_eq!(f[6..12], OWN.mac, "a foreign source MAC");
                    assert!(f[0] & 1 == 0 || f[..6] == [0xff; 6]);
                    if f[12..14] == ETHERTYPE_ARP {
                        assert!(is_arp(&f) && arp_oper(&f) == 1);
                        assert!(f[22..28] == OWN.mac && f[28..32] == OWN_IP);
                        continue;
                    }
                    let ip = ipv4(&f).expect("only IPv4 and ARP leave");
                    assert!(!ip.fragment, "a fragment left");
                    assert_eq!(ip.src, OWN_IP, "a foreign source address");
                    assert!(matches!(ip.proto, 6 | 17));
                    assert_eq!(v == Verdict::Hairpin, ip.dst == OWN_IP);
                    assert!(ip.dst == OWN_IP || unicast_elsewhere(t, ip.dst));
                }
            }
            assert!(
                sent.iter().all(|n| *n > 0),
                "the samples get through now and then: {sent:?}"
            );
        });
    }

    #[test]
    fn flood_of_hostile_syns_and_rsts_keeps_the_tables_whole() {
        with_flows(512, |t, _| {
            let mut rng = Rng(0xda942042e4dd58b5);
            for n in 0..30_000u32 {
                let (src, sport) = (random_source(&mut rng), rng.next() as u16);
                let flags = [SYN, SYN, ACK_, 0x04, 0x11, 0x12][rng.below(6)];
                t.now = n / 100;
                route(t, &wire_from(src, sport, flags), Source::Wire);
                if n % 100 == 0 {
                    t.sweep();
                }
                assert!(t.flows.len() <= t.flows.capacity());
                assert!(t.flows.unconfirmed() <= t.flows.unconfirmed_limit());
            }
            let owned: u32 = t.consumers.iter().flatten().map(|c| c.flows).sum();
            let grouped = t.group(1).unwrap().flows;
            assert_eq!(
                (owned, grouped),
                (t.flows.len() as u32, t.flows.len() as u32)
            );
        });
    }

    // ----- the send check, one test for a rule -----

    fn refused(t: &mut Tables, c: u8, f: &[u8]) -> Reason {
        match check_tx(t, c, f) {
            Verdict::Refuse(r) => r,
            v => panic!("{v:?}"),
        }
    }

    #[test]
    fn rule_1_frames_from_1515_bytes_up_are_refused() {
        with(|t, _| {
            let good = out_udp(BLOCK0, 53);
            for len in [1514, 1515, 1600, 2048, 2049, 4000] {
                let mut f = good.clone();
                f.resize(len, 0);
                let v = check_tx(t, 0, &f);
                assert_eq!(v == Verdict::Send, len == 1514, "{len}");
            }
        });
    }

    #[test]
    fn rule_1_length_and_ethernet() {
        with(|t, _| {
            let good = out_udp(BLOCK0, 53);
            assert_eq!(check_tx(t, 0, &good), Verdict::Send);
            assert_eq!(refused(t, 0, &good[..13]), Reason::Length);
            assert_eq!(
                refused(t, 0, &[good.clone(), vec![0; 1500]].concat()),
                Reason::Length
            );
            let mut mac = good.clone();
            mac[6] ^= 1;
            assert_eq!(refused(t, 0, &mac), Reason::SrcMac);
            let mut multi = good.clone();
            multi[0] = 1;
            assert_eq!(refused(t, 0, &multi), Reason::DstMac);
            let mut broadcast = good;
            broadcast[..6].fill(0xff);
            assert_eq!(refused(t, 0, &broadcast), Reason::DstMac);
            assert_eq!(t.consumers[0].as_ref().unwrap().ring.refused, 5);
        });
    }

    #[test]
    fn rule_2_arp_is_a_request_from_the_shared_mac_and_address_ten_a_second() {
        with(|t, _| {
            t.now = 5;
            assert_eq!(check_tx(t, 0, &arp(1, OWN.mac, OWN_IP)), Verdict::Send);
            assert_eq!(refused(t, 0, &arp(2, OWN.mac, OWN_IP)), Reason::ArpKind);
            assert_eq!(
                refused(t, 0, &arp(1, OWN.mac, [10, 0, 2, 77])),
                Reason::ArpSender
            );
            let mut other_mac = arp(1, OWN.mac, OWN_IP);
            other_mac[22] ^= 1;
            assert_eq!(refused(t, 0, &other_mac), Reason::ArpSender);
            for _ in 0..9 {
                assert_eq!(check_tx(t, 0, &arp(1, OWN.mac, OWN_IP)), Verdict::Send);
            }
            assert_eq!(refused(t, 0, &arp(1, OWN.mac, OWN_IP)), Reason::ArpRate);
            assert_eq!(
                check_tx(t, 1, &arp(1, OWN.mac, OWN_IP)),
                Verdict::Send,
                "per consumer"
            );
            t.now = 6;
            assert_eq!(check_tx(t, 0, &arp(1, OWN.mac, OWN_IP)), Verdict::Send);
        });
    }

    #[test]
    fn rule_3_ipv4_header_addresses_and_fragments() {
        with(|t, _| {
            let good = out_udp(BLOCK0, 53);
            let mut v6 = good.clone();
            v6[14] = 0x65;
            assert_eq!(refused(t, 0, &v6), Reason::Ipv4);
            let mut short = good.clone();
            short[14 + 3] = 200;
            assert_eq!(refused(t, 0, &short), Reason::Ipv4);
            let mut frag = good.clone();
            frag[14 + 6] = 0x20;
            assert_eq!(refused(t, 0, &frag), Reason::Fragment);
            let mut offset = good.clone();
            offset[14 + 7] = 8;
            assert_eq!(refused(t, 0, &offset), Reason::Fragment);
            let mut spoof = good.clone();
            spoof[14 + 12] = 9;
            assert_eq!(refused(t, 0, &spoof), Reason::SrcAddr);
            for dst in [
                [255; 4],
                [10, 0, 2, 255],
                [224, 0, 0, 1],
                [127, 0, 0, 1],
                [0; 4],
            ] {
                let mut f = good.clone();
                f[14 + 16..14 + 20].copy_from_slice(&dst);
                assert_eq!(refused(t, 0, &f), Reason::DstAddr, "{dst:?}");
            }
            let mut dont_fragment = good;
            dont_fragment[14 + 6] = 0x40;
            assert_eq!(check_tx(t, 0, &dont_fragment), Verdict::Send);
        });
    }

    #[test]
    fn rule_3_the_shared_address_as_destination_is_a_hairpin() {
        with(|t, _| {
            assert_eq!(
                check_tx(t, 0, &hair_tcp(BLOCK0, 9000, SYN)),
                Verdict::Hairpin
            );
            let udp = ip_frame(ME, ME, 17, &udp_part(BLOCK0, 53));
            assert_eq!(check_tx(t, 0, &udp), Verdict::Hairpin);
        });
    }

    #[test]
    fn rule_4_tcp_needs_an_owned_flow_or_a_syn_from_the_block() {
        with(|t, _| {
            // A SYN from the block makes the flow; its segments follow.
            assert_eq!(check_tx(t, 2, &out_tcp(BLOCK2, 80, SYN)), Verdict::Send);
            assert_eq!(check_tx(t, 2, &out_tcp(BLOCK2, 80, ACK_)), Verdict::Send);
            assert_eq!(
                check_tx(t, 2, &out_tcp(BLOCK2, 80, 0x04)),
                Verdict::Send,
                "its own RST"
            );
            // The other consumers cannot use the four, with a RST or without.
            assert_eq!(refused(t, 1, &out_tcp(BLOCK2, 80, ACK_)), Reason::Tcp);
            assert_eq!(refused(t, 1, &out_tcp(BLOCK2, 80, 0x04)), Reason::Tcp);
            assert_eq!(
                refused(t, 1, &out_tcp(BLOCK2, 80, SYN)),
                Reason::Tcp,
                "not from its block"
            );
            // An unknown four, a SYN|ACK, a SYN from outside the block.
            assert_eq!(refused(t, 2, &out_tcp(BLOCK2, 81, ACK_)), Reason::Tcp);
            assert_eq!(refused(t, 2, &out_tcp(BLOCK2, 81, SYN_ACK)), Reason::Tcp);
            assert_eq!(refused(t, 2, &out_tcp(8080, 81, SYN)), Reason::Tcp);
            // A member answers on the flow the switch made for it.
            let c = who(route(t, &wire_tcp(1234, 8080, SYN), Source::Wire));
            assert_eq!(check_tx(t, c, &out_tcp(8080, 1234, SYN_ACK)), Verdict::Send);
            assert_eq!(refused(t, 1 - c, &out_tcp(8080, 1234, ACK_)), Reason::Tcp);
            // A new generation does not inherit the flow.
            t.detach(c);
            let rig = Rig::new(sw::Layout::new(256, 64).unwrap());
            t.attach(c, 2, rig.ring(), 49152 + 512 * u16::from(c));
            assert_eq!(refused(t, c, &out_tcp(8080, 1234, ACK_)), Reason::Tcp);
        });
    }

    #[test]
    fn rule_5_udp_comes_from_a_group_of_the_member_or_its_block() {
        with(|t, _| {
            assert_eq!(check_tx(t, 0, &out_udp(5353, 9)), Verdict::Send);
            assert_eq!(check_tx(t, 1, &out_udp(5353, 9)), Verdict::Send);
            assert_eq!(
                refused(t, 2, &out_udp(5353, 9)),
                Reason::Udp,
                "not a member"
            );
            assert_eq!(check_tx(t, 2, &out_udp(BLOCK2 + 100, 9)), Verdict::Send);
            assert_eq!(
                refused(t, 0, &out_udp(BLOCK2 + 100, 9)),
                Reason::Udp,
                "another's block"
            );
            assert_eq!(refused(t, 0, &out_udp(9000, 9)), Reason::Udp);
            assert_eq!(
                refused(t, 0, &out_udp(8080, 9)),
                Reason::Udp,
                "a TCP group's port"
            );
        });
    }

    #[test]
    fn rule_6_everything_else_is_refused_and_counted() {
        with(|t, _| {
            let echo = ip_frame(ME, THEM, 1, &[8, 0, 0, 0, 0, 1, 0, 1]);
            assert_eq!(refused(t, 0, &echo), Reason::Proto);
            let ipv6 = [vec![0; 6], OWN.mac.to_vec(), vec![0x86, 0xdd], vec![0; 40]].concat();
            assert_eq!(refused(t, 0, &ipv6), Reason::Proto);
            assert_eq!(t.refused[Reason::Proto as usize], 2);
            assert_eq!(refused(t, 0, &out_udp(1, 1)), Reason::Udp);
        });
    }

    // ----- the hairpin of R-2a: four directions -----

    #[test]
    fn hairpin_a_program_of_the_guest_to_a_member() {
        with(|t, _| {
            let d = route(t, &hair_tcp(50000, 8080, SYN), Source::Stack);
            let b = who(d);
            let key = FlowKey {
                peer: OWN_IP,
                peer_port: 50000,
                own_port: 8080,
            };
            let f = *t.flows.get(t.flows.find(&key).unwrap());
            assert_eq!(f.consumer, b);
            // The member's answer goes back through the switch to the stack.
            assert_eq!(
                check_tx(t, b, &hair_tcp(8080, 50000, SYN_ACK)),
                Verdict::Hairpin
            );
            assert_eq!(
                route(t, &hair_tcp(8080, 50000, SYN_ACK), Source::Consumer(b)),
                Decision::Stack
            );
        });
    }

    #[test]
    fn hairpin_a_member_to_a_service_on_a_socket_of_the_stack() {
        with(|t, _| {
            let syn = hair_tcp(BLOCK0 + 5, 9000, SYN);
            assert_eq!(check_tx(t, 0, &syn), Verdict::Hairpin);
            assert_eq!(route(t, &syn, Source::Consumer(0)), Decision::Stack);
            // The service's reply comes from the stack to the consumer's block port.
            let reply = hair_tcp(9000, BLOCK0 + 5, SYN_ACK);
            assert_eq!(who(route(t, &reply, Source::Stack)), 0);
        });
    }

    #[test]
    fn hairpin_a_consumer_to_a_group_with_a_member_b_uses_two_keys() {
        with(|t, _| {
            let syn = hair_tcp(BLOCK2, 8080, SYN);
            assert_eq!(check_tx(t, 2, &syn), Verdict::Hairpin);
            let b = who(route(t, &syn, Source::Consumer(2)));
            assert!(b < 2);
            assert_eq!(t.flows.len(), 2, "one flow of A and one of B");
            let a_key = FlowKey {
                peer: OWN_IP,
                peer_port: 8080,
                own_port: BLOCK2,
            };
            let b_key = FlowKey {
                peer: OWN_IP,
                peer_port: BLOCK2,
                own_port: 8080,
            };
            assert_eq!(t.flows.get(t.flows.find(&a_key).unwrap()).consumer, 2);
            assert_eq!(t.flows.get(t.flows.find(&b_key).unwrap()).consumer, b);
            // B's answer reaches A, and A's next segment reaches B.
            let answer = hair_tcp(8080, BLOCK2, SYN_ACK);
            assert_eq!(check_tx(t, b, &answer), Verdict::Hairpin);
            assert_eq!(who(route(t, &answer, Source::Consumer(b))), 2);
            let ack = hair_tcp(BLOCK2, 8080, ACK_);
            assert_eq!(check_tx(t, 2, &ack), Verdict::Hairpin);
            assert_eq!(who(route(t, &ack, Source::Consumer(2))), b);
            assert_eq!(t.flows.len(), 2);
        });
    }

    #[test]
    fn hairpin_a_member_to_itself_through_the_group() {
        with(|t, _| {
            let syn = hair_tcp(BLOCK0, 8080, SYN);
            assert_eq!(check_tx(t, 0, &syn), Verdict::Hairpin);
            assert!(who(route(t, &syn, Source::Consumer(0))) < 2);
        });
    }

    #[test]
    fn a_turn_to_the_ports_of_dhcp_is_refused_and_no_frame_leaves_without_an_address() {
        with(|t, _| {
            let to_67 = ip_frame(ME, ME, 17, &udp_part(9000, 67));
            assert_eq!(refused(t, 0, &to_67), Reason::Udp);
            let own = t.own;
            t.own.ip = [0; 4];
            assert_eq!(refused(t, 0, &out_tcp(49152, 80, SYN)), Reason::SrcAddr);
            t.own = own;
        });
    }

    #[test]
    fn the_stacks_turns_are_whole_tcp_or_udp_to_the_shared_address() {
        with(|t, _| {
            let f = out_tcp(8080, 1234, ACK_);
            assert!(!faces_own(t, &f), "to another host");
            let mut f = hair_tcp(8080, 1234, ACK_);
            assert!(faces_own(t, &f));
            f[23] = 1;
            assert!(!faces_own(t, &f), "ICMP is the stack's own");
        });
    }
}
