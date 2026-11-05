// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The bypass ring between the service and the owner of the second device
//! (spec 6, 3.9; the layout is `proto_net::fast`): the owner passes the
//! frames of the second address's DHCP client (UDP from 67 to 68) and the
//! ARP replies for that address to the service, and the service passes
//! what the interface of the second device sends to the owner, who puts it
//! on the wire.
//!
//! The ring object is the owner's memory, and the owner may write into it
//! at any time. The service never makes a Rust reference to the bytes of a
//! slot: a frame is copied once into the service's own buffer, and every
//! check runs on that copy (`accepts`), so the frame the stack sees is the
//! frame that was checked. The indices are atomic words; the service's own
//! ends live in its memory and are only written to the object. An index
//! that says more frames than the ring holds, or a length past a slot,
//! breaks the ring (`Broken`): the service takes nothing from it any more
//! and refuses KICK, and the device stays the owner's until it ends.

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use proto_net::fast::{
    FRAME_MAX, RING_SLOTS, TO_OWNER, TO_SERVICE, head_offset, len_offset, slot_offset, tail_offset,
};
use virtio_net::frames::verify_sums;

/// The ring's indices or a length broke its rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Broken;

/// The ring object mapped at `base` in the service, and the service's own
/// ends of the two rings: the frames it took from the ring to it, and the
/// frames it put in the ring to the owner. The service keeps them in its
/// own memory and only writes them to the object, as rings of indices do
/// (Fuchsia's network sessions): an owner that rewinds them gets no frame
/// taken twice and no loop of steps.
pub struct Ring {
    base: usize,
    taken: u32,
    put: u32,
}

impl Ring {
    /// The ring at `base`.
    ///
    /// # Safety
    ///
    /// `base` is the start of a mapping of the ring object (`RING_PAGES`
    /// pages, read and write) that lasts as long as the value.
    pub const unsafe fn at(base: usize) -> Ring {
        Ring {
            base,
            taken: 0,
            put: 0,
        }
    }

    fn word(&self, offset: usize) -> &AtomicU32 {
        // SAFETY: the offset is one of the indices on page 0 (aligned to 4),
        // within the mapping; an atomic may change under any reference.
        unsafe { &*((self.base + offset) as *const AtomicU32) }
    }

    fn length(&self, ring: usize, slot: u32) -> u16 {
        // SAFETY: as for `word`, aligned to 2.
        let at = unsafe { &*((self.base + len_offset(ring, slot)) as *const AtomicU16) };
        at.load(Ordering::Relaxed)
    }

    /// The frames the owner put in the ring to the service that the
    /// service has not taken.
    pub fn waiting(&self) -> Result<u32, Broken> {
        let head = self.word(head_offset(TO_SERVICE)).load(Ordering::Acquire);
        let waiting = head.wrapping_sub(self.taken);
        if waiting > RING_SLOTS {
            return Err(Broken);
        }
        Ok(waiting)
    }

    /// Copies the next frame of the ring to the service into `into`, which
    /// is the service's own memory, and gives the slot back: its length,
    /// or None when the ring is empty.
    pub fn take(&mut self, into: &mut [u8; FRAME_MAX]) -> Result<Option<usize>, Broken> {
        if self.waiting()? == 0 {
            return Ok(None);
        }
        let tail = self.taken;
        let len = usize::from(self.length(TO_SERVICE, tail));
        if len == 0 || len > FRAME_MAX {
            return Err(Broken);
        }
        let from = (self.base + slot_offset(TO_SERVICE, tail)) as *const u8;
        // SAFETY: the slot is within the mapping and `len` within the slot;
        // `into` is the service's and apart from it. The owner may change
        // the bytes meanwhile: only the copy is ever looked at.
        unsafe { core::ptr::copy_nonoverlapping(from, into.as_mut_ptr(), len) };
        self.taken = tail.wrapping_add(1);
        self.word(tail_offset(TO_SERVICE))
            .store(self.taken, Ordering::Release);
        Ok(Some(len))
    }

    /// Puts `frame` in the ring to the owner: false when the ring is full
    /// (the frame is dropped; the protocol sends it again) or the frame is
    /// longer than a slot.
    pub fn put(&mut self, frame: &[u8]) -> Result<bool, Broken> {
        let head = self.put;
        let tail = self.word(tail_offset(TO_OWNER)).load(Ordering::Acquire);
        let used = head.wrapping_sub(tail);
        if used > RING_SLOTS {
            return Err(Broken);
        }
        if used == RING_SLOTS || frame.is_empty() || frame.len() > FRAME_MAX {
            return Ok(false);
        }
        let to = (self.base + slot_offset(TO_OWNER, head)) as *mut u8;
        // SAFETY: the slot is within the mapping, the frame fits it, and the
        // owner reads it only after the head moves past it.
        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), to, frame.len()) };
        // SAFETY: as for `length`.
        let len = unsafe { &*((self.base + len_offset(TO_OWNER, head)) as *const AtomicU16) };
        len.store(frame.len() as u16, Ordering::Relaxed);
        self.put = head.wrapping_add(1);
        self.word(head_offset(TO_OWNER))
            .store(self.put, Ordering::Release);
        Ok(true)
    }
}

/// The frames of the ring a step takes: the cost of a frame through the
/// stack is that of a frame of the wire (two fit a step with room).
pub const RING_RX: usize = 2;

/// The ring and the frames a step copied from it, each checked in the
/// service's memory (`accepts`, and the sums: the stack of the second
/// device checks none).
pub struct Taker {
    pub ring: Ring,
    frames: [[u8; FRAME_MAX]; RING_RX],
    lens: [usize; RING_RX],
    /// The frames copied this step, and the next to give to the stack.
    count: usize,
    next: usize,
    /// The ring broke its rules: nothing is taken from it any more, and
    /// KICK is refused. The device stays the owner's (its mappings of the
    /// window and the queues live until it ends); the service says so once.
    pub broken: bool,
    said: bool,
    /// Frames of the ring the check refused.
    pub refused: u64,
}

impl Taker {
    /// The ring at `base`.
    ///
    /// # Safety
    ///
    /// As `Ring::at`.
    pub unsafe fn new(base: usize) -> Taker {
        Taker {
            // SAFETY: the caller's promise.
            ring: unsafe { Ring::at(base) },
            frames: [[0; FRAME_MAX]; RING_RX],
            lens: [0; RING_RX],
            count: 0,
            next: 0,
            broken: false,
            said: false,
            refused: 0,
        }
    }

    /// Copies up to RING_RX frames of the ring and keeps those the check
    /// passes: the frames taken from the ring.
    pub fn take(&mut self, own: Own) -> u32 {
        self.count = 0;
        self.next = 0;
        let mut taken = 0;
        while !self.broken && taken < RING_RX as u32 {
            let slot = &mut self.frames[self.count];
            match self.ring.take(slot) {
                Ok(Some(len)) => {
                    taken += 1;
                    if accepts(&slot[..len], own) && verify_sums(&slot[..len]) {
                        self.lens[self.count] = len;
                        self.count += 1;
                    } else {
                        self.refused += 1;
                    }
                }
                Ok(None) => break,
                Err(Broken) => self.broken = true,
            }
        }
        taken
    }

    /// Whether frames are left in the ring for another step.
    pub fn waiting(&mut self) -> bool {
        if self.broken {
            return false;
        }
        match self.ring.waiting() {
            Ok(n) => n > 0,
            Err(Broken) => {
                self.broken = true;
                false
            }
        }
    }

    /// True once, at the step that found the ring broken.
    pub fn newly_broken(&mut self) -> bool {
        self.broken && !core::mem::replace(&mut self.said, true)
    }

    /// Whether a frame copied this step waits for the stack.
    pub fn has_frame(&self) -> bool {
        self.next < self.count && !self.broken
    }

    /// The next frame copied this step, with the ring and its state for
    /// the answer the stack sends to it.
    pub fn next_frame(&mut self) -> Option<(&[u8], &mut Ring, &mut bool)> {
        if !self.has_frame() {
            return None;
        }
        let i = self.next;
        self.next += 1;
        Some((
            &self.frames[i][..self.lens[i]],
            &mut self.ring,
            &mut self.broken,
        ))
    }
}

const ETHERNET: usize = 14;
const BROADCAST: [u8; 4] = [255; 4];

/// What the service knows of the second address when it checks a frame of
/// the ring: the device's MAC, the address (None while the DHCP client
/// has none).
#[derive(Clone, Copy, Debug)]
pub struct Own {
    pub mac: [u8; 6],
    pub address: Option<[u8; 4]>,
}

/// Whether the frame, copied into the service, is one the owner may pass:
/// an IPv4 datagram of UDP from port 67 to port 68 (RFC 2131, 4.1), whole
/// (no fragment), to the second address or to the broadcast address, or,
/// while the client has no address, to the device's MAC; or an ARP reply
/// (RFC 826) for the second address at the device's MAC. Nothing else
/// reaches the stack of the second device.
pub fn accepts(frame: &[u8], own: Own) -> bool {
    if frame.len() < ETHERNET || frame.len() > FRAME_MAX {
        return false;
    }
    match [frame[12], frame[13]] {
        [0x08, 0x00] => dhcp_reply(frame, own),
        [0x08, 0x06] => arp_reply(frame, own),
        _ => false,
    }
}

fn dhcp_reply(frame: &[u8], own: Own) -> bool {
    let ip = &frame[ETHERNET..];
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return false;
    }
    let header = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    // Neither the More Fragments bit nor an offset.
    let fragment = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff;
    if header < 20 || total < header + 8 || total > ip.len() || fragment != 0 || ip[9] != 17 {
        return false;
    }
    let udp = &ip[header..total];
    let (from, to) = (
        u16::from_be_bytes([udp[0], udp[1]]),
        u16::from_be_bytes([udp[2], udp[3]]),
    );
    let length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if from != 67 || to != 68 || length < 8 || length > udp.len() {
        return false;
    }
    let target: [u8; 4] = [ip[16], ip[17], ip[18], ip[19]];
    target == BROADCAST
        || Some(target) == own.address
        || (own.address.is_none() && frame[..6] == own.mac)
}

fn arp_reply(frame: &[u8], own: Own) -> bool {
    let Some(address) = own.address else {
        return false;
    };
    let Some(arp) = frame.get(ETHERNET..ETHERNET + 28) else {
        return false;
    };
    // Ethernet, IPv4, 6 and 4 bytes, a reply.
    arp[..8] == [0, 1, 8, 0, 6, 4, 0, 2] && arp[18..24] == own.mac && arp[24..28] == address
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_net::fast::RING_PAGES;

    const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x57];
    const OWN: [u8; 4] = [10, 0, 3, 15];

    fn own() -> Own {
        Own {
            mac: MAC,
            address: Some(OWN),
        }
    }

    /// A page-aligned ring object in the test's memory.
    struct Object(Vec<u64>);

    impl Object {
        fn new() -> Object {
            Object(vec![0; RING_PAGES as usize * 512 + 512])
        }
        fn base(&self) -> usize {
            (self.0.as_ptr() as usize).next_multiple_of(4096)
        }
        fn set32(&self, offset: usize, value: u32) {
            unsafe { ((self.base() + offset) as *mut u32).write(value) }
        }
        fn get32(&self, offset: usize) -> u32 {
            unsafe { ((self.base() + offset) as *const u32).read() }
        }
        /// The owner puts `frame` in the ring to the service.
        fn push(&self, frame: &[u8]) {
            let head = self.get32(head_offset(TO_SERVICE));
            let at = self.base() + slot_offset(TO_SERVICE, head);
            unsafe {
                core::ptr::copy_nonoverlapping(frame.as_ptr(), at as *mut u8, frame.len());
                ((self.base() + len_offset(TO_SERVICE, head)) as *mut u16)
                    .write(frame.len() as u16);
            }
            self.set32(head_offset(TO_SERVICE), head.wrapping_add(1));
        }
    }

    fn dhcp(to: [u8; 4], ihl: u8, flags: u16, ports: (u16, u16)) -> Vec<u8> {
        let header = usize::from(ihl) * 4;
        let total = header + 8 + 300;
        let mut f = vec![0u8; ETHERNET + total];
        f[..6].copy_from_slice(&MAC);
        f[12..14].copy_from_slice(&[0x08, 0x00]);
        f[14] = 0x40 | ihl;
        f[16..18].copy_from_slice(&(total as u16).to_be_bytes());
        f[20..22].copy_from_slice(&flags.to_be_bytes());
        f[23] = 17;
        f[30..34].copy_from_slice(&to);
        let udp = ETHERNET + header;
        f[udp..udp + 2].copy_from_slice(&ports.0.to_be_bytes());
        f[udp + 2..udp + 4].copy_from_slice(&ports.1.to_be_bytes());
        f[udp + 4..udp + 6].copy_from_slice(&308u16.to_be_bytes());
        f
    }

    fn arp(oper: u8, target_mac: [u8; 6], target: [u8; 4]) -> Vec<u8> {
        let mut f = vec![0u8; 42];
        f[12..14].copy_from_slice(&[0x08, 0x06]);
        f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, oper]);
        f[32..38].copy_from_slice(&target_mac);
        f[38..42].copy_from_slice(&target);
        f
    }

    #[test]
    fn a_server_message_to_the_second_address_or_to_all_passes() {
        assert!(accepts(&dhcp(OWN, 5, 0, (67, 68)), own()));
        assert!(accepts(&dhcp(BROADCAST, 5, 0x4000, (67, 68)), own()));
        assert!(accepts(&dhcp(OWN, 6, 0, (67, 68)), own()), "with options");
        assert!(!accepts(&dhcp([10, 0, 3, 16], 5, 0, (67, 68)), own()));
        // Without an address: any target at the device's MAC.
        let none = Own {
            address: None,
            ..own()
        };
        assert!(accepts(&dhcp([10, 0, 3, 99], 5, 0, (67, 68)), none));
        let mut elsewhere = dhcp([10, 0, 3, 99], 5, 0, (67, 68));
        elsewhere[0] = 0x02;
        assert!(!accepts(&elsewhere, none));
    }

    #[test]
    fn other_datagrams_and_fragments_do_not_pass() {
        assert!(!accepts(&dhcp(OWN, 5, 0, (68, 67)), own()), "a client's");
        assert!(!accepts(&dhcp(OWN, 5, 0, (53, 68)), own()));
        assert!(!accepts(&dhcp(OWN, 5, 0x2000, (67, 68)), own()), "MF");
        assert!(!accepts(&dhcp(OWN, 5, 0x0001, (67, 68)), own()), "offset");
        assert!(!accepts(&dhcp(OWN, 4, 0, (67, 68)), own()), "IHL 4");
        let mut tcp = dhcp(OWN, 5, 0, (67, 68));
        tcp[23] = 6;
        assert!(!accepts(&tcp, own()));
        let mut long = dhcp(OWN, 5, 0, (67, 68));
        long[16..18].copy_from_slice(&2000u16.to_be_bytes());
        assert!(!accepts(&long, own()), "a total past the frame");
        let mut udp_long = dhcp(OWN, 5, 0, (67, 68));
        udp_long[38..40].copy_from_slice(&1000u16.to_be_bytes());
        assert!(!accepts(&udp_long, own()), "a UDP length past the datagram");
        assert!(!accepts(&dhcp(OWN, 5, 0, (67, 68))[..30], own()));
        assert!(!accepts(&[0u8; 13], own()));
        assert!(!accepts(&vec![0u8; FRAME_MAX + 1], own()));
    }

    #[test]
    fn only_an_arp_reply_for_the_second_address_at_the_device_passes() {
        assert!(accepts(&arp(2, MAC, OWN), own()));
        assert!(!accepts(&arp(1, MAC, OWN), own()), "a request");
        assert!(!accepts(&arp(2, [2; 6], OWN), own()), "another MAC");
        assert!(
            !accepts(&arp(2, MAC, [10, 0, 3, 2]), own()),
            "another address"
        );
        let none = Own {
            address: None,
            ..own()
        };
        assert!(!accepts(&arp(2, MAC, OWN), none));
        assert!(!accepts(&arp(2, MAC, OWN)[..41], own()));
    }

    #[test]
    fn frames_come_out_in_order_and_the_check_runs_on_the_copy() {
        let object = Object::new();
        let mut ring = unsafe { Ring::at(object.base()) };
        let mut into = [0u8; FRAME_MAX];
        assert_eq!(ring.take(&mut into), Ok(None));
        let good = dhcp(OWN, 5, 0, (67, 68));
        object.push(&good);
        object.push(&arp(2, MAC, OWN));
        assert_eq!(ring.waiting(), Ok(2));
        assert_eq!(ring.take(&mut into), Ok(Some(good.len())));
        // The owner changes the slot after the copy: the copy stays as it
        // was checked.
        let slot = object.base() + slot_offset(TO_SERVICE, 0);
        unsafe { (slot as *mut u8).add(37).write(53) };
        assert!(accepts(&into[..good.len()], own()));
        assert_eq!(ring.take(&mut into), Ok(Some(42)));
        assert_eq!(ring.take(&mut into), Ok(None));
        assert_eq!(object.get32(tail_offset(TO_SERVICE)), 2);
    }

    #[test]
    fn indices_past_the_ring_and_bad_lengths_break_it() {
        let object = Object::new();
        let mut ring = unsafe { Ring::at(object.base()) };
        let mut into = [0u8; FRAME_MAX];
        object.set32(head_offset(TO_SERVICE), RING_SLOTS + 1);
        assert_eq!(ring.waiting(), Err(Broken));
        assert_eq!(ring.take(&mut into), Err(Broken));
        // A length of 0 or past a slot.
        for len in [0u16, FRAME_MAX as u16 + 1] {
            let mut ring = unsafe { Ring::at(object.base()) };
            object.set32(head_offset(TO_SERVICE), 1);
            unsafe { ((object.base() + len_offset(TO_SERVICE, 0)) as *mut u16).write(len) };
            assert_eq!(ring.take(&mut into), Err(Broken), "length {len}");
        }
        // The owner's tail of its ring says it took more than was put.
        let mut ring = unsafe { Ring::at(object.base()) };
        object.set32(tail_offset(TO_OWNER), 40u32.wrapping_neg());
        assert_eq!(ring.put(&[1; 60]), Err(Broken));
    }

    #[test]
    fn the_service_s_ends_are_its_own_and_a_rewind_takes_nothing_again() {
        let object = Object::new();
        let mut ring = unsafe { Ring::at(object.base()) };
        let mut into = [0u8; FRAME_MAX];
        object.push(&dhcp(OWN, 5, 0, (67, 68)));
        assert_eq!(ring.take(&mut into).map(|l| l.is_some()), Ok(true));
        // The owner rewinds the service's tail: nothing waits all the same.
        object.set32(tail_offset(TO_SERVICE), 0);
        assert_eq!(ring.waiting(), Ok(0));
        assert_eq!(ring.take(&mut into), Ok(None));
        assert_eq!(object.get32(tail_offset(TO_SERVICE)), 0, "only written");
        // Wrapping indices are fine.
        let mut ring = unsafe { Ring::at(object.base()) };
        ring.taken = u32::MAX;
        object.set32(head_offset(TO_SERVICE), 1);
        assert_eq!(ring.waiting(), Ok(2));
        // The owner rewinds the service's head of the ring to it: the next
        // frame goes after the last one all the same.
        let object = Object::new();
        let mut ring = unsafe { Ring::at(object.base()) };
        assert_eq!(ring.put(&[7; 60]), Ok(true));
        object.set32(head_offset(TO_OWNER), 0);
        assert_eq!(ring.put(&[8; 60]), Ok(true));
        assert_eq!(object.get32(head_offset(TO_OWNER)), 2);
    }

    #[test]
    fn indices_past_the_ring_break_it_and_it_says_so_once() {
        let object = Object::new();
        let mut taker = unsafe { Taker::new(object.base()) };
        assert_eq!(taker.take(own()), 0);
        assert!(!taker.broken);
        // Taken, and refused for its header sum of 0 (`verify_sums`).
        object.push(&dhcp(OWN, 5, 0, (67, 68)));
        assert_eq!(taker.take(own()), 1);
        assert_eq!(taker.refused, 1);
        object.set32(head_offset(TO_SERVICE), 1 + RING_SLOTS + 1);
        assert_eq!(taker.take(own()), 0);
        assert!(taker.broken);
        assert!(taker.newly_broken());
        assert!(!taker.newly_broken(), "said once");
        assert!(!taker.waiting());
        assert!(taker.next_frame().is_none());
    }

    #[test]
    fn the_ring_to_the_owner_holds_sixteen_frames() {
        let object = Object::new();
        let mut ring = unsafe { Ring::at(object.base()) };
        for i in 0..RING_SLOTS {
            assert_eq!(ring.put(&[i as u8; 60]), Ok(true));
        }
        assert_eq!(ring.put(&[0; 60]), Ok(false), "full");
        assert_eq!(object.get32(head_offset(TO_OWNER)), RING_SLOTS);
        object.set32(tail_offset(TO_OWNER), 1);
        assert_eq!(ring.put(&[0xAB; 342]), Ok(true));
        let slot = object.base() + slot_offset(TO_OWNER, RING_SLOTS);
        assert_eq!(unsafe { *(slot as *const u8) }, 0xAB);
        let len = unsafe { *((object.base() + len_offset(TO_OWNER, 0)) as *const u16) };
        assert_eq!(len, 342);
        assert_eq!(ring.put(&[]), Ok(false));
        assert_eq!(ring.put(&[0; FRAME_MAX + 1]), Ok(false));
    }
}
