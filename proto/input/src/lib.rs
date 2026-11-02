// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the input service (services/virtio-input), proto_wire:
//! the numbers of its methods, which never change once given, its codes
//! and the event of a key. Every number goes low byte first.
//!
//! | Method | Session | Request | Reply | Refusals |
//! |---|---|---|---|---|
//! | GRANT (1) | the display service's | the header alone | status 0 and one handle, the new session of focus (SEND, TRANSFER) | NOT_ALLOWED |
//! | REVOKE (2) | the display service's | the header alone | the status alone | NOT_ALLOWED |
//! | READ (3) | the focus | `max` (u32, 1 to MAX_READ) | status, `count` and `flags` (u32 each: bit 0 is LOST), then `count` events of 8 bytes | INVALID, REVOKED, NOT_ALLOWED |
//!
//! The service keeps at most one session of focus. Only the session init
//! gave the display service (the table's `connects`) asks for one: GRANT
//! makes it, a new label of the service, and revokes the one before; the
//! display service passes it on to the owner of the screen, so the focus
//! is always the owner's. REVOKE ends the focus when the screen goes back.
//! A key pressed while no session has the focus is dropped.
//!
//! The focus holds 64 events (RING). When more come, the oldest is dropped
//! and the next READ carries LOST, which it clears. READ never waits: it
//! returns the events there are, none included.
//!
//! A session of focus that was revoked gets REVOKED from READ. The channel
//! stays open: the kernel has no call that closes the service's side of
//! one label, so the service refuses with a code of its own.
//!
//! The event is the `struct virtio_input_event` of Virtio 1.2, 5.8.6, and
//! Linux's `struct input_event` without the time: `type`, `code`, `value`.
//! The service passes `EV_KEY` events whose value is 0 (release) or 1
//! (press) and drops the rest, repeats (value 2) among them. The codes of
//! keys are those of Linux's `input-event-codes.h`.

#![cfg_attr(not(test), no_std)]

use proto_wire::{Header, Reader, Status, Writer};

/// The version of the protocol, in the header of each request.
pub const VERSION: u16 = 1;

/// The events the focus holds.
pub const RING: usize = 64;
/// The most events one READ returns: a reply of 12 + 120 * 8 bytes fits
/// the message.
pub const MAX_READ: u32 = 120;

/// READ's `flags`: events were dropped since the last READ.
pub const LOST: u32 = 1;

/// The codes of the service.
pub const NOT_ALLOWED: u32 = 1101;
pub const REVOKED: u32 = 1102;
pub const INVALID: u32 = 1103;

pub const fn code(code: u32) -> Status {
    Status::Unknown(code)
}

/// The methods with their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Grant = 1,
    Revoke = 2,
    Read = 3,
}

impl Method {
    pub const ALL: [Method; 3] = [Method::Grant, Method::Revoke, Method::Read];

    pub const fn number(self) -> u16 {
        self as u16
    }

    pub fn from_number(number: u16) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.number() == number)
    }

    /// The header of a request of this method.
    pub const fn header(self) -> Header {
        Header::new(self.number(), VERSION)
    }
}

/// The type of a key's event (Linux's EV_KEY).
pub const EV_KEY: u16 = 1;
/// The values of a key's event: released, pressed. Linux's 2 is a repeat.
pub const RELEASE: i32 = 0;
pub const PRESS: i32 = 1;

/// One event, 8 bytes on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Event {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
}

/// The bytes of an event.
pub const EVENT_LEN: usize = 8;

impl Event {
    pub const fn key(code: u16, pressed: bool) -> Event {
        Event {
            kind: EV_KEY,
            code,
            value: if pressed { PRESS } else { RELEASE },
        }
    }

    /// The event of the 8 bytes the device wrote, low byte first.
    pub const fn from_bytes(b: [u8; EVENT_LEN]) -> Event {
        Event {
            kind: u16::from_le_bytes([b[0], b[1]]),
            code: u16::from_le_bytes([b[2], b[3]]),
            value: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    pub const fn to_bytes(self) -> [u8; EVENT_LEN] {
        let k = self.kind.to_le_bytes();
        let c = self.code.to_le_bytes();
        let v = self.value.to_le_bytes();
        [k[0], k[1], c[0], c[1], v[0], v[1], v[2], v[3]]
    }

    /// Whether the service passes the event on: a key pressed or
    /// released. Repeats, synchronisation, LEDs and the rest go.
    pub const fn passes(self) -> bool {
        self.kind == EV_KEY && (self.value == RELEASE || self.value == PRESS)
    }
}

/// READ's request: the header and `max`. INVALID outside 1..=MAX_READ.
pub fn write_read(max: u32, w: &mut Writer) -> Result<(), Status> {
    if !(1..=MAX_READ).contains(&max) {
        return Err(code(INVALID));
    }
    Method::Read.header().write(w)?;
    w.u32(max)
}

/// `max` from the bytes after the header of READ: BAD_SIZE unless it is
/// the one number, INVALID outside 1..=MAX_READ.
pub fn read_max(mut body: Reader<'_>) -> Result<u32, Status> {
    let max = body.u32()?;
    body.finish()?;
    if (1..=MAX_READ).contains(&max) {
        Ok(max)
    } else {
        Err(code(INVALID))
    }
}

/// READ's reply: status 0, the count, the flags, the events.
pub fn write_events(events: &[Event], lost: bool, w: &mut Writer) -> Result<(), Status> {
    w.u32(Status::Ok.code())?;
    w.u32(events.len() as u32)?;
    w.u32(if lost { LOST } else { 0 })?;
    for e in events {
        w.bytes(&e.to_bytes())?;
    }
    Ok(())
}

/// The status, the flags and the events of a reply of READ, each event
/// given to `each`; BAD_SIZE unless the reply is what the count says. A
/// refusal is its status alone, 8 bytes, and comes back as the error.
pub fn read_events(reply: &[u8], mut each: impl FnMut(Event)) -> Result<u32, Status> {
    let mut r = Reader::new(reply);
    let status = Status::from_code(r.u32()?);
    if status != Status::Ok {
        return Err(status);
    }
    let count = r.u32()?;
    let flags = r.u32()?;
    for _ in 0..count {
        let b = r.bytes(EVENT_LEN)?;
        each(Event::from_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]));
    }
    r.finish()?;
    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_methods_keep_their_numbers() {
        let numbers: Vec<_> = Method::ALL.iter().map(|m| m.number()).collect();
        assert_eq!(numbers, [1, 2, 3]);
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
        }
        assert_eq!(Method::from_number(0), None);
        assert_eq!(Method::from_number(4), None);
    }

    #[test]
    fn the_codes_are_apart_from_the_kernels_and_the_wires() {
        let codes = [NOT_ALLOWED, REVOKED, INVALID];
        for (i, c) in codes.iter().enumerate() {
            assert!(*c > 512);
            assert_eq!(Status::from_code(*c), Status::Unknown(*c));
            assert!(!codes[..i].contains(c));
            // Not the display service's (1001 to 1008).
            assert!(*c > 1100);
        }
    }

    #[test]
    fn an_event_is_the_device_s_eight_bytes() {
        // The press of KEY_A (30) as the device writes it.
        let e = Event::from_bytes([1, 0, 30, 0, 1, 0, 0, 0]);
        assert_eq!(e, Event::key(30, true));
        assert_eq!(e.to_bytes(), [1, 0, 30, 0, 1, 0, 0, 0]);
        let r = Event::key(0x1234, false);
        assert_eq!(r.to_bytes(), [1, 0, 0x34, 0x12, 0, 0, 0, 0]);
        let neg = Event {
            kind: 2,
            code: 3,
            value: -2,
        };
        assert_eq!(Event::from_bytes(neg.to_bytes()), neg);
    }

    #[test]
    fn only_presses_and_releases_of_keys_pass() {
        assert!(Event::key(30, true).passes());
        assert!(Event::key(30, false).passes());
        // A repeat, a sync (type 0), a LED (type 17), a key with a wild
        // value.
        for (kind, value) in [(EV_KEY, 2), (0, 0), (17, 1), (EV_KEY, -1), (EV_KEY, 3)] {
            let e = Event {
                kind,
                code: 30,
                value,
            };
            assert!(!e.passes(), "{e:?}");
        }
    }

    #[test]
    fn read_asks_for_one_to_the_most() {
        for max in [1, 64, MAX_READ] {
            let mut w = Writer::new();
            write_read(max, &mut w).expect("write");
            let bytes = w.as_bytes();
            assert_eq!(bytes.len(), 12);
            assert_eq!(read_max(Reader::new(&bytes[8..])), Ok(max));
        }
        for max in [0, MAX_READ + 1, u32::MAX] {
            assert_eq!(write_read(max, &mut Writer::new()), Err(code(INVALID)));
            assert_eq!(
                read_max(Reader::new(&max.to_le_bytes())),
                Err(code(INVALID))
            );
        }
        assert_eq!(read_max(Reader::new(&[1, 0])), Err(Status::BadSize));
        assert_eq!(
            read_max(Reader::new(&[1, 0, 0, 0, 0])),
            Err(Status::BadSize)
        );
    }

    #[test]
    fn a_full_reply_fits_the_message() {
        let events = vec![Event::key(30, true); MAX_READ as usize];
        let mut w = Writer::new();
        write_events(&events, true, &mut w).expect("write");
        assert_eq!(w.as_bytes().len(), 12 + 8 * MAX_READ as usize);
        assert!(w.as_bytes().len() <= abi::MESSAGE_MAX);
    }

    #[test]
    fn a_reply_round_trips_with_its_flags() {
        let sent = [Event::key(30, true), Event::key(30, false)];
        for lost in [false, true] {
            let mut w = Writer::new();
            write_events(&sent, lost, &mut w).expect("write");
            let mut got = Vec::new();
            let flags = read_events(w.as_bytes(), |e| got.push(e)).expect("read");
            assert_eq!(got, sent);
            assert_eq!(flags, if lost { LOST } else { 0 });
        }
        let mut w = Writer::new();
        write_events(&[], false, &mut w).expect("write");
        assert_eq!(read_events(w.as_bytes(), |_| panic!()), Ok(0));
    }

    #[test]
    fn a_reply_that_is_not_what_it_counts_is_refused() {
        let mut w = Writer::new();
        write_events(&[Event::key(1, true)], false, &mut w).expect("write");
        let bytes = w.as_bytes();
        assert_eq!(read_events(&bytes[..19], |_| {}), Err(Status::BadSize));
        let long = [bytes, &[0]].concat();
        assert_eq!(read_events(&long, |_| {}), Err(Status::BadSize));
        let refusal = proto_wire::reply(code(REVOKED));
        assert_eq!(read_events(&refusal, |_| {}), Err(code(REVOKED)));
    }
}
