// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the driver of the entropy device (services/virtio-rng,
//! proto_wire): the numbers of its methods, which never change once
//! given, and their bodies. Every number goes low byte first.
//!
//! FILL_START (1), FILL_TAKE (2) and FILL_CANCEL (3) are a fill in two
//! steps (proto_wire::long): FILL_START asks for `n` bytes of the device,
//! FILL_MIN to FILL_MAX, and answers WAIT k, since the bytes come at the
//! device's interrupt; FILL_TAKE carries k (and, the first time, a handle
//! with NOTIFY labelled k) and answers READY with the `n` bytes, or ARMED;
//! the driver sets bit 0 there once they came, and keeps them until
//! FILL_TAKE; FILL_CANCEL carries k and answers CANCELLED, or READY with
//! bytes that came. A driver holds a few fills at once; one more gets
//! LIMIT_REACHED. The bytes of a reply are the device's own, and the
//! driver keeps no copy once they went.
//!
//! CRASH (4): the request is the header alone; there is no reply: the
//! driver loads from address 0, which ends it with a fault while the
//! device may hold a request, so that init stops the device and starts
//! the driver again. Only a driver built with the feature `crash` has the
//! method.
//!
//! | Request | Bytes after the header |
//! |---|---|
//! | FILL_START | 0..4 `n`, 4..8 zero |
//! | FILL_TAKE, FILL_CANCEL | 0..8 the key k, above 0 |

#![cfg_attr(not(test), no_std)]

use proto_wire::{Header, Reader, Status, Writer};

/// The version of the protocol, in the header of each request.
pub const VERSION: u16 = 1;

/// The fewest and the most bytes one fill asks for.
pub const FILL_MIN: u32 = 32;
pub const FILL_MAX: u32 = 256;

/// The methods with their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    FillStart = 1,
    FillTake = 2,
    FillCancel = 3,
    Crash = 4,
}

impl Method {
    pub const ALL: [Method; 4] = [
        Method::FillStart,
        Method::FillTake,
        Method::FillCancel,
        Method::Crash,
    ];

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

/// FILL_START: the bytes asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fill {
    pub n: u32,
}

impl Fill {
    fn check(n: u32) -> Result<(), Status> {
        if (FILL_MIN..=FILL_MAX).contains(&n) {
            Ok(())
        } else {
            Err(Status::BadSize)
        }
    }

    /// The header of FILL_START, `n` and four zeros: BAD_SIZE for `n`
    /// outside FILL_MIN..=FILL_MAX.
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        Fill::check(self.n)?;
        Method::FillStart.header().write(w)?;
        w.u32(self.n)?;
        w.u32(0)
    }

    /// The request from `body`, its bytes after the header: BAD_SIZE
    /// unless they are `n` in FILL_MIN..=FILL_MAX and four zeros.
    pub fn read(mut body: Reader<'_>) -> Result<Fill, Status> {
        let (n, zero) = (body.u32()?, body.u32()?);
        body.finish()?;
        Fill::check(n)?;
        if zero != 0 {
            return Err(Status::BadSize);
        }
        Ok(Fill { n })
    }
}

/// FILL_TAKE and FILL_CANCEL: the key k of the fill, above 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub key: u64,
}

impl Key {
    pub fn write(&self, method: Method, w: &mut Writer) -> Result<(), Status> {
        if self.key == 0 || !matches!(method, Method::FillTake | Method::FillCancel) {
            return Err(Status::BadSize);
        }
        method.header().write(w)?;
        w.u64(self.key)
    }

    pub fn read(mut body: Reader<'_>) -> Result<Key, Status> {
        let key = body.u64()?;
        body.finish()?;
        if key == 0 {
            return Err(Status::BadSize);
        }
        Ok(Key { key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_numbers_are_fixed() {
        assert_eq!(Method::ALL.map(Method::number), [1, 2, 3, 4]);
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
            assert_eq!(m.header(), Header::new(m.number(), VERSION));
        }
        assert_eq!(Method::from_number(0), None);
        assert_eq!(Method::from_number(5), None);
        assert_eq!(Method::Crash.header().bytes(), [4, 0, 1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_fill_asks_for_32_to_256_bytes() {
        let mut w = Writer::new();
        Fill { n: 64 }.write(&mut w).unwrap();
        assert_eq!(
            w.as_bytes(),
            [1, 0, 1, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            Fill::read(Reader::new(&w.as_bytes()[8..])),
            Ok(Fill { n: 64 })
        );
        for n in [0, 31, 257, u32::MAX] {
            assert_eq!(Fill { n }.write(&mut Writer::new()), Err(Status::BadSize));
            let mut body = n.to_le_bytes().to_vec();
            body.extend([0; 4]);
            assert_eq!(Fill::read(Reader::new(&body)), Err(Status::BadSize));
        }
        for n in [32, 256] {
            let mut body = u32::to_le_bytes(n).to_vec();
            body.extend([0; 4]);
            assert_eq!(Fill::read(Reader::new(&body)), Ok(Fill { n }));
        }
        // Four zeros after `n`, and nothing past them.
        assert_eq!(
            Fill::read(Reader::new(&[64, 0, 0, 0, 1, 0, 0, 0])),
            Err(Status::BadSize)
        );
        assert_eq!(
            Fill::read(Reader::new(&[64, 0, 0, 0, 0, 0, 0, 0, 0])),
            Err(Status::BadSize)
        );
    }

    #[test]
    fn take_and_cancel_carry_their_key() {
        let key = Key {
            key: 0x0807_0605_0403_0201,
        };
        for (method, number) in [(Method::FillTake, 2), (Method::FillCancel, 3)] {
            let mut w = Writer::new();
            key.write(method, &mut w).unwrap();
            assert_eq!(
                w.as_bytes(),
                [number, 0, 1, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
            );
            assert_eq!(Key::read(Reader::new(&w.as_bytes()[8..])), Ok(key));
        }
        for bytes in [&[0; 8][..], &[1; 7][..], &[1; 9][..]] {
            assert_eq!(Key::read(Reader::new(bytes)), Err(Status::BadSize));
        }
        assert_eq!(
            Key { key: 0 }.write(Method::FillTake, &mut Writer::new()),
            Err(Status::BadSize)
        );
        assert_eq!(
            key.write(Method::FillStart, &mut Writer::new()),
            Err(Status::BadSize)
        );
    }
}
