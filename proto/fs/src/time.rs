// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Normalized signed file timestamps, independent of timer durations.

use proto_wire::{Reader, Status, Writer};

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
    reserved: u32,
}

impl Timestamp {
    pub const ZERO: Self = Self {
        seconds: 0,
        nanos: 0,
        reserved: 0,
    };

    pub const fn new(seconds: i64, nanos: u32) -> Result<Self, Status> {
        if nanos >= 1_000_000_000 {
            return Err(Status::BadSize);
        }
        Ok(Self {
            seconds,
            nanos,
            reserved: 0,
        })
    }

    pub fn from_ns(value: i128) -> Result<Self, Status> {
        let seconds =
            i64::try_from(value.div_euclid(1_000_000_000)).map_err(|_| Status::BadSize)?;
        Self::new(seconds, value.rem_euclid(1_000_000_000) as u32)
    }

    /// Explicit conversion for legacy diagnostic profiles using monotonic ns.
    pub const fn legacy_ns(value: u64) -> Self {
        Self {
            seconds: (value / 1_000_000_000) as i64,
            nanos: (value % 1_000_000_000) as u32,
            reserved: 0,
        }
    }

    pub fn valid(self) -> bool {
        self.nanos < 1_000_000_000 && self.reserved == 0
    }

    pub fn value(self) -> Result<i128, Status> {
        if !self.valid() {
            return Err(Status::BadSize);
        }
        Ok(i128::from(self.seconds) * 1_000_000_000 + i128::from(self.nanos))
    }

    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        if !self.valid() {
            return Err(Status::BadSize);
        }
        out.u64(self.seconds as u64)?;
        out.u32(self.nanos)?;
        out.u32(0)
    }

    pub fn read(input: &mut Reader<'_>) -> Result<Self, Status> {
        let result = Self {
            seconds: input.u64()? as i64,
            nanos: input.u32()?,
            reserved: input.u32()?,
        };
        if !result.valid() {
            return Err(Status::BadSize);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_normalization_and_wire_validation() {
        assert_eq!(core::mem::size_of::<Timestamp>(), 16);
        let value = Timestamp::from_ns(-1).unwrap();
        assert_eq!((value.seconds, value.nanos), (-1, 999_999_999));
        assert_eq!(value.value(), Ok(-1));
        for seconds in [i64::MIN, -1, 0, i64::MAX] {
            let time = Timestamp::new(seconds, 999_999_999).unwrap();
            let mut out = Writer::new();
            time.write(&mut out).unwrap();
            assert_eq!(Timestamp::read(&mut Reader::new(out.as_bytes())), Ok(time));
        }
        assert!(Timestamp::from_ns(i128::MAX).is_err());
        assert!(Timestamp::new(0, 1_000_000_000).is_err());
        for offset in [8, 12] {
            let mut bytes = [0u8; 16];
            let invalid = if offset == 8 { 1_000_000_000u32 } else { 1 };
            bytes[offset..offset + 4].copy_from_slice(&invalid.to_le_bytes());
            assert_eq!(
                Timestamp::read(&mut Reader::new(&bytes)),
                Err(Status::BadSize)
            );
        }
    }
}
