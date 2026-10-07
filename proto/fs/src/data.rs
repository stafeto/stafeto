// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact bounded data-operation arguments and recovery outcomes.

use crate::{MAX_READ, MAX_WRITE, OPEN_DESCRIPTION_MASK, OPEN_FD_MASK, OpenKey};
use proto_wire::{Reader, Status, Writer};

pub const FEED_MAX: usize = 1004;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DataKind {
    Write = 1,
    PWrite = 2,
    Read = 3,
    PRead = 4,
    Truncate = 5,
}
impl DataKind {
    pub fn from_number(number: u32) -> Option<Self> {
        match number {
            1 => Some(Self::Write),
            2 => Some(Self::PWrite),
            3 => Some(Self::Read),
            4 => Some(Self::PRead),
            5 => Some(Self::Truncate),
            _ => None,
        }
    }
    pub const fn writes(self) -> bool {
        matches!(self, Self::Write | Self::PWrite)
    }
    pub const fn reads(self) -> bool {
        matches!(self, Self::Read | Self::PRead)
    }
}

/// The complete native description identity captured before local publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataDescription {
    pub packed: u32,
    pub generation: u64,
}
impl DataDescription {
    pub fn validate(self) -> Result<(), Status> {
        if self.packed & !(OPEN_DESCRIPTION_MASK | OPEN_FD_MASK) != 0
            || !(3..=34).contains(&(self.packed & OPEN_FD_MASK))
            || self.generation == 0
        {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    pub fn fd(self) -> u32 {
        self.packed & OPEN_FD_MASK
    }
    pub fn slot(self) -> u32 {
        (self.packed & OPEN_DESCRIPTION_MASK) >> 8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataStart {
    pub key: OpenKey,
    pub kind: DataKind,
    pub description: DataDescription,
    pub count: u32,
    pub position: u64,
}
impl DataStart {
    pub fn validate(self) -> Result<(), Status> {
        self.key.validate().map_err(Status::from_code)?;
        self.description.validate()?;
        let valid = match self.kind {
            DataKind::Write => self.count as usize <= MAX_WRITE && self.position == 0,
            DataKind::PWrite => self.count as usize <= MAX_WRITE,
            DataKind::Read => self.count as usize <= MAX_READ && self.position == 0,
            DataKind::PRead => self.count as usize <= MAX_READ,
            DataKind::Truncate => self.count == 0,
        };
        if !valid {
            return Err(Status::BadSize);
        }
        if self.position > i64::MAX as u64 {
            return Err(Status::from_code(crate::OFFSET_OVERFLOW));
        }
        Ok(())
    }
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        out.u32(self.key.slot)?;
        out.u64(self.key.generation)?;
        out.u32(self.kind as u32)?;
        out.u32(self.description.packed)?;
        out.u64(self.description.generation)?;
        out.u32(self.count)?;
        out.u64(self.position)
    }
    pub fn read(mut input: Reader<'_>) -> Result<Self, Status> {
        let value = Self {
            key: OpenKey {
                slot: input.u32()?,
                generation: input.u64()?,
            },
            kind: DataKind::from_number(input.u32()?).ok_or(Status::BadSize)?,
            description: DataDescription {
                packed: input.u32()?,
                generation: input.u64()?,
            },
            count: input.u32()?,
            position: input.u64()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DataPhase {
    Captured = 0,
    Feeding = 1,
    Preparing = 2,
    Ready = 3,
    TimeDeferred = 4,
    Completed = 5,
    Canceling = 6,
}
impl DataPhase {
    pub fn from_number(number: u32) -> Option<Self> {
        match number {
            0 => Some(Self::Captured),
            1 => Some(Self::Feeding),
            2 => Some(Self::Preparing),
            3 => Some(Self::Ready),
            4 => Some(Self::TimeDeferred),
            5 => Some(Self::Completed),
            6 => Some(Self::Canceling),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataResult {
    None,
    Bytes(u64),
    FailedNoEffect(u32),
}

pub fn valid_job(job: u64) -> bool {
    job >> 8 != 0 && job & 255 < 128
}

/// Only a known terminal failure can carry a saved proof of no effect.
pub fn terminal_failure(code: u32) -> bool {
    match code {
        1..=255 => abi::Error::from_code(code as u64).is_some(),
        256..=258 | 300..=313 | 316..=318 | 320 | 322..=324 => true,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataOutcome {
    pub phase: DataPhase,
    pub job: u64,
    pub result: DataResult,
}
impl DataOutcome {
    pub fn validate(self, request: DataStart) -> Result<(), Status> {
        request.validate()?;
        if !valid_job(self.job) {
            return Err(Status::BadSize);
        }
        if (matches!(self.phase, DataPhase::Completed) && matches!(self.result, DataResult::None))
            || (!matches!(self.phase, DataPhase::Completed | DataPhase::Canceling)
                && !matches!(self.result, DataResult::None))
        {
            return Err(Status::BadSize);
        }
        match self.result {
            DataResult::Bytes(count)
                if count > request.count as u64
                    || (request.kind == DataKind::Truncate && count != 0) =>
            {
                Err(Status::BadSize)
            }
            DataResult::FailedNoEffect(code) if !terminal_failure(code) => Err(Status::BadSize),
            _ => Ok(()),
        }
    }
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        out.u32(0)?;
        out.u32(self.phase as u32)?;
        out.u64(self.job)?;
        let (tag, value) = match self.result {
            DataResult::None => (0, 0),
            DataResult::Bytes(n) => (1, n),
            DataResult::FailedNoEffect(code) => (2, code as u64),
        };
        out.u32(tag)?;
        out.u32(0)?;
        out.u64(value)
    }
    pub fn read(bytes: &[u8], handles: usize, request: DataStart) -> Result<Self, Status> {
        let mut input = reply(bytes, handles)?;
        let phase = DataPhase::from_number(input.u32()?).ok_or(Status::BadSize)?;
        let job = input.u64()?;
        let tag = input.u32()?;
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let value = input.u64()?;
        input.finish()?;
        let result = match tag {
            0 if value == 0 => DataResult::None,
            1 => DataResult::Bytes(value),
            2 if value <= u32::MAX as u64 => DataResult::FailedNoEffect(value as u32),
            _ => return Err(Status::BadSize),
        };
        let value = Self { phase, job, result };
        value.validate(request)?;
        Ok(value)
    }
}

/// Validate the complete error envelope before classifying a remote failure.
fn reply(bytes: &[u8], handles: usize) -> Result<Reader<'_>, Status> {
    if handles != 0 {
        return Err(Status::BadSize);
    }
    let mut input = Reader::new(bytes);
    let code = input.u32()?;
    if code != 0 {
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        input.finish()?;
        return Err(Status::from_code(code));
    }
    Ok(input)
}

pub fn data_start_reply(bytes: &[u8], handles: usize) -> Result<(DataPhase, u64), Status> {
    let mut input = reply(bytes, handles)?;
    let phase = DataPhase::from_number(input.u32()?).ok_or(Status::BadSize)?;
    let job = input.u64()?;
    input.finish()?;
    if !valid_job(job) {
        return Err(Status::BadSize);
    }
    Ok((phase, job))
}

pub fn data_progress_reply(bytes: &[u8], handles: usize) -> Result<(), Status> {
    let mut input = reply(bytes, handles)?;
    if input.u32()? != 0 {
        return Err(Status::BadSize);
    }
    input.finish()
}

pub fn data_read_reply(bytes: &[u8], handles: usize, expected: usize) -> Result<&[u8], Status> {
    let mut input = reply(bytes, handles)?;
    let count = input.u32()? as usize;
    if count != expected || count > MAX_READ {
        return Err(Status::BadSize);
    }
    let result = input.bytes(count)?;
    input.finish()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn start(kind: DataKind) -> DataStart {
        DataStart {
            key: OpenKey {
                slot: 31,
                generation: u64::MAX,
            },
            kind,
            description: DataDescription {
                packed: 34 | (127 << 8),
                generation: 1,
            },
            count: if kind == DataKind::Truncate { 0 } else { 1012 },
            position: 0,
        }
    }
    #[test]
    fn arguments_roundtrip_and_exact_identity_masks() {
        for kind in [
            DataKind::Write,
            DataKind::PWrite,
            DataKind::Read,
            DataKind::PRead,
            DataKind::Truncate,
        ] {
            let args = start(kind);
            let mut out = Writer::new();
            args.write(&mut out).unwrap();
            assert_eq!(out.as_bytes().len(), 40);
            assert_eq!(DataStart::read(Reader::new(out.as_bytes())), Ok(args));
            for end in 0..40 {
                assert!(DataStart::read(Reader::new(&out.as_bytes()[..end])).is_err());
            }
            out.u32(0).unwrap();
            assert_eq!(
                DataStart::read(Reader::new(out.as_bytes())),
                Err(Status::BadSize)
            );
        }
        for bit in [6, 7, 15, 16, 30, 31] {
            let mut args = start(DataKind::Write);
            args.description.packed |= 1 << bit;
            assert_eq!(args.validate(), Err(Status::BadSize));
        }
        let mut args = start(DataKind::Read);
        args.count = 1017;
        assert_eq!(args.validate(), Err(Status::BadSize));
        args = start(DataKind::Write);
        args.count = 1013;
        assert_eq!(args.validate(), Err(Status::BadSize));
        args = start(DataKind::Truncate);
        args.position = u64::MAX;
        assert_eq!(
            args.validate(),
            Err(Status::from_code(crate::OFFSET_OVERFLOW))
        );
    }
    #[test]
    fn outcomes_preserve_completed_results_and_reject_ambiguous_shapes() {
        let args = start(DataKind::Write);
        let value = DataOutcome {
            phase: DataPhase::Completed,
            job: 256,
            result: DataResult::Bytes(1012),
        };
        let mut out = Writer::new();
        value.write(&mut out).unwrap();
        let bytes = out.as_bytes();
        assert_eq!(DataOutcome::read(bytes, 0, args), Ok(value));
        assert_eq!(
            DataOutcome {
                phase: DataPhase::Canceling,
                ..value
            }
            .validate(args),
            Ok(())
        );
        for end in 0..32 {
            assert!(DataOutcome::read(&bytes[..end], 0, args).is_err());
        }
        assert_eq!(DataOutcome::read(bytes, 1, args), Err(Status::BadSize));
        for (offset, number) in [(4, 7u32), (16, 3), (20, 1)] {
            let mut bad = [0; 32];
            bad.copy_from_slice(bytes);
            bad[offset..offset + 4].copy_from_slice(&number.to_le_bytes());
            assert_eq!(DataOutcome::read(&bad, 0, args), Err(Status::BadSize));
        }
        for code in [0, 314, 315, 319, 321, 325, u32::MAX] {
            assert_eq!(
                DataOutcome {
                    result: DataResult::FailedNoEffect(code),
                    ..value
                }
                .validate(args),
                Err(Status::BadSize)
            );
        }
        for phase in [
            DataPhase::Captured,
            DataPhase::Feeding,
            DataPhase::Preparing,
            DataPhase::Ready,
            DataPhase::TimeDeferred,
        ] {
            assert_eq!(
                DataOutcome { phase, ..value }.validate(args),
                Err(Status::BadSize)
            );
        }
        assert_eq!(
            DataOutcome {
                result: DataResult::Bytes(1013),
                ..value
            }
            .validate(args),
            Err(Status::BadSize)
        );
        assert_eq!(
            DataOutcome {
                result: DataResult::None,
                ..value
            }
            .validate(args),
            Err(Status::BadSize)
        );
    }
    #[test]
    fn error_and_read_payload_envelopes_are_complete() {
        let error = proto_wire::reply(Status::from_code(crate::OPEN_RETIRED));
        assert_eq!(
            data_start_reply(&error, 0),
            Err(Status::from_code(crate::OPEN_RETIRED))
        );
        assert_eq!(data_start_reply(&error[..4], 0), Err(Status::BadSize));
        let mut bad = error;
        bad[4] = 1;
        assert_eq!(data_start_reply(&bad, 0), Err(Status::BadSize));
        let mut out = Writer::new();
        out.u32(0).unwrap();
        out.u32(3).unwrap();
        out.bytes(b"abc").unwrap();
        assert_eq!(data_read_reply(out.as_bytes(), 0, 3), Ok(&b"abc"[..]));
        assert_eq!(data_read_reply(out.as_bytes(), 0, 2), Err(Status::BadSize));
        out.u32(0).unwrap();
        assert_eq!(data_read_reply(out.as_bytes(), 0, 3), Err(Status::BadSize));
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    #[test]
    fn regression_result_envelopes_and_noeffect_status_domain() {
        let args = DataStart {
            key: OpenKey {
                slot: 0,
                generation: 1,
            },
            kind: DataKind::Read,
            description: DataDescription {
                packed: 3,
                generation: 1,
            },
            count: 1016,
            position: 0,
        };
        for phase_number in 0..=6 {
            let phase = DataPhase::from_number(phase_number).unwrap();
            for result in [
                DataResult::None,
                DataResult::Bytes(1016),
                DataResult::FailedNoEffect(300),
            ] {
                let outcome = DataOutcome {
                    phase,
                    job: 383,
                    result,
                };
                let mut w = Writer::new();
                outcome.write(&mut w).unwrap();
                let allowed = match phase {
                    DataPhase::Completed => result != DataResult::None,
                    DataPhase::Canceling => true,
                    _ => result == DataResult::None,
                };
                assert_eq!(DataOutcome::read(w.as_bytes(), 0, args).is_ok(), allowed);
                assert_eq!(
                    DataOutcome::read(w.as_bytes(), 1, args),
                    Err(Status::BadSize)
                );
                w.bytes(&[0]).unwrap();
                assert_eq!(
                    DataOutcome::read(w.as_bytes(), 0, args),
                    Err(Status::BadSize)
                );
            }
        }
        for code in [314, 315, 319, 321, 325] {
            assert!(!terminal_failure(code));
        }
        for job in [0, 127, 128, 255, 384, u64::MAX] {
            assert!(!valid_job(job));
        }
        for job in [256, 383, 512, u64::MAX - 128] {
            assert!(valid_job(job));
        }
        for number in 1..=325 {
            let bytes = proto_wire::reply(Status::from_code(number));
            assert!(data_progress_reply(&bytes, 0).is_err());
            assert_eq!(data_progress_reply(&bytes, 1), Err(Status::BadSize));
        }
    }
}
