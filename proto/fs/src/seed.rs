// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Initial source keys and terminal acknowledgement envelopes.
//! Native admission authenticates the endpoint, source and current record.
use proto_wire::{Reader, Status, Writer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub epoch: u64,
    pub ticket: u64,
    pub label: u64,
}
impl Key {
    fn valid(self) -> bool {
        self.epoch != 0 && self.ticket != 0 && self.label != 0
    }
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        if !self.valid() {
            return Err(Status::BadSize);
        }
        out.u64(self.epoch)?;
        out.u64(self.ticket)?;
        out.u64(self.label)
    }
    fn from_reader(input: &mut Reader<'_>) -> Result<Self, Status> {
        let key = Self {
            epoch: input.u64()?,
            ticket: input.u64()?,
            label: input.u64()?,
        };
        if !key.valid() {
            return Err(Status::BadSize);
        }
        Ok(key)
    }
    pub fn read(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps != 0 {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let key = Self::from_reader(&mut input)?;
        input.finish()?;
        Ok(key)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CancelAction {
    Cancel = 0,
    Retire = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancel {
    pub key: Key,
    pub action: CancelAction,
}
impl Cancel {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        self.key.write(out)?;
        out.u32(self.action as u32)?;
        out.u32(0)
    }
    pub fn read(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps != 0 {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let key = Key::from_reader(&mut input)?;
        let action = match input.u32()? {
            0 => CancelAction::Cancel,
            1 => CancelAction::Retire,
            _ => return Err(Status::BadSize),
        };
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        input.finish()?;
        Ok(Self { key, action })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AckAction {
    Creation = 0,
    Retirement = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ResultKind {
    Committed = 1,
    Canceled = 2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub key: Key,
    pub result: ResultKind,
    pub action: AckAction,
}
impl Ack {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        self.key.write(out)?;
        out.u32(self.result as u32)?;
        out.u32(0)?;
        out.u32(self.action as u32)?;
        out.u32(0)
    }
    pub fn read(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps != 0 {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let key = Key::from_reader(&mut input)?;
        let result = match input.u32()? {
            1 => ResultKind::Committed,
            2 => ResultKind::Canceled,
            _ => return Err(Status::BadSize),
        };
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let action = match input.u32()? {
            0 => AckAction::Creation,
            1 => AckAction::Retirement,
            _ => return Err(Status::BadSize),
        };
        if input.u32()? != 0 {
            return Err(Status::BadSize);
        }
        input.finish()?;
        Ok(Self {
            key,
            result,
            action,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn literal() -> [u8; 40] {
        // Literal full-width key, committed result and retirement action.
        [
            255, 255, 255, 255, 255, 255, 255, 255, 2, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0,
            128, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        ]
    }
    fn key() -> Key {
        Key {
            epoch: u64::MAX,
            ticket: 0x100000002,
            label: 0x8000000000000003,
        }
    }
    #[test]
    fn terminal_ack_has_full_key_and_new_action_word() {
        let bytes = literal();
        let ack = Ack::read(&bytes, 0).unwrap();
        assert_eq!(
            ack,
            Ack {
                key: key(),
                result: ResultKind::Committed,
                action: AckAction::Retirement
            }
        );
        let mut writer = Writer::new();
        ack.write(&mut writer).unwrap();
        assert_eq!(writer.as_bytes(), bytes);
        assert_eq!(Key::read(&bytes[..24], 0), Ok(key()));
        assert!(Ack::read(&bytes[..32], 0).is_err());
        let mut cancelbytes = [0; 32];
        cancelbytes[..24].copy_from_slice(&bytes[..24]);
        cancelbytes[24] = 1;
        let cancel = Cancel::read(&cancelbytes, 0).unwrap();
        assert_eq!(cancel.action, CancelAction::Retire);
        let mut writer = Writer::new();
        cancel.write(&mut writer).unwrap();
        assert_eq!(writer.as_bytes(), cancelbytes);
    }
    #[test]
    fn cancel_envelope_rejects_legacy_key_only_and_unknown_action() {
        let bytes = literal();
        let mut cancel = [0; 32];
        cancel[..24].copy_from_slice(&bytes[..24]);
        cancel[24] = 1;
        for length in 0..32 {
            assert!(Cancel::read(&cancel[..length], 0).is_err());
        }
        for caps in 1..=4 {
            assert!(Cancel::read(&cancel, caps).is_err());
        }
        let mut tail = [0; 33];
        tail[..32].copy_from_slice(&cancel);
        assert!(Cancel::read(&tail, 0).is_err());
        for at in 28..32 {
            let mut bad = cancel;
            bad[at] = 1;
            assert!(Cancel::read(&bad, 0).is_err());
        }
        for value in [2, u32::MAX] {
            let mut bad = cancel;
            bad[24..28].copy_from_slice(&value.to_le_bytes());
            assert!(Cancel::read(&bad, 0).is_err());
        }
        cancel[24] = 0;
        assert_eq!(
            Cancel::read(&cancel, 0).unwrap().action,
            CancelAction::Cancel
        );
    }
    #[test]
    fn terminal_envelopes_reject_truncation_tail_caps_and_reserved() {
        let bytes = literal();
        for length in 0..40 {
            assert!(Ack::read(&bytes[..length], 0).is_err());
        }
        let mut tail = [0; 41];
        tail[..40].copy_from_slice(&bytes);
        assert!(Ack::read(&tail, 0).is_err());
        for caps in 1..=4 {
            assert!(Ack::read(&bytes, caps).is_err());
            assert!(Key::read(&bytes[..24], caps).is_err());
        }
        for at in [28, 29, 30, 31, 36, 37, 38, 39] {
            let mut bad = bytes;
            bad[at] = 1;
            assert!(Ack::read(&bad, 0).is_err());
        }
        for at in [0, 8, 16] {
            let mut bad = bytes;
            bad[at..at + 8].fill(0);
            assert!(Ack::read(&bad, 0).is_err());
        }
        for result in [0, 3, u32::MAX] {
            let mut bad = bytes;
            bad[24..28].copy_from_slice(&result.to_le_bytes());
            assert!(Ack::read(&bad, 0).is_err());
        }
        for action in [2, u32::MAX] {
            let mut bad = bytes;
            bad[32..36].copy_from_slice(&action.to_le_bytes());
            assert!(Ack::read(&bad, 0).is_err());
        }
        for result in [ResultKind::Committed, ResultKind::Canceled] {
            for action in [AckAction::Creation, AckAction::Retirement] {
                let ack = Ack {
                    key: key(),
                    result,
                    action,
                };
                let mut writer = Writer::new();
                ack.write(&mut writer).unwrap();
                assert_eq!(Ack::read(writer.as_bytes(), 0), Ok(ack));
            }
        }
    }
}
