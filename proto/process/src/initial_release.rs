// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Metadata-only release from the trusted Init endpoint. Runtime admission
//! checks the current record, authenticated epoch and committed Seal.
use crate::initial_ack::Ack;
use proto_wire::{Reader, Status, Writer};

pub const BODY: usize = 72;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Mode {
    Bootstrap = 0,
    User = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release {
    pub ack: Ack,
    pub mode: Mode,
}
impl Release {
    pub fn write(self, out: &mut Writer) -> Result<(), Status> {
        if self.ack.epoch == 0 {
            return Err(Status::BadSize);
        }
        self.ack.write(out)?;
        out.u32(self.mode as u32)?;
        out.u32(0)
    }
    pub fn read(bytes: &[u8], caps: usize) -> Result<Self, Status> {
        if caps != 0 {
            return Err(Status::BadSize);
        }
        let mut input = Reader::new(bytes);
        let ack = Ack::read(input.bytes(crate::initial_ack::BODY)?, 0)?;
        let mode = match input.u32()? {
            0 => Mode::Bootstrap,
            1 => Mode::User,
            _ => return Err(Status::BadSize),
        };
        if input.u32()? != 0 || ack.epoch == 0 {
            return Err(Status::BadSize);
        }
        input.finish()?;
        Ok(Self { ack, mode })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_full_key_receipt_and_exact_bootstrap_user_modes() {
        // Independent full-width epoch and canonical schema/label/PID receipt.
        let body = [
            255, 255, 255, 255, 255, 255, 255, 255, 19, 0, 0, 0, 0, 0, 0, 0, 7, 0, 3, 0, 0, 1, 0,
            128, 1, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 7, 0, 3, 0, 0, 1, 0, 128, 7, 3,
            0, 0, 1, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        ];
        let value = Release::read(&body, 0).unwrap();
        assert_eq!(value.mode, Mode::User);
        assert_eq!(value.ack.epoch, u64::MAX);
        assert_eq!(value.ack.ticket, 19);
        assert_eq!(value.ack.label, 0x8000010000030007);
        let mut writer = Writer::new();
        value.write(&mut writer).unwrap();
        assert_eq!(writer.as_bytes(), body);
        let mut first = body;
        first[64] = 0;
        assert_eq!(Release::read(&first, 0).unwrap().mode, Mode::Bootstrap);
        for offset in [8, 16, 24, 28, 32, 40, 48, 52, 56, 64, 68] {
            let mut bad = body;
            bad[offset] ^= 2;
            assert_eq!(Release::read(&bad, 0), Err(Status::BadSize));
        }
        let mut zero_epoch = body;
        zero_epoch[..8].fill(0);
        assert_eq!(Release::read(&zero_epoch, 0), Err(Status::BadSize));
        let mut invalid = value;
        invalid.ack.epoch = 0;
        assert_eq!(invalid.write(&mut Writer::new()), Err(Status::BadSize));
        for caps in 1..=4 {
            assert_eq!(Release::read(&body, caps), Err(Status::BadSize));
        }
        for length in 0..BODY {
            assert_eq!(Release::read(&body[..length], 0), Err(Status::BadSize));
        }
        let mut tail = [0; BODY + 1];
        tail[..BODY].copy_from_slice(&body);
        assert_eq!(Release::read(&tail, 0), Err(Status::BadSize));
    }
}
