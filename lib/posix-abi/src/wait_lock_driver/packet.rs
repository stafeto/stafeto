// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Fixed inline envelopes; production never allocates Writer[8192].

use proto_fs::{Method, WaitKey, WaitReply, WaitStart};
use proto_wire::{Reader, Status};

pub struct Packet {
    bytes: [u8; 64],
    len: usize,
}
impl Packet {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    fn new(method: Method) -> Self {
        let mut packet = Self {
            bytes: [0; 64],
            len: 8,
        };
        packet.bytes[..8].copy_from_slice(&method.header().bytes());
        packet
    }
    fn u32(&mut self, value: u32) {
        self.bytes[self.len..self.len + 4].copy_from_slice(&value.to_le_bytes());
        self.len += 4;
    }
    fn u64(&mut self, value: u64) {
        self.bytes[self.len..self.len + 8].copy_from_slice(&value.to_le_bytes());
        self.len += 8;
    }
    pub fn start(wire: WaitStart) -> Result<Self, Status> {
        wire.validate()?;
        let mut p = Self::new(Method::WaitStart);
        p.u32(wire.key.slot);
        p.u64(wire.key.generation);
        p.u32(wire.description.packed);
        p.u64(wire.description.generation);
        p.u32(wire.mode as u32);
        p.u32(wire.kind as u32);
        p.u32(wire.whence);
        p.u64(wire.start as u64);
        p.u64(wire.length as u64);
        p.u32(wire.pid as u32);
        Ok(p)
    }
    pub fn keyed(method: Method, key: WaitKey) -> Result<Self, Status> {
        key.validate().map_err(Status::from_code)?;
        if !matches!(
            method,
            Method::WaitQuery | Method::WaitCancel | Method::WaitRelease | Method::WaitArm
        ) {
            return Err(Status::from_code(proto_fs::INVALID_ARGUMENT));
        }
        let mut p = Self::new(method);
        p.u32(key.slot);
        p.u64(key.generation);
        Ok(p)
    }
}
/// A failed envelope has exactly status/reserved; a successful WAIT is strict16.
pub fn reply(bytes: &[u8]) -> Result<WaitReply, Status> {
    let mut reader = Reader::new(bytes);
    let code = reader.u32()?;
    if code != 0 {
        if reader.u32()? != 0 {
            return Err(Status::BadSize);
        }
        reader.finish()?;
        return Err(Status::from_code(code));
    }
    WaitReply::read(Reader::new(bytes))
}
pub fn released(bytes: &[u8]) -> Result<(), Status> {
    let mut reader = Reader::new(bytes);
    let code = reader.u32()?;
    if reader.u32()? != 0 {
        return Err(Status::BadSize);
    }
    reader.finish()?;
    if code == 0 {
        Ok(())
    } else {
        Err(Status::from_code(code))
    }
}
