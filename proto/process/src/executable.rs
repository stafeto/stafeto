// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One trusted RAM assertion binds a prepaid executable capability to its loader.
use crate::{IMAGE_MAX, NO_ID};
use proto_wire::{Reader, Status, Writer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ExecKind {
    Execute = 0,
    Fork = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageExec {
    pub pid: u32,
    pub image: u32,
    pub ticket: u64,
    pub uid: u32,
    pub gid: u32,
    pub kind: ExecKind,
    pub label: u64,
}
/// Immutable arguments survive Commit's consumption of pending credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageReceipt {
    pub uid: u32,
    pub gid: u32,
    pub kind: ExecKind,
    pub label: u64,
}
impl StageExec {
    fn validate(&self) -> Result<(), Status> {
        if self.pid == 0
            || self.image == 0
            || self.image > IMAGE_MAX
            || self.ticket == 0
            || self.label == 0
            || self.kind == ExecKind::Fork && (self.uid != NO_ID || self.gid != NO_ID)
        {
            return Err(Status::BadSize);
        }
        Ok(())
    }
    pub fn receipt(self) -> StageReceipt {
        StageReceipt {
            uid: self.uid,
            gid: self.gid,
            kind: self.kind,
            label: self.label,
        }
    }
    pub fn write(self, w: &mut Writer) -> Result<(), Status> {
        self.validate()?;
        w.u32(self.pid)?;
        w.u32(self.image)?;
        w.u64(self.ticket)?;
        w.u32(self.uid)?;
        w.u32(self.gid)?;
        w.u32(self.kind as u32)?;
        w.u32(0)?;
        w.u64(self.label)
    }
    pub fn read(mut r: Reader<'_>) -> Result<Self, Status> {
        let pid = r.u32()?;
        let image = r.u32()?;
        let ticket = r.u64()?;
        let uid = r.u32()?;
        let gid = r.u32()?;
        let kind = match r.u32()? {
            0 => ExecKind::Execute,
            1 => ExecKind::Fork,
            _ => return Err(Status::BadSize),
        };
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        let label = r.u64()?;
        r.finish()?;
        let got = Self {
            pid,
            image,
            ticket,
            uid,
            gid,
            kind,
            label,
        };
        got.validate()?;
        Ok(got)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> StageExec {
        StageExec {
            pid: 257,
            image: 2,
            ticket: 256,
            uid: 37,
            gid: NO_ID,
            kind: ExecKind::Execute,
            label: 99,
        }
    }
    #[test]
    fn stage_layout_preserves_every_immutable_argument_and_both_no_ids() {
        let mut w = Writer::new();
        args().write(&mut w).unwrap();
        assert_eq!(w.as_bytes().len(), 40);
        assert_eq!(StageExec::read(Reader::new(w.as_bytes())), Ok(args()));
        let mut both = args();
        both.uid = NO_ID;
        let mut w = Writer::new();
        both.write(&mut w).unwrap();
        assert_eq!(StageExec::read(Reader::new(w.as_bytes())), Ok(both));
        both.kind = ExecKind::Fork;
        let mut w = Writer::new();
        both.write(&mut w).unwrap();
        assert_eq!(StageExec::read(Reader::new(w.as_bytes())), Ok(both));
    }
    #[test]
    fn malformed_stage_never_creates_a_typed_custody_assertion() {
        let mut w = Writer::new();
        args().write(&mut w).unwrap();
        for n in 0..40 {
            assert_eq!(
                StageExec::read(Reader::new(&w.as_bytes()[..n])),
                Err(Status::BadSize)
            );
        }
        let mut extra = [0; 41];
        extra[..40].copy_from_slice(w.as_bytes());
        assert_eq!(StageExec::read(Reader::new(&extra)), Err(Status::BadSize));
        for (offset, bytes) in [
            (0, [0; 4]),
            (4, [0; 4]),
            (4, (IMAGE_MAX + 1).to_le_bytes()),
            (24, 2u32.to_le_bytes()),
            (28, 1u32.to_le_bytes()),
        ] {
            let mut bad = [0; 40];
            bad.copy_from_slice(w.as_bytes());
            bad[offset..offset + 4].copy_from_slice(&bytes);
            assert_eq!(StageExec::read(Reader::new(&bad)), Err(Status::BadSize));
        }
        for offset in [8, 32] {
            let mut bad = [0; 40];
            bad.copy_from_slice(w.as_bytes());
            bad[offset..offset + 8].fill(0);
            assert_eq!(StageExec::read(Reader::new(&bad)), Err(Status::BadSize));
        }
        let mut bad = [0; 40];
        bad.copy_from_slice(w.as_bytes());
        bad[24..28].copy_from_slice(&(ExecKind::Fork as u32).to_le_bytes());
        assert_eq!(StageExec::read(Reader::new(&bad)), Err(Status::BadSize));
    }
}
