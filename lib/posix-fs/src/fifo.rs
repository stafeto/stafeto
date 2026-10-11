// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! FIFO I/O loans retain both exact backends in the existing held places.

use super::{FsError, PosixFs, Target, open::Recovery};
use entries::{Frame, nested};
use posix_fd::{DisposalSnapshot, DisposalToken, IoEnd, IoToken, OwnerToken};

pub type LoanEnd = IoEnd<Target, Recovery>;
impl PosixFs {
    pub fn begin_fifo_io(
        &mut self,
        owner: OwnerToken,
        fd: u32,
        frame: Frame,
    ) -> Result<(IoToken, Target), FsError> {
        if !matches!(self.descriptors.get(fd)?, Target::Fifo(_)) {
            return Err(FsError::InvalidArgument);
        }
        // This cleanup role uses the otherwise unused Open job/access words
        // for its exact caller frame. It never participates in Open recovery.
        let mut cleanup = Recovery::default();
        cleanup.job = frame.sp;
        cleanup.access = frame.z;
        self.descriptors
            .begin_io(owner, fd, cleanup)
            .map_err(FsError::from)
    }
    pub fn finish_fifo_io(
        &mut self,
        token: IoToken,
        owner: OwnerToken,
    ) -> Result<LoanEnd, FsError> {
        self.descriptors
            .finish_io(token, owner)
            .map_err(FsError::from)
    }
    pub fn abandon_fifo_io_owner(&mut self, owner: OwnerToken) -> Option<LoanEnd> {
        self.descriptors.abandon_io_owner(owner)
    }
    pub fn fifo_disposals(&self) -> impl Iterator<Item = DisposalToken> + '_ {
        self.descriptors.disposal_tokens()
    }
    pub fn fifo_disposal(
        &self,
        token: DisposalToken,
    ) -> Result<DisposalSnapshot<Target, Recovery>, FsError> {
        self.descriptors
            .disposal_snapshot(token)
            .map_err(FsError::from)
    }
    pub fn finish_fifo_disposal(&mut self, token: DisposalToken) -> Result<(), FsError> {
        self.descriptors
            .finish_disposal(token)
            .map_err(FsError::from)
    }
    pub(crate) fn mark_fifo_io_jump(&mut self, owner: OwnerToken, target: Frame) {
        let mut departing = [None; super::OPEN_MAX];
        for (index, token) in self.descriptors.io_tokens().enumerate() {
            if self.descriptors.io_snapshot(token).is_ok_and(|record| {
                record.owner == owner
                    && nested(
                        Frame {
                            sp: record.cleanup.job,
                            z: record.cleanup.access,
                        },
                        target,
                    )
            }) {
                departing[index] = Some(token);
            }
        }
        for token in departing.into_iter().flatten() {
            let _ = self.descriptors.finish_io(token, owner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::ManuallyDrop;
    use rt::{
        fs::{Files, PreparedOpen},
        handle::{Channel, Handle},
    };
    fn files() -> ManuallyDrop<PosixFs> {
        ManuallyDrop::new(
            PosixFs::from_files(Files::from_sessions(
                Handle::<Channel>::from_raw(rt::abi::Handle::new(7, 9)),
                None,
            ))
            .unwrap(),
        )
    }
    fn pair(generation: u64) -> Target {
        let ram = super::super::RamTarget::from_prepared(PreparedOpen {
            fd: 34,
            slot: 127,
            generation: 0x100000000 + generation,
            random: false,
        })
        .unwrap()
        .with_kind(super::super::FileKind::Fifo);
        Target::Fifo(
            super::super::FifoTarget::new(
                ram,
                proto_pipe::Endpoint::named(127, 0x200000000 + generation),
            )
            .unwrap(),
        )
    }
    fn owner(n: u64) -> OwnerToken {
        OwnerToken::new(n).unwrap()
    }
    #[test]
    fn last_fifo_fd_preserves_exact_pair_until_paid_disposal_confirmation() {
        let mut files = files();
        let old = pair(1);
        let fd = files.descriptors.insert(old, Default::default()).unwrap();
        let (loan, captured) = files.begin_fifo_io(owner(1), fd, Frame::main(200)).unwrap();
        assert_eq!(captured, old);
        assert_eq!(files.descriptors.close(fd), Ok(None));
        let fresh = pair(2);
        assert_eq!(files.descriptors.insert(fresh, Default::default()), Ok(fd));
        assert_eq!(
            files.finish_fifo_io(loan, owner(2)),
            Err(FsError::BadFileDescriptor)
        );
        let LoanEnd::Cleanup { token, snapshot } = files.finish_fifo_io(loan, owner(1)).unwrap()
        else {
            panic!("unpaid final pair");
        };
        assert_eq!(snapshot.backend, old);
        // An uncertain pipe/RAM cleanup reply must leave both full identities
        // in the same paid record, independent of public fd/slot reuse.
        for _ in 0..3 {
            assert_eq!(files.fifo_disposal(token), Ok(snapshot));
        }
        assert_eq!(files.target(fd), Ok(fresh));
        assert_eq!(files.fifo_disposals().count(), 1);
        assert_eq!(files.fifo_disposals().next(), Some(token));
        files.finish_fifo_disposal(token).unwrap();
        assert!(files.fifo_disposal(token).is_err());
        assert!(files.finish_fifo_io(loan, owner(1)).is_err());
        assert_eq!(files.target(fd), Ok(fresh));
    }
    #[test]
    fn jump_removes_only_departing_fifo_owner_frames() {
        let mut files = files();
        let fd = files
            .descriptors
            .insert(pair(1), Default::default())
            .unwrap();
        let (inner, _) = files.begin_fifo_io(owner(1), fd, Frame::main(200)).unwrap();
        let (outer, _) = files.begin_fifo_io(owner(1), fd, Frame::main(700)).unwrap();
        let (foreign, _) = files.begin_fifo_io(owner(2), fd, Frame::main(100)).unwrap();
        files.descriptors.close(fd).unwrap();
        files.mark_fifo_io_jump(owner(1), Frame::main(500));
        assert!(files.descriptors.io_snapshot(inner).is_err());
        assert!(files.descriptors.io_snapshot(outer).is_ok());
        assert!(files.descriptors.io_snapshot(foreign).is_ok());
        assert!(files.fifo_disposals().next().is_none());
        assert_eq!(files.finish_fifo_io(outer, owner(1)), Ok(LoanEnd::Released));
        let LoanEnd::Cleanup { token, snapshot } = files.finish_fifo_io(foreign, owner(2)).unwrap()
        else {
            panic!("lost final loan");
        };
        assert_eq!(snapshot.backend, pair(1));
        files.finish_fifo_disposal(token).unwrap();
    }
}
