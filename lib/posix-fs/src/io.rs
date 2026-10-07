// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact RAM operation pins retain paid last-reference disposal.

use super::{FsError, PosixFs, Target, Transport, open::Recovery};
pub use posix_fd::{DisposalToken, IoToken, OwnerToken};
pub type IoSnapshot = posix_fd::IoSnapshot<Target, Recovery>;
pub type DisposalSnapshot = posix_fd::DisposalSnapshot<Target, Recovery>;
pub type IoEnd = posix_fd::IoEnd<Target, Recovery>;

pub struct DisposalContext {
    token: DisposalToken,
    snapshot: DisposalSnapshot,
    session: rt::abi::Handle,
    transport: Transport,
}

/// Only a successful exact native close creates this local completion proof.
pub struct DisposalProof {
    token: DisposalToken,
    snapshot: DisposalSnapshot,
    session: rt::abi::Handle,
}

impl DisposalContext {
    pub fn send_once(self) -> Result<DisposalProof, FsError> {
        self.transport.release(Some(self.snapshot.backend))?;
        Ok(DisposalProof {
            token: self.token,
            snapshot: self.snapshot,
            session: self.session,
        })
    }
}

impl PosixFs {
    /// Capture one immutable exact RAM identity before any remote operation.
    pub fn begin_io(
        &mut self,
        owner: OwnerToken,
        fd: u32,
    ) -> Result<(IoToken, Target, Transport), FsError> {
        let target = self.target(fd)?;
        let (Target::Ram(ram) | Target::Random(ram)) = target else {
            return Err(FsError::InvalidArgument);
        };
        let mut recovery = Recovery::default();
        recovery.backend_fd = ram.fd();
        recovery.description_generation = ram.generation();
        let (token, backend) = self.descriptors.begin_io(owner, fd, recovery)?;
        Ok((token, backend, self.transport()))
    }

    pub fn io_snapshot(&self, token: IoToken) -> Result<IoSnapshot, FsError> {
        self.descriptors.io_snapshot(token).map_err(FsError::from)
    }

    pub fn io_tokens(&self) -> impl Iterator<Item = IoToken> + '_ {
        self.descriptors.io_tokens()
    }

    pub fn finish_io(&mut self, token: IoToken, owner: OwnerToken) -> Result<IoEnd, FsError> {
        self.descriptors
            .finish_io(token, owner)
            .map_err(FsError::from)
    }

    pub fn abandon_io_owner(&mut self, owner: OwnerToken) -> Option<IoEnd> {
        self.descriptors.abandon_io_owner(owner)
    }

    pub fn disposal_tokens(&self) -> impl Iterator<Item = DisposalToken> + '_ {
        self.descriptors.disposal_tokens()
    }

    pub fn disposal_snapshot(&self, token: DisposalToken) -> Result<DisposalSnapshot, FsError> {
        self.descriptors
            .disposal_snapshot(token)
            .map_err(FsError::from)
    }

    pub fn disposal_context(&self, token: DisposalToken) -> Result<DisposalContext, FsError> {
        let snapshot = self.disposal_snapshot(token)?;
        if !matches!(snapshot.backend, Target::Ram(_) | Target::Random(_)) {
            return Err(FsError::Io);
        }
        Ok(DisposalContext {
            token,
            snapshot,
            session: self.sessions().0.raw(),
            transport: self.transport(),
        })
    }

    pub fn finish_disposal(&mut self, proof: DisposalProof) -> Result<(), FsError> {
        if proof.session != self.sessions().0.raw()
            || self.disposal_snapshot(proof.token)? != proof.snapshot
        {
            return Err(FsError::Io);
        }
        self.descriptors
            .finish_disposal(proof.token)
            .map_err(FsError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::ManuallyDrop;
    use rt::{Handle, fs::Files, handle::Channel};

    fn owner(n: u64) -> OwnerToken {
        OwnerToken::new(n).unwrap()
    }

    fn files() -> ManuallyDrop<PosixFs> {
        ManuallyDrop::new(
            PosixFs::from_files(Files::from_sessions(
                Handle::<Channel>::from_raw(rt::abi::Handle::new(7, 9)),
                None,
            ))
            .unwrap(),
        )
    }

    fn target() -> Target {
        Target::Ram(
            super::super::RamTarget::from_prepared(rt::fs::PreparedOpen {
                fd: 3,
                slot: 17,
                generation: 43,
                random: false,
            })
            .unwrap(),
        )
    }

    #[test]
    fn reentrant_pins_preserve_last_debt_and_reject_foreign_session_proof() {
        let mut fs = files();
        let fd = fs
            .insert(target(), super::super::DescriptorFlags::default())
            .unwrap();
        let (a, _, _) = fs.begin_io(owner(1), fd).unwrap();
        let (b, _, _) = fs.begin_io(owner(1), fd).unwrap();
        assert_eq!(fs.take_close(fd), Ok(None));
        assert_eq!(fs.finish_io(a, owner(1)), Ok(IoEnd::Released));
        assert_eq!(fs.io_snapshot(b).unwrap().backend, target());
        assert_eq!(fs.finish_io(b, owner(2)), Err(FsError::BadFileDescriptor));
        let IoEnd::Cleanup { token, snapshot } = fs.finish_io(b, owner(1)).unwrap() else {
            panic!("last exact pin must retain disposal");
        };
        assert_eq!(token.slot(), b.slot());
        assert_eq!(snapshot.cleanup.description_generation, 43);
        assert_eq!(fs.disposal_tokens().count(), 1);
        let context = fs.disposal_context(token).unwrap();
        assert_eq!(
            fs.finish_disposal(DisposalProof {
                token,
                snapshot,
                session: rt::abi::Handle::new(7, 10),
            }),
            Err(FsError::Io)
        );
        assert_eq!(fs.disposal_snapshot(token), Ok(snapshot));
        // Test-only receipt models the canonical native producer's private fields.
        fs.finish_disposal(DisposalProof {
            token: context.token,
            snapshot: context.snapshot,
            session: context.session,
        })
        .unwrap();
        let replacement = fs
            .insert(target(), super::super::DescriptorFlags::default())
            .unwrap();
        let (new, _, _) = fs.begin_io(owner(1), replacement).unwrap();
        assert_ne!(new.generation(), a.generation());
        let session = fs.sessions().0.raw();
        assert!(
            fs.finish_disposal(DisposalProof {
                token,
                snapshot,
                session,
            })
            .is_err()
        );
        assert_eq!(fs.io_snapshot(new).unwrap().backend, target());
    }

    #[test]
    fn exact_data_detach_keeps_reentrant_operation_of_same_owner() {
        let mut fs = files();
        let fd = fs
            .insert(target(), super::super::DescriptorFlags::default())
            .unwrap();
        let (old, _, _) = fs
            .begin_data(owner(1), fd, proto_fs::DataKind::Read, 1, 0, &[])
            .unwrap();
        let (nested, _, _) = fs
            .begin_data(owner(1), fd, proto_fs::DataKind::Read, 1, 0, &[])
            .unwrap();
        assert!(fs.abandon_data(old, owner(2)).is_err());
        assert_eq!(fs.data_snapshot(old).unwrap().owner, Some(owner(1)));
        fs.abandon_data(old, owner(1)).unwrap();
        assert_eq!(fs.data_snapshot(old).unwrap().owner, None);
        assert_eq!(fs.data_snapshot(nested).unwrap().owner, Some(owner(1)));
        assert!(fs.abandon_data(old, owner(1)).is_err());
    }
}
