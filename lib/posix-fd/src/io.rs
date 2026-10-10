// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Exact I/O pins transfer last-reference disposal to their prepaid slot.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoToken {
    slot: usize,
    generation: u64,
}

impl IoToken {
    pub fn slot(self) -> usize {
        self.slot
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisposalToken {
    slot: usize,
    generation: u64,
}

impl DisposalToken {
    pub fn slot(self) -> usize {
        self.slot
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoSnapshot<T, R> {
    pub owner: OwnerToken,
    pub backend: T,
    pub cleanup: R,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisposalSnapshot<T, R> {
    pub backend: T,
    pub cleanup: R,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoEnd<T, R> {
    /// Surviving descriptor or operation references pay the final disposal.
    Released,
    /// Resident exact cleanup survives ambiguous replies and helper death.
    Cleanup {
        token: DisposalToken,
        snapshot: DisposalSnapshot<T, R>,
    },
}

#[derive(Clone, Copy)]
pub(super) struct IoRecord<T, R> {
    owner: OwnerToken,
    backend: T,
    cleanup: R,
}

impl<T: Copy + Eq, const N: usize, R: Copy, S: Copy, C: Copy> Table<T, N, R, S, C> {
    pub(super) fn io_pinned(&self, backend: T) -> bool {
        self.holds
            .iter()
            .any(|slot| matches!(slot.held, Held::RecoverableIo(r) if r.backend == backend))
    }

    fn io_record(&self, token: IoToken) -> Result<IoRecord<T, R>, Error> {
        let slot = self.holds.get(token.slot).ok_or(Error::BadFileDescriptor)?;
        if slot.generation != token.generation {
            return Err(Error::BadFileDescriptor);
        }
        match slot.held {
            Held::RecoverableIo(record) => Ok(record),
            _ => Err(Error::BadFileDescriptor),
        }
    }

    /// Each exact operation pays its own record and pin before remote work.
    /// The caller captures immutable native cleanup authority before admission.
    pub fn begin_io(
        &mut self,
        owner: OwnerToken,
        fd: u32,
        cleanup: R,
    ) -> Result<(IoToken, T), Error> {
        let backend = self.get(fd)?;
        if (self.release_early)(backend) {
            return Err(Error::InvalidArgument);
        }
        let (index, slot) = self
            .holds
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| {
                matches!(slot.held, Held::Empty)
                    && slot.generation < u64::MAX
                    && slot.changed.load(Ordering::Relaxed) < u32::MAX
            })
            .ok_or(Error::TooManyOpenFiles)?;
        slot.generation += 1;
        let token = IoToken {
            slot: index,
            generation: slot.generation,
        };
        slot.held = Held::RecoverableIo(IoRecord {
            owner,
            backend,
            cleanup,
        });
        slot.change();
        Ok((token, backend))
    }

    pub fn io_snapshot(&self, token: IoToken) -> Result<IoSnapshot<T, R>, Error> {
        let record = self.io_record(token)?;
        Ok(IoSnapshot {
            owner: record.owner,
            backend: record.backend,
            cleanup: record.cleanup,
        })
    }

    pub fn io_tokens(&self) -> impl Iterator<Item = IoToken> + '_ {
        self.holds.iter().enumerate().filter_map(|(slot, h)| {
            matches!(h.held, Held::RecoverableIo(_)).then_some(IoToken {
                slot,
                generation: h.generation,
            })
        })
    }

    /// Remove one exact owner pin under the table lock. The final reference
    /// becomes ownerless disposal in this same slot without new admission.
    pub fn finish_io(&mut self, token: IoToken, owner: OwnerToken) -> Result<IoEnd<T, R>, Error> {
        let record = self.io_record(token)?;
        if record.owner != owner {
            return Err(Error::BadFileDescriptor);
        }
        self.holds[token.slot].held = Held::Empty;
        self.job_gone();
        let release = self.left(record.backend);
        let result = match release {
            None => IoEnd::Released,
            Some(backend) => {
                let snapshot = DisposalSnapshot {
                    backend,
                    cleanup: record.cleanup,
                };
                self.holds[token.slot].held = Held::Disposal(snapshot);
                IoEnd::Cleanup {
                    token: DisposalToken {
                        slot: token.slot,
                        generation: token.generation,
                    },
                    snapshot,
                }
            }
        };
        self.holds[token.slot].change();
        Ok(result)
    }

    /// Detach one pin after the caller proves exact lifetime Ended or revoked.
    /// Repeated calls visit every pin of this owner. Disposal has no owner.
    pub fn abandon_io_owner(&mut self, owner: OwnerToken) -> Option<IoEnd<T, R>> {
        let (slot, generation) = self.holds.iter().enumerate().find_map(|(slot, h)| {
            matches!(h.held,Held::RecoverableIo(record) if record.owner == owner)
                .then_some((slot, h.generation))
        })?;
        self.finish_io(IoToken { slot, generation }, owner).ok()
    }

    pub fn disposal_tokens(&self) -> impl Iterator<Item = DisposalToken> + '_ {
        self.holds.iter().enumerate().filter_map(|(slot, h)| {
            matches!(h.held, Held::Disposal(_)).then_some(DisposalToken {
                slot,
                generation: h.generation,
            })
        })
    }

    pub fn disposal_snapshot(&self, token: DisposalToken) -> Result<DisposalSnapshot<T, R>, Error> {
        let slot = self.holds.get(token.slot).ok_or(Error::BadFileDescriptor)?;
        if slot.generation != token.generation {
            return Err(Error::BadFileDescriptor);
        }
        match slot.held {
            Held::Disposal(snapshot) => Ok(snapshot),
            _ => Err(Error::BadFileDescriptor),
        }
    }

    /// The caller proves canonical exact Close returned Closed or AlreadyGone.
    /// Unknown replies retain this record. Helpers may repeat idempotent native
    /// cleanup from its immutable snapshot, outside every table/files lock.
    pub fn finish_disposal(&mut self, token: DisposalToken) -> Result<(), Error> {
        self.disposal_snapshot(token)?;
        self.holds[token.slot].held = Held::Empty;
        self.holds[token.slot].change();
        self.job_gone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(n: u64) -> OwnerToken {
        OwnerToken::new(n).unwrap()
    }
    fn table() -> Table<u32, 4, u64, u64> {
        let mut t = Table::default();
        t.place(0, 10, Flags::default()).unwrap();
        t
    }
    fn cleanup(end: IoEnd<u32, u64>) -> (DisposalToken, DisposalSnapshot<u32, u64>) {
        let IoEnd::Cleanup { token, snapshot } = end else {
            panic!("resident disposal expected")
        };
        (token, snapshot)
    }

    #[test]
    fn each_owner_has_separate_pin_and_only_last_finish_creates_resident_debt() {
        let mut t = table();
        let (a, backend) = t.begin_io(owner(1), 0, 101).unwrap();
        let (b, _) = t.begin_io(owner(2), 0, 202).unwrap();
        assert_eq!(backend, 10);
        assert_ne!(a.slot(), b.slot());
        assert_eq!(t.close(0), Ok(None));
        assert_eq!(t.finish_io(a, owner(2)), Err(Error::BadFileDescriptor));
        assert_eq!(t.finish_io(a, owner(1)), Ok(IoEnd::Released));
        let (debt, snapshot) = cleanup(t.finish_io(b, owner(2)).unwrap());
        assert_eq!(debt.slot(), b.slot());
        assert_eq!(debt.generation(), b.generation());
        assert_eq!(
            snapshot,
            DisposalSnapshot {
                backend: 10,
                cleanup: 202
            }
        );
        assert!(t.io_snapshot(b).is_err());
        assert_eq!(t.disposal_snapshot(debt), Ok(snapshot));
        t.finish_disposal(debt).unwrap();
        assert!(t.finish_disposal(debt).is_err());
    }

    #[test]
    fn original_and_helper_death_and_unknown_reply_keep_immutable_disposal() {
        let mut t = table();
        let (io, _) = t.begin_io(owner(1), 0, 77).unwrap();
        t.close(0).unwrap();
        let (debt, snapshot) = cleanup(t.abandon_io_owner(owner(1)).unwrap());
        assert_eq!(t.abandon_io_owner(owner(1)), None);
        assert_eq!(t.io_tokens().count(), 0);
        for _ in 0..3 {
            assert_eq!(t.disposal_snapshot(debt), Ok(snapshot));
        }
        assert_eq!(snapshot.cleanup, 77);
        assert!(t.finish_io(io, owner(1)).is_err());
        t.finish_disposal(debt).unwrap();
        assert!(t.disposal_snapshot(debt).is_err());
    }

    #[test]
    fn scalar_and_recoverable_io_transfer_last_debt_in_every_order() {
        for scalar_first in [false, true] {
            let mut t = table();
            let (scalar, claim) = t.begin_scalar(owner(1), 0, 42).unwrap();
            let (io, _) = t.begin_io(owner(2), 0, 84).unwrap();
            t.complete_scalar(claim, ScalarResult::Bytes(5)).unwrap();
            assert_eq!(t.close(0), Ok(None));
            if scalar_first {
                assert_eq!(t.scalar_begin_cleanup(scalar).unwrap().last_target, None);
                let (debt, snapshot) = cleanup(t.finish_io(io, owner(2)).unwrap());
                assert_eq!(snapshot.backend, 10);
                t.finish_disposal(debt).unwrap();
            } else {
                assert_eq!(t.finish_io(io, owner(2)), Ok(IoEnd::Released));
                assert_eq!(
                    t.scalar_begin_cleanup(scalar).unwrap().last_target,
                    Some(10)
                );
            }
            t.scalar_finish_cleanup(scalar).unwrap();
            assert_eq!(t.ack_scalar(scalar, owner(1)), Ok(ScalarResult::Bytes(5)));
        }
    }

    #[test]
    fn aliases_remain_live_and_close_while_pin_exists_creates_one_debt() {
        let mut t = table();
        let alias = t.duplicate(0, 0, Flags::default()).unwrap();
        let (a, _) = t.begin_io(owner(1), 0, 1).unwrap();
        assert_eq!(t.finish_io(a, owner(1)), Ok(IoEnd::Released));
        let (b, _) = t.begin_io(owner(2), alias, 2).unwrap();
        assert_eq!(t.close(0), Ok(None));
        assert_eq!(t.close(alias), Ok(None));
        let (debt, snapshot) = cleanup(t.finish_io(b, owner(2)).unwrap());
        assert_eq!(snapshot.backend, 10);
        assert_eq!(t.disposal_tokens().count(), 1);
        t.finish_disposal(debt).unwrap();
    }

    #[test]
    fn numeric_reuse_with_same_generation_different_description_preserves_new_mapping() {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct Exact {
            fd: u32,
            slot: u8,
            generation: u64,
        }
        let old = Exact {
            fd: 3,
            slot: 1,
            generation: 1,
        };
        let new = Exact {
            fd: 3,
            slot: 2,
            generation: 1,
        };
        let mut t = Table::<Exact, 2, u64>::default();
        t.place(0, old, Flags::default()).unwrap();
        let (io, _) = t.begin_io(owner(1), 0, 901).unwrap();
        t.close(0).unwrap();
        t.place(0, new, Flags::default()).unwrap();
        let IoEnd::Cleanup { token, snapshot } = t.finish_io(io, owner(1)).unwrap() else {
            panic!()
        };
        assert_eq!(snapshot.backend, old);
        assert_ne!(snapshot.backend, new);
        t.finish_disposal(token).unwrap();
        assert_eq!(t.get(0), Ok(new));
    }

    #[test]
    fn same_backend_dup2_replaces_entry_lifetime_without_releasing_pin() {
        let mut t = table();
        let alias = t.duplicate(0, 0, Flags::default()).unwrap();
        let (io, _) = t.begin_io(owner(1), 0, 1).unwrap();
        let entry = t.entry_token(0).unwrap();
        assert_eq!(t.dup2(alias, 0), Ok((0, None)));
        assert_ne!(t.entry_token(0).unwrap(), entry);
        assert_eq!(t.finish_io(io, owner(1)), Ok(IoEnd::Released));
        assert_eq!(t.get(0), Ok(10));
        assert_eq!(t.disposal_tokens().count(), 0);
    }

    #[test]
    fn owner_enumeration_removes_one_pin_and_preserves_other_owners() {
        let mut t = table();
        t.begin_io(owner(1), 0, 11).unwrap();
        t.begin_io(owner(1), 0, 12).unwrap();
        let (other, _) = t.begin_io(owner(2), 0, 21).unwrap();
        t.close(0).unwrap();
        assert_eq!(t.abandon_io_owner(owner(1)), Some(IoEnd::Released));
        assert_eq!(t.abandon_io_owner(owner(1)), Some(IoEnd::Released));
        assert_eq!(t.abandon_io_owner(owner(1)), None);
        assert_eq!(t.io_snapshot(other).unwrap().owner, owner(2));
        let (debt, snapshot) = cleanup(t.abandon_io_owner(owner(2)).unwrap());
        assert_eq!(snapshot.cleanup, 21);
        assert_eq!(t.abandon_io_owner(owner(2)), None);
        assert_eq!(t.disposal_tokens().count(), 1);
        t.finish_disposal(debt).unwrap();
    }

    #[test]
    fn full_32_disposal_transition_needs_no_admission_and_stale_finish_cannot_reuse_slot() {
        let mut t = Table::<u32, 32, u64>::default();
        let mut selected = None;
        for fd in 0..32 {
            t.place(fd, fd + 10, Flags::default()).unwrap();
            let (token, _) = t.begin_io(owner(1), fd, u64::from(fd)).unwrap();
            if fd == 31 {
                selected = Some(token);
            }
            t.close(fd).unwrap();
        }
        t.place(0, 100, Flags::default()).unwrap();
        assert_eq!(t.begin_io(owner(2), 0, 99), Err(Error::TooManyOpenFiles));
        let (debt, snapshot) = cleanup(t.finish_io(selected.unwrap(), owner(1)).unwrap());
        assert_eq!(snapshot.backend, 41);
        assert_eq!(t.begin_io(owner(2), 0, 99), Err(Error::TooManyOpenFiles));
        assert_eq!(t.disposal_snapshot(debt), Ok(snapshot));
        t.finish_disposal(debt).unwrap();
        let (new, _) = t.begin_io(owner(2), 0, 99).unwrap();
        assert_eq!(new.slot(), debt.slot());
        assert!(new.generation() > debt.generation());
        assert!(t.finish_disposal(debt).is_err());
        assert_eq!(t.io_snapshot(new).unwrap().cleanup, 99);
        assert_eq!(t.get(0), Ok(100));
    }

    #[test]
    fn stale_disposal_generation_cannot_finish_new_disposal_in_same_slot() {
        let mut t = table();
        let (first, _) = t.begin_io(owner(1), 0, 1).unwrap();
        t.close(0).unwrap();
        let (old, _) = cleanup(t.finish_io(first, owner(1)).unwrap());
        t.finish_disposal(old).unwrap();
        t.place(0, 20, Flags::default()).unwrap();
        let (second, _) = t.begin_io(owner(2), 0, 2).unwrap();
        t.close(0).unwrap();
        let (new, snapshot) = cleanup(t.finish_io(second, owner(2)).unwrap());
        assert_eq!(new.slot(), old.slot());
        assert!(new.generation() > old.generation());
        assert!(t.finish_disposal(old).is_err());
        assert_eq!(t.disposal_snapshot(new), Ok(snapshot));
        assert_eq!(snapshot.backend, 20);
        t.finish_disposal(new).unwrap();
    }

    #[test]
    fn full_mixed_open_scalar_io_budget_fails_before_effect() {
        let mut t = Table::<u32, 32, u64, u64>::default();
        t.place(0, 10, Flags::default()).unwrap();
        for _ in 0..8 {
            t.begin_open(owner(1), 1).unwrap();
        }
        for _ in 0..8 {
            t.begin_scalar(owner(2), 0, 2).unwrap();
        }
        for _ in 0..32 {
            t.begin_io(owner(3), 0, 3).unwrap();
        }
        assert_eq!(t.begin_io(owner(3), 0, 4), Err(Error::TooManyOpenFiles));
        assert_eq!(t.begin_scalar(owner(3), 0, 4), Err(Error::TooManyOpenFiles));
        assert_eq!(t.begin_open(owner(3), 4), Err(Error::TooManyOpenFiles));
        assert_eq!(t.io_tokens().count(), 32);
        assert_eq!(t.get(0), Ok(10));
    }

    #[test]
    fn max_generation_and_wait_do_not_block_existing_disposal_cleanup() {
        let mut t = Table::<u32, 1, u64>::default();
        t.place(0, 10, Flags::default()).unwrap();
        t.holds[0].generation = u64::MAX - 1;
        let (io, _) = t.begin_io(owner(1), 0, 9).unwrap();
        assert_eq!(io.generation(), u64::MAX);
        t.holds[0].changed.store(u32::MAX, Ordering::Relaxed);
        assert_eq!(t.close(0), Ok(None));
        let (debt, snapshot) = cleanup(t.finish_io(io, owner(1)).unwrap());
        assert_eq!(snapshot.backend, 10);
        assert_eq!(debt.generation(), u64::MAX);
        t.finish_disposal(debt).unwrap();
        assert_eq!(t.holds[0].changed.load(Ordering::Relaxed), u32::MAX);
        t.place(0, 20, Flags::default()).unwrap();
        assert_eq!(t.begin_io(owner(2), 0, 2), Err(Error::TooManyOpenFiles));
    }

    #[test]
    fn fork_discards_pins_and_disposal_without_rpc_and_preserves_published_entries() {
        let mut t = table();
        let (pinned, _) = t.begin_io(owner(1), 0, 1).unwrap();
        t.place(1, 20, Flags::default()).unwrap();
        let (old, _) = t.begin_io(owner(2), 1, 2).unwrap();
        t.close(1).unwrap();
        let (debt, _) = cleanup(t.finish_io(old, owner(2)).unwrap());
        t.discard_open_after_fork();
        assert!(t.io_snapshot(pinned).is_err());
        assert!(t.disposal_snapshot(debt).is_err());
        assert_eq!(t.get(0), Ok(10));
        assert_eq!(t.close(0), Ok(Some(10)));
        assert_eq!(t.io_tokens().count(), 0);
        assert_eq!(t.disposal_tokens().count(), 0);
    }

    #[test]
    fn published_open_cleanup_transfers_last_debt_to_recoverable_io() {
        let mut t = table();
        let (open, claim) = t.begin_open(owner(1), 8).unwrap();
        t.reserve_open(claim, 0, Flags::default()).unwrap();
        t.stage_committed(claim, 20).unwrap();
        let entry = t.publish_open(claim).unwrap();
        let (io, _) = t.begin_io(owner(2), entry.fd, 22).unwrap();
        assert!(matches!(
            t.abandon_open_with_recovery(open, 88),
            Ok(Abandoned::Discarded { release: None, .. })
        ));
        let (_, snapshot) = cleanup(t.finish_io(io, owner(2)).unwrap());
        assert_eq!(snapshot.backend, 20);
    }

    #[test]
    fn early_release_and_wrong_kind_tokens_fail_before_mutation() {
        let mut t = Table::<u32, 1, u64>::with_early_release(|_| true);
        t.place(0, 10, Flags::default()).unwrap();
        assert_eq!(t.begin_io(owner(1), 0, 7), Err(Error::InvalidArgument));
        let (open, _) = t.begin_open(owner(1), 1).unwrap();
        let io = IoToken {
            slot: open.slot(),
            generation: open.generation(),
        };
        let debt = DisposalToken {
            slot: open.slot(),
            generation: open.generation(),
        };
        assert!(t.io_snapshot(io).is_err());
        assert!(t.finish_io(io, owner(1)).is_err());
        assert!(t.disposal_snapshot(debt).is_err());
        assert!(t.finish_disposal(debt).is_err());
        assert_eq!(t.open_snapshot(open).unwrap().recovery, Some(1));
    }

    #[test]
    fn in_place_initializer_and_layout_cover_new_resident_variants() {
        use core::mem::{MaybeUninit, size_of};
        type Small = Table<u32, 4, [u64; 3]>;
        assert_eq!(size_of::<IoRecord<u32, [u64; 3]>>(), 40);
        assert_eq!(size_of::<DisposalSnapshot<u32, [u64; 3]>>(), 32);
        assert_eq!(size_of::<Table<u32, 32, [u64; 3]>>(), 6544);
        assert_eq!(size_of::<Table<u32, 32, [u64; 3], [u8; 1012]>>(), 54160);
        let mut place = MaybeUninit::<Small>::uninit();
        // SAFETY: aligned uninitialized complete allocation is exclusively owned.
        unsafe {
            Small::initialize_at(place.as_mut_ptr(), |_| false);
        }
        // SAFETY: every table field was initialized before this read.
        let mut t = unsafe { place.assume_init() };
        t.place(0, 10, Flags::default()).unwrap();
        let (io, _) = t.begin_io(owner(1), 0, [1, 2, 3]).unwrap();
        t.close(0).unwrap();
        let IoEnd::Cleanup { token, snapshot } = t.finish_io(io, owner(1)).unwrap() else {
            panic!()
        };
        assert_eq!(snapshot.cleanup, [1, 2, 3]);
        t.finish_disposal(token).unwrap();
    }
}
