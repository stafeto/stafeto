// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Prepaid control outcomes and immutable cleanup sharing descriptor recovery slots.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlToken {
    slot: usize,
    generation: u64,
}
impl ControlToken {
    pub fn slot(self) -> usize {
        self.slot
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlClaimToken {
    control: ControlToken,
    serial: u64,
}
impl ControlClaimToken {
    pub fn control(self) -> ControlToken {
        self.control
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlResult {
    Value(u64),
    Failed(i32),
}
impl ControlResult {
    pub fn into_result(self) -> Result<u64, i32> {
        match self {
            Self::Value(value) => Ok(value),
            Self::Failed(errno) => Err(errno),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlPhase {
    Working,
    Complete,
    CleanupRequired,
    Cleaning,
    Cleaned,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlSnapshot<C> {
    pub owner: Option<OwnerToken>,
    pub claimant: Option<OwnerToken>,
    pub phase: ControlPhase,
    pub recovery: C,
    pub result: Option<ControlResult>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlClaim<C> {
    Acquired {
        token: ControlClaimToken,
        snapshot: ControlSnapshot<C>,
    },
    Busy(OwnerToken),
    Complete(ControlResult),
    Cleanup(ControlSnapshot<C>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlCleanup<C> {
    pub token: ControlToken,
    pub recovery: C,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlAbandoned<C> {
    Recover {
        token: ControlToken,
        snapshot: ControlSnapshot<C>,
    },
    ClaimReleased(ControlToken),
    Discarded(ControlToken),
}
#[derive(Clone, Copy)]
enum Cleanup {
    Pending,
    Running,
    Done,
}
#[derive(Clone, Copy)]
pub(super) struct ControlRecord<C> {
    owner: Option<OwnerToken>,
    claimant: Option<OwnerToken>,
    serial: u64,
    recovery: C,
    result: Option<ControlResult>,
    cleanup: Cleanup,
}
impl<C: Copy> ControlRecord<C> {
    fn snapshot(self) -> ControlSnapshot<C> {
        let phase = match self.cleanup {
            Cleanup::Running => ControlPhase::Cleaning,
            Cleanup::Done => ControlPhase::Cleaned,
            Cleanup::Pending if self.owner.is_none() || self.serial == u64::MAX => {
                ControlPhase::CleanupRequired
            }
            Cleanup::Pending if self.result.is_some() => ControlPhase::Complete,
            Cleanup::Pending => ControlPhase::Working,
        };
        ControlSnapshot {
            owner: self.owner,
            claimant: self.claimant,
            phase,
            recovery: self.recovery,
            result: self.result,
        }
    }
}
impl<T: Copy + Eq, const N: usize, R: Copy, S: Copy, C: Copy> Table<T, N, R, S, C> {
    fn control_record(&self, token: ControlToken) -> Result<ControlRecord<C>, Error> {
        let slot = self.holds.get(token.slot).ok_or(Error::BadFileDescriptor)?;
        if slot.generation != token.generation {
            return Err(Error::BadFileDescriptor);
        }
        match slot.held {
            Held::Control(record) => Ok(record),
            _ => Err(Error::BadFileDescriptor),
        }
    }
    fn control_claimed(&self, claim: ControlClaimToken) -> Result<ControlRecord<C>, Error> {
        let record = self.control_record(claim.control)?;
        if record.serial != claim.serial
            || record.claimant.is_none()
            || record.owner.is_none()
            || !matches!(record.cleanup, Cleanup::Pending)
            || record.result.is_some()
            || record.serial == u64::MAX
        {
            return Err(Error::BadFileDescriptor);
        }
        Ok(record)
    }
    fn save_control(&mut self, token: ControlToken, record: ControlRecord<C>) {
        let slot = &mut self.holds[token.slot];
        slot.held = Held::Control(record);
        slot.change();
    }
    fn free_control(&mut self, token: ControlToken) {
        let slot = &mut self.holds[token.slot];
        slot.held = Held::Empty;
        slot.change();
    }
    /// Pay resident custody before creating endpoints or sending the first request.
    pub fn begin_control(
        &mut self,
        owner: OwnerToken,
        recovery: C,
    ) -> Result<(ControlToken, ControlClaimToken), Error> {
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
        let token = ControlToken {
            slot: index,
            generation: slot.generation,
        };
        let claim = ControlClaimToken {
            control: token,
            serial: 1,
        };
        slot.held = Held::Control(ControlRecord {
            owner: Some(owner),
            claimant: Some(owner),
            serial: 1,
            recovery,
            result: None,
            cleanup: Cleanup::Pending,
        });
        slot.change();
        Ok((token, claim))
    }
    pub fn control_snapshot(&self, token: ControlToken) -> Result<ControlSnapshot<C>, Error> {
        Ok(self.control_record(token)?.snapshot())
    }
    pub fn control_tokens(&self) -> impl Iterator<Item = ControlToken> + '_ {
        self.holds.iter().enumerate().filter_map(|(slot, h)| {
            matches!(h.held, Held::Control(_)).then_some(ControlToken {
                slot,
                generation: h.generation,
            })
        })
    }
    pub fn claim_control(
        &mut self,
        token: ControlToken,
        helper: OwnerToken,
    ) -> Result<ControlClaim<C>, Error> {
        let mut record = self.control_record(token)?;
        if !matches!(record.cleanup, Cleanup::Pending)
            || record.owner.is_none()
            || record.serial == u64::MAX
        {
            return Ok(ControlClaim::Cleanup(record.snapshot()));
        }
        if let Some(result) = record.result {
            return Ok(ControlClaim::Complete(result));
        }
        if let Some(owner) = record.claimant {
            return Ok(ControlClaim::Busy(owner));
        }
        let Some(serial) = record
            .serial
            .checked_add(1)
            .filter(|&serial| serial < u64::MAX)
        else {
            record.serial = u64::MAX;
            record.claimant = None;
            self.save_control(token, record);
            return Ok(ControlClaim::Cleanup(record.snapshot()));
        };
        record.serial = serial;
        record.claimant = Some(helper);
        self.save_control(token, record);
        Ok(ControlClaim::Acquired {
            token: ControlClaimToken {
                control: token,
                serial,
            },
            snapshot: record.snapshot(),
        })
    }
    pub fn update_control(&mut self, claim: ControlClaimToken, recovery: C) -> Result<(), Error> {
        let mut record = self.control_claimed(claim)?;
        record.recovery = recovery;
        self.save_control(claim.control, record);
        Ok(())
    }
    pub fn release_control_claim(&mut self, claim: ControlClaimToken) -> Result<(), Error> {
        let mut record = self.control_claimed(claim)?;
        record.claimant = None;
        self.save_control(claim.control, record);
        Ok(())
    }
    pub fn complete_control(
        &mut self,
        claim: ControlClaimToken,
        result: ControlResult,
    ) -> Result<(), Error> {
        if matches!(result, ControlResult::Failed(errno) if errno <= 0) {
            return Err(Error::InvalidArgument);
        }
        let mut record = self.control_claimed(claim)?;
        record.result = Some(result);
        record.claimant = None;
        self.save_control(claim.control, record);
        Ok(())
    }
    /// Copy the original outcome while retaining every unpaid cleanup obligation.
    pub fn ack_control(
        &mut self,
        token: ControlToken,
        owner: OwnerToken,
    ) -> Result<ControlResult, Error> {
        let mut record = self.control_record(token)?;
        if record.owner != Some(owner) {
            return Err(Error::BadFileDescriptor);
        }
        let result = record.result.ok_or(Error::InvalidArgument)?;
        record.owner = None;
        if matches!(record.cleanup, Cleanup::Done) {
            self.free_control(token);
        } else {
            self.save_control(token, record);
        }
        Ok(result)
    }
    /// Revoke effect authority. Repeated cleanup uses this same immutable debt.
    /// The caller performs exact idempotent RPC and handle closure after unlocking.
    pub fn control_begin_cleanup(
        &mut self,
        token: ControlToken,
    ) -> Result<ControlCleanup<C>, Error> {
        let mut record = self.control_record(token)?;
        match record.cleanup {
            Cleanup::Done => return Err(Error::BadFileDescriptor),
            Cleanup::Running => {}
            Cleanup::Pending => {
                record.claimant = None;
                record.cleanup = Cleanup::Running;
                self.save_control(token, record);
            }
        }
        Ok(ControlCleanup {
            token,
            recovery: record.recovery,
        })
    }
    /// Finish only after canonical remote cleanup and exact local handle closure.
    /// Unknown prior effects retain terminal EIO and permit no fresh attempt.
    pub fn control_finish_cleanup(&mut self, token: ControlToken) -> Result<(), Error> {
        let mut record = self.control_record(token)?;
        match record.cleanup {
            Cleanup::Pending => return Err(Error::BadFileDescriptor),
            Cleanup::Done => return Ok(()),
            Cleanup::Running => {}
        }
        if record.result.is_none() {
            record.result = Some(ControlResult::Failed(5));
        }
        record.cleanup = Cleanup::Done;
        record.claimant = None;
        if record.owner.is_none() {
            self.free_control(token);
        } else {
            self.save_control(token, record);
        }
        Ok(())
    }
    pub fn abandon_control(&mut self, token: ControlToken) -> Result<ControlAbandoned<C>, Error> {
        let mut record = self.control_record(token)?;
        record.owner = None;
        record.claimant = None;
        if matches!(record.cleanup, Cleanup::Done) {
            self.free_control(token);
            Ok(ControlAbandoned::Discarded(token))
        } else {
            self.save_control(token, record);
            Ok(ControlAbandoned::Recover {
                token,
                snapshot: record.snapshot(),
            })
        }
    }
    /// Detach one native lifetime. Cleanup keeps its immutable capabilities and key.
    pub fn abandon_control_owner(&mut self, owner: OwnerToken) -> Option<ControlAbandoned<C>> {
        let (slot, record) = self
            .holds
            .iter()
            .enumerate()
            .find_map(|(slot, h)| match h.held {
                Held::Control(record)
                    if record.owner == Some(owner) || record.claimant == Some(owner) =>
                {
                    Some((slot, record))
                }
                _ => None,
            })?;
        let token = ControlToken {
            slot,
            generation: self.holds[slot].generation,
        };
        if record.owner == Some(owner) {
            return self.abandon_control(token).ok();
        }
        let mut record = record;
        record.claimant = None;
        self.save_control(token, record);
        Some(ControlAbandoned::ClaimReleased(token))
    }
    /// This address remains stable through reuse; wake occurs after unlocking.
    pub fn control_wait_word(&self, token: ControlToken) -> Result<&AtomicU32, Error> {
        self.holds
            .get(token.slot)
            .map(|slot| &slot.changed)
            .ok_or(Error::BadFileDescriptor)
    }
    pub fn control_wait_snapshot(&self, token: ControlToken) -> Result<WaitValue, Error> {
        self.control_record(token)?;
        let sequence = self.holds[token.slot].changed.load(Ordering::Acquire);
        Ok(if sequence == u32::MAX {
            WaitValue::NeverSleep
        } else {
            WaitValue::Sequence(sequence)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_layout_preserves_existing_payload_union_capacity() {
        use core::mem::size_of;
        type Base = Table<u32, 32, [u64; 3]>;
        type Control = Table<u32, 32, [u64; 3], (), [u64; 15]>;
        type ExistingWrite = Table<u32, 32, [u64; 3], [u8; 1012]>;
        type Write = Table<u32, 32, [u64; 3], [u8; 1012], [u64; 15]>;
        type Read = Table<u32, 32, [u64; 3], [u8; 1016], [u64; 15]>;
        assert_eq!(size_of::<ControlRecord<[u64; 15]>>(), 168);
        assert_eq!(size_of::<Base>(), 3848);
        assert!(size_of::<Control>() > size_of::<Base>());
        assert_eq!(size_of::<Write>(), size_of::<ExistingWrite>());
        assert_eq!(size_of::<Write>(), 35592);
        assert_eq!(size_of::<Read>(), size_of::<Write>());
    }
    fn owner(id: u64) -> OwnerToken {
        OwnerToken::new(id).unwrap()
    }
    fn acquired(claim: ControlClaim<u64>) -> ControlClaimToken {
        match claim {
            ControlClaim::Acquired { token, .. } => token,
            _ => panic!("control claim"),
        }
    }
    type Small = Table<u32, 4, u64, u64, u64>;

    #[test]
    fn result_and_cleanup_acknowledgments_preserve_first_outcome_in_both_orders() {
        for cleanup_first in [false, true] {
            let mut table = Small::default();
            let (token, claim) = table.begin_control(owner(1), 70).unwrap();
            let before = table.control_snapshot(token).unwrap();
            for errno in [0, -1] {
                assert_eq!(
                    table.complete_control(claim, ControlResult::Failed(errno)),
                    Err(Error::InvalidArgument)
                );
                assert_eq!(table.control_snapshot(token).unwrap(), before);
            }
            assert_eq!(
                table.ack_control(token, owner(1)),
                Err(Error::InvalidArgument)
            );
            assert_eq!(
                table.control_finish_cleanup(token),
                Err(Error::BadFileDescriptor)
            );
            table
                .complete_control(claim, ControlResult::Value(u64::MAX))
                .unwrap();
            assert_eq!(
                table.claim_control(token, owner(2)),
                Ok(ControlClaim::Complete(ControlResult::Value(u64::MAX)))
            );
            assert_eq!(
                table.update_control(claim, 99),
                Err(Error::BadFileDescriptor)
            );
            if cleanup_first {
                let cleanup = table.control_begin_cleanup(token).unwrap();
                assert_eq!(cleanup.recovery, 70);
                table.control_finish_cleanup(token).unwrap();
                table.control_finish_cleanup(token).unwrap();
                assert_eq!(table.control_tokens().count(), 1);
            }
            assert_eq!(
                table.ack_control(token, owner(2)),
                Err(Error::BadFileDescriptor)
            );
            assert_eq!(
                table.ack_control(token, owner(1)).unwrap().into_result(),
                Ok(u64::MAX)
            );
            if !cleanup_first {
                assert_eq!(table.control_tokens().count(), 1);
                let debt = table.control_begin_cleanup(token).unwrap();
                assert_eq!(table.control_begin_cleanup(token), Ok(debt));
                table.control_finish_cleanup(token).unwrap();
            }
            assert_eq!(table.control_tokens().count(), 0);
            assert_eq!(table.control_snapshot(token), Err(Error::BadFileDescriptor));
        }
    }

    #[test]
    fn helper_and_original_end_keep_immutable_debt_and_revoke_effect_authority() {
        let mut table = Small::default();
        let (token, first) = table.begin_control(owner(1), 70).unwrap();
        assert_eq!(
            table.claim_control(token, owner(2)),
            Ok(ControlClaim::Busy(owner(1)))
        );
        table.release_control_claim(first).unwrap();
        let second = acquired(table.claim_control(token, owner(2)).unwrap());
        table.update_control(second, 71).unwrap();
        assert_eq!(
            table.abandon_control_owner(owner(2)),
            Some(ControlAbandoned::ClaimReleased(token))
        );
        let third = acquired(table.claim_control(token, owner(3)).unwrap());
        assert_eq!(
            table.complete_control(second, ControlResult::Value(8)),
            Err(Error::BadFileDescriptor)
        );
        assert!(matches!(
            table.abandon_control_owner(owner(1)),
            Some(ControlAbandoned::Recover { .. })
        ));
        assert!(matches!(
            table.claim_control(token, owner(4)),
            Ok(ControlClaim::Cleanup(_))
        ));
        assert_eq!(
            table.complete_control(third, ControlResult::Value(9)),
            Err(Error::BadFileDescriptor)
        );
        let debt = table.control_begin_cleanup(token).unwrap();
        assert_eq!(debt.recovery, 71);
        assert_eq!(table.control_begin_cleanup(token), Ok(debt));
        assert_eq!(
            table.update_control(third, 99),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.abandon_control_owner(owner(3)), None);
        assert_eq!(table.control_snapshot(token).unwrap().recovery, 71);
        table.control_finish_cleanup(token).unwrap();
        assert_eq!(table.control_tokens().count(), 0);
        let (token, claim) = table.begin_control(owner(1), 72).unwrap();
        table.control_begin_cleanup(token).unwrap();
        assert_eq!(
            table.complete_control(claim, ControlResult::Value(9)),
            Err(Error::BadFileDescriptor)
        );
        table.control_finish_cleanup(token).unwrap();
        assert_eq!(
            table.ack_control(token, owner(1)),
            Ok(ControlResult::Failed(5))
        );
    }

    #[test]
    fn mixed_32_budget_keeps_acknowledged_debt_and_other_backend_pins() {
        let mut table = Table::<u32, 32, u64, u64, u64>::default();
        let io_fd = table.insert(10, Flags::default()).unwrap();
        table.hold(io_fd).unwrap();
        let scalar_fd = table.insert(20, Flags::default()).unwrap();
        let (scalar, _) = table.begin_scalar(owner(1), scalar_fd, 200).unwrap();
        let (open, _) = table.begin_open(owner(1), 300).unwrap();
        let mut last = None;
        for value in 0..29 {
            last = Some(table.begin_control(owner(1), value).unwrap());
        }
        assert_eq!(
            table.begin_control(owner(2), 999),
            Err(Error::TooManyOpenFiles)
        );
        assert_eq!(
            table.begin_open(owner(2), 999),
            Err(Error::TooManyOpenFiles)
        );
        let (token, claim) = last.unwrap();
        table
            .complete_control(claim, ControlResult::Value(31))
            .unwrap();
        assert_eq!(
            table.ack_control(token, owner(1)),
            Ok(ControlResult::Value(31))
        );
        assert_eq!(
            table.begin_control(owner(2), 999),
            Err(Error::TooManyOpenFiles)
        );
        assert_eq!(table.close(io_fd), Ok(None));
        assert_eq!(table.close(scalar_fd), Ok(None));
        assert_eq!(table.scalar_snapshot(scalar).unwrap().pin, Some(20));
        assert_eq!(table.open_snapshot(open).unwrap().recovery, Some(300));
        table.control_begin_cleanup(token).unwrap();
        table.control_finish_cleanup(token).unwrap();
        assert!(table.begin_control(owner(2), 999).is_ok());
        assert_eq!(table.unhold(10), Some(10));
        assert_eq!(table.scalar_snapshot(scalar).unwrap().pin, Some(20));
    }

    #[test]
    fn old_tokens_and_wrong_record_kinds_preserve_new_custody() {
        let mut table = Small::default();
        let (old, old_claim) = table.begin_control(owner(1), 70).unwrap();
        table.control_begin_cleanup(old).unwrap();
        table.control_finish_cleanup(old).unwrap();
        table.ack_control(old, owner(1)).unwrap();
        let (new, _) = table.begin_control(owner(2), 80).unwrap();
        assert_eq!(old.slot, new.slot);
        assert!(new.generation > old.generation);
        let before = table.control_snapshot(new).unwrap();
        assert_eq!(
            table.control_begin_cleanup(old),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(
            table.control_finish_cleanup(old),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(
            table.update_control(old_claim, 99),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.control_snapshot(new).unwrap(), before);
        let (open, _) = table.begin_open(owner(1), 90).unwrap();
        let fake = ControlToken {
            slot: open.slot(),
            generation: open.generation(),
        };
        assert_eq!(table.control_snapshot(fake), Err(Error::BadFileDescriptor));
        assert_eq!(
            table.control_begin_cleanup(fake),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(table.open_snapshot(open).unwrap().recovery, Some(90));
    }

    #[test]
    fn terminal_counters_preserve_cleanup_and_stable_wait_address() {
        let mut table = Small::default();
        table.holds[0].generation = u64::MAX - 1;
        let (token, claim) = table.begin_control(owner(1), 70).unwrap();
        let address = table.control_wait_word(token).unwrap() as *const AtomicU32;
        table.holds[0]
            .changed
            .store(u32::MAX - 1, Ordering::Relaxed);
        table.release_control_claim(claim).unwrap();
        assert_eq!(
            table.control_wait_snapshot(token),
            Ok(WaitValue::NeverSleep)
        );
        let Held::Control(record) = &mut table.holds[0].held else {
            panic!("control")
        };
        record.serial = u64::MAX - 1;
        assert!(matches!(
            table.claim_control(token, owner(2)),
            Ok(ControlClaim::Cleanup(_))
        ));
        let debt = table.control_begin_cleanup(token).unwrap();
        assert_eq!(table.control_begin_cleanup(token), Ok(debt));
        table.control_finish_cleanup(token).unwrap();
        assert_eq!(
            table.ack_control(token, owner(1)),
            Ok(ControlResult::Failed(5))
        );
        assert_eq!(
            table.control_wait_word(token).unwrap() as *const AtomicU32,
            address
        );
        let (next, _) = table.begin_control(owner(1), 80).unwrap();
        assert_ne!(token.slot, next.slot);
        assert_eq!(
            table.control_finish_cleanup(token),
            Err(Error::BadFileDescriptor)
        );
    }

    #[test]
    fn fieldwise_initializer_and_fork_discard_keep_published_entries() {
        type Large = Table<u32, 32, u64, [u8; 1016], [u64; 15]>;
        let mut storage = core::mem::MaybeUninit::<Large>::uninit();
        // SAFETY: exclusive aligned uninitialized storage covers the complete table.
        unsafe { Large::initialize_at(storage.as_mut_ptr(), |_| false) };
        // SAFETY: initialize_at wrote every live field and enum discriminant.
        let mut table = unsafe { storage.assume_init() };
        let fd = table.insert(17, Flags::default()).unwrap();
        let (token, _) = table.begin_control(owner(1), [17; 15]).unwrap();
        assert_eq!(table.control_snapshot(token).unwrap().recovery, [17; 15]);
        let (open, claim) = table.begin_open(owner(1), 70).unwrap();
        let pending = table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.discard_open_after_fork();
        assert_eq!(table.get(fd), Ok(17));
        assert_eq!(table.pending(pending.fd), None);
        assert_eq!(table.control_tokens().count(), 0);
        assert_eq!(table.open_tokens().count(), 0);
        assert_eq!(table.control_snapshot(token), Err(Error::BadFileDescriptor));
        assert_eq!(table.open_snapshot(open), Err(Error::BadFileDescriptor));
        let (next, _) = table.begin_control(owner(2), [18; 15]).unwrap();
        assert!(next.generation > token.generation);
        assert_eq!(table.get(fd), Ok(17));
    }
}
