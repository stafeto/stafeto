// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Resident scalar results with independently acknowledged remote cleanup.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarToken {
    slot: usize,
    generation: u64,
}

impl ScalarToken {
    pub fn slot(self) -> usize {
        32 + self.slot
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarClaimToken {
    scalar: ScalarToken,
    serial: u64,
}

impl ScalarClaimToken {
    pub fn scalar(self) -> ScalarToken {
        self.scalar
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarResult {
    Bytes(u64),
    Failed(i32),
}

impl ScalarResult {
    pub fn into_result(self) -> Result<u64, i32> {
        match self {
            Self::Bytes(n) => Ok(n),
            Self::Failed(errno) => Err(errno),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarPhase {
    Working,
    Complete,
    CleanupRequired,
    Cleaning,
    Cleaned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarSnapshot<T, S> {
    pub owner: Option<OwnerToken>,
    pub claimant: Option<OwnerToken>,
    pub phase: ScalarPhase,
    pub recovery: S,
    pub pin: Option<T>,
    pub result: Option<ScalarResult>,
    pub last_target: Option<T>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarClaim<T, S> {
    Acquired {
        token: ScalarClaimToken,
        snapshot: ScalarSnapshot<T, S>,
    },
    Busy(OwnerToken),
    Complete(ScalarResult),
    Cleanup(ScalarSnapshot<T, S>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarCleanup<T, S> {
    pub token: ScalarToken,
    pub recovery: S,
    /// The resident debt survives helper death until exact remote confirmation.
    pub last_target: Option<T>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarAbandoned<T, S> {
    Recover {
        token: ScalarToken,
        snapshot: ScalarSnapshot<T, S>,
    },
    ClaimReleased(ScalarToken),
    Discarded(ScalarToken),
}

#[derive(Clone, Copy)]
enum Cleanup<T> {
    Pending,
    Running { last_target: Option<T> },
    Done,
}

#[derive(Clone, Copy)]
pub(super) struct ScalarRecord<T, S> {
    owner: Option<OwnerToken>,
    claimant: Option<OwnerToken>,
    serial: u64,
    recovery: S,
    pin: Option<T>,
    result: Option<ScalarResult>,
    cleanup: Cleanup<T>,
}

impl<T: Copy, S: Copy> ScalarRecord<T, S> {
    pub(super) fn owner(&self) -> Option<OwnerToken> {
        self.owner
    }
    fn snapshot(self) -> ScalarSnapshot<T, S> {
        let (phase, last_target) = match self.cleanup {
            Cleanup::Running { last_target } => (ScalarPhase::Cleaning, last_target),
            Cleanup::Done => (ScalarPhase::Cleaned, None),
            Cleanup::Pending if self.result.is_some() => (ScalarPhase::Complete, None),
            Cleanup::Pending if self.serial == u64::MAX => (ScalarPhase::CleanupRequired, None),
            Cleanup::Pending => (ScalarPhase::Working, None),
        };
        ScalarSnapshot {
            owner: self.owner,
            claimant: self.claimant,
            phase,
            recovery: self.recovery,
            pin: self.pin,
            result: self.result,
            last_target,
        }
    }
}

impl<T: Copy + Eq, const N: usize, R: Copy, S: Copy, C: Copy> Table<T, N, R, S, C> {
    pub(super) fn scalar_pinned(&self, backend: T) -> bool {
        self.residents
            .iter()
            .any(|slot| matches!(slot.held, Held::Scalar(r) if r.pin == Some(backend)))
    }

    fn scalar_record(&self, token: ScalarToken) -> Result<ScalarRecord<T, S>, Error> {
        let slot = self
            .residents
            .get(token.slot)
            .ok_or(Error::BadFileDescriptor)?;
        if slot.generation != token.generation {
            return Err(Error::BadFileDescriptor);
        }
        match slot.held {
            Held::Scalar(record) => Ok(record),
            _ => Err(Error::BadFileDescriptor),
        }
    }

    fn scalar_claimed(&self, token: ScalarClaimToken) -> Result<ScalarRecord<T, S>, Error> {
        let record = self.scalar_record(token.scalar)?;
        if record.serial != token.serial
            || record.claimant.is_none()
            || !matches!(record.cleanup, Cleanup::Pending)
            || record.result.is_some()
            || record.serial == u64::MAX
        {
            return Err(Error::BadFileDescriptor);
        }
        Ok(record)
    }

    fn save_scalar(&mut self, token: ScalarToken, record: ScalarRecord<T, S>) {
        let slot = &mut self.residents[token.slot];
        slot.held = Held::Scalar(record);
        slot.change();
    }

    fn free_scalar(&mut self, token: ScalarToken) {
        let slot = &mut self.residents[token.slot];
        slot.held = Held::Empty;
        slot.change();
        self.job_gone();
    }

    /// Pay recovery and a backend pin together before any remote effect.
    /// Scalar operations use backends whose close waits for ordinary holds.
    pub fn begin_scalar(
        &mut self,
        owner: OwnerToken,
        fd: u32,
        recovery: S,
    ) -> Result<(ScalarToken, ScalarClaimToken), Error> {
        let backend = self.get(fd)?;
        if (self.release_early)(backend) {
            return Err(Error::InvalidArgument);
        }
        let (index, slot) = self
            .residents
            .iter_mut()
            .take(N.min(JOBS_MAX))
            .enumerate()
            .find(|(_, slot)| {
                matches!(slot.held, Held::Empty)
                    && slot.generation < u64::MAX
                    && slot.changed.load(Ordering::Relaxed) < u32::MAX
            })
            .ok_or(Error::TooManyOpenFiles)?;
        slot.generation += 1;
        let scalar = ScalarToken {
            slot: index,
            generation: slot.generation,
        };
        let claim = ScalarClaimToken { scalar, serial: 1 };
        slot.held = Held::Scalar(ScalarRecord {
            owner: Some(owner),
            claimant: Some(owner),
            serial: 1,
            recovery,
            pin: Some(backend),
            result: None,
            cleanup: Cleanup::Pending,
        });
        slot.change();
        Ok((scalar, claim))
    }

    pub fn scalar_snapshot(&self, token: ScalarToken) -> Result<ScalarSnapshot<T, S>, Error> {
        Ok(self.scalar_record(token)?.snapshot())
    }

    /// Inspect the exact current claim without changing the resident wait word.
    pub fn scalar_claim_snapshot(
        &self,
        claim: ScalarClaimToken,
    ) -> Result<ScalarSnapshot<T, S>, Error> {
        Ok(self.scalar_claimed(claim)?.snapshot())
    }

    pub fn scalar_tokens(&self) -> impl Iterator<Item = ScalarToken> + '_ {
        self.residents.iter().enumerate().filter_map(|(slot, h)| {
            matches!(h.held, Held::Scalar(_)).then_some(ScalarToken {
                slot,
                generation: h.generation,
            })
        })
    }

    pub fn claim_scalar(
        &mut self,
        token: ScalarToken,
        helper: OwnerToken,
    ) -> Result<ScalarClaim<T, S>, Error> {
        let mut record = self.scalar_record(token)?;
        if !matches!(record.cleanup, Cleanup::Pending) || record.serial == u64::MAX {
            return Ok(ScalarClaim::Cleanup(record.snapshot()));
        }
        if let Some(result) = record.result {
            return Ok(ScalarClaim::Complete(result));
        }
        if let Some(owner) = record.claimant {
            return Ok(ScalarClaim::Busy(owner));
        }
        let Some(serial) = record.serial.checked_add(1).filter(|&s| s < u64::MAX) else {
            record.serial = u64::MAX;
            record.claimant = None;
            self.save_scalar(token, record);
            return Ok(ScalarClaim::Cleanup(record.snapshot()));
        };
        record.serial = serial;
        record.claimant = Some(helper);
        self.save_scalar(token, record);
        Ok(ScalarClaim::Acquired {
            token: ScalarClaimToken {
                scalar: token,
                serial,
            },
            snapshot: record.snapshot(),
        })
    }

    pub fn update_scalar(&mut self, claim: ScalarClaimToken, recovery: S) -> Result<(), Error> {
        let mut record = self.scalar_claimed(claim)?;
        record.recovery = recovery;
        self.save_scalar(claim.scalar, record);
        Ok(())
    }

    pub fn release_scalar_claim(&mut self, claim: ScalarClaimToken) -> Result<(), Error> {
        let mut record = self.scalar_claimed(claim)?;
        record.claimant = None;
        self.save_scalar(claim.scalar, record);
        Ok(())
    }

    pub fn complete_scalar(
        &mut self,
        claim: ScalarClaimToken,
        result: ScalarResult,
    ) -> Result<(), Error> {
        if matches!(result, ScalarResult::Failed(errno) if errno <= 0) {
            return Err(Error::InvalidArgument);
        }
        let mut record = self.scalar_claimed(claim)?;
        record.result = Some(result);
        record.claimant = None;
        self.save_scalar(claim.scalar, record);
        Ok(())
    }

    /// Copy the original result before handlers. Remote cleanup remains resident.
    pub fn ack_scalar(
        &mut self,
        token: ScalarToken,
        owner: OwnerToken,
    ) -> Result<ScalarResult, Error> {
        let mut record = self.scalar_record(token)?;
        if record.owner != Some(owner) {
            return Err(Error::BadFileDescriptor);
        }
        let result = record.result.ok_or(Error::InvalidArgument)?;
        record.owner = None;
        if matches!(record.cleanup, Cleanup::Done) {
            self.free_scalar(token);
        } else {
            self.save_scalar(token, record);
        }
        Ok(result)
    }

    /// Revoke effect authority and detach the pin once. The returned immutable
    /// debt remains resident through helper death and repeated cleanup attempts.
    pub fn scalar_begin_cleanup(
        &mut self,
        token: ScalarToken,
    ) -> Result<ScalarCleanup<T, S>, Error> {
        let mut record = self.scalar_record(token)?;
        let last_target = match record.cleanup {
            Cleanup::Running { last_target } => last_target,
            Cleanup::Done => return Err(Error::BadFileDescriptor),
            Cleanup::Pending => {
                let backend = record.pin.take().expect("pending scalar pin");
                record.claimant = None;
                self.save_scalar(token, record);
                let last_target = self.left(backend);
                record.cleanup = Cleanup::Running { last_target };
                self.save_scalar(token, record);
                last_target
            }
        };
        Ok(ScalarCleanup {
            token,
            recovery: record.recovery,
            last_target,
        })
    }

    /// The caller proves canonical exact remote cleanup. An unresolved outcome
    /// becomes terminal EIO; it can include an earlier committed effect.
    pub fn scalar_finish_cleanup(&mut self, token: ScalarToken) -> Result<(), Error> {
        let mut record = self.scalar_record(token)?;
        match record.cleanup {
            Cleanup::Pending => return Err(Error::BadFileDescriptor),
            Cleanup::Done => return Ok(()),
            Cleanup::Running { .. } => {}
        }
        if record.result.is_none() {
            record.result = Some(ScalarResult::Failed(5));
        }
        record.cleanup = Cleanup::Done;
        record.claimant = None;
        if record.owner.is_none() {
            self.free_scalar(token);
        } else {
            self.save_scalar(token, record);
        }
        Ok(())
    }

    /// Detach an original lifetime while keeping its remote recovery obligation.
    pub fn abandon_scalar(&mut self, token: ScalarToken) -> Result<ScalarAbandoned<T, S>, Error> {
        let mut record = self.scalar_record(token)?;
        record.owner = None;
        record.claimant = None;
        if matches!(record.cleanup, Cleanup::Done) {
            self.free_scalar(token);
            Ok(ScalarAbandoned::Discarded(token))
        } else {
            self.save_scalar(token, record);
            Ok(ScalarAbandoned::Recover {
                token,
                snapshot: record.snapshot(),
            })
        }
    }

    /// Detach one original or helper reference. Native lifetime checks belong
    /// to the caller, whose final detach precedes reusable thread-place release.
    pub fn abandon_scalar_owner(&mut self, owner: OwnerToken) -> Option<ScalarAbandoned<T, S>> {
        let (slot, record) =
            self.residents
                .iter()
                .enumerate()
                .find_map(|(slot, h)| match h.held {
                    Held::Scalar(record)
                        if record.owner == Some(owner) || record.claimant == Some(owner) =>
                    {
                        Some((slot, record))
                    }
                    _ => None,
                })?;
        let token = ScalarToken {
            slot,
            generation: self.residents[slot].generation,
        };
        if record.owner == Some(owner) {
            return self.abandon_scalar(token).ok();
        }
        let mut record = record;
        record.claimant = None;
        self.save_scalar(token, record);
        Some(ScalarAbandoned::ClaimReleased(token))
    }

    /// Stable hold-header address; wake and all RPC happen after unlocking.
    pub fn scalar_wait_word(&self, token: ScalarToken) -> Result<&AtomicU32, Error> {
        self.residents
            .get(token.slot)
            .map(|slot| &slot.changed)
            .ok_or(Error::BadFileDescriptor)
    }

    pub fn scalar_wait_snapshot(&self, token: ScalarToken) -> Result<WaitValue, Error> {
        self.scalar_record(token)?;
        let sequence = self.residents[token.slot].changed.load(Ordering::Acquire);
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

    fn owner(n: u64) -> OwnerToken {
        OwnerToken::new(n).unwrap()
    }
    fn table() -> Table<u32, 4, u64, u64> {
        let mut t = Table::default();
        t.place(0, 10, Flags::default()).unwrap();
        t
    }

    #[test]
    fn claim_snapshot_preserves_wait_and_rejects_released_or_completed_claims() {
        let mut t = table();
        let (token, first) = t.begin_scalar(owner(1), 0, 71).unwrap();
        let before = t.scalar_wait_snapshot(token).unwrap();
        assert_eq!(t.scalar_claim_snapshot(first), t.scalar_snapshot(token));
        assert_eq!(t.scalar_wait_snapshot(token).unwrap(), before);
        t.release_scalar_claim(first).unwrap();
        let ScalarClaim::Acquired { token: next, .. } = t.claim_scalar(token, owner(2)).unwrap()
        else {
            panic!("new current claim")
        };
        let before = t.scalar_wait_snapshot(token).unwrap();
        assert_eq!(
            t.scalar_claim_snapshot(first),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(t.scalar_claim_snapshot(next), t.scalar_snapshot(token));
        assert_eq!(t.scalar_wait_snapshot(token).unwrap(), before);
        t.complete_scalar(next, ScalarResult::Bytes(3)).unwrap();
        assert_eq!(t.scalar_claim_snapshot(next), Err(Error::BadFileDescriptor));
        assert_eq!(
            t.scalar_snapshot(token).unwrap().result,
            Some(ScalarResult::Bytes(3))
        );
    }

    #[test]
    fn result_survives_ack_before_cleanup_and_remote_cleanup_first() {
        for ack_first in [false, true] {
            let mut t = table();
            let (token, claim) = t.begin_scalar(owner(1), 0, 71).unwrap();
            t.complete_scalar(claim, ScalarResult::Bytes(13)).unwrap();
            assert_eq!(t.close(0), Ok(None));
            if ack_first {
                assert_eq!(t.ack_scalar(token, owner(1)), Ok(ScalarResult::Bytes(13)));
            }
            let cleanup = t.scalar_begin_cleanup(token).unwrap();
            assert_eq!(cleanup.last_target, Some(10));
            assert_eq!(cleanup.recovery, 71);
            assert_eq!(t.scalar_begin_cleanup(token), Ok(cleanup));
            assert!(t.complete_scalar(claim, ScalarResult::Bytes(99)).is_err());
            t.scalar_finish_cleanup(token).unwrap();
            if !ack_first {
                assert_eq!(
                    t.scalar_snapshot(token).unwrap().result,
                    Some(ScalarResult::Bytes(13))
                );
                assert_eq!(t.ack_scalar(token, owner(1)), Ok(ScalarResult::Bytes(13)));
            }
            assert!(t.scalar_snapshot(token).is_err());
            assert!(t.scalar_finish_cleanup(token).is_err());
        }
    }

    #[test]
    fn failed_result_is_preserved_and_invalid_errno_has_no_effect() {
        let mut t = table();
        let (token, claim) = t.begin_scalar(owner(1), 0, 1).unwrap();
        assert_eq!(
            t.complete_scalar(claim, ScalarResult::Failed(0)),
            Err(Error::InvalidArgument)
        );
        t.complete_scalar(claim, ScalarResult::Failed(28)).unwrap();
        t.scalar_begin_cleanup(token).unwrap();
        t.scalar_finish_cleanup(token).unwrap();
        assert_eq!(t.ack_scalar(token, owner(1)), Ok(ScalarResult::Failed(28)));
        assert_eq!(t.get(0), Ok(10));
    }

    #[test]
    fn helper_death_keeps_payload_then_reclaims_with_fresh_serial() {
        let mut t = table();
        let (token, original) = t.begin_scalar(owner(1), 0, 11).unwrap();
        assert_eq!(
            t.claim_scalar(token, owner(2)),
            Ok(ScalarClaim::Busy(owner(1)))
        );
        t.release_scalar_claim(original).unwrap();
        let ScalarClaim::Acquired { token: helper, .. } = t.claim_scalar(token, owner(2)).unwrap()
        else {
            panic!()
        };
        t.update_scalar(helper, 22).unwrap();
        assert_eq!(
            t.abandon_scalar_owner(owner(2)),
            Some(ScalarAbandoned::ClaimReleased(token))
        );
        let ScalarClaim::Acquired {
            token: sibling,
            snapshot,
        } = t.claim_scalar(token, owner(3)).unwrap()
        else {
            panic!()
        };
        assert_eq!(snapshot.recovery, 22);
        assert!(t.complete_scalar(helper, ScalarResult::Bytes(99)).is_err());
        t.complete_scalar(sibling, ScalarResult::Bytes(7)).unwrap();
        t.scalar_begin_cleanup(token).unwrap();
        t.scalar_finish_cleanup(token).unwrap();
        assert_eq!(t.ack_scalar(token, owner(1)), Ok(ScalarResult::Bytes(7)));
    }

    #[test]
    fn owner_death_and_cleanup_helper_death_keep_same_resident_debt() {
        let mut t = table();
        let (token, claim) = t.begin_scalar(owner(1), 0, 444).unwrap();
        t.complete_scalar(claim, ScalarResult::Bytes(2)).unwrap();
        t.close(0).unwrap();
        let cleanup = t.scalar_begin_cleanup(token).unwrap();
        assert_eq!(cleanup.last_target, Some(10));
        t.abandon_scalar_owner(owner(1)).unwrap();
        assert_eq!(t.scalar_begin_cleanup(token), Ok(cleanup));
        assert_eq!(
            t.scalar_snapshot(token).unwrap().result,
            Some(ScalarResult::Bytes(2))
        );
        assert!(t.ack_scalar(token, owner(1)).is_err());
        t.scalar_finish_cleanup(token).unwrap();
        assert!(t.scalar_snapshot(token).is_err());
    }

    #[test]
    fn unresolved_canonical_cleanup_returns_terminal_eio_to_live_owner() {
        let mut t = table();
        let (token, claim) = t.begin_scalar(owner(1), 0, 1).unwrap();
        assert!(t.scalar_finish_cleanup(token).is_err());
        t.scalar_begin_cleanup(token).unwrap();
        assert!(t.update_scalar(claim, 99).is_err());
        t.scalar_finish_cleanup(token).unwrap();
        assert_eq!(t.scalar_finish_cleanup(token), Ok(()));
        assert_eq!(t.ack_scalar(token, owner(1)), Ok(ScalarResult::Failed(5)));
    }

    #[test]
    fn aliases_and_io_pins_transfer_last_release_in_both_orders() {
        for io_first in [false, true] {
            let mut t = table();
            let alias = t.duplicate(0, 0, Flags::default()).unwrap();
            let (token, _) = t.begin_scalar(owner(1), 0, 1).unwrap();
            assert_eq!(t.hold(0), Ok(10));
            assert_eq!(t.close(0), Ok(None));
            assert_eq!(t.close(alias), Ok(None));
            if io_first {
                assert_eq!(t.unhold(10), None);
                assert_eq!(t.scalar_begin_cleanup(token).unwrap().last_target, Some(10));
            } else {
                assert_eq!(t.scalar_begin_cleanup(token).unwrap().last_target, None);
                assert_eq!(t.unhold(10), Some(10));
            }
            t.abandon_scalar(token).unwrap();
            t.scalar_finish_cleanup(token).unwrap();
        }
    }

    #[test]
    fn scalar_pins_delay_ordinary_abandon_and_other_scalar_cleanup() {
        let mut t = table();
        let (a, _) = t.begin_scalar(owner(1), 0, 1).unwrap();
        let (b, _) = t.begin_scalar(owner(2), 0, 2).unwrap();
        t.hold(0).unwrap();
        t.close(0).unwrap();
        assert_eq!(t.abandon_hold(), None);
        assert_eq!(t.scalar_begin_cleanup(a).unwrap().last_target, None);
        assert_eq!(t.scalar_begin_cleanup(b).unwrap().last_target, Some(10));
        assert_eq!(t.scalar_begin_cleanup(a).unwrap().last_target, None);
    }

    #[test]
    fn replacement_preserves_exact_old_debt_and_new_entry() {
        let mut t = table();
        let (token, claim) = t.begin_scalar(owner(1), 0, 1).unwrap();
        t.place(1, 20, Flags::default()).unwrap();
        assert_eq!(t.dup2(1, 0), Ok((0, None)));
        t.complete_scalar(claim, ScalarResult::Bytes(3)).unwrap();
        assert_eq!(t.scalar_begin_cleanup(token).unwrap().last_target, Some(10));
        t.scalar_finish_cleanup(token).unwrap();
        assert_eq!(t.ack_scalar(token, owner(1)), Ok(ScalarResult::Bytes(3)));
        assert_eq!(t.get(0), Ok(20));
        assert_eq!(t.get(1), Ok(20));
    }

    #[test]
    fn published_open_abandon_respects_scalar_pin() {
        let mut t = table();
        let (open, claim) = t.begin_open(owner(1), 8).unwrap();
        t.reserve_open(claim, 0, Flags::default()).unwrap();
        t.stage_committed(claim, 20).unwrap();
        let entry = t.publish_open(claim).unwrap();
        let (scalar, _) = t.begin_scalar(owner(2), entry.fd, 9).unwrap();
        assert!(matches!(
            t.abandon_open_with_recovery(open, 99),
            Ok(Abandoned::Discarded { release: None, .. })
        ));
        assert_eq!(
            t.scalar_begin_cleanup(scalar).unwrap().last_target,
            Some(20)
        );
    }

    #[test]
    fn shared_32_budget_fails_before_effect_and_survives_abandoned_cleanup() {
        let mut t = Table::<u32, 32, u64, u64>::default();
        for fd in 0..16 {
            t.place(fd, fd + 10, Flags::default()).unwrap();
            t.hold(fd).unwrap();
        }
        for _ in 0..8 {
            t.begin_open(owner(1), 1).unwrap();
        }
        let mut scalar = None;
        for _ in 0..8 {
            scalar = Some(t.begin_scalar(owner(1), 0, 2).unwrap().0);
        }
        assert_eq!(t.begin_scalar(owner(1), 0, 3), Err(Error::TooManyOpenFiles));
        assert_eq!(t.begin_open(owner(1), 3), Err(Error::TooManyOpenFiles));
        let token = scalar.unwrap();
        t.abandon_scalar(token).unwrap();
        assert_eq!(t.begin_scalar(owner(1), 0, 3), Err(Error::TooManyOpenFiles));
        t.scalar_begin_cleanup(token).unwrap();
        t.scalar_finish_cleanup(token).unwrap();
        let (next, _) = t.begin_scalar(owner(2), 0, 3).unwrap();
        assert_eq!(next.slot(), token.slot());
        assert!(next.generation() > token.generation());
        assert!(t.scalar_finish_cleanup(token).is_err());
        assert_eq!(t.scalar_snapshot(next).unwrap().recovery, 3);
    }

    #[test]
    fn serial_max_transition_revokes_effect_but_keeps_existing_cleanup() {
        let mut t = table();
        let (token, old) = t.begin_scalar(owner(1), 0, 1).unwrap();
        t.release_scalar_claim(old).unwrap();
        let Held::Scalar(record) = &mut t.residents[token.slot].held else {
            panic!()
        };
        record.serial = u64::MAX - 1;
        assert!(matches!(
            t.claim_scalar(token, owner(2)),
            Ok(ScalarClaim::Cleanup(ScalarSnapshot {
                phase: ScalarPhase::CleanupRequired,
                ..
            }))
        ));
        assert!(t.complete_scalar(old, ScalarResult::Bytes(9)).is_err());
        t.close(0).unwrap();
        assert_eq!(t.scalar_begin_cleanup(token).unwrap().last_target, Some(10));
        t.scalar_finish_cleanup(token).unwrap();
        assert_eq!(t.ack_scalar(token, owner(1)), Ok(ScalarResult::Failed(5)));
    }

    #[test]
    fn saturated_generations_and_waits_allow_paid_cleanup_and_stable_wait_address() {
        let mut t = Table::<u32, 1, (), u64>::default();
        t.place(0, 10, Flags::default()).unwrap();
        t.residents[0].generation = u64::MAX - 1;
        let (token, _) = t.begin_scalar(owner(1), 0, 1).unwrap();
        let address = t.scalar_wait_word(token).unwrap() as *const AtomicU32;
        t.residents[0].changed.store(u32::MAX, Ordering::Relaxed);
        assert_eq!(t.scalar_wait_snapshot(token), Ok(WaitValue::NeverSleep));
        t.abandon_scalar(token).unwrap();
        t.scalar_begin_cleanup(token).unwrap();
        assert_eq!(
            t.scalar_wait_word(token).unwrap() as *const AtomicU32,
            address
        );
        t.scalar_finish_cleanup(token).unwrap();
        assert_eq!(t.residents[0].changed.load(Ordering::Relaxed), u32::MAX);
        assert_eq!(t.begin_scalar(owner(2), 0, 2), Err(Error::TooManyOpenFiles));
    }

    #[test]
    fn fork_discard_drops_scalar_authority_without_releasing_inherited_entry() {
        let mut t = table();
        let (scalar, _) = t.begin_scalar(owner(1), 0, 1).unwrap();
        let (open, _) = t.begin_open(owner(1), 2).unwrap();
        t.discard_open_after_fork();
        assert!(t.scalar_snapshot(scalar).is_err());
        assert!(t.open_snapshot(open).is_err());
        assert_eq!(t.get(0), Ok(10));
        assert_eq!(t.close(0), Ok(Some(10)));
    }

    #[test]
    fn early_release_backends_and_wrong_kind_tokens_are_rejected_before_admission() {
        let mut t = Table::<u32, 1, (), u64>::with_early_release(|_| true);
        t.place(0, 10, Flags::default()).unwrap();
        assert_eq!(t.begin_scalar(owner(1), 0, 9), Err(Error::InvalidArgument));
        let (open, _) = t.begin_open(owner(1), ()).unwrap();
        let wrong = ScalarToken {
            slot: open.slot(),
            generation: open.generation(),
        };
        assert!(t.scalar_snapshot(wrong).is_err());
        assert!(t.scalar_finish_cleanup(wrong).is_err());
    }

    #[test]
    fn full_job_budget_last_target_debt_stays_paid_until_remote_confirmation() {
        let mut t = Table::<u32, 32, (), u64>::default();
        let mut chosen = None;
        for fd in 0..16 {
            t.place(fd, fd + 10, Flags::default()).unwrap();
            let (token, claim) = t.begin_scalar(owner(1), fd, u64::from(fd)).unwrap();
            t.complete_scalar(claim, ScalarResult::Bytes(1)).unwrap();
            if fd == 15 {
                chosen = Some(token);
            }
            assert_eq!(t.close(fd), Ok(None));
        }
        let token = chosen.unwrap();
        let cleanup = t.scalar_begin_cleanup(token).unwrap();
        assert_eq!(cleanup.last_target, Some(25));
        t.abandon_scalar(token).unwrap();
        t.place(0, 100, Flags::default()).unwrap();
        assert_eq!(
            t.begin_scalar(owner(2), 0, 99),
            Err(Error::TooManyOpenFiles)
        );
        assert_eq!(t.scalar_begin_cleanup(token), Ok(cleanup));
        assert_eq!(t.scalar_tokens().count(), 16);
        t.scalar_finish_cleanup(token).unwrap();
        let (next, _) = t.begin_scalar(owner(2), 0, 99).unwrap();
        assert_eq!(next.slot(), token.slot());
        assert!(t.scalar_finish_cleanup(token).is_err());
        assert_eq!(t.get(0), Ok(100));
    }

    #[test]
    fn same_backend_replacement_and_shared_open_namespace_preserve_lifetimes() {
        let mut t = table();
        let alias = t.duplicate(0, 0, Flags::default()).unwrap();
        let (token, claim) = t.begin_scalar(owner(1), 0, 1).unwrap();
        let old_entry = t.entry_token(0).unwrap();
        assert_eq!(t.dup2(alias, 0), Ok((0, None)));
        assert_ne!(t.entry_token(0).unwrap(), old_entry);
        t.complete_scalar(claim, ScalarResult::Bytes(0)).unwrap();
        assert_eq!(t.scalar_begin_cleanup(token).unwrap().last_target, None);
        t.scalar_finish_cleanup(token).unwrap();
        assert_eq!(t.ack_scalar(token, owner(1)), Ok(ScalarResult::Bytes(0)));
        let (open, _) = t.begin_open(owner(2), 9).unwrap();
        assert_eq!(open.slot(), token.slot());
        assert!(open.generation() > token.generation());
        assert!(t.scalar_begin_cleanup(token).is_err());
        assert_eq!(t.get(0), Ok(10));
        assert_eq!(t.get(alias), Ok(10));
    }

    #[test]
    fn wait_change_and_helper_ack_do_not_consume_original_result() {
        let mut t = table();
        let (token, claim) = t.begin_scalar(owner(1), 0, 1).unwrap();
        let before = t.scalar_wait_snapshot(token).unwrap();
        t.complete_scalar(claim, ScalarResult::Bytes(5)).unwrap();
        assert_ne!(t.scalar_wait_snapshot(token).unwrap(), before);
        assert_eq!(t.ack_scalar(token, owner(2)), Err(Error::BadFileDescriptor));
        assert_eq!(
            t.claim_scalar(token, owner(2)),
            Ok(ScalarClaim::Complete(ScalarResult::Bytes(5)))
        );
        t.scalar_begin_cleanup(token).unwrap();
        t.scalar_finish_cleanup(token).unwrap();
        assert_eq!(t.ack_scalar(token, owner(1)), Ok(ScalarResult::Bytes(5)));
        assert!(t.ack_scalar(token, owner(1)).is_err());
    }

    #[test]
    fn pinned_startup_initialization_matches_constructor_and_scalar_lifecycle() {
        extern crate std;
        use std::boxed::Box;
        type Large = Table<u32, 32, [u64; 3], [u8; 1012]>;
        let mut storage = Box::<Large>::new_uninit();
        let address = storage.as_mut_ptr();
        // SAFETY: Box owns aligned writable uninitialized Large storage;
        // startup is exclusive and the allocation remains fixed for this test.
        unsafe {
            Large::initialize_at(address, |_| false);
        }
        // SAFETY: initialize_at initialized every field of this allocation.
        let mut pinned = unsafe { storage.assume_init() };
        let mut ordinary = Large::default();
        assert_eq!((&*pinned as *const Large).cast_mut(), address);
        for table in [&mut *pinned, &mut ordinary] {
            assert_eq!(table.open().count(), 0);
            for slot in &table.residents {
                assert_eq!(slot.generation, 0);
                assert_eq!(slot.changed.load(Ordering::Relaxed), 0);
                assert!(matches!(slot.held, Held::Empty));
            }
            for fd in 0..32 {
                assert_eq!(table.entries[fd].generation, 0);
                assert_eq!(table.get(fd as u32), Err(Error::BadFileDescriptor));
                table
                    .place(fd as u32, fd as u32 + 10, Flags::default())
                    .unwrap();
            }
            let (token, claim) = table.begin_scalar(owner(1), 0, [17; 1012]).unwrap();
            table
                .complete_scalar(claim, ScalarResult::Bytes(31))
                .unwrap();
            table.close(0).unwrap();
            assert_eq!(
                table.scalar_begin_cleanup(token).unwrap().last_target,
                Some(10)
            );
            table.scalar_finish_cleanup(token).unwrap();
            assert_eq!(
                table.ack_scalar(token, owner(1)),
                Ok(ScalarResult::Bytes(31))
            );
        }
        assert!(pinned.open().eq(ordinary.open()));
        assert_eq!((&*pinned as *const Large).cast_mut(), address);
    }

    #[test]
    fn in_place_startup_preserves_early_release_configuration() {
        let mut storage = core::mem::MaybeUninit::<Table<u32, 2>>::uninit();
        // SAFETY: this exclusive aligned allocation is completely uninitialized.
        unsafe {
            Table::initialize_at(storage.as_mut_ptr(), |target| target >= 100);
        }
        // SAFETY: initialize_at established all fields before this read.
        let mut table = unsafe { storage.assume_init() };
        table.place(0, 100, Flags::default()).unwrap();
        table.hold(0).unwrap();
        assert_eq!(table.close(0), Ok(Some(100)));
        assert_eq!(table.unhold(100), None);
    }

    #[test]
    fn scalar_layout_uses_existing_fixed_hold_headers() {
        use core::mem::size_of;
        type Base = Table<u32, 32, [u64; 3]>;
        type Payload = Table<u32, 32, [u64; 3], [u8; 1012]>;
        assert_eq!(size_of::<ScalarToken>(), 16);
        assert_eq!(size_of::<ScalarRecord<u32, [u8; 1012]>>(), 1072);
        assert_eq!(size_of::<Base>(), 6672);
        assert_eq!(size_of::<Payload>(), 54288);
    }
}
