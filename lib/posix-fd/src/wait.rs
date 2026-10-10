// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Independent paid WAIT records; cleanup returns channel debts, never closes them.

use crate::{Error, OwnerToken};
pub const WAIT_RECORDS: usize = 16;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitToken {
    slot: u8,
    generation: u64,
}
impl WaitToken {
    pub fn slot(self) -> usize {
        self.slot as usize
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitClaim {
    token: WaitToken,
    serial: u64,
}
impl WaitClaim {
    pub fn token(self) -> WaitToken {
        self.token
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitResult {
    Value(u64),
    Failed(i32),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitCancelReason {
    Signal,
    Close,
    Abandoned,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitRecordPhase {
    Working,
    Complete,
    Cleaning,
    Cleaned,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitSnapshot<W> {
    pub owner: Option<OwnerToken>,
    pub claimant: Option<OwnerToken>,
    pub recovery: W,
    pub result: Option<WaitResult>,
    pub reason: Option<WaitCancelReason>,
    pub phase: WaitRecordPhase,
    /// Full kernel handle, including its nonreused generation. No Rust Drop owns it.
    pub channel: Option<u64>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitChannelDebt {
    token: WaitToken,
    raw: u64,
}
impl WaitChannelDebt {
    pub fn token(self) -> WaitToken {
        self.token
    }
    pub fn raw(self) -> u64 {
        self.raw
    }
}
#[derive(Clone, Copy)]
struct Record<W> {
    owner: Option<OwnerToken>,
    claimant: Option<OwnerToken>,
    serial: u64,
    recovery: W,
    result: Option<WaitResult>,
    reason: Option<WaitCancelReason>,
    phase: WaitRecordPhase,
    channel: Option<u64>,
}
impl<W: Copy> Record<W> {
    fn snapshot(self) -> WaitSnapshot<W> {
        WaitSnapshot {
            owner: self.owner,
            claimant: self.claimant,
            recovery: self.recovery,
            result: self.result,
            reason: self.reason,
            phase: self.phase,
            channel: self.channel,
        }
    }
}
struct Slot<W> {
    generation: u64,
    record: Option<Record<W>>,
}
pub struct WaitRecords<W> {
    slots: [Slot<W>; WAIT_RECORDS],
}
impl<W: Copy> WaitRecords<W> {
    pub const fn new() -> Self {
        Self {
            slots: [const {
                Slot {
                    generation: 0,
                    record: None,
                }
            }; WAIT_RECORDS],
        }
    }
    /// # Safety
    /// Exclusive aligned writable uninitialized allocation for Self.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: initialized one cell at a time, never constructs an array on stack.
        unsafe {
            let slots = core::ptr::addr_of_mut!((*destination).slots).cast::<Slot<W>>();
            for i in 0..WAIT_RECORDS {
                slots.add(i).write(Slot {
                    generation: 0,
                    record: None,
                });
            }
        }
    }
    fn record(&self, token: WaitToken) -> Result<Record<W>, Error> {
        self.slots
            .get(token.slot())
            .filter(|s| s.generation == token.generation)
            .and_then(|s| s.record)
            .ok_or(Error::BadFileDescriptor)
    }
    fn save(&mut self, token: WaitToken, record: Record<W>) {
        self.slots[token.slot()].record = Some(record);
    }
    pub fn tokens(&self) -> impl Iterator<Item = WaitToken> + '_ {
        self.slots.iter().enumerate().filter_map(|(i, s)| {
            s.record.map(|_| WaitToken {
                slot: i as u8,
                generation: s.generation,
            })
        })
    }
    pub fn snapshot(&self, token: WaitToken) -> Result<WaitSnapshot<W>, Error> {
        Ok(self.record(token)?.snapshot())
    }
    pub fn begin(
        &mut self,
        owner: OwnerToken,
        recovery: W,
    ) -> Result<(WaitToken, WaitClaim), Error> {
        let (i, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.record.is_none() && s.generation < u64::MAX)
            .ok_or(Error::TooManyOpenFiles)?;
        slot.generation += 1;
        let token = WaitToken {
            slot: i as u8,
            generation: slot.generation,
        };
        let claim = WaitClaim { token, serial: 1 };
        slot.record = Some(Record {
            owner: Some(owner),
            claimant: Some(owner),
            serial: 1,
            recovery,
            result: None,
            reason: None,
            phase: WaitRecordPhase::Working,
            channel: None,
        });
        Ok((token, claim))
    }
    fn claimed(&self, claim: WaitClaim) -> Result<Record<W>, Error> {
        let r = self.record(claim.token)?;
        if r.serial != claim.serial
            || r.owner.is_none()
            || r.claimant != r.owner
            || r.result.is_some()
            || r.phase != WaitRecordPhase::Working
        {
            return Err(Error::BadFileDescriptor);
        }
        Ok(r)
    }
    pub fn is_working(&self, claim: WaitClaim) -> bool {
        self.claimed(claim).is_ok()
    }
    /// Move ownership of a genuine RECEIVE channel only after this succeeds.
    pub fn attach_channel(&mut self, claim: WaitClaim, raw: u64) -> Result<(), Error> {
        let mut r = self.claimed(claim)?;
        if raw >> 16 == 0 || r.channel.is_some() {
            return Err(Error::InvalidArgument);
        }
        r.channel = Some(raw);
        self.save(claim.token, r);
        Ok(())
    }
    pub fn complete<F>(
        &mut self,
        claim: WaitClaim,
        result: WaitResult,
        publish: F,
    ) -> Result<WaitSnapshot<W>, Error>
    where
        F: FnOnce(W) -> Result<W, Error>,
    {
        self.claimed(claim)?;
        self.publish(claim.token, result, publish)
    }
    /// Exact cleanup helpers save the first canonical payload and revoke old claims.
    pub fn publish<F>(
        &mut self,
        token: WaitToken,
        result: WaitResult,
        publish: F,
    ) -> Result<WaitSnapshot<W>, Error>
    where
        F: FnOnce(W) -> Result<W, Error>,
    {
        let mut r = self.record(token)?;
        if r.result.is_some() {
            return Ok(r.snapshot());
        }
        if r.phase == WaitRecordPhase::Cleaned {
            return Err(Error::InvalidArgument);
        }
        let recovery = publish(r.recovery)?;
        r.recovery = recovery;
        r.result = Some(result);
        r.claimant = None;
        if r.phase == WaitRecordPhase::Working {
            r.phase = WaitRecordPhase::Complete;
        }
        self.save(token, r);
        Ok(r.snapshot())
    }
    pub fn begin_cleanup(
        &mut self,
        token: WaitToken,
        reason: WaitCancelReason,
    ) -> Result<WaitSnapshot<W>, Error> {
        let mut r = self.record(token)?;
        if r.phase != WaitRecordPhase::Cleaned {
            r.phase = WaitRecordPhase::Cleaning;
            r.claimant = None;
            if r.reason.is_none() {
                r.reason = Some(reason);
            }
        }
        self.save(token, r);
        Ok(r.snapshot())
    }
    /// Confirm durable server Release, after the canonical receipt was saved.
    pub fn finish_cleanup(&mut self, token: WaitToken) -> Result<(), Error> {
        let mut r = self.record(token)?;
        if r.result.is_none()
            || !matches!(
                r.phase,
                WaitRecordPhase::Cleaning | WaitRecordPhase::Cleaned
            )
        {
            return Err(Error::InvalidArgument);
        }
        r.phase = WaitRecordPhase::Cleaned;
        r.claimant = None;
        self.save(token, r);
        Ok(())
    }
    /// Repeatable close debt. Caller closes the exact generation outside table lock.
    pub fn channel_debt(&self, token: WaitToken) -> Result<Option<WaitChannelDebt>, Error> {
        let r = self.record(token)?;
        if r.phase != WaitRecordPhase::Cleaned {
            return Err(Error::InvalidArgument);
        }
        Ok(r.channel.map(|raw| WaitChannelDebt { token, raw }))
    }
    /// A successful close or authoritative stale-handle reply confirms this debt.
    pub fn confirm_channel_closed(&mut self, debt: WaitChannelDebt) -> Result<(), Error> {
        let mut r = self.record(debt.token)?;
        if r.phase != WaitRecordPhase::Cleaned || r.channel.is_some_and(|raw| raw != debt.raw) {
            return Err(Error::InvalidArgument);
        }
        r.channel = None;
        self.save(debt.token, r);
        Ok(())
    }
    fn ack_ready(&self, token: WaitToken) -> Result<Record<W>, Error> {
        let r = self.record(token)?;
        if r.phase != WaitRecordPhase::Cleaned || r.channel.is_some() || r.result.is_none() {
            return Err(Error::InvalidArgument);
        }
        Ok(r)
    }
    pub fn ack(&mut self, token: WaitToken, owner: OwnerToken) -> Result<(WaitResult, W), Error> {
        let r = self.ack_ready(token)?;
        if r.owner != Some(owner) {
            return Err(Error::BadFileDescriptor);
        }
        self.slots[token.slot()].record = None;
        Ok((r.result.expect("ack result"), r.recovery))
    }
    pub fn ack_abandoned(&mut self, token: WaitToken) -> Result<(WaitResult, W), Error> {
        let r = self.ack_ready(token)?;
        if r.owner.is_some() {
            return Err(Error::BadFileDescriptor);
        }
        self.slots[token.slot()].record = None;
        Ok((r.result.expect("ack result"), r.recovery))
    }
    /// One bounded detach turn revokes an owner's next resident record.
    pub fn abandon_owner(&mut self, owner: OwnerToken) -> Option<WaitToken> {
        let token = self
            .tokens()
            .find(|&t| self.record(t).is_ok_and(|r| r.owner == Some(owner)))?;
        let mut r = self.record(token).expect("exact detach");
        r.owner = None;
        r.claimant = None;
        if r.phase != WaitRecordPhase::Cleaned {
            r.phase = WaitRecordPhase::Cleaning;
            if r.reason.is_none() {
                r.reason = Some(WaitCancelReason::Abandoned);
            }
        }
        self.save(token, r);
        Some(token)
    }
    /// Child never closes or cancels copied parent IDs; preserve generations.
    pub fn discard_after_fork(&mut self) {
        for slot in &mut self.slots {
            slot.record = None;
        }
    }
}
impl<W: Copy> Default for WaitRecords<W> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner() -> OwnerToken {
        OwnerToken::new(1).unwrap()
    }
    #[test]
    fn exhausted_generation_never_wraps_and_old_claim_cannot_attach() {
        let mut records = WaitRecords::<u64>::new();
        for slot in &mut records.slots {
            slot.generation = u64::MAX;
        }
        assert_eq!(records.begin(owner(), 7), Err(Error::TooManyOpenFiles));
        records.slots[0].generation = u64::MAX - 1;
        let (t, c) = records.begin(owner(), 7).unwrap();
        assert_eq!(t.generation(), u64::MAX);
        records
            .begin_cleanup(t, WaitCancelReason::Abandoned)
            .unwrap();
        assert!(records.attach_channel(c, 0x10007).is_err());
        records.publish(t, WaitResult::Value(0), Ok).unwrap();
        records.finish_cleanup(t).unwrap();
        records.ack(t, owner()).unwrap();
        assert_eq!(records.begin(owner(), 8), Err(Error::TooManyOpenFiles));
    }
    #[test]
    fn rejected_atomic_publication_preserves_claim_and_departed_ack_requires_cleanup() {
        let mut records = WaitRecords::new();
        let (t, c) = records.begin(owner(), 7u64).unwrap();
        assert_eq!(
            records.complete(c, WaitResult::Value(0), |_| Err(Error::InvalidArgument)),
            Err(Error::InvalidArgument)
        );
        assert!(records.is_working(c));
        assert_eq!(records.snapshot(t).unwrap().result, None);
        records.abandon_owner(owner()).unwrap();
        assert!(!records.is_working(c));
        assert!(records.ack_abandoned(t).is_err());
        records
            .publish(t, WaitResult::Failed(4), |_| Ok(9))
            .unwrap();
        records.finish_cleanup(t).unwrap();
        assert!(records.ack(t, owner()).is_err());
        assert_eq!(records.ack_abandoned(t), Ok((WaitResult::Failed(4), 9)));
    }
}
