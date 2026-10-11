// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Frozen close events retaining numeric descriptors until remote confirmation.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseToken {
    slot: usize,
    generation: u64,
}
impl CloseToken {
    pub fn slot(self) -> usize {
        48 + self.slot
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseSnapshot<T, C> {
    pub owner: Option<OwnerToken>,
    pub recovery: C,
    pub entry: EntryToken,
    pub backend: T,
    pub last_alias: bool,
    pub replacement: Option<(T, Flags)>,
    pub complete: bool,
    /// Exact physical cleanup remains paid until its canonical reply is confirmed.
    pub release: Option<T>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseAdmission<T, C> {
    Started {
        token: CloseToken,
        snapshot: CloseSnapshot<T, C>,
    },
    PendingOpen(OpenToken),
    PendingClose(CloseToken),
    Replaced(u32),
}
#[derive(Clone, Copy)]
pub(super) struct CloseRecord<T, C> {
    snapshot: CloseSnapshot<T, C>,
}

pub(super) struct CloseSlot<T, C> {
    pub(super) generation: u64,
    pub(super) changed: AtomicU32,
    pub(super) record: Option<CloseRecord<T, C>>,
}
impl<T, C> CloseSlot<T, C> {
    fn change(&self) {
        let value = self.changed.load(Ordering::Relaxed);
        self.changed
            .store(value.saturating_add(1), Ordering::Release);
    }
}

impl<T: Copy + Eq, const N: usize, R: Copy, S: Copy, C: Copy> Table<T, N, R, S, C> {
    fn close_record(&self, token: CloseToken) -> Result<CloseRecord<T, C>, Error> {
        let slot = self
            .closings
            .get(token.slot)
            .ok_or(Error::BadFileDescriptor)?;
        if slot.generation != token.generation {
            return Err(Error::BadFileDescriptor);
        }
        match slot.record {
            Some(record) => Ok(record),
            _ => Err(Error::BadFileDescriptor),
        }
    }
    fn save_close(&mut self, token: CloseToken, record: CloseRecord<T, C>) {
        let slot = &mut self.closings[token.slot];
        slot.record = Some(record);
        slot.change();
    }
    pub fn close_snapshot(&self, token: CloseToken) -> Result<CloseSnapshot<T, C>, Error> {
        Ok(self.close_record(token)?.snapshot)
    }
    /// Exact local recovery metadata only; the frozen receipt and wait sequence stay put.
    pub fn update_close_metadata<V>(
        &mut self,
        token: CloseToken,
        update: impl FnOnce(C) -> Result<(C, V), Error>,
    ) -> Result<V, Error> {
        let mut record = self.close_record(token)?;
        let (recovery, value) = update(record.snapshot.recovery)?;
        record.snapshot.recovery = recovery;
        // Metadata is not a new CloseEvent/physical outcome or waiter sequence.
        self.closings[token.slot].record = Some(record);
        Ok(value)
    }
    pub fn closing(&self, fd: u32) -> Option<CloseToken> {
        match self.entries.get(fd as usize)?.state {
            EntryState::Closing(token) => Some(token),
            _ => None,
        }
    }
    pub fn close_tokens(&self) -> impl Iterator<Item = CloseToken> + '_ {
        self.closings
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot.record.is_some().then_some(CloseToken {
                    slot: index,
                    generation: slot.generation,
                })
            })
    }
    /// Close admission remains available through a full ordinary or resident table.
    pub fn close_place(&self, owner: OwnerToken) -> JobPlace {
        let used = self.close_tokens().count();
        if used < N.min(JOBS_MAX) {
            return JobPlace::Free;
        }
        let own = self
            .closings
            .iter()
            .filter(
                |slot| matches!(slot.record, Some(record) if record.snapshot.owner == Some(owner)),
            )
            .count();
        JobPlace::Full {
            sequence: self.jobs.load(Ordering::Acquire),
            own: own >= used,
        }
    }
    pub fn close_wait_word(&self, token: CloseToken) -> Result<&AtomicU32, Error> {
        self.close_record(token)?;
        Ok(&self.closings[token.slot].changed)
    }
    pub fn close_wait_value(&self, token: CloseToken) -> Result<WaitValue, Error> {
        let word = self.close_wait_word(token)?;
        let value = word.load(Ordering::Acquire);
        Ok(if value == u32::MAX {
            WaitValue::NeverSleep
        } else {
            WaitValue::Sequence(value)
        })
    }
    pub(super) fn closing_references(&self, backend: T, physical: bool) -> bool {
        self.closings.iter().any(|slot| match slot.record {
            Some(record) if !record.snapshot.complete => {
                let snapshot = record.snapshot;
                (physical && snapshot.backend == backend)
                    || snapshot
                        .replacement
                        .is_some_and(|(next, _)| next == backend)
            }
            Some(record) => physical && record.snapshot.release == Some(backend),
            _ => false,
        })
    }
    fn close_blocked(&self, fd: u32) -> Option<CloseAdmission<T, C>> {
        if let Some(token) = self.pending(fd) {
            return Some(CloseAdmission::PendingOpen(token));
        }
        self.closing(fd).map(CloseAdmission::PendingClose)
    }
    pub fn begin_close(
        &mut self,
        owner: OwnerToken,
        fd: u32,
        recovery: C,
    ) -> Result<CloseAdmission<T, C>, Error> {
        if let Some(blocked) = self.close_blocked(fd) {
            return Ok(blocked);
        }
        self.start_close(Some(owner), fd, recovery, None)
    }
    /// Cleanup retains immutable work without requiring a new caller admission.
    pub fn begin_close_unowned(
        &mut self,
        fd: u32,
        recovery: C,
    ) -> Result<CloseAdmission<T, C>, Error> {
        if let Some(blocked) = self.close_blocked(fd) {
            return Ok(blocked);
        }
        self.start_close(None, fd, recovery, None)
    }
    /// Freeze a replacement before the close event can leave the table lock.
    pub fn begin_replace(
        &mut self,
        owner: OwnerToken,
        source: u32,
        target: u32,
        flags: Option<Flags>,
        recovery: C,
    ) -> Result<CloseAdmission<T, C>, Error> {
        self.begin_replace_with_owner(Some(owner), source, target, flags, recovery)
    }
    pub fn begin_replace_unowned(
        &mut self,
        source: u32,
        target: u32,
        flags: Option<Flags>,
        recovery: C,
    ) -> Result<CloseAdmission<T, C>, Error> {
        self.begin_replace_with_owner(None, source, target, flags, recovery)
    }
    fn begin_replace_with_owner(
        &mut self,
        owner: Option<OwnerToken>,
        source: u32,
        target: u32,
        flags: Option<Flags>,
        recovery: C,
    ) -> Result<CloseAdmission<T, C>, Error> {
        if let Some(blocked) = self.close_blocked(source) {
            return Ok(blocked);
        }
        let backend = self.get(source)?;
        if target as usize >= N {
            return Err(Error::BadFileDescriptor);
        }
        if source == target {
            return if flags.is_none() {
                Ok(CloseAdmission::Replaced(target))
            } else {
                Err(Error::InvalidArgument)
            };
        }
        if let Some(blocked) = self.close_blocked(target) {
            return Ok(blocked);
        }
        self.entries[target as usize]
            .generation
            .checked_add(1)
            .ok_or(Error::Io)?;
        let next = Some((backend, flags.unwrap_or_default()));
        match self.entries[target as usize].state {
            EntryState::Empty => {
                self.install(target, backend, flags.unwrap_or_default())?;
                Ok(CloseAdmission::Replaced(target))
            }
            EntryState::Open(_) => self.start_close(owner, target, recovery, next),
            _ => Err(Error::Io),
        }
    }
    fn start_close(
        &mut self,
        owner: Option<OwnerToken>,
        fd: u32,
        recovery: C,
        replacement: Option<(T, Flags)>,
    ) -> Result<CloseAdmission<T, C>, Error> {
        let entry = self.entry_token(fd)?;
        let backend = self.get(fd)?;
        let (index, slot) = self
            .closings
            .iter_mut()
            .take(N.min(JOBS_MAX))
            .enumerate()
            .find(|(_, slot)| {
                slot.record.is_none()
                    && slot.generation < u64::MAX
                    && slot.changed.load(Ordering::Relaxed) < u32::MAX
            })
            .ok_or(Error::TooManyOpenFiles)?;
        slot.generation += 1;
        let token = CloseToken {
            slot: index,
            generation: slot.generation,
        };
        self.entries[fd as usize].state = EntryState::Closing(token);
        let last_alias =
            !self.entries.iter().any(
                |slot| matches!(slot.state, EntryState::Open(open) if open.backend == backend),
            ) && !self.closing_references(backend, false)
                && !replacement.is_some_and(|(next, _)| next == backend);
        let snapshot = CloseSnapshot {
            owner,
            recovery,
            entry,
            backend,
            last_alias,
            replacement,
            complete: false,
            release: None,
        };
        self.save_close(token, CloseRecord { snapshot });
        Ok(CloseAdmission::Started { token, snapshot })
    }
    /// Confirm the exact remote event and publish the local change once.
    pub fn finish_close(&mut self, token: CloseToken) -> Result<Option<T>, Error> {
        let mut record = self.close_record(token)?;
        if record.snapshot.complete {
            return Ok(None);
        }
        let snapshot = record.snapshot;
        let entry = &self.entries[snapshot.entry.fd as usize];
        if entry.generation != snapshot.entry.generation()
            || !matches!(entry.state, EntryState::Closing(current) if current == token)
        {
            return Err(Error::Io);
        }
        match snapshot.replacement {
            Some((next, flags)) => self.install(snapshot.entry.fd, next, flags)?,
            None => self.entries[snapshot.entry.fd as usize].state = EntryState::Empty,
        }
        record.snapshot.complete = true;
        self.save_close(token, record);
        let release = self.left(snapshot.backend);
        record.snapshot.release = release;
        self.save_close(token, record);
        Ok(release)
    }
    /// Confirm the exact physical cleanup receipt without altering a reused fd.
    pub fn finish_close_release(&mut self, token: CloseToken, backend: T) -> Result<(), Error> {
        let mut record = self.close_record(token)?;
        if !record.snapshot.complete || record.snapshot.backend != backend {
            return Err(Error::BadFileDescriptor);
        }
        record.snapshot.release = None;
        self.save_close(token, record);
        Ok(())
    }
    /// The owner or its collector acknowledges the retained completion.
    pub fn ack_close(&mut self, token: CloseToken, owner: Option<OwnerToken>) -> Result<(), Error> {
        let record = self.close_record(token)?;
        if !record.snapshot.complete
            || record.snapshot.release.is_some()
            || record.snapshot.owner != owner
        {
            return Err(Error::BadFileDescriptor);
        }
        let slot = &mut self.closings[token.slot];
        slot.record = None;
        slot.change();
        self.job_gone();
        Ok(())
    }
    /// A lost owner leaves immutable work available to another helper.
    pub fn abandon_close_owner(
        &mut self,
        owner: OwnerToken,
    ) -> Option<(CloseToken, CloseSnapshot<T, C>)> {
        let (index, slot) = self.closings.iter_mut().enumerate().find(
            |(_, slot)| matches!(slot.record, Some(record) if record.snapshot.owner == Some(owner)),
        )?;
        let Some(mut record) = slot.record else {
            unreachable!()
        };
        record.snapshot.owner = None;
        let token = CloseToken {
            slot: index,
            generation: slot.generation,
        };
        self.save_close(token, record);
        Some((token, record.snapshot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestTable = Table<u32, 32, u64, (), u64>;
    fn owner(value: u64) -> OwnerToken {
        OwnerToken::new(value).unwrap()
    }
    fn start(table: &mut TestTable, fd: u32) -> (CloseToken, CloseSnapshot<u32, u64>) {
        match table.begin_close(owner(1), fd, 42).unwrap() {
            CloseAdmission::Started { token, snapshot } => (token, snapshot),
            _ => panic!("close did not start"),
        }
    }
    #[test]
    fn unregistered_cleanup_has_its_own_receipt_through_full_io_and_control_tables() {
        let mut table = TestTable::default();
        for fd in 0..32 {
            table.place(fd, 100 + fd, Flags::default()).unwrap();
            table.hold(fd).unwrap();
        }
        for _ in 0..JOBS_MAX {
            table.begin_control(owner(1), 7).unwrap();
        }
        let CloseAdmission::Started { token, snapshot } = table.begin_close_unowned(0, 42).unwrap()
        else {
            panic!()
        };
        assert_eq!(snapshot.owner, None);
        assert_eq!(snapshot.recovery, 42);
        assert!(snapshot.last_alias);
        assert_eq!(table.finish_close(token), Ok(None));
        assert_eq!(table.unhold(100), Some(100));
        assert!(table.ack_close(token, Some(owner(1))).is_err());
        table.ack_close(token, None).unwrap();
        assert_eq!(table.jobs_in_use(), JOBS_MAX);
        assert_eq!(table.get(1), Ok(101));
    }

    #[test]
    fn unregistered_replacement_keeps_source_and_physical_target_until_confirmation() {
        let mut table = TestTable::default();
        let source = table.insert(100, Flags::default()).unwrap();
        let target = table.insert(200, Flags::default()).unwrap();
        let flags = Flags {
            close_on_exec: true,
            close_on_fork: false,
        };
        let CloseAdmission::Started { token, snapshot } = table
            .begin_replace_unowned(source, target, Some(flags), 42)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(snapshot.owner, None);
        assert_eq!(snapshot.replacement, Some((100, flags)));
        assert_eq!(table.close(source), Ok(None));
        assert_eq!(table.finish_close(token), Ok(Some(200)));
        assert_eq!(table.get(target), Ok(100));
        assert_eq!(table.flags(target), Ok(flags));
        assert!(table.ack_close(token, None).is_err());
        table.finish_close_release(token, 200).unwrap();
        table.ack_close(token, None).unwrap();
        assert_eq!(table.close(target), Ok(Some(100)));
    }

    #[test]
    fn lost_owner_after_numeric_completion_preserves_exact_physical_cleanup_debt() {
        let mut table = TestTable::default();
        let fd = table.insert(100, Flags::default()).unwrap();
        let (token, _) = start(&mut table, fd);
        assert!(table.finish_close_release(token, 100).is_err());
        assert_eq!(table.finish_close(token), Ok(Some(100)));
        assert_eq!(table.insert(200, Flags::default()), Ok(fd));
        let (debt, snapshot) = table.abandon_close_owner(owner(1)).unwrap();
        assert_eq!(debt, token);
        assert!(snapshot.complete);
        assert_eq!(snapshot.release, Some(100));
        assert!(table.referenced(100));
        assert!(table.ack_close(token, None).is_err());
        assert!(table.finish_close_release(token, 200).is_err());
        assert_eq!(table.close_snapshot(token).unwrap().release, Some(100));
        assert_eq!(table.finish_close(token), Ok(None));
        table.finish_close_release(token, 100).unwrap();
        table.finish_close_release(token, 100).unwrap();
        assert!(!table.referenced(100));
        table.ack_close(token, None).unwrap();
        assert_eq!(table.get(fd), Ok(200));
        let (next, _) = start(&mut table, fd);
        assert_eq!(next.slot(), token.slot());
        assert!(table.finish_close_release(token, 100).is_err());
        assert_eq!(table.closing(fd), Some(next));
    }

    #[test]
    fn full_close_table_cannot_return_any_place_before_physical_receipts() {
        let mut table = TestTable::default();
        let mut tokens = [None; JOBS_MAX];
        for (fd, token) in tokens.iter_mut().enumerate() {
            table
                .place(fd as u32, 100 + fd as u32, Flags::default())
                .unwrap();
            let (next, _) = start(&mut table, fd as u32);
            assert_eq!(table.finish_close(next), Ok(Some(100 + fd as u32)));
            *token = Some(next);
        }
        assert!(matches!(
            table.close_place(owner(1)),
            JobPlace::Full { own: true, .. }
        ));
        for token in tokens.into_iter().flatten() {
            assert!(table.ack_close(token, Some(owner(1))).is_err());
        }
        let first = tokens[0].unwrap();
        table.finish_close_release(first, 100).unwrap();
        table.ack_close(first, Some(owner(1))).unwrap();
        assert_eq!(table.close_place(owner(2)), JobPlace::Free);
        for token in tokens[1..].iter().copied().flatten() {
            assert!(table.close_snapshot(token).unwrap().release.is_some());
        }
    }

    #[test]
    fn closing_number_stays_reserved_until_confirmation_and_retains_exact_completion() {
        let mut table = TestTable::default();
        let fd = table.insert(100, Flags::default()).unwrap();
        let entry = table.entry_token(fd).unwrap();
        let (token, snapshot) = start(&mut table, fd);
        assert_eq!(snapshot.entry, entry);
        assert_eq!(snapshot.recovery, 42);
        assert!(snapshot.last_alias);
        assert_eq!(table.get(fd), Err(Error::BadFileDescriptor));
        assert_eq!(table.vacant(0), Ok(1));
        assert_eq!(
            table.place(fd, 101, Flags::default()),
            Err(Error::BadFileDescriptor)
        );
        assert_eq!(
            table.begin_close(owner(2), fd, 99),
            Ok(CloseAdmission::PendingClose(token))
        );
        assert_eq!(table.place(1, 777, Flags::default()), Ok(()));
        assert_eq!(table.try_dup2(1, fd), Err(Error::Io));
        assert_eq!(table.closing(fd), Some(token));
        let address = core::ptr::from_ref(table.close_wait_word(token).unwrap());
        let sequence = table
            .close_wait_word(token)
            .unwrap()
            .load(Ordering::Acquire);
        assert!(table.ack_close(token, Some(owner(1))).is_err());
        assert_eq!(table.finish_close(token), Ok(Some(100)));
        assert!(
            table
                .close_wait_word(token)
                .unwrap()
                .load(Ordering::Acquire)
                > sequence
        );
        assert_eq!(
            core::ptr::from_ref(table.close_wait_word(token).unwrap()),
            address
        );
        assert_eq!(table.insert(101, Flags::default()), Ok(fd));
        assert_ne!(table.entry_token(fd).unwrap(), entry);
        assert_eq!(table.finish_close(token), Ok(None));
        assert_eq!(table.get(fd), Ok(101));
        assert!(table.close_snapshot(token).unwrap().complete);
        assert!(table.ack_close(token, Some(owner(2))).is_err());
        table.finish_close_release(token, 100).unwrap();
        table.ack_close(token, Some(owner(1))).unwrap();
        let (next, _) = start(&mut table, fd);
        assert_eq!(next.slot(), token.slot());
        assert!(next.generation() > token.generation());
        assert!(table.close_snapshot(token).is_err());
        assert!(table.finish_close(token).is_err());
        assert!(table.ack_close(token, Some(owner(1))).is_err());
        assert_eq!(table.closing(fd), Some(next));
    }
    #[test]
    fn concurrent_alias_closes_separate_last_real_alias_from_physical_custody() {
        let mut table = TestTable::default();
        let first = table.insert(100, Flags::default()).unwrap();
        let second = table.duplicate(first, 0, Flags::default()).unwrap();
        table.hold(first).unwrap();
        let (a, sa) = start(&mut table, first);
        assert!(!sa.last_alias);
        let (b, sb) = start(&mut table, second);
        assert!(sb.last_alias);
        assert!(table.referenced(100));
        assert_eq!(table.finish_close(b), Ok(None));
        assert_eq!(table.unhold(100), None);
        assert_eq!(table.finish_close(a), Ok(Some(100)));
        assert_eq!(table.finish_close(b), Ok(None));
        assert!(table.referenced(100));
        assert_eq!(table.close_snapshot(a).unwrap().release, Some(100));
        table.finish_close_release(a, 100).unwrap();
        assert!(!table.referenced(100));
    }
    #[test]
    fn replacement_retains_source_backend_when_the_source_closes_first() {
        let mut table = TestTable::default();
        let source = table.insert(100, Flags::default()).unwrap();
        let target = table.insert(200, Flags::default()).unwrap();
        let old = table.entry_token(target).unwrap();
        let flags = Flags {
            close_on_exec: true,
            close_on_fork: true,
        };
        let CloseAdmission::Started { token, snapshot } = table
            .begin_replace(owner(1), source, target, Some(flags), 7)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(snapshot.entry, old);
        assert_eq!(snapshot.backend, 200);
        assert_eq!(snapshot.replacement, Some((100, flags)));
        assert!(snapshot.last_alias);
        assert!(table.referenced(100));
        let (source_close, source_snapshot) = start(&mut table, source);
        assert!(!source_snapshot.last_alias);
        assert_eq!(table.finish_close(source_close), Ok(None));
        assert_eq!(table.finish_close(token), Ok(Some(200)));
        assert_eq!(table.get(target), Ok(100));
        assert_eq!(table.flags(target), Ok(flags));
        assert_ne!(table.entry_token(target).unwrap(), old);
        assert_eq!(table.close_exact(old), None);
        assert_eq!(table.finish_close(token), Ok(None));
        assert_eq!(table.close(target), Ok(Some(100)));
    }
    #[test]
    fn same_backend_replacement_still_has_a_close_event_and_fresh_target_lifetime() {
        let mut table = TestTable::default();
        let source = table
            .insert(
                100,
                Flags {
                    close_on_exec: true,
                    close_on_fork: true,
                },
            )
            .unwrap();
        let target = table.duplicate(source, 0, Flags::default()).unwrap();
        let old = table.entry_token(target).unwrap();
        let CloseAdmission::Started { token, snapshot } = table
            .begin_replace(owner(1), source, target, None, 42)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(snapshot.backend, 100);
        assert!(!snapshot.last_alias);
        assert_eq!(table.finish_close(token), Ok(None));
        assert_eq!(table.flags(target), Ok(Flags::default()));
        assert_ne!(table.entry_token(target).unwrap(), old);
        assert_eq!(
            table.begin_replace(owner(1), source, source, None, 42),
            Ok(CloseAdmission::Replaced(source))
        );
        assert_eq!(
            table.begin_replace(owner(1), source, source, Some(Flags::default()), 42),
            Err(Error::InvalidArgument)
        );
    }
    #[test]
    fn close_places_stay_independent_of_all_io_and_resident_places_and_fail_before_effects() {
        let mut table = TestTable::default();
        for fd in 0..32 {
            table.place(fd, 100 + fd, Flags::default()).unwrap();
            table.hold(fd).unwrap();
        }
        for _ in 0..JOBS_MAX {
            table.begin_control(owner(1), 7).unwrap();
        }
        assert_eq!(table.jobs_in_use(), JOBS_MAX);
        assert_eq!(table.close_place(owner(1)), JobPlace::Free);
        let mut tokens = [None; JOBS_MAX];
        for (fd, slot) in tokens.iter_mut().enumerate() {
            let (token, _) = start(&mut table, fd as u32);
            assert_eq!(table.finish_close(token), Ok(None));
            *slot = Some(token);
        }
        assert!(matches!(
            table.close_place(owner(1)),
            JobPlace::Full { own: true, .. }
        ));
        assert!(matches!(
            table.close_place(owner(2)),
            JobPlace::Full { own: false, .. }
        ));
        let entry = table.entry_token(16).unwrap();
        assert_eq!(
            table.begin_close(owner(2), 16, 9),
            Err(Error::TooManyOpenFiles)
        );
        assert_eq!(table.entry_token(16), Ok(entry));
        let old = tokens[0].unwrap();
        table.ack_close(old, Some(owner(1))).unwrap();
        assert_eq!(table.close_place(owner(2)), JobPlace::Free);
        let (new, _) = start(&mut table, 16);
        assert!(new.generation() > old.generation());
        assert_eq!(table.jobs_in_use(), JOBS_MAX);
        assert_eq!(table.unhold(100), Some(100));
    }
    #[test]
    fn failed_replacement_and_terminal_counters_preserve_original_descriptor() {
        let mut table = TestTable::default();
        table.place(0, 100, Flags::default()).unwrap();
        table.place(1, 200, Flags::default()).unwrap();
        table.entries[1].generation = u64::MAX;
        assert_eq!(
            table.begin_replace(owner(1), 0, 1, None, 42),
            Err(Error::Io)
        );
        assert_eq!(table.get(1), Ok(200));
        assert_eq!(table.close_tokens().count(), 0);
        table.entries[1].generation = 1;
        for slot in &mut table.closings {
            slot.generation = u64::MAX;
        }
        assert_eq!(
            table.begin_close(owner(1), 1, 42),
            Err(Error::TooManyOpenFiles)
        );
        assert_eq!(table.get(1), Ok(200));
        table.closings[0].generation = 0;
        table.closings[0].changed.store(u32::MAX, Ordering::Release);
        assert_eq!(
            table.begin_close(owner(1), 1, 42),
            Err(Error::TooManyOpenFiles)
        );
        assert_eq!(table.get(1), Ok(200));
        assert_eq!(
            table.begin_close(owner(1), 99, 42),
            Err(Error::BadFileDescriptor)
        );
    }
    #[test]
    fn owner_death_keeps_close_work_and_the_collector_acknowledges_it() {
        let mut table = TestTable::default();
        let fd = table.insert(100, Flags::default()).unwrap();
        let (token, frozen) = start(&mut table, fd);
        let (debt, snapshot) = table.abandon_close_owner(owner(1)).unwrap();
        assert_eq!(debt, token);
        assert_eq!(snapshot.owner, None);
        assert_eq!(snapshot.entry, frozen.entry);
        assert_eq!(snapshot.recovery, frozen.recovery);
        assert_eq!(table.closing(fd), Some(token));
        assert!(table.ack_close(token, None).is_err());
        assert_eq!(table.finish_close(token), Ok(Some(100)));
        assert!(table.ack_close(token, Some(owner(1))).is_err());
        table.finish_close_release(token, 100).unwrap();
        table.ack_close(token, None).unwrap();
        assert_eq!(table.close_tokens().count(), 0);
        assert_eq!(table.abandon_close_owner(owner(1)), None);
    }
    #[test]
    fn fork_local_cleanup_discards_parent_close_work_and_keeps_other_published_fds() {
        let mut table = TestTable::default();
        table.place(0, 100, Flags::default()).unwrap();
        table.place(1, 200, Flags::default()).unwrap();
        let (token, _) = start(&mut table, 0);
        table.discard_open_after_fork();
        assert_eq!(table.get(1), Ok(200));
        assert_eq!(table.get(0), Err(Error::BadFileDescriptor));
        assert_eq!(table.closing(0), None);
        assert!(table.close_snapshot(token).is_err());
        assert_eq!(table.close_tokens().count(), 0);
        assert_eq!(table.vacant(0), Ok(0));
    }
    #[test]
    fn pending_open_and_close_targets_are_helped_before_replacement() {
        let mut table = TestTable::default();
        table.place(0, 100, Flags::default()).unwrap();
        let (open, claim) = table.begin_open(owner(1), 7).unwrap();
        let entry = table.reserve_open(claim, 1, Flags::default()).unwrap();
        assert_eq!(
            table.begin_close(owner(2), entry.fd, 42),
            Ok(CloseAdmission::PendingOpen(open))
        );
        assert_eq!(
            table.begin_replace(owner(2), 0, entry.fd, None, 42),
            Ok(CloseAdmission::PendingOpen(open))
        );
        assert_eq!(
            table.begin_replace(owner(2), entry.fd, 0, None, 42),
            Ok(CloseAdmission::PendingOpen(open))
        );
        let (close, _) = start(&mut table, 0);
        assert_eq!(
            table.begin_replace(owner(2), 0, 2, None, 42),
            Ok(CloseAdmission::PendingClose(close))
        );
        assert_eq!(table.close_tokens().count(), 1);
        assert_eq!(table.close_wait_value(close), Ok(WaitValue::Sequence(1)));
        table.closings[close.slot]
            .changed
            .store(u32::MAX, Ordering::Release);
        assert_eq!(table.close_wait_value(close), Ok(WaitValue::NeverSleep));
        assert_eq!(table.finish_close(close), Ok(Some(100)));
        assert_eq!(table.close_wait_value(close), Ok(WaitValue::NeverSleep));
        table.finish_close_release(close, 100).unwrap();
        table.ack_close(close, Some(owner(1))).unwrap();
    }
    #[test]
    fn exact_metadata_update_rejects_retired_generation_without_calling_callback() {
        let mut table = TestTable::default();
        let fd = table.insert(100, Flags::default()).unwrap();
        let (old, _) = start(&mut table, fd);
        let sequence = table.close_wait_value(old).unwrap();
        assert_eq!(table.update_close_metadata(old, |r| Ok((r + 1, 7))), Ok(7));
        assert_eq!(table.close_snapshot(old).unwrap().recovery, 43);
        assert_eq!(table.close_wait_value(old).unwrap(), sequence);
        assert_eq!(
            table.update_close_metadata(old, |_| Err::<(u64, ()), _>(Error::InvalidArgument)),
            Err(Error::InvalidArgument)
        );
        assert_eq!(table.close_snapshot(old).unwrap().recovery, 43);
        table.finish_close(old).unwrap();
        table.finish_close_release(old, 100).unwrap();
        table.ack_close(old, Some(owner(1))).unwrap();
        let fd = table.insert(101, Flags::default()).unwrap();
        let (current, snapshot) = start(&mut table, fd);
        assert_eq!(old.slot(), current.slot());
        assert_ne!(old.generation(), current.generation());
        let mut called = false;
        assert_eq!(
            table.update_close_metadata(old, |r| {
                called = true;
                Ok((r, ()))
            }),
            Err(Error::BadFileDescriptor)
        );
        assert!(!called);
        assert_eq!(table.close_snapshot(current).unwrap(), snapshot);
    }
}
