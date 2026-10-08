// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Paid initial-image custody in the existing record Work union.
//! Native admission supplies authenticated metadata and real object proofs.

use proto_init::InitialSource;
use proto_process::initial_map::{ENTRIES, Entry, Key, Receipt, Reply};
use proto_process::initial_publication::Publication;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedKey {
    pub epoch: u64,
    pub ticket: u64,
    pub label: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    Reserved,
    GuardWait,
    Loading,
    StageWait,
    MapsReady,
    BootstrapReady,
    CRTWait,
    MapsAcked,
    SealWait,
    UserReleased,
    Canceling,
    Cleanup,
    Terminal,
}

pub enum CleanupOwner<M, C, T> {
    Memory(M),
    Channel(C),
    Thread(T),
}

pub struct InitialResident<M, C, T, D> {
    pub publication: Publication,
    pub originals: [Option<M>; ENTRIES],
    pub reply_copies: [Option<M>; ENTRIES],
    pub cleanup: [Option<CleanupOwner<M, C, T>>; ENTRIES],
    pub retained_thread: Option<T>,
    pub retained_identity: Option<C>,
    pub key: SeedKey,
    phase: Phase,
    cursor: u8,
    flags: u16,
    end_reason: u32,
    guard_label: u64,
    pub crt_pending: Option<D>,
    pub operation_pending: Option<D>,
}
const MAPS: u16 = 1;
const MAPS_ACK: u16 = 2;
const STAGE: u16 = 4;
const BOOTSTRAP: u16 = 8;
const USER: u16 = 16;
const INIT_ACK: u16 = 32;
const CRT_REPLIED: u16 = 64;
const ENDED: u16 = 128;
const PAGE_NARROW: u16 = 256;
const PAGE_MAPPED: u16 = 512;
const PAGE_SETTLED: u16 = 1024;
const MAP_VALIDATING: u16 = 2048;
const STOP_SENT: u16 = 4096;
const IDENTITY_CHECKED: u16 = 8192;
const IDENTITY_REFUSED: u16 = 16384;
const NATIVE_END: u16 = 32768;

impl<M, C, T, D> InitialResident<M, C, T, D> {
    pub fn reserved(key: SeedKey, receipt: Receipt, source: InitialSource) -> Option<Self> {
        if key.ticket == 0
            || key.label == 0
            || key.ticket != receipt.init_ticket
            || key.ticket != receipt.key.key
            || key.label != receipt.label
            || receipt.key.image != proto_process::IMAGE
        {
            return None;
        }
        Some(Self {
            publication: Publication {
                map: Reply {
                    receipt,
                    count: 0,
                    entries: [Entry::EMPTY; ENTRIES],
                },
                source,
            },
            originals: core::array::from_fn(|_| None),
            reply_copies: core::array::from_fn(|_| None),
            cleanup: core::array::from_fn(|_| None),
            retained_thread: None,
            retained_identity: None,
            key,
            phase: Phase::Reserved,
            cursor: 0,
            flags: 0,
            end_reason: 0,
            guard_label: 0,
            crt_pending: None,
            operation_pending: None,
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn flags(&self) -> u32 {
        u32::from(self.flags & 63)
    }
    pub fn end_reason(&self) -> Option<u32> {
        (self.flags & ENDED != 0).then_some(self.end_reason)
    }
    pub fn guard_label(&self) -> u64 {
        self.guard_label
    }
    pub fn awaiting_guard(&mut self) -> bool {
        if self.phase != Phase::Reserved {
            return false;
        }
        self.phase = Phase::GuardWait;
        true
    }
    /// Proposed epoch is CPU metadata in an unused map entry before maps exist.
    pub fn queue_stage(&mut self, epoch: u64, uid: u32, gid: u32, mode: u32) -> bool {
        if epoch == 0
            || mode > 1
            || self.key.epoch != 0
            || self.phase != Phase::GuardWait
            || self.flags != 0
            || self.publication.map.count != 0
            || self
                .publication
                .map
                .entries
                .iter()
                .any(|entry| *entry != Entry::EMPTY)
            || self.originals.iter().any(Option::is_some)
            || self.reply_copies.iter().any(Option::is_some)
        {
            return false;
        }
        self.publication.map.entries[0].address = epoch;
        self.end_reason = uid;
        self.guard_label = u64::from(gid) | (u64::from(mode) << 32);
        self.phase = Phase::StageWait;
        true
    }
    pub fn pending_stage(&self) -> Option<(u64, u32, u32, u32)> {
        (self.phase == Phase::StageWait && self.key.epoch == 0 && self.flags == 0).then_some((
            self.publication.map.entries[0].address,
            self.end_reason,
            self.guard_label as u32,
            (self.guard_label >> 32) as u32,
        ))
    }
    fn clear_pending_epoch(&mut self) {
        if self.flags & MAPS == 0 {
            self.publication.map.entries[0] = Entry::EMPTY;
        }
    }

    /// The native caller has verified the actual registered RAM private source.
    pub fn authenticated_stage(&mut self, key: SeedKey, source_label: u64) -> bool {
        if self.flags & ENDED != 0
            || source_label == 0
            || key.epoch == 0
            || key.ticket != self.key.ticket
            || key.label != self.key.label
        {
            return false;
        }
        if self.flags & STAGE != 0 {
            return key == self.key && self.guard_label == source_label;
        }
        if self.key.epoch == 0 {
            if self.pending_stage().map(|value| value.0) != Some(key.epoch) {
                return false;
            }
            self.clear_pending_epoch();
            self.end_reason = 0;
            self.key.epoch = key.epoch;
        } else if key != self.key || self.phase != Phase::GuardWait {
            return false;
        }
        self.guard_label = source_label;
        self.flags |= STAGE;
        self.phase = Phase::Loading;
        true
    }
    pub fn maps_ready(&self) -> bool {
        self.page_ready() && self.flags & (MAPS | ENDED) == MAPS
    }
    pub fn user_ready(&self) -> bool {
        self.maps_ready() && self.flags & USER != 0
    }
    pub fn page_ready(&self) -> bool {
        self.flags & (STAGE | PAGE_SETTLED | ENDED) == STAGE | PAGE_SETTLED
    }
    pub fn page_mapped(&self) -> bool {
        self.flags & PAGE_MAPPED != 0
    }
    pub fn page_copy(&self) -> Option<&M> {
        match self.cleanup[2].as_ref() {
            Some(CleanupOwner::Memory(value)) => Some(value),
            _ => None,
        }
    }
    pub fn page_needs_copy(&self) -> bool {
        self.phase == Phase::Loading && self.flags & (STAGE | PAGE_NARROW | ENDED) == STAGE
    }
    pub fn retain_page_copy(&mut self, owner: M) -> Result<(), M> {
        if !self.page_needs_copy() || self.cleanup[2].is_some() {
            return Err(owner);
        }
        self.cleanup[2] = Some(CleanupOwner::Memory(owner));
        self.flags |= PAGE_NARROW;
        Ok(())
    }
    pub fn confirm_page_map(&mut self) -> bool {
        if self.flags & (PAGE_NARROW | PAGE_MAPPED | ENDED) != PAGE_NARROW
            || self.page_copy().is_none()
        {
            return false;
        }
        self.flags |= PAGE_MAPPED;
        true
    }
    /// Move the owner only after the native Close has succeeded.
    pub fn remove_page_copy(&mut self) -> Option<M> {
        if self.flags & PAGE_MAPPED == 0 {
            return None;
        }
        match self.cleanup[2].take() {
            Some(CleanupOwner::Memory(value)) => Some(value),
            other => {
                self.cleanup[2] = other;
                None
            }
        }
    }
    pub fn confirm_page_settled(&mut self) -> bool {
        if self.flags & (PAGE_MAPPED | ENDED) != PAGE_MAPPED || self.cleanup[2].is_some() {
            return false;
        }
        self.flags |= PAGE_SETTLED;
        true
    }
    /// Source::Exit is posted after kernel teardown released target mappings.
    pub fn native_exited(&mut self, key: SeedKey, reason: u32) -> bool {
        if key != self.key {
            return false;
        }
        if self.flags & ENDED == 0 && !self.ended(key, reason) {
            return false;
        }
        self.flags |= NATIVE_END;
        self.flags &= !(PAGE_MAPPED | PAGE_SETTLED);
        true
    }
    pub fn native_end_confirmed(&self) -> bool {
        self.flags & NATIVE_END != 0
    }

    /// Every failed or replayed admission returns the whole incoming tuple.
    pub fn publish(
        &mut self,
        publication: Publication,
        objects: [Option<M>; ENTRIES],
    ) -> Result<(), [Option<M>; ENTRIES]> {
        let count = usize::from(publication.map.count);
        if self.flags & ENDED != 0
            || self.flags & STAGE == 0
            || self.phase != Phase::Loading
            || !self.page_ready()
            || self.flags & MAPS != 0
            || publication.validate().is_err()
            || publication.map.receipt != self.publication.map.receipt
            || publication.source != self.publication.source
            || !objects
                .iter()
                .enumerate()
                .all(|(i, m)| m.is_some() == (i < count))
        {
            return Err(objects);
        }
        self.publication = publication;
        self.originals = objects;
        self.flags |= MAPS;
        self.phase = Phase::MapsReady;
        Ok(())
    }
    pub fn begin_publish(
        &mut self,
        publication: Publication,
        objects: [Option<M>; ENTRIES],
    ) -> Result<(), [Option<M>; ENTRIES]> {
        self.publish(publication, objects)?;
        self.flags = (self.flags & !MAPS) | MAP_VALIDATING;
        self.phase = Phase::Loading;
        self.cursor = 0;
        Ok(())
    }
    pub fn memory_validation(&self) -> Option<(usize, &M, Entry)> {
        if self.flags & (MAP_VALIDATING | ENDED) != MAP_VALIDATING {
            return None;
        }
        let slot = usize::from(self.cursor);
        Some((
            slot,
            self.originals.get(slot)?.as_ref()?,
            self.publication.map.entries[slot],
        ))
    }
    pub fn memory_validated(&mut self, slot: usize) -> bool {
        if self.flags & (MAP_VALIDATING | ENDED) != MAP_VALIDATING
            || slot != usize::from(self.cursor)
            || slot >= usize::from(self.publication.map.count)
        {
            return false;
        }
        self.cursor += 1;
        if usize::from(self.cursor) == usize::from(self.publication.map.count) {
            self.flags = (self.flags & !MAP_VALIDATING) | MAPS;
            self.phase = Phase::MapsReady;
            self.cursor = 0;
        }
        true
    }
    pub fn identity_checked(&self) -> bool {
        self.flags & IDENTITY_CHECKED != 0
    }
    pub fn identity_result(&mut self, genuine: bool) {
        assert!(!self.identity_checked());
        self.flags |= IDENTITY_CHECKED;
        if !genuine {
            self.flags |= IDENTITY_REFUSED;
        }
    }
    pub fn identity_genuine(&self) -> bool {
        self.flags & (IDENTITY_CHECKED | IDENTITY_REFUSED | ENDED) == IDENTITY_CHECKED
    }
    pub fn identity_finished(&mut self) {
        assert!(self.retained_identity.is_none() && self.crt_pending.is_none());
        self.flags &= !(IDENTITY_CHECKED | IDENTITY_REFUSED);
    }
    pub fn needs_stop(&self) -> bool {
        self.flags & (ENDED | STOP_SENT | NATIVE_END) == ENDED
    }
    pub fn stop_sent(&mut self) {
        assert!(self.needs_stop());
        self.flags |= STOP_SENT;
    }
    pub fn replay_matches(&self, publication: &Publication) -> bool {
        self.flags & MAPS != 0 && self.publication == *publication
    }
    pub fn bootstrap(&mut self, key: SeedKey) -> bool {
        if key != self.key || !self.page_ready() || self.flags & (MAPS | STAGE) != MAPS | STAGE {
            return false;
        }
        self.flags |= BOOTSTRAP;
        self.phase = Phase::CRTWait;
        true
    }
    pub fn map_reply(&self, key: Key) -> Option<Reply> {
        (self.flags & (MAPS | BOOTSTRAP) == MAPS | BOOTSTRAP
            && self.flags & (MAPS_ACK | ENDED) == 0
            && (key == Key::FIRST || key == self.publication.map.receipt.key))
            .then_some(self.publication.map)
    }
    pub fn map_ack(&mut self, key: Key) -> Option<Receipt> {
        if key != self.publication.map.receipt.key
            || self.flags & (MAPS | BOOTSTRAP) != MAPS | BOOTSTRAP
            || self.flags & ENDED != 0
        {
            return None;
        }
        self.flags |= MAPS_ACK;
        self.phase = Phase::SealWait;
        Some(self.publication.map.receipt)
    }
    /// Only the trusted Init native endpoint supplies a committed Seal key.
    pub fn user_release(&mut self, key: SeedKey) -> bool {
        if key != self.key
            || self.flags & ENDED != 0
            || self.flags & (MAPS | MAPS_ACK | STAGE | BOOTSTRAP)
                != MAPS | MAPS_ACK | STAGE | BOOTSTRAP
        {
            return false;
        }
        self.flags |= USER;
        self.phase = Phase::UserReleased;
        true
    }
    pub fn crt_reply_confirmed(&mut self) {
        self.flags |= CRT_REPLIED;
    }
    pub fn init_ack(&mut self, key: SeedKey, receipt: Receipt) -> bool {
        if key != self.key
            || receipt != self.publication.map.receipt
            || self.flags & (USER | ENDED) == 0
        {
            return false;
        }
        self.flags |= INIT_ACK;
        true
    }
    pub fn ended(&mut self, key: SeedKey, reason: u32) -> bool {
        if key != self.key {
            return false;
        }
        if self.flags & ENDED != 0 {
            return self.end_reason == reason;
        }
        self.clear_pending_epoch();
        self.flags |= ENDED;
        self.end_reason = reason;
        self.phase = Phase::Canceling;
        true
    }
    /// Moves one owner for a later native close. A failed close restores this slot.
    pub fn cleanup_original(&mut self) -> Option<(usize, M)> {
        if self.flags & (MAPS_ACK | ENDED) == 0 {
            return None;
        }
        for _ in 0..ENTRIES {
            let slot = usize::from(self.cursor);
            self.cursor = ((slot + 1) % ENTRIES) as u8;
            if let Some(owner) = self.originals[slot].take() {
                return Some((slot, owner));
            }
        }
        None
    }
    pub fn restore_original(&mut self, slot: usize, owner: M) -> Result<(), M> {
        match self.originals.get_mut(slot) {
            Some(place) if place.is_none() => {
                *place = Some(owner);
                Ok(())
            }
            _ => Err(owner),
        }
    }
    pub fn releasable(&self) -> bool {
        self.flags & INIT_ACK != 0
            && (self.flags & ENDED != 0 || self.flags & (USER | CRT_REPLIED) == USER | CRT_REPLIED)
            && self.originals.iter().all(Option::is_none)
            && self.reply_copies.iter().all(Option::is_none)
            && self.cleanup.iter().all(Option::is_none)
            && self.retained_thread.is_none()
            && self.retained_identity.is_none()
            && self.crt_pending.is_none()
            && self.operation_pending.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::Access;
    use std::{cell::RefCell, rc::Rc, vec::Vec};
    struct Cap(u32, Rc<RefCell<Vec<u32>>>);
    impl Drop for Cap {
        fn drop(&mut self) {
            self.1.borrow_mut().push(self.0);
        }
    }
    type Resident = InitialResident<Cap, Cap, Cap, Cap>;
    fn fixture() -> (Resident, Publication, Rc<RefCell<Vec<u32>>>) {
        let key = SeedKey {
            epoch: 1,
            ticket: u64::MAX,
            label: proto_process::Label {
                index: 0,
                generation: 1,
            }
            .raw_at(1),
        };
        let receipt = Receipt {
            key: Key {
                key: key.ticket,
                image: 1,
            },
            label: key.label,
            pid: proto_process::Label {
                index: 0,
                generation: 1,
            }
            .pid(),
            init_ticket: key.ticket,
        };
        let source = InitialSource {
            artifact: 2,
            raw: 3,
            canonical: Some(4),
        };
        let resident = Resident::reserved(key, receipt, source).unwrap();
        let publication = Publication {
            source,
            map: Reply {
                receipt,
                count: 2,
                entries: [
                    Entry {
                        address: 4096,
                        pages: 1,
                        access: Access::Read,
                        slot: 0,
                    },
                    Entry {
                        address: 8192,
                        pages: 1,
                        access: Access::ReadWrite,
                        slot: 1,
                    },
                    Entry::EMPTY,
                    Entry::EMPTY,
                ],
            },
        };
        (resident, publication, Rc::new(RefCell::new(Vec::new())))
    }
    fn objects(log: &Rc<RefCell<Vec<u32>>>) -> [Option<Cap>; 4] {
        [
            Some(Cap(1, log.clone())),
            Some(Cap(2, log.clone())),
            None,
            None,
        ]
    }
    #[test]
    fn reserved_epoch_is_private_until_exact_proof_and_cleared_before_maps() {
        let (mut resident, publication, log) = fixture();
        resident.key.epoch = 0;
        assert!(resident.awaiting_guard());
        assert!(resident.queue_stage(37, 12, 13, 1));
        assert_eq!(resident.key.epoch, 0);
        assert_eq!(resident.pending_stage(), Some((37, 12, 13, 1)));
        assert!(!resident.queue_stage(38, 12, 13, 1));
        assert!(resident.map_reply(Key::FIRST).is_none());
        let owners = resident.publish(publication, objects(&log)).err().unwrap();
        assert_eq!(resident.pending_stage(), Some((37, 12, 13, 1)));
        let key = SeedKey {
            epoch: 38,
            ..resident.key
        };
        assert!(!resident.authenticated_stage(key, 71));
        assert_eq!(resident.key.epoch, 0);
        assert!(resident.authenticated_stage(SeedKey { epoch: 37, ..key }, 71));
        assert_eq!(resident.key.epoch, 37);
        assert_eq!(resident.publication.map.entries[0], Entry::EMPTY);
        assert!(resident.pending_stage().is_none());
        resident.flags |= PAGE_MAPPED | PAGE_SETTLED;
        assert!(resident.publish(publication, owners).is_ok());
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn target_page_owner_waits_for_proof_map_close_and_exact_native_end() {
        let (mut resident, publication, log) = fixture();
        assert!(resident.awaiting_guard());
        assert!(!resident.page_needs_copy());
        assert!(resident.retain_page_copy(Cap(7, log.clone())).is_err());
        assert!(resident.authenticated_stage(resident.key, 71));
        assert!(resident.page_needs_copy());
        assert!(resident.retain_page_copy(Cap(8, log.clone())).is_ok());
        assert!(!resident.page_ready());
        assert!(!resident.confirm_page_settled());
        assert!(resident.remove_page_copy().is_none());
        let owners = resident.publish(publication, objects(&log)).err().unwrap();
        assert!(resident.confirm_page_map());
        assert!(resident.page_mapped());
        assert!(!resident.confirm_page_settled());
        let owner = resident.remove_page_copy().unwrap();
        assert!(resident.confirm_page_settled());
        assert!(resident.page_ready());
        assert!(resident.publish(publication, owners).is_ok());
        let foreign = SeedKey {
            label: resident.key.label + 1,
            ..resident.key
        };
        assert!(!resident.native_exited(foreign, 19));
        assert!(resident.page_mapped());
        assert!(resident.native_exited(resident.key, 19));
        assert!(resident.native_end_confirmed());
        assert!(!resident.page_mapped());
        assert!(!resident.page_ready());
        assert!(!resident.bootstrap(resident.key));
        drop(owner);
        assert_eq!(log.borrow().as_slice(), &[7, 8]);
    }

    #[test]
    fn end_before_maps_clears_only_cpu_alias_and_blocks_late_proof() {
        let (mut resident, _, log) = fixture();
        resident.key.epoch = 0;
        assert!(resident.awaiting_guard());
        assert!(resident.queue_stage(37, 12, 13, 1));
        assert!(resident.ended(resident.key, 19));
        assert_eq!(resident.publication.map.entries[0], Entry::EMPTY);
        assert!(resident.cleanup_original().is_none());
        assert!(!resident.authenticated_stage(
            SeedKey {
                epoch: 37,
                ..resident.key
            },
            71
        ));
        assert_eq!(resident.end_reason(), Some(19));
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn guard_precedes_maps_and_rejected_tuple_never_drops_in_admission() {
        let (mut resident, publication, log) = fixture();
        let back = resident.publish(publication, objects(&log)).err().unwrap();
        assert!(log.borrow().is_empty());
        assert!(resident.awaiting_guard());
        assert!(resident.authenticated_stage(resident.key, 9));
        resident.flags |= PAGE_MAPPED | PAGE_SETTLED;
        assert!(resident.publish(publication, back).is_ok());
        let replay = resident.publish(publication, objects(&log)).err().unwrap();
        assert!(resident.replay_matches(&publication));
        assert!(log.borrow().is_empty());
        drop(replay);
        drop(resident);
    }
    #[test]
    fn init_ack_and_confirmed_crt_reply_both_withhold_slot() {
        let (mut resident, publication, log) = fixture();
        assert!(resident.awaiting_guard());
        assert!(resident.authenticated_stage(resident.key, 9));
        resident.flags |= PAGE_MAPPED | PAGE_SETTLED;
        assert!(resident.publish(publication, objects(&log)).is_ok());
        assert!(!resident.user_release(resident.key));
        assert!(!resident.init_ack(resident.key, publication.map.receipt));
        assert!(resident.bootstrap(resident.key));
        assert_eq!(resident.map_reply(Key::FIRST), Some(publication.map));
        assert_eq!(
            resident.map_ack(publication.map.receipt.key),
            Some(publication.map.receipt)
        );
        assert!(resident.map_reply(Key::FIRST).is_none());
        assert!(resident.user_release(resident.key));
        assert!(resident.init_ack(resident.key, publication.map.receipt));
        assert!(!resident.releasable());
        while let Some((_, owner)) = resident.cleanup_original() {
            drop(owner);
        }
        assert!(!resident.releasable());
        resident.crt_pending = Some(Cap(3, log.clone()));
        resident.crt_reply_confirmed();
        assert!(!resident.releasable());
        drop(resident.crt_pending.take());
        assert!(resident.releasable());
        assert_eq!(*log.borrow(), [1, 2, 3]);
    }
    #[test]
    fn exact_end_blocks_late_release_and_failed_close_rotates() {
        let (mut resident, publication, log) = fixture();
        assert!(resident.awaiting_guard());
        assert!(resident.authenticated_stage(resident.key, 9));
        resident.flags |= PAGE_MAPPED | PAGE_SETTLED;
        assert!(resident.publish(publication, objects(&log)).is_ok());
        let foreign = SeedKey {
            epoch: 2,
            ..resident.key
        };
        assert!(!resident.ended(foreign, 11));
        assert!(resident.ended(resident.key, 11));
        assert!(!resident.ended(resident.key, 12));
        assert!(!resident.bootstrap(resident.key));
        assert!(!resident.user_release(resident.key));
        let (slot, owner) = resident.cleanup_original().unwrap();
        assert_eq!(slot, 0);
        assert!(resident.restore_original(slot, owner).is_ok());
        let (slot, owner) = resident.cleanup_original().unwrap();
        assert_eq!(slot, 1);
        drop(owner);
        assert!(!resident.releasable());
        let (_, owner) = resident.cleanup_original().unwrap();
        drop(owner);
        assert!(resident.init_ack(resident.key, publication.map.receipt));
        assert!(resident.releasable());
        assert_eq!(resident.end_reason(), Some(11));
        assert_eq!(*log.borrow(), [2, 1]);
    }
}
