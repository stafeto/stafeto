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
    MapReplyCopies,
    MapReplySend,
    MapReplyUncertain,
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

/// Delivery describes the token and copy ownership after the native reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapDelivery {
    Completed,
    ReturnedLive,
    Consumed,
}

/// Each method performs at most one native effect. Reply restores returned
/// copies in their exact slots and retains a consumed Pending as a marker.
pub trait MapEffects<M, D> {
    fn is_live(&self, pending: &D) -> bool;
    fn duplicate(&mut self, original: &M, entry: Entry) -> Option<M>;
    fn send(
        &mut self,
        reply: &Reply,
        copies: &mut [Option<M>; ENTRIES],
        pending: &mut D,
    ) -> MapDelivery;
    fn close(&mut self, owner: M) -> Result<(), M>;
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
    /// Every native custody effect remains bound to the full current image.
    pub fn matches_image(&self, label: u64, image: u32) -> bool {
        label == self.key.label
            && label == self.publication.map.receipt.label
            && image == self.publication.map.receipt.key.image
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
            return false;
        }
        if self.key.epoch == 0 {
            if self.pending_stage().map(|value| value.0) != Some(key.epoch) {
                return false;
            }
            self.clear_pending_epoch();
            self.key.epoch = key.epoch;
        } else if key != self.key || self.phase != Phase::GuardWait {
            return false;
        }
        self.flags |= STAGE;
        self.phase = Phase::Loading;
        true
    }
    /// The caller also checks the actual source label retained in its Record.
    pub fn stage_replay_matches(&self, stage: &proto_process::initial_stage::Stage) -> bool {
        self.page_ready()
            && self.operation_pending.is_none()
            && stage.epoch == self.key.epoch
            && stage.ticket == self.key.ticket
            && stage.label == self.key.label
            && stage.query.receipt == self.publication.map.receipt
            && stage.source == self.publication.source
            && stage.uid == self.end_reason
            && (u64::from(stage.gid) | (u64::from(stage.mode) << 32)) == self.guard_label
    }

    pub fn maps_replay_matches(&self, publication: &Publication) -> bool {
        self.maps_ready()
            && self.operation_pending.is_none()
            && self.publication == *publication
            && self.originals.iter().enumerate().all(|(slot, owner)| {
                owner.is_some() == (slot < usize::from(self.publication.map.count))
            })
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
    pub fn can_begin_map_reply<E: MapEffects<M, D>>(&self, key: Key, effects: &E) -> bool {
        self.map_reply(key).is_some()
            && match self.phase {
                Phase::CRTWait => self.operation_pending.is_none(),
                Phase::MapReplyUncertain => {
                    key == self.publication.map.receipt.key
                        && self
                            .operation_pending
                            .as_ref()
                            .is_some_and(|pending| !effects.is_live(pending))
                }
                _ => false,
            }
    }
    pub fn begin_map_reply<E: MapEffects<M, D>>(
        &mut self,
        key: Key,
        pending: D,
        effects: &E,
    ) -> Result<(), D> {
        if !self.can_begin_map_reply(key, effects) || !effects.is_live(&pending) {
            return Err(pending);
        }
        // Admission only replaces a marker whose token has already been consumed.
        self.operation_pending = Some(pending);
        self.phase = Phase::MapReplyCopies;
        Ok(())
    }
    pub fn acknowledge_maps<E: MapEffects<M, D>>(
        &mut self,
        key: Key,
        effects: &E,
    ) -> Option<Receipt> {
        if self
            .operation_pending
            .as_ref()
            .is_some_and(|p| effects.is_live(p))
        {
            return None;
        }
        let receipt = self.map_ack(key)?;
        self.operation_pending.take();
        Some(receipt)
    }
    /// Returns true when this visit belongs to the map driver, including a
    /// waiting or refused effect. The caller performs no second native effect.
    pub fn map_step<E: MapEffects<M, D>>(&mut self, effects: &mut E) -> bool {
        if self.flags & ENDED != 0 {
            return false;
        }
        match self.phase {
            Phase::MapReplyCopies => {
                let count = usize::from(self.publication.map.count);
                if let Some(slot) = (0..count).find(|&slot| self.reply_copies[slot].is_none()) {
                    let original = self.originals[slot].as_ref().expect("retained initial map");
                    if let Some(copy) =
                        effects.duplicate(original, self.publication.map.entries[slot])
                    {
                        self.reply_copies[slot] = Some(copy);
                    }
                } else {
                    self.phase = Phase::MapReplySend;
                }
                true
            }
            Phase::MapReplySend => {
                let pending = self
                    .operation_pending
                    .as_mut()
                    .expect("initial map request");
                match effects.send(&self.publication.map, &mut self.reply_copies, pending) {
                    MapDelivery::Completed => {
                        assert!(!effects.is_live(pending));
                        assert!(self.reply_copies.iter().all(Option::is_none));
                        self.operation_pending.take();
                        self.phase = Phase::CRTWait;
                    }
                    MapDelivery::ReturnedLive => {
                        assert!(effects.is_live(pending));
                        assert!(self.reply_copies.iter().enumerate().all(|(slot, owner)| {
                            owner.is_some() == (slot < usize::from(self.publication.map.count))
                        }));
                    }
                    MapDelivery::Consumed => {
                        assert!(!effects.is_live(pending));
                        self.phase = Phase::MapReplyUncertain;
                    }
                }
                true
            }
            Phase::MapReplyUncertain => true,
            _ if self.flags & MAPS_ACK != 0 => {
                if let Some((slot, owner)) = self.cleanup_reply_copy() {
                    if let Err(owner) = effects.close(owner) {
                        assert!(self.restore_reply_copy(slot, owner).is_ok());
                    }
                    return true;
                }
                if let Some((slot, owner)) = self.cleanup_original() {
                    if let Err(owner) = effects.close(owner) {
                        assert!(self.restore_original(slot, owner).is_ok());
                    }
                    return true;
                }
                false
            }
            _ => false,
        }
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
    pub fn cleanup_reply_copy(&mut self) -> Option<(usize, M)> {
        if self.flags & MAPS_ACK == 0 && !self.native_end_confirmed() {
            return None;
        }
        self.reply_copies
            .iter_mut()
            .enumerate()
            .find_map(|(slot, owner)| owner.take().map(|owner| (slot, owner)))
    }

    pub fn restore_reply_copy(&mut self, slot: usize, owner: M) -> Result<(), M> {
        match self.reply_copies.get_mut(slot) {
            Some(place) if place.is_none() => {
                *place = Some(owner);
                Ok(())
            }
            _ => Err(owner),
        }
    }

    pub fn cleanup_thread(&mut self) -> Option<T> {
        if !self.native_end_confirmed() {
            return None;
        }
        self.retained_thread.take()
    }

    /// A terminal reply can leave an empty Pending that has no Drop effect.
    pub fn settle_operation(&mut self, token_returned: bool) {
        if !token_returned {
            self.operation_pending.take();
        }
    }

    pub fn settle_identity(&mut self, token_returned: bool) {
        if !token_returned {
            self.crt_pending.take();
            self.identity_finished();
        }
    }

    pub fn releasable_for<P, A>(
        &self,
        record: &crate::records::Record<P, A>,
        initial_ticket: u64,
    ) -> bool {
        let ack = proto_process::initial_ack::Ack {
            epoch: self.key.epoch,
            ticket: self.key.ticket,
            label: self.key.label,
            receipt: self.publication.map.receipt,
        };
        self.releasable()
            && record.initial_ack_replay_matches(initial_ticket, ack)
            && (self.end_reason().is_none()
                || (self.native_end_confirmed() && record.active_exec.is_none()))
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
    struct MapPending {
        live: bool,
    }
    struct Effects {
        log: Rc<RefCell<Vec<u32>>>,
        calls: usize,
        dup_fail: bool,
        close_fail: bool,
        outcome: MapDelivery,
        returned: bool,
        received: Vec<Cap>,
    }
    impl MapEffects<Cap, MapPending> for Effects {
        fn is_live(&self, pending: &MapPending) -> bool {
            pending.live
        }
        fn duplicate(&mut self, original: &Cap, _entry: Entry) -> Option<Cap> {
            self.calls += 1;
            if self.dup_fail {
                return None;
            }
            Some(Cap(original.0 + 100, self.log.clone()))
        }
        fn send(
            &mut self,
            reply: &Reply,
            copies: &mut [Option<Cap>; ENTRIES],
            pending: &mut MapPending,
        ) -> MapDelivery {
            self.calls += 1;
            assert!(pending.live);
            for (slot, copy) in copies.iter().enumerate() {
                assert_eq!(
                    copy.as_ref().map(|cap| cap.0),
                    (slot < usize::from(reply.count)).then_some(slot as u32 + 101)
                );
            }
            pending.live = self.outcome == MapDelivery::ReturnedLive;
            if !self.returned {
                for copy in copies.iter_mut().filter_map(Option::take) {
                    self.received.push(copy);
                }
            }
            self.outcome
        }
        fn close(&mut self, owner: Cap) -> Result<(), Cap> {
            self.calls += 1;
            if self.close_fail {
                return Err(owner);
            }
            drop(owner);
            Ok(())
        }
    }
    fn map_fixture(count: u8) -> (InitialResident<Cap, Cap, Cap, MapPending>, Effects) {
        let (base, mut publication, log) = fixture();
        publication.map.count = u16::from(count);
        for slot in 0..ENTRIES {
            publication.map.entries[slot] = if slot < usize::from(count) {
                Entry {
                    address: (slot as u64 + 1) * 4096,
                    pages: 1,
                    access: Access::Read,
                    slot: slot as u32,
                }
            } else {
                Entry::EMPTY
            };
        }
        let mut resident =
            InitialResident::reserved(base.key, publication.map.receipt, publication.source)
                .unwrap();
        assert!(resident.awaiting_guard());
        assert!(resident.authenticated_stage(resident.key, 9));
        resident.flags |= PAGE_MAPPED | PAGE_SETTLED;
        assert!(
            resident
                .publish(
                    publication,
                    core::array::from_fn(|slot| {
                        (slot < usize::from(count)).then(|| Cap(slot as u32 + 1, log.clone()))
                    })
                )
                .is_ok()
        );
        assert!(resident.bootstrap(resident.key));
        (
            resident,
            Effects {
                log,
                calls: 0,
                dup_fail: false,
                close_fail: false,
                outcome: MapDelivery::Completed,
                returned: false,
                received: Vec::new(),
            },
        )
    }
    #[test]
    fn map_delivery_preserves_originals_and_retries_only_missing_copies() {
        for count in 1..=ENTRIES as u8 {
            for (outcome, returned) in [
                (MapDelivery::Completed, false),
                (MapDelivery::ReturnedLive, true),
                (MapDelivery::Consumed, true),
                (MapDelivery::Consumed, false),
            ] {
                let (mut resident, mut effects) = map_fixture(count);
                effects.outcome = outcome;
                effects.returned = returned;
                let key = resident.publication.map.receipt.key;
                assert!(
                    resident
                        .begin_map_reply(Key::FIRST, MapPending { live: true }, &effects)
                        .is_ok()
                );
                effects.dup_fail = true;
                assert!(resident.map_step(&mut effects));
                assert!(resident.reply_copies.iter().all(Option::is_none));
                effects.dup_fail = false;
                for _ in 0..count {
                    assert!(resident.map_step(&mut effects));
                }
                assert_eq!(effects.calls, usize::from(count) + 1);
                assert!(resident.map_step(&mut effects)); // CPU phase change.
                assert_eq!(effects.calls, usize::from(count) + 1);
                assert!(resident.acknowledge_maps(key, &effects).is_none());
                assert!(resident.map_step(&mut effects));
                assert!(effects.log.borrow().is_empty());
                assert!(
                    resident
                        .originals
                        .iter()
                        .enumerate()
                        .all(|(slot, cap)| cap.as_ref().map(|c| c.0)
                            == (slot < usize::from(count)).then_some(slot as u32 + 1))
                );
                if outcome == MapDelivery::ReturnedLive {
                    assert!(!resident.can_begin_map_reply(key, &effects));
                    assert!(resident.acknowledge_maps(key, &effects).is_none());
                    effects.outcome = MapDelivery::Completed;
                    effects.returned = false;
                    assert!(resident.map_step(&mut effects));
                } else if outcome == MapDelivery::Consumed {
                    assert!(!resident.can_begin_map_reply(Key::FIRST, &effects));
                    let calls = effects.calls;
                    assert!(resident.map_step(&mut effects));
                    assert_eq!(effects.calls, calls);
                    let foreign = Key {
                        key: key.key - 1,
                        image: key.image,
                    };
                    assert!(!resident.can_begin_map_reply(foreign, &effects));
                    assert!(
                        resident
                            .begin_map_reply(key, MapPending { live: true }, &effects)
                            .is_ok()
                    );
                    let before = effects.calls;
                    for _ in 0..=count {
                        resident.map_step(&mut effects);
                    }
                    assert_eq!(
                        effects.calls - before,
                        if returned { 1 } else { usize::from(count) }
                    );
                    // Returned tuples reach Send immediately; no new duplicate.
                    if resident.phase == Phase::MapReplySend {
                        resident.map_step(&mut effects);
                    }
                }
                assert!(resident.acknowledge_maps(key, &effects).is_some());
                assert!(resident.operation_pending.is_none());
                assert!(!resident.can_begin_map_reply(key, &effects));
                let calls = effects.calls;
                assert!(resident.acknowledge_maps(key, &effects).is_some());
                assert_eq!(effects.calls, calls);
                effects.close_fail = true;
                let before = effects.calls;
                assert!(resident.map_step(&mut effects));
                assert_eq!(effects.calls, before + 1);
                assert!(effects.log.borrow().is_empty());
                effects.close_fail = false;
                while resident.map_step(&mut effects) {}
                assert!(resident.originals.iter().all(Option::is_none));
                assert!(resident.reply_copies.iter().all(Option::is_none));
                for original in 1..=u32::from(count) {
                    assert_eq!(
                        effects
                            .log
                            .borrow()
                            .iter()
                            .filter(|&&id| id == original)
                            .count(),
                        1
                    );
                }
            }
        }
    }
    #[test]
    fn exact_ack_reconciles_consumed_marker_and_closes_returned_copies() {
        for returned in [false, true] {
            let (mut resident, mut effects) = map_fixture(2);
            effects.outcome = MapDelivery::Consumed;
            effects.returned = returned;
            let key = resident.publication.map.receipt.key;
            assert!(
                resident
                    .begin_map_reply(key, MapPending { live: true }, &effects)
                    .is_ok()
            );
            for _ in 0..4 {
                assert!(resident.map_step(&mut effects));
            }
            assert_eq!(resident.phase, Phase::MapReplyUncertain);
            let wrong = Key {
                key: key.key,
                image: key.image + 1,
            };
            assert!(resident.acknowledge_maps(wrong, &effects).is_none());
            assert!(resident.operation_pending.is_some());
            let calls = effects.calls;
            assert!(resident.acknowledge_maps(key, &effects).is_some());
            assert_eq!(effects.calls, calls);
            assert!(resident.operation_pending.is_none());
            assert!(effects.log.borrow().is_empty());
            while resident.map_step(&mut effects) {}
            let log = effects.log.borrow();
            assert_eq!(log.iter().filter(|&&id| id <= 2).count(), 2);
            assert_eq!(
                log.iter().filter(|&&id| id >= 100).count(),
                if returned { 2 } else { 0 }
            );
            assert_eq!(effects.received.len(), if returned { 0 } else { 2 });
        }
    }
    #[test]
    fn end_after_ack_waits_for_native_exit_before_closing_maps() {
        let (mut resident, mut effects) = map_fixture(2);
        let key = resident.publication.map.receipt.key;
        assert!(resident.acknowledge_maps(key, &effects).is_some());
        assert!(resident.ended(resident.key, 9));
        assert!(!resident.native_end_confirmed());
        assert!(!resident.map_step(&mut effects));
        assert_eq!(effects.calls, 0);
        assert!(resident.originals[0].is_some());
        assert!(effects.log.borrow().is_empty());
    }
    #[test]
    fn end_blocks_map_effects_in_every_reply_phase() {
        for phase in [
            Phase::MapReplyCopies,
            Phase::MapReplySend,
            Phase::MapReplyUncertain,
        ] {
            let (mut resident, mut effects) = map_fixture(4);
            resident.phase = phase;
            resident.operation_pending = Some(MapPending {
                live: phase != Phase::MapReplyUncertain,
            });
            resident.reply_copies[0] = Some(Cap(101, effects.log.clone()));
            assert!(resident.ended(resident.key, 9));
            assert!(!resident.map_step(&mut effects));
            assert_eq!(effects.calls, 0);
            assert!(effects.log.borrow().is_empty());
            assert!(resident.cleanup_reply_copy().is_none());
            assert!(!resident.can_begin_map_reply(Key::FIRST, &effects));
        }
    }
    #[test]
    fn terminal_release_keeps_all_owners_until_native_end_and_exact_ack() {
        use crate::initial_origin::{INIT_ACKED, InitialOrigin, SourceOrigin};
        let (mut resident, publication, log) = fixture();
        let mut table = crate::records::Records::<u32, u32>::with_exec_custody();
        let label = table.next_label().unwrap();
        assert_eq!(label.raw_at(1), resident.key.label);
        table.insert(
            label,
            0,
            None,
            proto_process::Credentials::ROOT,
            31,
            crate::records::Join::Inherit,
        );
        let record = table.get_mut(usize::from(label.index)).unwrap();
        let ticket = resident.key.ticket;
        record.source_origin = SourceOrigin::boot(2, false).unwrap();
        assert!(record.set_initial_epoch(ticket, resident.key.epoch));
        assert!(resident.ended(resident.key, 9));
        assert!(resident.init_ack(resident.key, publication.map.receipt));
        assert!(!resident.releasable_for(record, ticket));
        assert!(record.set_initial_origin(ticket, InitialOrigin::new(2, INIT_ACKED).unwrap()));
        assert!(!resident.releasable_for(record, ticket));
        assert!(resident.native_exited(resident.key, 9));
        record.active_exec = Some(73);
        assert!(!resident.releasable_for(record, ticket));
        record.active_exec = None;
        assert!(resident.releasable_for(record, ticket));
        resident.operation_pending = Some(Cap(7, log.clone()));
        resident.settle_operation(true);
        assert!(!resident.releasable_for(record, ticket));
        resident.settle_operation(false);
        resident.cleanup[0] = Some(CleanupOwner::Channel(Cap(8, log.clone())));
        assert!(!resident.releasable_for(record, ticket));
        drop(resident.cleanup[0].take());
        resident.retained_thread = Some(Cap(9, log.clone()));
        let thread = resident.cleanup_thread().unwrap();
        assert!(resident.retained_thread.replace(thread).is_none());
        assert!(!resident.releasable_for(record, ticket));
        drop(resident.cleanup_thread());
        assert!(resident.releasable_for(record, ticket));
        assert!(!resident.releasable_for(record, ticket - 1));
        resident.key.epoch ^= 1 << 48;
        assert!(!resident.releasable_for(record, ticket));
        resident.key.epoch ^= 1 << 48;
        record.image += 1;
        assert!(!resident.releasable_for(record, ticket));
        assert_eq!(*log.borrow(), [7, 8, 9]);
    }
    #[test]
    fn settled_replay_preserves_complete_stage_and_verified_original_custody() {
        let (mut resident, publication, log) = fixture();
        resident.key.epoch = 0;
        let stage = proto_process::initial_stage::Stage {
            epoch: 37,
            ticket: resident.key.ticket,
            label: resident.key.label,
            source: publication.source,
            query: proto_process::initial_identity::Query {
                receipt: publication.map.receipt,
            },
            uid: u32::MAX,
            gid: u32::MAX - 1,
            mode: 1,
        };
        assert!(!resident.stage_replay_matches(&stage));
        assert!(resident.awaiting_guard());
        assert!(resident.queue_stage(stage.epoch, stage.uid, stage.gid, stage.mode));
        resident.operation_pending = Some(Cap(90, log.clone()));
        assert!(!resident.stage_replay_matches(&stage));
        assert!(!resident.authenticated_stage(
            SeedKey {
                epoch: 38,
                ..resident.key
            },
            71
        ));
        assert!(resident.authenticated_stage(
            SeedKey {
                epoch: 37,
                ..resident.key
            },
            71
        ));
        assert!(!resident.authenticated_stage(resident.key, 72));
        assert!(!resident.stage_replay_matches(&stage));
        assert!(resident.retain_page_copy(Cap(80, log.clone())).is_ok());
        assert!(resident.confirm_page_map());
        assert!(!resident.stage_replay_matches(&stage));
        drop(resident.remove_page_copy().unwrap());
        assert!(resident.confirm_page_settled());
        assert!(!resident.stage_replay_matches(&stage));
        resident.settle_operation(true);
        assert!(resident.operation_pending.is_some());
        resident.settle_operation(false);
        assert!(resident.stage_replay_matches(&stage));
        for field in 0..12 {
            let mut foreign = stage;
            match field {
                0 => foreign.epoch += 1,
                1 => foreign.ticket -= 1,
                2 => foreign.label += 1 << 32,
                3 => foreign.source.artifact += 1,
                4 => foreign.source.raw += 1,
                5 => foreign.source.canonical = None,
                6 => foreign.query.receipt.pid += 1,
                7 => foreign.query.receipt.key.image += 1,
                8 => foreign.query.receipt.init_ticket -= 1,
                9 => foreign.uid -= 1,
                10 => foreign.gid -= 1,
                _ => foreign.mode = 0,
            }
            assert!(
                !resident.stage_replay_matches(&foreign),
                "stage field {field}"
            );
        }
        assert!(!resident.maps_replay_matches(&publication));
        assert!(resident.begin_publish(publication, objects(&log)).is_ok());
        assert!(!resident.maps_replay_matches(&publication));
        resident.operation_pending = Some(Cap(91, log.clone()));
        assert!(!resident.maps_replay_matches(&publication));
        assert!(resident.memory_validated(0));
        assert!(!resident.maps_replay_matches(&publication));
        assert!(resident.memory_validated(1));
        assert!(resident.maps_ready());
        assert!(!resident.maps_replay_matches(&publication));
        resident.settle_operation(false);
        assert!(resident.maps_replay_matches(&publication));
        assert!(resident.stage_replay_matches(&stage));
        for field in 0..9 {
            let mut foreign = publication;
            match field {
                0 => foreign.source.artifact += 1,
                1 => foreign.source.raw += 1,
                2 => foreign.source.canonical = None,
                3 => foreign.map.receipt.key.key -= 1,
                4 => foreign.map.receipt.label += 1 << 32,
                5 => foreign.map.receipt.pid += 1,
                6 => foreign.map.receipt.init_ticket -= 1,
                7 => foreign.map.entries[0].address += 4096,
                _ => foreign.map.entries[1].access = Access::Read,
            }
            assert!(
                !resident.maps_replay_matches(&foreign),
                "publication field {field}"
            );
        }
        let duplicates = resident
            .begin_publish(publication, objects(&log))
            .err()
            .unwrap();
        assert_eq!(resident.originals[0].as_ref().unwrap().0, 1);
        assert!(resident.maps_replay_matches(&publication));
        drop(duplicates);
        resident.flags &= !PAGE_SETTLED;
        assert!(!resident.maps_replay_matches(&publication));
        assert!(!resident.stage_replay_matches(&stage));
        resident.flags |= PAGE_SETTLED;
        assert!(resident.native_exited(resident.key, 19));
        assert!(!resident.maps_replay_matches(&publication));
        assert!(!resident.stage_replay_matches(&stage));
        assert_eq!(resident.end_reason(), Some(19));
    }

    #[test]
    fn source_custody_stays_bound_to_full_generation_and_current_image() {
        let (mut resident, _, _) = fixture();
        let label = resident.key.label;
        assert!(resident.matches_image(label, 1));
        assert!(!resident.matches_image(label, 2));
        assert!(!resident.matches_image(label + (1 << 32), 1));
        assert!(!resident.matches_image(label ^ (1 << 16), 1));
        assert!(resident.awaiting_guard());
        assert!(!resident.authenticated_stage(resident.key, 0));
        assert!(resident.authenticated_stage(resident.key, 71));
        assert!(!resident.authenticated_stage(resident.key, 72));
        assert!(!resident.authenticated_stage(resident.key, 71));
        assert!(resident.native_exited(resident.key, 19));
        assert!(!resident.matches_image(label, 2));
    }

    #[test]
    fn exact_end_keeps_every_reply_copy_thread_and_failed_close_owner() {
        let (mut resident, _, log) = fixture();
        resident.reply_copies[0] = Some(Cap(20, log.clone()));
        resident.reply_copies[3] = Some(Cap(23, log.clone()));
        resident.retained_thread = Some(Cap(30, log.clone()));
        assert!(resident.cleanup_reply_copy().is_none());
        assert!(resident.cleanup_thread().is_none());
        assert!(resident.ended(resident.key, 19));
        assert!(resident.cleanup_reply_copy().is_none());
        assert!(resident.cleanup_thread().is_none());
        assert!(!resident.native_exited(
            SeedKey {
                label: resident.key.label + 1,
                ..resident.key
            },
            19
        ));
        assert!(resident.cleanup_thread().is_none());
        assert!(resident.native_exited(resident.key, 19));
        let (slot, owner) = resident.cleanup_reply_copy().unwrap();
        assert_eq!((slot, owner.0), (0, 20));
        assert!(resident.restore_reply_copy(slot, owner).is_ok());
        assert!(log.borrow().is_empty());
        let (slot, owner) = resident.cleanup_reply_copy().unwrap();
        assert_eq!(slot, 0);
        drop(owner);
        assert_eq!(log.borrow().as_slice(), &[20]);
        let (slot, owner) = resident.cleanup_reply_copy().unwrap();
        assert_eq!(slot, 3);
        drop(owner);
        let owner = resident.cleanup_thread().unwrap();
        assert_eq!(owner.0, 30);
        resident.retained_thread = Some(owner);
        assert_eq!(log.borrow().as_slice(), &[20, 23]);
        drop(resident.cleanup_thread().unwrap());
        assert!(resident.cleanup_reply_copy().is_none());
        assert!(resident.cleanup_thread().is_none());
        assert!(!resident.releasable());
        resident.flags |= INIT_ACK;
        assert!(resident.releasable());
        assert_eq!(log.borrow().as_slice(), &[20, 23, 30]);
    }

    #[test]
    fn new_identity_attempt_clears_previous_proof_after_consumed_reply() {
        let (mut resident, publication, log) = fixture();
        assert!(!resident.maps_ready());
        assert!(resident.awaiting_guard());
        assert!(resident.authenticated_stage(resident.key, 71));
        resident.flags |= PAGE_MAPPED | PAGE_SETTLED;
        assert!(resident.begin_publish(publication, objects(&log)).is_ok());
        assert!(!resident.maps_ready());
        assert!(resident.memory_validated(0));
        assert!(resident.memory_validated(1));
        assert!(resident.maps_ready());
        resident.crt_pending = Some(Cap(40, log.clone()));
        resident.identity_result(true);
        assert!(resident.identity_genuine());
        resident.settle_identity(true);
        assert!(resident.crt_pending.is_some());
        assert!(resident.identity_genuine());
        resident.settle_identity(false);
        assert!(resident.crt_pending.is_none());
        assert!(!resident.identity_checked());
        resident.crt_pending = Some(Cap(41, log.clone()));
        assert!(!resident.identity_genuine());
        resident.identity_result(false);
        assert!(!resident.identity_genuine());
        resident.settle_identity(false);
        assert!(!resident.identity_checked());
        assert_eq!(log.borrow().as_slice(), &[40, 41]);
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
