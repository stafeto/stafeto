// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Paid identities and direct indices for inode/owner lock groups.
//! The service serializes access and retains revoked identities until cleanup.

use super::Owner;
use crate::storage::Token;
use core::num::NonZeroU64;

const NONE: u16 = u16::MAX;
const PID_PLACES: u32 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    NoLocks,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Id {
    slot: u16,
    generation: NonZeroU64,
}
impl Id {
    pub fn slot(self) -> usize {
        self.slot as usize
    }
    pub fn generation(self) -> u64 {
        self.generation.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capture {
    id: Id,
    epoch: u64,
}
impl Capture {
    pub fn id(self) -> Id {
        self.id
    }
    pub fn epoch(self) -> u64 {
        self.epoch
    }
}

/// Exclusive custody of one departed PID's still-paid group chain.
/// Each step revokes one group; record cleanup retains its identity separately.
pub struct Departure {
    pid: u32,
    next: Option<Id>,
}
impl Departure {
    pub fn done(&self) -> bool {
        self.next.is_none()
    }
    pub fn step<
        const N: usize,
        const I: usize,
        const P: usize,
        const D: usize,
        const R: usize,
        const S: usize,
    >(
        &mut self,
        groups: &mut Groups<N, I, P, D, R, S>,
    ) -> Result<Option<(Id, Snapshot)>, Error> {
        let Some(id) = self.next else { return Ok(None) };
        let group = *groups.group(id)?;
        if !group.active
            || group.snapshot.owner != Owner::Process(self.pid)
            || groups.owner_live(group.snapshot.owner)
        {
            return Err(Error::Invalid);
        }
        groups.detach(id, group);
        self.next = group.owner_next;
        Ok(Some((id, group.snapshot)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub inode: Token,
    pub owner: Owner,
    pub root: u16,
    pub epoch: u64,
}

#[derive(Clone, Copy)]
struct Group {
    snapshot: Snapshot,
    active: bool,
    inode_prev: Option<Id>,
    inode_next: Option<Id>,
    owner_prev: Option<Id>,
    owner_next: Option<Id>,
}
#[derive(Clone, Copy)]
enum Slot {
    Fresh,
    Free(u16),
    Paid(Group),
    Exhausted,
}
#[derive(Clone, Copy)]
struct PidHead {
    pid: u32,
    live: bool,
    head: Option<Id>,
}
impl PidHead {
    const EMPTY: Self = Self {
        pid: 0,
        live: false,
        head: None,
    };
}
#[derive(Clone, Copy)]
enum Position {
    Pid(usize),
    Description(usize),
}

/// Fixed metadata; region heads and reader custody are added by the actor.
/// Each direct cell is checked against the group's complete inode and owner.
pub struct Groups<
    const N: usize,
    const INODES: usize,
    const PIDS: usize,
    const DESCRIPTIONS: usize,
    const ROOTS: usize,
    const SHARE: usize,
> {
    slots: [Slot; N],
    generations: [u64; N],
    pid_index: [[u16; INODES]; PIDS],
    ofd_index: [u16; DESCRIPTIONS],
    inode_heads: [Option<Id>; INODES],
    inode_revisions: [u64; INODES],
    pid_heads: [PidHead; PIDS],
    used: [u16; ROOTS],
    fresh: u16,
    free: u16,
    available: u16,
}

impl<
    const N: usize,
    const INODES: usize,
    const PIDS: usize,
    const DESCRIPTIONS: usize,
    const ROOTS: usize,
    const SHARE: usize,
> Groups<N, INODES, PIDS, DESCRIPTIONS, ROOTS, SHARE>
{
    const fn check_dimensions() {
        assert!(N > 0 && N < NONE as usize);
        assert!(INODES > 0 && INODES <= NONE as usize);
        assert!(PIDS > 0 && PIDS <= PID_PLACES as usize);
        assert!(DESCRIPTIONS > 0 && DESCRIPTIONS <= NONE as usize);
        assert!(ROOTS > 0 && ROOTS <= NONE as usize);
        assert!(SHARE > 0 && SHARE <= N);
    }

    /// Initialize directly in the permanent allocation without a matrix copy.
    ///
    /// # Safety
    /// The destination covers aligned, writable, uninitialized Self storage,
    /// exclusively held by the caller until every field has been written.
    pub unsafe fn initialize_at(destination: *mut Self) {
        Self::check_dimensions();
        // SAFETY: field addresses lie within the caller's complete allocation.
        unsafe {
            let slots = core::ptr::addr_of_mut!((*destination).slots).cast::<Slot>();
            let generations = core::ptr::addr_of_mut!((*destination).generations).cast::<u64>();
            for index in 0..N {
                slots.add(index).write(Slot::Fresh);
                generations.add(index).write(0);
            }
            let index = core::ptr::addr_of_mut!((*destination).pid_index).cast::<u16>();
            for pid in 0..PIDS {
                for inode in 0..INODES {
                    index.add(pid * INODES + inode).write(NONE);
                }
            }
            let index = core::ptr::addr_of_mut!((*destination).ofd_index).cast::<u16>();
            for slot in 0..DESCRIPTIONS {
                index.add(slot).write(NONE);
            }
            let revisions = core::ptr::addr_of_mut!((*destination).inode_revisions).cast::<u64>();
            for inode in 0..INODES {
                revisions.add(inode).write(1);
            }
            let heads = core::ptr::addr_of_mut!((*destination).inode_heads).cast::<Option<Id>>();
            for inode in 0..INODES {
                heads.add(inode).write(None);
            }
            let heads = core::ptr::addr_of_mut!((*destination).pid_heads).cast::<PidHead>();
            for pid in 0..PIDS {
                heads.add(pid).write(PidHead::EMPTY);
            }
            let used = core::ptr::addr_of_mut!((*destination).used).cast::<u16>();
            for root in 0..ROOTS {
                used.add(root).write(0);
            }
            core::ptr::addr_of_mut!((*destination).fresh).write(0);
            core::ptr::addr_of_mut!((*destination).free).write(NONE);
            core::ptr::addr_of_mut!((*destination).available).write(N as u16);
        }
    }

    fn position(owner: Owner) -> Result<Position, Error> {
        match owner {
            Owner::Process(pid)
                if pid <= i32::MAX as u32
                    && pid / PID_PLACES != 0
                    && (pid % PID_PLACES) < PIDS as u32 =>
            {
                Ok(Position::Pid((pid % PID_PLACES) as usize))
            }
            Owner::Description { slot, generation }
                if generation != 0 && (slot as usize) < DESCRIPTIONS =>
            {
                Ok(Position::Description(slot as usize))
            }
            _ => Err(Error::Invalid),
        }
    }
    fn group(&self, id: Id) -> Result<&Group, Error> {
        if self.generations.get(id.slot()) != Some(&id.generation()) {
            return Err(Error::Invalid);
        }
        match self.slots.get(id.slot()) {
            Some(Slot::Paid(group)) => Ok(group),
            _ => Err(Error::Invalid),
        }
    }
    fn group_mut(&mut self, id: Id) -> Result<&mut Group, Error> {
        if self.generations.get(id.slot()) != Some(&id.generation()) {
            return Err(Error::Invalid);
        }
        match self.slots.get_mut(id.slot()) {
            Some(Slot::Paid(group)) => Ok(group),
            _ => Err(Error::Invalid),
        }
    }
    fn id_at(&self, slot: u16) -> Option<Id> {
        if slot == NONE {
            return None;
        }
        matches!(self.slots.get(slot as usize), Some(Slot::Paid(_))).then(|| Id {
            slot,
            generation: NonZeroU64::new(self.generations[slot as usize]).expect("paid generation"),
        })
    }
    fn owner_live(&self, owner: Owner) -> bool {
        match Self::position(owner) {
            Ok(Position::Pid(index)) => {
                matches!(owner, Owner::Process(pid) if self.pid_heads[index].live && self.pid_heads[index].pid == pid)
            }
            Ok(Position::Description(_)) => true,
            Err(_) => false,
        }
    }
    #[cfg(test)]
    pub(super) fn set_test_epoch(&mut self, id: Id, epoch: u64) {
        self.group_mut(id).expect("test paid group").snapshot.epoch = epoch;
    }

    pub fn valid(&self, capture: Capture) -> bool {
        self.group(capture.id).is_ok_and(|group| {
            group.active
                && group.snapshot.epoch == capture.epoch
                && self.owner_live(group.snapshot.owner)
        })
    }
    /// A paid exact identity can be absent from the live view after revocation.
    pub fn capture(&self, id: Id) -> Result<Option<Capture>, Error> {
        let group = self.group(id)?;
        let capture = Capture {
            id,
            epoch: group.snapshot.epoch,
        };
        Ok(self.valid(capture).then_some(capture))
    }

    /// Cleanup keeps the payer accessible through an exact revoked lifetime.
    pub fn retained_snapshot(&self, id: Id) -> Result<Snapshot, Error> {
        Ok(self.group(id)?.snapshot)
    }

    pub fn snapshot(&self, capture: Capture) -> Result<Snapshot, Error> {
        if !self.valid(capture) {
            return Err(Error::Invalid);
        }
        Ok(self.group(capture.id)?.snapshot)
    }
    pub fn lookup(&self, inode: Token, owner: Owner) -> Result<Option<Capture>, Error> {
        if inode.generation == 0 || inode.slot as usize >= INODES {
            return Err(Error::Invalid);
        }
        let slot = match Self::position(owner)? {
            Position::Pid(index) => self.pid_index[index][inode.slot as usize],
            Position::Description(index) => self.ofd_index[index],
        };
        let Some(id) = self.id_at(slot) else {
            return Ok(None);
        };
        let group = self.group(id)?;
        if group.snapshot.inode != inode || group.snapshot.owner != owner {
            return Ok(None);
        }
        let capture = Capture {
            id,
            epoch: group.snapshot.epoch,
        };
        Ok(self.valid(capture).then_some(capture))
    }
    pub fn used(&self, root: u16) -> Option<usize> {
        self.used.get(root as usize).map(|n| *n as usize)
    }
    pub fn available(&self) -> usize {
        self.available as usize
    }
    /// Never resets on inode reuse. Saturation disables optional snapshots only.
    pub fn inode_revision(&self, inode: Token) -> Option<u64> {
        if inode.generation == 0 {
            return None;
        }
        self.inode_revisions
            .get(usize::from(inode.slot))
            .copied()
            .filter(|revision| *revision != u64::MAX)
    }
    fn change_inode(&mut self, inode: Token) {
        let revision = &mut self.inode_revisions[usize::from(inode.slot)];
        *revision = revision.saturating_add(1);
    }
    /// Exact local visibility is additional to the genuine Process lifetime.
    pub fn pid_visible(&self, pid: u32) -> bool {
        let Ok(Position::Pid(index)) = Self::position(Owner::Process(pid)) else {
            return false;
        };
        self.pid_heads[index].pid == pid && self.pid_heads[index].live
    }
    #[cfg(test)]
    pub(super) fn inode_revisions_for_test(&self, inode: Token) -> u64 {
        self.inode_revisions[usize::from(inode.slot)]
    }
    #[cfg(test)]
    pub(super) fn set_test_inode_revision(&mut self, inode: Token, revision: u64) {
        self.inode_revisions[usize::from(inode.slot)] = revision;
    }
    pub fn inode_head(&self, inode: Token) -> Result<Option<Id>, Error> {
        if inode.generation == 0 || inode.slot as usize >= INODES {
            return Err(Error::Invalid);
        }
        let head = self.inode_heads[inode.slot as usize];
        Ok(head.filter(|id| {
            self.group(*id)
                .is_ok_and(|group| group.snapshot.inode == inode)
        }))
    }
    pub fn inode_next(&self, id: Id) -> Result<Option<Id>, Error> {
        Ok(self.group(id)?.inode_next)
    }
    pub fn pid_head(&self, pid: u32) -> Result<Option<Id>, Error> {
        let Position::Pid(index) = Self::position(Owner::Process(pid))? else {
            return Err(Error::Invalid);
        };
        let head = self.pid_heads[index];
        Ok((head.pid == pid && head.live)
            .then_some(head.head)
            .flatten())
    }
    /// One direct place for service-driven death observation, independent of credentials.
    /// One OFD place retains the exact live owner and inode for direct audits.
    pub fn tracked_description(&self, index: usize) -> Result<Option<Snapshot>, Error> {
        let slot = *self.ofd_index.get(index).ok_or(Error::Invalid)?;
        let Some(id) = self.id_at(slot) else {
            return Ok(None);
        };
        let group = self.group(id)?;
        Ok(group.active.then_some(group.snapshot))
    }
    pub fn tracked_pid(&self, index: usize) -> Result<Option<u32>, Error> {
        let head = self.pid_heads.get(index).ok_or(Error::Invalid)?;
        Ok((head.live && head.head.is_some()).then_some(head.pid))
    }
    /// Exclude the complete PID immediately and transfer its head once.
    /// The caller confirms death using the process service's lifetime page.
    pub fn depart_pid(&mut self, pid: u32) -> Result<Departure, Error> {
        let Position::Pid(index) = Self::position(Owner::Process(pid))? else {
            return Err(Error::Invalid);
        };
        let head = &mut self.pid_heads[index];
        let next = if head.pid == pid && head.live {
            head.live = false;
            head.head.take()
        } else {
            None
        };
        Ok(Departure { pid, next })
    }

    pub fn owner_next(&self, id: Id) -> Result<Option<Id>, Error> {
        Ok(self.group(id)?.owner_next)
    }

    /// Charge a fresh group before exposing either direct cell.
    pub fn allocate(&mut self, inode: Token, owner: Owner, root: u16) -> Result<Capture, Error> {
        let used = *self.used.get(root as usize).ok_or(Error::Invalid)?;
        if let Some(capture) = self.lookup(inode, owner)? {
            return Ok(capture);
        }
        let position = Self::position(owner)?;
        if self.inode_heads[inode.slot as usize].is_some_and(|id| {
            self.group(id)
                .is_ok_and(|group| group.snapshot.inode != inode)
        }) {
            return Err(Error::Invalid);
        }
        match position {
            Position::Pid(index) => {
                if let Owner::Process(pid) = owner {
                    let head = self.pid_heads[index];
                    if pid < head.pid
                        || (pid == head.pid && !head.live)
                        || (pid != head.pid && head.head.is_some())
                    {
                        return Err(Error::Invalid);
                    }
                }
                if self
                    .id_at(self.pid_index[index][inode.slot as usize])
                    .is_some_and(|id| {
                        self.group(id)
                            .is_ok_and(|g| g.active && self.owner_live(g.snapshot.owner))
                    })
                {
                    return Err(Error::Invalid);
                }
            }
            Position::Description(index) => {
                if self
                    .id_at(self.ofd_index[index])
                    .is_some_and(|id| self.group(id).is_ok_and(|g| g.active))
                {
                    return Err(Error::Invalid);
                }
            }
        }
        if used as usize >= SHARE || self.available == 0 {
            return Err(Error::NoLocks);
        }
        let slot = if self.free != NONE {
            let slot = self.free;
            let Slot::Free(next) = self.slots[slot as usize] else {
                unreachable!("vacant free head")
            };
            self.free = next;
            slot
        } else {
            assert!((self.fresh as usize) < N);
            let slot = self.fresh;
            self.fresh += 1;
            slot
        };
        let generation = self.generations[slot as usize]
            .checked_add(1)
            .expect("fresh group lifetime");
        self.generations[slot as usize] = generation;
        let id = Id {
            slot,
            generation: NonZeroU64::new(generation).expect("nonzero group lifetime"),
        };
        let inode_next = self.inode_heads[inode.slot as usize];
        let owner_next = match (position, owner) {
            (Position::Pid(index), Owner::Process(pid)) => {
                let head = &mut self.pid_heads[index];
                if head.pid != pid {
                    *head = PidHead {
                        pid,
                        live: true,
                        head: None,
                    };
                }
                head.live = true;
                head.head
            }
            _ => None,
        };
        self.change_inode(inode);
        self.slots[slot as usize] = Slot::Paid(Group {
            snapshot: Snapshot {
                inode,
                owner,
                root,
                epoch: 1,
            },
            active: true,
            inode_prev: None,
            inode_next,
            owner_prev: None,
            owner_next,
        });
        if let Some(next) = inode_next {
            self.group_mut(next)
                .expect("paid inode successor")
                .inode_prev = Some(id);
        }
        if let Some(next) = owner_next {
            self.group_mut(next)
                .expect("paid owner successor")
                .owner_prev = Some(id);
        }
        self.inode_heads[inode.slot as usize] = Some(id);
        match position {
            Position::Pid(index) => {
                self.pid_index[index][inode.slot as usize] = slot;
                self.pid_heads[index].head = Some(id);
            }
            Position::Description(index) => self.ofd_index[index] = slot,
        }
        self.used[root as usize] += 1;
        self.available -= 1;
        Ok(Capture { id, epoch: 1 })
    }
    /// Advance a group's preparation version before a metadata publication.
    pub fn advance(&mut self, capture: Capture) -> Result<Capture, Error> {
        if !self.valid(capture) {
            return Err(Error::Invalid);
        }
        let snapshot = self.group(capture.id)?.snapshot;
        let epoch = snapshot.epoch.checked_add(1).ok_or(Error::NoLocks)?;
        self.change_inode(snapshot.inode);
        let group = self.group_mut(capture.id)?;
        group.snapshot.epoch = epoch;
        Ok(Capture {
            id: capture.id,
            epoch: group.snapshot.epoch,
        })
    }
    /// Detach one inode/owner group with constant work before replying to close.
    pub fn revoke(&mut self, capture: Capture) -> Result<Snapshot, Error> {
        if !self.valid(capture) {
            return Err(Error::Invalid);
        }
        let group = *self.group(capture.id)?;
        self.detach(capture.id, group);
        Ok(group.snapshot)
    }
    fn detach(&mut self, id: Id, group: Group) {
        self.change_inode(group.snapshot.inode);
        let inode = group.snapshot.inode.slot as usize;
        if let Some(prev) = group.inode_prev {
            self.group_mut(prev)
                .expect("paid inode predecessor")
                .inode_next = group.inode_next;
        } else if self.inode_heads[inode] == Some(id) {
            self.inode_heads[inode] = group.inode_next;
        }
        if let Some(next) = group.inode_next {
            self.group_mut(next)
                .expect("paid inode successor")
                .inode_prev = group.inode_prev;
        }
        match Self::position(group.snapshot.owner).expect("validated owner") {
            Position::Pid(index) => {
                if self.pid_index[index][inode] == id.slot {
                    self.pid_index[index][inode] = NONE;
                }
                if let Some(prev) = group.owner_prev {
                    self.group_mut(prev)
                        .expect("paid owner predecessor")
                        .owner_next = group.owner_next;
                } else if self.pid_heads[index].head == Some(id) {
                    self.pid_heads[index].head = group.owner_next;
                }
                if let Some(next) = group.owner_next {
                    self.group_mut(next)
                        .expect("paid owner successor")
                        .owner_prev = group.owner_prev;
                }
            }
            Position::Description(index) => {
                if self.ofd_index[index] == id.slot {
                    self.ofd_index[index] = NONE;
                }
            }
        }
        let group = self.group_mut(id).expect("paid detached group");
        group.active = false;
        group.snapshot.epoch = group.snapshot.epoch.saturating_add(1);
    }
    /// Empty identity metadata can return its charge after revocation.
    /// The actor retains a group until all region and reader custody is done.
    pub fn release(&mut self, id: Id) -> Result<(), Error> {
        let group = *self.group(id)?;
        if group.active {
            return Err(Error::Invalid);
        }
        self.used[group.snapshot.root as usize] -= 1;
        if id.generation() == u64::MAX {
            self.slots[id.slot()] = Slot::Exhausted;
        } else {
            self.slots[id.slot()] = Slot::Free(self.free);
            self.free = id.slot;
            self.available += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;
    type Small = Groups<8, 4, 2, 4, 2, 4>;
    fn inode(slot: u16) -> Token {
        Token {
            slot,
            generation: 1,
        }
    }
    fn fresh<
        const N: usize,
        const I: usize,
        const P: usize,
        const D: usize,
        const R: usize,
        const S: usize,
    >() -> Box<Groups<N, I, P, D, R, S>> {
        let mut allocation = Box::<Groups<N, I, P, D, R, S>>::new_uninit();
        // SAFETY: the Box provides exclusive aligned complete uninitialized storage.
        unsafe {
            Groups::<N, I, P, D, R, S>::initialize_at(allocation.as_mut_ptr());
            allocation.assume_init()
        }
    }

    #[test]
    fn close_one_inode_preserves_the_same_pids_other_inode_and_other_owners() {
        let mut groups: Box<Small> = fresh();
        let a = groups.allocate(inode(0), Owner::Process(256), 0).unwrap();
        let b = groups.allocate(inode(1), Owner::Process(256), 0).unwrap();
        let other = groups.allocate(inode(0), Owner::Process(257), 1).unwrap();
        let ofd_owner = Owner::Description {
            slot: 0,
            generation: 7,
        };
        let ofd = groups.allocate(inode(0), ofd_owner, 1).unwrap();
        assert_eq!(groups.allocate(inode(0), Owner::Process(256), 1), Ok(a));
        assert_eq!(groups.used(0), Some(2));
        assert_eq!(groups.used(1), Some(2));
        assert_eq!(groups.pid_head(256), Ok(Some(b.id())));
        assert_eq!(groups.owner_next(b.id()), Ok(Some(a.id())));
        assert_eq!(groups.inode_head(inode(0)), Ok(Some(ofd.id())));
        assert_eq!(groups.inode_next(ofd.id()), Ok(Some(other.id())));
        assert_eq!(groups.revoke(a).unwrap().inode, inode(0));
        assert_eq!(groups.lookup(inode(0), Owner::Process(256)), Ok(None));
        for capture in [b, other, ofd] {
            assert!(groups.valid(capture));
        }
        assert_eq!(groups.lookup(inode(1), Owner::Process(256)), Ok(Some(b)));
        assert_eq!(groups.owner_next(b.id()), Ok(None));
        assert_eq!(groups.inode_next(other.id()), Ok(None));
        assert_eq!(groups.used(0), Some(2));
        groups.release(a.id()).unwrap();
        assert_eq!(groups.used(0), Some(1));
        assert_eq!(groups.release(a.id()), Err(Error::Invalid));
        assert_eq!(groups.revoke(a), Err(Error::Invalid));
    }

    #[test]
    fn publication_epoch_and_group_generation_reject_stale_authority() {
        let mut groups: Box<Groups<1, 2, 1, 1, 1, 1>> = fresh();
        let old = groups.allocate(inode(0), Owner::Process(256), 0).unwrap();
        let current = groups.advance(old).unwrap();
        assert!(!groups.valid(old));
        assert_eq!(groups.revoke(old), Err(Error::Invalid));
        assert!(groups.valid(current));
        groups.revoke(current).unwrap();
        groups.release(current.id()).unwrap();
        let next = groups.allocate(inode(0), Owner::Process(256), 0).unwrap();
        assert_eq!(old.id().slot(), next.id().slot());
        assert!(next.id().generation() > old.id().generation());
        assert!(!groups.valid(current));
        assert!(!groups.valid(old));
        assert_eq!(groups.revoke(old), Err(Error::Invalid));
        assert_eq!(groups.release(current.id()), Err(Error::Invalid));
        assert_eq!(groups.revoke(current), Err(Error::Invalid));
        assert!(groups.valid(next));
        assert_eq!(groups.used(0), Some(1));
    }

    #[test]
    fn quota_failure_leaves_indices_unchanged_and_revocation_stays_paid() {
        let mut groups: Box<Groups<3, 4, 2, 1, 2, 2>> = fresh();
        let a = groups.allocate(inode(0), Owner::Process(256), 0).unwrap();
        let b = groups.allocate(inode(1), Owner::Process(256), 0).unwrap();
        assert_eq!(
            groups.allocate(inode(2), Owner::Process(256), 0),
            Err(Error::NoLocks)
        );
        assert_eq!(groups.lookup(inode(2), Owner::Process(256)), Ok(None));
        assert_eq!(groups.pid_head(256), Ok(Some(b.id())));
        assert_eq!(groups.used(0), Some(2));
        let other = groups.allocate(inode(2), Owner::Process(257), 1).unwrap();
        assert_eq!(groups.available(), 0);
        groups.revoke(a).unwrap();
        assert_eq!(groups.available(), 0);
        assert_eq!(
            groups.allocate(inode(3), Owner::Process(257), 1),
            Err(Error::NoLocks)
        );
        groups.release(a.id()).unwrap();
        assert!(groups.allocate(inode(3), Owner::Process(257), 1).is_ok());
        assert!(groups.valid(b));
        assert!(groups.valid(other));
    }

    #[test]
    fn malformed_keys_and_mixed_inode_lifetimes_have_no_effect() {
        let mut groups: Box<Small> = fresh();
        for (node, owner, root) in [
            (
                Token {
                    slot: 0,
                    generation: 0,
                },
                Owner::Process(256),
                0,
            ),
            (inode(4), Owner::Process(256), 0),
            (inode(0), Owner::Process(0), 0),
            (inode(0), Owner::Process(u32::MAX), 0),
            (inode(0), Owner::Process(258), 0),
            (
                inode(0),
                Owner::Description {
                    slot: 4,
                    generation: 1,
                },
                0,
            ),
            (
                inode(0),
                Owner::Description {
                    slot: 0,
                    generation: 0,
                },
                0,
            ),
            (inode(0), Owner::Process(256), 2),
        ] {
            assert_eq!(groups.allocate(node, owner, root), Err(Error::Invalid));
        }
        assert_eq!(groups.available(), 8);
        assert_eq!(groups.used(0), Some(0));
        let old = groups.allocate(inode(0), Owner::Process(256), 0).unwrap();
        let later = Token {
            slot: 0,
            generation: 2,
        };
        assert_eq!(groups.inode_head(later), Ok(None));
        assert_eq!(groups.lookup(later, Owner::Process(256)), Ok(None));
        assert_eq!(
            groups.allocate(later, Owner::Process(257), 1),
            Err(Error::Invalid)
        );
        assert_eq!(groups.used(1), Some(0));
        assert!(groups.valid(old));
    }

    #[test]
    fn terminal_epoch_still_closes_and_terminal_generation_never_reuses() {
        let mut groups: Box<Groups<1, 1, 1, 1, 1, 1>> = fresh();
        groups.generations[0] = u64::MAX - 1;
        let capture = groups.allocate(inode(0), Owner::Process(256), 0).unwrap();
        assert_eq!(capture.id().generation(), u64::MAX);
        groups.group_mut(capture.id()).unwrap().snapshot.epoch = u64::MAX;
        let terminal = groups
            .lookup(inode(0), Owner::Process(256))
            .unwrap()
            .unwrap();
        assert_eq!(groups.advance(terminal), Err(Error::NoLocks));
        assert!(groups.valid(terminal));
        groups.revoke(terminal).unwrap();
        assert!(!groups.valid(terminal));
        groups.release(terminal.id()).unwrap();
        assert_eq!(groups.used(0), Some(0));
        assert_eq!(groups.available(), 0);
        assert_eq!(
            groups.allocate(inode(0), Owner::Process(256), 0),
            Err(Error::NoLocks)
        );
    }

    #[test]
    fn departure_excludes_all_pid_groups_before_cleanup_and_preserves_other_owners() {
        let mut groups: Box<Small> = fresh();
        let a = groups.allocate(inode(0), Owner::Process(256), 0).unwrap();
        let b = groups.allocate(inode(1), Owner::Process(256), 0).unwrap();
        let other = groups.allocate(inode(0), Owner::Process(257), 1).unwrap();
        let ofd = groups
            .allocate(
                inode(0),
                Owner::Description {
                    slot: 0,
                    generation: 1,
                },
                1,
            )
            .unwrap();
        let mut cursor = groups.depart_pid(256).unwrap();
        assert!(!cursor.done());
        assert!(!groups.valid(a));
        assert!(!groups.valid(b));
        assert_eq!(groups.lookup(inode(0), Owner::Process(256)), Ok(None));
        assert_eq!(groups.lookup(inode(1), Owner::Process(256)), Ok(None));
        assert!(groups.valid(other));
        assert!(groups.valid(ofd));
        assert_eq!(groups.used(0), Some(2));
        assert_eq!(groups.release(a.id()), Err(Error::Invalid));
        assert!(groups.depart_pid(256).unwrap().done());
        assert_eq!(cursor.step(&mut groups).unwrap().unwrap().0, b.id());
        assert!(!cursor.done());
        assert_eq!(groups.release(a.id()), Err(Error::Invalid));
        assert_eq!(groups.used(0), Some(2));
        groups.release(b.id()).unwrap();
        assert_eq!(groups.used(0), Some(1));
        assert_eq!(cursor.step(&mut groups).unwrap().unwrap().0, a.id());
        assert!(cursor.done());
        groups.release(a.id()).unwrap();
        assert_eq!(cursor.step(&mut groups), Ok(None));
        assert_eq!(groups.used(0), Some(0));
        assert!(groups.valid(other));
        assert!(groups.valid(ofd));
    }

    #[test]
    fn new_pid_generation_replaces_cells_before_old_cleanup_without_resurrection() {
        let mut groups: Box<Small> = fresh();
        let old = groups.allocate(inode(0), Owner::Process(256), 0).unwrap();
        let mut cursor = groups.depart_pid(256).unwrap();
        assert_eq!(
            groups.allocate(inode(1), Owner::Process(256), 0),
            Err(Error::Invalid)
        );
        let new = groups.allocate(inode(0), Owner::Process(512), 1).unwrap();
        assert!(groups.valid(new));
        assert!(!groups.valid(old));
        assert_eq!(
            groups.allocate(inode(1), Owner::Process(256), 0),
            Err(Error::Invalid)
        );
        assert!(groups.depart_pid(256).unwrap().done());
        assert_eq!(cursor.step(&mut groups).unwrap().unwrap().0, old.id());
        groups.release(old.id()).unwrap();
        assert_eq!(groups.lookup(inode(0), Owner::Process(512)), Ok(Some(new)));
        assert_eq!(groups.pid_head(512), Ok(Some(new.id())));
        assert_eq!(groups.owner_next(new.id()), Ok(None));
        assert_eq!(groups.inode_head(inode(0)), Ok(Some(new.id())));
        assert_eq!(groups.inode_next(new.id()), Ok(None));
        assert!(groups.valid(new));
    }

    #[test]
    fn departure_reclaims_one_group_per_step_and_retains_the_tail() {
        let mut groups: Box<Groups<12, 12, 1, 1, 1, 12>> = fresh();
        let mut ids = std::vec::Vec::new();
        for slot in 0..12 {
            ids.push(
                groups
                    .allocate(inode(slot), Owner::Process(256), 0)
                    .unwrap()
                    .id(),
            );
        }
        let mut cursor = groups.depart_pid(256).unwrap();
        for expected in ids.into_iter().rev() {
            let before = groups.used(0).unwrap();
            let (id, snapshot) = cursor.step(&mut groups).unwrap().unwrap();
            assert_eq!(id, expected);
            assert_eq!(snapshot.owner, Owner::Process(256));
            assert_eq!(groups.used(0), Some(before));
            let revoked = groups
                .slots
                .iter()
                .filter(|s| matches!(s, Slot::Paid(g) if !g.active))
                .count();
            assert_eq!(revoked, 1);
            groups.release(id).unwrap();
            assert_eq!(groups.used(0), Some(before - 1));
        }
        assert!(cursor.done());
        assert_eq!(groups.available(), 12);
    }

    #[test]
    fn production_matrix_initializes_in_its_allocation_and_checks_both_ends() {
        type Full =
            Groups<512, { crate::storage::NODES }, 256, 128, { crate::storage::ROOTS }, 256>;
        let mut groups: Box<Full> = fresh();
        assert!(groups.pid_index.iter().flatten().all(|cell| *cell == NONE));
        assert!(groups.ofd_index.iter().all(|cell| *cell == NONE));
        assert!(groups.used.iter().all(|used| *used == 0));
        let low = groups.allocate(inode(0), Owner::Process(256), 0).unwrap();
        let high = groups
            .allocate(
                inode((crate::storage::NODES - 1) as u16),
                Owner::Process(i32::MAX as u32),
                319,
            )
            .unwrap();
        assert_eq!(groups.lookup(inode(0), Owner::Process(256)), Ok(Some(low)));
        assert_eq!(
            groups.lookup(
                inode((crate::storage::NODES - 1) as u16),
                Owner::Process(i32::MAX as u32)
            ),
            Ok(Some(high))
        );
        groups.revoke(high).unwrap();
        groups.release(high.id()).unwrap();
        assert!(groups.valid(low));
        assert_eq!(groups.used(319), Some(0));
    }
}
