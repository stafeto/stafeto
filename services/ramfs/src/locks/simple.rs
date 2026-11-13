// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Bounded inode lists backed by pages paid by the exact creating root.

use super::{Kind, Lock, Owner, Range};
use crate::storage::{self, LockPage, Pin, Root, Storage, Token};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    NoLocks,
    Busy,
    Cancelled,
    Conflict(Lock),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Get(Kind),
    Set(Option<Kind>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub inode: Token,
    pub owner: Owner,
    pub root: u16,
    pub range: Range,
    pub command: Command,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response {
    Blocker(Option<Lock>),
    Changed,
}

pub const PER_INODE: usize = 64;
const SLOTS: usize = 64;
const BYTES: usize = 40;
const NONE: u32 = u32::MAX;
const NO_PAGE: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Head {
    generation: u64,
    first: u32,
    count: u8,
    revision: u64,
}
impl Head {
    const EMPTY: Self = Self {
        generation: 0,
        first: NONE,
        count: 0,
        revision: 0,
    };
}
struct Page {
    paid: Option<LockPage>,
    free: u64,
    previous: u16,
    next: u16,
}
impl Page {
    const EMPTY: Self = Self {
        paid: None,
        free: 0,
        previous: NO_PAGE,
        next: NO_PAGE,
    };
}
#[derive(Clone, Copy)]
struct Entry {
    lock: Lock,
    id: u32,
    next: u32,
}
// Unchanged records remain references into the old dispatch snapshot. A patch
// index selects a replacement body; payer identifies its exact original root.
#[derive(Clone, Copy)]
struct Work {
    id: u32,
    original: u8,
    payer: u8,
    patch: u8,
}
impl Work {
    #[inline(always)]
    fn lock<'a>(&self, old: &'a [Entry], patches: &'a [Lock]) -> &'a Lock {
        if self.patch == u8::MAX {
            &old[self.original as usize].lock
        } else {
            &patches[self.patch as usize]
        }
    }
    #[inline(always)]
    fn root(&self, table: &SimpleLocks, old: &[Entry], root: Root) -> Root {
        if self.payer == u8::MAX {
            root
        } else {
            table.page(old[self.payer as usize].id).root()
        }
    }
}
// Only the written prefix contains values. Unused capacity is never read,
// initialized or copied. No published storage points into this dispatch scratch.
struct Buffer<T: Copy, const N: usize> {
    values: [core::mem::MaybeUninit<T>; N],
    len: usize,
}
impl<T: Copy, const N: usize> Buffer<T, N> {
    fn new() -> Self {
        Self {
            values: [core::mem::MaybeUninit::uninit(); N],
            len: 0,
        }
    }
    #[inline(always)]
    fn push(&mut self, entry: T) {
        assert!(self.len < N);
        self.values[self.len].write(entry);
        self.len += 1;
    }
}
impl<T: Copy, const N: usize> core::ops::Deref for Buffer<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        // SAFETY: push initializes each prefix element before increasing len.
        unsafe { core::slice::from_raw_parts(self.values.as_ptr().cast::<T>(), self.len) }
    }
}
impl<T: Copy, const N: usize> core::ops::DerefMut for Buffer<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        // SAFETY: the initialized prefix belongs exclusively to this Buffer.
        unsafe { core::slice::from_raw_parts_mut(self.values.as_mut_ptr().cast::<T>(), self.len) }
    }
}

/// At most 64 blockers, independent of other files and expenditure roots.
pub struct Conflicts {
    values: [Option<Lock>; PER_INODE],
    count: usize,
}
impl Conflicts {
    pub fn iter(&self) -> impl Iterator<Item = Lock> + '_ {
        self.values[..self.count].iter().copied().flatten()
    }
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[derive(Default)]
pub struct SweepCursor {
    pub inode: usize,
    remaining: usize,
    /// The locks of the inode under the cursor already examined (they are kept) and the
    /// revision the list had then: a list changed by anyone else is examined again from its
    /// first lock.
    examined: usize,
    revision: u64,
    /// The times the inode under the cursor changed under the sweep and the examination began
    /// again: after `SWEEP_RESTARTS` the sweep goes on to the next inode and the next circle
    /// returns, so that traffic on one inode cannot hold the circle.
    restarts: usize,
}
impl SweepCursor {
    /// A new death owes a complete circle from the current physical position, and a list the
    /// sweep has half examined owes its first locks again: a death leaves the list as it was.
    pub fn restart(&mut self) {
        self.remaining = storage::NODES;
        self.examined = 0;
        self.restarts = 0;
    }
    /// Moves the cursor to the next inode: the place inside the inode ends. Tells whether the
    /// circle of the table wrapped.
    fn advance(&mut self) -> bool {
        self.examined = 0;
        self.restarts = 0;
        self.remaining -= 1;
        self.inode += 1;
        if self.inode == storage::NODES {
            self.inode = 0;
            return true;
        }
        false
    }
    /// Periodic polling never replenishes an unfinished circle.
    pub fn poll(&mut self) {
        if !self.pending() {
            self.restart();
        }
    }
    pub fn pending(&self) -> bool {
        self.remaining != 0
    }
    pub fn stop(&mut self) {
        self.remaining = 0;
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryDetails {
    pub blocker: Option<Lock>,
    pub owns_overlap: bool,
}
pub struct Sweep {
    pub visited: usize,
    pub removed: usize,
    /// The locks of the inodes the turn examined (an inode with none costs a few instructions).
    pub locks: usize,
    pub wrapped: bool,
}

/// Distinct owners that hold at least one lock record at the same time.
const OWNERS: usize = 2048;
/// The locks of one inode that a turn of the sweep examines.
pub const SWEEP_PIECE: usize = 16;
/// The times a list that others keep changing is examined again before the sweep leaves it for
/// the next circle.
pub const SWEEP_RESTARTS: usize = 2;

#[derive(Clone, Copy)]
struct Holder {
    owner: Option<Owner>,
    records: u32,
}
impl Holder {
    const EMPTY: Self = Self {
        owner: None,
        records: 0,
    };
}

/// Lock records per owner across all inodes: an open-addressed table with
/// backward-shift deletion, so lookups never see tombstones.
struct Holders {
    slots: [Holder; OWNERS],
    used: usize,
}
impl Holders {
    fn home(owner: Owner) -> usize {
        let key = match owner {
            Owner::Process(pid) => u64::from(pid),
            Owner::Description { slot, generation } => {
                generation.rotate_left(17) ^ u64::from(slot) ^ (1 << 63)
            }
        };
        (key.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40) as usize % OWNERS
    }
    fn find(&self, owner: Owner) -> Option<usize> {
        let mut at = Self::home(owner);
        for _ in 0..OWNERS {
            match self.slots[at].owner {
                None => return None,
                Some(found) if found == owner => return Some(at),
                Some(_) => at = (at + 1) % OWNERS,
            }
        }
        None
    }
    fn holds(&self, owner: Owner) -> bool {
        self.find(owner).is_some()
    }
    /// A new owner needs a free slot.
    fn admits(&self, owner: Owner) -> bool {
        self.used < OWNERS || self.holds(owner)
    }
    /// Returns true when the owner goes from no records to some.
    fn add(&mut self, owner: Owner, records: u32) -> bool {
        if let Some(at) = self.find(owner) {
            self.slots[at].records += records;
            return false;
        }
        let mut at = Self::home(owner);
        while self.slots[at].owner.is_some() {
            at = (at + 1) % OWNERS;
        }
        self.slots[at] = Holder {
            owner: Some(owner),
            records,
        };
        self.used += 1;
        true
    }
    fn sub(&mut self, owner: Owner, records: u32) {
        let at = self.find(owner).expect("counted owner");
        self.slots[at].records -= records;
        if self.slots[at].records != 0 {
            return;
        }
        let mut hole = at;
        let mut next = at;
        loop {
            next = (next + 1) % OWNERS;
            let Some(moved) = self.slots[next].owner else {
                break;
            };
            let home = Self::home(moved);
            // The entry may fill the hole only when its home is not inside the
            // cyclic interval (hole, next].
            let inside = if hole <= next {
                hole < home && home <= next
            } else {
                hole < home || home <= next
            };
            if !inside {
                self.slots[hole] = self.slots[next];
                hole = next;
            }
        }
        self.slots[hole] = Holder::EMPTY;
        self.used -= 1;
    }
}

pub struct SimpleLocks {
    heads: [Head; storage::NODES],
    pages: [Page; storage::PAGES],
    available: [u16; storage::ROOTS],
    holders: Holders,
    started: Option<Owner>,
    total: usize,
}
impl SimpleLocks {
    pub const fn new() -> Self {
        Self {
            heads: [Head::EMPTY; storage::NODES],
            pages: [const { Page::EMPTY }; storage::PAGES],
            available: [NO_PAGE; storage::ROOTS],
            holders: Holders {
                slots: [Holder::EMPTY; OWNERS],
                used: 0,
            },
            started: None,
            total: 0,
        }
    }
    /// Initialize permanent storage without putting the table on a guest stack.
    ///
    /// # Safety
    /// `destination` owns aligned writable uninitialized storage for Self.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: all destinations belong to the exclusive caller allocation.
        unsafe {
            core::ptr::addr_of_mut!((*destination).total).write(0);
            core::ptr::addr_of_mut!((*destination).started).write(None);
            core::ptr::addr_of_mut!((*destination).holders.used).write(0);
            let slots = core::ptr::addr_of_mut!((*destination).holders.slots).cast::<Holder>();
            for i in 0..OWNERS {
                slots.add(i).write(Holder::EMPTY);
            }
            let heads = core::ptr::addr_of_mut!((*destination).heads).cast::<Head>();
            for i in 0..storage::NODES {
                heads.add(i).write(Head::EMPTY);
            }
            let pages = core::ptr::addr_of_mut!((*destination).pages).cast::<Page>();
            for i in 0..storage::PAGES {
                pages.add(i).write(Page::EMPTY);
            }
            let available = core::ptr::addr_of_mut!((*destination).available).cast::<u16>();
            for i in 0..storage::ROOTS {
                available.add(i).write(NO_PAGE);
            }
        }
    }
    /// The records held in the whole table.
    pub fn total(&self) -> usize {
        self.total
    }
    pub fn has_locks(&self) -> bool {
        self.total != 0
    }
    /// Whether `owner` holds at least one lock record on any inode. O(1).
    pub fn holds(&self, owner: Owner) -> bool {
        self.holders.holds(owner)
    }
    /// The owner whose lock count went from zero to one since the last call.
    pub fn take_started(&mut self) -> Option<Owner> {
        self.started.take()
    }
    pub fn count(&self, inode: Token) -> usize {
        self.heads
            .get(inode.slot as usize)
            .filter(|head| head.generation == inode.generation)
            .map_or(0, |head| head.count as usize)
    }
    #[inline(always)]
    fn entries(
        &self,
        storage: &Storage<'_>,
        inode: Token,
        out: &mut Buffer<Entry, PER_INODE>,
    ) -> Result<(), Error> {
        storage.node(inode).map_err(|_| Error::Invalid)?;
        let head = self.heads[inode.slot as usize];
        if head.count != 0 && head.generation != inode.generation {
            return Err(Error::Invalid);
        }
        let mut id = head.first;
        for _ in 0..head.count {
            let (lock, next) = self.read(storage, id);
            out.push(Entry { lock, id, next });
            id = next;
        }
        assert_eq!(id, NONE);
        Ok(())
    }
    pub fn conflicts(
        &self,
        storage: &Storage<'_>,
        request: Request,
        mut live: impl FnMut(Owner) -> bool,
    ) -> Result<Conflicts, Error> {
        let kind = match request.command {
            Command::Get(kind) | Command::Set(Some(kind)) => kind,
            Command::Set(None) => {
                return Ok(Conflicts {
                    values: [None; PER_INODE],
                    count: 0,
                });
            }
        };
        let wanted = Lock {
            owner: request.owner,
            kind,
            range: request.range,
        };
        storage.node(request.inode).map_err(|_| Error::Invalid)?;
        let head = self.heads[request.inode.slot as usize];
        if head.count != 0 && head.generation != request.inode.generation {
            return Err(Error::Invalid);
        }
        let mut out = Conflicts {
            values: [None; PER_INODE],
            count: 0,
        };
        let mut id = head.first;
        for _ in 0..head.count {
            let (lock, next) = self.read(storage, id);
            id = next;
            if live(lock.owner) && lock.conflicts(wanted) {
                out.values[out.count] = Some(lock);
                out.count += 1;
            }
        }
        assert_eq!(id, NONE);
        Ok(out)
    }
    pub fn query(
        &self,
        storage: &Storage<'_>,
        request: Request,
        live: impl FnMut(Owner) -> bool,
    ) -> Result<Option<Lock>, Error> {
        self.query_details(storage, request, live)
            .map(|details| details.blocker)
    }
    pub fn query_details(
        &self,
        storage: &Storage<'_>,
        request: Request,
        mut live: impl FnMut(Owner) -> bool,
    ) -> Result<QueryDetails, Error> {
        let kind = match request.command {
            Command::Get(kind) | Command::Set(Some(kind)) => kind,
            Command::Set(None) => {
                return Ok(QueryDetails {
                    blocker: None,
                    owns_overlap: false,
                });
            }
        };
        storage.node(request.inode).map_err(|_| Error::Invalid)?;
        let head = self.heads[request.inode.slot as usize];
        if head.count != 0 && head.generation != request.inode.generation {
            return Err(Error::Invalid);
        }
        let wanted = Lock {
            owner: request.owner,
            kind,
            range: request.range,
        };
        let mut blocker: Option<Lock> = None;
        let mut owns_overlap = false;
        let mut id = head.first;
        for _ in 0..head.count {
            let (lock, next) = self.read(storage, id);
            id = next;
            if live(lock.owner) {
                owns_overlap |= lock.owner == request.owner && lock.range.overlaps(request.range);
                if lock.conflicts(wanted)
                    && blocker.is_none_or(|old| lock.range.first() < old.range.first())
                {
                    blocker = Some(lock);
                }
            }
        }
        assert_eq!(id, NONE);
        Ok(QueryDetails {
            blocker,
            owns_overlap,
        })
    }
    /// Preflight every new slot before changing any published record.
    pub fn set(
        &mut self,
        storage: &mut Storage<'_>,
        root: Root,
        request: Request,
        mut live: impl FnMut(Owner) -> bool,
    ) -> Result<(), Error> {
        let Command::Set(kind) = request.command else {
            return Err(Error::Invalid);
        };
        let mut old = Buffer::new();
        self.entries(storage, request.inode, &mut old)?;
        let count = old.len();
        let mut work: Buffer<Work, { PER_INODE + 2 }> = Buffer::new();
        let mut patches: Buffer<Lock, { PER_INODE + 2 }> = Buffer::new();
        // Work references never move after append. Only these entries can need
        // a reused or newly paid slot; unchanged records require neither scan.
        let mut unallocated: Buffer<u8, { PER_INODE + 2 }> = Buffer::new();
        let mut len = 0;
        let mut retained = 0u64;
        // Owners whose records are dropped as dead.
        let mut dead: Buffer<Owner, PER_INODE> = Buffer::new();
        let mut added = kind.map(|kind| Lock {
            owner: request.owner,
            kind,
            range: request.range,
        });
        for (index, entry) in old[..count].iter().enumerate() {
            let original = index as u8;
            if !live(entry.lock.owner) {
                if dead.len < SWEEP_PIECE {
                    dead.push(entry.lock.owner);
                } else {
                    // The rest of the dead records are left to the sweep: a request frees
                    // at most `SWEEP_PIECE` of them, so that its step stays bounded. They
                    // block nobody and stay in place.
                    work.push(Work {
                        id: entry.id,
                        original,
                        payer: original,
                        patch: u8::MAX,
                    });
                    retained |= 1u64 << original;
                    len += 1;
                }
                continue;
            }
            if let Some(kind) = kind
                && entry.lock.owner != request.owner
            {
                let wanted = Lock {
                    owner: request.owner,
                    kind,
                    range: request.range,
                };
                if entry.lock.conflicts(wanted) {
                    return Err(Error::Conflict(entry.lock));
                }
            }
            // A region already covered by this owner's identical kind is a
            // semantic no-op, irrespective of its position in the inode list.
            if kind == Some(entry.lock.kind)
                && entry.lock.owner == request.owner
                && entry.lock.range.first() <= request.range.first()
                && entry.lock.range.last() >= request.range.last()
            {
                return Ok(());
            }
            if entry.lock.owner != request.owner || !entry.lock.range.overlaps(request.range) {
                if let Some(lock) = added.as_mut()
                    && entry.lock.owner == lock.owner
                    && entry.lock.kind == lock.kind
                    && let Some(range) = lock.range.merge(entry.lock.range)
                {
                    lock.range = range;
                    continue;
                }
                work.push(Work {
                    id: entry.id,
                    original,
                    payer: original,
                    patch: u8::MAX,
                });
                retained |= 1u64 << original;
                len += 1;
                continue;
            }
            // Fully replaced regions have no fragments. Only the two interval
            // boundaries can need remainder bodies, regardless of list size.
            if request.range.first() <= entry.lock.range.first()
                && request.range.last() >= entry.lock.range.last()
            {
                continue;
            }
            for (edge, lock) in entry
                .lock
                .remainder(request.owner, request.range)
                .into_iter()
                .flatten()
                .enumerate()
            {
                if let Some(added) = added.as_mut()
                    && lock.kind == added.kind
                    && let Some(range) = added.range.merge(lock.range)
                {
                    added.range = range;
                    continue;
                }
                let patch = patches.len() as u8;
                patches.push(lock);
                if edge != 0 {
                    unallocated.push(len as u8);
                } else {
                    retained |= 1u64 << original;
                }
                work.push(Work {
                    id: if edge == 0 { entry.id } else { NONE },
                    original: if edge == 0 { original } else { u8::MAX },
                    payer: original,
                    patch,
                });
                len += 1;
            }
        }
        // Each owner's intervals are disjoint and same-kind touching regions
        // already coalesced. Removing the requested interval leaves at most one
        // touching boundary on each side; merging it cannot expose a previously
        // skipped neighbor. The single pass therefore needs no restart/scan.
        if let Some(added) = added {
            let patch = patches.len() as u8;
            patches.push(added);
            unallocated.push(len as u8);
            work.push(Work {
                id: NONE,
                original: u8::MAX,
                payer: u8::MAX,
                patch,
            });
            len += 1;
        }
        if len > PER_INODE {
            return Err(Error::NoLocks);
        }
        // Reuse unpublished old slots belonging to the same payer before
        // asking the page pool for capacity. Their bytes change only at commit.
        let all_old = if count == PER_INODE {
            u64::MAX
        } else {
            (1u64 << count) - 1
        };
        for &index in &unallocated[..] {
            let entry = &mut work[index as usize];
            if retained != all_old
                && let Some((index, previous)) =
                    old[..count].iter().enumerate().find(|(index, previous)| {
                        retained & (1u64 << index) == 0
                            && self.page(previous.id).root() == entry.root(self, &old, root)
                    })
            {
                entry.id = previous.id;
                entry.original = index as u8;
                retained |= 1u64 << index;
            }
        }
        // Only the requester's records change besides the dead ones dropped,
        // so the list length gives the requester's net change.
        let net = (len + dead.len()) as i64 - count as i64;
        if net > 0 && !self.holders.admits(request.owner) {
            return Err(Error::NoLocks);
        }
        let first_pin = count == 0 && len != 0;
        if first_pin {
            storage
                .pin(request.inode, Pin::Lock)
                .map_err(|_| Error::NoLocks)?;
        }
        let mut reserved: Buffer<u32, PER_INODE> = Buffer::new();
        for &index in &unallocated[..] {
            let entry = &mut work[index as usize];
            if entry.id != NONE {
                continue;
            }
            match self.allocate(storage, entry.root(self, &old, root)) {
                Ok(id) => {
                    entry.id = id;
                    reserved.push(id);
                }
                Err(error) => {
                    for &id in &reserved[..] {
                        self.free(storage, id);
                    }
                    if first_pin {
                        storage
                            .unpin(request.inode, Pin::Lock)
                            .expect("rollback inode pin");
                    }
                    return Err(error);
                }
            }
        }
        let mut changed = count != len || !reserved.is_empty();
        if retained != all_old {
            for (index, entry) in old[..count].iter().enumerate() {
                if retained & (1u64 << index) == 0 {
                    changed = true;
                    self.free(storage, entry.id);
                }
            }
        }
        for i in 0..len {
            let next = work
                .get(i + 1)
                .filter(|_| i + 1 < len)
                .map_or(NONE, |entry| entry.id);
            let entry = work[i];
            let unchanged = entry.patch == u8::MAX;
            if !unchanged {
                self.write(storage, entry.id, *entry.lock(&old, &patches), next);
                changed = true;
            } else if old[entry.original as usize].next != next {
                self.write_next(storage, entry.id, next);
                changed = true;
            }
        }
        changed |= self.heads[request.inode.slot as usize].first
            != if len == 0 { NONE } else { work[0].id };
        for &owner in &dead[..] {
            self.holders.sub(owner, 1);
        }
        if net > 0 {
            if self.holders.add(request.owner, net as u32) {
                self.started = Some(request.owner);
            }
        } else if net < 0 {
            self.holders.sub(request.owner, (-net) as u32);
        }
        self.total = self.total - count + len;
        self.heads[request.inode.slot as usize] = Head {
            generation: request.inode.generation,
            first: if len == 0 { NONE } else { work[0].id },
            count: len as u8,
            revision: self.heads[request.inode.slot as usize]
                .revision
                .checked_add(u64::from(changed))
                .expect("lock revision exhausted"),
        };
        if count != 0 && len == 0 {
            storage
                .unpin(request.inode, Pin::Lock)
                .expect("last inode lock");
        }
        Ok(())
    }
    pub fn revision(&self, inode: Token) -> u64 {
        let head = self.heads[inode.slot as usize];
        if head.generation == inode.generation {
            head.revision
        } else {
            0
        }
    }
    pub fn close(
        &mut self,
        storage: &mut Storage<'_>,
        inode: Token,
        owner: Owner,
    ) -> Result<bool, Error> {
        self.close_owners(storage, inode, Some(owner), None)
    }
    pub fn close_owners(
        &mut self,
        storage: &mut Storage<'_>,
        inode: Token,
        first: Option<Owner>,
        second: Option<Owner>,
    ) -> Result<bool, Error> {
        if first.is_none() && second.is_none() {
            return Ok(false);
        }
        self.remove(storage, inode, |lock| {
            Some(lock.owner) == first || Some(lock.owner) == second
        })
    }
    fn remove(
        &mut self,
        storage: &mut Storage<'_>,
        inode: Token,
        remove: impl FnMut(Lock) -> bool,
    ) -> Result<bool, Error> {
        self.remove_window(storage, inode, 0..PER_INODE, remove)
    }
    /// Removes the locks of the inode that `remove` selects among those at the places of
    /// `window` in the list; the others stay without being asked about.
    fn remove_window(
        &mut self,
        storage: &mut Storage<'_>,
        inode: Token,
        window: core::ops::Range<usize>,
        mut remove: impl FnMut(Lock) -> bool,
    ) -> Result<bool, Error> {
        let mut old = Buffer::new();
        self.entries(storage, inode, &mut old)?;
        let count = old.len();
        let mut kept: Buffer<Entry, PER_INODE> = Buffer::new();
        let mut len = 0;
        for (place, entry) in old[..count].iter().enumerate() {
            if window.contains(&place) && remove(entry.lock) {
                self.holders.sub(entry.lock.owner, 1);
                self.free(storage, entry.id);
            } else {
                kept.push(*entry);
                len += 1;
            }
        }
        for i in 0..len {
            let next = if i + 1 < len { kept[i + 1].id } else { NONE };
            if kept[i].next != next {
                self.write_next(storage, kept[i].id, next);
            }
        }
        self.total = self.total - count + len;
        self.heads[inode.slot as usize] = Head {
            generation: inode.generation,
            first: if len == 0 { NONE } else { kept[0].id },
            count: len as u8,
            revision: self.heads[inode.slot as usize]
                .revision
                .checked_add(u64::from(count != len))
                .expect("lock revision exhausted"),
        };
        if count != 0 && len == 0 {
            storage.unpin(inode, Pin::Lock).expect("last inode lock");
        }
        Ok(count != len)
    }
    /// Each turn visits a caller-bounded number of inode lists.
    pub fn sweep(
        &mut self,
        storage: &mut Storage<'_>,
        cursor: &mut SweepCursor,
        max_inodes: usize,
        mut live: impl FnMut(Owner) -> bool,
    ) -> Sweep {
        let mut result = Sweep {
            visited: 0,
            removed: 0,
            locks: 0,
            wrapped: false,
        };
        for _ in 0..max_inodes.min(cursor.remaining) {
            let slot = cursor.inode;
            let head = self.heads[slot];
            if head.count != 0 {
                result.locks += head.count as usize;
                let token = Token {
                    slot: slot as u16,
                    generation: head.generation,
                };
                self.remove(storage, token, |lock| !live(lock.owner))
                    .expect("pinned sweep inode");
                result.removed += head.count as usize - self.heads[slot].count as usize;
            }
            result.visited += 1;
            result.wrapped |= cursor.advance();
        }
        result
    }
    /// Examines the inode under the cursor, at most `limit` locks of it, and moves the cursor
    /// on only when the whole list has been examined: a list of 64 locks takes several turns,
    /// so that no turn costs more than `limit` locks and the removals among them.
    fn sweep_piece(
        &mut self,
        storage: &mut Storage<'_>,
        cursor: &mut SweepCursor,
        limit: usize,
        mut live: impl FnMut(Owner) -> bool,
    ) -> Sweep {
        let slot = cursor.inode;
        let head = self.heads[slot];
        if head.count as usize <= limit {
            cursor.examined = 0;
            return self.sweep(storage, cursor, 1, live);
        }
        if cursor.examined >= head.count as usize
            || (cursor.examined != 0 && cursor.revision != head.revision)
        {
            // Another request changed the list under the sweep: the examination begins again,
            // and begins again only a bounded number of times.
            cursor.examined = 0;
            cursor.restarts += 1;
            if cursor.restarts > SWEEP_RESTARTS {
                return Sweep {
                    visited: 1,
                    removed: 0,
                    locks: 0,
                    wrapped: cursor.advance(),
                };
            }
        }
        let from = cursor.examined;
        let to = (from + limit).min(head.count as usize);
        let token = Token {
            slot: slot as u16,
            generation: head.generation,
        };
        self.remove_window(storage, token, from..to, |lock| !live(lock.owner))
            .expect("pinned sweep inode");
        let after = self.heads[slot];
        let removed = head.count as usize - after.count as usize;
        let mut result = Sweep {
            visited: 0,
            removed,
            locks: to - from,
            wrapped: false,
        };
        if to >= head.count as usize {
            result.visited = 1;
            result.wrapped = cursor.advance();
        } else {
            cursor.examined = to - removed;
            cursor.revision = after.revision;
        }
        result
    }
    /// One maintenance turn of the circle: it passes up to `max_empty`
    /// inodes without locks, which cost a few instructions each, and ends
    /// after the first inode that holds locks. A turn per inode would spend
    /// a whole round of maintenance on each empty one and keep the service
    /// busy for most of the period that restarts the circle.
    pub fn sweep_run(
        &mut self,
        storage: &mut Storage<'_>,
        cursor: &mut SweepCursor,
        max_empty: usize,
        mut live: impl FnMut(Owner) -> bool,
    ) -> Sweep {
        let mut total = Sweep {
            visited: 0,
            removed: 0,
            locks: 0,
            wrapped: false,
        };
        // A place with no node holds no lock and is passed by a few instructions, without a
        // call; it counts as an inode without locks, so a turn is as long as it was before the
        // layers (the maintenance step stays under B).
        let mut spent = 0;
        while cursor.pending() {
            let held = self.heads[cursor.inode].count != 0;
            let free = storage.state.nodes[cursor.inode].kind == 0 && !held;
            if free {
                // A place with no node holds no lock: it is passed without a call.
                total.wrapped |= cursor.advance();
                total.visited += 1;
                spent += 1;
                if spent >= max_empty {
                    break;
                }
                continue;
            }
            let step = self.sweep_piece(storage, cursor, SWEEP_PIECE, &mut live);
            total.visited += step.visited;
            total.removed += step.removed;
            total.locks += step.locks;
            total.wrapped |= step.wrapped;
            spent += 1;
            if held || spent >= max_empty {
                break;
            }
        }
        total
    }
    fn page(&self, id: u32) -> &LockPage {
        self.pages[id as usize / SLOTS]
            .paid
            .as_ref()
            .expect("allocated lock slot")
    }
    fn unlink_available(&mut self, physical: u16) {
        let page = &self.pages[physical as usize];
        let payer = page.paid.as_ref().unwrap().payer() as usize;
        let (previous, next) = (page.previous, page.next);
        if previous == NO_PAGE {
            self.available[payer] = next;
        } else {
            self.pages[previous as usize].next = next;
        }
        if next != NO_PAGE {
            self.pages[next as usize].previous = previous;
        }
        self.pages[physical as usize].previous = NO_PAGE;
        self.pages[physical as usize].next = NO_PAGE;
    }
    fn link_available(&mut self, physical: u16) {
        let payer = self.pages[physical as usize].paid.as_ref().unwrap().payer() as usize;
        let next = self.available[payer];
        self.pages[physical as usize].next = next;
        self.pages[physical as usize].previous = NO_PAGE;
        if next != NO_PAGE {
            self.pages[next as usize].previous = physical;
        }
        self.available[payer] = physical;
    }
    fn allocate(&mut self, storage: &mut Storage<'_>, root: Root) -> Result<u32, Error> {
        let anchor = storage.lock_anchor(root).map_err(|_| Error::NoLocks)?;
        let payer = anchor.index() as usize;
        let mut physical = self.available[payer];
        storage
            .release_lock_anchor(anchor)
            .expect("temporary lookup anchor");
        if physical == NO_PAGE {
            let paid = storage
                .allocate_lock_page(root)
                .map_err(|_| Error::NoLocks)?;
            physical = paid.physical();
            self.pages[physical as usize] = Page {
                paid: Some(paid),
                free: u64::MAX,
                previous: NO_PAGE,
                next: NO_PAGE,
            };
            self.link_available(physical);
        }
        let page = &mut self.pages[physical as usize];
        let slot = page.free.trailing_zeros();
        assert!(slot < SLOTS as u32);
        page.free &= !(1u64 << slot);
        if page.free == 0 {
            self.unlink_available(physical);
        }
        Ok(u32::from(physical) * SLOTS as u32 + slot)
    }
    fn free(&mut self, storage: &mut Storage<'_>, id: u32) {
        let physical = (id as usize / SLOTS) as u16;
        let bit = 1u64 << (id as usize % SLOTS);
        let was_full = self.pages[physical as usize].free == 0;
        assert_eq!(self.pages[physical as usize].free & bit, 0);
        self.pages[physical as usize].free |= bit;
        if was_full {
            self.link_available(physical);
        }
        if self.pages[physical as usize].free == u64::MAX {
            self.unlink_available(physical);
            let page = self.pages[physical as usize].paid.take().unwrap();
            storage.release_lock_page(page);
            // take already cleared paid. Reset only the remaining live fields;
            // no full-page metadata copy is needed for its now-free slot.
            let empty = &mut self.pages[physical as usize];
            empty.free = 0;
            empty.previous = NO_PAGE;
            empty.next = NO_PAGE;
        }
    }
    #[inline(always)]
    fn read(&self, storage: &Storage<'_>, id: u32) -> (Lock, u32) {
        let words = storage.lock_page_words(self.page(id), id as usize % SLOTS * BYTES);
        let owner = match (words[3] >> 32) & 255 {
            1 => Owner::Process(words[3] as u32),
            2 => Owner::Description {
                slot: words[3] as u16,
                generation: words[2],
            },
            _ => panic!("invalid stored lock owner"),
        };
        (
            Lock {
                owner,
                kind: if (words[3] >> 40) & 255 == 0 {
                    Kind::Read
                } else {
                    Kind::Write
                },
                range: Range {
                    first: words[0],
                    last: words[1],
                },
            },
            words[4] as u32,
        )
    }
    fn write_next(&self, storage: &mut Storage<'_>, id: u32, next: u32) {
        storage.lock_page_write(
            self.page(id),
            id as usize % SLOTS * BYTES + 32,
            &next.to_le_bytes(),
        );
    }
    fn write(&self, storage: &mut Storage<'_>, id: u32, lock: Lock, next: u32) {
        let mut bytes = [0u8; BYTES];
        bytes[..8].copy_from_slice(&lock.range.first().to_le_bytes());
        bytes[8..16].copy_from_slice(&lock.range.last().to_le_bytes());
        match lock.owner {
            Owner::Process(pid) => {
                bytes[28] = 1;
                bytes[24..28].copy_from_slice(&pid.to_le_bytes());
            }
            Owner::Description { slot, generation } => {
                bytes[28] = 2;
                bytes[16..24].copy_from_slice(&generation.to_le_bytes());
                bytes[24..28].copy_from_slice(&u32::from(slot).to_le_bytes());
            }
        }
        bytes[29] = u8::from(lock.kind == Kind::Write);
        bytes[32..36].copy_from_slice(&next.to_le_bytes());
        storage.lock_page_write(self.page(id), id as usize % SLOTS * BYTES, &bytes);
    }
}
impl Default for SimpleLocks {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{boxed::Box, vec::Vec};

    fn fresh() -> Box<SimpleLocks> {
        let mut table = Box::<SimpleLocks>::new_uninit();
        // SAFETY: this Box exclusively owns aligned uninitialized table storage.
        unsafe {
            SimpleLocks::initialize_at(table.as_mut_ptr());
            table.assume_init()
        }
    }
    fn inode(ram: &mut crate::Ram<'_>, name: &[u8]) -> Token {
        let reservation = ram
            .storage
            .reserve(
                storage::BOOT_ROOT,
                storage::ROOT,
                name,
                (crate::REG, 0o600, 0, 0),
            )
            .unwrap();
        ram.storage.commit(reservation).unwrap()
    }
    fn request(inode: Token, owner: Owner, first: i64, length: i64, kind: Option<Kind>) -> Request {
        Request {
            inode,
            owner,
            root: 0,
            range: Range::relative(0, first, length).unwrap(),
            command: Command::Set(kind),
        }
    }
    fn payer(id: u64) -> Root {
        Root { id, generation: 7 }
    }

    #[test]
    fn death_mid_sweep_revisits_earlier_inodes_and_releases_every_paid_pin() {
        let mut ram = crate::Ram::default();
        let a = inode(&mut ram, b"sweep-a");
        let b = inode(&mut ram, b"sweep-b");
        let [low, high] = if a.slot < b.slot { [a, b] } else { [b, a] };
        let mut table = fresh();
        let owner = Owner::Process(256);
        for file in [low, high] {
            table
                .set(
                    &mut ram.storage,
                    payer(1),
                    request(file, owner, 0, 1, Some(Kind::Write)),
                    |_| true,
                )
                .unwrap();
        }
        let mut cursor = SweepCursor::default();
        cursor.restart();
        let passed = table.sweep(&mut ram.storage, &mut cursor, low.slot as usize + 1, |_| {
            true
        });
        assert_eq!(passed.removed, 0);
        assert_eq!(cursor.inode, low.slot as usize + 1);
        // The owner dies after its lower inode was already visited.
        cursor.restart();
        let mut visited = 0;
        let mut removed = 0;
        while cursor.pending() {
            let result = table.sweep(&mut ram.storage, &mut cursor, 1, |_| false);
            assert_eq!(result.visited, 1);
            visited += result.visited;
            removed += result.removed;
            assert!(visited <= storage::NODES);
        }
        assert_eq!(visited, storage::NODES);
        assert_eq!(removed, 2);
        for file in [low, high] {
            assert_eq!(table.count(file), 0);
            assert_eq!(
                ram.storage.node(file).unwrap().pins,
                [0; storage::PIN_KINDS]
            );
        }
        assert_eq!(ram.storage.usage(payer(1)), storage::Usage::default());
    }

    #[test]
    fn a_circle_of_runs_passes_empty_inodes_in_bulk_and_ends_after_each_held_one() {
        let mut ram = crate::Ram::default();
        let a = inode(&mut ram, b"run-a");
        let b = inode(&mut ram, b"run-b");
        let mut table = fresh();
        let owner = Owner::Process(256);
        for file in [a, b] {
            table
                .set(
                    &mut ram.storage,
                    payer(1),
                    request(file, owner, 0, 1, Some(Kind::Write)),
                    |_| true,
                )
                .unwrap();
        }
        let mut cursor = SweepCursor::default();
        cursor.restart();
        let (mut turns, mut visited, mut removed) = (0, 0, 0);
        while cursor.pending() {
            let before = cursor.inode;
            let held: std::vec::Vec<usize> = [a, b]
                .into_iter()
                .filter(|file| table.count(*file) != 0)
                .map(|file| usize::from(file.slot))
                .collect();
            let result = table.sweep_run(&mut ram.storage, &mut cursor, 64, |_| false);
            assert!(result.visited >= 1 && result.visited <= 64);
            // A turn that met a held inode ends on it: it is the last the
            // turn visited.
            let last = (before + result.visited - 1) % storage::NODES;
            let met: std::vec::Vec<usize> = (0..result.visited)
                .map(|k| (before + k) % storage::NODES)
                .filter(|inode| held.contains(inode))
                .collect();
            assert!(
                met.is_empty() || met == [last],
                "turn from {before} visited {}, met {met:?}",
                result.visited
            );
            turns += 1;
            visited += result.visited;
            removed += result.removed;
            assert!(turns <= storage::NODES);
        }
        assert_eq!(visited, storage::NODES);
        assert_eq!(removed, 2);
        // Two held inodes and the empty ones in runs of at most 64.
        assert!(turns <= 2 + storage::NODES / 64 + 2, "{turns}");
        assert_eq!(table.count(a) + table.count(b), 0);
    }

    fn fill(ram: &mut crate::Ram<'_>, table: &mut SimpleLocks, file: Token) {
        for i in 0..PER_INODE as u32 {
            table
                .set(
                    &mut ram.storage,
                    payer(1),
                    request(
                        file,
                        Owner::Process(256 + i),
                        i64::from(i) * 3,
                        1,
                        Some(Kind::Read),
                    ),
                    |_| true,
                )
                .unwrap();
        }
        assert_eq!(table.count(file), PER_INODE);
    }

    #[test]
    fn a_full_inode_is_swept_in_pieces_and_every_dead_lock_goes() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let file = inode(&mut ram, b"pieces");
        let mut table = fresh();
        fill(&mut ram, &mut table, file);
        let mut cursor = SweepCursor::default();
        cursor.restart();
        let (mut turns_on_file, mut removed) = (0, 0);
        let mut turns = 0;
        while cursor.pending() {
            let on_file = cursor.inode == usize::from(file.slot);
            let result = table.sweep_run(
                &mut ram.storage,
                &mut cursor,
                64,
                |owner| matches!(owner, Owner::Process(pid) if pid % 2 == 0),
            );
            assert!(result.locks <= SWEEP_PIECE, "{}", result.locks);
            if on_file && result.locks != 0 {
                turns_on_file += 1;
            }
            removed += result.removed;
            turns += 1;
            assert!(turns < 4 * storage::NODES);
        }
        // The removed locks shorten the list, so the four pieces of 64 may take only three.
        assert!((3..=PER_INODE / SWEEP_PIECE).contains(&turns_on_file));
        assert_eq!(removed, PER_INODE / 2);
        assert_eq!(table.count(file), PER_INODE / 2);
    }

    #[test]
    fn a_list_changed_between_pieces_is_examined_again_from_its_first_lock() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let file = inode(&mut ram, b"changed");
        let mut table = fresh();
        fill(&mut ram, &mut table, file);
        let mut cursor = SweepCursor::default();
        cursor.restart();
        while cursor.inode != usize::from(file.slot) {
            table.sweep_run(&mut ram.storage, &mut cursor, 64, |_| true);
        }
        // One piece finds everybody alive; then another request takes the first lock away.
        let first = table.sweep_run(&mut ram.storage, &mut cursor, 64, |_| true);
        assert_eq!((first.locks, first.removed), (SWEEP_PIECE, 0));
        table
            .close(&mut ram.storage, file, Owner::Process(256))
            .unwrap();
        // Now all are dead: no lock may stay behind a piece that was skipped.
        let mut turns = 0;
        while table.count(file) != 0 {
            table.sweep_run(&mut ram.storage, &mut cursor, 64, |_| false);
            turns += 1;
            assert!(turns <= PER_INODE, "{} locks left", table.count(file));
        }
    }

    fn at_inode(
        table: &mut SimpleLocks,
        ram: &mut crate::Ram<'_>,
        cursor: &mut SweepCursor,
        file: Token,
    ) {
        while cursor.inode != usize::from(file.slot) {
            table.sweep_run(&mut ram.storage, cursor, 64, |_| true);
        }
    }

    #[test]
    fn a_death_in_the_middle_of_an_inode_owes_its_first_locks_again() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let file = inode(&mut ram, b"death");
        let mut table = fresh();
        fill(&mut ram, &mut table, file);
        let mut cursor = SweepCursor::default();
        cursor.restart();
        at_inode(&mut table, &mut ram, &mut cursor, file);
        // One piece while everybody lives; then every owner dies, which changes no list.
        let first = table.sweep_run(&mut ram.storage, &mut cursor, 64, |_| true);
        assert_eq!((first.locks, first.removed), (SWEEP_PIECE, 0));
        cursor.restart();
        let mut turns = 0;
        while cursor.pending() {
            table.sweep_run(&mut ram.storage, &mut cursor, 64, |_| false);
            turns += 1;
            assert!(turns < 4 * storage::NODES);
        }
        assert_eq!(table.count(file), 0);
    }

    #[test]
    fn the_place_inside_an_inode_ends_where_the_cursor_moves_on() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut table = fresh();
        let free = (0..storage::NODES - 1)
            .find(|slot| ram.storage.state.nodes[*slot].kind == 0)
            .unwrap();
        let mut cursor = SweepCursor::default();
        cursor.restart();
        cursor.inode = free;
        cursor.examined = 7;
        cursor.revision = 3;
        cursor.restarts = 1;
        // A place with no node is passed with one step of the run.
        let turn = table.sweep_run(&mut ram.storage, &mut cursor, 1, |_| true);
        assert_eq!((turn.visited, cursor.inode), (1, free + 1));
        assert_eq!((cursor.examined, cursor.restarts), (0, 0));
    }

    #[test]
    fn traffic_on_one_inode_cannot_hold_the_circle() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let file = inode(&mut ram, b"busy");
        let mut table = fresh();
        for i in 0..PER_INODE as u32 - 2 {
            table
                .set(
                    &mut ram.storage,
                    payer(1),
                    request(
                        file,
                        Owner::Process(256 + i),
                        i64::from(i) * 3,
                        1,
                        Some(Kind::Read),
                    ),
                    |_| true,
                )
                .unwrap();
        }
        let mut cursor = SweepCursor::default();
        cursor.restart();
        at_inode(&mut table, &mut ram, &mut cursor, file);
        let stranger = Owner::Process(9_999);
        let mut turns = 0;
        while cursor.inode == usize::from(file.slot) {
            // A piece of the sweep; then another request changes the list.
            table.sweep_run(&mut ram.storage, &mut cursor, 64, |_| true);
            table
                .set(
                    &mut ram.storage,
                    payer(1),
                    request(file, stranger, 1_000, 1, Some(Kind::Read)),
                    |_| true,
                )
                .unwrap();
            table.close(&mut ram.storage, file, stranger).unwrap();
            turns += 1;
            assert!(turns <= 4 * (SWEEP_RESTARTS + 1), "the circle is held");
        }
    }

    #[test]
    fn a_request_frees_at_most_one_piece_of_dead_records_and_the_sweep_takes_the_rest() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let file = inode(&mut ram, b"dead-set");
        let mut table = fresh();
        fill(&mut ram, &mut table, file);
        let stranger = Owner::Process(9_999);
        table
            .set(
                &mut ram.storage,
                payer(1),
                request(file, stranger, 1_000, 1, Some(Kind::Write)),
                |owner| owner == stranger,
            )
            .unwrap();
        // 64 records were dead: 16 went, 48 stay beside the new one.
        assert_eq!(table.count(file), PER_INODE - SWEEP_PIECE + 1);
        // The dead records block nobody and the sweep takes them.
        let mut cursor = SweepCursor::default();
        cursor.restart();
        let mut turns = 0;
        while cursor.pending() {
            table.sweep_run(&mut ram.storage, &mut cursor, 64, |owner| owner == stranger);
            turns += 1;
            assert!(turns < 4 * storage::NODES);
        }
        assert_eq!(table.count(file), 1);
    }

    #[test]
    fn the_piece_of_the_sweep_is_a_part_of_an_inode() {
        const { assert!(SWEEP_RESTARTS >= 1 && SWEEP_RESTARTS < 8) };
        const {
            assert!(
                SWEEP_PIECE > 0 && SWEEP_PIECE < PER_INODE && PER_INODE.is_multiple_of(SWEEP_PIECE)
            )
        };
        assert_eq!((SWEEP_PIECE, SWEEP_RESTARTS), (16, 2));
    }

    #[test]
    fn periodic_poll_preserves_debt_but_a_new_death_restarts_one_circle() {
        let mut ram = crate::Ram::default();
        let mut table = fresh();
        let mut cursor = SweepCursor::default();
        assert_eq!(
            table
                .sweep(&mut ram.storage, &mut cursor, 1, |_| true)
                .visited,
            0
        );
        cursor.poll();
        table.sweep(&mut ram.storage, &mut cursor, 3, |_| true);
        let position = cursor.inode;
        assert_eq!(cursor.remaining, storage::NODES - 3);
        cursor.poll();
        assert_eq!(cursor.remaining, storage::NODES - 3);
        cursor.restart();
        assert_eq!(cursor.remaining, storage::NODES);
        assert_eq!(cursor.inode, position);
        cursor.stop();
        assert!(!cursor.pending());
        cursor.poll();
        assert_eq!(cursor.remaining, storage::NODES);
    }

    #[test]
    fn query_details_requires_live_same_owner_overlap_and_retains_foreign_blocker() {
        let mut ram = crate::Ram::default();
        let file = inode(&mut ram, b"query-holder");
        let mut table = fresh();
        for (pid, first) in [(256, 0), (257, 3)] {
            table
                .set(
                    &mut ram.storage,
                    payer(1),
                    request(file, Owner::Process(pid), first, 2, Some(Kind::Read)),
                    |_| true,
                )
                .unwrap();
        }
        let asked = request(file, Owner::Process(256), 1, 4, Some(Kind::Write));
        let details = table.query_details(&ram.storage, asked, |_| true).unwrap();
        assert!(details.owns_overlap);
        assert_eq!(details.blocker.unwrap().owner, Owner::Process(257));
        assert!(
            !table
                .query_details(&ram.storage, asked, |owner| owner != Owner::Process(256))
                .unwrap()
                .owns_overlap
        );
        let disjoint = request(file, Owner::Process(256), 10, 1, Some(Kind::Write));
        assert!(
            !table
                .query_details(&ram.storage, disjoint, |_| true)
                .unwrap()
                .owns_overlap
        );
    }

    #[test]
    fn coalescing_both_boundaries_is_independent_of_inode_list_order() {
        for positions in [[0, 20], [20, 0]] {
            let mut ram = crate::Ram::default();
            let file = inode(&mut ram, b"coalesce-order");
            let mut table = fresh();
            for first in positions {
                table
                    .set(
                        &mut ram.storage,
                        payer(1),
                        request(file, Owner::Process(257), first, 10, Some(Kind::Write)),
                        |_| true,
                    )
                    .unwrap();
            }
            table
                .set(
                    &mut ram.storage,
                    payer(2),
                    request(file, Owner::Process(258), 100, 1, Some(Kind::Read)),
                    |_| true,
                )
                .unwrap();
            table
                .set(
                    &mut ram.storage,
                    payer(3),
                    request(file, Owner::Process(257), 10, 10, Some(Kind::Write)),
                    |_| true,
                )
                .unwrap();
            assert_eq!(table.count(file), 2);
            let blocker = table
                .query(
                    &ram.storage,
                    request(file, Owner::Process(259), 15, 1, Some(Kind::Write)),
                    |_| true,
                )
                .unwrap()
                .unwrap();
            assert_eq!(blocker.range, Range::relative(0, 0, 30).unwrap());
            assert_eq!(ram.storage.usage(payer(1)), storage::Usage::default());
            assert_eq!(ram.storage.usage(payer(2)).pages, 1);
            assert_eq!(ram.storage.usage(payer(3)).pages, 1);
        }
    }

    #[test]
    fn identical_set_and_missing_unlock_preserve_dependency_revision() {
        let mut ram = crate::Ram::default();
        let file = inode(&mut ram, b"revision");
        let mut table = fresh();
        let lock = request(file, Owner::Process(257), 0, 10, Some(Kind::Write));
        table
            .set(&mut ram.storage, payer(1), lock, |_| true)
            .unwrap();
        table
            .set(
                &mut ram.storage,
                payer(1),
                request(file, lock.owner, 20, 2, Some(Kind::Read)),
                |_| true,
            )
            .unwrap();
        table
            .set(
                &mut ram.storage,
                payer(2),
                request(file, Owner::Process(258), 40, 2, Some(Kind::Write)),
                |_| true,
            )
            .unwrap();
        let revision = table.revision(file);
        table
            .set(&mut ram.storage, payer(1), lock, |_| true)
            .unwrap();
        assert_eq!(table.revision(file), revision);
        table
            .set(
                &mut ram.storage,
                payer(1),
                request(file, lock.owner, 20, 2, Some(Kind::Read)),
                |_| true,
            )
            .unwrap();
        assert_eq!(table.revision(file), revision);

        table
            .set(
                &mut ram.storage,
                payer(1),
                request(file, lock.owner, 100, 1, None),
                |_| true,
            )
            .unwrap();
        assert_eq!(table.revision(file), revision);
        table
            .set(
                &mut ram.storage,
                payer(1),
                request(file, lock.owner, 2, 2, Some(Kind::Read)),
                |_| true,
            )
            .unwrap();
        assert!(table.revision(file) > revision);
    }

    #[test]
    fn splits_merge_conflicts_and_exact_owner_close() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let file = inode(&mut ram, b"range");
        let mut table = fresh();
        let owner = Owner::Process(256);
        table
            .set(
                &mut ram.storage,
                payer(1),
                request(file, owner, 0, 100, Some(Kind::Write)),
                |_| true,
            )
            .unwrap();
        table
            .set(
                &mut ram.storage,
                payer(1),
                request(file, owner, 20, 20, None),
                |_| true,
            )
            .unwrap();
        assert_eq!(table.count(file), 2);
        let stranger = request(file, Owner::Process(512), 30, 1, Some(Kind::Write));
        assert_eq!(table.query(&ram.storage, stranger, |_| true), Ok(None));
        let held = request(file, Owner::Process(512), 0, 1, Some(Kind::Write));
        assert_eq!(
            table
                .query(&ram.storage, held, |_| true)
                .unwrap()
                .unwrap()
                .owner,
            owner
        );
        table
            .set(
                &mut ram.storage,
                payer(1),
                request(file, owner, 20, 20, Some(Kind::Write)),
                |_| true,
            )
            .unwrap();
        assert_eq!(table.count(file), 1);
        assert!(
            !table
                .close(&mut ram.storage, file, Owner::Process(257))
                .unwrap()
        );
        assert!(table.close(&mut ram.storage, file, owner).unwrap());
        assert_eq!(table.count(file), 0);
        assert_eq!(ram.storage.usage(payer(1)), storage::Usage::default());
    }

    #[test]
    fn inode_limit_is_atomic_and_dead_owners_do_not_block() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let file = inode(&mut ram, b"capacity");
        let mut table = fresh();
        for i in 0..64 {
            table
                .set(
                    &mut ram.storage,
                    payer(1),
                    request(
                        file,
                        Owner::Process(256 + i),
                        i64::from(i) * 3,
                        1,
                        Some(Kind::Read),
                    ),
                    |_| true,
                )
                .unwrap();
        }
        let used = ram.storage.usage(payer(1));
        assert_eq!(
            table.set(
                &mut ram.storage,
                payer(1),
                request(file, Owner::Process(999), 200, 1, Some(Kind::Read)),
                |_| true
            ),
            Err(Error::NoLocks)
        );
        assert_eq!(table.count(file), 64);
        assert_eq!(ram.storage.usage(payer(1)), used);
        let wanted = request(
            file,
            Owner::Description {
                slot: 1,
                generation: 55,
            },
            0,
            1,
            Some(Kind::Write),
        );
        assert_eq!(
            table.query(&ram.storage, wanted, |owner| owner != Owner::Process(256)),
            Ok(None)
        );
        table
            .set(&mut ram.storage, payer(2), wanted, |owner| {
                owner != Owner::Process(256)
            })
            .unwrap();
        assert_eq!(table.count(file), 64);
        let mut cursor = SweepCursor::default();
        cursor.restart();
        let result = table.sweep(&mut ram.storage, &mut cursor, storage::NODES, |owner| {
            matches!(owner, Owner::Description { .. })
        });
        assert_eq!(result.removed, 63);
        assert_eq!(table.count(file), 1);
        assert_eq!(ram.storage.usage(payer(1)), storage::Usage::default());
        table.close(&mut ram.storage, file, wanted.owner).unwrap();
        assert_eq!(ram.storage.usage(payer(2)), storage::Usage::default());
    }

    #[test]
    fn nine_payers_and_more_than_256_records_share_real_paid_pages() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let files: Vec<_> = (0..5)
            .map(|i| inode(&mut ram, std::format!("file{i}").as_bytes()))
            .collect();
        let mut table = fresh();
        for i in 0..300 {
            let file = files[i / 60];
            let root = payer((i % 9 + 1) as u64);
            table
                .set(
                    &mut ram.storage,
                    root,
                    request(
                        file,
                        Owner::Process(256 + i as u32),
                        (i % 60) as i64 * 3,
                        1,
                        Some(Kind::Read),
                    ),
                    |_| true,
                )
                .unwrap();
        }
        assert_eq!(
            files.iter().map(|&file| table.count(file)).sum::<usize>(),
            300
        );
        for id in 1..=9 {
            assert_eq!(ram.storage.usage(payer(id)).pages, 1);
        }
        let mut cursor = SweepCursor::default();
        cursor.restart();
        table.sweep(&mut ram.storage, &mut cursor, storage::NODES, |_| false);
        for id in 1..=9 {
            assert_eq!(ram.storage.usage(payer(id)), storage::Usage::default());
        }
    }

    #[test]
    fn page_quota_failure_rolls_back_new_inode_pin_and_preserves_old_locks() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let file = inode(&mut ram, b"full");
        let other = inode(&mut ram, b"other");
        let mut table = fresh();
        for i in 0..64 {
            table
                .set(
                    &mut ram.storage,
                    payer(1),
                    request(
                        file,
                        Owner::Process(256 + i),
                        i64::from(i) * 3,
                        1,
                        Some(Kind::Write),
                    ),
                    |_| true,
                )
                .unwrap();
        }
        let pages: Vec<_> = (1..storage::PAGE_SHARE)
            .map(|_| ram.storage.allocate_lock_page(payer(1)).unwrap())
            .collect();
        let before = ram.storage.node(other).unwrap().pins;
        let query = request(other, Owner::Process(999), 0, 1, Some(Kind::Write));
        assert_eq!(
            table.set(&mut ram.storage, payer(1), query, |_| true),
            Err(Error::NoLocks)
        );
        assert_eq!(ram.storage.node(other).unwrap().pins, before);
        assert_eq!(table.count(file), 64);
        assert!(
            table
                .query(
                    &ram.storage,
                    request(file, Owner::Process(999), 0, 1, Some(Kind::Write)),
                    |_| true
                )
                .unwrap()
                .is_some()
        );
        for page in pages {
            ram.storage.release_lock_page(page);
        }
        let mut cursor = SweepCursor::default();
        cursor.restart();
        table.sweep(&mut ram.storage, &mut cursor, storage::NODES, |_| false);
        assert_eq!(ram.storage.usage(payer(1)), storage::Usage::default());
    }

    #[test]
    fn holders_table_matches_a_reference_through_collisions_and_deletions() {
        extern crate std;
        let mut table = std::boxed::Box::new(Holders {
            slots: [Holder::EMPTY; OWNERS],
            used: 0,
        });
        let mut reference = std::collections::BTreeMap::<u32, u32>::new();
        let mut state = 0x1234_5678_9abc_def0u64;
        let owner = |n: u32| {
            if n.is_multiple_of(5) {
                Owner::Description {
                    slot: (n / 5) as u16,
                    generation: u64::from(n),
                }
            } else {
                Owner::Process(n)
            }
        };
        for step in 0..200_000u32 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // About 1500 distinct owners keep the table dense and clustered.
            let n = ((state >> 33) % 1500) as u32;
            let have = reference.get(&n).copied().unwrap_or(0);
            if (state >> 20) & 3 != 0 && table.admits(owner(n)) {
                let started = table.add(owner(n), 1);
                assert_eq!(started, have == 0, "step {step}");
                *reference.entry(n).or_insert(0) += 1;
            } else if have != 0 {
                table.sub(owner(n), 1);
                if have == 1 {
                    reference.remove(&n);
                } else {
                    reference.insert(n, have - 1);
                }
            }
            assert_eq!(table.used, reference.len());
            if step % 997 == 0 {
                for n in 0..1500 {
                    assert_eq!(table.holds(owner(n)), reference.contains_key(&n));
                }
            }
        }
    }
}
