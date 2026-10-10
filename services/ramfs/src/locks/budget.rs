// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Constant-time logical record budgets around the single physical pool.
//! The actor applies charges and returns only alongside exact pool lifetimes.

pub const ROOT_PLACES: usize = 8;
pub const GUARANTEE: usize = 16;
pub const COMMON: usize = 128;
pub const PUBLISHED: usize = 256;
pub const PRIVATE: usize = 128;
pub const TOTAL: usize = 512;
pub const ROOT_LIVE: usize = 127;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Busy,
    NoLocks,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub published: usize,
    pub private: usize,
    pub retired: usize,
}
impl Counts {
    pub const fn paid(self) -> usize {
        self.published + self.private + self.retired
    }
    const EMPTY: Self = Self {
        published: 0,
        private: 0,
        retired: 0,
    };
}

/// Admission reserves every active root's guarantee until all its debt ends.
/// A preparation runs after prior retirement; mandatory close can retire freely.
pub struct Budget<const ROOTS: usize> {
    counts: [Counts; ROOTS],
    registered: [bool; ROOTS],
    totals: Counts,
    active: usize,
    common: usize,
    preparing: Option<u16>,
}
impl<const ROOTS: usize> Budget<ROOTS> {
    pub const fn new() -> Self {
        assert!(ROOTS > 0 && ROOTS <= u16::MAX as usize);
        Self {
            counts: [Counts::EMPTY; ROOTS],
            registered: [false; ROOTS],
            totals: Counts::EMPTY,
            active: 0,
            common: 0,
            preparing: None,
        }
    }
    pub fn root(&self, root: u16) -> Option<Counts> {
        self.counts.get(root as usize).copied()
    }
    pub const fn totals(&self) -> Counts {
        self.totals
    }
    pub const fn active(&self) -> usize {
        self.active
    }
    pub const fn common(&self) -> usize {
        self.common
    }
    pub const fn preparing(&self) -> Option<u16> {
        self.preparing
    }
    fn excess(n: usize) -> usize {
        n.saturating_sub(GUARANTEE)
    }
    fn unregister_empty(&mut self, root: u16) {
        let index = root as usize;
        if self.registered[index] && self.counts[index].paid() == 0 && self.preparing != Some(root)
        {
            self.registered[index] = false;
            self.active -= 1;
        }
    }
    pub fn begin(&mut self, root: u16) -> Result<(), Error> {
        let index = root as usize;
        self.counts.get(index).ok_or(Error::Invalid)?;
        if self.preparing.is_some() || self.totals.retired != 0 {
            return Err(Error::Busy);
        }
        if !self.registered[index] {
            if self.active == ROOT_PLACES {
                return Err(Error::NoLocks);
            }
            self.registered[index] = true;
            self.active += 1;
        }
        self.preparing = Some(root);
        Ok(())
    }
    /// The actor can preflight this operation before spending a pool place.
    pub fn can_charge_private(&self) -> Result<u16, Error> {
        let root = self.preparing.ok_or(Error::Invalid)?;
        if self.totals.private == PRIVATE || self.totals.paid() == TOTAL {
            return Err(Error::NoLocks);
        }
        Ok(root)
    }
    pub fn charge_private(&mut self) -> Result<(), Error> {
        let root = self.can_charge_private()?;
        self.counts[root as usize].private += 1;
        self.totals.private += 1;
        Ok(())
    }
    /// Check the complete future published view before changing either class.
    pub fn can_publish(&self, old: usize) -> Result<(), Error> {
        let root = self.preparing.ok_or(Error::Invalid)?;
        let counts = self.counts[root as usize];
        if old > counts.published {
            return Err(Error::Invalid);
        }
        let future = counts.published - old + counts.private;
        let common = self.common - Self::excess(counts.published) + Self::excess(future);
        let published = self.totals.published - old + counts.private;
        if future > ROOT_LIVE || common > COMMON || published > PUBLISHED {
            return Err(Error::NoLocks);
        }
        Ok(())
    }
    /// Exchange an old chain for the completed private chain, preserving debt.
    pub fn publish(&mut self, old: usize) -> Result<(), Error> {
        self.can_publish(old)?;
        let root = self.preparing.take().expect("validated preparation");
        let counts = &mut self.counts[root as usize];
        let private = counts.private;
        let future = counts.published - old + private;
        self.common = self.common - Self::excess(counts.published) + Self::excess(future);
        counts.published = future;
        counts.private = 0;
        counts.retired += old;
        self.totals.published = self.totals.published - old + private;
        self.totals.private -= private;
        self.totals.retired += old;
        self.unregister_empty(root);
        Ok(())
    }
    /// Cancellation transfers debt to cleanup without returning pool places.
    pub fn cancel(&mut self) -> Result<(), Error> {
        let root = self.preparing.take().ok_or(Error::Invalid)?;
        let counts = &mut self.counts[root as usize];
        let private = counts.private;
        counts.private = 0;
        counts.retired += private;
        self.totals.private -= private;
        self.totals.retired += private;
        self.unregister_empty(root);
        Ok(())
    }
    /// Mandatory close/death has no retirement admission limit.
    pub fn retire(&mut self, root: u16, n: usize) -> Result<(), Error> {
        let counts = self.counts.get_mut(root as usize).ok_or(Error::Invalid)?;
        if n > counts.published {
            return Err(Error::Invalid);
        }
        let future = counts.published - n;
        self.common = self.common - Self::excess(counts.published) + Self::excess(future);
        counts.published = future;
        counts.retired += n;
        self.totals.published -= n;
        self.totals.retired += n;
        Ok(())
    }
    /// Called after a reclaim portion has returned these exact physical places.
    pub fn release_retired(&mut self, root: u16, n: usize) -> Result<(), Error> {
        let counts = self.counts.get_mut(root as usize).ok_or(Error::Invalid)?;
        if n > counts.retired {
            return Err(Error::Invalid);
        }
        counts.retired -= n;
        self.totals.retired -= n;
        self.unregister_empty(root);
        Ok(())
    }
}
impl<const ROOTS: usize> Default for Budget<ROOTS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn publish<const R: usize>(b: &mut Budget<R>, root: u16, n: usize, old: usize) {
        b.begin(root).unwrap();
        for _ in 0..n {
            b.charge_private().unwrap();
        }
        b.publish(old).unwrap();
    }
    #[test]
    fn eight_roots_keep_sixteen_places_when_the_shared_budget_is_full() {
        let mut b = Budget::<9>::new();
        publish(&mut b, 0, 127, 0);
        publish(&mut b, 1, 33, 0);
        assert_eq!(b.common(), COMMON);
        b.begin(1).unwrap();
        for _ in 0..34 {
            b.charge_private().unwrap();
        }
        let before = b.totals();
        assert_eq!(b.publish(33), Err(Error::NoLocks));
        assert_eq!(b.totals(), before);
        b.cancel().unwrap();
        b.release_retired(1, 34).unwrap();
        for root in 2..8 {
            publish(&mut b, root, GUARANTEE, 0);
        }
        assert_eq!(b.totals().published, PUBLISHED);
        assert_eq!(b.active(), ROOT_PLACES);
        assert_eq!(b.begin(8), Err(Error::NoLocks));
        assert_eq!(b.preparing(), None);
        assert_eq!(b.root(8), Some(Counts::EMPTY));
        b.begin(2).unwrap();
        b.charge_private().unwrap();
        let before = b.totals();
        assert_eq!(b.publish(0), Err(Error::NoLocks));
        assert_eq!(b.totals(), before);
        b.cancel().unwrap();
        b.release_retired(2, 1).unwrap();
    }
    #[test]
    fn full_publication_leaves_a_complete_private_copy_and_failure_has_no_effect() {
        let mut b = Budget::<8>::new();
        publish(&mut b, 0, 127, 0);
        publish(&mut b, 1, 33, 0);
        for root in 2..8 {
            publish(&mut b, root, 16, 0);
        }
        b.begin(0).unwrap();
        for _ in 0..PRIVATE {
            b.charge_private().unwrap();
        }
        assert_eq!(b.totals().paid(), PUBLISHED + PRIVATE);
        let before = b.totals();
        assert_eq!(b.charge_private(), Err(Error::NoLocks));
        assert_eq!(b.publish(127), Err(Error::NoLocks));
        assert_eq!(b.totals(), before);
        assert_eq!(b.root(0).unwrap().published, 127);
        b.cancel().unwrap();
        assert_eq!(b.totals().paid(), before.paid());
        assert_eq!(b.begin(1), Err(Error::Busy));
        for _ in 0..16 {
            b.release_retired(0, 8).unwrap();
        }
        assert_eq!(b.totals().private, 0);
        b.begin(0).unwrap();
        for _ in 0..127 {
            b.charge_private().unwrap();
        }
        let paid = b.totals().paid();
        b.publish(127).unwrap();
        assert_eq!(b.totals().paid(), paid);
        assert_eq!(b.totals().retired, 127);
        assert_eq!(b.root(0).unwrap().published, 127);
    }
    #[test]
    fn fragmentation_limit_rejects_before_publication_and_full_interval_unlock_fits() {
        let mut b = Budget::<1>::new();
        publish(&mut b, 0, ROOT_LIVE, 0);
        b.begin(0).unwrap();
        for _ in 0..128 {
            b.charge_private().unwrap();
        }
        let before = b.totals();
        assert_eq!(b.publish(127), Err(Error::NoLocks));
        assert_eq!(b.totals(), before);
        assert_eq!(b.root(0).unwrap().published, 127);
        b.cancel().unwrap();
        b.release_retired(0, 128).unwrap();
        publish(&mut b, 0, 126, 127);
        assert_eq!(b.root(0).unwrap().published, 126);
        assert_eq!(b.root(0).unwrap().retired, 127);
        assert_eq!(b.root(0).unwrap().paid(), 253);
    }

    #[test]
    fn mandatory_retirement_can_exceed_one_copy_and_stays_charged_until_release() {
        let mut b = Budget::<9>::new();
        publish(&mut b, 0, 127, 0);
        publish(&mut b, 1, 33, 0);
        for root in 2..8 {
            publish(&mut b, root, 16, 0);
        }
        let paid = b.totals().paid();
        for root in 0..8 {
            let n = b.root(root).unwrap().published;
            b.retire(root, n).unwrap();
        }
        assert_eq!(b.totals().retired, PUBLISHED);
        assert_eq!(b.totals().paid(), paid);
        assert_eq!(b.active(), ROOT_PLACES);
        assert_eq!(b.common(), 0);
        assert_eq!(b.begin(8), Err(Error::Busy));
        for root in 0..8 {
            let n = b.root(root).unwrap().retired;
            b.release_retired(root, n).unwrap();
        }
        assert_eq!(b.active(), 0);
        assert_eq!(b.totals(), Counts::EMPTY);
        b.begin(8).unwrap();
        b.cancel().unwrap();
        assert_eq!(b.active(), 0);
    }
    #[test]
    fn one_preparation_and_cancel_keep_new_root_admission_paid() {
        let mut b = Budget::<9>::new();
        for root in 0..7 {
            publish(&mut b, root, 1, 0);
        }
        b.begin(7).unwrap();
        assert_eq!(b.active(), 8);
        assert_eq!(b.begin(8), Err(Error::Busy));
        b.charge_private().unwrap();
        b.cancel().unwrap();
        assert_eq!(b.active(), 8);
        assert_eq!(b.root(7).unwrap().paid(), 1);
        assert_eq!(b.begin(8), Err(Error::Busy));
        b.release_retired(7, 1).unwrap();
        assert_eq!(b.active(), 7);
        b.begin(8).unwrap();
        assert_eq!(b.active(), 8);
        b.cancel().unwrap();
        assert_eq!(b.active(), 7);
    }
    #[test]
    fn invalid_counts_do_not_change_the_view_and_close_can_cancel_a_preparation() {
        let mut b = Budget::<2>::new();
        assert_eq!(b.begin(2), Err(Error::Invalid));
        assert_eq!(b.charge_private(), Err(Error::Invalid));
        assert_eq!(b.publish(0), Err(Error::Invalid));
        assert_eq!(b.cancel(), Err(Error::Invalid));
        assert_eq!(b.totals(), Counts::EMPTY);
        publish(&mut b, 0, 3, 0);
        b.begin(0).unwrap();
        b.charge_private().unwrap();
        let before = b.totals();
        assert_eq!(b.publish(4), Err(Error::Invalid));
        assert_eq!(b.retire(0, 4), Err(Error::Invalid));
        assert_eq!(b.release_retired(0, 1), Err(Error::Invalid));
        assert_eq!(b.release_retired(2, 0), Err(Error::Invalid));
        assert_eq!(b.totals(), before);
        b.retire(0, 3).unwrap();
        assert_eq!(b.publish(3), Err(Error::Invalid));
        b.cancel().unwrap();
        assert_eq!(b.root(0).unwrap().retired, 4);
        b.release_retired(0, 4).unwrap();
        assert_eq!(b.totals(), Counts::EMPTY);
        assert_eq!(b.active(), 0);
    }
}
