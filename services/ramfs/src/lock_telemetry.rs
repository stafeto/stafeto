// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Measurement-only, fixed full-dispatch witnesses. Never changes lock custody.
pub const METHOD: u16 = 0xfff1;
pub const ROWS: usize = 32;
pub const BRANCHES: usize = 16;
pub const PAGES: u32 = 20;
/// Exact effects use the previously unused rows, separate from branch maxima.
pub const EFFECT_BRANCHES: [usize; 6] = [8, 12, 15, 9, 0, 0];
pub fn control(id: crate::locks::jobs::Id) -> [u64; 4] {
    [id.owner(), u64::from(id.key().slot), id.key().generation, 0]
}
pub fn wait(id: crate::locks::wait_receipts::Id) -> [u64; 4] {
    [id.owner(), u64::from(id.key().slot), id.key().generation, 1]
}
pub fn registration(token: crate::locks::waiters::RegistrationToken) -> [u64; 4] {
    let id = token.receipt();
    [
        id.owner(),
        u64::from(id.key().slot),
        id.key().generation,
        token.slot() as u64,
    ]
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Occupancy {
    pub published: u16,
    pub private: u16,
    pub retired: u16,
    pub common: u16,
    pub roots: u8,
}
impl Occupancy {
    fn full(self) -> bool {
        self == Self {
            published: 256,
            private: 0,
            retired: 0,
            common: 128,
            roots: 8,
        }
    }
    fn packed(self) -> u64 {
        u64::from(self.published)
            | u64::from(self.private) << 16
            | u64::from(self.retired) << 32
            | u64::from(self.common) << 48
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Payer {
    pub id: u64,
    pub generation: u64,
    pub published: u16,
    pub private: u16,
    pub retired: u16,
}
/// Read at most eight physical indices, returning one exact paid payer.
pub fn census(
    first: usize,
    length: usize,
    mut read: impl FnMut(usize) -> Option<Payer>,
) -> Result<[u64; 5], Error> {
    if first >= length {
        return Err(Error::Invalid);
    }
    let end = first.saturating_add(8).min(length);
    for index in first..end {
        if let Some(payer) = read(index) {
            if payer.published == 0 && payer.private == 0 && payer.retired == 0 {
                continue;
            }
            return Ok([
                (index + 1) as u64,
                ((index - first + 1) as u64) | (1_u64 << 63),
                payer.id,
                payer.generation,
                u64::from(payer.published)
                    | u64::from(payer.private) << 16
                    | u64::from(payer.retired) << 32,
            ]);
        }
    }
    Ok([end as u64, (end - first) as u64, 0, 0, 0])
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Source {
    pub packed: u32,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    pub place: usize,
    pub owner: u64,
    pub nonce: u64,
    pub source: Source,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Timing {
    pub kind: usize,
    pub detail: u64,
    pub whole: u64,
    pub waited: u64,
    pub took: u64,
    pub valid: bool,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Branch {
    pub visited: u8,
    pub ambiguous: bool,
    pub witness: [u64; 4],
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Dispatch {
    pub before: Occupancy,
    pub mask: u16,
    pub marks: [Branch; BRANCHES],
    observer: bool,
    effects: u8,
    exact: [Branch; 6],
}
impl Dispatch {
    pub fn mark(&mut self, bit: usize, visited: u8, witness: [u64; 4]) -> bool {
        let Some(mark) = self.marks.get_mut(bit) else {
            return false;
        };
        let flag = 1_u16 << bit;
        if self.mask & flag == 0 {
            mark.witness = witness;
        } else if mark.witness != witness {
            mark.ambiguous = true;
        }
        mark.visited = mark.visited.max(visited);
        self.mask |= flag;
        true
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    pub serial: u64,
    pub count: u64,
    pub timing: Timing,
    pub before: Occupancy,
    pub after: Occupancy,
    pub mask: u16,
    pub marks: [Branch; BRANCHES],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    Authority,
    Exhausted,
}
pub struct Table {
    scope: Option<Scope>,
    epoch: u64,
    profile: u32,
    active: bool,
    failed: bool,
    dispatch: Dispatch,
    rows: [Option<Row>; ROWS],
}
const _: () = assert!(core::mem::size_of::<Table>() <= 32768);
impl Table {
    /// # Safety
    /// Exclusive aligned writable uninitialized storage for the complete Table.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: each field is initialized in its permanent allocation.
        unsafe {
            core::ptr::addr_of_mut!((*destination).scope).write(None);
            core::ptr::addr_of_mut!((*destination).epoch).write(0);
            core::ptr::addr_of_mut!((*destination).profile).write(0);
            core::ptr::addr_of_mut!((*destination).active).write(false);
            core::ptr::addr_of_mut!((*destination).failed).write(false);
            core::ptr::addr_of_mut!((*destination).dispatch).write(Dispatch::default());
            let rows = core::ptr::addr_of_mut!((*destination).rows).cast::<Option<Row>>();
            for i in 0..ROWS {
                rows.add(i).write(None);
            }
        }
    }
    /// Identity observations belong to setup before the first capture.
    pub fn authorize_identity(&self, scope: Scope, epoch: u64) -> Result<(), Error> {
        if self.scope.is_none()
            && self.epoch == 0
            && epoch == 0
            && scope.owner != 0
            && scope.nonce != 0
            && scope.source.generation != 0
        {
            Ok(())
        } else {
            Err(Error::Authority)
        }
    }
    pub fn authorize_oracle(&self, scope: Scope, epoch: u64) -> Result<(), Error> {
        if self.scope.is_none()
            && epoch == 0
            && scope.owner != 0
            && scope.nonce != 0
            && scope.source.generation != 0
        {
            Ok(())
        } else {
            self.authorize(scope, epoch)
        }
    }
    pub fn authorize(&self, scope: Scope, epoch: u64) -> Result<(), Error> {
        if self.scope == Some(scope) && self.epoch == epoch {
            Ok(())
        } else {
            Err(Error::Authority)
        }
    }
    pub fn start(
        &mut self,
        scope: Scope,
        previous: u64,
        profile: u32,
        before: Occupancy,
    ) -> Result<u64, Error> {
        if scope.owner == 0
            || scope.nonce == 0
            || scope.source.generation == 0
            || !matches!(profile, 4 | 7)
            || !before.full()
        {
            return Err(Error::Invalid);
        }
        if self.active
            || self
                .scope
                .is_some_and(|old| old.owner != scope.owner || old.source != scope.source)
            || previous != self.epoch
            || self.scope == Some(scope)
        {
            return Err(Error::Authority);
        }
        let Some(epoch) = self.epoch.checked_add(1) else {
            self.failed = true;
            return Err(Error::Exhausted);
        };
        if self.failed {
            return Err(Error::Exhausted);
        }
        self.epoch = epoch;
        self.scope = Some(scope);
        self.profile = profile;
        self.active = true;
        self.rows.fill(None);
        Ok(epoch)
    }
    pub fn stop(&mut self, scope: Scope, epoch: u64) -> Result<(), Error> {
        self.authorize(scope, epoch)?;
        self.active = false;
        Ok(())
    }
    pub fn scope(&self) -> Option<Scope> {
        self.scope
    }
    pub fn invalidate(&mut self) {
        self.active = false;
    }
    pub fn invalidate_owner(&mut self, owner: u64) {
        if self.scope.is_some_and(|s| s.owner == owner) {
            self.active = false;
        }
    }
    pub fn begin_dispatch(&mut self, before: Occupancy) {
        self.dispatch = Dispatch {
            before,
            ..Dispatch::default()
        };
    }
    pub fn observer(&mut self) {
        self.dispatch.observer = true;
    }
    pub fn mark(&mut self, bit: usize, visited: u8, witness: [u64; 4]) -> bool {
        self.dispatch.mark(bit, visited, witness)
    }
    /// Counts only an executed portion, never an idle call.
    pub fn portion(&mut self, bit: usize, visited: usize, witness: [u64; 4]) {
        if visited == 0 {
            return;
        }
        let Ok(visited) = u8::try_from(visited) else {
            self.active = false;
            self.failed = true;
            return;
        };
        self.mark(bit, visited, witness);
    }
    /// Publish only after an actual effect; repeated distinct identities are ambiguous.
    pub fn effect(&mut self, index: usize, visited: usize, witness: [u64; 4]) {
        let Some(mark) = self.dispatch.exact.get_mut(index) else {
            self.failed = true;
            self.active = false;
            return;
        };
        let Ok(visited) = u8::try_from(visited) else {
            self.failed = true;
            self.active = false;
            return;
        };
        if visited == 0 || visited > 8 {
            self.failed = true;
            self.active = false;
            return;
        }
        let flag = 1_u8 << index;
        if self.dispatch.effects & flag == 0 {
            mark.witness = witness;
        } else if mark.witness != witness {
            mark.ambiguous = true;
        }
        mark.visited = mark.visited.max(visited);
        self.dispatch.effects |= flag;
    }
    /// A bounded portion observed more than one distinct effect identity.
    pub fn effect_ambiguous(&mut self, index: usize) {
        if let Some(mark) = self.dispatch.exact.get_mut(index) {
            mark.ambiguous = true;
        }
    }
    pub fn actor(
        &mut self,
        progress: crate::locks::actor::Progress,
        stage: u8,
        receipt: Option<[u64; 4]>,
    ) {
        // Cleanup may run while a pending worker still retains an active receipt.
        let receipt = receipt.filter(|_| matches!(stage, 1..=4));
        let mut witness = receipt.unwrap_or([0; 4]);
        witness[3] |= u64::from(stage) << 32;
        // Production charged bounds for these two single-cell transitions are eight.
        let visits = if matches!(stage, 17 | 18) {
            1
        } else {
            progress.visited
        };
        self.portion(0, visits, witness);
        if progress.completed.is_some() {
            self.mark(1, 0, witness);
        }
    }
    pub fn finish(&mut self, timing: Timing, after: Occupancy) {
        if !self.active || self.dispatch.observer {
            return;
        }
        if !timing.valid
            || timing.whole < timing.waited
            || timing.whole - timing.waited != timing.took
        {
            self.failed = true;
            self.active = false;
            return;
        }
        if (49..=58).contains(&timing.kind) {
            self.record(timing.kind - 49, timing, after);
        }
        for bit in 0..BRANCHES {
            if !self.active {
                return;
            }
            if self.dispatch.mask & (1 << bit) != 0 {
                self.record(10 + bit, timing, after);
            }
        }
        for (index, &bit) in EFFECT_BRANCHES.iter().enumerate() {
            if self.dispatch.effects & (1 << index) == 0 {
                continue;
            }
            // No callback/RPC runs while substituting this exact mark. Keep the
            // ordinary branch maxima and their original witness unchanged.
            let previous = self.dispatch.marks[bit];
            let mask = self.dispatch.mask;
            self.dispatch.marks[bit] = self.dispatch.exact[index];
            self.dispatch.mask |= 1 << bit;
            self.record(26 + index, timing, after);
            self.dispatch.marks[bit] = previous;
            self.dispatch.mask = mask;
        }
    }
    fn record(&mut self, index: usize, timing: Timing, after: Occupancy) {
        let previous = self.rows[index];
        let Some(count) = previous.map_or(Some(1), |r| r.count.checked_add(1)) else {
            self.failed = true;
            self.active = false;
            return;
        };
        let Some(serial) = previous.map_or(Some(1), |r| r.serial.checked_add(1)) else {
            self.failed = true;
            self.active = false;
            return;
        };
        if previous.is_some_and(|r| timing.took <= r.timing.took) {
            let row = self.rows[index].as_mut().unwrap();
            row.count = count;
            row.serial = serial;
            return;
        }
        self.rows[index] = Some(Row {
            serial,
            count,
            timing,
            before: self.dispatch.before,
            after,
            mask: self.dispatch.mask,
            marks: self.dispatch.marks,
        });
    }
    pub fn header(&self) -> [u64; 5] {
        [
            u64::from(self.profile),
            ROWS as u64,
            u64::from(self.active),
            u64::from(self.failed),
            self.epoch,
        ]
    }
    pub fn page(&self, index: usize, page: u32) -> Result<[u64; 5], Error> {
        let row = self
            .rows
            .get(index)
            .ok_or(Error::Invalid)?
            .ok_or(Error::Invalid)?;
        match page {
            0 => Ok([
                row.serial,
                row.count,
                row.timing.took,
                u64::from(row.mask),
                row.timing.kind as u64,
            ]),
            1 => Ok([
                row.serial,
                row.before.packed(),
                row.after.packed(),
                u64::from(row.before.roots),
                u64::from(row.after.roots),
            ]),
            2..=17 => {
                let mark = row.marks[(page - 2) as usize];
                Ok([
                    row.serial,
                    mark.witness[0],
                    mark.witness[1],
                    mark.witness[2],
                    mark.witness[3],
                ])
            }
            18 => Ok([
                row.serial,
                row.timing.whole,
                row.timing.waited,
                row.timing.detail,
                u64::from(row.timing.valid),
            ]),
            19 => {
                let mut visited = [0_u64; 2];
                let mut ambiguous = 0_u64;
                for (i, mark) in row.marks.iter().enumerate() {
                    visited[i / 8] |= u64::from(mark.visited) << ((i % 8) * 8);
                    ambiguous |= u64::from(mark.ambiguous) << i;
                }
                Ok([
                    row.serial,
                    visited[0],
                    visited[1],
                    ambiguous,
                    u64::from(row.mask),
                ])
            }
            _ => Err(Error::Invalid),
        }
    }
}
#[cfg(test)]
pub(crate) fn test_record(bit: usize, apply: impl FnOnce(&mut Table)) -> ([u64; 5], [u64; 5]) {
    let mut allocation = Box::<Table>::new_uninit();
    // SAFETY: exclusive aligned heap allocation initialized in place.
    let mut table = unsafe {
        Table::initialize_at(allocation.as_mut_ptr());
        allocation.assume_init()
    };
    let occupancy = Occupancy {
        published: 256,
        private: 0,
        retired: 0,
        common: 128,
        roots: 8,
    };
    table
        .start(
            Scope {
                place: 0,
                owner: 1,
                nonce: 1,
                source: Source {
                    packed: 3,
                    generation: 1,
                },
            },
            0,
            4,
            occupancy,
        )
        .unwrap();
    table.begin_dispatch(occupancy);
    apply(&mut table);
    table.finish(
        Timing {
            kind: 2,
            detail: 0,
            whole: 1,
            waited: 0,
            took: 1,
            valid: true,
        },
        occupancy,
    );
    (
        table.page(10 + bit, 19).unwrap_or([0; 5]),
        table.page(10 + bit, 2 + bit as u32).unwrap_or([0; 5]),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fresh() -> Box<Table> {
        let mut table = Box::<Table>::new_uninit();
        unsafe {
            Table::initialize_at(table.as_mut_ptr());
            table.assume_init()
        }
    }
    fn scope() -> Scope {
        Scope {
            place: 3,
            owner: 0x100000001,
            nonce: 71,
            source: Source {
                packed: 34,
                generation: 77,
            },
        }
    }
    fn full() -> Occupancy {
        Occupancy {
            published: 256,
            private: 0,
            retired: 0,
            common: 128,
            roots: 8,
        }
    }
    fn timing(took: u64) -> Timing {
        Timing {
            kind: 54,
            detail: 32,
            whole: took + 5,
            waited: 5,
            took,
            valid: true,
        }
    }
    #[test]
    fn setup_identity_closes_permanently_when_capture_begins() {
        let mut table = fresh();
        assert_eq!(table.authorize_identity(scope(), 0), Ok(()));
        assert_eq!(table.authorize_identity(scope(), 1), Err(Error::Authority));
        for malformed in [
            Scope {
                owner: 0,
                ..scope()
            },
            Scope {
                nonce: 0,
                ..scope()
            },
            Scope {
                source: Source {
                    generation: 0,
                    ..scope().source
                },
                ..scope()
            },
        ] {
            assert_eq!(
                table.authorize_identity(malformed, 0),
                Err(Error::Authority)
            );
        }
        let epoch = table.start(scope(), 0, 4, full()).unwrap();
        assert_eq!(table.authorize_identity(scope(), 0), Err(Error::Authority));
        assert_eq!(
            table.authorize_identity(scope(), epoch),
            Err(Error::Authority)
        );
        table.stop(scope(), epoch).unwrap();
        assert_eq!(table.authorize_identity(scope(), 0), Err(Error::Authority));
        assert_eq!(
            table.authorize_identity(scope(), epoch),
            Err(Error::Authority)
        );
        table.invalidate();
        assert_eq!(table.authorize_identity(scope(), 0), Err(Error::Authority));
    }
    #[test]
    fn complete_dispatch_keeps_same_step_occupancy_and_all_branch_witnesses() {
        let mut t = fresh();
        assert_eq!(t.start(scope(), 0, 4, full()), Ok(1));
        t.begin_dispatch(full());
        assert!(t.mark(0, 8, [1, 2, 3, 4]));
        assert!(t.mark(15, 7, [5, 6, 7, 8]));
        let after = Occupancy {
            published: 255,
            retired: 1,
            ..full()
        };
        t.finish(timing(900), after);
        let r = t.rows[5].unwrap();
        assert_eq!((r.before, r.after), (full(), after));
        assert_eq!(r.mask, 0x8001);
        assert_eq!(r.marks[0].witness, [1, 2, 3, 4]);
        assert_eq!(r.marks[15].witness, [5, 6, 7, 8]);
        assert_eq!(t.rows[25].unwrap(), r);
        t.begin_dispatch(after);
        t.mark(0, 1, [9; 4]);
        t.finish(timing(100), after);
        assert_eq!(t.rows[5].unwrap().before, full());
        assert_eq!(t.rows[5].unwrap().marks[0].witness, [1, 2, 3, 4]);
        assert_eq!(t.rows[5].unwrap().count, 2);
    }
    #[test]
    fn ambiguity_preserves_first_exact_witness_without_losing_work() {
        let mut t = fresh();
        t.start(scope(), 0, 7, full()).unwrap();
        t.begin_dispatch(full());
        t.mark(2, 3, [1; 4]);
        t.mark(2, 8, [2; 4]);
        t.finish(timing(42), full());
        let r = t.rows[12].unwrap();
        assert_eq!(r.mask, 4);
        assert_eq!(r.marks[2].witness, [1; 4]);
        assert!(r.marks[2].ambiguous);
        assert_eq!(r.marks[2].visited, 8);
    }
    #[test]
    fn controller_requires_full_table_and_exact_identity_epoch() {
        let mut t = fresh();
        assert_eq!(
            t.start(
                scope(),
                0,
                4,
                Occupancy {
                    published: 255,
                    ..full()
                }
            ),
            Err(Error::Invalid)
        );
        t.start(scope(), 0, 4, full()).unwrap();
        let mut wrong = scope();
        wrong.source.generation += 1;
        assert_eq!(t.stop(wrong, 1), Err(Error::Authority));
        let mut wrong_owner = scope();
        wrong_owner.owner ^= 1 << 32;
        assert_eq!(t.stop(wrong_owner, 1), Err(Error::Authority));
        let mut wrong_place = scope();
        wrong_place.place += 1;
        assert_eq!(t.stop(wrong_place, 1), Err(Error::Authority));
        assert_eq!(t.stop(scope(), 0), Err(Error::Authority));
        t.begin_dispatch(full());
        t.observer();
        t.finish(timing(99), full());
        assert!(t.rows.iter().all(Option::is_none));
        t.stop(scope(), 1).unwrap();
        assert_eq!(t.start(scope(), 1, 4, full()), Err(Error::Authority));
    }
    #[test]
    fn pagination_preserves_full_serial_visits_and_all_witness_words() {
        let mut t = fresh();
        t.start(scope(), 0, 4, full()).unwrap();
        t.begin_dispatch(full());
        t.mark(15, 8, [u64::MAX, 2, 3, u64::MAX - 1]);
        t.finish(timing(300), full());
        t.rows[5].as_mut().unwrap().serial = u64::MAX - 1;
        assert_eq!(
            t.page(5, 17).unwrap(),
            [u64::MAX - 1, u64::MAX, 2, 3, u64::MAX - 1]
        );
        assert_eq!(t.page(5, 19).unwrap()[2], 8_u64 << 56);
        assert_eq!(t.page(5, PAGES), Err(Error::Invalid));
        t.finish(timing(100), full());
        assert_eq!(t.rows[5].unwrap().serial, u64::MAX);
        t.finish(timing(101), full());
        assert!(t.failed);
        assert_eq!(t.rows[5].unwrap().serial, u64::MAX);
    }
    #[test]
    fn invalid_accounting_freezes_history_and_fresh_before_is_not_reused() {
        let mut t = fresh();
        t.start(scope(), 0, 4, full()).unwrap();
        t.begin_dispatch(full());
        t.mark(1, 8, [77; 4]);
        t.finish(timing(10), full());
        let before = t.rows[5];
        let next = Occupancy {
            published: 255,
            retired: 1,
            ..full()
        };
        t.begin_dispatch(next);
        t.finish(timing(20), next);
        let row = t.rows[5].unwrap();
        assert_eq!(row.before, next);
        assert_eq!(row.mask, 0);
        assert_ne!(t.rows[5], before);
        let saved = t.rows[5];
        let mut invalid = timing(30);
        invalid.valid = false;
        t.finish(invalid, full());
        assert_eq!(t.rows[5], saved);
        assert!(t.failed);
        assert!(!t.active);
    }
    #[test]
    fn census_visits_real_physical_indices_and_preserves_full_payer_generation() {
        let mut seen = Vec::new();
        assert_eq!(
            census(0, 320, |i| {
                seen.push(i);
                None
            }),
            Ok([8, 8, 0, 0, 0])
        );
        assert_eq!(seen, (0..8).collect::<Vec<_>>());
        let answer = census(8, 320, |i| {
            (i == 10).then_some(Payer {
                id: 0x100000001,
                generation: 0x200000002,
                published: 48,
                private: 0,
                retired: 0,
            })
        })
        .unwrap();
        assert_eq!(
            answer,
            [11, (1_u64 << 63) | 3, 0x100000001, 0x200000002, 48]
        );
        assert_eq!(census(319, 320, |_| None), Ok([320, 1, 0, 0, 0]));
        assert_eq!(census(320, 320, |_| None), Err(Error::Invalid));
        assert_eq!(
            census(0, 320, |_| Some(Payer {
                id: 9,
                generation: 1,
                published: 0,
                private: 0,
                retired: 0
            })),
            Ok([8, 8, 0, 0, 0])
        );
    }
    #[test]
    fn preregistration_oracle_does_not_grant_controller_authority() {
        let mut t = fresh();
        assert_eq!(t.authorize_oracle(scope(), 0), Ok(()));
        assert_eq!(t.authorize(scope(), 0), Err(Error::Authority));
        assert_eq!(t.authorize_oracle(scope(), 1), Err(Error::Authority));
        t.start(scope(), 0, 4, full()).unwrap();
        assert_eq!(t.authorize_oracle(scope(), 0), Err(Error::Authority));
        assert_eq!(t.authorize_oracle(scope(), 1), Ok(()));
    }
    #[test]
    fn saturation_disables_measurement_without_reusing_history() {
        let mut t = fresh();
        t.epoch = u64::MAX;
        assert_eq!(t.start(scope(), u64::MAX, 4, full()), Err(Error::Exhausted));
        assert_eq!(t.epoch, u64::MAX);
        let mut t = fresh();
        t.start(scope(), 0, 4, full()).unwrap();
        t.begin_dispatch(full());
        t.finish(timing(8), full());
        t.rows[5].as_mut().unwrap().count = u64::MAX;
        t.finish(timing(9), full());
        assert!(!t.active);
        assert!(t.failed);
        assert_eq!(t.rows[5].unwrap().count, u64::MAX);
    }
}

#[cfg(test)]
mod exact_effect_tests {
    use super::*;
    fn table() -> Box<Table> {
        let mut allocation = Box::<Table>::new_uninit();
        // SAFETY: exclusive aligned complete allocation.
        let mut table = unsafe {
            Table::initialize_at(allocation.as_mut_ptr());
            allocation.assume_init()
        };
        table
            .start(
                Scope {
                    place: 0,
                    owner: 77,
                    nonce: 1,
                    source: Source {
                        packed: 3,
                        generation: 1,
                    },
                },
                0,
                4,
                Occupancy {
                    published: 256,
                    common: 128,
                    roots: 8,
                    ..Occupancy::default()
                },
            )
            .unwrap();
        table
    }
    fn finish(table: &mut Table, took: u64) {
        table.finish(
            Timing {
                kind: 2,
                whole: took,
                took,
                valid: true,
                ..Timing::default()
            },
            Occupancy::default(),
        );
    }
    #[test]
    fn empty_sweep_cannot_replace_actual_removed_pid_with_faster_or_slower_work() {
        let mut t = table();
        t.begin_dispatch(Occupancy::default());
        t.portion(8, 8, [0, 8, 0, 0]);
        finish(&mut t, 99);
        assert_eq!(t.page(26, 0), Err(Error::Invalid));
        t.begin_dispatch(Occupancy::default());
        t.portion(8, 8, [0, 8, 0, 1]);
        t.effect(0, 8, [264, 0 | (8 << 32), 1, 1]);
        finish(&mut t, 7);
        assert_eq!(t.page(26, 10).unwrap()[1..], [264, 8 << 32, 1, 1]);
        assert_eq!(t.page(26, 18).unwrap()[1], 7);
        t.begin_dispatch(Occupancy::default());
        t.portion(8, 8, [0, 8, 0, 0]);
        finish(&mut t, 200);
        assert_eq!(t.page(26, 10).unwrap()[1], 264);
    }
    #[test]
    fn two_distinct_full_keys_are_ambiguous_and_geometry_growth_is_bounded() {
        let mut t = table();
        t.begin_dispatch(Occupancy::default());
        t.effect(1, 8, [77, 1 << 32, 9, 330]);
        t.effect(1, 8, [77, 1 << 32, 10, 330]);
        finish(&mut t, 9);
        assert_ne!(t.page(27, 19).unwrap()[3] & (1 << 12), 0);
        assert_eq!(t.page(27, 14).unwrap()[3], 9);
        assert!(
            core::mem::size_of::<Dispatch>()
                - (core::mem::size_of::<Occupancy>() + 8 + core::mem::size_of::<[Branch; 16]>())
                <= 256
        );
        std::println!(
            "exact effect layout Dispatch={} Table={}",
            core::mem::size_of::<Dispatch>(),
            core::mem::size_of::<Table>()
        );
    }
}
