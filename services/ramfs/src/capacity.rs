// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Value-only phase records for two genuine expenditure-root leaders.

use crate::storage::Root;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Checkpoint {
    pub root: Root,
    pub pid: u32,
    pub image: u32,
    pub phase: u32,
    reserved: u32,
}

impl Checkpoint {
    pub const EMPTY: Self = Self {
        root: Root {
            id: 0,
            generation: 0,
        },
        pid: 0,
        image: 0,
        phase: 0,
        reserved: 0,
    };
}
const _: () = assert!(core::mem::size_of::<Checkpoint>() == 32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoints(pub [Checkpoint; 2]);
impl Default for Checkpoints {
    fn default() -> Self {
        Self([Checkpoint::EMPTY; 2])
    }
}
impl Checkpoints {
    /// Validate every field before occupying or changing a phase record.
    pub fn advance(&mut self, root: Root, pid: u32, image: u32, phase: u32) -> Result<bool, u32> {
        if !(1..=5).contains(&phase)
            || pid == 0
            || image == 0
            || root.id != u64::from(pid)
            || root.generation == 0
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        let slot = self
            .0
            .iter()
            .position(|c| c.root == root)
            .or_else(|| self.0.iter().position(|c| c.phase == 0))
            .ok_or(proto_fs::NO_SPACE)?;
        let current = self.0[slot];
        if current.phase != 0 && (current.pid != pid || current.image != image) {
            return Err(proto_fs::PERMISSION);
        }
        if phase == current.phase {
            return Ok(false);
        }
        if phase != current.phase + 1 {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        self.0[slot] = Checkpoint {
            root,
            pid,
            image,
            phase,
            reserved: 0,
        };
        Ok(true)
    }
    pub fn phase(&self, root: Root) -> u32 {
        self.0
            .iter()
            .find(|c| c.root == root)
            .map_or(0, |c| c.phase)
    }
    /// Value-only progress in registration order, including this authenticated root.
    pub fn phase_pack(&self, root: Root) -> u32 {
        self.phase(root) | (self.0[0].phase << 8) | (self.0[1].phase << 16)
    }
    pub fn both(&self, phase: u32) -> bool {
        self.0.iter().all(|c| c.phase == phase && c.pid != 0)
    }
}

/// One observation owns no capability, charge, page or client key allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredGate {
    label: u64,
    pid: u32,
    image: u32,
    root: Root,
    key: proto_fs::OpenKey,
    job: u64,
    fired: bool,
}
impl RetiredGate {
    pub fn new(
        label: u64,
        pid: u32,
        image: u32,
        root: Root,
        key: proto_fs::OpenKey,
        job: u64,
    ) -> Result<Self, u32> {
        key.validate()?;
        if label == 0
            || pid == 0
            || image == 0
            || root.id != u64::from(pid)
            || root.generation == 0
            || job == 0
        {
            return Err(proto_fs::INVALID_ARGUMENT);
        }
        Ok(Self {
            label,
            pid,
            image,
            root,
            key,
            job,
            fired: false,
        })
    }
    pub fn owner(self, label: u64) -> bool {
        self.label == label
    }
    pub fn exact(
        self,
        label: u64,
        pid: u32,
        image: u32,
        root: Root,
        key: proto_fs::OpenKey,
        job: u64,
    ) -> bool {
        (
            self.label, self.pid, self.image, self.root, self.key, self.job,
        ) == (label, pid, image, root, key, job)
    }
    /// Only the first actual successful server effect changes Armed to Fired.
    pub fn committed(
        &mut self,
        label: u64,
        key: proto_fs::OpenKey,
        before: proto_fs::DataOutcome,
        after: proto_fs::DataOutcome,
    ) -> bool {
        if self.fired
            || self.label != label
            || self.key != key
            || self.job != before.job
            || before.job != after.job
            || before.phase != proto_fs::DataPhase::Ready
            || before.result != proto_fs::DataResult::None
            || after.phase != proto_fs::DataPhase::Completed
            || after.result != proto_fs::DataResult::Bytes(0)
        {
            return false;
        }
        self.fired = true;
        true
    }
    pub fn paused(self) -> bool {
        self.fired
    }
    pub fn canceled_armed(self, label: u64, job: u64) -> bool {
        !self.fired && self.label == label && self.job == job
    }
    pub fn observed(self, label: u64, pid: u32, image: u32, root: Root) -> bool {
        self.fired && (self.label, self.pid, self.image, self.root) == (label, pid, image, root)
    }
}
const _: () = assert!(core::mem::size_of::<RetiredGate>() == 64);

#[cfg(test)]
mod tests {
    use super::*;
    fn root(pid: u32) -> Root {
        Root {
            id: u64::from(pid),
            generation: 7,
        }
    }
    #[test]
    fn refused_phase_leaves_both_slots_and_identity_unchanged() {
        let mut records = Checkpoints::default();
        let before = records;
        for phase in [0, 2, 5, 6] {
            assert!(records.advance(root(3), 3, 1, phase).is_err());
            assert_eq!(records, before);
        }
        assert!(records.advance(root(3), 4, 1, 1).is_err());
        assert_eq!(records, before);
        assert_eq!(records.advance(root(3), 3, 1, 1), Ok(true));
        let before = records;
        assert!(records.advance(root(3), 3, 2, 2).is_err());
        assert!(records.advance(root(3), 3, 1, 3).is_err());
        assert_eq!(records, before);
        assert_eq!(records.advance(root(3), 3, 1, 1), Ok(false));
        assert_eq!(records, before);
    }
    #[test]
    fn two_full_root_generations_progress_without_account_aliasing() {
        let mut records = Checkpoints::default();
        assert!(!records.both(1));
        records.advance(root(3), 3, 1, 1).unwrap();
        records.advance(root(4), 4, 2, 1).unwrap();
        assert!(records.both(1));
        let before = records;
        assert!(records.advance(root(5), 5, 1, 1).is_err());
        let mut reused = root(3);
        reused.generation += 1;
        assert!(records.advance(reused, 3, 1, 1).is_err());
        assert_eq!(records, before);
        for phase in 2..=5 {
            records.advance(root(3), 3, 1, phase).unwrap();
            records.advance(root(4), 4, 2, phase).unwrap();
        }
        assert!(records.both(5));
        let before = records;
        assert!(records.advance(root(3), 3, 1, 4).is_err());
        assert_eq!(records, before);
    }
    #[test]
    fn packed_phase_keeps_registration_order_and_the_exact_root_generation() {
        let mut records = Checkpoints::default();
        records.advance(root(4), 4, 1, 1).unwrap();
        records.advance(root(3), 3, 1, 1).unwrap();
        records.advance(root(3), 3, 1, 2).unwrap();
        records.advance(root(3), 3, 1, 3).unwrap();
        assert_eq!(records.phase_pack(root(4)), 1 | (1 << 8) | (3 << 16));
        assert_eq!(records.phase_pack(root(3)), 3 | (1 << 8) | (3 << 16));
        let mut stale = root(4);
        stale.generation += 1;
        assert_eq!(records.phase_pack(stale), (1 << 8) | (3 << 16));
    }
    fn gate() -> RetiredGate {
        RetiredGate::new(
            17,
            3,
            2,
            root(3),
            proto_fs::OpenKey {
                slot: 0,
                generation: 4,
            },
            257,
        )
        .unwrap()
    }
    fn ready() -> proto_fs::DataOutcome {
        proto_fs::DataOutcome {
            phase: proto_fs::DataPhase::Ready,
            job: 257,
            result: proto_fs::DataResult::None,
        }
    }
    fn completed() -> proto_fs::DataOutcome {
        proto_fs::DataOutcome {
            phase: proto_fs::DataPhase::Completed,
            job: 257,
            result: proto_fs::DataResult::Bytes(0),
        }
    }
    #[test]
    fn gate_requires_actual_success_and_exact_owner_key_job() {
        let baseline = gate();
        let key = proto_fs::OpenKey {
            slot: 0,
            generation: 4,
        };
        let mut wrong = key;
        wrong.generation += 1;
        let mut wrong_job = ready();
        wrong_job.job += 1;
        for (label, key, before, after) in [
            (18, key, ready(), completed()),
            (17, wrong, ready(), completed()),
            (17, key, wrong_job, completed()),
            (17, key, completed(), completed()),
            (
                17,
                key,
                ready(),
                proto_fs::DataOutcome {
                    result: proto_fs::DataResult::FailedNoEffect(proto_fs::NO_SPACE),
                    ..completed()
                },
            ),
        ] {
            let mut g = baseline;
            assert!(!g.committed(label, key, before, after));
            assert_eq!(g, baseline);
        }
        let mut g = baseline;
        assert!(g.committed(17, key, ready(), completed()));
        assert!(g.paused());
        assert!(!g.committed(17, key, ready(), completed()));
    }
    #[test]
    fn armed_cancel_and_fired_ack_keep_distinct_observation_custody() {
        let key = proto_fs::OpenKey {
            slot: 0,
            generation: 4,
        };
        let mut g = gate();
        assert!(g.canceled_armed(17, 257));
        assert!(!g.canceled_armed(18, 257));
        assert!(!g.observed(17, 3, 2, root(3)));
        assert!(g.committed(17, key, ready(), completed()));
        // A lost Reply and original ACK leave the value-only Fired observation intact.
        assert!(!g.canceled_armed(17, 257));
        assert!(g.observed(17, 3, 2, root(3)));
        assert!(!g.observed(18, 3, 2, root(3)));
        assert!(!g.observed(17, 3, 3, root(3)));
        assert!(!g.observed(17, 4, 2, root(3)));
        let mut reused = root(3);
        reused.generation += 1;
        assert!(!g.observed(17, 3, 2, reused));
        assert!(!g.exact(17, 3, 2, root(3), key, 258));
    }
}
