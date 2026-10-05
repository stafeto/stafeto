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
}
