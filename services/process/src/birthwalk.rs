// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The passed walks owed one newborn delivery, before its thread starts.
//! A bit belongs to its resident walk until delivery or exact cancellation.
//! Callers clear it before replacing that walk, including sender reuse.

use crate::preparing::Key;
use crate::records::Records;
use crate::walk::Walk;
use proto_process::RECORDS;

pub struct BirthWalk {
    key: Option<Key>,
    eligible: [u64; RECORDS / 64],
    tty: Option<u64>,
}

impl BirthWalk {
    pub const fn new() -> Self {
        Self {
            key: None,
            eligible: [0; RECORDS / 64],
            tty: None,
        }
    }

    pub fn key(&self) -> Option<Key> {
        self.key
    }

    /// Pure bounded capture: the callback must neither deliver nor make SVC.
    pub fn capture(&mut self, key: Key, tty: Option<u64>, mut takes: impl FnMut(usize) -> bool) {
        assert!(self.key.is_none());
        self.key = Some(key);
        self.tty = tty;
        for sender in 0..RECORDS {
            if takes(sender) {
                self.eligible[sender / 64] |= 1 << (sender % 64);
            }
        }
    }

    pub fn holds(&self, sender: usize) -> bool {
        self.eligible[sender / 64] & (1 << (sender % 64)) != 0
    }

    pub fn clear(&mut self, sender: usize) {
        self.eligible[sender / 64] &= !(1 << (sender % 64));
    }

    pub fn next(&self) -> Option<usize> {
        self.eligible.iter().enumerate().find_map(|(word, bits)| {
            (*bits != 0).then(|| word * 64 + bits.trailing_zeros() as usize)
        })
    }

    pub fn tty(&self) -> Option<u64> {
        self.tty
    }
    pub fn clear_tty(&mut self) {
        self.tty = None;
    }

    pub fn release(&mut self, key: Key) -> bool {
        if self.key != Some(key) || self.next().is_some() || self.tty.is_some() {
            return false;
        }
        self.key = None;
        true
    }

    /// Authoritative removal of this exact newborn cancels its remaining debt.
    pub fn removed(&mut self, key: Key) -> bool {
        if self.key != Some(key) {
            return false;
        }
        self.eligible = [0; RECORDS / 64];
        self.tty = None;
        self.key = None;
        true
    }
}

/// The retained pending session names this exact sender image before the
/// cursor's eligibility can confer any delivery authority.
pub fn eligible<P, C>(
    walk: &Walk,
    records: &Records<P, C>,
    pending_label: u64,
    sender: usize,
    newborn: usize,
    pgid: u32,
) -> bool {
    records.find(pending_label) == Some(sender) && walk.takes_newborn(newborn, pgid)
}

impl Default for BirthWalk {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_process::Label;
    fn key(image: u32) -> Key {
        Key {
            label: Label {
                index: 7,
                generation: 3,
            },
            image,
        }
    }

    #[test]
    fn capture_visits_every_sender_without_delivering_and_retains_only_passed() {
        let mut birth = BirthWalk::new();
        let mut visits = 0;
        birth.capture(key(1), Some(u64::MAX), |sender| {
            visits += 1;
            sender % 17 == 0
        });
        assert_eq!(visits, RECORDS);
        assert_eq!(core::mem::size_of::<BirthWalk>(), 64);
        assert!(!birth.release(key(1)));
        while let Some(sender) = birth.next() {
            assert_eq!(sender % 17, 0);
            birth.clear(sender);
        }
        assert!(!birth.release(key(1)));
        birth.clear_tty();
        assert!(birth.release(key(1)));
    }

    #[test]
    fn canceled_sender_and_terminal_do_not_pass_eligibility_to_their_successors() {
        let mut birth = BirthWalk::new();
        birth.capture(key(1), Some(99), |sender| sender == 4);
        birth.clear(4);
        birth.clear_tty();
        assert!(!birth.holds(4));
        assert_eq!(birth.tty(), None);
        assert!(
            !birth.removed(key(2)),
            "late image removal must retain current debt"
        );
        assert_eq!(birth.key(), Some(key(1)));
        assert!(birth.release(key(1)));
        birth.capture(key(2), None, |_| false);
        assert!(!birth.holds(4));
        assert!(!birth.removed(key(1)));
        assert!(birth.release(key(2)));
    }

    #[test]
    fn pending_old_image_cannot_capture_authority_of_replaced_sender() {
        use crate::records::{Join, State};
        use crate::walk::{Step, Target};
        use proto_process::Credentials;
        let mut records = Records::<u32>::new();
        let sender = records.next_label().unwrap();
        records.insert(sender, 1, None, Credentials::ROOT, 31, Join::Inherit);
        let index = usize::from(sender.index);
        records.get_mut(index).unwrap().state = State::Alive;
        let pending_label = records.session_label(index).unwrap();
        let mut walk = Walk::new(Target::All, index);
        assert!(matches!(walk.step(&records), Step::Looked));
        assert!(eligible(
            &walk,
            &records,
            pending_label,
            index,
            index + 1,
            1
        ));
        records.get_mut(index).unwrap().image += 1;
        assert!(!eligible(
            &walk,
            &records,
            pending_label,
            index,
            index + 1,
            1
        ));
        assert!(eligible(
            &walk,
            &records,
            records.session_label(index).unwrap(),
            index,
            index + 1,
            1
        ));
    }
}
