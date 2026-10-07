// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! CPU journal borrowed from the sole current ingress frame.

use crate::{
    image::ImageHold,
    storage::{Root, Token},
};

pub const WORDS: usize = 11;
const _: () = assert!(core::mem::size_of::<[u64; WORDS]>() == 88);
const _: () = assert!(core::mem::align_of::<[u64; WORDS]>() == 8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Phase {
    Idle,
    Info,
    Validate,
    Map,
    Copy,
    Unmap,
    Close,
    Finish,
}

pub struct Loan<'a>(&'a mut [u64; WORDS]);
impl<'a> Loan<'a> {
    pub fn new(words: &'a mut [u64; WORDS]) -> Self {
        Self(words)
    }
    pub fn phase(&self) -> Phase {
        match self.0[0] {
            0 => Phase::Idle,
            1 => Phase::Info,
            2 => Phase::Validate,
            3 => Phase::Map,
            4 => Phase::Copy,
            5 => Phase::Unmap,
            6 => Phase::Close,
            7 => Phase::Finish,
            _ => panic!("current loan phase"),
        }
    }
    pub fn begin(&mut self, fd: u32, count: u32, offset: u64, at: u64, image: ImageHold) {
        assert_eq!(self.phase(), Phase::Idle);
        assert!(count <= 12288);
        self.0[1] = (u64::from(count) << 32) | u64::from(fd);
        self.0[2] = offset;
        self.0[3] = at;
        self.0[7] = (u64::from(image.entry) << 16) | u64::from(image.token.slot);
        self.0[8] = image.token.generation;
        self.0[9] = image.root.id;
        self.0[10] = image.root.generation;
        self.set_phase(Phase::Info);
    }
    pub fn set_phase(&mut self, phase: Phase) {
        self.0[0] = phase as u64;
    }
    pub fn fd(&self) -> u32 {
        self.0[1] as u32
    }
    pub fn count(&self) -> usize {
        (self.0[1] >> 32) as usize
    }
    pub fn offset(&self) -> u64 {
        self.0[2]
    }
    pub fn at(&self) -> u64 {
        self.0[3]
    }
    pub fn size(&self) -> u64 {
        self.0[4]
    }
    pub fn set_size(&mut self, size: u64) {
        self.0[4] = size;
    }
    pub fn copied(&self) -> usize {
        let copied = self.0[5] as usize;
        assert!(copied <= self.count());
        copied
    }
    pub fn advance(&mut self, n: usize) {
        let copied = self.copied().checked_add(n).expect("bounded copy count");
        assert!(copied <= self.count());
        self.0[5] = copied as u64;
    }
    pub fn status(&self) -> u32 {
        self.0[6] as u32
    }
    pub fn fail(&mut self, code: u32, next: Phase) {
        self.0[6] = u64::from(code);
        self.set_phase(next);
    }
    pub fn image(&self) -> ImageHold {
        assert_eq!(self.0[7] >> 32, 0);
        ImageHold {
            token: Token {
                slot: self.0[7] as u16,
                generation: self.0[8],
            },
            entry: (self.0[7] >> 16) as u16,
            root: Root {
                id: self.0[9],
                generation: self.0[10],
            },
        }
    }
    pub fn next_offset(&self) -> Option<u64> {
        self.offset().checked_add(self.copied() as u64)
    }
    pub fn remaining(&self) -> usize {
        self.count() - self.copied()
    }
    pub fn reset(&mut self) {
        self.0.fill(0);
    }
}

/// Adapter owns effects; the journal contains scalar progress only.
pub trait Effects {
    fn info(&mut self) -> u64;
    fn incoming(&self) -> usize;
    fn busy(&self) -> bool;
    fn admit(&mut self, count: usize);
    fn map(&mut self, at: u64) -> Result<(), (u32, bool)>;
    fn copy(
        &mut self,
        image: ImageHold,
        offset: u64,
        copied: usize,
        remaining: usize,
    ) -> Result<(usize, usize), u32>;
    fn unmap(&mut self) -> Result<(), u32>;
    fn close(&mut self) -> bool;
    fn wake_due(&mut self);
}
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    Idle,
    Continue,
    Finish { code: u32, count: u32 },
}
impl Loan<'_> {
    /// Execute one bounded phase, preserving the original error and copy count.
    pub fn step(&mut self, effects: &mut impl Effects) -> Progress {
        match self.phase() {
            Phase::Idle => return Progress::Idle,
            Phase::Info => {
                self.set_size(effects.info());
                self.set_phase(Phase::Validate);
            }
            Phase::Validate => {
                if !crate::read_into_valid(
                    self.fd(),
                    self.count(),
                    self.at(),
                    effects.incoming(),
                    true,
                    self.size(),
                ) {
                    self.fail(proto_wire::Status::BadSize.code(), Phase::Finish);
                } else if effects.busy() {
                    self.fail(proto_fs::RESOLVING, Phase::Finish);
                } else {
                    effects.admit(self.count());
                    self.set_phase(if self.count() == 0 {
                        Phase::Close
                    } else {
                        Phase::Map
                    });
                }
            }
            Phase::Map => match effects.map(self.at()) {
                Ok(()) => self.set_phase(Phase::Copy),
                Err((code, ambiguous)) => self.fail(
                    code,
                    if ambiguous {
                        Phase::Unmap
                    } else {
                        Phase::Close
                    },
                ),
            },
            Phase::Copy => {
                let result = self
                    .next_offset()
                    .ok_or(proto_fs::INVALID_ARGUMENT)
                    .and_then(|offset| {
                        effects.copy(self.image(), offset, self.copied(), self.remaining())
                    });
                match result {
                    Ok((n, requested)) => {
                        assert!(
                            requested <= 1024 && n <= requested && requested <= self.remaining()
                        );
                        self.advance(n);
                        if n < requested || requested == 0 || self.remaining() == 0 {
                            self.set_phase(Phase::Unmap);
                        }
                    }
                    Err(code) => self.fail(code, Phase::Unmap),
                }
            }
            Phase::Unmap => match effects.unmap() {
                Ok(()) => self.set_phase(Phase::Close),
                Err(code) => {
                    self.fail(code, Phase::Finish);
                    effects.wake_due();
                }
            },
            Phase::Close => {
                if !effects.close() {
                    effects.wake_due();
                }
                self.set_phase(Phase::Finish);
            }
            Phase::Finish => {
                let code = self.status();
                let count = if code == 0 { self.copied() as u32 } else { 0 };
                self.reset();
                return Progress::Finish { code, count };
            }
        }
        Progress::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_identity_and_checked_copy_survive_each_visit_then_reset() {
        let image = ImageHold {
            token: Token {
                slot: 511,
                generation: u64::MAX,
            },
            entry: 65535,
            root: Root {
                id: u64::MAX - 1,
                generation: u64::MAX - 2,
            },
        };
        let mut words = [0; WORDS];
        let mut loan = Loan::new(&mut words);
        loan.begin(0, 12288, u64::MAX - 512, 4096, image);
        assert_eq!(loan.image(), image);
        assert_eq!(loan.next_offset(), Some(u64::MAX - 512));
        loan.advance(1024);
        assert_eq!(loan.next_offset(), None);
        loan.fail(77, Phase::Unmap);
        assert_eq!(loan.status(), 77);
        assert_eq!(loan.image(), image);
        assert_eq!(loan.copied(), 1024);
        loan.reset();
        assert_eq!(words, [0; WORDS]);
    }
    #[test]
    #[should_panic(expected = "current loan phase")]
    fn invalid_phase_fails_the_journal_invariant() {
        let mut words = [0; WORDS];
        words[0] = 8;
        let _ = Loan::new(&mut words).phase();
    }
}

#[cfg(test)]
mod phase_tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;
    struct Fixture {
        events: Vec<&'static str>,
        size: u64,
        busy: bool,
        mapped: bool,
        owner: Option<u64>,
        map_error: Option<(u32, bool)>,
        unmap_error: bool,
        close_error: bool,
        copy_error: bool,
        eof: usize,
        wake: bool,
    }
    impl Default for Fixture {
        fn default() -> Self {
            Self {
                events: Vec::new(),
                size: 16384,
                busy: false,
                mapped: false,
                owner: None,
                map_error: None,
                unmap_error: false,
                close_error: false,
                copy_error: false,
                eof: 12288,
                wake: false,
            }
        }
    }
    impl Effects for Fixture {
        fn info(&mut self) -> u64 {
            self.events.push("info");
            self.size
        }
        fn incoming(&self) -> usize {
            1
        }
        fn busy(&self) -> bool {
            self.busy
        }
        fn admit(&mut self, _: usize) {
            assert!(self.owner.is_none());
            self.owner = Some(u64::MAX);
        }
        fn map(&mut self, _: u64) -> Result<(), (u32, bool)> {
            self.events.push("map");
            self.mapped = self.map_error.is_none_or(|(_, ambiguous)| ambiguous);
            self.map_error.map_or(Ok(()), Err)
        }
        fn copy(
            &mut self,
            image: ImageHold,
            offset: u64,
            copied: usize,
            remaining: usize,
        ) -> Result<(usize, usize), u32> {
            self.events.push("copy");
            assert!(self.mapped);
            assert_eq!(image.root.id, u64::MAX);
            assert_eq!(image.token.generation, 33);
            if self.copy_error {
                return Err(97);
            }
            let count = 1024.min(4096 - offset as usize % 4096).min(remaining);
            Ok((count.min(self.eof.saturating_sub(copied)), count))
        }
        fn unmap(&mut self) -> Result<(), u32> {
            self.events.push("unmap");
            assert!(self.mapped);
            if self.unmap_error {
                Err(98)
            } else {
                self.mapped = false;
                Ok(())
            }
        }
        fn close(&mut self) -> bool {
            self.events.push("close");
            assert!(!self.mapped);
            assert_eq!(self.owner, Some(u64::MAX));
            if self.close_error {
                false
            } else {
                self.owner = None;
                true
            }
        }
        fn wake_due(&mut self) {
            self.wake = true;
        }
    }
    fn begin(words: &mut [u64; WORDS], count: u32, offset: u64) -> Loan<'_> {
        let mut loan = Loan::new(words);
        loan.begin(
            0,
            count,
            offset,
            4096,
            ImageHold {
                token: Token {
                    slot: 32,
                    generation: 33,
                },
                entry: 7,
                root: Root {
                    id: u64::MAX,
                    generation: u64::MAX - 1,
                },
            },
        );
        loan
    }
    fn settle(loan: &mut Loan<'_>, fixture: &mut Fixture) -> (u32, u32) {
        for _ in 0..32 {
            let before = fixture.events.len();
            let progress = loan.step(fixture);
            assert!(fixture.events.len() - before <= 1, "combined effects");
            match progress {
                Progress::Continue => (),
                Progress::Finish { code, count } => {
                    assert_eq!(loan.phase(), Phase::Idle);
                    return (code, count);
                }
                Progress::Idle => panic!("missing response"),
            }
        }
        panic!("unbounded request loan")
    }
    #[test]
    fn full_count_and_unaligned_source_copy_have_separate_effects_and_exact_total() {
        let mut words = [0; WORDS];
        let mut fixture = Fixture::default();
        assert_eq!(
            settle(&mut begin(&mut words, 12288, 4095), &mut fixture),
            (0, 12288)
        );
        assert_eq!(&fixture.events[..2], &["info", "map"]);
        assert_eq!(
            fixture
                .events
                .iter()
                .filter(|event| **event == "copy")
                .count(),
            13
        );
        assert_eq!(
            &fixture.events[fixture.events.len() - 2..],
            &["unmap", "close"]
        );
        assert!(fixture.owner.is_none());
        assert!(!fixture.wake);
    }
    #[test]
    fn zero_count_still_checks_info_and_busy_before_close_without_mapping() {
        for busy in [false, true] {
            let mut words = [0; WORDS];
            let mut fixture = Fixture {
                busy,
                ..Default::default()
            };
            assert_eq!(
                settle(&mut begin(&mut words, 0, 0), &mut fixture),
                (if busy { proto_fs::RESOLVING } else { 0 }, 0)
            );
            assert_eq!(
                fixture.events,
                if busy {
                    std::vec!["info"]
                } else {
                    std::vec!["info", "close"]
                }
            );
        }
    }
    #[test]
    fn info_failure_keeps_bad_size_priority_over_busy_and_never_maps() {
        let mut words = [0; WORDS];
        let mut fixture = Fixture {
            size: 0,
            busy: true,
            ..Default::default()
        };
        assert_eq!(
            settle(&mut begin(&mut words, 1, 0), &mut fixture),
            (proto_wire::Status::BadSize.code(), 0)
        );
        assert_eq!(fixture.events, ["info"]);
    }
    #[test]
    fn map_canonical_failure_closes_and_ambiguous_failure_revokes_exact_attempt_first() {
        for ambiguous in [false, true] {
            let mut words = [0; WORDS];
            let mut fixture = Fixture {
                map_error: Some((96, ambiguous)),
                ..Default::default()
            };
            assert_eq!(
                settle(&mut begin(&mut words, 1024, 0), &mut fixture),
                (96, 0)
            );
            assert_eq!(
                fixture.events,
                if ambiguous {
                    std::vec!["info", "map", "unmap", "close"]
                } else {
                    std::vec!["info", "map", "close"]
                }
            );
            assert!(fixture.owner.is_none());
        }
    }
    #[test]
    fn unmap_fault_detaches_exact_memory_and_mapping_with_separate_wake_debt() {
        let mut words = [0; WORDS];
        let mut fixture = Fixture {
            unmap_error: true,
            ..Default::default()
        };
        assert_eq!(
            settle(&mut begin(&mut words, 1024, 0), &mut fixture),
            (98, 0)
        );
        assert_eq!(fixture.owner, Some(u64::MAX));
        assert!(fixture.mapped && fixture.wake);
        assert_eq!(fixture.events, ["info", "map", "copy", "unmap"]);
    }
    #[test]
    fn close_fault_preserves_successful_count_and_exact_unmapped_owner() {
        let mut words = [0; WORDS];
        let mut fixture = Fixture {
            close_error: true,
            eof: 313,
            ..Default::default()
        };
        assert_eq!(
            settle(&mut begin(&mut words, 1024, 0), &mut fixture),
            (0, 313)
        );
        assert_eq!(fixture.owner, Some(u64::MAX));
        assert!(!fixture.mapped && fixture.wake);
    }
    #[test]
    fn stale_or_copy_error_has_zero_response_count_and_distinct_unmap_close() {
        let mut words = [0; WORDS];
        let mut fixture = Fixture::default();
        let mut loan = begin(&mut words, 2048, 0);
        for _ in 0..4 {
            assert_eq!(loan.step(&mut fixture), Progress::Continue);
        }
        assert_eq!(loan.copied(), 1024);
        fixture.copy_error = true;
        assert_eq!(settle(&mut loan, &mut fixture), (97, 0));
        assert_eq!(
            &fixture.events[fixture.events.len() - 3..],
            &["copy", "unmap", "close"]
        );
    }
    #[test]
    fn checked_offset_overflow_reports_fault_after_prefix_without_another_copy() {
        let mut words = [0; WORDS];
        let mut fixture = Fixture::default();
        assert_eq!(
            settle(&mut begin(&mut words, 1024, u64::MAX), &mut fixture),
            (proto_fs::INVALID_ARGUMENT, 0)
        );
        assert_eq!(
            fixture
                .events
                .iter()
                .filter(|event| **event == "copy")
                .count(),
            1
        );
    }
}
