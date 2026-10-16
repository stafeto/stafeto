// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One completed dispatch, using the existing service clock and send accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StepSample {
    pub kind: usize,
    pub detail: u64,
    pub whole: u64,
    pub waited: u64,
    pub took: u64,
    pub accounting_valid: bool,
}
impl StepSample {
    pub fn measured(kind: usize, detail: u64, whole: u64, counted: u64) -> Self {
        let waited = counted.min(whole);
        Self {
            kind,
            detail,
            whole,
            waited,
            took: whole - waited,
            accounting_valid: counted <= whole,
        }
    }

    /// The sample with `ran`, the CPU ticks of the thread in the step, as
    /// its own part when that is shorter than the clock's: a thread of a
    /// higher level that ran in the middle lengthens `whole`, not `ran`.
    /// 0 stands for a thread that could not read its time.
    pub fn cpu(mut self, ran: u64) -> Self {
        if ran != 0 {
            self.took = self.took.min(ran);
        }
        self
    }
}
/// The reply/maintenance tail completes before the existing end clock is read.
#[inline(always)]
pub fn finish_after<T>(dispatch: impl FnOnce(), finish: impl FnOnce() -> T) -> T {
    dispatch();
    finish()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_actual_leader_wait_is_removed_from_complete_dispatch() {
        let s = StepSample::measured(58, 16, 20410, 300);
        assert_eq!((s.whole, s.waited, s.took), (20410, 300, 20110));
        assert!(s.accounting_valid);
        assert_eq!((s.kind, s.detail), (58, 16));
    }
    #[test]
    fn a_thread_above_that_ran_in_the_middle_is_not_the_steps() {
        let s = StepSample::measured(50, 32, 22_349, 0).cpu(19_699);
        assert_eq!((s.whole, s.waited, s.took), (22_349, 0, 19_699));
        // A reading longer than the clock's part, or none, changes nothing.
        assert_eq!(StepSample::measured(50, 32, 100, 10).cpu(500).took, 90);
        assert_eq!(StepSample::measured(50, 32, 100, 10).cpu(0).took, 90);
    }

    #[test]
    fn excess_wait_is_visible_and_never_underflows() {
        let s = StepSample::measured(65, 32, 17, 18);
        assert_eq!((s.whole, s.waited, s.took), (17, 17, 0));
        assert!(!s.accounting_valid);
    }
    #[test]
    fn final_reply_tail_is_part_of_completed_sample() {
        let clock = core::cell::Cell::new(0);
        let sample = finish_after(
            || {
                clock.set(900);
                clock.set(clock.get() + 211);
            },
            || StepSample::measured(54, 0, clock.get(), 11),
        );
        assert_eq!(sample.took, 1100);
    }
}
