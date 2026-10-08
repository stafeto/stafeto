// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

pub fn receive<T, E: PartialEq>(
    deadline: u64,
    interrupted: E,
    mut receive_until: impl FnMut(u64) -> Result<T, E>,
) -> Result<T, E> {
    loop {
        match receive_until(deadline) {
            Err(error) if error == interrupted => continue,
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Received {
        Got,
        Expired,
    }

    fn check(sequence: &[Result<Received, u64>], expected: Result<Received, u64>) {
        let deadline = 0xfedc_ba98_7654_3210;
        let mut calls = 0;
        let result = receive(deadline, 10, |actual_deadline| {
            assert_eq!(actual_deadline, deadline);
            let result = sequence[calls];
            calls += 1;
            result
        });
        assert_eq!(result, expected);
        assert_eq!(calls, sequence.len());
    }

    #[test]
    fn interruptions_preserve_the_absolute_deadline_until_got() {
        check(&[Err(10), Err(10), Ok(Received::Got)], Ok(Received::Got));
    }

    #[test]
    fn expiry_is_returned_without_synthetic_success() {
        check(&[Err(10), Ok(Received::Expired)], Ok(Received::Expired));
    }

    #[test]
    fn other_errors_including_unknown_are_returned_unchanged() {
        for error in [3, u64::MAX] {
            check(&[Err(10), Err(error)], Err(error));
        }
    }

    #[test]
    fn immediate_got_does_not_receive_again() {
        check(&[Ok(Received::Got)], Ok(Received::Got));
    }

    #[test]
    fn armed_poll_retries_receive_without_rearming() {
        let deadline = 123_456;
        let timer_sets = core::cell::Cell::new(0);
        let arm = |actual_deadline| {
            assert_eq!(actual_deadline, deadline);
            timer_sets.set(timer_sets.get() + 1);
        };
        arm(deadline);
        let sequence = [Err(10), Err(10), Ok(Received::Got)];
        let mut calls = 0;
        let result = receive(deadline, 10, |actual_deadline| {
            assert_eq!(actual_deadline, deadline);
            let result = sequence[calls];
            calls += 1;
            result
        });
        assert_eq!(result, Ok(Received::Got));
        assert_eq!(calls, 3);
        assert_eq!(timer_sets.get(), 1);
    }
}
