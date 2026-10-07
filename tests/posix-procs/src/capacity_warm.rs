// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

pub fn initial_empty(previous: u32, sequence: u32, action: u32, idle: bool) -> bool {
    previous == 0 && sequence == 1 && action == 3 && idle
}

pub fn initial_ready(
    jobs: u32,
    preparations: u32,
    root_preparations: u32,
    free: u32,
    pages: u32,
    reclamation_pending: bool,
) -> bool {
    jobs == 0
        && preparations == 0
        && root_preparations == 0
        && free == 4096
        && pages == 0
        && !reclamation_pending
}

pub fn await_ready(
    mut attempt: impl FnMut() -> Result<(), i32>,
    mut pause: impl FnMut() -> Result<(), i32>,
    retry: i32,
    exhausted: i32,
) -> Result<(), i32> {
    for _ in 0..200_000 {
        match attempt() {
            Ok(()) => return Ok(()),
            Err(error) if error == retry => pause()?,
            Err(error) => return Err(error),
        }
    }
    Err(exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_first_empty_shutdown_can_skip_full_release() {
        assert!(initial_empty(0, 1, 3, true));
        for (previous, sequence, action, idle) in [
            (1, 2, 3, true),
            (0, 2, 3, true),
            (1, 1, 3, true),
            (0, 1, 1, true),
            (0, 1, 2, true),
            (0, 1, 3, false),
        ] {
            assert!(!initial_empty(previous, sequence, action, idle));
        }
    }
    #[test]
    fn failed_or_exhausted_readiness_aborts_and_success_is_never_replayed() {
        let mut attempts = 0;
        let mut pauses = 0;
        assert_eq!(
            await_ready(
                || {
                    attempts += 1;
                    if attempts < 3 { Err(22) } else { Ok(()) }
                },
                || {
                    pauses += 1;
                    Ok(())
                },
                22,
                5
            ),
            Ok(())
        );
        assert_eq!((attempts, pauses), (3, 2));
        attempts = 0;
        assert_eq!(
            await_ready(
                || {
                    attempts += 1;
                    Err(9)
                },
                || panic!("terminal error cannot pause"),
                22,
                5
            ),
            Err(9)
        );
        assert_eq!(attempts, 1);
        attempts = 0;
        assert_eq!(
            await_ready(
                || {
                    attempts += 1;
                    Err(22)
                },
                || Ok(()),
                22,
                5
            ),
            Err(5)
        );
        assert_eq!(attempts, 200_000);
        assert_eq!(await_ready(|| Err(22), || Err(7), 22, 5), Err(7));
    }
}
