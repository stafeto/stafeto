// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The table of the jobs of the loop: a request whose walk or whose calls to the data file service
//! go on in the steps of the loop (`main.rs`). A place is taken when the request is deferred; a
//! request that finds no place is answered busy (`STARTING`, which the clients ask again), so no
//! request ever does the work of a job inside its own step, however many clients ask at once.

/// The jobs the service holds at once.
pub const JOBS: usize = 8;
/// The jobs one session holds at once.
pub const PER_SESSION: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Every place is taken.
    Full,
    /// The session holds `PER_SESSION` places.
    PerSession,
}

/// The place for a job of the session `label`, given the labels of the places in use.
pub fn place(held: &[Option<u64>; JOBS], label: u64) -> Result<usize, Refused> {
    if held.iter().flatten().filter(|&&l| l == label).count() >= PER_SESSION {
        return Err(Refused::PerSession);
    }
    held.iter().position(Option::is_none).ok_or(Refused::Full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_table_and_a_session_at_its_share_are_refused() {
        let mut held = [None; JOBS];
        // Four sessions take two places each: the table is full, and the next session is refused.
        for label in 1..=4u64 {
            for _ in 0..PER_SESSION {
                let at = place(&held, label).unwrap();
                held[at] = Some(label);
            }
        }
        assert_eq!(place(&held, 5), Err(Refused::Full));
        // A session that holds its share is refused before the table is.
        let mut held = [None; JOBS];
        for _ in 0..PER_SESSION {
            let at = place(&held, 1).unwrap();
            held[at] = Some(1);
        }
        assert_eq!(place(&held, 1), Err(Refused::PerSession));
        assert!(place(&held, 2).is_ok());
        // A place that frees is taken again.
        held[0] = None;
        assert_eq!(place(&held, 1), Ok(0));
    }

    #[test]
    fn nine_clients_with_deep_paths_get_eight_places_and_one_busy() {
        let mut held = [None; JOBS];
        let mut busy = 0;
        for label in 1..=9u64 {
            match place(&held, label) {
                Ok(at) => held[at] = Some(label),
                Err(_) => busy += 1,
            }
        }
        assert_eq!(busy, 1);
    }
}
