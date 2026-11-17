// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The bounds and the choices of the accept queue of a listening
//! description: how much one SYN may rebuild, which half-open entry goes
//! first under pressure, how long a queue socket may stay silent, and how
//! many sockets a queue lacks. `net.rs` (which the host does not build) acts
//! on them; the tests here fix the rules.

/// Sockets of a queue one SYN may rebuild (release one that closed, build a
/// fresh one that listens). The step of the service is bound at 16 500 ticks;
/// a rebuild is the costly part, so later SYNs reap the rest.
pub const REBUILD_MAX: u8 = 4;

/// How long a connection that has not finished its handshake (SYN-RECEIVED)
/// may stay in a queue, in seconds.
pub const EMBRYO_S: u64 = 30;

/// How long a connection that is established, not yet accepted and silent
/// may stay in a queue, in seconds.
pub const QUEUE_IDLE_S: u64 = 120;

/// The work one SYN spends on the queues of its listening description: it
/// ends when one fresh socket that listens stands for the SYN, or when
/// `REBUILD_MAX` rebuilds have been tried.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReapBudget {
    tried: u8,
    fresh: u8,
}

impl ReapBudget {
    pub const fn new() -> Self {
        Self { tried: 0, fresh: 0 }
    }

    /// Whether another rebuild may start.
    pub const fn open(&self) -> bool {
        self.fresh == 0 && self.tried < REBUILD_MAX
    }

    /// One rebuild was tried; `built` tells whether a fresh socket stands.
    pub fn charge(&mut self, built: bool) {
        self.tried += 1;
        if built {
            self.fresh += 1;
        }
    }

    pub const fn tried(&self) -> u8 {
        self.tried
    }
}

/// The timeout of a queue socket that left LISTEN, in seconds.
pub const fn member_timeout_s(established: bool) -> u64 {
    if established { QUEUE_IDLE_S } else { EMBRYO_S }
}

/// The half-open entry to recycle: of the entries offered `(place, left_at)`
/// the one that left LISTEN first (the first offered among equals).
#[derive(Clone, Copy, Debug, Default)]
pub struct Oldest(Option<(usize, u64)>);

impl Oldest {
    pub const fn new() -> Self {
        Self(None)
    }

    pub fn offer(&mut self, place: usize, left_at: u64) {
        if self.0.is_none_or(|(_, at)| left_at < at) {
            self.0 = Some((place, left_at));
        }
    }

    pub fn place(&self) -> Option<usize> {
        self.0.map(|(place, _)| place)
    }
}

/// How many sockets a queue lacks of the backlog that was asked for.
pub const fn missing(wanted: u8, have: u8) -> u8 {
    wanted.saturating_sub(have)
}

/// A SYN on the four of a queue socket that closed ends that socket (its
/// place is rebuilt) and goes on to the listening description as any other.
pub const fn closed_member_on_four(syn: bool, queue_socket: bool, closed: bool) -> bool {
    syn && queue_socket && closed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_fresh_socket_ends_the_reap() {
        let mut b = ReapBudget::new();
        assert!(b.open());
        b.charge(true);
        assert!(!b.open());
        assert_eq!(b.tried(), 1);
    }

    #[test]
    fn sixty_four_closed_sockets_cost_one_syn_four_rebuilds_at_most() {
        // The sockets cannot be built: every try fails, and the SYN stops
        // after REBUILD_MAX of the 64.
        let mut b = ReapBudget::new();
        let mut tried = 0;
        for _ in 0..64 {
            if !b.open() {
                break;
            }
            b.charge(false);
            tried += 1;
        }
        assert_eq!(tried, usize::from(REBUILD_MAX));
        // Built ones stop at the first.
        let mut b = ReapBudget::new();
        let mut tried = 0;
        for _ in 0..64 {
            if !b.open() {
                break;
            }
            b.charge(true);
            tried += 1;
        }
        assert_eq!(tried, 1);
    }

    #[test]
    fn the_oldest_half_open_entry_goes_first() {
        let mut o = Oldest::new();
        assert_eq!(o.place(), None);
        for (place, at) in [(7, 300), (3, 100), (9, 200)] {
            o.offer(place, at);
        }
        assert_eq!(o.place(), Some(3));
        let mut o = Oldest::new();
        o.offer(7, 100);
        o.offer(3, 100);
        assert_eq!(o.place(), Some(7));
    }

    #[test]
    fn half_open_entries_time_out_sooner_than_established_ones() {
        assert_eq!(member_timeout_s(false), 30);
        assert_eq!(member_timeout_s(true), 120);
        assert!(member_timeout_s(false) < member_timeout_s(true));
    }

    #[test]
    fn a_short_queue_is_topped_up_to_the_backlog() {
        assert_eq!(missing(16, 13), 3);
        assert_eq!(missing(16, 0), 16);
        assert_eq!(missing(4, 4), 0);
        assert_eq!(missing(4, 5), 0);
    }

    #[test]
    fn a_syn_on_the_four_of_a_closed_queue_socket_is_not_sent_to_it() {
        assert!(closed_member_on_four(true, true, true));
        assert!(!closed_member_on_four(false, true, true));
        assert!(!closed_member_on_four(true, false, true));
        assert!(!closed_member_on_four(true, true, false));
    }
}
