// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The bounds and the choices of the accept queue of a listening
//! description: how much one SYN may rebuild, which half-open entry goes
//! first under pressure, how long a queue socket may stay silent, and how
//! many sockets a queue lacks. `net.rs` (which the host does not build) acts
//! on them; the tests here fix the rules.

/// Sockets of a queue one SYN may rebuild (release one that closed, build a
/// fresh one that listens). The step of the service has a bound of 18 369 ticks
/// (16 500 is the margin at which the probes warn); a rebuild is the costly part, so later SYNs reap the rest.
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
    /// Whether the first fresh socket that listens ends the work (the SYN's
    /// budget) or only the count of tries does (the build of a queue).
    ends_at_fresh: bool,
}

impl ReapBudget {
    pub const fn new() -> Self {
        Self {
            tried: 0,
            fresh: 0,
            ends_at_fresh: true,
        }
    }

    /// The work of one step that builds the sockets a queue lacks: it ends
    /// after `REBUILD_MAX` tries, whatever stands.
    pub const fn build() -> Self {
        Self {
            tried: 0,
            fresh: 0,
            ends_at_fresh: false,
        }
    }

    /// Whether another rebuild may start.
    pub const fn open(&self) -> bool {
        (self.fresh == 0 || !self.ends_at_fresh) && self.tried < REBUILD_MAX
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

/// The least age of a half-open socket that may be recycled, in
/// nanoseconds: about one retransmission timeout of the SYN-ACK, so that a
/// burst of legitimate handshakes is dropped and retried as before and only
/// stale entries are taken.
pub const EMBRYO_MIN_AGE_NS: u64 = 1_000_000_000;

/// Whether a half-open socket of this age may be recycled.
pub const fn recyclable(age_ns: u64) -> bool {
    age_ns >= EMBRYO_MIN_AGE_NS
}

/// Whether the place is still the orphan noted at `captured`: it is an
/// orphan now and was let go of at that time. A place given to another
/// stream since is not.
pub const fn same_orphan(is_orphan: bool, captured: u64, current: u64) -> bool {
    is_orphan && captured == current
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

/// The sockets the call that makes a queue (`listen`) builds at once: the
/// first ones, so that the listener accepts connections now, and no more than
/// one step may spend (`REBUILD_MAX`). The rest of the backlog is built by
/// `top_up` in the steps that follow.
pub const fn first_build(wanted: usize) -> usize {
    if wanted < REBUILD_MAX as usize {
        wanted
    } else {
        REBUILD_MAX as usize
    }
}

/// A SYN on the four of a queue socket that closed ends that socket (its
/// place is rebuilt) and goes on to the listening description as any other.
pub const fn closed_member_on_four(syn: bool, queue_socket: bool, closed: bool) -> bool {
    syn && queue_socket && closed
}

/// Whether the key a queue socket holds is the key of an earlier
/// connection: it has one and the connection it stands in now has another.
/// A socket that went back to LISTEN after an RST keeps its key until a SYN
/// finds it, and the SYN that takes it makes it a new connection at once.
pub const fn key_is_stale(has_key: bool, key_is_current: bool) -> bool {
    has_key && !key_is_current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_builds_at_most_one_step_of_sockets() {
        assert_eq!(first_build(1), 1);
        assert_eq!(first_build(3), 3);
        assert_eq!(first_build(4), 4);
        assert_eq!(first_build(5), usize::from(REBUILD_MAX));
        assert_eq!(first_build(16), usize::from(REBUILD_MAX));
    }

    #[test]
    fn the_rest_of_a_backlog_takes_whole_steps_of_builds() {
        // A queue of 16 is complete after four calls of 4, each within the
        // bound of a step, and `missing` counts it down exactly.
        let wanted = 16u8;
        let mut have = first_build(usize::from(wanted)) as u8;
        let mut steps = 1;
        while missing(wanted, have) > 0 {
            let mut b = ReapBudget::build();
            while b.open() && missing(wanted, have) > 0 {
                b.charge(true);
                have += 1;
            }
            assert!(b.tried() <= REBUILD_MAX);
            steps += 1;
        }
        assert_eq!((have, steps), (16, 4));
    }

    #[test]
    fn a_build_budget_goes_on_past_fresh_sockets_until_its_tries_end() {
        let mut b = ReapBudget::build();
        for _ in 0..REBUILD_MAX {
            assert!(b.open());
            b.charge(true);
        }
        assert!(!b.open());
    }

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
    fn a_place_given_to_another_stream_since_the_capture_is_not_released() {
        assert!(same_orphan(true, 500, 500));
        // Evicted and allocated again as a queue socket.
        assert!(!same_orphan(false, 500, 0));
        // Evicted and let go of again later.
        assert!(!same_orphan(true, 500, 900));
    }

    #[test]
    fn one_budget_for_a_syn_bounds_all_its_steps() {
        // The closed four, the reap and the recycling share one budget: four
        // failed rebuilds in any mix end the work of the SYN.
        let mut b = ReapBudget::new();
        for _ in 0..3 {
            assert!(b.open());
            b.charge(false);
        }
        assert!(b.open());
        b.charge(false);
        assert!(!b.open());
        assert_eq!(b.tried(), REBUILD_MAX);
    }

    #[test]
    fn only_stale_half_open_entries_are_recycled() {
        assert!(!recyclable(0));
        assert!(!recyclable(EMBRYO_MIN_AGE_NS - 1));
        assert!(recyclable(EMBRYO_MIN_AGE_NS));
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

    #[test]
    fn a_key_of_an_earlier_connection_is_replaced() {
        assert!(key_is_stale(true, false));
        assert!(!key_is_stale(true, true));
        assert!(!key_is_stale(false, false));
    }
}
