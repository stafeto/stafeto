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

/// What `adopt` does with a socket of a queue after the stack took a SYN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRule {
    /// Leave the key as it is (none, or already the key of its connection).
    Keep,
    /// The socket listens again: its key goes.
    Release,
    /// The socket has no key and stands in a connection: it gets the key.
    Register,
    /// The socket holds the key of an earlier connection and stands in
    /// another: the old key goes and the new one is registered.
    Replace,
}

/// The rule of `adopt` for a queue socket: whether it listens, whether it
/// holds a key, and whether that key is the one of the connection it stands in.
pub const fn adopt_rule(listening: bool, has_key: bool, key_is_current: bool) -> KeyRule {
    match (listening, has_key, key_is_current) {
        (true, true, _) => KeyRule::Release,
        (true, false, _) => KeyRule::Keep,
        (false, false, _) => KeyRule::Register,
        (false, true, true) => KeyRule::Keep,
        (false, true, false) => KeyRule::Replace,
    }
}

/// Whether `sync` finds a queue socket back in LISTEN after a connection (the
/// peer's RST in SYN-RECEIVED): it holds the key of that connection, or it
/// took a SYN (`had_connection`) and its key never went in the table. The
/// key leaves the table and the socket is due for a replacement.
pub const fn back_in_listen(
    is_queue_socket: bool,
    listening: bool,
    has_key: bool,
    had_connection: bool,
) -> bool {
    is_queue_socket && listening && (has_key || had_connection)
}

/// Whether the rebuild of a queue replaces the socket: it closed, or it
/// listens again after a connection and holds the state of that one (its
/// round-trip sample, which can set the retransmission timeout of the next
/// connection up to a minute, and its choice of TCP timestamps).
pub const fn replaces(closed: bool, listening: bool, relistened: bool) -> bool {
    closed || (listening && relistened)
}

/// Whether `route` drops a SYN: its four is held by a queue socket in
/// SYN-RECEIVED. A socket of the set that listens would take the SYN and
/// hold a second half-open connection on the same four.
pub const fn drops_repeated_syn(syn: bool, is_queue_socket: bool, syn_received: bool) -> bool {
    syn && is_queue_socket && syn_received
}

/// How long the line of counters of the queues waits after the last one, in
/// nanoseconds, when counters changed, and when CONFIG asked for it.
pub const QUEUES_EVERY_NS: u64 = 30_000_000_000;
pub const QUEUES_ASKED_NS: u64 = 5_000_000_000;

/// Whether the line of the queue counters prints now. `said_at` is the time
/// of the last line (0 before the first one, which is the baseline of a
/// boot), `said_sum` the sum of the counters then. A CONFIG that asked
/// prints after `QUEUES_ASKED_NS`; any other call prints when a counter
/// changed and `QUEUES_EVERY_NS` have passed.
pub const fn queues_due(asked: bool, now: u64, said_at: u64, said_sum: u64, sum: u64) -> bool {
    let since = now.saturating_sub(said_at);
    if asked {
        since >= QUEUES_ASKED_NS
    } else {
        (sum != said_sum || said_at == 0) && since >= QUEUES_EVERY_NS
    }
}

/// Whether a queue socket in this state makes its listening description
/// due for a rebuild of its closed sockets: it closed (the peer's RST after
/// the handshake) and keeps its place and its debit of the room.
pub const fn marks_for_reap(is_queue_socket: bool, closed: bool) -> bool {
    is_queue_socket && closed
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

    #[test]
    fn the_rule_of_adopt_names_what_happens_to_the_key() {
        assert_eq!(adopt_rule(true, true, false), KeyRule::Release);
        assert_eq!(adopt_rule(true, false, false), KeyRule::Keep);
        assert_eq!(adopt_rule(false, false, false), KeyRule::Register);
        assert_eq!(adopt_rule(false, true, true), KeyRule::Keep);
        assert_eq!(adopt_rule(false, true, false), KeyRule::Replace);
    }

    #[test]
    fn a_queue_socket_back_in_listen_after_a_connection_is_due() {
        assert!(back_in_listen(true, true, true, true));
        assert!(back_in_listen(true, true, false, true));
        assert!(!back_in_listen(true, true, false, false));
        assert!(!back_in_listen(true, false, true, true));
        assert!(!back_in_listen(false, true, true, true));
    }

    #[test]
    fn the_rebuild_replaces_closed_and_relistened_sockets_only() {
        assert!(replaces(true, false, false));
        assert!(replaces(false, true, true));
        assert!(!replaces(false, true, false));
        assert!(!replaces(false, false, true));
    }

    #[test]
    fn only_a_syn_on_a_half_open_queue_socket_is_dropped() {
        assert!(drops_repeated_syn(true, true, true));
        assert!(!drops_repeated_syn(false, true, true));
        assert!(!drops_repeated_syn(true, false, true));
        assert!(!drops_repeated_syn(true, true, false));
    }

    #[test]
    fn the_queue_line_prints_the_baseline_then_changes_every_30_s() {
        let s = 1_000_000_000;
        // The baseline of a boot.
        assert!(queues_due(false, 31 * s, 0, 0, 0));
        assert!(!queues_due(false, 10 * s, 0, 0, 0));
        // Unchanged: nothing, however late.
        assert!(!queues_due(false, 500 * s, 40 * s, 7, 7));
        // Changed, but inside 30 s: later.
        assert!(!queues_due(false, 69 * s, 40 * s, 7, 8));
        assert!(queues_due(false, 70 * s, 40 * s, 7, 8));
        // CONFIG asked: 5 s apply, and the change is not needed.
        assert!(!queues_due(true, 44 * s, 40 * s, 7, 7));
        assert!(queues_due(true, 45 * s, 40 * s, 7, 7));
    }

    #[test]
    fn a_closed_queue_socket_marks_its_listener() {
        assert!(marks_for_reap(true, true));
        assert!(!marks_for_reap(true, false));
        assert!(!marks_for_reap(false, true));
    }

    /// Four listeners of a group, 16 sockets each: connections that were
    /// reset after the handshake leave closed sockets that keep their debit of
    /// room. The old rule reaps only when no listener has room (and stops at
    /// the first fresh socket), so the listeners the circle did not reach stay
    /// without room; the new rule rebuilds each marked listener at once.
    #[test]
    fn marked_listeners_are_rebuilt_without_waiting_for_the_group_to_fill() {
        // (room, closed) of each listener after a reset abuse.
        let abused = [(0u8, 4u8), (0, 6), (0, 1), (5, 0)];
        // Old: nobody reaps while listener 3 has room, listeners 0 to 2 stay out.
        let usable_old = abused.iter().filter(|l| l.0 > 0).count();
        assert_eq!(usable_old, 1);
        // New: each listener with a closed socket is rebuilt, `REBUILD_MAX` a step.
        let mut usable_new = 0;
        let mut steps = 0;
        for (room, closed) in abused {
            let mut left = closed;
            let mut room = room;
            while left > 0 {
                let n = left.min(REBUILD_MAX);
                left -= n;
                room += n;
                steps += 1;
            }
            usable_new += usize::from(room > 0);
        }
        assert_eq!(usable_new, 4);
        assert_eq!(steps, 4);
    }
}
