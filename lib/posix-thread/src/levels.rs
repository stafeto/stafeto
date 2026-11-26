// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The levels of the POSIX priorities of a process, as arithmetic the host
//! tests: where a policy and priority land under the process's top level and
//! its ceiling, and what level and top a child of a spawn or exec starts
//! with (`posix_abi::sched` makes the calls).
//!
//! The top is the level SCHED_FIFO and SCHED_RR priority 32 map to; a child
//! that starts below its parent keeps the parent's top (carried in its start
//! word), so that its own priorities map as its parent's did. The ceiling
//! is the process's: a thread's level stays strictly below it, where the
//! holders of the layer's locks run.

pub const SCHED_OTHER: i32 = 0;
pub const SCHED_FIFO: i32 = 1;
pub const SCHED_RR: i32 = 2;
/// The least and the greatest priority of SCHED_FIFO and SCHED_RR.
pub const MIN_PRIORITY: i32 = 1;
pub const MAX_PRIORITY: i32 = 32;

const EPERM: i32 = 1;
const EINVAL: i32 = 22;

/// The level of SCHED_OTHER under `top`: below the room of the priorities
/// when there is room for them; a process with less room keeps it at the top.
pub const fn other_level(top: u8) -> u8 {
    if top as i32 > MAX_PRIORITY {
        top - MAX_PRIORITY as u8
    } else {
        top
    }
}

/// The highest level a thread of a process with `ceiling` may have: one
/// below it, at least 1.
pub const fn highest(ceiling: u8) -> u8 {
    if ceiling > 1 { ceiling - 1 } else { 1 }
}

/// The highest level a thread may be given under `top` and `ceiling`: one
/// below the ceiling, or the top itself when the top is the process's own
/// (a process whose ceiling is its top, such as init's POSIX_FILES_TABLE,
/// keeps the mapping it had); a top inherited from a parent is above what
/// the ceiling allows.
pub const fn most(top: u8, ceiling: u8, inherited: bool) -> u8 {
    let below = highest(ceiling);
    if !inherited && top > below {
        top
    } else {
        below
    }
}

/// The base level of `policy` and `priority` under `top` and `ceiling`:
/// EINVAL for a policy or priority out of range, EPERM for a level the
/// ceiling does not allow (SCHED_OTHER goes down to the highest level that
/// is allowed, as it has no priority to refuse). `inherited`: the top came
/// from the parent's start word.
pub fn level_for(
    policy: i32,
    priority: i32,
    top: u8,
    ceiling: u8,
    inherited: bool,
) -> Result<u8, i32> {
    let most = most(top, ceiling, inherited);
    match policy {
        SCHED_OTHER if priority == 0 => Ok(other_level(top).min(most)),
        SCHED_FIFO | SCHED_RR if (MIN_PRIORITY..=MAX_PRIORITY).contains(&priority) => {
            // At least one above SCHED_OTHER, at most the top.
            let level = (i32::from(top) - MAX_PRIORITY + priority).max(1);
            if level > i32::from(most) {
                Err(EPERM)
            } else {
                Ok(level as u8)
            }
        }
        _ => Err(EINVAL),
    }
}

/// The level of a priority-protect mutex of ceiling `priority`: the level of
/// the priority, held down to the highest a thread may have (a mutex asks
/// for no error beyond EINVAL for a priority out of range, so it is clamped,
/// not refused).
pub fn protect_level(priority: i32, top: u8, ceiling: u8, inherited: bool) -> Result<u8, i32> {
    if !(MIN_PRIORITY..=MAX_PRIORITY).contains(&priority) {
        return Err(EINVAL);
    }
    let level = (i32::from(top) - MAX_PRIORITY + priority).max(1);
    Ok(level.min(i32::from(most(top, ceiling, inherited))) as u8)
}

/// Where a child of a spawn or exec starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Child {
    /// The level of its loader and its main thread's start.
    pub level: u8,
    /// A spawn with a scheduling that puts it below the caller's top: the
    /// process service gives it the ceiling of its level plus one.
    pub lowered: bool,
    /// The top its priorities map from, when it is not its start level.
    pub top: Option<u8>,
}

/// What a child starts with. `spec` is the scheduling the spawn asks for (None:
/// the caller's own, `own`), `own_level` the base level of the calling thread,
/// `top` the caller's top, `inherited` whether that top came from a parent
/// that started below its own, `ceiling` the caller's process's.
pub fn child_start(
    spec: Option<(i32, i32)>,
    own: (i32, i32),
    own_level: u8,
    top: u8,
    inherited: bool,
    ceiling: u8,
) -> Result<Child, i32> {
    let (policy, priority) = spec.unwrap_or(own);
    let level = level_for(policy, priority, top, ceiling, inherited)?;
    let real_time = matches!(policy, SCHED_FIFO | SCHED_RR);
    if spec.is_some() && real_time && level < top {
        return Ok(Child {
            level,
            lowered: true,
            top: Some(top),
        });
    }
    if inherited {
        return Ok(Child {
            level: if spec.is_some() { level } else { own_level },
            lowered: false,
            top: Some(top),
        });
    }
    Ok(Child {
        level: top,
        lowered: false,
        top: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_with_a_ceiling_above_its_top_maps_as_it_did() {
        // Top 30, ceiling 31.
        assert_eq!(level_for(SCHED_RR, 32, 30, 31, false), Ok(30));
        assert_eq!(level_for(SCHED_FIFO, 30, 30, 31, false), Ok(28));
        assert_eq!(level_for(SCHED_RR, 1, 30, 31, false), Ok(1));
        assert_eq!(level_for(SCHED_OTHER, 0, 30, 31, false), Ok(30));
        assert_eq!(level_for(SCHED_OTHER, 1, 30, 31, false), Err(EINVAL));
        assert_eq!(level_for(SCHED_RR, 33, 30, 31, false), Err(EINVAL));
        // Room for the priorities under the top: SCHED_OTHER is below them.
        assert_eq!(level_for(SCHED_OTHER, 0, 40, 41, false), Ok(8));
    }

    #[test]
    fn a_process_whose_ceiling_is_its_top_keeps_its_mapping() {
        // init's POSIX_FILES_TABLE: priority 40, ceiling 40.
        assert_eq!(level_for(SCHED_RR, 32, 40, 40, false), Ok(40));
        assert_eq!(level_for(SCHED_RR, 1, 40, 40, false), Ok(9));
        assert_eq!(level_for(SCHED_OTHER, 0, 40, 40, false), Ok(8));
        assert_eq!(most(40, 40, false), 40);
        assert_eq!(most(40, 40, true), 39);
        assert_eq!(most(30, 31, false), 30);
    }

    #[test]
    fn a_protect_mutex_is_clamped_to_what_a_thread_may_have() {
        // A lowered child: top 30 inherited, ceiling 29.
        assert_eq!(protect_level(30, 30, 29, true), Ok(28));
        assert_eq!(protect_level(32, 30, 29, true), Ok(28));
        assert_eq!(protect_level(5, 30, 29, true), Ok(3));
        // A process at its top: the mapping stays, also with ceiling == top.
        assert_eq!(protect_level(32, 40, 40, false), Ok(40));
        assert_eq!(protect_level(32, 30, 31, false), Ok(30));
        assert_eq!(protect_level(0, 30, 31, false), Err(EINVAL));
        assert_eq!(protect_level(33, 30, 31, false), Err(EINVAL));
    }

    #[test]
    fn a_top_inherited_above_the_ceiling_refuses_the_levels_it_has_no_room_for() {
        // The child of a spawn at RR 30 from top 30: level 28, ceiling 29.
        assert_eq!(level_for(SCHED_RR, 30, 30, 29, true), Ok(28));
        assert_eq!(level_for(SCHED_RR, 29, 30, 29, true), Ok(27));
        assert_eq!(level_for(SCHED_RR, 31, 30, 29, true), Err(EPERM));
        assert_eq!(level_for(SCHED_RR, 32, 30, 29, true), Err(EPERM));
        assert_eq!(level_for(SCHED_FIFO, 32, 30, 29, true), Err(EPERM));
        // SCHED_OTHER is not above what the process can take.
        assert_eq!(level_for(SCHED_OTHER, 0, 30, 29, true), Ok(28));
        assert_eq!(highest(29), 28);
        assert_eq!(highest(1), 1);
    }

    #[test]
    fn a_spawn_below_the_top_starts_there_and_carries_the_top() {
        let child = child_start(Some((SCHED_RR, 30)), (SCHED_OTHER, 0), 30, 30, false, 31).unwrap();
        assert_eq!(
            child,
            Child {
                level: 28,
                lowered: true,
                top: Some(30)
            }
        );
        // The same priority as the top: not below it.
        let same = child_start(Some((SCHED_RR, 32)), (SCHED_OTHER, 0), 30, 30, false, 31).unwrap();
        assert_eq!(
            same,
            Child {
                level: 30,
                lowered: false,
                top: None
            }
        );
        // SCHED_OTHER asked for explicitly does not lower the ceiling.
        let other = child_start(Some((SCHED_OTHER, 0)), (SCHED_RR, 5), 4, 30, false, 31).unwrap();
        assert!(!other.lowered);
    }

    #[test]
    fn a_plain_spawn_or_exec_from_a_lowered_child_stays_where_it_is() {
        // The lowered child: top 30 inherited, level 28, ceiling 29, RR 30.
        let plain = child_start(None, (SCHED_RR, 30), 28, 30, true, 29).unwrap();
        assert_eq!(
            plain,
            Child {
                level: 28,
                lowered: false,
                top: Some(30)
            }
        );
        // An explicit scheduling it may take.
        let lower = child_start(Some((SCHED_RR, 20)), (SCHED_RR, 30), 28, 30, true, 29).unwrap();
        assert_eq!(lower.level, 18);
        assert!(lower.lowered);
        // One it may not take.
        assert_eq!(
            child_start(Some((SCHED_RR, 32)), (SCHED_RR, 30), 28, 30, true, 29),
            Err(EPERM)
        );
        // A process that started at its top passes nothing on.
        let plain = child_start(None, (SCHED_OTHER, 0), 30, 30, false, 31).unwrap();
        assert_eq!(
            plain,
            Child {
                level: 30,
                lowered: false,
                top: None
            }
        );
    }
}
