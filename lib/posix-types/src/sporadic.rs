// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! SCHED_SPORADIC (XSH 2.8.4) in 0.5.0: the policy and the members of
//! `struct sched_param` (48 bytes, as relibc lays it out) exist for
//! compilation, and no thread can take the policy. The options are
//! announced as 0 in `<unistd.h>` ("supported for compilation, and might
//! or might not be supported at runtime"), and every call that would give
//! a thread the policy is refused here, whoever asks: root or not.

pub const EINVAL: i32 = 22;
pub const ENOTSUP: i32 = 95;

/// The policy number of SCHED_SPORADIC (the number Linux leaves free).
pub const SCHED_SPORADIC: i32 = 4;
/// SS_REPL_MAX of `<limits.h>`: the replenishments the kernel keeps pending.
pub const SS_REPL_MAX: i32 = 4;

/// `struct timespec` of the C library on AArch64.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// `struct sched_param` as relibc lays it out (tools/abi-layouts.c).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedParam {
    pub sched_priority: i32,
    pub sched_ss_low_priority: i32,
    pub sched_ss_repl_period: Timespec,
    pub sched_ss_init_budget: Timespec,
    pub sched_ss_max_repl: i32,
    pub _pad: i32,
}

const _: () = assert!(core::mem::size_of::<SchedParam>() == 48);
const _: () = assert!(core::mem::offset_of!(SchedParam, sched_ss_repl_period) == 8);
const _: () = assert!(core::mem::offset_of!(SchedParam, sched_ss_init_budget) == 24);
const _: () = assert!(core::mem::offset_of!(SchedParam, sched_ss_max_repl) == 40);

impl SchedParam {
    /// A parameter structure with this priority and the rest zero.
    pub const fn with_priority(sched_priority: i32) -> SchedParam {
        SchedParam {
            sched_priority,
            sched_ss_low_priority: 0,
            sched_ss_repl_period: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            sched_ss_init_budget: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            sched_ss_max_repl: 0,
            _pad: 0,
        }
    }
}

/// The calls that can give a thread a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    /// `sched_setscheduler`.
    SetScheduler,
    /// `sched_setparam` and `pthread_setschedprio` keep the policy.
    SetParam,
    /// `pthread_setschedparam`.
    ThreadSetParam,
    /// `pthread_create` with `PTHREAD_EXPLICIT_SCHED` and a policy in its
    /// attributes (the attribute object refuses the policy first).
    ThreadCreate,
    /// `posix_spawn` with `POSIX_SPAWN_SETSCHEDULER`.
    Spawn,
    /// `pthread_attr_setschedpolicy` and `posix_spawnattr_setschedpolicy`:
    /// the first refuses (relibc), the second records it for the spawn.
    AttrSetPolicy,
}

/// The error a call gives for `policy` when the policy is not supported at
/// this run: None for another policy. EINVAL for the calls whose XSH ERRORS
/// say the policy is invalid, ENOTSUP where the attribute object is asked
/// (XSH `pthread_attr_setschedpolicy`: "[ENOTSUP] An attempt was made to set
/// the attribute to an unsupported value"). The same for root and for a
/// user: the refusal does not depend on privilege.
pub const fn refusal(call: Call, policy: i32) -> Option<i32> {
    if policy != SCHED_SPORADIC {
        return None;
    }
    Some(match call {
        Call::AttrSetPolicy => ENOTSUP,
        _ => EINVAL,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_call_that_would_give_the_policy_refuses_it() {
        for call in [
            Call::SetScheduler,
            Call::SetParam,
            Call::ThreadSetParam,
            Call::ThreadCreate,
            Call::Spawn,
        ] {
            assert_eq!(refusal(call, SCHED_SPORADIC), Some(EINVAL), "{call:?}");
        }
        assert_eq!(refusal(Call::AttrSetPolicy, SCHED_SPORADIC), Some(ENOTSUP));
    }

    #[test]
    fn the_other_policies_are_not_refused() {
        for policy in [0, 1, 2, 3, 5, -1] {
            assert_eq!(refusal(Call::SetScheduler, policy), None);
            assert_eq!(refusal(Call::AttrSetPolicy, policy), None);
        }
    }

    #[test]
    fn the_structure_is_the_one_relibc_lays_out() {
        assert_eq!(core::mem::size_of::<SchedParam>(), 48);
        assert_eq!(core::mem::align_of::<SchedParam>(), 8);
        assert_eq!(SchedParam::with_priority(7).sched_priority, 7);
        assert_eq!(SchedParam::with_priority(7).sched_ss_max_repl, 0);
    }
}
