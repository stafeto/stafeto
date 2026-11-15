// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The parameters of SCHED_SPORADIC (XSH 2.8.4; `struct sched_param` of
//! relibc, 48 bytes) and the checks the layer makes of them before it asks
//! for a budget (plan 4b): the mapping of C, T, `low`, `sched_priority` and
//! `sched_ss_max_repl` to the kernel's budget.

pub const EINVAL: i32 = 22;

/// The least and the greatest priority of the policies of real time.
pub const MIN_PRIORITY: i32 = 1;
pub const MAX_PRIORITY: i32 = 32;
/// SS_REPL_MAX: the replenishments the kernel keeps pending.
pub const SS_REPL_MAX: i32 = 4;
/// The least budget and the least period the kernel accepts, in ns
/// (`abi::MIN_BUDGET_NS`, `abi::MIN_PERIOD_NS`).
pub const MIN_BUDGET_NS: u64 = 10_000;
pub const MIN_PERIOD_NS: u64 = 100_000;
/// The policy number of SCHED_SPORADIC (the number Linux leaves free).
pub const SCHED_SPORADIC: i32 = 4;

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

/// The sporadic server's parameters of a thread, in the units of the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ss {
    /// `sched_ss_low_priority`, 1 to 32.
    pub low: i32,
    /// The budget C and the period T in nanoseconds.
    pub c_ns: u64,
    pub t_ns: u64,
    /// `sched_ss_max_repl`, 1 to SS_REPL_MAX.
    pub max_repl: u32,
}

/// The nanoseconds of a time of a parameter: None for a negative number of
/// seconds, a `tv_nsec` outside 0..999 999 999 or a time past a u64.
fn nanoseconds(t: Timespec) -> Option<u64> {
    let sec = u64::try_from(t.tv_sec).ok()?;
    let nsec = u64::try_from(t.tv_nsec)
        .ok()
        .filter(|&n| n < 1_000_000_000)?;
    sec.checked_mul(1_000_000_000)?.checked_add(nsec)
}

/// The checks of the parameters of SCHED_SPORADIC with `priority` as its
/// base (EINVAL for any that fails): both priorities in 1 to 32 and `low`
/// below the base (POSIX leaves a `low` at or above the base undefined, the
/// layer refuses it); C, T and the replenishments within what the kernel's
/// budget takes: `max_repl` in 1 to SS_REPL_MAX, C at most T, C at least
/// `MIN_BUDGET_NS` and T at least `MIN_PERIOD_NS`.
pub fn validate(p: &SchedParam) -> Result<Ss, i32> {
    let priority = p.sched_priority;
    let low = p.sched_ss_low_priority;
    if !(MIN_PRIORITY..=MAX_PRIORITY).contains(&priority)
        || !(MIN_PRIORITY..=MAX_PRIORITY).contains(&low)
    {
        return Err(EINVAL);
    }
    // The break: a `low` at or above the base passes (`cargo xtask sporadic-breaks`).
    if cfg!(not(feature = "break-ss-ignore-low")) && low >= priority {
        return Err(EINVAL);
    }
    if !(1..=SS_REPL_MAX).contains(&p.sched_ss_max_repl) {
        return Err(EINVAL);
    }
    let t = nanoseconds(p.sched_ss_repl_period).ok_or(EINVAL)?;
    let c = nanoseconds(p.sched_ss_init_budget).ok_or(EINVAL)?;
    if c > t || c < MIN_BUDGET_NS || t < MIN_PERIOD_NS {
        return Err(EINVAL);
    }
    Ok(Ss {
        low,
        c_ns: c,
        t_ns: t,
        max_repl: p.sched_ss_max_repl as u32,
    })
}

/// The parameters of `ss` and the base `priority` as POSIX reads them back.
pub fn to_param(priority: i32, ss: &Ss) -> SchedParam {
    let split = |ns: u64| Timespec {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_nsec: (ns % 1_000_000_000) as i64,
    };
    SchedParam {
        sched_priority: priority,
        sched_ss_low_priority: ss.low,
        sched_ss_repl_period: split(ss.t_ns),
        sched_ss_init_budget: split(ss.c_ns),
        sched_ss_max_repl: ss.max_repl as i32,
        _pad: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> SchedParam {
        SchedParam {
            sched_priority: 20,
            sched_ss_low_priority: 10,
            sched_ss_repl_period: Timespec {
                tv_sec: 0,
                tv_nsec: 10_000_000,
            },
            sched_ss_init_budget: Timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            },
            sched_ss_max_repl: 4,
            _pad: 0,
        }
    }

    #[test]
    fn good_parameters_become_a_budget_and_read_back() {
        let ss = validate(&good()).unwrap();
        assert_eq!(
            ss,
            Ss {
                low: 10,
                c_ns: 1_000_000,
                t_ns: 10_000_000,
                max_repl: 4
            }
        );
        assert_eq!(to_param(20, &ss), good());
    }

    #[test]
    fn a_low_priority_at_or_above_the_base_is_refused() {
        let mut p = good();
        p.sched_ss_low_priority = 20;
        assert_eq!(validate(&p), Err(EINVAL));
        p.sched_ss_low_priority = 21;
        assert_eq!(validate(&p), Err(EINVAL));
        p.sched_ss_low_priority = 19;
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn priorities_out_of_range_are_refused() {
        for (base, low) in [(0, 0), (33, 10), (20, 0), (20, 33), (20, -1)] {
            let mut p = good();
            p.sched_priority = base;
            p.sched_ss_low_priority = low;
            assert_eq!(validate(&p), Err(EINVAL), "{base} {low}");
        }
    }

    #[test]
    fn the_replenishments_run_from_one_to_the_ring() {
        for (n, ok) in [(0, false), (1, true), (4, true), (5, false), (-1, false)] {
            let mut p = good();
            p.sched_ss_max_repl = n;
            assert_eq!(validate(&p).is_ok(), ok, "{n}");
        }
    }

    #[test]
    fn the_times_obey_the_rules_of_the_kernel_call() {
        let time = |sec, nsec| Timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        // (period, budget, accepted)
        let cases = [
            (time(0, 10_000_000), time(0, 10_000_000), true),
            (time(0, 10_000_000), time(0, 10_000_001), false),
            (time(1, 0), time(2, 0), false),
            (time(0, 100_000), time(0, 10_000), true),
            (time(0, 99_999), time(0, 10_000), false),
            (time(0, 10_000_000), time(0, 9_999), false),
            (time(0, 1_000_000_000), time(0, 10_000), false),
            (time(0, 10_000_000), time(0, -1), false),
            (time(-1, 0), time(0, 10_000), false),
            (time(i64::MAX, 0), time(0, 10_000), false),
        ];
        for (t, c, ok) in cases {
            let mut p = good();
            p.sched_ss_repl_period = t;
            p.sched_ss_init_budget = c;
            assert_eq!(validate(&p).is_ok(), ok, "{t:?} {c:?}");
        }
    }

    #[test]
    fn the_structure_is_the_one_relibc_lays_out() {
        assert_eq!(core::mem::size_of::<SchedParam>(), 48);
        assert_eq!(core::mem::align_of::<SchedParam>(), 8);
    }
}
