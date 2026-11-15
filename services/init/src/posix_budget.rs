// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The admission of the time budgets of POSIX threads (SCHED_SPORADIC, plan
//! 4b, proto_init BUDGET). The process service asks init for a budget for
//! each thread that runs under a sporadic server; init lets the budgets of
//! POSIX threads take `table::POSIX_BUDGETS` of a CPU together (the table's
//! own budgets are counted with that row in `table::check`), so that the
//! levels below keep what the layout of the CPU leaves them.
//!
//! `Shares` is the list init keeps: the number it gave each budget, the
//! CPU and the share. The numbers go up by one and are never given twice.

use crate::table;

/// The budgets of POSIX threads init holds at once.
pub const ENTRIES: usize = 64;

/// The share of a CPU a budget takes, in parts per million, rounded up.
pub const fn share_ppm(c_ns: u64, t_ns: u64) -> u64 {
    (c_ns * 1_000_000).div_ceil(t_ns)
}

/// Why `Shares::admit` refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The sum on the CPU would pass its share of POSIX threads.
    Share,
    /// The list is full.
    Room,
    /// A CPU that has no row, or numbers that are no budget.
    Invalid,
}

/// The budgets of POSIX threads and what they take of each CPU.
pub struct Shares {
    limit: [u64; 8],
    used: [u64; 8],
    /// The number of each entry, 0 for a free one, with its share and CPU.
    ids: [u32; ENTRIES],
    ppms: [u32; ENTRIES],
    cpus: [u8; ENTRIES],
    next: u32,
}

impl Shares {
    pub const fn new(limit: [u64; 8]) -> Shares {
        Shares {
            limit,
            used: [0; 8],
            ids: [0; ENTRIES],
            ppms: [0; ENTRIES],
            cpus: [0; ENTRIES],
            next: 1,
        }
    }

    /// What the budgets take of `cpu` now, in parts per million.
    pub fn used(&self, cpu: usize) -> u64 {
        self.used.get(cpu).copied().unwrap_or(0)
    }

    /// Counts a budget of `c_ns` for each `t_ns` on `cpu` and returns its
    /// number. With `replace`, the budget of that number on the same CPU is
    /// taken off the sum for the check, and stays counted until `release`.
    pub fn admit(&mut self, cpu: u32, c_ns: u64, t_ns: u64, replace: u64) -> Result<u64, Refused> {
        let cpu = usize::try_from(cpu).ok().filter(|&c| c < 8);
        let Some(cpu) = cpu else {
            return Err(Refused::Invalid);
        };
        if t_ns == 0 || c_ns > t_ns || c_ns.checked_mul(1_000_000).is_none() {
            return Err(Refused::Invalid);
        }
        let ppm = share_ppm(c_ns, t_ns);
        let old = if replace == 0 {
            0
        } else {
            match self.find(replace) {
                Some(i) if usize::from(self.cpus[i]) == cpu => u64::from(self.ppms[i]),
                Some(_) => 0,
                None => return Err(Refused::Invalid),
            }
        };
        // The break: init counts no share and admits every request.
        if cfg!(not(feature = "break-ss-no-admission"))
            && self.used[cpu] - old + ppm > self.limit[cpu]
        {
            return Err(Refused::Share);
        }
        let Some(slot) = self.ids.iter().position(|&id| id == 0) else {
            return Err(Refused::Room);
        };
        let Some(next) = self.next.checked_add(1) else {
            return Err(Refused::Room);
        };
        let id = self.next;
        self.next = next;
        self.ids[slot] = id;
        self.ppms[slot] = ppm as u32;
        self.cpus[slot] = cpu as u8;
        self.used[cpu] += ppm;
        Ok(u64::from(id))
    }

    /// Gives the budget `id` back. False for a number init does not hold.
    pub fn release(&mut self, id: u64) -> bool {
        let Some(i) = self.find(id) else {
            return false;
        };
        self.used[usize::from(self.cpus[i])] -= u64::from(self.ppms[i]);
        self.ids[i] = 0;
        true
    }

    /// Forgets every budget: the process service's instance ended, and with
    /// it every thread that held one.
    pub fn clear(&mut self) {
        self.ids = [0; ENTRIES];
        self.used = [0; 8];
    }

    fn find(&self, id: u64) -> Option<usize> {
        let id = u32::try_from(id).ok().filter(|&id| id != 0)?;
        self.ids.iter().position(|&held| held == id)
    }
}

/// The row of the table for `Shares::new`.
pub const fn limits() -> [u64; 8] {
    table::POSIX_BUDGETS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cpu_admits_budgets_up_to_its_row() {
        let mut s = Shares::new([0, 200_000, 500_000, 500_000, 0, 0, 0, 0]);
        // 1 ms of 10 ms is 100 000 ppm.
        let a = s.admit(1, 1_000_000, 10_000_000, 0).unwrap();
        let b = s.admit(1, 1_000_000, 10_000_000, 0).unwrap();
        assert_ne!(a, b);
        assert_eq!(s.used(1), 200_000);
        assert_eq!(
            s.admit(1, 10_000, 10_000_000, 0),
            Err(Refused::Share),
            "a CPU whose row is full refuses even the least budget"
        );
        assert_eq!(s.admit(0, 10_000, 1_000_000, 0), Err(Refused::Share));
        assert!(s.release(a));
        assert_eq!(s.used(1), 100_000);
        assert!(s.admit(1, 1_000_000, 10_000_000, 0).is_ok());
    }

    #[test]
    fn a_replacement_is_checked_against_the_sum_less_the_old_share() {
        let mut s = Shares::new([0, 0, 500_000, 0, 0, 0, 0, 0]);
        let old = s.admit(2, 5_000_000, 10_000_000, 0).unwrap();
        // 40 % where 50 % of the same CPU stood passes.
        let new = s.admit(2, 4_000_000, 10_000_000, old).unwrap();
        // Both are counted until the old one goes.
        assert_eq!(s.used(2), 900_000);
        assert!(s.release(old));
        assert_eq!(s.used(2), 400_000);
        // 60 % does not fit where 40 % stood.
        assert_eq!(s.admit(2, 6_000_000, 10_000_000, new), Err(Refused::Share));
        // A rebind that moves to another CPU counts the new share whole.
        let mut s = Shares::new([0, 500_000, 500_000, 0, 0, 0, 0, 0]);
        let a = s.admit(1, 5_000_000, 10_000_000, 0).unwrap();
        s.admit(2, 5_000_000, 10_000_000, 0).unwrap();
        assert_eq!(s.admit(2, 1_000_000, 10_000_000, a), Err(Refused::Share));
    }

    #[test]
    fn numbers_that_are_no_budget_are_refused() {
        let mut s = Shares::new([0, 100_000, 0, 0, 0, 0, 0, 0]);
        assert_eq!(s.admit(8, 1, 10, 0), Err(Refused::Invalid));
        assert_eq!(s.admit(1, 20, 10, 0), Err(Refused::Invalid));
        assert_eq!(s.admit(1, 1, 0, 0), Err(Refused::Invalid));
        assert_eq!(s.admit(1, 1_000, 10_000, 99), Err(Refused::Invalid));
        assert!(!s.release(99));
    }

    #[test]
    fn the_list_is_full_at_its_size_and_a_clear_empties_it() {
        let mut s = Shares::new([1_000_000; 8]);
        for _ in 0..ENTRIES {
            s.admit(0, 10_000, 10_000_000, 0).unwrap();
        }
        assert_eq!(s.admit(0, 10_000, 10_000_000, 0), Err(Refused::Room));
        s.clear();
        assert_eq!(s.used(0), 0);
        assert!(s.admit(0, 10_000, 10_000_000, 0).is_ok());
    }

    #[test]
    fn the_numbers_are_never_given_twice() {
        let mut s = Shares::new([1_000_000; 8]);
        let a = s.admit(0, 10_000, 10_000_000, 0).unwrap();
        assert!(s.release(a));
        let b = s.admit(0, 10_000, 10_000_000, 0).unwrap();
        assert_ne!(a, b);
    }
}
