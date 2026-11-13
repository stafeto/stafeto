// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The home of a session: the stack instance that holds all the sockets of a process's
//! session. The service runs one instance for each CPU of its mask (up to a limit the file
//! `netd.conf` sets), the instance k on the k-th CPU of the mask in the order of the
//! numbers. A session gets its home once, at its first call that touches a socket, from the
//! CPU of the calling thread: a thread stays on its CPU, so every call it makes afterwards
//! is local to its instance, and a call from a thread on another CPU of the same process is
//! the one that crosses (`Counters::calls_remote`).

/// The CPUs the instances stand on: the `limit` lowest CPUs of `mask`, as a mask.
pub fn instance_cpus(mask: u32, limit: usize) -> u32 {
    let mut left = mask;
    let mut cpus = 0;
    for _ in 0..limit {
        if left == 0 {
            break;
        }
        let low = left.isolate_lowest_one();
        cpus |= low;
        left &= !low;
    }
    cpus
}

/// How many instances `cpus` holds.
pub fn count(cpus: u32) -> usize {
    cpus.count_ones() as usize
}

/// The CPU instance `k` stands on.
pub fn cpu_of(cpus: u32, k: usize) -> Option<u32> {
    let mut left = cpus;
    for _ in 0..k {
        left &= left.wrapping_sub(1);
    }
    (left != 0).then(|| left.trailing_zeros())
}

/// The instance that stands on `cpu`.
pub fn instance_on(cpus: u32, cpu: u32) -> Option<usize> {
    (cpu < 32 && cpus >> cpu & 1 != 0).then(|| (cpus & ((1u32 << cpu) - 1)).count_ones() as usize)
}

/// The home of a session whose first call came from `cpu` in a process that may run on
/// `allowed`: the instance on that CPU; for a CPU with no instance, the instance of the
/// lowest CPU of the process that has one; else instance 0.
pub fn choose(cpus: u32, cpu: u32, allowed: u32) -> usize {
    instance_on(cpus, cpu)
        .or_else(|| {
            let common = cpus & allowed;
            (common != 0).then(|| instance_on(cpus, common.trailing_zeros()))?
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_instances_stand_on_the_lowest_cpus_of_the_mask() {
        assert_eq!(instance_cpus(0b1111, 4), 0b1111);
        assert_eq!(instance_cpus(0b1111, 2), 0b0011);
        assert_eq!(instance_cpus(0b1110, 2), 0b0110);
        assert_eq!(instance_cpus(0b0001, 4), 0b0001);
        assert_eq!(instance_cpus(0, 4), 0);
        assert_eq!(count(0b0110), 2);
        assert_eq!(cpu_of(0b1010, 0), Some(1));
        assert_eq!(cpu_of(0b1010, 1), Some(3));
        assert_eq!(cpu_of(0b1010, 2), None);
    }

    #[test]
    fn a_session_is_homed_on_the_instance_of_its_cpu() {
        let cpus = 0b1111;
        for cpu in 0..4 {
            assert_eq!(choose(cpus, cpu, 0b1110), cpu as usize);
        }
    }

    #[test]
    fn a_cpu_without_an_instance_takes_the_lowest_cpu_of_the_process_that_has_one() {
        // Normal images: instances on CPUs 0 and 1, the process may run on 0 to 3.
        let cpus = 0b0011;
        assert_eq!(
            choose(cpus, 2, 0b1100),
            0,
            "no CPU of the process has an instance"
        );
        assert_eq!(choose(cpus, 3, 0b1110), 1);
        assert_eq!(choose(cpus, 2, 0b0111), 0);
        assert_eq!(choose(cpus, 40, 0), 0);
    }
}
