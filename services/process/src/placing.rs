// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The choice of the CPU for the main thread of a new image, apart from the
//! reads of the kernel's counters that feed it: tested on the host.

/// The CPUs the service tells apart at most.
pub const MAX_CPUS: usize = 8;

/// What the service knows of the CPUs when it places an image: whether
/// each was awake enough over the last window (`load` at or above 250 of
/// 1000), and the images put on each in this window and the one before.
pub struct Crowd<'a> {
    pub load: &'a [u32; MAX_CPUS],
    pub issued: [&'a [u32; MAX_CPUS]; 2],
    /// The CPU the service put the parent of the image placed on (None for a
    /// parent it never placed). The mark of the parent's own placement does
    /// not count against its children: the parent made the image and is
    /// no crowd for it. The discount is one mark of that CPU for every
    /// placement, taken whether or not the parent's own mark is still in the
    /// two windows, so the bias to the parent's CPU is one mark at most. For
    /// an exec the parent is the process itself, so an image made by fork
    /// and then exec stays on the CPU the fork gave it when nothing else is
    /// lighter.
    pub parent: Option<usize>,
}

impl Crowd<'_> {
    /// How busy the CPU `c` is: one when it was awake a quarter of the
    /// last window, and one for each image put on it lately but for the
    /// parent's own.
    pub fn busy(&self, c: usize) -> u32 {
        let marks = self.issued[0][c] + self.issued[1][c];
        let own = u32::from(self.parent == Some(c));
        u32::from(self.load[c] >= 250) + marks.saturating_sub(own)
    }
}

/// The CPU for an image among the `cpus` of the machine, those of the
/// mask `allowed` (all when 0): the least busy, and among equals the first
/// after `last`, the CPU of the last placement, so that images made one
/// after the other go to different CPUs.
pub fn choose(cpus: usize, allowed: u64, last: usize, crowd: &Crowd<'_>) -> usize {
    (1..=cpus)
        .map(|step| (last + step) % cpus)
        .filter(|&c| allowed == 0 || allowed >> c & 1 != 0)
        .min_by_key(|&c| crowd.busy(c))
        .unwrap_or(0)
}

/// The mask of the CPUs an image may stand on: the CPUs its page names
/// within those of its record (`record`, 0 for any), and the record's when
/// the page names none of them.
pub const fn allowed_cpus(page: u64, record: u64) -> u64 {
    match page & if record == 0 { u64::MAX } else { record } {
        0 => record,
        mask => mask,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The workers of a master on CPU 1, which the services of the image
    /// share (awake a quarter of the window), put on CPUs 1 to 3 one after
    /// the other, as the master forks them; the master's own mark is in
    /// the window.
    fn workers(parent: Option<usize>) -> [usize; 3] {
        let mut load = [0; MAX_CPUS];
        load[1] = 300;
        let mut issued = [0; MAX_CPUS];
        issued[1] = 1;
        let before = [0; MAX_CPUS];
        let mut last = 1;
        let mut out = [0; 3];
        for worker in &mut out {
            let crowd = Crowd {
                load: &load,
                issued: [&issued, &before],
                parent,
            };
            *worker = choose(4, 0b1110, last, &crowd);
            issued[*worker] += 1;
            last = *worker;
        }
        out
    }

    #[test]
    fn three_workers_of_a_master_on_a_shared_cpu_stand_on_cpus_1_2_3() {
        let mut got = workers(Some(1));
        got.sort_unstable();
        assert_eq!(got, [1, 2, 3]);
    }

    #[test]
    fn the_mark_of_the_parent_is_the_one_that_crowds_cpu_1() {
        // Without the discount the third worker stacks on CPU 2.
        assert_eq!(workers(None), [2, 3, 2]);
    }

    #[test]
    fn the_discount_takes_one_mark_and_no_more() {
        let load = [0; MAX_CPUS];
        let mut issued = [0; MAX_CPUS];
        issued[1] = 3;
        let none = [0; MAX_CPUS];
        let crowd = Crowd {
            load: &load,
            issued: [&issued, &none],
            parent: Some(1),
        };
        assert_eq!(crowd.busy(1), 2);
        let crowd = Crowd {
            parent: Some(2),
            ..crowd
        };
        assert_eq!(crowd.busy(2), 0);
        assert_eq!(crowd.busy(1), 3);
    }

    #[test]
    fn the_mask_limits_the_choice() {
        let load = [0; MAX_CPUS];
        let none = [0; MAX_CPUS];
        let crowd = Crowd {
            load: &load,
            issued: [&none, &none],
            parent: None,
        };
        assert_eq!(choose(4, 0b0100, 0, &crowd), 2);
        assert_eq!(choose(4, 0, 3, &crowd), 0);
    }

    #[test]
    fn the_mask_of_the_page_stays_within_the_record() {
        assert_eq!(allowed_cpus(0b0110, 0b1110), 0b0110);
        assert_eq!(allowed_cpus(0b0001, 0b1110), 0b1110);
        assert_eq!(allowed_cpus(0, 0), 0);
    }
}
