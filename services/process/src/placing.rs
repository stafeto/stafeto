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
    /// lighter. `discounted_parent` says when it is set.
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

/// The CPU whose mark of the parent's own placement is left out of the
/// crowd: that of the record `parent` (None when the service never placed it),
/// and only when the mask `allowed` of the image leaves CPU 0 out (0 for any
/// CPU). CPU 0 is where the network service and its switch run, so a mask
/// without it marks a set of CPUs the launcher keeps for its workers (the
/// measurement images, `BENCH_PINNED_CPUS`), and there the children of one
/// parent are to spread over the set, the parent's CPU included. Everywhere
/// else the parent's mark counts like any other, which keeps its children
/// off its CPU (and off CPU 0 below the switch) when others are lighter.
pub fn discounted_parent<P>(
    records: &crate::records::Records<P>,
    allowed: u64,
    parent: usize,
) -> Option<usize> {
    if allowed != 0 && allowed & 1 == 0 {
        records.placed_cpu(parent)
    } else {
        None
    }
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
    fn the_discount_is_for_a_mask_without_cpu_0_and_the_placed_parent() {
        use crate::records::{Join, Records};
        use proto_process::Credentials;
        let mut t = Records::<u32>::new();
        let mut make = |cpu: Option<u8>| {
            let label = t.next_label().unwrap();
            let index = t.insert(label, 0, None, Credentials::ROOT, 31, Join::NewSession);
            if let Some(cpu) = cpu {
                let record = t.get_mut(index).unwrap();
                (record.cpu, record.placed) = (cpu, true);
            }
            index
        };
        let (parent, child, adopted) = (make(Some(1)), make(Some(3)), make(None));
        // The CPU of the parent, not that of the image placed.
        assert_eq!(discounted_parent(&t, 0b1110, parent), Some(1));
        assert_ne!(discounted_parent(&t, 0b1110, parent), t.placed_cpu(child));
        // A parent the service never placed: none.
        assert_eq!(discounted_parent(&t, 0b1110, adopted), None);
        // Any CPU, or a mask with CPU 0: the parent's mark counts.
        assert_eq!(discounted_parent(&t, 0, parent), None);
        assert_eq!(discounted_parent(&t, 0b0011, parent), None);
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
