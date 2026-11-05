// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The readers against a concurrent change: a writer keeps two words equal by changing
//! them one after the other; a reader that the counter lets through never sees them differ.

use crate::seq::Seq;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::thread;

#[test]
fn a_reader_that_passes_the_check_never_sees_a_change_half_way() {
    let (seq, a, b) = (Seq::new(), AtomicU64::new(0), AtomicU64::new(0));
    let done = AtomicBool::new(false);
    let (passed, refused) = (AtomicU64::new(0), AtomicU64::new(0));
    thread::scope(|s| {
        s.spawn(|| {
            for i in 1..=200_000u64 {
                seq.write(|| {
                    a.store(i, Relaxed);
                    thread::yield_now();
                    b.store(i, Relaxed);
                });
            }
            done.store(true, Relaxed);
        });
        for _ in 0..3 {
            s.spawn(|| {
                while !done.load(Relaxed) {
                    let Some(start) = seq.begin() else {
                        refused.fetch_add(1, Relaxed);
                        continue;
                    };
                    let (x, y) = (a.load(Relaxed), b.load(Relaxed));
                    if seq.unchanged(start) {
                        assert_eq!(x, y, "a torn read passed the check");
                        passed.fetch_add(1, Relaxed);
                    } else {
                        refused.fetch_add(1, Relaxed);
                    }
                }
            });
        }
    });
    assert!(passed.load(Relaxed) > 0, "no read ever passed");
}

#[test]
fn the_count_is_odd_while_a_change_is_made_and_a_read_across_it_is_refused() {
    let seq = Seq::new();
    let start = seq.begin().unwrap();
    seq.write(|| assert!(seq.begin().is_none()));
    assert!(!seq.unchanged(start));
    let next = seq.begin().unwrap();
    assert!(seq.unchanged(next) && next != start);
}
