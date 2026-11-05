// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Host checks of the bank of the service's notifications and of the rule
//! that every receive on the thread's channel of the POSIX layer goes
//! through `fast::receive` or `fast::try_receive`.

use crate::fast_bank::{Bank, CLIENT_GONE, FAST_LABEL, FAST_MASK, GONE, bits_of};
use std::fs;
use std::path::Path;

const TRY_3: u64 = FAST_LABEL | 3;
const TRY_4: u64 = FAST_LABEL | 4;

#[test]
fn the_label_of_the_active_try_is_banked() {
    let bank = Bank::new();
    bank.activate(TRY_3);
    bank.deposit(TRY_3, 0b0101);
    assert_eq!(bank.take(), 0b0101);
    assert!(!bank.lost());
}

#[test]
fn the_label_of_another_try_is_dropped() {
    let bank = Bank::new();
    bank.activate(TRY_4);
    bank.deposit(TRY_3, 0b1111);
    bank.deposit(TRY_3, CLIENT_GONE);
    assert_eq!(bank.take(), 0);
    assert!(!bank.lost());
    // Before any try holds the device nothing is banked.
    let early = Bank::new();
    early.deposit(TRY_3, 0b1);
    assert_eq!(early.take(), 0);
}

#[test]
fn the_end_of_the_service_sets_the_sticky_bit() {
    let bank = Bank::new();
    bank.activate(TRY_3);
    bank.deposit(TRY_3, CLIENT_GONE | 0b10);
    assert!(bank.lost());
    assert_eq!(bank.take(), GONE | 0b10);
    // Taking the bits leaves the loss in place.
    assert_eq!(bank.take(), 0);
    assert!(bank.lost());
}

#[test]
fn a_bit_goes_to_one_taker_and_bits_that_came_meanwhile_join() {
    let bank = Bank::new();
    bank.activate(TRY_3);
    bank.deposit(TRY_3, 0b0001);
    bank.deposit(TRY_3, 0b0100);
    assert_eq!(bank.take(), 0b0101);
    assert_eq!(bank.take(), 0);
    bank.deposit(TRY_3, 0b0010);
    assert_eq!(bank.take(), 0b0010);
}

#[test]
fn a_waiting_loop_wakes_on_bits_and_on_the_loss() {
    let bank = Bank::new();
    bank.activate(TRY_3);
    assert!(!bank.waiting());
    bank.deposit(TRY_3, 0b1);
    assert!(bank.waiting());
    assert_eq!(bank.take(), 0b1);
    assert!(!bank.waiting());
    // The loss stays: the loop that sees it does not sleep again.
    bank.deposit(TRY_3, CLIENT_GONE);
    assert_eq!(bank.take(), GONE);
    assert!(bank.waiting());
}

#[test]
fn the_bits_of_a_notification_map_as_wait_gives_them() {
    assert_eq!(bits_of(0xf), 0xf);
    assert_eq!(bits_of(0x30), 0);
    assert_eq!(bits_of(CLIENT_GONE), GONE);
    assert_eq!(bits_of(CLIENT_GONE | 1), GONE | 1);
}

#[test]
fn the_mask_takes_the_fast_label_of_every_try_and_nothing_else() {
    assert_eq!(TRY_3 & FAST_MASK, FAST_LABEL);
    assert_eq!((FAST_LABEL | 0xffff_ffff) & FAST_MASK, FAST_LABEL);
    // The timer of the waits, the label of `wait` (bit 63) and the small
    // labels of the long operations stay out.
    assert_ne!((1u64 << 62 | 0xfa58 << 32) & FAST_MASK, FAST_LABEL);
    assert_ne!((1u64 << 63 | 5) & FAST_MASK, FAST_LABEL);
    assert_ne!(7u64 & FAST_MASK, FAST_LABEL);
}

fn sources(dir: &Path, root: &Path, found: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, root, found);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            found.push((name, fs::read_to_string(&path).unwrap()));
        }
    }
}

/// The raw calls of the kernel's receive that each file of the layer may
/// hold, by path from the root of the repository. The wrappers are in
/// `receiver.rs`; the others listen on a channel that is not the thread's
/// (the EXITS channel, a probe's fake channel, the loader probe's root, the
/// platform's parked child).
const RAW: [(&str, usize); 5] = [
    ("lib/posix-sync/src/receiver.rs", 2),
    ("lib/posix-abi/src/relibc.rs", 1),
    ("lib/posix-abi/src/process.rs", 1),
    ("lib/posix-abi/src/loader_probe.rs", 1),
    ("lib/posix-platform/src/lib.rs", 1),
];

/// The number of raw receives in the code of a text: a call of
/// `sys::receive(` or `sys::try_receive(`, or a `use` that brings either
/// name into scope (a call without the path would escape the first form).
fn raw_receives(text: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let code = line.split("//").next().unwrap();
        let call = code.contains("sys::receive(") || code.contains("sys::try_receive(");
        let import = code.trim_start().starts_with("use ")
            && code.contains("sys::")
            && (code.contains("receive") || code.contains("try_receive"));
        if call || import {
            lines.push(n + 1);
        }
    }
    lines
}

#[test]
fn every_receive_of_the_layer_goes_through_the_wrappers() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for dir in [
        "lib/posix-abi/src",
        "lib/posix-sync/src",
        "lib/posix-platform/src",
    ] {
        let mut part = Vec::new();
        sources(&repo.join(dir), &repo, &mut part);
        files.extend(part);
    }
    assert!(files.len() > 45, "the sources were not found");
    let mut wrapped = 0;
    for (name, text) in &files {
        let raw = raw_receives(text);
        let expected = RAW
            .iter()
            .find(|(path, _)| name.as_str() == *path)
            .map_or(0, |(_, count)| *count);
        assert_eq!(
            raw.len(),
            expected,
            "{name}: {} raw receives at lines {raw:?}, {expected} allowed",
            raw.len()
        );
        wrapped += text
            .lines()
            .filter(|l| {
                let code = l.split("//").next().unwrap();
                code.contains("fast::receive(") || code.contains("receiver::receive(")
            })
            .count();
    }
    for (path, _) in RAW {
        assert!(files.iter().any(|(name, _)| name == path), "{path} is gone");
    }
    // wait 1, long 2, lock_wait 1, signals 5, open_driver 1, sleep 1,
    // the wait on an address in posix-sync 1.
    assert!(wrapped >= 12, "only {wrapped} wrapped receives");
}

#[test]
fn the_scan_sees_a_raw_receive_and_an_import() {
    assert_eq!(raw_receives("let a = sys::receive(&c);\nlet b = 1;"), [1]);
    assert_eq!(raw_receives("use rt::sys::{receive, send};"), [1]);
    assert_eq!(raw_receives("    // sys::receive(&c)"), Vec::<usize>::new());
    assert_eq!(raw_receives("fast::receive(&c)"), Vec::<usize>::new());
}
