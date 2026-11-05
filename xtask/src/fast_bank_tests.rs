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

fn sources(dir: &Path, found: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            found.push((name, fs::read_to_string(&path).unwrap()));
        }
    }
}

/// The raw receive of the kernel is named only in `fast.rs` (the wrappers),
/// in `relibc.rs` (the EXITS channel, another channel), in `process.rs` (the
/// fake channel of a probe) and in `loader_probe.rs`.
#[test]
fn every_receive_of_the_layer_goes_through_the_wrappers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../lib/posix-abi/src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(files.len() > 40, "the sources were not found");
    let allowed = ["fast.rs", "relibc.rs", "process.rs", "loader_probe.rs"];
    let mut wrapped = 0;
    for (name, text) in &files {
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap();
            if code.contains("sys::receive(") || code.contains("sys::try_receive(") {
                assert!(
                    allowed.contains(&name.as_str()),
                    "{name}:{}: a raw receive outside the wrappers: {line}",
                    n + 1
                );
            }
            if code.contains("fast::receive(") {
                wrapped += 1;
            }
        }
    }
    // wait 1, long 2, lock_wait 1, signals 5, open_driver 1, sleep 1.
    assert!(wrapped >= 11, "only {wrapped} wrapped receives");
}
