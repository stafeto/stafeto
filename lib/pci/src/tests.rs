// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;
use crate::fake::{ENA, Fake, t4g};
use std::collections::BTreeMap;

#[test]
fn the_address_of_a_function_follows_the_ecam_layout() {
    let ecam = Ecam {
        base: 0x2000_0000,
        first_bus: 0,
        last_bus: 255,
    };
    assert_eq!(ecam.address(ENA), Some(0x2000_0000 + (5 << 15)));
    assert_eq!(
        ecam.address(Address::new(2, 3, 4)),
        Some(0x2000_0000 + (2 << 20) + (3 << 15) + (4 << 12))
    );
    assert_eq!(ecam.len(), 256 << 20);
    // The bus numbers count from the MCFG's first bus.
    let shifted = Ecam {
        base: 0x4000_0000,
        first_bus: 16,
        last_bus: 31,
    };
    assert_eq!(
        shifted.address(Address::new(17, 0, 1)),
        Some(0x4000_0000 + (1 << 20) + (1 << 12))
    );
    assert_eq!(shifted.address(Address::new(15, 0, 0)), None);
    assert_eq!(shifted.address(Address::new(32, 0, 0)), None);
    assert_eq!(shifted.len(), 16 << 20);
    assert_eq!(Address::new(1, 2, 3).rid(), 0x0113);
}

#[test]
fn the_t4g_set_finds_the_ena_the_console_and_two_nvme() {
    let mut config = t4g();
    let mut seen = Vec::new();
    scan(&mut config, 0, 255, |f| {
        seen.push((f.at.device, f.id(), f.class));
        true
    });
    assert_eq!(
        seen,
        [
            (0, 0x1d0f_0200, 0x060000),
            (1, 0x1d0f_8250, 0x070003),
            (4, 0x1d0f_8061, 0x010802),
            (5, 0x1d0f_ec20, 0x020000),
            (0x1f, 0x1d0f_8061, 0x010802),
        ]
    );
    let ena = find(&mut config, 0, 255, 0x1d0f_ec20, 0).unwrap();
    assert_eq!(ena.at, ENA);
    assert_eq!(ena.revision, 5);
    // The second NVMe is the second function with that ID, in the order of the walk.
    let nvme = find(&mut config, 0, 255, 0x1d0f_8061, 1).unwrap();
    assert_eq!(nvme.at.device, 0x1f);
    assert_eq!(find(&mut config, 0, 255, 0x1d0f_8061, 2), None);
    assert_eq!(find(&mut config, 0, 255, 0x1234_5678, 0), None);
}

#[test]
fn the_walk_of_all_buses_reads_each_device_slot_once_and_empty_ones_read_ones() {
    let mut config = t4g();
    scan(&mut config, 0, 255, |_| true);
    // 256 buses of 32 devices; functions beyond 0 only for a multifunction one.
    assert_eq!(config.reads_of_id, 256 * 32);
}

#[test]
fn a_function_after_zero_is_visited_only_when_function_zero_says_multifunction() {
    let mut config = Fake::default();
    let single = Address::new(0, 2, 0);
    config.function(single, 0x1af4, 0x1000, 0x020000, false);
    config.function(Address::new(0, 2, 1), 0x1af4, 0x1001, 0x020000, false);
    let multi = Address::new(0, 3, 0);
    config.function(multi, 0x1af4, 0x1002, 0x020000, true);
    config.function(Address::new(0, 3, 7), 0x1af4, 0x1003, 0x020000, false);
    let mut seen = Vec::new();
    scan(&mut config, 0, 0, |f| {
        seen.push((f.at.device, f.at.function));
        true
    });
    assert_eq!(seen, [(2, 0), (3, 0), (3, 7)]);
}

#[test]
fn bars_read_as_the_firmware_set_them() {
    let mut config = Fake::default();
    let at = Address::new(0, 6, 0);
    config.function(at, 0x1d0f, 0xec21, 0x020000, false);
    config.mem64(at, 0, 0x40_0000_0000, 0x10_0000);
    config.mem32(at, 2, 0x8000_0000, 0x1000);
    config.io(at, 3, 0x2000, 0x20);
    let b0 = bar(&mut config, at, 0).unwrap();
    assert_eq!(
        (b0.kind, b0.base, b0.prefetchable, b0.registers()),
        (Kind::Mem64, 0x40_0000_0000, true, 2)
    );
    // Register 1 is the upper half of BAR 0, and BAR 2 follows it.
    let b2 = bar(&mut config, at, 2).unwrap();
    assert_eq!(
        (b2.kind, b2.base, b2.prefetchable),
        (Kind::Mem32, 0x8000_0000, false)
    );
    let b3 = bar(&mut config, at, 3).unwrap();
    assert_eq!((b3.kind, b3.base), (Kind::Io, 0x2000));
    assert_eq!(bar(&mut config, at, 6), None);
    // A 64-bit BAR at the last index has no upper half.
    config.words.insert((at, BAR0 + 20), 0b100);
    assert_eq!(bar(&mut config, at, 5), None);
}

#[test]
fn a_bar_size_is_measured_with_decoding_off_and_everything_restored() {
    let mut config = t4g();
    let f = function(&mut config, ENA).unwrap();
    let b = bar(&mut config, ENA, 0).unwrap();
    config.log.clear();
    assert_eq!(measure(&mut config, &f, &b), Ok(0x4000));
    // The first write turns decoding off, the last restores the command word.
    let log = config.log.clone();
    assert_eq!(log[0], (ENA, COMMAND, 0x0004));
    assert_eq!(log[log.len() - 1], (ENA, COMMAND, 0x0006));
    assert_eq!(config.words[&(ENA, BAR0)], 0x8000_4000);
    // The BAR is untouched but for the probe in between.
    let ones = log
        .iter()
        .position(|w| w.1 == BAR0 && w.2 == 0xFFFF_FFFF)
        .unwrap();
    assert!(ones > 0 && log[ones + 1] == (ENA, BAR0, 0x8000_4000));
}

#[test]
fn bars_of_32_bit_64_bit_and_io_kinds_measure() {
    let mut config = Fake::default();
    let at = Address::new(0, 6, 0);
    config.function(at, 0x1d0f, 0xec21, 0x020000, false);
    config.mem64(at, 0, 0x40_0000_0000, 0x10_0000);
    config.mem32(at, 2, 0x8000_0000, 0x1000);
    config.io(at, 3, 0x2000, 0x20);
    let f = function(&mut config, at).unwrap();
    let size = |config: &mut Fake, i| {
        let b = bar(config, at, i).unwrap();
        measure(config, &f, &b)
    };
    assert_eq!(size(&mut config, 0), Ok(0x10_0000));
    assert_eq!(size(&mut config, 2), Ok(0x1000));
    assert_eq!(size(&mut config, 3), Ok(0x20));
    // A 64-bit BAR of 8 GiB sets bits in the upper half.
    config.mem64(at, 4, 0x80_0000_0000, 0x2_0000_0000);
    // BAR 4 and 5 are the last pair.
    assert_eq!(size(&mut config, 4), Ok(0x2_0000_0000));
    // An unimplemented BAR measures 0.
    let empty = Bar {
        index: 1,
        kind: Kind::Mem32,
        prefetchable: false,
        base: 0,
    };
    config.words.insert((at, BAR0 + 4), 0);
    config.masks.insert((at, BAR0 + 4), 0);
    assert_eq!(measure(&mut config, &f, &empty), Ok(0));
}

#[test]
fn the_console_function_is_never_written_to() {
    let mut config = t4g();
    let console = Address::new(0, 1, 0);
    let f = function(&mut config, console).unwrap();
    let b = bar(&mut config, console, 0).unwrap();
    config.log.clear();
    assert_eq!(measure(&mut config, &f, &b), Err(Refused::Console));
    assert!(config.log.is_empty(), "no write reached the console");
}

#[test]
fn a_base_the_size_does_not_divide_is_refused() {
    let mut config = t4g();
    // The firmware put the 16 KiB BAR of the ENA at a 4 KiB boundary.
    config.words.insert((ENA, BAR0), 0x8000_5000);
    let f = function(&mut config, ENA).unwrap();
    let b = bar(&mut config, ENA, 0).unwrap();
    assert_eq!(measure(&mut config, &f, &b), Err(Refused::Misaligned));
}

/// The configuration of a function with the capabilities `list` at 0x40...
fn with_list(list: &[(usize, [u32; 3])]) -> impl FnMut(usize) -> u32 {
    let mut words = BTreeMap::new();
    words.insert(CAPABILITIES, list.first().map_or(0, |c| c.0 as u32));
    for (i, (at, body)) in list.iter().enumerate() {
        let next = list.get(i + 1).map_or(0, |n| n.0 as u32);
        words.insert(*at, body[0] & !0xFF00 | next << 8);
        words.insert(at + 4, body[1]);
        words.insert(at + 8, body[2]);
    }
    move |offset| words.get(&offset).copied().unwrap_or(0)
}

#[test]
fn msix_is_found_through_the_list_with_its_table_and_pending_array() {
    // The list: a power-management capability, then MSI-X with 3 vectors
    // (size field 2), the table in BAR 4 at 0x1000, the pending array in
    // BAR 4 at 0x2000.
    let read = with_list(&[(0x40, [0x01, 0, 0]), (0x50, [0x0002_0011, 0x1004, 0x2004])]);
    let m = msix(read).unwrap();
    assert_eq!(
        m,
        Msix {
            at: 0x50,
            vectors: 3,
            bar: 4,
            offset: 0x1000,
            pba_bar: 4,
            pba_offset: 0x2000
        }
    );
    assert_eq!(m.queue_vector(2), 2);
    assert_eq!(m.queue_vector(3), NO_VECTOR);
    assert_eq!(Msix::enabled(0x0002_0011) >> 30, 0b10);
    assert_eq!(Msix::entry(0x1_2345_6780, 7), [0x2345_6780, 1, 7, 0]);
}

#[test]
fn a_list_without_msix_or_with_a_bad_pointer_gives_none() {
    assert_eq!(msix(with_list(&[(0x40, [0x01, 0, 0])])), None);
    assert_eq!(msix(with_list(&[])), None);
    // A next pointer below 0x40 ends the list.
    let mut words = BTreeMap::new();
    words.insert(CAPABILITIES, 0x40);
    words.insert(0x40, 0x0000_2001);
    assert_eq!(msix(|o| words.get(&o).copied().unwrap_or(0)), None);
}

#[test]
fn a_loop_in_the_capability_list_ends_after_48_steps() {
    // The capability at 0x40 points at itself.
    let mut steps = 0usize;
    let mut read = |offset: usize| {
        if offset == CAPABILITIES {
            return 0x40;
        }
        steps += 1;
        // ID 0x01, next 0x40.
        0x4001
    };
    assert_eq!(capability(&mut read, |h| h & 0xFF == MSIX_CAPABILITY), None);
    assert_eq!(steps, MOST_CAPABILITIES);
}
