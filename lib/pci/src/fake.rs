// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A set of functions in memory for the tests of this library and of the
//! tables that name functions (feature `fake`): the words of each
//! function's page, and the size masks of its BARs, which a write of ones
//! shows back.

extern crate std;

use crate::*;
use std::collections::BTreeMap;
use std::vec::Vec;

/// A set of functions in memory: the words of each function's page, and the
/// size masks of its BARs, which a write of ones shows back.
#[derive(Default)]
pub struct Fake {
    pub words: BTreeMap<(Address, usize), u32>,
    /// (function, BAR register) -> the bits a write sticks in.
    pub masks: BTreeMap<(Address, usize), u32>,
    /// The command writes in order, with the BAR writes between them.
    pub log: Vec<(Address, usize, u32)>,
    pub reads_of_id: usize,
}

impl Fake {
    pub fn function(&mut self, at: Address, vendor: u16, device: u16, class: u32, multi: bool) {
        self.words
            .insert((at, ID), u32::from(device) << 16 | u32::from(vendor));
        self.words.insert((at, CLASS), class << 8 | 0x05);
        let header = if multi { 1 << 23 } else { 0 };
        self.words.insert((at, HEADER), header);
        self.words.insert((at, COMMAND), 0x0006);
    }

    /// A 32-bit memory BAR of `size` at `base`.
    pub fn mem32(&mut self, at: Address, index: usize, base: u32, size: u32) {
        self.words.insert((at, BAR0 + 4 * index), base);
        self.masks.insert((at, BAR0 + 4 * index), !(size - 1));
    }

    /// A 64-bit prefetchable memory BAR of `size` at `base`.
    pub fn mem64(&mut self, at: Address, index: usize, base: u64, size: u64) {
        let low = (base as u32 & !0xF) | 0b1100;
        self.words.insert((at, BAR0 + 4 * index), low);
        self.words
            .insert((at, BAR0 + 4 * index + 4), (base >> 32) as u32);
        self.masks
            .insert((at, BAR0 + 4 * index), (!(size - 1)) as u32 & !0xF);
        self.masks
            .insert((at, BAR0 + 4 * index + 4), (!(size - 1) >> 32) as u32);
    }

    pub fn io(&mut self, at: Address, index: usize, base: u32, size: u32) {
        self.words.insert((at, BAR0 + 4 * index), base | 1);
        self.masks.insert((at, BAR0 + 4 * index), !(size - 1) & !3);
    }
}

impl Config for Fake {
    fn read(&mut self, at: Address, offset: usize) -> u32 {
        assert_eq!(offset % 4, 0, "reads are whole words");
        if offset == ID {
            self.reads_of_id += 1;
        }
        self.words
            .get(&(at, offset))
            .copied()
            .unwrap_or(match offset {
                ID => 0xFFFF_FFFF,
                _ => 0,
            })
    }

    fn write(&mut self, at: Address, offset: usize, value: u32) {
        assert_eq!(offset % 4, 0, "writes are whole words");
        self.log.push((at, offset, value));
        if let Some(mask) = self.masks.get(&(at, offset)) {
            let kept = self.words[&(at, offset)] & !mask;
            self.words.insert((at, offset), kept | (value & mask));
        } else {
            self.words.insert((at, offset), value);
        }
    }
}

pub const ENA: Address = Address::new(0, 5, 0);

/// The functions of a t4g.small (`fixtures/graviton-t4g/pci.txt`).
pub fn t4g() -> Fake {
    let mut f = Fake::default();
    f.function(Address::new(0, 0, 0), 0x1d0f, 0x0200, 0x060000, false);
    f.function(Address::new(0, 1, 0), 0x1d0f, 0x8250, 0x070003, false);
    f.mem32(Address::new(0, 1, 0), 0, 0x8000_c000, 0x1000);
    f.function(Address::new(0, 4, 0), 0x1d0f, 0x8061, 0x010802, false);
    f.mem32(Address::new(0, 4, 0), 0, 0x8000_8000, 0x4000);
    f.function(ENA, 0x1d0f, 0xec20, 0x020000, false);
    f.mem32(ENA, 0, 0x8000_4000, 0x4000);
    f.function(Address::new(0, 0x1f, 0), 0x1d0f, 0x8061, 0x010802, false);
    f.mem32(Address::new(0, 0x1f, 0), 0, 0x8000_0000, 0x4000);
    f
}
