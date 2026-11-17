// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A device in memory for the tests, with a volatile write cache and a cut of the power.
//!
//! A write lands in the cache; `flush` moves the cache to the medium. When the power is cut (the
//! write that makes the count of `cut_after` sectors, which then writes only its first sectors),
//! every call fails until `power_cycle`, which decides for each sector of the cache whether it
//! reached the medium. That is the weakest device a flush can be asked of: the sectors written
//! since the last flush survive in any combination.

extern crate std;

use crate::{Device, DeviceError, SECTOR};
use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

pub struct MemDevice {
    medium: Vec<u8>,
    cache: BTreeMap<u64, [u8; SECTOR]>,
    /// The sectors written so far, flushes not counted.
    pub written: u64,
    /// The flushes so far.
    pub flushes: u64,
    cut_after: Option<u64>,
    dead: bool,
}

/// Which sectors of the cache a power cut lets through to the medium.
#[derive(Clone, Copy, Debug)]
pub enum Survive {
    None,
    All,
    /// Each sector with the chance of half, from this seed.
    Random(u64),
    /// The cache sectors from the first on, up to this many.
    Prefix(usize),
}

impl MemDevice {
    pub fn new(sectors: u64) -> Self {
        Self {
            medium: vec![0; sectors as usize * SECTOR],
            cache: BTreeMap::new(),
            written: 0,
            flushes: 0,
            cut_after: None,
            dead: false,
        }
    }

    /// The power is cut when `n` more sectors have been written (the write that reaches `n` stops
    /// there). `None` turns the cut off.
    pub fn cut_after(&mut self, n: Option<u64>) {
        self.cut_after = n.map(|n| self.written + n);
    }

    pub fn is_dead(&self) -> bool {
        self.dead
    }

    /// The machine starts again: the cache keeps what `survive` says, the rest is lost.
    pub fn power_cycle(&mut self, survive: Survive) {
        let mut state = match survive {
            Survive::Random(seed) => seed,
            _ => 0,
        };
        for (i, (sector, data)) in core::mem::take(&mut self.cache).into_iter().enumerate() {
            let keep = match survive {
                Survive::None => false,
                Survive::All => true,
                Survive::Random(_) => {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    state >> 33 & 1 == 1
                }
                Survive::Prefix(n) => i < n,
            };
            if keep {
                self.medium[sector as usize * SECTOR..][..SECTOR].copy_from_slice(&data);
            }
        }
        self.dead = false;
        self.cut_after = None;
    }

    /// The medium as it is (what a reader after a power cut sees, once the cache is settled).
    pub fn medium(&self) -> &[u8] {
        &self.medium
    }

    pub fn from_medium(medium: Vec<u8>) -> Self {
        Self {
            medium,
            cache: BTreeMap::new(),
            written: 0,
            flushes: 0,
            cut_after: None,
            dead: false,
        }
    }
}

impl Device for MemDevice {
    fn sectors(&self) -> u64 {
        (self.medium.len() / SECTOR) as u64
    }

    fn read(&mut self, sector: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        if self.dead || !out.len().is_multiple_of(SECTOR) {
            return Err(DeviceError);
        }
        let count = (out.len() / SECTOR) as u64;
        if sector + count > self.sectors() {
            return Err(DeviceError);
        }
        for i in 0..count {
            let at = (sector + i) as usize;
            let piece = &mut out[i as usize * SECTOR..][..SECTOR];
            match self.cache.get(&(sector + i)) {
                Some(cached) => piece.copy_from_slice(cached),
                None => piece.copy_from_slice(&self.medium[at * SECTOR..][..SECTOR]),
            }
        }
        Ok(())
    }

    fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), DeviceError> {
        if self.dead || !data.len().is_multiple_of(SECTOR) {
            return Err(DeviceError);
        }
        let count = (data.len() / SECTOR) as u64;
        if sector + count > self.sectors() {
            return Err(DeviceError);
        }
        for i in 0..count {
            if self.cut_after == Some(self.written) {
                self.dead = true;
                return Err(DeviceError);
            }
            let mut piece = [0; SECTOR];
            piece.copy_from_slice(&data[i as usize * SECTOR..][..SECTOR]);
            self.cache.insert(sector + i, piece);
            self.written += 1;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), DeviceError> {
        if self.dead {
            return Err(DeviceError);
        }
        for (sector, data) in core::mem::take(&mut self.cache) {
            self.medium[sector as usize * SECTOR..][..SECTOR].copy_from_slice(&data);
        }
        self.flushes += 1;
        Ok(())
    }
}
