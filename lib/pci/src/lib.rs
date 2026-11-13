// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! PCI configuration space through ECAM (PCI Express Base, "Enhanced
//! Configuration Access Mechanism"): the address of a function, a flat
//! enumeration of the buses the firmware's MCFG names, the BARs as the
//! firmware set them, the size of a BAR measured once (PCI Local Bus 3.0,
//! 6.2.5.1) and the capability list with MSI-X.
//!
//! The firmware has numbered the buses and placed the BARs, so nothing here
//! programs a bridge or moves a BAR; a bridge is one more function of the
//! flat walk. Every access of the library is 32 bits wide [G34]: the
//! command word is written together with the status half, which clears its
//! bits when written with 1, so the library writes 0 there.
//!
//! The library holds no memory access of its own: the caller gives it a
//! `Config`, which reads and writes the 32-bit words of a function's page
//! (a window over ECAM in `init`, a vector of words in the tests).

#![cfg_attr(not(test), no_std)]

/// The bus, device and function of a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Address {
    pub const fn new(bus: u8, device: u8, function: u8) -> Address {
        assert!(device < 32 && function < 8);
        Address {
            bus,
            device,
            function,
        }
    }

    /// The requester ID the function sends with: bus, device and function in
    /// 16 bits, the key of an MSI device.
    pub const fn rid(&self) -> u32 {
        (self.bus as u32) << 8 | (self.device as u32) << 3 | self.function as u32
    }
}

/// The ECAM of a segment as the MCFG names it: the base of the bus
/// `first_bus` and the last bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ecam {
    pub base: u64,
    pub first_bus: u8,
    pub last_bus: u8,
}

/// The bytes of one function's configuration space in ECAM.
pub const FUNCTION_LEN: u64 = 4096;

impl Ecam {
    /// The offset of the function's page from `base`:
    /// `(bus - first_bus) << 20 | device << 15 | function << 12`.
    /// None for a bus outside the range.
    pub const fn offset(&self, at: Address) -> Option<u64> {
        if at.bus < self.first_bus || at.bus > self.last_bus {
            return None;
        }
        Some(
            ((at.bus - self.first_bus) as u64) << 20
                | (at.device as u64) << 15
                | (at.function as u64) << 12,
        )
    }

    /// The physical address of the function's page.
    pub const fn address(&self, at: Address) -> Option<u64> {
        match self.offset(at) {
            Some(offset) => Some(self.base + offset),
            None => None,
        }
    }

    /// The bytes of ECAM the range covers.
    pub const fn len(&self) -> u64 {
        ((self.last_bus - self.first_bus) as u64 + 1) << 20
    }

    pub const fn is_empty(&self) -> bool {
        false
    }
}

/// The words of the configuration space of the functions, 32 bits wide.
pub trait Config {
    /// The word at the byte `offset` (a multiple of 4) of the function.
    fn read(&mut self, at: Address, offset: usize) -> u32;
    fn write(&mut self, at: Address, offset: usize, value: u32);
}

/// Vendor and device, offset 0.
pub const ID: usize = 0x00;
/// Command (low half) and status (high half).
pub const COMMAND: usize = 0x04;
/// Revision (low byte) and class code (upper 24 bits).
pub const CLASS: usize = 0x08;
/// Cache line, latency, header type (bits 23:16, bit 7 multifunction), BIST.
pub const HEADER: usize = 0x0C;
/// The first BAR; six in a type 0 header.
pub const BAR0: usize = 0x10;
pub const BARS: usize = 6;
/// The capabilities pointer, in the low byte of the word at 0x34.
pub const CAPABILITIES: usize = 0x34;
/// I/O space and memory space decoding, bus mastering.
pub const IO: u32 = 1 << 0;
pub const MEMORY: u32 = 1 << 1;
pub const BUS_MASTER: u32 = 1 << 2;
/// The first byte past the header, where capabilities begin.
pub const FIRST_CAPABILITY: usize = 0x40;
/// The capabilities a list may hold: 48 fit in the 192 bytes past the
/// header, so a longer walk is a loop in the list.
pub const MOST_CAPABILITIES: usize = 48;
/// An empty function reads all ones.
const NONE: u32 = 0xFFFF_FFFF;

/// What a function says of itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    pub at: Address,
    pub vendor: u16,
    pub device: u16,
    pub revision: u8,
    /// Base class, subclass and interface.
    pub class: u32,
    /// The header type without the multifunction bit.
    pub header: u8,
}

impl Function {
    /// `vendor << 16 | device`, the form the tables of init name a function by.
    pub const fn id(&self) -> u32 {
        (self.vendor as u32) << 16 | self.device as u32
    }
}

/// The function at `at`; None when none answers.
pub fn function(config: &mut impl Config, at: Address) -> Option<Function> {
    let id = config.read(at, ID);
    if id == NONE || id & 0xFFFF == 0xFFFF {
        return None;
    }
    let class = config.read(at, CLASS);
    let header = config.read(at, HEADER);
    Some(Function {
        at,
        vendor: id as u16,
        device: (id >> 16) as u16,
        revision: class as u8,
        class: class >> 8,
        header: ((header >> 16) & 0x7F) as u8,
    })
}

/// Visits the functions of the buses `first..=last` in the order of
/// bus, device, function; functions 1 to 7 only where function 0 has the
/// multifunction bit. The work is at most `buses * 256` reads of an ID.
/// `visit` returns false to stop.
pub fn scan(
    config: &mut impl Config,
    first: u8,
    last: u8,
    mut visit: impl FnMut(Function) -> bool,
) {
    for bus in first..=last {
        for device in 0..32 {
            let zero = Address::new(bus, device, 0);
            let Some(head) = function(config, zero) else {
                continue;
            };
            let multi = config.read(zero, HEADER) & (1 << 23) != 0;
            let count = if multi || cfg!(feature = "break-multifunction") {
                8
            } else {
                1
            };
            for f in 0..count {
                let at = Address::new(bus, device, f);
                let found = if f == 0 {
                    Some(head)
                } else {
                    function(config, at)
                };
                if let Some(found) = found
                    && !visit(found)
                {
                    return;
                }
            }
        }
        if bus == 255 {
            break;
        }
    }
}

/// The n-th function (counting from 0, in the order of `scan`) whose vendor
/// and device are `id` (`vendor << 16 | device`).
pub fn find(
    config: &mut impl Config,
    first: u8,
    last: u8,
    id: u32,
    index: usize,
) -> Option<Function> {
    let mut seen = 0;
    let mut found = None;
    scan(config, first, last, |f| {
        if f.id() == id {
            if seen == index {
                found = Some(f);
                return false;
            }
            seen += 1;
        }
        true
    });
    found
}

/// What a BAR decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Io,
    Mem32,
    Mem64,
}

/// A BAR as the firmware set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bar {
    pub index: usize,
    pub kind: Kind,
    pub prefetchable: bool,
    /// The address the firmware wrote; 0 for a BAR it left empty.
    pub base: u64,
}

impl Bar {
    /// The number of BAR registers it takes.
    pub const fn registers(&self) -> usize {
        if matches!(self.kind, Kind::Mem64) {
            2
        } else {
            1
        }
    }
}

/// The BAR at `index`, read as it stands. A 64-bit BAR at the last index
/// has no upper half and reads as None, as does an index past 5.
pub fn bar(config: &mut impl Config, at: Address, index: usize) -> Option<Bar> {
    if index >= BARS {
        return None;
    }
    let low = config.read(at, BAR0 + 4 * index);
    if low & 1 == 1 {
        return Some(Bar {
            index,
            kind: Kind::Io,
            prefetchable: false,
            base: u64::from(low & !0b11),
        });
    }
    let prefetchable = low & 0b1000 != 0;
    if (low >> 1) & 3 == 2 {
        if index + 1 >= BARS {
            return None;
        }
        let high = config.read(at, BAR0 + 4 * index + 4);
        return Some(Bar {
            index,
            kind: Kind::Mem64,
            prefetchable,
            base: u64::from(high) << 32 | u64::from(low & !0xF),
        });
    }
    Some(Bar {
        index,
        kind: Kind::Mem32,
        prefetchable,
        base: u64::from(low & !0xF),
    })
}

/// Why a BAR was not measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The function is a serial controller (base class 0x07), which may be
    /// the console: the library never writes to it.
    Console,
    /// The size is no power of two or does not divide the base.
    Misaligned,
}

/// The base class of the communication controllers, the console among them.
pub const CLASS_COMMUNICATION: u32 = 0x07;

/// The size of the BAR, measured the standard way: decoding off, all ones
/// written, the mask read back, the BAR and the command word restored. It
/// writes to the function, so the caller measures once, at start, before a
/// driver runs, and the library refuses a serial function outright (the
/// console may speak through it). 0 for a BAR that is not implemented. The
/// size is checked against the base: a base the size does not divide is the
/// firmware's own mistake.
pub fn measure(config: &mut impl Config, function: &Function, bar: &Bar) -> Result<u64, Refused> {
    if function.class >> 16 == CLASS_COMMUNICATION && !cfg!(feature = "break-measure-console") {
        return Err(Refused::Console);
    }
    let at = function.at;
    let register = BAR0 + 4 * bar.index;
    let command = config.read(at, COMMAND) & 0xFFFF;
    config.write(at, COMMAND, command & !(IO | MEMORY));
    let low_old = config.read(at, register);
    config.write(at, register, NONE);
    let low = config.read(at, register);
    config.write(at, register, low_old);
    let size = match bar.kind {
        Kind::Io => mask_size(u64::from(low & !0b11), 0xFFFF_FFFF),
        Kind::Mem32 => mask_size(u64::from(low & !0xF), 0xFFFF_FFFF),
        Kind::Mem64 => {
            let high_old = config.read(at, register + 4);
            config.write(at, register + 4, NONE);
            let high = config.read(at, register + 4);
            config.write(at, register + 4, high_old);
            mask_size(u64::from(high) << 32 | u64::from(low & !0xF), u64::MAX)
        }
    };
    if !cfg!(feature = "break-restore-command") {
        config.write(at, COMMAND, command);
    }
    if size != 0 && (!size.is_power_of_two() || !bar.base.is_multiple_of(size)) {
        return Err(Refused::Misaligned);
    }
    Ok(size)
}

/// The size a BAR's address mask shows: its lowest set bit, 0 for no bit.
/// `all` is the width of the register, whose clear upper bits of a narrow
/// BAR are not part of the size.
const fn mask_size(mask: u64, all: u64) -> u64 {
    if mask == 0 { 0 } else { (!mask & all) + 1 }
}

/// The offset of the first capability of the function's list whose first
/// word `wanted` takes, from `read`, the 32-bit registers of the
/// configuration space. None when the list holds none or does not end: a
/// next pointer below 0x40 or off a word ends the list, and the walk stops
/// after `MOST_CAPABILITIES` steps.
pub fn capability(
    read: &mut impl FnMut(usize) -> u32,
    wanted: impl Fn(u32) -> bool,
) -> Option<usize> {
    let mut at = (read(CAPABILITIES) & 0xFC) as usize;
    if at < FIRST_CAPABILITY {
        return None;
    }
    for _ in 0..MOST_CAPABILITIES + usize::from(cfg!(feature = "break-cap-limit")) {
        let head = read(at);
        if wanted(head) {
            return Some(at);
        }
        at = ((head >> 8) & 0xFF) as usize;
        if at < FIRST_CAPABILITY || at & 3 != 0 {
            return None;
        }
    }
    None
}

/// The MSI-X capability (PCI Local Bus 3.0, 6.8.2): its ID, and the bits of
/// its first word, whose upper half is Message Control: MSI-X Enable (15),
/// Function Mask (14) and the table's size less one (10:0).
pub const MSIX_CAPABILITY: u32 = 0x11;
pub const MSIX_ENABLE: u32 = 1 << 31;
pub const MSIX_FUNCTION_MASK: u32 = 1 << 30;
/// An entry of the table: 16 bytes, the address (low, high), the data and
/// Vector Control, whose bit 0 masks the vector.
pub const MSIX_ENTRY: usize = 16;
pub const MSIX_MASKED: u32 = 1;
/// The value of no vector in the Virtio common configuration.
pub const NO_VECTOR: u16 = 0xFFFF;

/// The function's MSI-X capability: where it lies in the configuration
/// space, the vectors of its table, and the BAR and offset of the table and
/// of the pending bit array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msix {
    pub at: usize,
    pub vectors: u16,
    pub bar: u8,
    pub offset: u32,
    pub pba_bar: u8,
    pub pba_offset: u32,
}

impl Msix {
    /// The first word of the capability with MSI-X on and no function
    /// mask, from the word `head` read there; the ID and next pointer are
    /// read-only, and the table size too.
    pub const fn enabled(head: u32) -> u32 {
        (head | MSIX_ENABLE) & !MSIX_FUNCTION_MASK
    }

    /// The four words of the table entry of a vector that writes `data` to
    /// `address`, unmasked.
    pub const fn entry(address: u64, data: u32) -> [u32; 4] {
        [address as u32, (address >> 32) as u32, data, 0]
    }

    /// The vector of queue `queue`: queue i takes vector i while the table
    /// has one, and none past it (a driver then polls that queue).
    pub const fn queue_vector(&self, queue: u16) -> u16 {
        if queue < self.vectors {
            queue
        } else {
            NO_VECTOR
        }
    }
}

/// The function's MSI-X capability from `read`; None without one.
pub fn msix(mut read: impl FnMut(usize) -> u32) -> Option<Msix> {
    let at = capability(&mut read, |head| head & 0xFF == MSIX_CAPABILITY)?;
    let table = read(at + 4);
    let pba = read(at + 8);
    Some(Msix {
        at,
        vectors: ((read(at) >> 16) & 0x7FF) as u16 + 1,
        bar: (table & 0b111) as u8,
        offset: table & !0b111,
        pba_bar: (pba & 0b111) as u8,
        pba_offset: pba & !0b111,
    })
}

#[cfg(any(test, feature = "fake"))]
pub mod fake;
#[cfg(test)]
mod tests;
