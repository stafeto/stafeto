// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The relocations (spec 2, 3.12.4): libc.so first, then the program, all
//! of them at once (`DT_BIND_NOW` or not), no resolver left behind.

use crate::symbol::{SHN_COMMON, STB_WEAK, STT_FUNC, STT_NOTYPE, STT_OBJECT, STT_TLS};
use crate::{
    LOOKUPS_MAX, Limit, Map, Memory, Module, NAME_MAX, RELA_SIZE, RELOCS_MAX, Refusal, Role,
    Symbol, lookup,
};

const R_AARCH64_NONE: u32 = 0;
const R_AARCH64_ABS64: u32 = 257;
const R_AARCH64_GLOB_DAT: u32 = 1025;
const R_AARCH64_JUMP_SLOT: u32 = 1026;
const R_AARCH64_RELATIVE: u32 = 1027;
const R_AARCH64_TLS_TPREL64: u32 = 1030;

/// The records applied in one module, by kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kinds {
    pub none: u32,
    pub abs64: u32,
    pub glob_dat: u32,
    pub jump_slot: u32,
    pub relative: u32,
    /// Places a `DT_RELR` table applied.
    pub relr: u32,
    pub tpoff: u32,
}

impl Kinds {
    /// All the records that wrote something.
    pub fn total(&self) -> u32 {
        self.abs64 + self.glob_dat + self.jump_slot + self.relative + self.relr + self.tpoff
    }
}

/// What `relocate` did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub library: Kinds,
    pub program: Kinds,
    /// Names searched in the library (for the program's references).
    pub lookups: u32,
}

/// Relocates `library` (libc.so), then `program`, in `mem`. Writes only
/// whole words in the read-write segments. The first refusal stops the work
/// with the memory partly written: the process is not started then.
pub fn relocate<M: Memory + ?Sized>(
    library: &Module,
    program: &Module,
    mem: &mut M,
) -> Result<Counts, Refusal> {
    if library.dynamic.role != Role::Library || program.dynamic.role != Role::Program {
        return Err(Refusal::Role);
    }
    let mut counts = Counts::default();
    counts.library = module(library, library, mem, &mut counts.lookups)?;
    counts.program = module(program, library, mem, &mut counts.lookups)?;
    Ok(counts)
}

/// The align-up of the TLS offset of the library: the TLS block of libc.so
/// sits after the 16 bytes of the thread control block.
fn tls_base(library: &Module) -> Result<u64, Refusal> {
    let align = library.tls_align;
    if align == 0 || !align.is_power_of_two() {
        return Err(Refusal::NoTls);
    }
    Ok(16u64.next_multiple_of(align))
}

struct Record {
    place: u64,
    kind: u32,
    symbol: u32,
    addend: i64,
}

fn read_record<M: Memory + ?Sized>(
    map: &Map<'_>,
    mem: &M,
    at: u64,
    tag: i64,
) -> Result<Record, Refusal> {
    let mut bytes = [0u8; RELA_SIZE as usize];
    map.read(mem, at, &mut bytes, tag)?;
    let info = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    Ok(Record {
        place: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        kind: info as u32,
        symbol: (info >> 32) as u32,
        addend: i64::from_le_bytes(bytes[16..24].try_into().unwrap()),
    })
}

/// The value of the symbol of `record` for module `this`: its own address
/// in the library, in the program the program's own definition or the
/// library's (the weak ones that nothing defines have 0).
fn resolve<M: Memory + ?Sized>(
    this: &Module,
    library: &Module,
    mem: &M,
    record: &Record,
    lookups: &mut u32,
) -> Result<u64, Refusal> {
    let tls = record.kind == R_AARCH64_TLS_TPREL64;
    if record.symbol == 0 {
        // Without a symbol: the base of the block (TLS) or 0.
        return if tls { tls_base(library) } else { Ok(0) };
    }
    let symbol = this.symbol(mem, record.symbol)?;
    let is_library = this.dynamic.role == Role::Library;
    let found: Symbol;
    let found_in: &Module;
    if symbol.defined() {
        if symbol.shndx == SHN_COMMON {
            return Err(Refusal::SymbolType(record.symbol));
        }
        if symbol.kind == STT_TLS && !is_library {
            // The program has no TLS block of its own.
            return Err(Refusal::NoTls);
        }
        found = symbol;
        found_in = this;
    } else if is_library {
        // -Bsymbolic and -z defs: libc.so defines everything it uses.
        return Err(Refusal::Unresolved(record.symbol));
    } else {
        let mut name = [0u8; NAME_MAX];
        let len = this.name_of(mem, &symbol, &mut name)?;
        *lookups += 1;
        if *lookups > LOOKUPS_MAX {
            return Err(Refusal::Limit(Limit::Lookups));
        }
        match lookup(library, mem, &name[..len])? {
            Some(s) => {
                found = s;
                found_in = library;
            }
            None if symbol.bind == STB_WEAK && !tls => return Ok(0),
            None => return Err(Refusal::Unresolved(record.symbol)),
        }
    }
    match (tls, found.kind) {
        (true, STT_TLS) => {
            let base = tls_base(library)?;
            base.checked_add(found.value).ok_or(Refusal::Overflow)
        }
        (false, STT_NOTYPE | STT_OBJECT | STT_FUNC) => found.address(found_in.bias),
        _ => Err(Refusal::SymbolType(record.symbol)),
    }
}

fn module<M: Memory + ?Sized>(
    this: &Module,
    library: &Module,
    mem: &mut M,
    lookups: &mut u32,
) -> Result<Kinds, Refusal> {
    let d = &this.dynamic;
    let map = this.map();
    let mut kinds = Kinds::default();
    let records = (d.relasz + d.pltrelsz) / RELA_SIZE;
    if records > RELOCS_MAX as u64 {
        return Err(Refusal::Limit(Limit::Relocs));
    }
    let mut done = records as u32;
    for (table, size, tag) in [(d.rela, d.relasz, 7), (d.jmprel, d.pltrelsz, 23)] {
        for i in 0..size / RELA_SIZE {
            let record = read_record(&map, mem, table + i * RELA_SIZE, tag)?;
            apply(this, library, mem, &record, &mut kinds, lookups)?;
        }
    }
    // RELR: an even word is an address, an odd one a bitmap of the 63 words
    // after the last place.
    let mut next = 0u64;
    for i in 0..d.relrsz / 8 {
        let word = map.u64(mem, d.relr + 8 * i, 36)?;
        if word & 1 == 0 {
            relr_place(&map, mem, word, &mut kinds, &mut done)?;
            next = word.checked_add(8).ok_or(Refusal::Overflow)?;
        } else {
            for bit in 0..63u64 {
                if word >> (bit + 1) & 1 != 0 {
                    let place = next.checked_add(8 * bit).ok_or(Refusal::Overflow)?;
                    relr_place(&map, mem, place, &mut kinds, &mut done)?;
                }
            }
            next = next.checked_add(63 * 8).ok_or(Refusal::Overflow)?;
        }
    }
    Ok(kinds)
}

/// The word at `place` gets the bias added.
fn relr_place<M: Memory + ?Sized>(
    map: &Map<'_>,
    mem: &mut M,
    place: u64,
    kinds: &mut Kinds,
    done: &mut u32,
) -> Result<(), Refusal> {
    *done += 1;
    if *done > RELOCS_MAX {
        return Err(Refusal::Limit(Limit::Relocs));
    }
    check_place(map, place)?;
    let at = map.absolute(place)?;
    let mut bytes = [0u8; 8];
    mem.read(at, &mut bytes)?;
    let value = u64::from_le_bytes(bytes)
        .checked_add(map.bias)
        .ok_or(Refusal::Overflow)?;
    mem.write(at, &value.to_le_bytes())?;
    kinds.relr += 1;
    Ok(())
}

/// A place is a whole word, aligned, in the read-write segment.
fn check_place(map: &Map<'_>, place: u64) -> Result<(), Refusal> {
    if !place.is_multiple_of(8) || !map.writable(place, 8) {
        return Err(Refusal::Place(place));
    }
    Ok(())
}

fn apply<M: Memory + ?Sized>(
    this: &Module,
    library: &Module,
    mem: &mut M,
    record: &Record,
    kinds: &mut Kinds,
    lookups: &mut u32,
) -> Result<(), Refusal> {
    let map = this.map();
    let counter = match record.kind {
        R_AARCH64_NONE => {
            kinds.none += 1;
            return Ok(());
        }
        R_AARCH64_ABS64 => &mut kinds.abs64,
        R_AARCH64_GLOB_DAT => &mut kinds.glob_dat,
        R_AARCH64_JUMP_SLOT => &mut kinds.jump_slot,
        R_AARCH64_RELATIVE => &mut kinds.relative,
        R_AARCH64_TLS_TPREL64 => &mut kinds.tpoff,
        other => return Err(Refusal::Kind(other)),
    };
    check_place(&map, record.place)?;
    let base = if record.kind == R_AARCH64_RELATIVE {
        if record.symbol != 0 {
            return Err(Refusal::Symbol(record.symbol));
        }
        this.bias
    } else {
        resolve(this, library, mem, record, lookups)?
    };
    let value = base
        .checked_add_signed(record.addend)
        .ok_or(Refusal::Overflow)?;
    mem.write(map.absolute(record.place)?, &value.to_le_bytes())?;
    *counter += 1;
    Ok(())
}
