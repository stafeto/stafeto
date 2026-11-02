// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Symbols: the table, the names and the search by `DT_GNU_HASH`.

use crate::{CHAIN_MAX, Limit, Memory, Module, NAME_MAX, Refusal, SYM_SIZE};

pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;

pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_TLS: u8 = 6;

const TAG_STRTAB: i64 = 5;
const TAG_SYMTAB: i64 = 6;
const TAG_HASH: i64 = 0x6fff_fef5;

/// A symbol of a module as its table holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub name: u32,
    pub bind: u8,
    pub kind: u8,
    pub shndx: u16,
    /// `st_value`: the address in the module's own space (before the bias),
    /// the absolute address for `SHN_ABS`, the offset in the TLS block for
    /// `STT_TLS`.
    pub value: u64,
    pub size: u64,
}

impl Symbol {
    pub fn defined(&self) -> bool {
        self.shndx != SHN_UNDEF
    }

    /// The address in the process: `value` plus the bias, except for
    /// `SHN_ABS`.
    pub fn address(&self, bias: u64) -> Result<u64, Refusal> {
        if self.shndx == SHN_ABS {
            Ok(self.value)
        } else {
            bias.checked_add(self.value).ok_or(Refusal::Overflow)
        }
    }
}

/// The hash `DT_GNU_HASH` uses (the djb2 of the bytes).
pub fn gnu_hash(name: &[u8]) -> u32 {
    name.iter()
        .fold(5381u32, |h, &c| h.wrapping_mul(33).wrapping_add(c as u32))
}

impl Module {
    /// The symbol `index` of the table; the index is below the count the
    /// hash table gives.
    pub fn symbol<M: Memory + ?Sized>(&self, mem: &M, index: u32) -> Result<Symbol, Refusal> {
        if index >= self.dynamic.nsyms {
            return Err(Refusal::Symbol(index));
        }
        let map = self.map();
        let mut bytes = [0u8; SYM_SIZE as usize];
        let at = self.dynamic.symtab + index as u64 * SYM_SIZE;
        map.read(mem, at, &mut bytes, TAG_SYMTAB)?;
        Ok(Symbol {
            name: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            bind: bytes[4] >> 4,
            kind: bytes[4] & 15,
            shndx: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            value: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            size: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        })
    }

    /// Copies the name of `symbol` into `out` and gives its length: inside
    /// `DT_STRSZ`, ended by NUL, NAME_MAX bytes at most.
    pub fn name_of<M: Memory + ?Sized>(
        &self,
        mem: &M,
        symbol: &Symbol,
        out: &mut [u8; NAME_MAX],
    ) -> Result<usize, Refusal> {
        let d = &self.dynamic;
        let map = self.map();
        let start = symbol.name as u64;
        let mut length = 0;
        loop {
            let at = start + length as u64;
            if at >= d.strsz {
                return Err(Refusal::Name);
            }
            let mut byte = [0u8];
            map.read(mem, d.strtab + at, &mut byte, TAG_STRTAB)?;
            if byte[0] == 0 {
                return Ok(length);
            }
            *out.get_mut(length).ok_or(Refusal::Name)? = byte[0];
            length += 1;
        }
    }

    /// Whether the name of `symbol` is `name`, byte for byte and ended there.
    fn name_is<M: Memory + ?Sized>(
        &self,
        mem: &M,
        symbol: &Symbol,
        name: &[u8],
    ) -> Result<bool, Refusal> {
        let d = &self.dynamic;
        let map = self.map();
        let start = symbol.name as u64;
        for i in 0..=name.len() {
            let at = start + i as u64;
            if at >= d.strsz {
                return Err(Refusal::Name);
            }
            let mut byte = [0u8];
            map.read(mem, d.strtab + at, &mut byte, TAG_STRTAB)?;
            if byte[0] != name.get(i).copied().unwrap_or(0) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Whether a symbol may satisfy a reference from another module: defined,
/// global or weak, an object, a function, a TLS symbol or untyped.
fn exports(symbol: &Symbol) -> bool {
    symbol.defined()
        && symbol.shndx != SHN_COMMON
        && matches!(symbol.bind, STB_GLOBAL | STB_WEAK)
        && matches!(symbol.kind, STT_NOTYPE | STT_OBJECT | STT_FUNC | STT_TLS)
}

/// Looks `name` up in the module by its `DT_GNU_HASH` (the Bloom filter,
/// the bucket, the chain of at most CHAIN_MAX steps): the first symbol of
/// that name that the module exports, or None. A name longer than
/// NAME_MAX or a broken table is a refusal.
pub fn lookup<M: Memory + ?Sized>(
    module: &Module,
    mem: &M,
    name: &[u8],
) -> Result<Option<Symbol>, Refusal> {
    let d = &module.dynamic;
    let map = module.map();
    if name.len() > NAME_MAX {
        return Err(Refusal::Name);
    }
    if name.is_empty() || d.nsyms == 0 {
        return Ok(None);
    }
    let hash = gnu_hash(name);
    let bloom_at = d.gnu_hash + 16;
    let word = map.u64(
        mem,
        bloom_at + 8 * ((hash / 64) & (d.bloom_size - 1)) as u64,
        TAG_HASH,
    )?;
    let second = hash.checked_shr(d.bloom_shift).unwrap_or(0);
    let mask = 1u64 << (hash % 64) | 1u64 << (second % 64);
    if word & mask != mask {
        return Ok(None);
    }
    let buckets = bloom_at + 8 * d.bloom_size as u64;
    let chains = buckets + 4 * d.nbuckets as u64;
    let mut index = map.u32(mem, buckets + 4 * (hash % d.nbuckets) as u64, TAG_HASH)?;
    if index < d.symoffset {
        return Ok(None);
    }
    let mut step = 0;
    loop {
        if step >= CHAIN_MAX {
            return Err(Refusal::Limit(Limit::Chain));
        }
        if index >= d.nsyms {
            return Err(Refusal::Symbol(index));
        }
        let link = map.u32(mem, chains + 4 * (index - d.symoffset) as u64, TAG_HASH)?;
        if (link ^ hash) >> 1 == 0 {
            let symbol = module.symbol(mem, index)?;
            if exports(&symbol) && module.name_is(mem, &symbol, name)? {
                return Ok(Some(symbol));
            }
        }
        if link & 1 != 0 {
            return Ok(None);
        }
        index += 1;
        step += 1;
    }
}
