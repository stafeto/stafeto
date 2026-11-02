// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `PT_DYNAMIC`: the tags the loader accepts (spec 2, 3.12.4) and the
//! checks of every table they name.

use crate::{
    Access, Array, Dynamic, Limit, Map, Memory, Module, NEEDED, RELA_SIZE, Refusal, Role, SYM_SIZE,
    SYMBOLS_MAX, Segment,
};

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_PLTGOT: i64 = 3;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_SONAME: i64 = 14;
const DT_RPATH: i64 = 15;
const DT_SYMBOLIC: i64 = 16;
const DT_DEBUG: i64 = 21;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_BIND_NOW: i64 = 24;
const DT_INIT_ARRAY: i64 = 25;
const DT_FINI_ARRAY: i64 = 26;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_FINI_ARRAYSZ: i64 = 28;
const DT_RUNPATH: i64 = 29;
const DT_FLAGS: i64 = 30;
const DT_PREINIT_ARRAY: i64 = 32;
const DT_PREINIT_ARRAYSZ: i64 = 33;
const DT_RELRSZ: i64 = 35;
const DT_RELR: i64 = 36;
const DT_RELRENT: i64 = 37;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_RELACOUNT: i64 = 0x6fff_fff9;
const DT_FLAGS_1: i64 = 0x6fff_fffb;
/// The tags of the AArch64 psABI (BTI, PAC, variant PCS, memory tagging).
const DT_AARCH64: core::ops::RangeInclusive<i64> = 0x7000_0000..=0x7000_000f;

const DF_SYMBOLIC: u64 = 0x2;
const DF_BIND_NOW: u64 = 0x8;
const DF_STATIC_TLS: u64 = 0x10;
const DF_1_NOW: u64 = 0x1;

/// A tag that may come once: its value, or absent.
#[derive(Clone, Copy, Default)]
struct Once(Option<u64>);

impl Once {
    fn set(&mut self, tag: i64, value: u64) -> Result<(), Refusal> {
        if self.0.is_some() {
            return Err(Refusal::Duplicate(tag));
        }
        self.0 = Some(value);
        Ok(())
    }

    fn need(self, tag: i64) -> Result<u64, Refusal> {
        self.0.ok_or(Refusal::Missing(tag))
    }
}

/// A table with its size, both or neither; the size a whole number of
/// records of `unit` bytes, the table inside a segment.
fn table(
    map: &Map<'_>,
    (address, size): (Once, Once),
    tags: (i64, i64),
    unit: u64,
) -> Result<(u64, u64), Refusal> {
    match (address.0, size.0) {
        (None, None) => Ok((0, 0)),
        (Some(_), None) => Err(Refusal::Missing(tags.1)),
        (None, Some(_)) => Err(Refusal::Missing(tags.0)),
        (Some(address), Some(size)) => {
            if !size.is_multiple_of(unit)
                || !address.is_multiple_of(unit.min(8))
                || !map.contains(address, size)
            {
                return Err(Refusal::Table(tags.0));
            }
            if size == 0 {
                return Ok((0, 0));
            }
            Ok((address, size))
        }
    }
}

/// The accepted entry size of a table, when the tag is given.
fn entry(tag: i64, given: Once, want: u64) -> Result<(), Refusal> {
    match given.0 {
        Some(value) if value != want => Err(Refusal::Tag(tag)),
        _ => Ok(()),
    }
}

/// Reads the dynamic section `dynamic` (the bytes of `PT_DYNAMIC`) of a
/// module with these `segments` and `bias`, in the given `role`, and checks
/// everything it names against the segments and the contents of `mem`.
/// The part of the spec's `parse(module, dynamic_bytes)` that needs the
/// segments is given apart, because the module holds the result.
pub fn parse<M: Memory + ?Sized>(
    role: Role,
    segments: &[Segment; 3],
    bias: u64,
    dynamic: &[u8],
    mem: &M,
) -> Result<Dynamic, Refusal> {
    let map = Map { segments, bias };
    if !dynamic.len().is_multiple_of(16) {
        return Err(Refusal::Section);
    }
    let (mut strtab, mut strsz, mut symtab, mut syment) = <(Once, Once, Once, Once)>::default();
    let (mut rela, mut relasz, mut relaent) = <(Once, Once, Once)>::default();
    let (mut jmprel, mut pltrelsz, mut pltrel) = <(Once, Once, Once)>::default();
    let (mut relr, mut relrsz, mut relrent) = <(Once, Once, Once)>::default();
    let (mut pre, mut presz, mut init, mut initsz, mut fini, mut finisz) =
        <(Once, Once, Once, Once, Once, Once)>::default();
    let (mut flags, mut flags_1, mut gnu_hash) = <(Once, Once, Once)>::default();
    let mut needed: Option<u64> = None;
    let mut ended = false;
    for record in dynamic.as_chunks::<16>().0 {
        let tag = i64::from_le_bytes(record[..8].try_into().unwrap());
        let value = u64::from_le_bytes(record[8..].try_into().unwrap());
        match tag {
            DT_NULL => {
                ended = true;
                break;
            }
            DT_NEEDED => {
                if role == Role::Library || needed.is_some() {
                    return Err(Refusal::Needed);
                }
                needed = Some(value);
            }
            DT_PLTRELSZ => pltrelsz.set(tag, value)?,
            DT_STRTAB => strtab.set(tag, value)?,
            DT_STRSZ => strsz.set(tag, value)?,
            DT_SYMTAB => symtab.set(tag, value)?,
            DT_SYMENT => syment.set(tag, value)?,
            DT_RELA => rela.set(tag, value)?,
            DT_RELASZ => relasz.set(tag, value)?,
            DT_RELAENT => relaent.set(tag, value)?,
            DT_JMPREL => jmprel.set(tag, value)?,
            DT_PLTREL => pltrel.set(tag, value)?,
            DT_RELR => relr.set(tag, value)?,
            DT_RELRSZ => relrsz.set(tag, value)?,
            DT_RELRENT => relrent.set(tag, value)?,
            DT_PREINIT_ARRAY => pre.set(tag, value)?,
            DT_PREINIT_ARRAYSZ => presz.set(tag, value)?,
            DT_INIT_ARRAY => init.set(tag, value)?,
            DT_INIT_ARRAYSZ => initsz.set(tag, value)?,
            DT_FINI_ARRAY => fini.set(tag, value)?,
            DT_FINI_ARRAYSZ => finisz.set(tag, value)?,
            DT_GNU_HASH => gnu_hash.set(tag, value)?,
            DT_FLAGS => {
                if value & !(DF_SYMBOLIC | DF_BIND_NOW | DF_STATIC_TLS) != 0 {
                    return Err(Refusal::Tag(tag));
                }
                flags.set(tag, value)?;
            }
            DT_FLAGS_1 => {
                if value & !DF_1_NOW != 0 {
                    return Err(Refusal::Tag(tag));
                }
                flags_1.set(tag, value)?;
            }
            // The tables of the dynamic section that need no check or are
            // not used: the address of the GOT is the loader's to fill by
            // the relocations, the others the loader never reads.
            DT_BIND_NOW | DT_SYMBOLIC | DT_PLTGOT | DT_RELACOUNT | DT_DEBUG | DT_SONAME
            | DT_HASH | DT_RPATH | DT_RUNPATH => {}
            t if DT_AARCH64.contains(&t) => {}
            // DT_TEXTREL, DT_INIT, DT_FINI, DT_VERNEED, DT_REL*, anything else.
            _ => return Err(Refusal::Tag(tag)),
        }
    }
    if !ended {
        return Err(Refusal::Section);
    }

    let strtab_at = strtab.need(DT_STRTAB)?;
    let strsz = strsz.need(DT_STRSZ)?;
    if strsz == 0 || !map.contains(strtab_at, strsz) {
        return Err(Refusal::Table(DT_STRTAB));
    }
    let symtab_at = symtab.need(DT_SYMTAB)?;
    entry(DT_SYMENT, syment, SYM_SIZE)?;
    if !symtab_at.is_multiple_of(8) {
        return Err(Refusal::Table(DT_SYMTAB));
    }
    let hash_at = gnu_hash.need(DT_GNU_HASH)?;
    entry(DT_RELAENT, relaent, RELA_SIZE)?;
    entry(DT_RELRENT, relrent, 8)?;
    let (rela_at, relasz) = table(&map, (rela, relasz), (DT_RELA, DT_RELASZ), RELA_SIZE)?;
    let (jmprel_at, pltrelsz) = table(
        &map,
        (jmprel, pltrelsz),
        (DT_JMPREL, DT_PLTRELSZ),
        RELA_SIZE,
    )?;
    if jmprel.0.is_some() {
        match pltrel.0 {
            Some(7) => {}
            Some(_) => return Err(Refusal::Tag(DT_PLTREL)),
            None => return Err(Refusal::Missing(DT_PLTREL)),
        }
    }
    let (relr_at, relrsz) = table(&map, (relr, relrsz), (DT_RELR, DT_RELRSZ), 8)?;
    let array = |(address, size): (Once, Once), tags: (i64, i64)| {
        table(&map, (address, size), tags, 8).map(|(vaddr, size)| Array { vaddr, size })
    };
    let preinit = array((pre, presz), (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ))?;
    let init = array((init, initsz), (DT_INIT_ARRAY, DT_INIT_ARRAYSZ))?;
    let fini = array((fini, finisz), (DT_FINI_ARRAY, DT_FINI_ARRAYSZ))?;

    match (role, needed) {
        (Role::Program, None) => return Err(Refusal::Needed),
        (Role::Program, Some(name)) => needed_is_libc(&map, mem, strtab_at, strsz, name)?,
        _ => {}
    }

    let mut parsed = Dynamic {
        strtab: strtab_at,
        strsz,
        symtab: symtab_at,
        rela: rela_at,
        relasz,
        jmprel: jmprel_at,
        pltrelsz,
        relr: relr_at,
        relrsz,
        preinit,
        init,
        fini,
        flags: flags.0.unwrap_or(0) | flags_1.0.unwrap_or(0) << 32,
        gnu_hash: hash_at,
        nbuckets: 0,
        symoffset: 0,
        bloom_size: 0,
        bloom_shift: 0,
        nsyms: 0,
        role,
    };
    hash_geometry(&map, mem, &mut parsed)?;
    if !map.contains(symtab_at, parsed.nsyms as u64 * SYM_SIZE) {
        return Err(Refusal::Table(DT_SYMTAB));
    }
    Ok(parsed)
}

/// `DT_NEEDED` of a program names libc.so and nothing else.
fn needed_is_libc<M: Memory + ?Sized>(
    map: &Map<'_>,
    mem: &M,
    strtab: u64,
    strsz: u64,
    name: u64,
) -> Result<(), Refusal> {
    let end = name
        .checked_add(NEEDED.len() as u64 + 1)
        .ok_or(Refusal::Needed)?;
    if end > strsz {
        return Err(Refusal::Needed);
    }
    let mut bytes = [0u8; NEEDED.len() + 1];
    map.read(mem, strtab + name, &mut bytes, DT_STRTAB)?;
    if &bytes[..NEEDED.len()] != NEEDED || bytes[NEEDED.len()] != 0 {
        return Err(Refusal::Needed);
    }
    Ok(())
}

/// Reads the header of `DT_GNU_HASH`, checks the table inside a segment and
/// counts the symbols the chains name: from the last bucket's chain to the
/// entry with the end bit.
fn hash_geometry<M: Memory + ?Sized>(
    map: &Map<'_>,
    mem: &M,
    d: &mut Dynamic,
) -> Result<(), Refusal> {
    const TAG: i64 = DT_GNU_HASH;
    let at = d.gnu_hash;
    if !at.is_multiple_of(8) {
        return Err(Refusal::Table(TAG));
    }
    let nbuckets = map.u32(mem, at, TAG)?;
    let symoffset = map.u32(mem, at + 4, TAG)?;
    let bloom_size = map.u32(mem, at + 8, TAG)?;
    let bloom_shift = map.u32(mem, at + 12, TAG)?;
    if nbuckets == 0 || !bloom_size.is_power_of_two() || symoffset == 0 {
        return Err(Refusal::Hash);
    }
    if nbuckets > SYMBOLS_MAX || bloom_size > SYMBOLS_MAX || symoffset > SYMBOLS_MAX {
        return Err(Refusal::Limit(Limit::Symbols));
    }
    let buckets = at.checked_add(16 + 8 * bloom_size as u64);
    let chains = buckets.and_then(|b| b.checked_add(4 * nbuckets as u64));
    let (Some(buckets), Some(chains)) = (buckets, chains) else {
        return Err(Refusal::Table(TAG));
    };
    if !map.contains(at, chains - at) {
        return Err(Refusal::Table(TAG));
    }
    let mut last = 0u32;
    for i in 0..nbuckets {
        let bucket = map.u32(mem, buckets + 4 * i as u64, TAG)?;
        if bucket == 0 {
            continue;
        }
        if bucket < symoffset {
            return Err(Refusal::Hash);
        }
        last = last.max(bucket);
    }
    let nsyms = if last == 0 {
        symoffset
    } else {
        let mut i = last;
        loop {
            if i >= SYMBOLS_MAX {
                return Err(Refusal::Limit(Limit::Symbols));
            }
            let link = map.u32(mem, chains + 4 * (i - symoffset) as u64, TAG)?;
            if link & 1 != 0 {
                break i + 1;
            }
            i += 1;
        }
    };
    d.nbuckets = nbuckets;
    d.symoffset = symoffset;
    d.bloom_size = bloom_size;
    d.bloom_shift = bloom_shift;
    d.nsyms = nsyms;
    Ok(())
}

/// The bytes of a `PT_DYNAMIC` the layer reads for `dlsym` (the loader's
/// limit, 64 entries).
pub const DYNAMIC_MAX: usize = 1024;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_TLS: u32 = 7;
/// The bytes of an `Elf64_Phdr`.
pub const PHDR_SIZE: usize = 56;

/// The module of an object that is already in memory, from the bytes of its
/// program headers (`headers`, whole `Elf64_Phdr` records): one `PT_LOAD`
/// each of read-only, read-execute and read-write, a `PT_DYNAMIC` that fits
/// `DYNAMIC_MAX`, and the bias `bias`. The tables the dynamic section names
/// are checked as `parse` checks them. The layer's `dlsym` uses it on the
/// program and on libc.so, which the loader has already linked.
pub fn module<M: Memory + ?Sized>(
    role: Role,
    headers: &[u8],
    bias: u64,
    mem: &M,
) -> Result<Module, Refusal> {
    if !headers.len().is_multiple_of(PHDR_SIZE) {
        return Err(Refusal::Section);
    }
    let word = |h: &[u8], at: usize| u64::from_le_bytes(h[at..at + 8].try_into().unwrap());
    let mut parts: [Option<Segment>; 3] = [None; 3];
    let mut dynamic: Option<(u64, u64)> = None;
    let mut tls_align = 0;
    for h in headers.as_chunks::<PHDR_SIZE>().0 {
        let kind = u32::from_le_bytes(h[0..4].try_into().unwrap());
        let flags = u32::from_le_bytes(h[4..8].try_into().unwrap());
        let (vaddr, filesz, memsz, align) = (word(h, 16), word(h, 32), word(h, 40), word(h, 48));
        match kind {
            PT_LOAD => {
                let (slot, access) = match flags & 7 {
                    4 => (0, Access::Read),
                    5 => (1, Access::ReadExec),
                    6 => (2, Access::ReadWrite),
                    _ => return Err(Refusal::Section),
                };
                if parts[slot]
                    .replace(Segment {
                        vaddr,
                        memsz,
                        access,
                    })
                    .is_some()
                {
                    return Err(Refusal::Section);
                }
            }
            PT_DYNAMIC => {
                if dynamic.replace((vaddr, filesz)).is_some() {
                    return Err(Refusal::Section);
                }
            }
            PT_TLS => tls_align = align,
            _ => (),
        }
    }
    let [Some(a), Some(b), Some(c)] = parts else {
        return Err(Refusal::Section);
    };
    let segments = [a, b, c];
    let (at, size) = dynamic.ok_or(Refusal::Section)?;
    let size = usize::try_from(size).map_err(|_| Refusal::Section)?;
    if size == 0 || size > DYNAMIC_MAX {
        return Err(Refusal::Section);
    }
    let mut bytes = [0u8; DYNAMIC_MAX];
    let bytes = &mut bytes[..size];
    let from = at.checked_add(bias).ok_or(Refusal::Overflow)?;
    mem.read(from, bytes)?;
    let dynamic = parse(role, &segments, bias, bytes, mem)?;
    Ok(Module {
        segments,
        bias,
        tls_align,
        dynamic,
    })
}
