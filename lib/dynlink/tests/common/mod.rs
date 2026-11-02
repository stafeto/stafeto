// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A builder of small ELF modules in memory, the memory of the tests, and a
//! loader of real ELF files (the files of `target/libc-so`).
#![allow(dead_code)]

use dynlink::{Access, Dynamic, Fault, Memory, Module, Refusal, Role, Segment, gnu_hash, parse};
use std::collections::HashMap;

pub const PAGE: u64 = 4096;

pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_SONAME: i64 = 14;
pub const DT_RUNPATH: i64 = 29;
pub const DT_REL: i64 = 17;
pub const DT_DEBUG: i64 = 21;
pub const DT_PLTREL: i64 = 20;
pub const DT_TEXTREL: i64 = 22;
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_INIT_ARRAYSZ: i64 = 27;
pub const DT_FINI_ARRAYSZ: i64 = 28;
pub const DT_FLAGS: i64 = 30;
pub const DT_PREINIT_ARRAY: i64 = 32;
pub const DT_PREINIT_ARRAYSZ: i64 = 33;
pub const DT_RELRSZ: i64 = 35;
pub const DT_RELR: i64 = 36;
pub const DT_RELRENT: i64 = 37;
pub const DT_GNU_HASH: i64 = 0x6fff_fef5;
pub const DT_VERSYM: i64 = 0x6fff_fff0;
pub const DT_FLAGS_1: i64 = 0x6fff_fffb;
pub const DT_VERDEF: i64 = 0x6fff_fffc;
pub const DT_VERNEED: i64 = 0x6fff_fffe;
pub const DT_AARCH64_BTI_PLT: i64 = 0x7000_0001;

pub const R_NONE: u32 = 0;
pub const R_ABS64: u32 = 257;
pub const R_COPY: u32 = 1024;
pub const R_GLOB_DAT: u32 = 1025;
pub const R_JUMP_SLOT: u32 = 1026;
pub const R_RELATIVE: u32 = 1027;
pub const R_TLS_DTPMOD64: u32 = 1028;
pub const R_TLS_DTPREL64: u32 = 1029;
pub const R_TLS_TPREL64: u32 = 1030;
pub const R_TLSDESC: u32 = 1031;
pub const R_IRELATIVE: u32 = 1032;

pub const LOCAL: u8 = 0;
pub const GLOBAL: u8 = 1;
pub const WEAK: u8 = 2;
pub const NOTYPE: u8 = 0;
pub const OBJECT: u8 = 1;
pub const FUNC: u8 = 2;
pub const SECTION: u8 = 3;
pub const FILE: u8 = 4;
pub const TLS: u8 = 6;
pub const IFUNC: u8 = 10;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;

pub const LIB_BASE: u64 = 0x0400_0000;
pub const PROG_BASE: u64 = 0x20_0000;

/// The process's memory: pieces at addresses, a log of the writes.
#[derive(Clone, Default)]
pub struct Space {
    pub pieces: Vec<(u64, Vec<u8>)>,
    pub writes: Vec<u64>,
}

impl Space {
    pub fn with(mut self, address: u64, bytes: Vec<u8>) -> Space {
        self.pieces.push((address, bytes));
        self
    }

    fn piece(&self, address: u64, len: usize) -> Option<(usize, usize)> {
        let end = address.checked_add(len as u64)?;
        self.pieces
            .iter()
            .position(|(base, bytes)| *base <= address && end <= base + bytes.len() as u64)
            .map(|i| (i, (address - self.pieces[i].0) as usize))
    }

    pub fn word(&self, address: u64) -> u64 {
        let mut bytes = [0; 8];
        self.read(address, &mut bytes).unwrap();
        u64::from_le_bytes(bytes)
    }

    pub fn set(&mut self, address: u64, bytes: &[u8]) {
        let (i, at) = self.piece(address, bytes.len()).unwrap();
        self.pieces[i].1[at..at + bytes.len()].copy_from_slice(bytes);
    }

    pub fn set_u32(&mut self, address: u64, value: u32) {
        self.set(address, &value.to_le_bytes());
    }

    pub fn set_u64(&mut self, address: u64, value: u64) {
        self.set(address, &value.to_le_bytes());
    }

    pub fn bytes(&self, address: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        self.read(address, &mut out).unwrap();
        out
    }
}

impl Memory for Space {
    fn read(&self, address: u64, out: &mut [u8]) -> Result<(), Fault> {
        let (i, at) = self.piece(address, out.len()).ok_or(Fault)?;
        out.copy_from_slice(&self.pieces[i].1[at..at + out.len()]);
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Fault> {
        let (i, at) = self.piece(address, bytes.len()).ok_or(Fault)?;
        self.pieces[i].1[at..at + bytes.len()].copy_from_slice(bytes);
        self.writes.push(address);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Sym {
    pub name: String,
    pub bind: u8,
    pub kind: u8,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
    /// An undefined symbol that stays in the hashed part (to test that the
    /// lookup passes it by).
    pub hashed: bool,
}

#[derive(Clone, Debug)]
pub struct Rel {
    pub place: u64,
    pub kind: u32,
    pub sym: Option<String>,
    pub raw_sym: Option<u32>,
    pub addend: i64,
}

/// A module under construction. The segments: read-only (the tables),
/// executable (one page), read-write (`rw_size` bytes).
#[derive(Clone)]
pub struct B {
    pub base: u64,
    pub bias: u64,
    pub role: Role,
    pub syms: Vec<Sym>,
    pub rela: Vec<Rel>,
    pub jmprel: Vec<Rel>,
    pub relr: Vec<u64>,
    pub needed: Vec<String>,
    pub extra: Vec<(i64, u64)>,
    pub drop: Vec<i64>,
    pub nbuckets: u32,
    pub bloom_size: u32,
    pub r_size: u64,
    pub rw_size: u64,
    pub tls_align: u64,
    pub flags: Option<u64>,
}

impl B {
    pub fn library() -> B {
        B::new(LIB_BASE, Role::Library, vec![])
    }

    pub fn program() -> B {
        B::new(PROG_BASE, Role::Program, vec!["libc.so".into()])
    }

    fn new(base: u64, role: Role, needed: Vec<String>) -> B {
        B {
            base,
            bias: 0,
            role,
            syms: vec![],
            rela: vec![],
            jmprel: vec![],
            relr: vec![],
            needed,
            extra: vec![],
            drop: vec![],
            nbuckets: 3,
            bloom_size: 2,
            r_size: 4 * PAGE,
            rw_size: PAGE,
            tls_align: 0,
            flags: Some(0x8),
        }
    }

    pub fn sym(mut self, name: &str, bind: u8, kind: u8, shndx: u16, value: u64) -> B {
        self.syms.push(Sym {
            name: name.into(),
            bind,
            kind,
            shndx,
            value,
            size: 0,
            hashed: false,
        });
        self
    }

    /// A defined function: global, section 1.
    pub fn func(self, name: &str, value: u64) -> B {
        self.sym(name, GLOBAL, FUNC, 1, value)
    }

    pub fn undef(self, name: &str, bind: u8) -> B {
        self.sym(name, bind, NOTYPE, 0, 0)
    }

    pub fn rel(mut self, place: u64, kind: u32, sym: Option<&str>, addend: i64) -> B {
        self.rela.push(Rel {
            place,
            kind,
            sym: sym.map(String::from),
            raw_sym: None,
            addend,
        });
        self
    }

    pub fn slot(mut self, place: u64, kind: u32, sym: Option<&str>, addend: i64) -> B {
        self.jmprel.push(Rel {
            place,
            kind,
            sym: sym.map(String::from),
            raw_sym: None,
            addend,
        });
        self
    }

    /// Where the read-write segment starts.
    pub fn rw(&self) -> u64 {
        self.base + self.r_size + PAGE
    }

    pub fn build(&self) -> Built {
        let read_size = self.r_size;
        let rx = self.base + read_size;
        let rw = rx + PAGE;
        let total = (read_size + PAGE + self.rw_size) as usize;
        let mut image = vec![0u8; total];
        let mut at = 0usize;
        let put = |image: &mut Vec<u8>, at: &mut usize, bytes: &[u8], align: usize| -> u64 {
            *at = at.next_multiple_of(align);
            image[*at..*at + bytes.len()].copy_from_slice(bytes);
            let vaddr = *at as u64;
            *at += bytes.len();
            vaddr
        };
        // Symbols: null, the undefined ones, the defined ones by bucket.
        let (mut undef, mut defd): (Vec<Sym>, Vec<Sym>) = self
            .syms
            .iter()
            .cloned()
            .partition(|s| s.shndx == 0 && !s.hashed);
        defd.sort_by_key(|s| gnu_hash(s.name.as_bytes()) % self.nbuckets);
        let mut list = vec![];
        list.append(&mut undef);
        let symoffset = list.len() as u32 + 1;
        list.append(&mut defd);
        let mut strtab = vec![0u8];
        let mut offsets = HashMap::new();
        let name_at = |strtab: &mut Vec<u8>, name: &str| -> u32 {
            let at = strtab.len() as u32;
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            at
        };
        let mut index = HashMap::new();
        let mut symtab = vec![0u8; 24];
        for (i, s) in list.iter().enumerate() {
            let off = name_at(&mut strtab, &s.name);
            offsets.insert(s.name.clone(), off);
            index.entry(s.name.clone()).or_insert(i as u32 + 1);
            symtab.extend_from_slice(&off.to_le_bytes());
            symtab.push(s.bind << 4 | s.kind);
            symtab.push(0);
            symtab.extend_from_slice(&s.shndx.to_le_bytes());
            symtab.extend_from_slice(&s.value.to_le_bytes());
            symtab.extend_from_slice(&s.size.to_le_bytes());
        }
        let needed: Vec<u32> = self
            .needed
            .iter()
            .map(|n| name_at(&mut strtab, n))
            .collect();
        // The GNU hash.
        let mut hash = vec![];
        for v in [self.nbuckets, symoffset, self.bloom_size, 6] {
            hash.extend_from_slice(&v.to_le_bytes());
        }
        let mut bloom = vec![0u64; self.bloom_size as usize];
        let hashes: Vec<u32> = list
            .iter()
            .skip(symoffset as usize - 1)
            .map(|s| gnu_hash(s.name.as_bytes()))
            .collect();
        for h in &hashes {
            let w = ((h / 64) & (self.bloom_size - 1)) as usize;
            bloom[w] |= 1 << (h % 64) | 1 << ((h >> 6) % 64);
        }
        for w in &bloom {
            hash.extend_from_slice(&w.to_le_bytes());
        }
        let mut buckets = vec![0u32; self.nbuckets as usize];
        let mut chain = vec![];
        for (k, h) in hashes.iter().enumerate() {
            let b = (h % self.nbuckets) as usize;
            if buckets[b] == 0 {
                buckets[b] = symoffset + k as u32;
            }
            let last = hashes
                .get(k + 1)
                .is_none_or(|n| n % self.nbuckets != h % self.nbuckets);
            chain.push(h & !1 | last as u32);
        }
        for b in &buckets {
            hash.extend_from_slice(&b.to_le_bytes());
        }
        for c in &chain {
            hash.extend_from_slice(&c.to_le_bytes());
        }
        let rela_bytes = |rels: &[Rel]| -> Vec<u8> {
            let mut out = vec![];
            for r in rels {
                let sym = r
                    .raw_sym
                    .or_else(|| r.sym.as_ref().map(|n| index[n]))
                    .unwrap_or(0);
                out.extend_from_slice(&r.place.to_le_bytes());
                out.extend_from_slice(&((sym as u64) << 32 | r.kind as u64).to_le_bytes());
                out.extend_from_slice(&r.addend.to_le_bytes());
            }
            out
        };
        let symtab_at = put(&mut image, &mut at, &symtab, 8);
        let strtab_at = put(&mut image, &mut at, &strtab, 1);
        let hash_at = put(&mut image, &mut at, &hash, 8);
        let rela = rela_bytes(&self.rela);
        let jmprel = rela_bytes(&self.jmprel);
        let relr: Vec<u8> = self.relr.iter().flat_map(|w| w.to_le_bytes()).collect();
        let rela_at = put(&mut image, &mut at, &rela, 8);
        let jmprel_at = put(&mut image, &mut at, &jmprel, 8);
        let relr_at = put(&mut image, &mut at, &relr, 8);
        let base = self.base;
        let mut tags: Vec<(i64, u64)> = vec![];
        for n in &needed {
            tags.push((DT_NEEDED, *n as u64));
        }
        tags.push((DT_STRTAB, base + strtab_at));
        tags.push((DT_STRSZ, strtab.len() as u64));
        tags.push((DT_SYMTAB, base + symtab_at));
        tags.push((DT_SYMENT, 24));
        tags.push((DT_GNU_HASH, base + hash_at));
        if !rela.is_empty() {
            tags.push((DT_RELA, base + rela_at));
            tags.push((DT_RELASZ, rela.len() as u64));
            tags.push((DT_RELAENT, 24));
        }
        if !jmprel.is_empty() {
            tags.push((DT_JMPREL, base + jmprel_at));
            tags.push((DT_PLTRELSZ, jmprel.len() as u64));
            tags.push((DT_PLTREL, 7));
        }
        if !relr.is_empty() {
            tags.push((DT_RELR, base + relr_at));
            tags.push((DT_RELRSZ, relr.len() as u64));
            tags.push((DT_RELRENT, 8));
        }
        if let Some(f) = self.flags {
            tags.push((DT_FLAGS, f));
        }
        tags.retain(|(t, _)| !self.drop.contains(t));
        tags.extend(self.extra.iter().copied());
        let segments = [
            Segment {
                vaddr: base,
                memsz: read_size,
                access: Access::Read,
            },
            Segment {
                vaddr: rx,
                memsz: PAGE,
                access: Access::ReadExec,
            },
            Segment {
                vaddr: rw,
                memsz: self.rw_size,
                access: Access::ReadWrite,
            },
        ];
        // The dynamic section itself, for the picture; the parser takes the bytes.
        Built {
            space_base: base + self.bias,
            image,
            segments,
            tags,
            index,
            role: self.role,
            bias: self.bias,
            tls_align: self.tls_align,
            strtab: base + strtab_at,
            symtab: base + symtab_at,
            hash: base + hash_at,
            rela: base + rela_at,
            jmprel: base + jmprel_at,
            relr: base + relr_at,
            rw,
        }
    }
}

/// A module as built: the bytes of its three segments in memory, the
/// dynamic tags (to change before `module`), where things are.
#[derive(Clone)]
pub struct Built {
    pub space_base: u64,
    pub image: Vec<u8>,
    pub segments: [Segment; 3],
    pub tags: Vec<(i64, u64)>,
    pub index: HashMap<String, u32>,
    pub role: Role,
    pub bias: u64,
    pub tls_align: u64,
    pub strtab: u64,
    pub symtab: u64,
    pub hash: u64,
    pub rela: u64,
    pub jmprel: u64,
    pub relr: u64,
    pub rw: u64,
}

impl Built {
    pub fn dynamic_bytes(&self) -> Vec<u8> {
        let mut out = vec![];
        for (t, v) in &self.tags {
            out.extend_from_slice(&t.to_le_bytes());
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&[0; 16]);
        out
    }

    pub fn space(&self) -> Space {
        Space::default().with(self.space_base, self.image.clone())
    }

    /// The tag's value, changed.
    pub fn set_tag(&mut self, tag: i64, value: u64) {
        for t in &mut self.tags {
            if t.0 == tag {
                t.1 = value;
            }
        }
    }

    pub fn remove_tag(&mut self, tag: i64) {
        self.tags.retain(|t| t.0 != tag);
    }

    pub fn tag(&self, tag: i64) -> u64 {
        self.tags.iter().find(|t| t.0 == tag).unwrap().1
    }

    pub fn parse(&self, mem: &Space) -> Result<Dynamic, Refusal> {
        parse(
            self.role,
            &self.segments,
            self.bias,
            &self.dynamic_bytes(),
            mem,
        )
    }

    pub fn module(&self, mem: &Space) -> Result<Module, Refusal> {
        Ok(Module {
            segments: self.segments,
            bias: self.bias,
            tls_align: self.tls_align,
            dynamic: self.parse(mem)?,
        })
    }

    /// The address of the symbol `name` in the table.
    pub fn index(&self, name: &str) -> u32 {
        self.index[name]
    }

    /// Where the memory of the segment `n` starts in the process.
    pub fn at(&self, vaddr: u64) -> u64 {
        vaddr + self.bias
    }
}

/// Both modules in one space.
pub fn pair(lib: &B, prog: &B) -> (Built, Built, Space) {
    let (l, p) = (lib.build(), prog.build());
    let space = Space::default()
        .with(l.space_base, l.image.clone())
        .with(p.space_base, p.image.clone());
    (l, p, space)
}

// ---- Real files.

pub struct Loaded {
    pub segments: [Segment; 3],
    pub dynamic: Vec<u8>,
    pub tls_align: u64,
    pub base: u64,
    pub image: Vec<u8>,
}

fn u16_at(b: &[u8], at: usize) -> u64 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap()) as u64
}
fn u32_at(b: &[u8], at: usize) -> u64 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as u64
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// Loads the three PT_LOAD segments of an ELF file at their own addresses.
pub fn load_elf(file: &[u8]) -> Loaded {
    let phoff = u64_at(file, 32) as usize;
    let phentsize = u16_at(file, 54) as usize;
    let phnum = u16_at(file, 56) as usize;
    let mut loads = vec![];
    let mut dynamic = vec![];
    let mut tls_align = 0;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        let (kind, flags) = (u32_at(file, ph), u32_at(file, ph + 4));
        let (off, vaddr, filesz, memsz, align) = (
            u64_at(file, ph + 8) as usize,
            u64_at(file, ph + 16),
            u64_at(file, ph + 32) as usize,
            u64_at(file, ph + 40),
            u64_at(file, ph + 48),
        );
        match kind {
            1 => loads.push((vaddr, memsz, flags, off, filesz)),
            2 => dynamic = file[off..off + filesz].to_vec(),
            7 => tls_align = align,
            _ => {}
        }
    }
    assert_eq!(loads.len(), 3);
    let base = loads[0].0;
    let end = loads.iter().map(|l| l.0 + l.1).max().unwrap();
    let mut image = vec![0u8; (end - base) as usize];
    let mut segments = vec![];
    for (vaddr, memsz, flags, off, filesz) in &loads {
        let at = (vaddr - base) as usize;
        image[at..at + filesz].copy_from_slice(&file[*off..off + filesz]);
        let access = match (flags & 2 != 0, flags & 1 != 0) {
            (true, _) => Access::ReadWrite,
            (false, true) => Access::ReadExec,
            _ => Access::Read,
        };
        segments.push(Segment {
            vaddr: *vaddr,
            memsz: *memsz,
            access,
        });
    }
    Loaded {
        segments: segments.try_into().unwrap(),
        dynamic,
        tls_align,
        base,
        image,
    }
}
