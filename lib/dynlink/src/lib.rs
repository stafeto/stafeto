// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Dynamic linking of the shared C library (spec 2, 3.12.4). A module is
//! one ELF object in memory: the program (`ET_EXEC`) or libc.so, three
//! segments, a bias and the parsed `PT_DYNAMIC`. The loader of the process
//! service relocates libc.so and then the program before the jump
//! (`relocate`); the layer's `dlsym` looks a name up (`lookup`).
//!
//! The program is untrusted (any user can build one, and the loader belongs
//! to the trusted base of set-ID), so nothing here trusts a table: every
//! read goes through `Memory` after a check that it lies in a segment of the
//! module, every write lies in a read-write segment, every sum of addresses
//! is checked, and every loop has a limit. Everything unusual is a
//! `Refusal`, which the loader turns into NOT_EXEC.
//!
//! No `alloc`, no globals: the memory is a trait (the process's own space in
//! the loader, an array of bytes in the tests).

#![cfg_attr(not(test), no_std)]

mod parse;
mod relocate;
mod symbol;

pub use parse::{DYNAMIC_MAX, PHDR_SIZE, module, parse};
pub use relocate::{Counts, Kinds, relocate};
pub use symbol::{Symbol, gnu_hash, lookup};

/// Records of `DT_RELA` and `DT_JMPREL` together with the places a `DT_RELR`
/// table applies, at most, in one module.
pub const RELOCS_MAX: u32 = 65_536;
/// Searches of a name in the library for one load.
pub const LOOKUPS_MAX: u32 = 8_192;
/// Steps of a hash chain.
pub const CHAIN_MAX: u32 = 64;
/// The bytes of a symbol name, without its NUL.
pub const NAME_MAX: usize = 255;
/// Symbols of a module.
pub const SYMBOLS_MAX: u32 = 65_536;
/// The bytes of a symbol record.
pub const SYM_SIZE: u64 = 24;
/// The bytes of a `DT_RELA` record.
pub const RELA_SIZE: u64 = 24;

/// The name the only `DT_NEEDED` of a program carries.
pub const NEEDED: &[u8] = b"libc.so";

/// What a segment allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    ReadExec,
    ReadWrite,
}

/// A loaded segment of a module: where it starts in the module's own
/// addresses (before the bias), how far its memory reaches, what it allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u64,
    pub memsz: u64,
    pub access: Access,
}

/// Which of the two roles a module has; the role decides what its
/// `PT_DYNAMIC` may hold and how its symbols resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// libc.so: no `DT_NEEDED`, every symbol it uses is its own.
    Library,
    /// The program: one `DT_NEEDED`, `libc.so`; symbols resolve in the
    /// program, then in the library.
    Program,
}

/// A table of constructors or destructors: `size` bytes at `vaddr`, or 0
/// of both for none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Array {
    pub vaddr: u64,
    pub size: u64,
}

/// The parsed `PT_DYNAMIC` (3.12.4): the tags the loader accepts, with the
/// addresses as the file gives them (before the bias); 0 for a tag that is
/// absent. Built by `parse`, which checks every table against the segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dynamic {
    pub strtab: u64,
    pub strsz: u64,
    pub symtab: u64,
    pub rela: u64,
    pub relasz: u64,
    pub jmprel: u64,
    pub pltrelsz: u64,
    pub relr: u64,
    pub relrsz: u64,
    pub preinit: Array,
    pub init: Array,
    pub fini: Array,
    /// The `DT_FLAGS` word (0 for none).
    pub flags: u64,
    /// The `DT_GNU_HASH` table and what its header says.
    pub gnu_hash: u64,
    pub nbuckets: u32,
    pub symoffset: u32,
    pub bloom_size: u32,
    pub bloom_shift: u32,
    /// The symbols the table counts: the chains end after the last one.
    pub nsyms: u32,
    pub role: Role,
}

/// One module in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module {
    /// The read-only, executable and writable segments, one each.
    pub segments: [Segment; 3],
    /// Added to every address of the file (0 for both modules of part 3).
    pub bias: u64,
    /// The `p_align` of the `PT_TLS` header of the module, 0 for none.
    pub tls_align: u64,
    pub dynamic: Dynamic,
}

/// A read or write the memory could not do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault;

/// The memory of the process the module lives in, read and written by
/// absolute address. The checks of the segments are made before, here;
/// an implementation checks that the page is mapped.
pub trait Memory {
    fn read(&self, address: u64, out: &mut [u8]) -> Result<(), Fault>;
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Fault>;
}

/// Which limit a refusal hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    Relocs,
    Lookups,
    Chain,
    Symbols,
}

/// Why the module cannot be linked. The loader answers NOT_EXEC to every
/// one of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A tag the loader does not accept (`DT_TEXTREL`, `DT_INIT`, ...), or
    /// one with a value outside what is accepted (`DT_SYMENT` not 24, an
    /// unknown flag bit, `DT_PLTREL` other than `DT_RELA`).
    Tag(i64),
    /// A tag twice.
    Duplicate(i64),
    /// A tag the module needs and lacks (or half of a pair: table and size).
    Missing(i64),
    /// `DT_NEEDED` is not what the role allows.
    Needed,
    /// The dynamic section has no `DT_NULL` or its size is not whole entries.
    Section,
    /// A table outside the segments of the module, a size that is not whole
    /// records, a misaligned address.
    Table(i64),
    /// The geometry of `DT_GNU_HASH` makes no sense.
    Hash,
    /// A relocation kind not accepted.
    Kind(u32),
    /// The place of a relocation is not a whole aligned word of the
    /// read-write segment.
    Place(u64),
    /// A symbol index beyond the table, or a symbol on a kind that has none.
    Symbol(u32),
    /// The name of a symbol is outside the string table, not ended, or
    /// longer than NAME_MAX.
    Name,
    /// A symbol whose type does not fit the relocation: an address needs an
    /// object, a function or an untyped symbol, `TLS_TPREL64` needs a TLS
    /// symbol, and section symbols and `SHN_COMMON` fit none.
    SymbolType(u32),
    /// A strong reference nothing defines, or a library reference to a name
    /// it does not define.
    Unresolved(u32),
    /// TLS relocation without a `PT_TLS` of the library, or a bad alignment.
    NoTls,
    Limit(Limit),
    /// A sum of addresses wrapped.
    Overflow,
    /// The memory refused a read or a write.
    Memory,
    /// Modules given in the wrong roles.
    Role,
}

impl From<Fault> for Refusal {
    fn from(_: Fault) -> Refusal {
        Refusal::Memory
    }
}

/// The segments of a module with its bias: the one place where an address
/// of a table is checked before the memory sees it.
#[derive(Clone, Copy)]
pub(crate) struct Map<'a> {
    pub segments: &'a [Segment; 3],
    pub bias: u64,
}

impl Map<'_> {
    /// The segment that holds all of `len` bytes from `vaddr`.
    pub fn find(&self, vaddr: u64, len: u64) -> Option<&Segment> {
        let end = vaddr.checked_add(len)?;
        self.segments.iter().find(|s| {
            s.vaddr
                .checked_add(s.memsz)
                .is_some_and(|top| s.vaddr <= vaddr && end <= top)
        })
    }

    pub fn contains(&self, vaddr: u64, len: u64) -> bool {
        self.find(vaddr, len).is_some()
    }

    pub fn writable(&self, vaddr: u64, len: u64) -> bool {
        self.find(vaddr, len)
            .is_some_and(|s| s.access == Access::ReadWrite)
    }

    pub fn absolute(&self, vaddr: u64) -> Result<u64, Refusal> {
        self.bias.checked_add(vaddr).ok_or(Refusal::Overflow)
    }

    pub fn read<M: Memory + ?Sized>(
        &self,
        mem: &M,
        vaddr: u64,
        out: &mut [u8],
        tag: i64,
    ) -> Result<(), Refusal> {
        if !self.contains(vaddr, out.len() as u64) {
            return Err(Refusal::Table(tag));
        }
        mem.read(self.absolute(vaddr)?, out)?;
        Ok(())
    }

    pub fn u32<M: Memory + ?Sized>(&self, mem: &M, vaddr: u64, tag: i64) -> Result<u32, Refusal> {
        let mut bytes = [0; 4];
        self.read(mem, vaddr, &mut bytes, tag)?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn u64<M: Memory + ?Sized>(&self, mem: &M, vaddr: u64, tag: i64) -> Result<u64, Refusal> {
        let mut bytes = [0; 8];
        self.read(mem, vaddr, &mut bytes, tag)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

impl Module {
    pub(crate) fn map(&self) -> Map<'_> {
        Map {
            segments: &self.segments,
            bias: self.bias,
        }
    }

    /// The tables of constructors and destructors with their absolute
    /// addresses: preinit, init, fini. The loader does not run them (the
    /// C library's start does, in the order of the gABI); this is what a
    /// check of their bounds sees.
    pub fn init_arrays(&self) -> Result<[Array; 3], Refusal> {
        let d = &self.dynamic;
        let mut out = [Array::default(); 3];
        for (slot, array) in out.iter_mut().zip([d.preinit, d.init, d.fini]) {
            if array.size != 0 {
                *slot = Array {
                    vaddr: self.map().absolute(array.vaddr)?,
                    size: array.size,
                };
            }
        }
        Ok(out)
    }
}
