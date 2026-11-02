// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `PT_DYNAMIC`: the tags that pass, the tags and values that are refused,
//! the tables outside the segments.

mod common;
use common::*;
use dynlink::{Limit, Refusal, Role};

fn lib() -> B {
    B::library().func("f", 0x400_0100).func("g", 0x400_0200)
}

fn prog() -> B {
    B::program().undef("f", GLOBAL)
}

/// The built module with one more tag in its dynamic section.
fn with(b: &B, tag: i64, value: u64) -> (Built, Space) {
    let mut built = b.build();
    built.tags.push((tag, value));
    let space = built.space();
    (built, space)
}

fn refused(b: &B, tag: i64, value: u64) -> Refusal {
    let (built, space) = with(b, tag, value);
    built.parse(&space).unwrap_err()
}

#[test]
fn a_library_and_a_program_parse() {
    let l = lib().rel(lib().rw(), R_RELATIVE, None, 8).build();
    let space = l.space();
    let d = l.parse(&space).unwrap();
    assert_eq!(
        (d.nsyms, d.symoffset, d.nbuckets, d.bloom_size),
        (3, 1, 3, 2)
    );
    assert_eq!((d.relasz, d.jmprel, d.relrsz), (24, 0, 0));
    assert_eq!(d.role, Role::Library);
    let p = prog().slot(prog().rw(), R_JUMP_SLOT, Some("f"), 0).build();
    let d = p.parse(&p.space()).unwrap();
    assert_eq!((d.nsyms, d.symoffset, d.pltrelsz), (2, 2, 24));
    assert_eq!(d.role, Role::Program);
}

#[test]
fn a_module_without_symbols_has_the_count_of_its_offset() {
    let l = B::library().build();
    let d = l.parse(&l.space()).unwrap();
    assert_eq!((d.nsyms, d.symoffset), (1, 1));
}

#[test]
fn the_tags_that_are_skipped_pass() {
    for (tag, value) in [
        (DT_DEBUG, 0),
        (DT_SONAME, 1),
        (DT_RUNPATH, 1),
        (DT_BIND_NOW, 0),
        (4, 0x1234),      // DT_HASH
        (3, 0),           // DT_PLTGOT
        (0x6fff_fff9, 5), // DT_RELACOUNT
        (DT_AARCH64_BTI_PLT, 1),
        (0x7000_0005, 1), // DT_AARCH64_VARIANT_PCS
        (DT_FLAGS_1, 1),
    ] {
        let (b, s) = with(&lib(), tag, value);
        // The duplicate of DT_FLAGS_1 is not in the standard set, so none.
        assert!(b.parse(&s).is_ok(), "tag {tag}");
        let (b, s) = with(&prog(), tag, value);
        assert!(b.parse(&s).is_ok(), "tag {tag}");
    }
}

#[test]
fn the_version_tags_pass_in_the_library_alone() {
    for tag in [DT_VERSYM, DT_VERDEF, 0x6fff_fffd] {
        let (b, s) = with(&lib(), tag, 0x1000);
        assert!(b.parse(&s).is_ok(), "{tag:#x}");
        assert_eq!(refused(&prog(), tag, 0x1000), Refusal::Tag(tag));
    }
}

#[test]
fn the_flags_of_the_text_and_the_pie_are_refused() {
    for tag in [
        DT_TEXTREL,
        DT_INIT,
        DT_FINI,
        DT_REL,
        DT_VERNEED,
        0x6fff_ffff,
        18,
        19,
        0x1234,
        -5,
    ] {
        assert_eq!(refused(&lib(), tag, 0), Refusal::Tag(tag), "{tag}");
        assert_eq!(refused(&prog(), tag, 0), Refusal::Tag(tag), "{tag}");
    }
    for bit in [0x1u64, 0x4, 0x20, 0x100] {
        let mut b = lib();
        b.flags = Some(0x8 | bit);
        let built = b.build();
        assert_eq!(
            built.parse(&built.space()),
            Err(Refusal::Tag(DT_FLAGS)),
            "{bit:#x}"
        );
    }
    for bit in [0x2u64, 0x0800_0000, 0x4, 0x8000_0000] {
        assert_eq!(
            refused(&lib(), DT_FLAGS_1, 1 | bit),
            Refusal::Tag(DT_FLAGS_1),
            "{bit:#x}"
        );
    }
    // The three flags the toolchain sets pass.
    let mut b = lib();
    b.flags = Some(0x2 | 0x8 | 0x10);
    let built = b.build();
    assert!(built.parse(&built.space()).is_ok());
}

#[test]
fn entry_sizes_other_than_the_record_are_refused() {
    assert_eq!(
        refused(&lib(), DT_SYMENT, 32),
        Refusal::Duplicate(DT_SYMENT)
    );
    let mut b = lib().build();
    b.set_tag(DT_SYMENT, 32);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Tag(DT_SYMENT)));
    let l = lib().rel(lib().rw(), R_RELATIVE, None, 0).build();
    let mut b = l.clone();
    b.set_tag(DT_RELAENT, 16);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Tag(DT_RELAENT)));
    let mut l = lib();
    l.relr = vec![l.rw()];
    let mut b = l.build();
    b.set_tag(DT_RELRENT, 4);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Tag(DT_RELRENT)));
    // DT_PLTREL must say RELA.
    let p = prog().slot(prog().rw(), R_JUMP_SLOT, Some("f"), 0);
    let mut b = p.build();
    b.set_tag(DT_PLTREL, 17);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Tag(DT_PLTREL)));
    b.remove_tag(DT_PLTREL);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Missing(DT_PLTREL)));
}

#[test]
fn a_tag_twice_or_a_tag_missing_is_refused() {
    for tag in [DT_STRTAB, DT_STRSZ, DT_SYMTAB, DT_GNU_HASH, DT_FLAGS] {
        let l = lib().build();
        let v = l.tag(tag);
        assert_eq!(refused(&lib(), tag, v), Refusal::Duplicate(tag));
    }
    for tag in [DT_STRTAB, DT_STRSZ, DT_SYMTAB, DT_GNU_HASH] {
        let mut b = lib().build();
        b.remove_tag(tag);
        assert_eq!(b.parse(&b.space()), Err(Refusal::Missing(tag)), "{tag}");
    }
    // A table without its size, a size without its table.
    let l = lib().rel(lib().rw(), R_RELATIVE, None, 0);
    for (tag, other) in [(DT_RELASZ, DT_RELA), (DT_RELA, DT_RELASZ)] {
        let mut b = l.build();
        b.remove_tag(tag);
        assert_eq!(b.parse(&b.space()), Err(Refusal::Missing(tag)), "{other}");
    }
    let mut b = lib();
    b.relr = vec![b.rw()];
    for tag in [DT_RELR, DT_RELRSZ] {
        let mut x = b.build();
        x.remove_tag(tag);
        assert_eq!(x.parse(&x.space()), Err(Refusal::Missing(tag)));
    }
    let p = prog().slot(prog().rw(), R_JUMP_SLOT, Some("f"), 0);
    for tag in [DT_JMPREL, DT_PLTRELSZ] {
        let mut x = p.build();
        x.remove_tag(tag);
        assert_eq!(x.parse(&x.space()), Err(Refusal::Missing(tag)));
    }
}

#[test]
fn the_section_must_end_and_hold_whole_entries() {
    let l = lib().build();
    let mut bytes = l.dynamic_bytes();
    let space = l.space();
    let parse = |b: &[u8]| dynlink::parse(Role::Library, &l.segments, 0, b, &space);
    assert!(parse(&bytes).is_ok());
    // Without DT_NULL.
    bytes.truncate(bytes.len() - 16);
    assert_eq!(parse(&bytes), Err(Refusal::Section));
    // A tail of 8 bytes.
    let mut odd = l.dynamic_bytes();
    odd.truncate(odd.len() - 8);
    assert_eq!(parse(&odd), Err(Refusal::Section));
    // Entries after DT_NULL are not read.
    let mut more = l.dynamic_bytes();
    more.extend_from_slice(&DT_TEXTREL.to_le_bytes());
    more.extend_from_slice(&[0; 8]);
    assert!(parse(&more).is_ok());
    assert_eq!(parse(&[]), Err(Refusal::Section));
}

#[test]
fn needed_is_libc_so_in_a_program_and_nothing_in_the_library() {
    // A library with a DT_NEEDED.
    let mut l = lib();
    l.needed = vec!["libc.so".into()];
    let b = l.build();
    assert_eq!(b.parse(&b.space()), Err(Refusal::Needed));
    // A program without, with two, with another name.
    for names in [
        vec![],
        vec!["libc.so", "libc.so"],
        vec!["libx.so"],
        vec!["libc.so.6"],
        vec!["libc.s"],
        vec!["libc.soo"],
        vec!["libc"],
        vec!["LIBC.SO"],
    ] {
        let mut p = prog();
        p.needed = names.iter().map(|s| s.to_string()).collect();
        let b = p.build();
        assert_eq!(b.parse(&b.space()), Err(Refusal::Needed), "{names:?}");
    }
    // The name is past the string table, or its NUL is.
    let mut b = prog().build();
    b.set_tag(DT_NEEDED, 1000);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Needed));
    let mut b = prog().build();
    let strsz = b.tag(DT_STRSZ);
    b.set_tag(DT_NEEDED, strsz - 7); // "libc.so" without its NUL in the table
    assert_eq!(b.parse(&b.space()), Err(Refusal::Needed));
    b.set_tag(DT_NEEDED, u64::MAX - 3);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Needed));
}

#[test]
fn tables_outside_the_segments_are_refused() {
    let l = lib()
        .rel(lib().rw(), R_RELATIVE, None, 0)
        .rel(lib().rw() + 8, R_RELATIVE, None, 0);
    let read_end = l.base + l.r_size;
    let cases: [(i64, u64, i64); 5] = [
        (DT_RELA, read_end - 24, DT_RELA), // runs past the segment
        (DT_RELA, read_end + 8, DT_RELA),  // in the code segment
        (DT_RELA, 0x10, DT_RELA),          // nowhere
        (DT_STRTAB, read_end - 4, DT_STRTAB),
        (DT_STRTAB, u64::MAX - 2, DT_STRTAB),
    ];
    for (tag, value, expected) in cases {
        let mut b = l.build();
        b.set_tag(tag, value);
        let r = b.parse(&b.space());
        if value == read_end + 8 {
            // Inside the executable segment: a segment, so it passes; the
            // table is read where it is.
            assert!(r.is_ok());
        } else {
            assert_eq!(r, Err(Refusal::Table(expected)), "{tag} {value:#x}");
        }
    }
    // A table that straddles two segments.
    let mut b = l.build();
    b.set_tag(DT_RELA, read_end - 24);
    b.set_tag(DT_RELASZ, 48);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Table(DT_RELA)));
    // Sizes that are not whole records or whose end wraps.
    for size in [23u64, 25, 47, u64::MAX - 7, u64::MAX / 24 * 24] {
        let mut b = l.build();
        b.set_tag(DT_RELASZ, size);
        assert_eq!(b.parse(&b.space()), Err(Refusal::Table(DT_RELA)), "{size}");
    }
    // A misaligned table.
    let mut b = l.build();
    b.set_tag(DT_RELA, b.tag(DT_RELA) + 4);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Table(DT_RELA)));
    // A string table of no bytes.
    let mut b = l.build();
    b.set_tag(DT_STRSZ, 0);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Table(DT_STRTAB)));
    // The symbol table runs out of its segment (more symbols than room).
    let mut b = l.build();
    b.set_tag(DT_SYMTAB, read_end - 24);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Table(DT_SYMTAB)));
}

#[test]
fn the_jmprel_and_relr_tables_are_checked_too() {
    let p = prog().slot(prog().rw(), R_JUMP_SLOT, Some("f"), 0);
    let mut b = p.build();
    b.set_tag(DT_PLTRELSZ, 25);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Table(DT_JMPREL)));
    let mut b = p.build();
    b.set_tag(DT_JMPREL, 0x1000);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Table(DT_JMPREL)));
    let mut l = lib();
    l.relr = vec![l.rw(), 0b1011];
    let mut b = l.build();
    b.set_tag(DT_RELRSZ, 12);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Table(DT_RELR)));
    let mut b = l.build();
    b.set_tag(DT_RELR, b.tag(DT_RELR) + 1);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Table(DT_RELR)));
    let mut b = l.build();
    b.set_tag(DT_RELR, l.base + l.r_size - 8);
    assert_eq!(b.parse(&b.space()), Err(Refusal::Table(DT_RELR)));
}

#[test]
fn the_arrays_of_constructors_stay_in_the_segments_and_whole() {
    let rw = lib().rw();
    let tags = |kind: i64| match kind {
        0 => (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ),
        1 => (DT_INIT_ARRAY, DT_INIT_ARRAYSZ),
        _ => (DT_FINI_ARRAY, DT_FINI_ARRAYSZ),
    };
    for kind in 0..3 {
        let (a, s) = tags(kind);
        let mut b = lib().build();
        b.tags.push((a, rw));
        b.tags.push((s, 16));
        let space = b.space();
        let m = b.module(&space).unwrap();
        let arrays = m.init_arrays().unwrap();
        assert_eq!(arrays[kind as usize].vaddr, rw);
        assert_eq!(arrays[kind as usize].size, 16);
        for (other, array) in arrays.iter().enumerate() {
            if other != kind as usize {
                assert_eq!(array.size, 0);
            }
        }
        for (addr, size) in [
            (rw + 4, 16),          // misaligned
            (rw, 12),              // not whole words
            (rw, 0x2000),          // past the segment
            (rw + 0x1000 - 8, 16), // across its end
            (0x10, 8),             // nowhere
            (u64::MAX - 7, 8),     // wraps
        ] {
            let mut b = lib().build();
            b.tags.push((a, addr));
            b.tags.push((s, size));
            assert_eq!(
                b.parse(&b.space()),
                Err(Refusal::Table(a)),
                "{addr:#x} {size}"
            );
        }
        let mut b = lib().build();
        b.tags.push((a, rw));
        assert_eq!(b.parse(&b.space()), Err(Refusal::Missing(s)));
        let mut b = lib().build();
        b.tags.push((s, 8));
        assert_eq!(b.parse(&b.space()), Err(Refusal::Missing(a)));
    }
}

#[test]
fn init_arrays_come_with_the_bias() {
    let mut l = lib();
    l.bias = 0x1_0000;
    let mut b = l.build();
    let rw = l.rw();
    b.tags.push((DT_INIT_ARRAY, rw));
    b.tags.push((DT_INIT_ARRAYSZ, 8));
    let space = b.space();
    let m = b.module(&space).unwrap();
    assert_eq!(m.init_arrays().unwrap()[1].vaddr, rw + 0x1_0000);
}

#[test]
fn the_hash_table_must_make_sense() {
    let l = lib();
    let patch = |offset: u64, value: u32| {
        let b = l.build();
        let mut space = b.space();
        space.set_u32(b.hash + offset, value);
        b.parse(&space)
    };
    assert_eq!(patch(0, 0), Err(Refusal::Hash), "no buckets");
    assert_eq!(patch(4, 0), Err(Refusal::Hash), "symoffset 0");
    assert_eq!(patch(8, 0), Err(Refusal::Hash), "no bloom words");
    assert_eq!(
        patch(8, 3),
        Err(Refusal::Hash),
        "bloom size not a power of two"
    );
    assert_eq!(patch(0, 1 << 20), Err(Refusal::Limit(Limit::Symbols)));
    assert_eq!(patch(8, 1 << 20), Err(Refusal::Limit(Limit::Symbols)));
    assert_eq!(patch(4, 1 << 20), Err(Refusal::Limit(Limit::Symbols)));
    // The geometry runs out of the segment.
    assert_eq!(patch(0, 5000), Err(Refusal::Table(DT_GNU_HASH)));
    // A bucket that names a symbol below the offset.
    let b = l.build();
    let mut space = b.space();
    let buckets = b.hash + 16 + 8 * 2;
    for i in 0..3 {
        if space.word(buckets + 4 * i) & 0xffff_ffff != 0 {
            space.set_u32(buckets + 4 * i, 0);
        }
    }
    space.set_u32(buckets, 1);
    // symoffset is 1, so bucket 1 is the first hashed symbol: valid; with
    // symoffset 2 it would be below the offset.
    space.set_u32(b.hash + 4, 2);
    assert_eq!(b.parse(&space), Err(Refusal::Hash));
}

#[test]
fn a_chain_that_never_ends_is_refused() {
    let b = lib().build();
    let mut space = b.space();
    let chains = b.hash + 16 + 8 * 2 + 4 * 3;
    for i in 0..2 {
        let at = chains + 4 * i;
        let v = u32::from_le_bytes(space.bytes(at, 4).try_into().unwrap());
        space.set_u32(at, v & !1);
    }
    // The walk runs through the segment and out of it.
    let e = b.parse(&space).unwrap_err();
    assert!(
        matches!(e, Refusal::Table(_) | Refusal::Limit(Limit::Symbols)),
        "{e:?}"
    );
}

#[test]
fn a_count_beyond_the_symbols_the_segment_holds_is_refused() {
    // Many symbols whose table does not fit the read-only segment.
    let mut l = B::library();
    l.r_size = 0x4000;
    for i in 0..300 {
        l = l.func(&format!("s{i}"), 0x400_0000 + i);
    }
    let mut b = l.build();
    b.segments[0].memsz = 0x1000;
    assert!(b.parse(&b.space()).is_err());
}
