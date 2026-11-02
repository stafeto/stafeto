// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The real files of `target/libc-so` (`libc.so` and the programs of the probe
//! linked against it by the build of the shared library). The tests skip, with a
//! message, when the directory is absent; `cargo xtask libc-so` fills it.

mod common;
use common::*;
use dynlink::{Access, Module, NAME_MAX, Refusal, Role, lookup, parse, relocate};
use std::path::PathBuf;

const R_JUMP_SLOT_KIND: u32 = 1026;
/// The programs of the probe `cargo xtask libc-so` builds, under
/// target/libc-so.
const HELLO: &str = "probes/so-hello";
const IMAGE: &str = "probes/so-image";

/// What the section headers of a file say it needs: the records of its
/// RELA sections by kind, the places of its RELR sections, and how many
/// records name a symbol. Counted from the file, apart from the code that
/// is tested.
#[derive(Default, Debug)]
struct Expected {
    kinds: std::collections::BTreeMap<u32, u32>,
    relr: u32,
    with_symbol: u32,
}

fn expected(file: &[u8]) -> Expected {
    let u16_at = |at: usize| u16::from_le_bytes(file[at..at + 2].try_into().unwrap()) as usize;
    let u32_at = |at: usize| u32::from_le_bytes(file[at..at + 4].try_into().unwrap());
    let u64_at = |at: usize| u64::from_le_bytes(file[at..at + 8].try_into().unwrap());
    let (shoff, shentsize, shnum) = (u64_at(40) as usize, u16_at(58), u16_at(60));
    let mut out = Expected::default();
    for i in 0..shnum {
        let h = shoff + i * shentsize;
        let (kind, offset, size) = (
            u32_at(h + 4),
            u64_at(h + 24) as usize,
            u64_at(h + 32) as usize,
        );
        match kind {
            4 => {
                // SHT_RELA
                for r in file[offset..offset + size].as_chunks::<24>().0.iter() {
                    let info = u64::from_le_bytes(r[8..16].try_into().unwrap());
                    *out.kinds.entry(info as u32).or_default() += 1;
                    out.with_symbol += u32::from(info >> 32 != 0);
                }
            }
            19 => {
                // SHT_RELR: an even word is a place, an odd one a bitmap.
                for w in file[offset..offset + size].as_chunks::<8>().0.iter() {
                    let w = u64::from_le_bytes(*w);
                    out.relr += if w & 1 == 0 { 1 } else { (w >> 1).count_ones() };
                }
            }
            _ => {}
        }
    }
    out
}

fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(dir().join(name)).unwrap()
}

/// In the build that fills `target/libc-so` the files are required: the
/// variable makes a missing one a failure instead of a skip.
fn required() -> bool {
    std::env::var_os("STAFETO_REQUIRE_LIBC_SO").is_some()
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/libc-so")
}

struct World {
    space: Space,
    library: Module,
    program: Module,
}

fn world(program: &str) -> Option<World> {
    let (lib_file, prog_file) = match (
        std::fs::read(dir().join("libc.so")),
        std::fs::read(dir().join(program)),
    ) {
        (Ok(l), Ok(p)) => (l, p),
        _ => {
            assert!(
                !required(),
                "{} has no libc.so and {program}",
                dir().display()
            );
            eprintln!("skipped: {} has no libc.so and {program}", dir().display());
            return None;
        }
    };
    let (l, p) = (load_elf(&lib_file), load_elf(&prog_file));
    let space = Space::default()
        .with(l.base, l.image.clone())
        .with(p.base, p.image.clone());
    let library = Module {
        segments: l.segments,
        bias: 0,
        tls_align: l.tls_align,
        dynamic: parse(Role::Library, &l.segments, 0, &l.dynamic, &space).unwrap(),
    };
    let program = Module {
        segments: p.segments,
        bias: 0,
        tls_align: p.tls_align,
        dynamic: parse(Role::Program, &p.segments, 0, &p.dynamic, &space).unwrap(),
    };
    Some(World {
        space,
        library,
        program,
    })
}

/// A libc.so from the probe has one undefined name, `main` (a GLOB_DAT of
/// the layer); the library of the build has none. The record is turned
/// into NONE so the rest is relocated the same.
fn without_main(w: &mut World) -> bool {
    let mut found = false;
    let d = w.library.dynamic;
    for i in 0..d.relasz / 24 {
        let at = d.rela + 24 * i;
        let info = w.space.word(at + 8);
        if info as u32 == 1025 {
            let symbol = w.library.symbol(&w.space, (info >> 32) as u32).unwrap();
            let mut name = [0; NAME_MAX];
            let n = w.library.name_of(&w.space, &symbol, &mut name).unwrap();
            if &name[..n] == b"main" {
                w.space.set_u64(at + 8, 0);
                found = true;
            }
        }
    }
    found
}

#[test]
fn libc_so_parses_and_has_what_programs_need() {
    let Some(w) = world(HELLO) else { return };
    let d = w.library.dynamic;
    assert!(d.nsyms > 1_000 && d.nsyms < 10_000, "{}", d.nsyms);
    assert_eq!(
        w.library.segments.map(|s| s.access),
        [Access::Read, Access::ReadExec, Access::ReadWrite]
    );
    assert!(w.library.tls_align.is_power_of_two());
    for (name, kind) in [
        ("printf", 2u8),
        ("malloc", 2),
        ("environ", 1),
        ("stdout", 1),
        ("errno", 6),
    ] {
        let found = lookup(&w.library, &w.space, name.as_bytes()).unwrap();
        if let Some(s) = found {
            assert_eq!(s.kind, kind, "{name}");
            assert!(s.defined());
        } else {
            // errno is a thread-local of the layer and may not be exported.
            assert!(name == "errno", "{name} is not exported");
        }
    }
    let printf = lookup(&w.library, &w.space, b"printf").unwrap().unwrap();
    assert!(
        w.library.segments[1].vaddr <= printf.value
            && printf.value < w.library.segments[1].vaddr + w.library.segments[1].memsz
    );
    for name in ["so_absent_name", "main_not_here", ""] {
        assert_eq!(lookup(&w.library, &w.space, name.as_bytes()).unwrap(), None);
    }
    let arrays = w.library.init_arrays().unwrap();
    for a in arrays {
        assert_eq!(a.size % 8, 0);
    }
}

#[test]
fn libc_so_and_hello_are_relocated() {
    let Some(mut w) = world(HELLO) else { return };
    let had_main = without_main(&mut w);
    let counts = relocate(&w.library, &w.program, &mut w.space).unwrap();
    let (lib_want, prog_want) = (expected(&bytes("libc.so")), expected(&bytes(HELLO)));
    let k = |e: &Expected, kind| e.kinds.get(&kind).copied().unwrap_or(0);
    // Every record and place, less NONE and the GLOB_DAT of `main` that a
    // probe build has and the test turned into NONE.
    let all: u32 = lib_want
        .kinds
        .iter()
        .filter(|(kind, _)| **kind != 0)
        .map(|(_, n)| n)
        .sum();
    assert_eq!(
        counts.library.total(),
        all + lib_want.relr - u32::from(had_main),
        "{:?}",
        counts.library
    );
    assert_eq!(counts.library.relr, lib_want.relr);
    assert_eq!(counts.library.relative, k(&lib_want, 1027));
    assert_eq!(counts.library.tpoff, k(&lib_want, 1030));
    assert_eq!(
        counts.library.glob_dat + counts.library.jump_slot + counts.library.abs64,
        0
    );
    assert_eq!(counts.program.jump_slot, k(&prog_want, 1026));
    assert_eq!(counts.program.glob_dat, k(&prog_want, 1025));
    assert_eq!(
        counts.program.total(),
        k(&prog_want, 1026) + k(&prog_want, 1025)
    );
    assert_eq!(counts.lookups, prog_want.with_symbol);
    check_slots(&w);
}

#[test]
fn a_bigger_program_is_relocated() {
    let Some(mut w) = world(IMAGE) else {
        return;
    };
    without_main(&mut w);
    let counts = relocate(&w.library, &w.program, &mut w.space).unwrap();
    let want = expected(&bytes(IMAGE));
    let k = |kind| want.kinds.get(&kind).copied().unwrap_or(0);
    assert_eq!(counts.program.jump_slot, k(1026));
    assert_eq!(counts.program.glob_dat, k(1025));
    assert_eq!(counts.program.total(), k(1026) + k(1025));
    assert!(k(1026) >= 2, "so-image imports printf and the probe hook");
    check_slots(&w);
}

/// Every JUMP_SLOT and GLOB_DAT of the program holds the address of the
/// library's symbol of that name; every TPREL of the library holds
/// the offset of the formula.
fn check_slots(w: &World) {
    let p = &w.program;
    let d = p.dynamic;
    let mut seen = 0;
    for (table, size) in [(d.rela, d.relasz), (d.jmprel, d.pltrelsz)] {
        for i in 0..size / 24 {
            let at = table + 24 * i;
            let (place, info) = (w.space.word(at), w.space.word(at + 8));
            let (kind, index) = (info as u32, (info >> 32) as u32);
            if kind != R_JUMP_SLOT_KIND && kind != 1025 {
                continue;
            }
            let symbol = p.symbol(&w.space, index).unwrap();
            let mut name = [0; NAME_MAX];
            let n = p.name_of(&w.space, &symbol, &mut name).unwrap();
            let text = String::from_utf8_lossy(&name[..n]).into_owned();
            match lookup(&w.library, &w.space, &name[..n]).unwrap() {
                Some(found) => {
                    assert_eq!(w.space.word(place), found.value, "{text}");
                    assert_ne!(found.value, 0);
                }
                None => {
                    // The weak reference nothing defines (so_absent) is 0.
                    assert_eq!(symbol.bind, 2, "{text} is not weak");
                    assert_eq!(w.space.word(place), 0, "{text}");
                }
            }
            seen += 1;
        }
    }
    assert!(seen >= 4, "{seen}");
    let l = &w.library;
    let base = 16u64.next_multiple_of(l.tls_align);
    let ld = l.dynamic;
    let mut tpoff = 0;
    for i in 0..ld.relasz / 24 {
        let at = ld.rela + 24 * i;
        let (place, info, addend) = (
            w.space.word(at),
            w.space.word(at + 8),
            w.space.word(at + 16),
        );
        if info as u32 == 1030 {
            let index = (info >> 32) as u32;
            let st_value = if index == 0 {
                0
            } else {
                l.symbol(&w.space, index).unwrap().value
            };
            assert_eq!(w.space.word(place), base + st_value + addend);
            tpoff += 1;
        }
    }
    // With RELR packing the TLS records stay in RELA: the 11 of the report.
    assert!(tpoff >= 1);
}

#[test]
fn damage_to_the_real_files_is_refused() {
    let Some(w) = world(HELLO) else { return };
    let l = load_elf(&std::fs::read(dir().join("libc.so")).unwrap());
    let p = load_elf(&std::fs::read(dir().join(HELLO)).unwrap());
    let with_tag = |dynamic: &[u8], tag: i64, value: u64| {
        // Before DT_NULL: the section is the entries up to the first NULL.
        let mut out = vec![];
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
        out.extend_from_slice(dynamic);
        out
    };
    assert_eq!(
        parse(
            Role::Library,
            &l.segments,
            0,
            &with_tag(&l.dynamic, DT_TEXTREL, 0),
            &w.space
        ),
        Err(Refusal::Tag(DT_TEXTREL))
    );
    assert_eq!(
        parse(
            Role::Program,
            &p.segments,
            0,
            &with_tag(&p.dynamic, DT_INIT, 0x1000),
            &w.space
        ),
        Err(Refusal::Tag(DT_INIT))
    );
    // A program parsed as a library, a library as a program.
    assert_eq!(
        parse(Role::Library, &p.segments, 0, &p.dynamic, &w.space),
        Err(Refusal::Needed)
    );
    assert_eq!(
        parse(Role::Program, &l.segments, 0, &l.dynamic, &w.space),
        Err(Refusal::Needed)
    );
}

#[test]
fn a_module_from_its_program_headers_is_the_one_parse_builds() {
    let Some(w) = world(HELLO) else { return };
    for (name, role, parsed) in [
        ("libc.so", Role::Library, &w.library),
        (HELLO, Role::Program, &w.program),
    ] {
        let file = bytes(name);
        let phoff = u64::from_le_bytes(file[32..40].try_into().unwrap()) as usize;
        let phnum = u16::from_le_bytes(file[56..58].try_into().unwrap()) as usize;
        let headers = &file[phoff..phoff + phnum * dynlink::PHDR_SIZE];
        let found = dynlink::module(role, headers, 0, &w.space).unwrap();
        assert_eq!(&found, parsed, "{name}");
        // Headers cut in the middle of a record, or without a segment.
        assert_eq!(
            dynlink::module(role, &headers[..headers.len() - 1], 0, &w.space),
            Err(Refusal::Section)
        );
        assert_eq!(
            dynlink::module(role, &headers[..dynlink::PHDR_SIZE], 0, &w.space),
            Err(Refusal::Section)
        );
    }
}
