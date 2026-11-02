// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The real files of `target/libc-so` (`libc.so` and the programs linked
//! against it by the build of the shared library). The tests skip, with a
//! message, when the directory is absent; `cargo xtask libc-so` fills it.

mod common;
use common::*;
use dynlink::{Access, Module, NAME_MAX, Refusal, Role, lookup, parse, relocate};
use std::path::PathBuf;

const R_JUMP_SLOT_KIND: u32 = 1026;
/// What the build of libc.so has to give (spec 2, 3.12.4): the relocations
/// of libc.so (the places of RELATIVE and TLS_TPREL64) and of `hello`.
const LIBC_RELOCATIONS: u32 = 1_983;
const HELLO_RELOCATIONS: u32 = 8;
const HELLO_BIG_RELOCATIONS: u32 = 89;

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
fn without_main(w: &mut World) {
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
            }
        }
    }
}

#[test]
fn libc_so_parses_and_has_what_programs_need() {
    let Some(w) = world("hello") else { return };
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
    let Some(mut w) = world("hello") else { return };
    without_main(&mut w);
    let counts = relocate(&w.library, &w.program, &mut w.space).unwrap();
    assert_eq!(
        counts.library.total(),
        LIBC_RELOCATIONS,
        "{:?}",
        counts.library
    );
    assert_eq!(
        counts.library.glob_dat + counts.library.jump_slot + counts.library.abs64,
        0
    );
    assert!(counts.library.none <= 1, "at most the patched main");
    assert_eq!(
        counts.program.total(),
        HELLO_RELOCATIONS,
        "{:?}",
        counts.program
    );
    assert_eq!(counts.program.jump_slot, 6);
    assert_eq!(counts.program.glob_dat, 2);
    assert_eq!(counts.lookups, 8);
    check_slots(&w);
}

#[test]
fn a_bigger_program_is_relocated() {
    let Some(mut w) = world("hello-big") else {
        return;
    };
    without_main(&mut w);
    let counts = relocate(&w.library, &w.program, &mut w.space).unwrap();
    assert_eq!(
        counts.program.total(),
        HELLO_BIG_RELOCATIONS,
        "{:?}",
        counts.program
    );
    assert_eq!(counts.program.jump_slot, 88);
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
            let found = lookup(&w.library, &w.space, &name[..n]).unwrap().unwrap();
            assert_eq!(
                w.space.word(place),
                found.value,
                "{}",
                String::from_utf8_lossy(&name[..n])
            );
            assert_ne!(found.value, 0);
            seen += 1;
        }
    }
    assert!(seen >= 8, "{seen}");
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
    let Some(w) = world("hello") else { return };
    let l = load_elf(&std::fs::read(dir().join("libc.so")).unwrap());
    let p = load_elf(&std::fs::read(dir().join("hello")).unwrap());
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
