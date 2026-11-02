// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The relocations: each kind of the table of spec 2, 3.12.4, each refusal,
//! the limits, the order of the modules.

mod common;
use common::*;
use dynlink::{Access, Counts, Kinds, LOOKUPS_MAX, Limit, RELOCS_MAX, Refusal, Role, relocate};

fn lib() -> B {
    B::library()
        .func("f", 0x400_0100)
        .func("g", 0x400_0200)
        .sym("obj", GLOBAL, OBJECT, 1, 0x400_2000)
        .sym("weakf", WEAK, FUNC, 1, 0x400_0300)
}

fn prog() -> B {
    B::program()
}

/// Both modules relocated in one space.
fn run(l: &B, p: &B) -> (Result<Counts, Refusal>, Space, Built, Built) {
    let (lb, pb, mut space) = pair(l, p);
    let (lm, pm) = (lb.module(&space), pb.module(&space));
    let result = match (lm, pm) {
        (Ok(lm), Ok(pm)) => relocate(&lm, &pm, &mut space),
        (Err(e), _) | (_, Err(e)) => Err(e),
    };
    (result, space, lb, pb)
}

fn word(space: &Space, address: u64) -> u64 {
    space.word(address)
}

#[test]
fn each_kind_writes_what_the_table_says() {
    let l = lib();
    let rw = l.rw();
    let l = l
        .rel(rw, R_ABS64, Some("f"), 0x10)
        .rel(rw + 8, R_GLOB_DAT, Some("obj"), 0)
        .rel(rw + 16, R_RELATIVE, None, 0x400_0040)
        .rel(rw + 24, R_NONE, None, 77)
        .slot(rw + 32, R_JUMP_SLOT, Some("g"), 0)
        .slot(rw + 40, R_JUMP_SLOT, Some("weakf"), 4);
    let lb = l.build();
    let mut space = lb.space();
    space.set_u64(rw + 24, 0xdead);
    let lm = lb.module(&space).unwrap();
    let pb = prog().build();
    let pm = pb.module(&pb.space()).unwrap();
    let mut both = space.clone().with(pb.space_base, pb.image.clone());
    let counts = relocate(&lm, &pm, &mut both).unwrap();
    assert_eq!(word(&both, rw), 0x400_0110, "ABS64 is S + A");
    assert_eq!(word(&both, rw + 8), 0x400_2000, "GLOB_DAT is S");
    assert_eq!(
        word(&both, rw + 16),
        0x400_0040,
        "RELATIVE is B + A, B is 0"
    );
    assert_eq!(word(&both, rw + 24), 0xdead, "NONE writes nothing");
    assert_eq!(word(&both, rw + 32), 0x400_0200, "JUMP_SLOT is S");
    assert_eq!(
        word(&both, rw + 40),
        0x400_0304,
        "a weak definition counts, S + A"
    );
    assert_eq!(
        counts.library,
        Kinds {
            none: 1,
            abs64: 1,
            glob_dat: 1,
            jump_slot: 2,
            relative: 1,
            relr: 0,
            tpoff: 0
        }
    );
    assert_eq!(counts.library.total(), 5);
    assert_eq!(counts.program, Kinds::default());
    assert_eq!(
        counts.lookups, 0,
        "a library finds its own symbols without a search"
    );
}

#[test]
fn a_program_takes_its_symbols_from_itself_then_from_the_library() {
    let p = prog()
        .func("mine", 0x20_1000)
        .func("f", 0x20_2000)
        .undef("g", GLOBAL)
        .undef("obj", GLOBAL);
    let rw = p.rw();
    let p = p
        .rel(rw, R_GLOB_DAT, Some("mine"), 0)
        .rel(rw + 8, R_GLOB_DAT, Some("f"), 0) // the program defines f too
        .rel(rw + 16, R_ABS64, Some("obj"), 0x20)
        .slot(rw + 24, R_JUMP_SLOT, Some("g"), 0)
        .slot(rw + 32, R_JUMP_SLOT, Some("g"), 0);
    let (result, space, _, _) = run(&lib(), &p);
    let counts = result.unwrap();
    assert_eq!(word(&space, rw), 0x20_1000);
    assert_eq!(
        word(&space, rw + 8),
        0x20_2000,
        "the program's definition wins"
    );
    assert_eq!(word(&space, rw + 16), 0x400_2020);
    assert_eq!(word(&space, rw + 24), 0x400_0200);
    assert_eq!(word(&space, rw + 32), 0x400_0200);
    assert_eq!(
        counts.lookups, 3,
        "obj and g twice; the program's own are not searched"
    );
    assert_eq!(
        counts.program,
        Kinds {
            abs64: 1,
            glob_dat: 2,
            jump_slot: 2,
            ..Kinds::default()
        }
    );
}

#[test]
fn a_weak_undefined_symbol_is_zero() {
    let p = prog().undef("so_absent", WEAK).undef("g", WEAK);
    let rw = p.rw();
    let p = p
        .rel(rw, R_GLOB_DAT, Some("so_absent"), 0)
        .rel(rw + 8, R_ABS64, Some("so_absent"), 12)
        .slot(rw + 16, R_JUMP_SLOT, Some("so_absent"), 0)
        .rel(rw + 24, R_GLOB_DAT, Some("g"), 0);
    let (result, space, _, _) = run(&lib(), &p);
    result.unwrap();
    assert_eq!(word(&space, rw), 0, "NULL for the program");
    assert_eq!(word(&space, rw + 8), 12, "plus the addend");
    assert_eq!(word(&space, rw + 16), 0);
    assert_eq!(
        word(&space, rw + 24),
        0x400_0200,
        "a weak reference to a name the library has"
    );
}

#[test]
fn a_strong_undefined_symbol_is_refused() {
    let p = prog().undef("so_missing", GLOBAL);
    let rw = p.rw();
    let idx = 1;
    for tables in [0, 1] {
        let q = if tables == 0 {
            p.clone().rel(rw, R_GLOB_DAT, Some("so_missing"), 0)
        } else {
            p.clone().slot(rw, R_JUMP_SLOT, Some("so_missing"), 0)
        };
        let (result, ..) = run(&lib(), &q);
        assert_eq!(result, Err(Refusal::Unresolved(idx)));
    }
    // A local binding that nothing defines.
    let q = prog().sym("loc", LOCAL, NOTYPE, 0, 0);
    let q = q.clone().rel(q.rw(), R_GLOB_DAT, Some("loc"), 0);
    assert!(matches!(run(&lib(), &q).0, Err(Refusal::Unresolved(_))));
}

#[test]
fn what_the_library_does_not_export_does_not_satisfy_a_reference() {
    let mut hidden = lib()
        .sym("loc", LOCAL, FUNC, 1, 0x400_0400)
        .sym("sec", GLOBAL, SECTION, 1, 0x400_0400)
        .sym("file", GLOBAL, FILE, 1, 0)
        .sym("ifunc", GLOBAL, IFUNC, 1, 0x400_0500)
        .sym("common", GLOBAL, OBJECT, SHN_COMMON, 8);
    hidden = hidden.undef("und", GLOBAL);
    hidden.syms.last_mut().unwrap().hashed = true;
    for name in ["loc", "sec", "file", "ifunc", "common", "und"] {
        let p = prog().undef(name, GLOBAL);
        let p = p.clone().rel(p.rw(), R_GLOB_DAT, Some(name), 0);
        assert!(
            matches!(run(&hidden, &p).0, Err(Refusal::Unresolved(_))),
            "{name}"
        );
        // A weak reference to it is NULL.
        let p = prog().undef(name, WEAK);
        let p = p.clone().rel(p.rw(), R_GLOB_DAT, Some(name), 0);
        let (result, space, ..) = run(&hidden, &p);
        result.unwrap();
        assert_eq!(word(&space, p.rw()), 0, "{name}");
    }
}

#[test]
fn a_library_never_resolves_outside_itself() {
    for bind in [GLOBAL, WEAK] {
        let l = lib().undef("ext", bind);
        let l = l.clone().rel(l.rw(), R_GLOB_DAT, Some("ext"), 0);
        let (result, ..) = run(&l, &prog());
        assert!(matches!(result, Err(Refusal::Unresolved(_))), "{bind}");
    }
    // Not even the name of the program's own definition.
    let l = lib().undef("pdef", GLOBAL);
    let l = l.clone().rel(l.rw(), R_ABS64, Some("pdef"), 0);
    let (result, ..) = run(&l, &prog().func("pdef", 0x20_3000));
    assert!(matches!(result, Err(Refusal::Unresolved(_))));
}

#[test]
fn absolute_symbols_and_the_bias() {
    let mut l = lib().sym("abs", GLOBAL, OBJECT, SHN_ABS, 0x1234);
    l.bias = 0x1_0000;
    let rw = l.rw();
    let l = l
        .rel(rw, R_RELATIVE, None, 0x400_0040)
        .rel(rw + 8, R_ABS64, Some("f"), 0)
        .rel(rw + 16, R_ABS64, Some("abs"), 1);
    let mut l2 = l.clone();
    l2.relr = vec![rw + 24, 0b11];
    let mut p = prog().undef("f", GLOBAL).undef("abs", GLOBAL);
    p.bias = 0x2_0000;
    let prw = p.rw();
    let p = p
        .rel(prw, R_GLOB_DAT, Some("f"), 0)
        .rel(prw + 8, R_GLOB_DAT, Some("abs"), 0)
        .rel(prw + 16, R_RELATIVE, None, 8);
    let (lb, pb, mut space) = pair(&l2, &p);
    // The words the RELR table adds the bias to.
    space.set_u64(lb.at(rw + 24), 0x400_0500);
    space.set_u64(lb.at(rw + 32), 0x400_0600);
    let (lm, pm) = (lb.module(&space).unwrap(), pb.module(&space).unwrap());
    let counts = relocate(&lm, &pm, &mut space).unwrap();
    assert_eq!(word(&space, lb.at(rw)), 0x1_0000 + 0x400_0040);
    assert_eq!(word(&space, lb.at(rw + 8)), 0x1_0000 + 0x400_0100);
    assert_eq!(
        word(&space, lb.at(rw + 16)),
        0x1235,
        "SHN_ABS takes no bias"
    );
    assert_eq!(word(&space, lb.at(rw + 24)), 0x1_0000 + 0x400_0500);
    assert_eq!(word(&space, lb.at(rw + 32)), 0x1_0000 + 0x400_0600);
    assert_eq!(
        word(&space, pb.at(prw)),
        0x1_0000 + 0x400_0100,
        "a symbol of the library carries its bias"
    );
    assert_eq!(word(&space, pb.at(prw + 8)), 0x1234);
    assert_eq!(word(&space, pb.at(prw + 16)), 0x2_0008);
    assert_eq!(counts.library.relr, 2);
}

#[test]
fn relr_has_addresses_and_bitmaps() {
    let mut l = lib();
    l.rw_size = 0x4000;
    let rw = l.rw();
    // An address word, a bitmap for the words after it (bits 1 and 3: the
    // first and the third), then a second bitmap that continues 63 words
    // after the first one began, then a new address.
    l.relr = vec![rw, 0b1011, 0b11, rw + 0x1000];
    let (lb, pb, mut space) = pair(&l, &prog());
    for i in 0..0x400 {
        space.set_u64(rw + 8 * i, 0x1000_0000 + i * 0x100);
    }
    let mut l2 = lb.module(&space).unwrap();
    l2.dynamic.role = Role::Library;
    let pm = pb.module(&space).unwrap();
    let before = space.clone();
    let counts = relocate(&l2, &pm, &mut space).unwrap();
    assert_eq!(counts.library.relr, 1 + 2 + 1 + 1);
    for a in (rw..rw + 0x1008).step_by(8) {
        let expected = word(&before, a);
        assert_eq!(word(&space, a), expected, "bias 0 changes no value: {a:#x}");
    }
    // At bias 0 the places are checked and counted, and nothing is written.
    assert!(space.writes.is_empty(), "{:?}", space.writes);
}

#[test]
fn relr_adds_the_bias_to_the_words_it_names() {
    let mut l = lib();
    l.bias = 0x100_0000;
    l.rw_size = 0x2000;
    let rw = l.rw();
    l.relr = vec![rw + 8, 0b101, 0xffff_ffff_ffff_ffff];
    let (lb, pb, mut space) = pair(&l, &prog());
    for i in 0..0x300 {
        space.set_u64(lb.at(rw) + 8 * i, 0x2000 + 8 * i);
    }
    let (lm, pm) = (lb.module(&space).unwrap(), pb.module(&space).unwrap());
    let counts = relocate(&lm, &pm, &mut space).unwrap();
    // rw+8, then the bitmap 0b101: bit 2 -> the second word after rw+16... k=1 -> rw+16+8.
    let named: Vec<u64> = {
        let mut v = vec![rw + 8, rw + 16 + 8];
        let next = rw + 16 + 63 * 8;
        v.extend((0..63).map(|k| next + 8 * k));
        v
    };
    assert_eq!(counts.library.relr as usize, named.len());
    for i in 0..0x300u64 {
        let at = rw + 8 * i;
        let base = 0x2000 + 8 * i;
        let expected = if named.contains(&at) {
            base + 0x100_0000
        } else {
            base
        };
        assert_eq!(word(&space, lb.at(at)), expected, "{at:#x}");
    }
}

#[test]
fn a_relr_place_that_is_not_a_word_of_the_data_is_refused() {
    let rw = lib().rw();
    for table in [
        vec![rw + 4],            // not aligned
        vec![rw - 8],            // the code segment
        vec![0x10],              // nowhere
        vec![rw + 0x1000],       // past the data
        vec![rw + 0xff8 + 8],    // the same
        vec![0b11],              // a bitmap first: the places start at 0
        vec![rw + 0xff0, 0b111], // the bitmap runs off the end
        vec![u64::MAX - 1],      // wraps
    ] {
        let mut l = lib();
        l.relr = table.clone();
        let (result, ..) = run(&l, &prog());
        assert!(
            matches!(result, Err(Refusal::Place(_))),
            "{table:x?} {result:?}"
        );
    }
    let mut l = lib();
    l.bias = 1;
    l.relr = vec![rw];
    let (lb, pb, mut space) = pair(&l, &prog());
    space.set_u64(lb.at(rw), u64::MAX);
    let (lm, pm) = (lb.module(&space).unwrap(), pb.module(&space).unwrap());
    assert_eq!(relocate(&lm, &pm, &mut space), Err(Refusal::Overflow));
}

#[test]
fn tls_offsets_follow_the_block_of_the_library() {
    for (align, base) in [(8u64, 16u64), (16, 16), (32, 32), (64, 64), (4096, 4096)] {
        let mut l = lib()
            .sym("tv", GLOBAL, TLS, 1, 0x20)
            .sym("tw", GLOBAL, TLS, 1, 0);
        l.tls_align = align;
        let rw = l.rw();
        let l = l
            .rel(rw, R_TLS_TPREL64, Some("tv"), 4)
            .rel(rw + 8, R_TLS_TPREL64, None, 8) // no symbol: the base alone
            .rel(rw + 16, R_TLS_TPREL64, Some("tw"), 0);
        let p = prog().undef("tv", GLOBAL);
        let p = p.clone().rel(p.rw(), R_TLS_TPREL64, Some("tv"), 2);
        let (result, space, lb, pb) = run(&l, &p);
        let counts = result.unwrap();
        assert_eq!(word(&space, lb.at(rw)), base + 0x20 + 4, "align {align}");
        assert_eq!(word(&space, lb.at(rw + 8)), base + 8);
        assert_eq!(word(&space, lb.at(rw + 16)), base);
        assert_eq!(
            word(&space, pb.at(p.rw())),
            base + 0x20 + 2,
            "the program's reference"
        );
        assert_eq!((counts.library.tpoff, counts.program.tpoff), (3, 1));
    }
}

#[test]
fn a_program_asks_for_tls_through_a_symbol_alone() {
    let mut l = lib().sym("tv", GLOBAL, TLS, 1, 0x20);
    l.tls_align = 16;
    let p = prog();
    let p = p.clone().rel(p.rw(), R_TLS_TPREL64, None, 8);
    assert_eq!(run(&l, &p).0, Err(Refusal::Symbol(0)));
    let p = prog();
    let p = p.clone().slot(p.rw(), R_TLS_TPREL64, None, 8);
    assert_eq!(run(&l, &p).0, Err(Refusal::Symbol(0)));
    // The library itself may.
    let l2 = l.clone().rel(l.rw(), R_TLS_TPREL64, None, 8);
    assert!(run(&l2, &prog()).0.is_ok());
}

#[test]
fn tls_relocations_need_a_block_and_a_tls_symbol() {
    let tls_lib = |align| {
        let mut l = lib().sym("tv", GLOBAL, TLS, 1, 0x20);
        l.tls_align = align;
        l
    };
    // No PT_TLS, or an alignment that is no power of two.
    for align in [0, 3, 24] {
        let l = tls_lib(align);
        let l = l.clone().rel(l.rw(), R_TLS_TPREL64, Some("tv"), 0);
        assert_eq!(run(&l, &prog()).0, Err(Refusal::NoTls), "{align}");
        let l = tls_lib(align);
        let l = l.clone().rel(l.rw(), R_TLS_TPREL64, None, 0);
        assert_eq!(run(&l, &prog()).0, Err(Refusal::NoTls), "{align}");
    }
    // The program has no block: its own TLS symbol is refused.
    let p = prog().sym("own", GLOBAL, TLS, 1, 0);
    let p = p.clone().rel(p.rw(), R_TLS_TPREL64, Some("own"), 0);
    assert_eq!(run(&tls_lib(16), &p).0, Err(Refusal::NoTls));
    // The program asks for the offset of a symbol that is no TLS symbol, or
    // takes the address of a TLS symbol.
    let p = prog().undef("f", GLOBAL);
    let p = p.clone().rel(p.rw(), R_TLS_TPREL64, Some("f"), 0);
    assert!(matches!(
        run(&tls_lib(16), &p).0,
        Err(Refusal::SymbolType(_))
    ));
    for kind in [R_ABS64, R_GLOB_DAT, R_JUMP_SLOT] {
        let p = prog().undef("tv", GLOBAL);
        let p = p.clone().rel(p.rw(), kind, Some("tv"), 0);
        assert!(
            matches!(run(&tls_lib(16), &p).0, Err(Refusal::SymbolType(_))),
            "{kind}"
        );
    }
    // A TLS symbol of the program's own through another kind.
    let p = prog().sym("own", GLOBAL, TLS, 1, 0);
    let p = p.clone().rel(p.rw(), R_GLOB_DAT, Some("own"), 0);
    assert_eq!(run(&tls_lib(16), &p).0, Err(Refusal::NoTls));
    // A weak reference nothing defines has no offset to be zero.
    let p = prog().undef("nothing", WEAK);
    let p = p.clone().rel(p.rw(), R_TLS_TPREL64, Some("nothing"), 0);
    assert!(matches!(
        run(&tls_lib(16), &p).0,
        Err(Refusal::Unresolved(_))
    ));
    // A common symbol is no definition.
    let p = prog().sym("c", GLOBAL, OBJECT, SHN_COMMON, 8);
    let p = p.clone().rel(p.rw(), R_GLOB_DAT, Some("c"), 0);
    assert!(matches!(run(&lib(), &p).0, Err(Refusal::SymbolType(_))));
    let p = prog().sym("s", GLOBAL, SECTION, 1, 0x20_0000);
    let p = p.clone().rel(p.rw(), R_GLOB_DAT, Some("s"), 0);
    assert!(matches!(run(&lib(), &p).0, Err(Refusal::SymbolType(_))));
}

#[test]
fn the_kinds_the_loader_does_not_know_are_refused() {
    for kind in [
        R_COPY,
        R_TLS_DTPMOD64,
        R_TLS_DTPREL64,
        R_TLSDESC,
        R_IRELATIVE,
        1,
        2,
        9999,
        0x1_0000,
    ] {
        for table in 0..2 {
            for module in 0..2 {
                let mk = |b: B| {
                    if table == 0 {
                        b.clone().rel(b.rw(), kind, None, 0)
                    } else {
                        b.clone().slot(b.rw(), kind, None, 0)
                    }
                };
                let (l, p) = if module == 0 {
                    (mk(lib()), prog())
                } else {
                    (lib(), mk(prog()))
                };
                assert_eq!(
                    run(&l, &p).0,
                    Err(Refusal::Kind(kind)),
                    "kind {kind} table {table}"
                );
            }
        }
    }
}

/// The place in the code segment is the check the spec names first: a
/// relocation that writes there is a text relocation.
#[test]
fn a_place_in_the_code_segment_is_refused() {
    let l = lib();
    let rx = l.base + l.r_size;
    for place in [rx, rx + 0x100, rx + PAGE - 8, l.base, l.base + 0x100] {
        for kind in [R_RELATIVE, R_ABS64, R_GLOB_DAT] {
            let q = lib().rel(
                place,
                kind,
                if kind == R_RELATIVE { None } else { Some("f") },
                0,
            );
            assert_eq!(
                run(&q, &prog()).0,
                Err(Refusal::Place(place)),
                "{place:#x} {kind}"
            );
        }
        let q = prog().undef("f", GLOBAL).slot(
            place - lib().base + prog().base,
            R_JUMP_SLOT,
            Some("f"),
            0,
        );
        assert!(matches!(run(&lib(), &q).0, Err(Refusal::Place(_))));
    }
}

#[test]
fn a_place_that_is_not_a_whole_aligned_word_of_the_data_is_refused() {
    let l = lib();
    let rw = l.rw();
    let end = rw + PAGE;
    for place in [
        rw + 4,
        rw + 1,
        end - 4,
        end,
        end + 8,
        rw - 8,
        0,
        0x10,
        u64::MAX - 3,
        u64::MAX - 7,
        !7,
    ] {
        let q = lib().rel(place, R_RELATIVE, None, 0);
        assert_eq!(run(&q, &prog()).0, Err(Refusal::Place(place)), "{place:#x}");
        let q = lib().slot(place, R_JUMP_SLOT, Some("f"), 0);
        assert_eq!(run(&q, &prog()).0, Err(Refusal::Place(place)), "{place:#x}");
    }
    // The first and the last word of the data are fine.
    let q = lib()
        .rel(rw, R_RELATIVE, None, 1)
        .rel(end - 8, R_RELATIVE, None, 2);
    let (result, space, lb, _) = run(&q, &prog());
    result.unwrap();
    assert_eq!(
        (word(&space, lb.at(rw)), word(&space, lb.at(end - 8))),
        (1, 2)
    );
}

#[test]
fn a_symbol_index_beyond_the_table_is_refused() {
    let p = prog().undef("f", GLOBAL); // 2 symbols
    for raw in [2, 3, 99, u32::MAX] {
        let mut q = p.clone().rel(p.rw(), R_GLOB_DAT, Some("f"), 0);
        q.rela[0].raw_sym = Some(raw);
        assert_eq!(run(&lib(), &q).0, Err(Refusal::Symbol(raw)), "{raw}");
        let mut q = p.clone().slot(p.rw(), R_JUMP_SLOT, Some("f"), 0);
        q.jmprel[0].raw_sym = Some(raw);
        assert_eq!(run(&lib(), &q).0, Err(Refusal::Symbol(raw)), "{raw}");
    }
    // The last symbol is still fine.
    let mut q = p.clone().rel(p.rw(), R_GLOB_DAT, Some("f"), 0);
    q.rela[0].raw_sym = Some(1);
    run(&lib(), &q).0.unwrap();
    // RELATIVE has no symbol.
    let mut q = lib().rel(lib().rw(), R_RELATIVE, None, 0);
    q.rela[0].raw_sym = Some(1);
    assert_eq!(run(&q, &prog()).0, Err(Refusal::Symbol(1)));
}

#[test]
fn names_stay_in_the_string_table_and_at_most_255_bytes() {
    // 255 bytes: found. 256: refused.
    let long = "n".repeat(255);
    let l = lib().func(&long, 0x400_0900);
    let p = prog().undef(&long, GLOBAL);
    let p = p.clone().rel(p.rw(), R_GLOB_DAT, Some(&long), 0);
    let (result, space, _, pb) = run(&l, &p);
    result.unwrap();
    assert_eq!(word(&space, pb.at(p.rw())), 0x400_0900);
    let longer = "n".repeat(256);
    let p = prog().undef(&longer, GLOBAL);
    let p = p.clone().rel(p.rw(), R_GLOB_DAT, Some(&longer), 0);
    assert_eq!(run(&l, &p).0, Err(Refusal::Name));
    // A name offset past the table.
    let p = prog().undef("f", GLOBAL);
    let p = p.clone().rel(p.rw(), R_GLOB_DAT, Some("f"), 0);
    let (lb, pb, mut space) = pair(&lib(), &p);
    let at = pb.symtab + 24;
    space.set_u32(at, 100_000);
    let (lm, pm) = (lb.module(&space).unwrap(), pb.module(&space).unwrap());
    assert_eq!(relocate(&lm, &pm, &mut space), Err(Refusal::Name));
    // A name that runs to the end of the table without a NUL.
    let (lb, pb, mut space) = pair(&lib(), &p);
    let (lm, pm) = (lb.module(&space).unwrap(), pb.module(&space).unwrap());
    let last = pb.strtab + pm.dynamic.strsz - 1;
    let first_needed = pm.dynamic.strsz - 8; // "libc.so\0" is the end of the table
    space.set_u32(pb.symtab + 24, first_needed as u32);
    space.set(last, b"x");
    assert_eq!(relocate(&lm, &pm, &mut space), Err(Refusal::Name));
}

#[test]
fn the_limits_of_the_records_the_places_and_the_searches() {
    let big = |l: &mut B| l.r_size = 0x20_0000;
    // RELOCS_MAX records pass, one more is refused, rela and jmprel together.
    let mut l = lib();
    big(&mut l);
    let place = l.rw();
    let mk = |rela: u32, slots: u32| {
        let mut l = l.clone();
        for _ in 0..rela {
            l = l.rel(place, R_RELATIVE, None, 1);
        }
        for _ in 0..slots {
            l = l.slot(place, R_JUMP_SLOT, Some("f"), 0);
        }
        l
    };
    let (result, ..) = run(&mk(RELOCS_MAX, 0), &prog());
    assert_eq!(result.unwrap().library.relative, RELOCS_MAX);
    assert_eq!(
        run(&mk(RELOCS_MAX + 1, 0), &prog()).0,
        Err(Refusal::Limit(Limit::Relocs))
    );
    assert_eq!(
        run(&mk(0, RELOCS_MAX + 1), &prog()).0,
        Err(Refusal::Limit(Limit::Relocs))
    );
    assert_eq!(
        run(&mk(40_000, 25_537), &prog()).0,
        Err(Refusal::Limit(Limit::Relocs))
    );
    assert!(run(&mk(40_000, 25_536), &prog()).0.is_ok());
    // The program has its own count.
    let mut p = prog().undef("f", GLOBAL);
    p.r_size = 0x20_0000;
    let mut q = p.clone();
    for _ in 0..=RELOCS_MAX {
        q = q.rel(p.rw(), R_RELATIVE, None, 0);
    }
    assert_eq!(run(&lib(), &q).0, Err(Refusal::Limit(Limit::Relocs)));
    // RELR: every word of the table and every place it applies count as
    // one record each.
    let mut l = lib();
    l.rw_size = 0x10_0000;
    let rw = l.rw();
    for (bitmaps, ok) in [(1023usize, true), (1024, false)] {
        let mut l = l.clone();
        l.relr = vec![rw];
        l.relr.extend(std::iter::repeat_n(u64::MAX, bitmaps));
        let (result, ..) = run(&l, &prog());
        if ok {
            assert_eq!(result.unwrap().library.relr as usize, 1 + 63 * bitmaps);
        } else {
            assert_eq!(result, Err(Refusal::Limit(Limit::Relocs)));
        }
    }
    // A table of words without a bit does no work and still counts.
    for (words, ok) in [
        (RELOCS_MAX as usize - 1, true),
        (RELOCS_MAX as usize, false),
    ] {
        let mut l = lib();
        l.r_size = 0x10_0000;
        let rw = l.rw();
        l.relr = vec![rw];
        l.relr.extend(std::iter::repeat_n(1u64, words - 1));
        let (result, ..) = run(&l, &prog());
        if ok {
            assert_eq!(result.unwrap().library.relr, 1);
        } else {
            assert_eq!(result, Err(Refusal::Limit(Limit::Relocs)));
        }
    }
    // The records and the places add up.
    let mut l = lib();
    for _ in 0..100 {
        l = l.rel(rw, R_RELATIVE, None, 0);
    }
    l.rw_size = 0x10_0000;
    l.relr = vec![rw];
    l.relr.extend(std::iter::repeat_n(u64::MAX, 1023));
    assert_eq!(run(&l, &prog()).0, Err(Refusal::Limit(Limit::Relocs)));
    // LOOKUPS_MAX searches pass, one more is refused.
    let mut p = prog().undef("f", GLOBAL);
    p.r_size = 0x8_0000;
    let place = p.rw();
    let mk = |n: u32| {
        let mut q = p.clone();
        for _ in 0..n {
            q = q.slot(place, R_JUMP_SLOT, Some("f"), 0);
        }
        q
    };
    assert_eq!(
        run(&lib(), &mk(LOOKUPS_MAX)).0.unwrap().lookups,
        LOOKUPS_MAX
    );
    assert_eq!(
        run(&lib(), &mk(LOOKUPS_MAX + 1)).0,
        Err(Refusal::Limit(Limit::Lookups))
    );
}

#[test]
fn a_chain_longer_than_the_limit_is_refused_in_a_relocation() {
    let mut l = lib();
    l.nbuckets = 1;
    for i in 0..70 {
        l = l.func(&format!("c{i}"), 0x400_1000 + i);
    }
    // One bucket, in the order of the table: f, g, obj and weakf of lib()
    // come first, so c59 is the 64th symbol of the chain and c60 the 65th.
    for (name, ok) in [("c0", true), ("c59", true), ("c60", false), ("c69", false)] {
        let p = prog().undef(name, GLOBAL);
        let p = p.clone().rel(p.rw(), R_GLOB_DAT, Some(name), 0);
        let result = run(&l, &p).0;
        if ok {
            result.unwrap();
        } else {
            assert_eq!(result, Err(Refusal::Limit(Limit::Chain)), "{name}");
        }
    }
}

#[test]
fn overflowing_sums_are_refused() {
    let l = lib().rel(lib().rw(), R_RELATIVE, None, i64::MIN);
    assert_eq!(run(&l, &prog()).0, Err(Refusal::Overflow));
    let l = lib().rel(lib().rw(), R_ABS64, Some("f"), i64::MIN);
    assert_eq!(run(&l, &prog()).0, Err(Refusal::Overflow));
}

#[test]
fn only_the_data_segments_are_written() {
    let l = lib();
    let rw = l.rw();
    let l = l
        .rel(rw, R_ABS64, Some("f"), 0)
        .slot(rw + 8, R_JUMP_SLOT, Some("g"), 0)
        .rel(rw + 16, R_RELATIVE, None, 5);
    let p = prog().undef("f", GLOBAL);
    let prw = p.rw();
    let mut p = p.rel(prw, R_GLOB_DAT, Some("f"), 0);
    p.relr = vec![prw + 8];
    let (lb, pb, mut space) = pair(&l, &p);
    let (lm, pm) = (lb.module(&space).unwrap(), pb.module(&space).unwrap());
    let before = space.clone();
    relocate(&lm, &pm, &mut space).unwrap();
    for built in [&lb, &pb] {
        for segment in &built.segments {
            if segment.access == Access::ReadWrite {
                continue;
            }
            let n = segment.memsz as usize;
            assert_eq!(
                space.bytes(segment.vaddr, n),
                before.bytes(segment.vaddr, n),
                "{:#x}",
                segment.vaddr
            );
        }
    }
    for w in &space.writes {
        assert!(
            [lb.segments[2], pb.segments[2]]
                .iter()
                .any(|s| s.vaddr <= *w && *w + 8 <= s.vaddr + s.memsz),
            "{w:#x}"
        );
    }
    // The RELR word of the program (bias 0) is checked and not written.
    assert_eq!(space.writes.len(), 3 + 1);
}

/// The library goes first: its words are written when the program is
/// refused, and its refusal comes before the program's.
#[test]
fn the_library_is_relocated_before_the_program() {
    let l = lib();
    let lrw = l.rw();
    let l = l.rel(lrw, R_RELATIVE, None, 0x77);
    let p = prog();
    let p = p.clone().rel(p.rw(), R_COPY, None, 0);
    let (result, space, lb, _) = run(&l, &p);
    assert_eq!(result, Err(Refusal::Kind(R_COPY)));
    assert_eq!(word(&space, lb.at(lrw)), 0x77);
    // Both bad: the library's refusal is the one reported.
    let l = lib();
    let l = l.clone().rel(l.rw(), R_IRELATIVE, None, 0);
    assert_eq!(run(&l, &p).0, Err(Refusal::Kind(R_IRELATIVE)));
    // The program's references see a library that is already relocated: the
    // order of the area is library, then program (the program's pointer
    // into the library's data is the library's own address).
    let p = prog().undef("obj", GLOBAL);
    let prw = p.rw();
    let p = p.rel(prw, R_ABS64, Some("obj"), 0);
    let (result, space, _, pb) = run(&lib(), &p);
    result.unwrap();
    assert_eq!(word(&space, pb.at(prw)), 0x400_2000);
}

#[test]
fn the_modules_must_be_given_in_their_roles() {
    let (lb, pb, mut space) = pair(&lib(), &prog());
    let (lm, pm) = (lb.module(&space).unwrap(), pb.module(&space).unwrap());
    assert_eq!(relocate(&pm, &lm, &mut space), Err(Refusal::Role));
    assert_eq!(relocate(&lm, &lm, &mut space), Err(Refusal::Role));
    assert_eq!(relocate(&pm, &pm, &mut space), Err(Refusal::Role));
    assert!(relocate(&lm, &pm, &mut space).is_ok());
}

#[test]
fn memory_that_refuses_is_a_refusal() {
    let l = lib().rel(lib().rw(), R_RELATIVE, None, 0);
    let (lb, pb, space) = pair(&l, &prog());
    let (lm, pm) = (lb.module(&space).unwrap(), pb.module(&space).unwrap());
    // Memory that lacks the data page.
    let mut short = Space::default()
        .with(
            lb.space_base,
            lb.image[..lb.segments[2].vaddr as usize - lb.space_base as usize].to_vec(),
        )
        .with(pb.space_base, pb.image.clone());
    assert_eq!(relocate(&lm, &pm, &mut short), Err(Refusal::Memory));
}
