// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The search by `DT_GNU_HASH`.

mod common;
use common::*;
use dynlink::{CHAIN_MAX, Limit, Module, NAME_MAX, Refusal, Symbol, gnu_hash, lookup};

fn find(b: &B, name: &[u8]) -> Result<Option<Symbol>, Refusal> {
    let built = b.build();
    let space = built.space();
    let m: Module = built.module(&space).unwrap();
    lookup(&m, &space, name)
}

#[test]
fn the_hash_is_the_djb2_of_the_gnu_table() {
    assert_eq!(gnu_hash(b""), 5381);
    assert_eq!(gnu_hash(b"a"), 5381 * 33 + 97);
    assert_eq!(gnu_hash(b"printf"), 0x156b_2bb8);
    // Two names of one hash (the pair the tests below collide on).
    assert_eq!(gnu_hash(b"abx"), gnu_hash(b"bAx"));
}

#[test]
fn a_defined_symbol_is_found_with_its_value() {
    let b = B::library()
        .func("f", 0x400_0100)
        .sym("obj", GLOBAL, OBJECT, 1, 0x400_2000)
        .sym("w", WEAK, FUNC, 1, 0x400_0300)
        .sym("t", GLOBAL, TLS, 1, 0x18)
        .sym("n", GLOBAL, NOTYPE, 1, 0x400_0500);
    for (name, value, kind) in [
        ("f", 0x400_0100, FUNC),
        ("obj", 0x400_2000, OBJECT),
        ("w", 0x400_0300, FUNC),
        ("t", 0x18, TLS),
        ("n", 0x400_0500, NOTYPE),
    ] {
        let s = find(&b, name.as_bytes()).unwrap().unwrap();
        assert_eq!((s.value, s.kind), (value, kind), "{name}");
        assert!(s.defined());
    }
    assert_eq!(find(&b, b"w").unwrap().unwrap().bind, WEAK);
    // The address carries the bias; an absolute symbol does not.
    let s = find(&b, b"f").unwrap().unwrap();
    assert_eq!(s.address(0x1000).unwrap(), 0x400_1100);
    assert_eq!(s.address(u64::MAX), Err(Refusal::Overflow));
}

#[test]
fn a_name_the_module_lacks_is_none() {
    let b = B::library().func("foo", 1).func("foobar", 2).func("fo", 3);
    for name in ["", "f", "foob", "foobarr", "Foo", "bar", "foo\0", "zzzzzz"] {
        assert_eq!(find(&b, name.as_bytes()).unwrap(), None, "{name:?}");
    }
    assert_eq!(find(&b, b"foo").unwrap().unwrap().value, 1);
    assert_eq!(find(&b, b"foobar").unwrap().unwrap().value, 2);
    assert_eq!(find(&b, b"fo").unwrap().unwrap().value, 3);
    // No symbols at all.
    assert_eq!(find(&B::library(), b"x").unwrap(), None);
}

#[test]
fn names_with_one_hash_are_told_apart_by_their_bytes() {
    let b = B::library().func("abx", 11).func("bAx", 22);
    assert_eq!(find(&b, b"abx").unwrap().unwrap().value, 11);
    assert_eq!(find(&b, b"bAx").unwrap().unwrap().value, 22);
    // Only one of the two is in the table: the other has the hash but is not there.
    let one = B::library().func("abx", 11);
    assert_eq!(find(&one, b"bAx").unwrap(), None);
}

#[test]
fn what_a_module_does_not_export_is_not_found() {
    let mut b = B::library()
        .sym("local", LOCAL, FUNC, 1, 1)
        .sym("section", GLOBAL, SECTION, 1, 2)
        .sym("file", GLOBAL, FILE, 1, 3)
        .sym("ifunc", GLOBAL, IFUNC, 1, 4)
        .sym("common", GLOBAL, OBJECT, SHN_COMMON, 5)
        .undef("undefined", GLOBAL)
        .undef("weak_undefined", WEAK)
        .sym("good", GLOBAL, FUNC, 1, 6);
    for s in b.syms.iter_mut().filter(|s| s.shndx == 0) {
        s.hashed = true;
    }
    for name in [
        "local",
        "section",
        "file",
        "ifunc",
        "common",
        "undefined",
        "weak_undefined",
    ] {
        assert_eq!(find(&b, name.as_bytes()).unwrap(), None, "{name}");
    }
    assert_eq!(find(&b, b"good").unwrap().unwrap().value, 6);
    // An absolute symbol is a definition.
    let b = B::library().sym("abs", GLOBAL, OBJECT, SHN_ABS, 0x77);
    let s = find(&b, b"abs").unwrap().unwrap();
    assert_eq!(s.address(0x1000).unwrap(), 0x77);
}

#[test]
fn a_global_and_a_weak_of_one_name_give_the_first() {
    let b = B::library()
        .sym("dup", WEAK, FUNC, 1, 1)
        .sym("dup", GLOBAL, FUNC, 1, 2);
    let s = find(&b, b"dup").unwrap().unwrap();
    assert_eq!(s.value, 1, "the first of the chain");
    // A local one before a global one: the local is skipped.
    let b = B::library()
        .sym("dup", LOCAL, FUNC, 1, 1)
        .sym("dup", GLOBAL, FUNC, 1, 2);
    assert_eq!(find(&b, b"dup").unwrap().unwrap().value, 2);
}

fn chain(n: usize, buckets: u32) -> B {
    let mut b = B::library();
    b.nbuckets = buckets;
    for i in 0..n {
        b = b.func(&format!("c{i}"), 0x400_1000 + i as u64);
    }
    b
}

#[test]
fn a_chain_of_the_limit_is_walked_and_one_step_more_is_refused() {
    let n = CHAIN_MAX as usize;
    let b = chain(n + 6, 1);
    // The symbols are in the table in order; the k-th one sits k steps in.
    for k in [0, 1, 10, n - 1] {
        let s = find(&b, format!("c{k}").as_bytes()).unwrap().unwrap();
        assert_eq!(s.value, 0x400_1000 + k as u64, "step {k}");
    }
    for k in [n, n + 1, n + 5] {
        assert_eq!(
            find(&b, format!("c{k}").as_bytes()),
            Err(Refusal::Limit(Limit::Chain)),
            "step {k}"
        );
    }
    // A chain of exactly the limit ends well.
    let b = chain(n, 1);
    assert_eq!(
        find(&b, format!("c{}", n - 1).as_bytes())
            .unwrap()
            .unwrap()
            .value,
        0x400_1000 + n as u64 - 1
    );
    // A name the chain lacks: the walk runs the whole chain and says none,
    // or the Bloom filter stops it first.
    let r = find(&b, b"absent");
    assert!(
        matches!(r, Ok(None) | Err(Refusal::Limit(Limit::Chain))),
        "{r:?}"
    );
}

#[test]
fn many_buckets_keep_the_chains_short() {
    let b = chain(500, 64);
    for i in (0..500).step_by(7) {
        let s = find(&b, format!("c{i}").as_bytes());
        match s {
            Ok(Some(s)) => assert_eq!(s.value, 0x400_1000 + i),
            other => panic!("c{i}: {other:?}"),
        }
    }
    assert_eq!(find(&b, b"c500").unwrap(), None);
}

#[test]
fn a_name_longer_than_the_limit_is_refused() {
    let b = B::library().func("f", 1);
    assert_eq!(find(&b, &vec![b'x'; NAME_MAX + 1]), Err(Refusal::Name));
    let long = "y".repeat(NAME_MAX);
    let b = B::library().func(&long, 9);
    assert_eq!(find(&b, long.as_bytes()).unwrap().unwrap().value, 9);
}

#[test]
fn a_symbol_whose_name_leaves_the_table_is_a_refusal() {
    let b = B::library().func("f", 0x400_0100).build();
    let mut space = b.space();
    let m = b.module(&space).unwrap();
    // The name of symbol 1 points past DT_STRSZ.
    space.set_u32(b.symtab + 24, 5000);
    assert_eq!(lookup(&m, &space, b"f"), Err(Refusal::Name));
    // A chain entry that names a symbol beyond the table.
    let b = B::library().func("f", 0x400_0100).build();
    let mut space = b.space();
    let m = b.module(&space).unwrap();
    let buckets = b.hash + 16 + 8 * 2;
    let h = gnu_hash(b"f");
    space.set_u32(buckets + 4 * (h % 3) as u64, 9);
    assert_eq!(lookup(&m, &space, b"f"), Err(Refusal::Symbol(9)));
    // A bucket below the first hashed symbol is empty.
    space.set_u32(buckets + 4 * (h % 3) as u64, 0);
    assert_eq!(lookup(&m, &space, b"f").unwrap(), None);
}

#[test]
fn memory_that_refuses_is_a_refusal() {
    let b = B::library().func("f", 0x400_0100).build();
    let space = b.space();
    let m = b.module(&space).unwrap();
    assert_eq!(lookup(&m, &Space::default(), b"f"), Err(Refusal::Memory));
}

#[test]
fn a_module_with_a_bias_finds_its_tables_there() {
    let mut l = B::library().func("f", 0x400_0100);
    l.bias = 0x1_0000;
    let b = l.build();
    let space = b.space();
    let m = b.module(&space).unwrap();
    let s = lookup(&m, &space, b"f").unwrap().unwrap();
    assert_eq!(s.address(m.bias).unwrap(), 0x401_0100);
}
