// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The tests of the answers of the service over a volume and a lower set in memory.

use crate::composition::Composition;
use crate::identity::{Vouched, vouched_from};
use crate::index::Index;
use crate::names::{Client, Core, Done, State};
use crate::scan::Scan;
use crate::testkit::{FakeLower, FakeVolume};
use proto_data as d;
use proto_fs as f;
use proto_fs::names::{self as n, OpenAnswer, UPPER_INO_TAG};
use proto_layer as l;
use proto_wire::{Status, Writer};
use std::boxed::Box;
use std::vec::Vec;

fn st(code: u32) -> Status {
    Status::Unknown(code)
}

/// The volume of the tests: the live layer 00 with /etc (a mark of deletion for motd, a file that
/// shadows a lower one, a file of its own), /home (0700) with a file, /opq (opaque) with a file,
/// and a file of the layer of the user only.
fn volume() -> FakeVolume {
    let mut v = FakeVolume::new();
    v.dir("/.layers", 0o700, 0)
        .dir("/.layers/00", 0o755, 0)
        .dir("/.layers/work", 0o700, 0)
        .file(
            "/.layers/COMPOSITION",
            0o600,
            0,
            b"STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 00 live unsealed - -\n",
        )
        .dir("/.layers/00/etc", 0o755, 0)
        .file("/.layers/00/etc/.wh.motd", 0o644, 0, b"")
        .file("/.layers/00/etc/passwd", 0o644, 0, b"upper passwd")
        .file_numbered(
            "/.layers/00/etc/own.conf",
            0o640,
            1000,
            UPPER_INO_TAG | 7,
            b"own bytes",
        )
        .dir("/.layers/00/home", 0o700, 0)
        .file("/.layers/00/home/secret", 0o644, 0, b"s")
        .dir("/.layers/00/opq", 0o755, 0)
        .file("/.layers/00/opq/.wh..wh..opq", 0o644, 0, b"")
        .file("/.layers/00/opq/u1", 0o644, 0, b"u1")
        .file("/.layers/00/opq/u2", 0o644, 0, b"u2");
    v
}

fn lower() -> FakeLower {
    let mut l = FakeLower::new();
    l.dir("/etc", 10)
        .file("/etc/motd", 11)
        .file("/etc/passwd", 12)
        .file("/etc/hostname", 13)
        .file("/etc/group", 14)
        .dir("/bin", 20)
        .file("/bin/ls", 21)
        .dir("/opq", 30)
        .file("/opq/l1", 31)
        .file("/opq/l2", 32)
        .dir("/home", 40)
        .file("/home/other", 41);
    for i in 0..20 {
        l.file(&format!("/etc/big{i:02}"), 100 + i);
    }
    l
}

struct World {
    index: Box<Index>,
    scan: Box<Scan>,
}

impl World {
    fn new() -> World {
        World {
            index: Box::new(Index::new()),
            scan: Box::new(Scan::new()),
        }
    }

    fn core(&mut self, v: FakeVolume) -> Core<'_, FakeVolume, FakeLower> {
        Core::new(&mut self.index, &mut self.scan, v, lower(), 5)
    }
}

fn ready(core: &mut Core<'_, FakeVolume, FakeLower>) {
    core.prepare();
    assert_eq!(core.state, State::Starting);
    let mut steps = 0;
    while !core.build_step() {
        steps += 1;
        assert!(steps < 1000);
    }
    assert_eq!(core.state, State::Ready);
}

fn who(uid: u32) -> Vouched {
    vouched_from(&crate::identity::tests_who(uid)).unwrap()
}

fn open(
    core: &mut Core<'_, FakeVolume, FakeLower>,
    uid: u32,
    flags: u32,
    path: &str,
) -> Result<(Vec<u8>, Option<Vec<u8>>), Status> {
    let v = who(uid);
    let c = Client {
        owner: 40 + u64::from(uid),
        who: &v,
    };
    let mut w = Writer::new();
    let done = core.open(&c, flags, path.as_bytes(), &mut w)?;
    Ok((
        w.as_bytes().to_vec(),
        match done {
            Done::Written => None,
            Done::Pass(p) => Some(p),
        },
    ))
}

fn handle_of(reply: &[u8]) -> u32 {
    match OpenAnswer::read(reply).unwrap() {
        OpenAnswer::Directory { handle } => handle,
        other => panic!("{other:?}"),
    }
}

/// All the names of a directory description, with the number of requests it took.
fn list(core: &mut Core<'_, FakeVolume, FakeLower>, owner: u64, h: u32) -> (Vec<Vec<u8>>, usize) {
    let mut names = Vec::new();
    let mut requests = 0;
    loop {
        let (bytes, len) = core.read_dir(owner, h).unwrap();
        requests += 1;
        assert!(requests < 100);
        let (more, _, entries) = n::read_dir_reply(&bytes[..len]).unwrap();
        for e in entries {
            names.push(e.unwrap().name.to_vec());
        }
        if !more {
            return (names, requests);
        }
    }
}

fn sorted(mut v: Vec<Vec<u8>>) -> Vec<String> {
    v.sort();
    v.into_iter()
        .map(|n| String::from_utf8(n).unwrap())
        .collect()
}

#[test]
fn the_first_start_makes_the_layers_directory_and_the_composition() {
    let mut v = FakeVolume::new();
    let mut world = World::new();
    {
        let mut core = world.core(std::mem::take(&mut v));
        core.prepare();
        assert_eq!(core.state, State::Starting);
        let nodes = &core.volume.nodes;
        assert_eq!(nodes[&b"/.layers".to_vec()].mode, 0o700);
        assert_eq!(nodes[&b"/.layers".to_vec()].uid, 0);
        assert!(nodes[&b"/.layers/00".to_vec()].dir);
        assert!(nodes[&b"/.layers/work".to_vec()].dir);
        assert!(!nodes.contains_key(&b"/.layers/COMPOSITION.tmp".to_vec()));
        let text = &nodes[&b"/.layers/COMPOSITION".to_vec()].data;
        assert_eq!(Composition::parse(text), Ok(Composition::first()));
        // The file was made under another name, synced and renamed.
        assert_eq!(core.volume.calls_of("fsync"), 1);
        assert_eq!(core.volume.calls_of("rename"), 1);
        v = core.volume;
    }
    // A second start finds it and makes nothing.
    let mut world = World::new();
    let mut core = world.core(v);
    let before = core.volume.calls_of("mkdir");
    core.prepare();
    assert_eq!(core.state, State::Starting);
    assert_eq!(core.volume.calls_of("mkdir"), before);
    assert_eq!(core.volume.calls_of("rename"), 1);
}

#[test]
fn a_start_empties_the_work_directory() {
    let mut v = volume();
    v.file("/.layers/work/left", 0o600, 0, b"x")
        .dir("/.layers/work/dir", 0o700, 0)
        .file("/.layers/work/dir/inner", 0o600, 0, b"y");
    let mut world = World::new();
    let mut core = world.core(v);
    core.prepare();
    assert_eq!(core.state, State::Starting);
    assert!(core.volume.children(b"/.layers/work").is_empty());
    assert!(core.volume.nodes.contains_key(b"/.layers/work".as_slice()));
}

#[test]
fn a_frozen_layer_a_broken_file_and_a_lost_live_layer_are_damaged() {
    for text in [
        &b"STAFLAYR 1\nnext 02\nino 1\nlower -\nlayer 00 frozen unsealed - -\nlayer 01 live unsealed - -\n"[..],
        b"garbage\n",
        b"STAFLAYR 1\nnext 01\nino 1\nlower -\nlayer 05 live unsealed - -\n",
    ] {
        let mut v = volume();
        v.file("/.layers/COMPOSITION", 0o600, 0, text);
        let mut world = World::new();
        let mut core = world.core(v);
        core.prepare();
        assert_eq!(core.state, State::Damaged, "{text:?}");
        let mut w = Writer::new();
        assert_eq!(core.status(&mut w), Err(st(l::DAMAGED)));
        assert_eq!(
            open(&mut core, 0, f::READ_ONLY, "/etc/passwd").err(),
            Some(st(l::DAMAGED))
        );
    }
}

#[test]
fn with_no_volume_the_service_says_so() {
    let mut v = volume();
    v.not_ready = true;
    let mut world = World::new();
    let mut core = world.core(v);
    core.prepare();
    assert_eq!(core.state, State::NoStore);
    let mut w = Writer::new();
    core.status(&mut w).unwrap();
    let stat = l::Stat::read(w.as_bytes()).unwrap();
    assert_eq!(stat.flags, l::STATUS_NO_STORE);
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc").err(),
        Some(st(l::NO_STORE))
    );
}

#[test]
fn until_the_index_is_built_the_names_answer_starting() {
    let mut world = World::new();
    let mut core = world.core(volume());
    core.prepare();
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/passwd").err(),
        Some(st(l::STARTING))
    );
    let mut w = Writer::new();
    core.status(&mut w).unwrap();
    assert_eq!(
        l::Stat::read(w.as_bytes()).unwrap().flags,
        l::STATUS_STARTING
    );
    // The build takes more than one step (the batches of the listing are three entries).
    let mut steps = 0;
    while !core.build_step() {
        steps += 1;
    }
    assert!(steps >= 6, "{steps}");
    assert_eq!(core.state, State::Ready);
    let mut w = Writer::new();
    core.status(&mut w).unwrap();
    let stat = l::Stat::read(w.as_bytes()).unwrap();
    assert_eq!((stat.flags, stat.live, stat.frozen), (0, 0, 0));
    // etc, home, opq, passwd, own.conf, secret, u1, u2 and the mark of motd.
    assert_eq!((stat.added, stat.deleted, stat.names), (8, 1, 9));
}

#[test]
fn the_index_holds_the_layer_with_its_marks_and_its_opaque_directories() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let ix = &core.index;
    let etc = ix.lookup(0, b"etc").unwrap().0;
    assert_eq!(
        ix.lookup(etc, b"motd").unwrap().1.kind,
        crate::index::Kind::Whiteout
    );
    assert!(ix.lookup(etc, b".wh.motd").is_none());
    assert_eq!(
        ix.lookup(etc, b"own.conf").unwrap().1.number,
        UPPER_INO_TAG | 7
    );
    let opq = ix.lookup(0, b"opq").unwrap().0;
    assert_ne!(ix.flags(opq) & crate::index::OPAQUE, 0);
    assert!(ix.lookup(opq, b".wh..wh..opq").is_none());
    assert_eq!(ix.flags(etc) & crate::index::OPAQUE, 0);
    let home = ix.lookup(0, b"home").unwrap().0;
    assert_eq!(ix.attr(home).unwrap().mode, 0o700);
    assert_eq!(ix.attr(0).unwrap().mode, 0o755);
}

#[test]
fn a_name_of_the_lower_set_is_a_redirect_to_the_ram_service_with_the_whole_path() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    for path in ["/bin/ls", "/etc/hostname", "/usr/x", "/etc/../bin/ls"] {
        let (reply, pass) = open(&mut core, 1000, f::READ_ONLY, path).unwrap();
        assert!(pass.is_none());
        match OpenAnswer::read(&reply).unwrap() {
            OpenAnswer::Redirect(r) => {
                assert_eq!(r.target, f::REDIRECT_RAM);
                assert_eq!(r.path, path.as_bytes());
                assert_eq!((r.index, r.links), (0, 0));
            }
            other => panic!("{other:?}"),
        }
    }
    // A directory of the lower set alone, and the names the root passes through.
    let (reply, _) = open(&mut core, 1000, f::READ_ONLY | f::DIRECTORY_ONLY, "/bin").unwrap();
    assert!(matches!(
        OpenAnswer::read(&reply).unwrap(),
        OpenAnswer::Redirect(r) if r.path == b"/bin"
    ));
    let (reply, _) = open(&mut core, 1000, f::READ_ONLY, "/data/x").unwrap();
    assert!(matches!(
        OpenAnswer::read(&reply).unwrap(),
        OpenAnswer::Redirect(r) if r.target == f::REDIRECT_DATA
    ));
    let (reply, _) = open(&mut core, 1000, f::READ_ONLY, "/tmp/x").unwrap();
    assert!(matches!(
        OpenAnswer::read(&reply).unwrap(),
        OpenAnswer::Redirect(r) if r.target == f::REDIRECT_RAM
    ));
}

#[test]
fn a_file_of_the_layer_of_the_user_is_a_pass_after_the_check_of_the_right_to_read() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // 0640 owned by 1000: the owner reads, the superuser reads, another user does not.
    let (reply, pass) = open(&mut core, 1000, f::READ_ONLY, "/etc/own.conf").unwrap();
    assert_eq!(OpenAnswer::read(&reply), Ok(OpenAnswer::Pass));
    assert_eq!(pass.as_deref(), Some(&b"/.layers/00/etc/own.conf"[..]));
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/etc/own.conf")
            .unwrap()
            .1
            .is_some()
    );
    assert_eq!(
        open(&mut core, 1001, f::READ_ONLY, "/etc/own.conf").err(),
        Some(st(f::ACCESS_DENIED))
    );
    // The description opened for the pass is closed again: the service holds none.
    assert_eq!(core.volume.calls_of("export"), 2);
    assert_eq!(
        core.volume.calls_of("open") - core.volume.calls_of("close"),
        0
    );
    // A file that shadows a lower one.
    let (_, pass) = open(&mut core, 1000, f::READ_ONLY, "/etc/passwd").unwrap();
    assert_eq!(pass.as_deref(), Some(&b"/.layers/00/etc/passwd"[..]));
}

#[test]
fn the_names_a_layer_deleted_or_never_had_are_not_there() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // motd is in the lower set and the layer deleted it.
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/motd").err(),
        Some(st(f::NO_ENTRY))
    );
    // The opaque directory shows its own names only.
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/opq/u1")
            .unwrap()
            .1
            .is_some()
    );
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/opq/l1").err(),
        Some(st(f::NO_ENTRY))
    );
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/opq/u1/x").err(),
        Some(st(f::NOT_DIRECTORY))
    );
    assert_eq!(
        open(
            &mut core,
            0,
            f::READ_ONLY | f::DIRECTORY_ONLY,
            "/etc/own.conf"
        )
        .err(),
        Some(st(f::NOT_DIRECTORY))
    );
}

#[test]
fn each_directory_of_the_layer_is_checked_for_the_right_to_search() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    // /home is 0700 owned by root in the layer, and a lower /home/other exists: the user gets
    // EACCES for the one and the other, whatever the lower set says.
    for path in ["/home/secret", "/home/other", "/home/none"] {
        assert_eq!(
            open(&mut core, 1000, f::READ_ONLY, path).err(),
            Some(st(f::ACCESS_DENIED)),
            "{path}"
        );
    }
    assert!(
        open(&mut core, 0, f::READ_ONLY, "/home/secret")
            .unwrap()
            .1
            .is_some()
    );
    // The directory itself cannot be read either.
    assert_eq!(
        open(&mut core, 1000, f::READ_ONLY | f::DIRECTORY_ONLY, "/home").err(),
        Some(st(f::ACCESS_DENIED))
    );
}

#[test]
fn a_write_or_a_create_is_a_read_only_file_system() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    for flags in [
        f::WRITE_ONLY,
        f::READ_WRITE,
        f::READ_ONLY | f::CREATE,
        f::READ_ONLY | f::TRUNCATE,
        f::READ_ONLY | f::APPEND,
    ] {
        assert_eq!(
            open(&mut core, 0, flags, "/etc/passwd").err(),
            Some(st(f::READ_ONLY_FILESYSTEM)),
            "{flags}"
        );
        assert_eq!(
            open(&mut core, 0, flags, "/etc").err(),
            Some(st(f::READ_ONLY_FILESYSTEM))
        );
    }
    // A name of the lower set, one that exists and one that does not: the same.
    for path in ["/bin/ls", "/bin/none", "/usr/new"] {
        assert_eq!(
            open(&mut core, 0, f::READ_ONLY | f::CREATE, path).err(),
            Some(st(f::READ_ONLY_FILESYSTEM)),
            "{path}"
        );
        assert_eq!(
            open(&mut core, 0, f::WRITE_ONLY, path).err(),
            Some(st(f::READ_ONLY_FILESYSTEM)),
            "{path}"
        );
    }
    // The names the root passes through are the services' own.
    let (reply, _) = open(&mut core, 0, f::WRITE_ONLY | f::CREATE, "/tmp/x").unwrap();
    assert!(matches!(
        OpenAnswer::read(&reply),
        Ok(OpenAnswer::Redirect(_))
    ));
    assert_eq!(core.change(), st(f::READ_ONLY_FILESYSTEM));
}

#[test]
fn a_merged_directory_lists_the_layer_then_the_lower_set_without_what_the_layer_hides() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let (reply, _) = open(&mut core, 1000, f::READ_ONLY | f::DIRECTORY_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    let (names, requests) = list(&mut core, 1040, h);
    let names = sorted(names);
    // The mark of motd and the file `.wh.motd` itself are not names; passwd is listed once.
    assert!(!names.iter().any(|n| n.starts_with(".wh.")));
    assert!(!names.contains(&"motd".into()));
    assert_eq!(names.iter().filter(|n| *n == "passwd").count(), 1);
    for expected in [
        ".", "..", "own.conf", "passwd", "hostname", "group", "big00", "big19",
    ] {
        assert!(
            names.contains(&expected.to_string()),
            "{expected}: {names:?}"
        );
    }
    // The lower directory has 4 names and 20 more: at most 8 of them in one reply.
    assert!(requests >= 4, "{requests}");
    let mut dups = names.clone();
    dups.dedup();
    assert_eq!(dups.len(), names.len());
}

#[test]
fn a_reply_takes_at_most_eight_entries_of_the_lower_set() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    let mut lower_seen = 0;
    loop {
        let (bytes, len) = core.read_dir(40, h).unwrap();
        let (more, cursor, entries) = n::read_dir_reply(&bytes[..len]).unwrap();
        let (stage, _) = n::split_cursor(cursor);
        let mut in_reply = 0;
        for e in entries {
            let e = e.unwrap();
            if e.ino < 1000 && e.ino > 1 {
                in_reply += 1;
            }
        }
        assert!(in_reply <= n::LOWER_PER_READDIR, "{in_reply}");
        lower_seen += in_reply;
        if !more {
            assert_eq!(stage, 1);
            break;
        }
    }
    // passwd (12) of the lower set is shadowed, motd (11) deleted: 3 + 20 remain... and the
    // lower inodes 13, 14 and 100..119.
    assert_eq!(lower_seen, 2 + 20);
}

#[test]
fn an_opaque_directory_lists_only_its_own_names_and_a_lower_only_one_is_no_description() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let (reply, _) = open(&mut core, 0, f::READ_ONLY | f::DIRECTORY_ONLY, "/opq").unwrap();
    let h = handle_of(&reply);
    let (names, _) = list(&mut core, 40, h);
    assert_eq!(sorted(names), [".", "..", "u1", "u2"]);
    assert_eq!(core.lower.opened, 0, "the lower directory is never opened");
    // The root: the layer's names and the lower root's, the pass-through ones as the lower set
    // lists them.
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/").unwrap();
    let root = handle_of(&reply);
    let (names, _) = list(&mut core, 40, root);
    let names = sorted(names);
    for expected in ["etc", "home", "opq", "bin"] {
        assert!(
            names.contains(&expected.to_string()),
            "{expected}: {names:?}"
        );
    }
    assert_eq!(names.iter().filter(|n| *n == "etc").count(), 1);
}

#[test]
fn a_description_rewinds_seeks_closes_and_goes_with_its_session() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let (reply, _) = open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    let h = handle_of(&reply);
    let owner = 40;
    let (first, _) = list(&mut core, owner, h);
    core.rewind(owner, h).unwrap();
    let (second, _) = list(&mut core, owner, h);
    assert_eq!(first, second);
    // A cursor a reply gave puts the listing back where it was.
    core.rewind(owner, h).unwrap();
    let (bytes, len) = core.read_dir(owner, h).unwrap();
    let (_, cursor, entries) = n::read_dir_reply(&bytes[..len]).unwrap();
    let head: Vec<_> = entries.map(|e| e.unwrap().name.to_vec()).collect();
    let (rest_a, _) = list(&mut core, owner, h);
    core.seek_dir(owner, h, cursor).unwrap();
    let (rest_b, _) = list(&mut core, owner, h);
    assert_eq!(rest_a, rest_b);
    assert!(!head.is_empty());
    assert_eq!(
        core.seek_dir(owner, h, n::cursor(2, 0)),
        Err(st(f::INVALID_ARGUMENT))
    );
    // Another session cannot use the handle, a handle of an earlier instance is STALE.
    assert_eq!(core.read_dir(41, h).err(), Some(st(f::BAD_FD)));
    let stale = n::handle(0, 1, core.epoch() + 1);
    assert_eq!(core.read_dir(owner, stale).err(), Some(st(f::STALE)));
    let mut w = Writer::new();
    core.fstat(owner, h, &mut w).unwrap();
    assert_eq!(n::read_info(w.as_bytes()).unwrap().kind, 1);
    core.close(owner, h).unwrap();
    assert_eq!(core.close(owner, h), Err(st(f::BAD_FD)));
    // The lower directory was opened and closed with it.
    assert_eq!(core.lower.opened, core.lower.closed);
    // A session that goes frees what it held.
    for _ in 0..3 {
        open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    }
    assert_eq!(core.descriptions(), 3);
    core.gone(owner);
    assert_eq!(core.descriptions(), 0);
}

#[test]
fn a_session_holds_sixteen_descriptions() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    for _ in 0..crate::descriptions::PER_SESSION {
        open(&mut core, 0, f::READ_ONLY, "/etc").unwrap();
    }
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc").err(),
        Some(st(f::TOO_MANY_OPEN_FILES))
    );
}

#[test]
fn stat_numbers_come_from_the_service_that_holds_the_name() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let v = who(1000);
    let c = Client { owner: 40, who: &v };
    let stat = |core: &mut Core<'_, FakeVolume, FakeLower>, path: &str| {
        let mut w = Writer::new();
        core.stat(&c, 0, path.as_bytes(), &mut w)
            .map(|()| n::read_info(w.as_bytes()).unwrap())
    };
    // A file of the layer: the number the data volume keeps, device 0.
    let own = stat(&mut core, "/etc/own.conf").unwrap();
    assert_eq!(own.inode, UPPER_INO_TAG | 7);
    assert_eq!(
        (own.device, own.uid, own.permissions, own.size),
        (0, 1000, 0o640, 9)
    );
    assert_eq!(own.kind, 2);
    // A lower name: the number the RAM service gives, and none of the top bits.
    let ls = stat(&mut core, "/bin/ls").unwrap();
    assert_eq!((ls.inode, ls.device), (21, 0));
    assert_eq!(ls.inode & (UPPER_INO_TAG | 1 << 63), 0);
    // A directory of the layer, the root, a directory of the lower set.
    assert_eq!(stat(&mut core, "/etc").unwrap().kind, 1);
    let root = core.volume.nodes[&b"/.layers/00".to_vec()].ino;
    assert_eq!(stat(&mut core, "/").unwrap().inode, root);
    assert_eq!(stat(&mut core, "/bin").unwrap().inode, 20);
    assert_eq!(stat(&mut core, "/etc/motd").err(), Some(st(f::NO_ENTRY)));
    assert_eq!(
        stat(&mut core, "/home/secret").err(),
        Some(st(f::ACCESS_DENIED))
    );
    assert_eq!(stat(&mut core, "/nothing").err(), Some(st(f::NO_ENTRY)));
    assert_eq!(
        stat(&mut core, "/etc/own.conf/").err(),
        Some(st(f::NOT_DIRECTORY))
    );
    assert_eq!(
        stat(&mut core, "/bin/ls/").err(),
        Some(st(f::NOT_DIRECTORY))
    );
    // The times are the data service's, in seconds and nanoseconds.
    assert_eq!(own.modify_time.seconds, 2);
    // A pass-through name is a redirect.
    let mut w = Writer::new();
    core.stat(&c, 0, b"/data", &mut w).unwrap();
    assert!(proto_fs::Redirect::read_reply(w.as_bytes()).is_some());
}

#[test]
fn access_checks_the_bits_and_refuses_a_write() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let v = who(1001);
    let c = Client { owner: 41, who: &v };
    let mut w = Writer::new();
    assert!(core.access(&c, 0, 0, b"/etc/own.conf", &mut w).is_ok());
    let mut w = Writer::new();
    assert_eq!(
        core.access(&c, 4, 0, b"/etc/own.conf", &mut w),
        Err(st(f::ACCESS_DENIED))
    );
    let mut w = Writer::new();
    assert!(core.access(&c, 4, 0, b"/etc/passwd", &mut w).is_ok());
    let mut w = Writer::new();
    assert_eq!(
        core.access(&c, 2, 0, b"/etc/passwd", &mut w),
        Err(st(f::READ_ONLY_FILESYSTEM))
    );
    let mut w = Writer::new();
    core.readlink(&c, b"/bin/ls", &mut w).unwrap();
    let mut w = Writer::new();
    assert_eq!(
        core.readlink(&c, b"/etc/passwd", &mut w),
        Err(st(f::INVALID_ARGUMENT))
    );
}

#[test]
fn list_gives_the_lower_set_and_the_live_layer() {
    let mut world = World::new();
    let mut core = world.core(volume());
    ready(&mut core);
    let mut w = Writer::new();
    core.list(0, &mut w).unwrap();
    let mut out = [None; l::LIST_MAX as usize];
    let (count, next) = l::read_list(w.as_bytes(), &mut out).unwrap();
    assert_eq!((count, next), (2, 0));
    assert_eq!(out[0].unwrap().kind, l::KIND_PACKAGES);
    assert_eq!(out[1].unwrap().kind, l::KIND_LIVE);
    assert_eq!(out[1].unwrap().number, 0);
    let mut w = Writer::new();
    core.list(5, &mut w).unwrap();
    assert_eq!(l::read_list(w.as_bytes(), &mut out).unwrap().0, 0);
}

#[test]
fn a_full_index_fails_the_start_with_no_space() {
    let mut v = volume();
    // More names than the table takes within eight probes: 20,000 files in one directory.
    for i in 0..20_000 {
        v.file(&format!("/.layers/00/opq/f{i:05}"), 0o644, 0, b"");
    }
    v.batch = 59;
    let mut world = World::new();
    let mut core = world.core(v);
    core.prepare();
    let mut steps = 0;
    while !core.build_step() {
        steps += 1;
        assert!(steps < 100_000);
    }
    assert_eq!(core.state, State::Failed(l::NO_SPACE));
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc").err(),
        Some(st(l::NO_SPACE))
    );
}

#[test]
fn the_volume_statuses_become_the_statuses_of_the_names() {
    let mut world = World::new();
    let mut v = volume();
    // The file is gone from the volume after the index was built.
    v.file("/.layers/00/etc/own.conf", 0o640, 1000, b"x");
    let mut core = world.core(v);
    ready(&mut core);
    core.volume
        .nodes
        .remove(b"/.layers/00/etc/own.conf".as_slice());
    assert_eq!(
        open(&mut core, 0, f::READ_ONLY, "/etc/own.conf").err(),
        Some(st(f::NO_ENTRY))
    );
    let _ = d::NO_ENTRY;
}
